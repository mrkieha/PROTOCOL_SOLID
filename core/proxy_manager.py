"""
proxy_manager.py — управление mtprotoproxy.
Генерирует секрет fake-tls, запускает/останавливает прокси,
генерирует ссылку и QR-код для Telegram.
"""

import os
import re
import io
import signal
import secrets
import logging
import subprocess
import base64
from pathlib import Path
from typing import Optional

logger = logging.getLogger("proxy_manager")

SCRIPT_DIR  = Path(__file__).resolve().parent.parent
MTPROTO_DIR = SCRIPT_DIR / "mtprotoproxy"
CONFIG_DIR  = SCRIPT_DIR / "config"
PROXY_CONF  = CONFIG_DIR / "mtproto_config.py"
LOG_DIR     = SCRIPT_DIR / "logs"
PROXY_LOG   = LOG_DIR / "mtproto.log"
PID_FILE    = LOG_DIR / "mtproto.pid"

VENV_PY = SCRIPT_DIR / "venv" / "bin" / "python3"

# TLS-домены для маскировки трафика.
# Используем живые CDN — имитируем реальный HTTPS-трафик.
# Это критично для обхода DPI в РФ.
TLS_DOMAINS = [
    "cloudflare.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "akamai.com",
    "fastly.net",
]

_proxy_process: Optional[subprocess.Popen] = None


# ---------------------------------------------------------------------------
# Генерация секрета
# ---------------------------------------------------------------------------

def generate_secret(domain: Optional[str] = None) -> str:
    """
    Генерирует fake-tls секрет для MTProto.
    Формат: ee + 32 hex символа + hex(domain)
    Префикс 'ee' говорит Telegram-клиенту использовать TLS-маскировку.
    """
    if domain is None:
        domain = secrets.choice(TLS_DOMAINS)

    # 16 случайных байт = 32 hex символа
    rand_hex = secrets.token_hex(16)
    # Домен кодируем в hex
    domain_hex = domain.encode().hex()
    secret = f"ee{rand_hex}{domain_hex}"
    logger.info(f"Сгенерирован секрет для домена: {domain}")
    return secret


def _read_current_secret() -> Optional[str]:
    """Читаем текущий секрет из конфига."""
    if not PROXY_CONF.exists():
        return None
    try:
        text = PROXY_CONF.read_text()
        m = re.search(r'"user"\s*:\s*"([a-fA-F0-9]+)"', text)
        return m.group(1) if m else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Генерация конфига mtprotoproxy
# ---------------------------------------------------------------------------

def generate_config(
    port: int = 443,
    domain: Optional[str] = None,
    secret: Optional[str] = None,
) -> dict:
    """
    Генерирует config.py для mtprotoproxy и сохраняет в CONFIG_DIR.
    Порт 443 — минимальная блокировка (HTTPS трафик).
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    if secret is None:
        secret = generate_secret(domain)

    conf_text = f"""# Автогенерировано tg-proxy
# Не редактируй вручную — используй веб-интерфейс

PORT = {port}

# fake-tls секрет: ee + 32hex + hex(domain)
# Имитирует TLS-хендшейк с реальным CDN-доменом
USERS = {{
    "user": "{secret}"
}}

# Рекламный тег намеренно пуст — публичные прокси с тегом
# могут попасть в базы блокировок
AD_TAG = ""

# Логирование
VERBOSE = False
"""

    PROXY_CONF.write_text(conf_text)
    PROXY_CONF.chmod(0o600)
    logger.info(f"MTProto конфиг сохранён: {PROXY_CONF}")

    return {"port": port, "secret": secret, "config_path": str(PROXY_CONF)}


# ---------------------------------------------------------------------------
# Определение внешнего IP
# ---------------------------------------------------------------------------

def _get_public_ip() -> str:
    """Пытаемся определить внешний IP несколькими методами."""
    endpoints = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ]
    import urllib.request
    for url in endpoints:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                ip = r.read().decode().strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    return ip
        except Exception:
            continue
    return "127.0.0.1"


# ---------------------------------------------------------------------------
# Ссылка и QR-код
# ---------------------------------------------------------------------------

def get_proxy_link(host: Optional[str] = None, port: int = 443) -> Optional[str]:
    """Возвращает tg://proxy?... ссылку."""
    secret = _read_current_secret()
    if not secret:
        return None
    if host is None:
        host = _get_public_ip()
    return f"tg://proxy?server={host}&port={port}&secret={secret}"


def get_qr_base64(link: str) -> str:
    """Генерируем QR-код для ссылки, возвращаем base64 PNG."""
    try:
        import qrcode
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=2,
        )
        qr.add_data(link)
        qr.make(fit=True)
        img = qr.make_image(fill_color="white", back_color="#0d1117")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except ImportError:
        logger.warning("qrcode/Pillow не установлены, QR недоступен")
        return ""
    except Exception as e:
        logger.error(f"Ошибка генерации QR: {e}")
        return ""


# ---------------------------------------------------------------------------
# Запуск / остановка
# ---------------------------------------------------------------------------

def _get_python() -> str:
    """Возвращаем путь к Python из venv или системный."""
    if VENV_PY.exists():
        return str(VENV_PY)
    import shutil
    return shutil.which("python3") or "python3"


def _read_pid() -> Optional[int]:
    try:
        return int(PID_FILE.read_text().strip())
    except Exception:
        return None


def _write_pid(pid: int):
    PID_FILE.write_text(str(pid))


def _clear_pid():
    PID_FILE.unlink(missing_ok=True)


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def start(port: int = 443) -> dict:
    """Запускаем mtprotoproxy."""
    global _proxy_process

    # Проверяем конфиг
    if not PROXY_CONF.exists():
        result = generate_config(port=port)
        logger.info(f"Сгенерирован новый конфиг: {result}")

    if not MTPROTO_DIR.exists():
        return {"ok": False, "error": f"mtprotoproxy не найден: {MTPROTO_DIR}. Запусти install.sh"}

    # Убиваем старый процесс если есть
    stop()

    main_py = MTPROTO_DIR / "mtprotoproxy.py"
    if not main_py.exists():
        return {"ok": False, "error": f"Не найден {main_py}"}

    log_f = open(PROXY_LOG, "a")
    try:
        proc = subprocess.Popen(
            [_get_python(), str(main_py), str(PROXY_CONF)],
            stdout=log_f,
            stderr=log_f,
            cwd=str(MTPROTO_DIR),
            preexec_fn=os.setsid,  # процессная группа для kill
        )
        _proxy_process = proc
        _write_pid(proc.pid)
        logger.info(f"mtprotoproxy запущен, PID={proc.pid}, порт={port}")
        return {"ok": True, "pid": proc.pid, "port": port}
    except Exception as e:
        logger.error(f"Ошибка запуска mtprotoproxy: {e}")
        return {"ok": False, "error": str(e)}


def stop() -> dict:
    """Останавливаем mtprotoproxy."""
    global _proxy_process

    stopped = False

    # Сначала через сохранённый объект процесса
    if _proxy_process and _proxy_process.poll() is None:
        try:
            os.killpg(os.getpgid(_proxy_process.pid), signal.SIGTERM)
            _proxy_process.wait(timeout=5)
            stopped = True
        except Exception:
            try:
                _proxy_process.kill()
                stopped = True
            except Exception:
                pass
        _proxy_process = None

    # Через PID-файл
    pid = _read_pid()
    if pid and _process_alive(pid):
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            stopped = True
        except Exception:
            try:
                os.kill(pid, signal.SIGKILL)
                stopped = True
            except Exception:
                pass

    _clear_pid()

    # Убиваем процессы по имени как последний resort
    try:
        subprocess.run(
            ["pkill", "-f", "mtprotoproxy"],
            capture_output=True, check=False
        )
    except Exception:
        pass

    logger.info("mtprotoproxy остановлен")
    return {"ok": True, "was_running": stopped}


def restart(port: int = 443) -> dict:
    """Перезапуск."""
    stop()
    import time; time.sleep(1)
    return start(port=port)


# ---------------------------------------------------------------------------
# Статус
# ---------------------------------------------------------------------------

def get_status(port: int = 443) -> dict:
    """Возвращаем статус прокси."""
    pid = _read_pid()
    running = bool(pid and _process_alive(pid))

    # Дополнительная проверка через глобальный объект
    if not running and _proxy_process:
        running = _proxy_process.poll() is None
        if running:
            pid = _proxy_process.pid

    status = {
        "running": running,
        "pid":     pid,
        "port":    port,
    }

    if running:
        link = get_proxy_link(port=port)
        status["link"] = link
        if link:
            status["qr"] = get_qr_base64(link)

    secret = _read_current_secret()
    if secret:
        status["secret"] = secret
        status["link"]   = get_proxy_link(port=port)

    return status


# ---------------------------------------------------------------------------
# Логи
# ---------------------------------------------------------------------------

def get_logs(lines: int = 50) -> list[str]:
    """Возвращаем последние N строк лога."""
    if not PROXY_LOG.exists():
        return []
    try:
        all_lines = PROXY_LOG.read_text(errors="replace").splitlines()
        return all_lines[-lines:]
    except Exception:
        return []
