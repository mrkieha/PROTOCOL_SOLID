"""
proxy_manager.py — управление mtprotoproxy.

Ключевые фиксы:
- Правильный формат секрета: в конфиге хранится base_secret (32 hex),
  в ссылке tg:// — ee+base_secret+domain_hex. Это то что ожидает mtprotoproxy.
- Диагностика доступности порта снаружи
- Явный биндинг на 0.0.0.0
"""

import os
import re
import io
import signal
import secrets
import logging
import threading
import subprocess
import socket
import urllib.request
import base64
from pathlib import Path
from typing import Optional

logger = logging.getLogger("proxy_manager")

SCRIPT_DIR  = Path(__file__).resolve().parent.parent
MTPROTO_DIR = SCRIPT_DIR / "mtprotoproxy"
CONFIG_DIR  = SCRIPT_DIR / "config"
PROXY_CONF  = CONFIG_DIR / "mtproto_config.py"
DUCK_CONF   = CONFIG_DIR / "duckdns.conf"
SECRET_FILE = CONFIG_DIR / "secret.txt"   # храним base_secret отдельно
DOMAIN_FILE = CONFIG_DIR / "tls_domain.txt"
LOG_DIR     = SCRIPT_DIR / "logs"
PROXY_LOG   = LOG_DIR / "mtproto.log"
PID_FILE    = LOG_DIR / "mtproto.pid"
VENV_PY     = SCRIPT_DIR / "venv" / "bin" / "python3"

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
_duck_timer:    Optional[threading.Timer]   = None


# ---------------------------------------------------------------------------
# Секрет — правильная двухуровневая схема
# ---------------------------------------------------------------------------
#
# mtprotoproxy в config.py ожидает в USERS:
#   - простой режим:   "xxxxxxxx..."  (ровно 32 hex символа)
#   - fake-tls режим:  "eedd..." (ee + 32 hex) — но ТОЛЬКО в новых версиях
#
# Ссылка tg://proxy?secret= всегда:
#   - простой:  base64url(bytes.fromhex(secret))  — или просто hex
#   - fake-tls: "ee" + base_secret_hex + domain_hex
#
# Правильная схема:
#   base_secret = 16 случайных байт = 32 hex символа  → идёт в конфиг
#   tls_domain  = например "cloudflare.com"
#   link_secret = "ee" + base_secret_hex + hex(domain) → идёт в ссылку
#
# ---------------------------------------------------------------------------

def generate_base_secret() -> str:
    """16 случайных байт → 32 hex символа. Именно это в конфиг."""
    return secrets.token_hex(16)


def make_link_secret(base_secret: str, domain: str) -> str:
    """
    Формирует секрет для tg:// ссылки в формате fake-tls.
    base_secret — 32 hex символа (без префикса)
    """
    return f"ee{base_secret}{domain.encode().hex()}"


def _save_secret(base_secret: str, domain: str):
    SECRET_FILE.write_text(base_secret)
    DOMAIN_FILE.write_text(domain)
    SECRET_FILE.chmod(0o600)


def _load_secret() -> tuple[Optional[str], Optional[str]]:
    """Возвращает (base_secret, domain) или (None, None)."""
    try:
        base   = SECRET_FILE.read_text().strip()
        domain = DOMAIN_FILE.read_text().strip() if DOMAIN_FILE.exists() else TLS_DOMAINS[0]
        return base, domain
    except Exception:
        # Fallback: пробуем вытащить из конфига
        if PROXY_CONF.exists():
            m = re.search(r'"user"\s*:\s*"([a-fA-F0-9]+)"', PROXY_CONF.read_text())
            if m:
                s = m.group(1)
                # Если уже ee-формат — вытащим base часть
                if s.startswith("ee") and len(s) > 34:
                    return s[2:34], TLS_DOMAINS[0]
                if len(s) == 32:
                    return s, TLS_DOMAINS[0]
        return None, None


# ---------------------------------------------------------------------------
# Duck DNS
# ---------------------------------------------------------------------------

def save_duck_config(token: str, domain: str) -> dict:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    domain = domain.strip().lower().removesuffix(".duckdns.org")
    token  = token.strip()
    if not token or not domain:
        return {"ok": False, "error": "token и domain обязательны"}
    DUCK_CONF.write_text(f"token={token}\ndomain={domain}\n")
    DUCK_CONF.chmod(0o600)
    return {"ok": True, "hostname": f"{domain}.duckdns.org"}


def load_duck_config() -> Optional[dict]:
    if not DUCK_CONF.exists():
        return None
    cfg = {}
    for line in DUCK_CONF.read_text().splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            cfg[k.strip()] = v.strip()
    t = cfg.get("token", ""); d = cfg.get("domain", "")
    return {"token": t, "domain": d, "hostname": f"{d}.duckdns.org"} if t and d else None


def update_duck_dns() -> dict:
    cfg = load_duck_config()
    if not cfg:
        return {"ok": False, "error": "Duck DNS не настроен"}
    url = f"https://www.duckdns.org/update?domains={cfg['domain']}&token={cfg['token']}&ip="
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            resp = r.read().decode().strip()
        ok = resp.lower().startswith("ok")
        logger.info(f"Duck DNS: {resp} ({cfg['hostname']})")
        return {"ok": ok, "response": resp, "hostname": cfg["hostname"]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _schedule_duck_update(interval: int = 300):
    global _duck_timer
    if _duck_timer: _duck_timer.cancel()
    def _tick():
        update_duck_dns()
        _schedule_duck_update(interval)
    _duck_timer = threading.Timer(interval, _tick)
    _duck_timer.daemon = True
    _duck_timer.start()


def start_duck_updater():
    if load_duck_config():
        update_duck_dns()
        _schedule_duck_update()


def stop_duck_updater():
    global _duck_timer
    if _duck_timer: _duck_timer.cancel(); _duck_timer = None


# ---------------------------------------------------------------------------
# Получение внешнего адреса
# ---------------------------------------------------------------------------

def get_public_hostname() -> str:
    cfg = load_duck_config()
    if cfg: return cfg["hostname"]
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                ip = r.read().decode().strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                return ip
        except Exception:
            continue
    return "127.0.0.1"


# ---------------------------------------------------------------------------
# Диагностика доступности порта
# ---------------------------------------------------------------------------

def check_port_open(port: int, timeout: int = 5) -> dict:
    """
    Проверяем доступен ли порт снаружи через внешний сервис.
    Используем canyouseeme-подобный подход через портовый сканер API.
    """
    result = {"port": port, "reachable": False, "method": "", "details": ""}

    # Метод 1: portchecker.io API
    try:
        url = f"https://portchecker.io/api/v1/query"
        host = get_public_hostname()
        # Простой TCP probe через публичный API
        req = urllib.request.Request(
            f"https://www.yougetsignal.com/tools/open-ports/php/process.php",
            data=f"remoteAddress={host}&portNumber={port}".encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp = r.read().decode()
        if "open" in resp.lower():
            result.update(reachable=True, method="yougetsignal", details=resp[:100])
            return result
    except Exception:
        pass

    # Метод 2: прямой TCP со стороны сервера к себе (локальная проверка)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            result.update(
                reachable=None,   # None = локально открыт, но снаружи неизвестно
                method="local_tcp",
                details=f"Порт {port} открыт локально — mtprotoproxy слушает. "
                        "Доступность снаружи зависит от роутера/файрвола."
            )
    except ConnectionRefusedError:
        result["details"] = f"Порт {port} не слушает локально — прокси не запущен или завис"
    except Exception as e:
        result["details"] = str(e)

    return result


def check_awg_connectivity() -> dict:
    """
    Проверяем что через AWG туннель реально доходит трафик
    до серверов Telegram (149.154.0.0/16).
    """
    TG_IPS = ["149.154.167.51", "149.154.175.55", "91.108.56.130"]
    results = []
    for ip in TG_IPS:
        try:
            start = __import__("time").time()
            with socket.create_connection((ip, 443), timeout=4):
                ms = int((__import__("time").time() - start) * 1000)
                results.append({"ip": ip, "ok": True, "ms": ms})
                break
        except Exception as e:
            results.append({"ip": ip, "ok": False, "error": str(e)})

    any_ok = any(r["ok"] for r in results)
    return {
        "reachable": any_ok,
        "results":   results,
        "details":   "Telegram доступен через туннель" if any_ok else "Telegram недоступен — проверь AWG"
    }


# ---------------------------------------------------------------------------
# Конфиг прокси
# ---------------------------------------------------------------------------

def generate_config(
    port: int = 8443,
    domain: Optional[str] = None,
    secret: Optional[str] = None,
) -> dict:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    if domain is None:
        domain = secrets.choice(TLS_DOMAINS)

    # base_secret — ровно 32 hex символа, это то что идёт В КОНФИГ
    if secret and len(secret) == 32 and all(c in "0123456789abcdefABCDEF" for c in secret):
        base_secret = secret
    else:
        base_secret = generate_base_secret()

    _save_secret(base_secret, domain)

    # В конфиге mtprotoproxy — ТОЛЬКО base_secret (32 hex)
    # ee-префикс и домен идут только в tg:// ссылку
    PROXY_CONF.write_text(
        f"# Автогенерировано tg-proxy\n"
        f"# НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ\n\n"
        f"PORT = {port}\n"
        f"# Биндинг на все интерфейсы — нужен чтобы принимать внешние соединения\n"
        f"BIND_IP = \"0.0.0.0\"\n"
        f"USERS = {{\"user\": \"{base_secret}\"}}\n"
        f"AD_TAG = \"\"\n"
        f"VERBOSE = True\n"  # True чтобы видеть соединения в логе
    )
    PROXY_CONF.chmod(0o600)

    link_secret = make_link_secret(base_secret, domain)
    logger.info(f"MTProto конфиг: порт={port}, домен={domain}, base_secret={base_secret[:8]}...")
    return {
        "port":        port,
        "domain":      domain,
        "base_secret": base_secret,
        "link_secret": link_secret,
    }


# ---------------------------------------------------------------------------
# Ссылка и QR
# ---------------------------------------------------------------------------

def get_proxy_link(port: int = 8443) -> Optional[str]:
    base, domain = _load_secret()
    if not base or not domain:
        return None
    host      = get_public_hostname()
    link_sec  = make_link_secret(base, domain)
    return f"tg://proxy?server={host}&port={port}&secret={link_sec}"


def get_qr_base64(link: str) -> str:
    try:
        import qrcode
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,
                           box_size=8, border=2)
        qr.add_data(link)
        qr.make(fit=True)
        img = qr.make_image(fill_color="white", back_color="#0d1117")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:
        logger.warning(f"QR недоступен: {e}")
        return ""


# ---------------------------------------------------------------------------
# Запуск / остановка
# ---------------------------------------------------------------------------

def _python() -> str:
    if VENV_PY.exists(): return str(VENV_PY)
    import shutil; return shutil.which("python3") or "python3"


def _read_pid() -> Optional[int]:
    try: return int(PID_FILE.read_text().strip())
    except: return None


def _alive(pid: int) -> bool:
    try: os.kill(pid, 0); return True
    except: return False


def start(port: int = 8443) -> dict:
    global _proxy_process

    if not PROXY_CONF.exists():
        generate_config(port=port)

    if not MTPROTO_DIR.exists():
        return {"ok": False, "error": f"mtprotoproxy не найден: {MTPROTO_DIR}. Запусти install.sh"}

    stop()

    main_py = MTPROTO_DIR / "mtprotoproxy.py"
    if not main_py.exists():
        return {"ok": False, "error": f"Не найден {main_py}"}

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Пишем timestamp в лог при каждом старте
    with open(PROXY_LOG, "a") as f:
        from datetime import datetime
        f.write(f"\n{'='*50}\n[{datetime.now():%Y-%m-%d %H:%M:%S}] ЗАПУСК\n{'='*50}\n")

    log_f = open(PROXY_LOG, "a")
    try:
        proc = subprocess.Popen(
            [_python(), str(main_py), str(PROXY_CONF)],
            stdout=log_f, stderr=log_f,
            cwd=str(MTPROTO_DIR),
            preexec_fn=os.setsid,
        )
        _proxy_process = proc
        PID_FILE.write_text(str(proc.pid))
        logger.info(f"mtprotoproxy PID={proc.pid} port={port}")
        start_duck_updater()
        return {"ok": True, "pid": proc.pid, "port": port}
    except Exception as e:
        logger.error(f"Ошибка запуска: {e}")
        return {"ok": False, "error": str(e)}


def stop() -> dict:
    global _proxy_process
    stop_duck_updater()
    if _proxy_process and _proxy_process.poll() is None:
        try:
            os.killpg(os.getpgid(_proxy_process.pid), signal.SIGTERM)
            _proxy_process.wait(timeout=4)
        except Exception:
            try: _proxy_process.kill()
            except: pass
    _proxy_process = None
    pid = _read_pid()
    if pid and _alive(pid):
        try: os.killpg(os.getpgid(pid), signal.SIGTERM)
        except:
            try: os.kill(pid, signal.SIGKILL)
            except: pass
    PID_FILE.unlink(missing_ok=True)
    subprocess.run(["pkill", "-f", "mtprotoproxy"], capture_output=True)
    return {"ok": True}


def restart(port: int = 8443) -> dict:
    stop()
    import time; time.sleep(0.8)
    return start(port=port)


def get_status(port: int = 8443) -> dict:
    pid     = _read_pid()
    running = bool(pid and _alive(pid))
    if not running and _proxy_process:
        running = _proxy_process.poll() is None
        if running: pid = _proxy_process.pid

    duck = load_duck_config()
    status = {
        "running": running,
        "pid":     pid,
        "port":    port,
        "duck_dns": {
            "configured": bool(duck),
            "hostname":   duck["hostname"] if duck else None,
        }
    }

    base, domain = _load_secret()
    if base and domain:
        link = get_proxy_link(port=port)
        status["link"]        = link
        status["base_secret"] = base
        status["tls_domain"]  = domain
        if running and link:
            status["qr"] = get_qr_base64(link)

    return status


def get_logs(lines: int = 60) -> list:
    if not PROXY_LOG.exists(): return []
    try:
        return PROXY_LOG.read_text(errors="replace").splitlines()[-lines:]
    except Exception:
        return []
