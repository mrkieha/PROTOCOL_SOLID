"""
proxy_manager.py — управление mtprotoproxy.
Поддерживает Duck DNS (автообновление hostname + произвольный порт).
"""

import os
import re
import io
import signal
import secrets
import logging
import threading
import subprocess
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
# Duck DNS
# ---------------------------------------------------------------------------

def save_duck_config(token: str, domain: str) -> dict:
    """
    Сохраняем настройки Duck DNS.
    domain — только субдомен без .duckdns.org, например: myproxy
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    domain = domain.strip().lower().removesuffix(".duckdns.org")
    token  = token.strip()
    if not token or not domain:
        return {"ok": False, "error": "token и domain обязательны"}

    DUCK_CONF.write_text(f"token={token}\ndomain={domain}\n")
    DUCK_CONF.chmod(0o600)
    logger.info(f"Duck DNS конфиг сохранён: {domain}.duckdns.org")
    return {"ok": True, "hostname": f"{domain}.duckdns.org"}


def load_duck_config() -> Optional[dict]:
    """Загружаем настройки Duck DNS, None если не настроено."""
    if not DUCK_CONF.exists():
        return None
    cfg = {}
    for line in DUCK_CONF.read_text().splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            cfg[k.strip()] = v.strip()
    token  = cfg.get("token", "")
    domain = cfg.get("domain", "")
    if not token or not domain:
        return None
    return {"token": token, "domain": domain,
            "hostname": f"{domain}.duckdns.org"}


def update_duck_dns() -> dict:
    """Обновляем IP в Duck DNS. Возвращает {"ok": bool, "response": str}."""
    cfg = load_duck_config()
    if not cfg:
        return {"ok": False, "error": "Duck DNS не настроен"}

    url = (f"https://www.duckdns.org/update"
           f"?domains={cfg['domain']}&token={cfg['token']}&ip=")
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            resp = r.read().decode().strip()
        ok = resp.lower().startswith("ok")
        if ok:
            logger.info(f"Duck DNS обновлён: {cfg['hostname']}")
        else:
            logger.warning(f"Duck DNS ответил: {resp}")
        return {"ok": ok, "response": resp, "hostname": cfg["hostname"]}
    except Exception as e:
        logger.error(f"Ошибка Duck DNS: {e}")
        return {"ok": False, "error": str(e)}


def _schedule_duck_update(interval_sec: int = 300):
    """Обновляем Duck DNS каждые 5 минут в фоне."""
    global _duck_timer
    if _duck_timer:
        _duck_timer.cancel()

    def _tick():
        update_duck_dns()
        _schedule_duck_update(interval_sec)

    _duck_timer = threading.Timer(interval_sec, _tick)
    _duck_timer.daemon = True
    _duck_timer.start()


def start_duck_updater():
    """Запускаем фоновое обновление Duck DNS (если настроен)."""
    if load_duck_config():
        update_duck_dns()         # сразу
        _schedule_duck_update()   # потом каждые 5 мин


def stop_duck_updater():
    global _duck_timer
    if _duck_timer:
        _duck_timer.cancel()
        _duck_timer = None


# ---------------------------------------------------------------------------
# Определение внешнего hostname / IP
# ---------------------------------------------------------------------------

def get_public_hostname(port: int) -> tuple[str, str]:
    """
    Возвращает (hostname, full_link_host).
    Если Duck DNS настроен — используем его, иначе берём IP.
    """
    cfg = load_duck_config()
    if cfg:
        return cfg["hostname"], cfg["hostname"]

    # Fallback: внешний IP
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip",
                "https://icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                ip = r.read().decode().strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                return ip, ip
        except Exception:
            continue
    return "127.0.0.1", "127.0.0.1"


# ---------------------------------------------------------------------------
# Секрет MTProto
# ---------------------------------------------------------------------------

def generate_secret(domain: Optional[str] = None) -> str:
    """fake-tls секрет: ee + 32hex + hex(domain)"""
    if not domain:
        domain = secrets.choice(TLS_DOMAINS)
    return f"ee{secrets.token_hex(16)}{domain.encode().hex()}"


def _read_current_secret() -> Optional[str]:
    if not PROXY_CONF.exists():
        return None
    m = re.search(r'"user"\s*:\s*"([a-fA-F0-9]+)"', PROXY_CONF.read_text())
    return m.group(1) if m else None


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

    if not secret:
        secret = generate_secret(domain)

    PROXY_CONF.write_text(f"""# Автогенерировано tg-proxy
PORT = {port}
USERS = {{"user": "{secret}"}}
AD_TAG = ""
VERBOSE = False
""")
    PROXY_CONF.chmod(0o600)
    logger.info(f"MTProto конфиг: порт={port}")
    return {"port": port, "secret": secret}


# ---------------------------------------------------------------------------
# Ссылка и QR
# ---------------------------------------------------------------------------

def get_proxy_link(port: int = 8443) -> Optional[str]:
    secret = _read_current_secret()
    if not secret:
        return None
    host, _ = get_public_hostname(port)
    return f"tg://proxy?server={host}&port={port}&secret={secret}"


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
    if VENV_PY.exists():
        return str(VENV_PY)
    import shutil
    return shutil.which("python3") or "python3"


def _read_pid() -> Optional[int]:
    try:   return int(PID_FILE.read_text().strip())
    except: return None


def _alive(pid: int) -> bool:
    try:   os.kill(pid, 0); return True
    except: return False


def start(port: int = 8443) -> dict:
    global _proxy_process

    if not PROXY_CONF.exists():
        generate_config(port=port)

    if not MTPROTO_DIR.exists():
        return {"ok": False,
                "error": f"mtprotoproxy не найден: {MTPROTO_DIR}. Запусти install.sh"}

    stop()

    main_py = MTPROTO_DIR / "mtprotoproxy.py"
    if not main_py.exists():
        return {"ok": False, "error": f"Не найден {main_py}"}

    LOG_DIR.mkdir(parents=True, exist_ok=True)
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
        logger.info(f"mtprotoproxy запущен PID={proc.pid} port={port}")

        # Запускаем Duck DNS обновление если настроен
        start_duck_updater()

        return {"ok": True, "pid": proc.pid, "port": port}
    except Exception as e:
        logger.error(f"Ошибка запуска: {e}")
        return {"ok": False, "error": str(e)}


def stop() -> dict:
    global _proxy_process
    stop_duck_updater()

    for src in (_proxy_process, None):
        if src and src.poll() is None:
            try:
                os.killpg(os.getpgid(src.pid), signal.SIGTERM)
                src.wait(timeout=4)
            except Exception:
                try: src.kill()
                except: pass
    _proxy_process = None

    pid = _read_pid()
    if pid and _alive(pid):
        try:   os.killpg(os.getpgid(pid), signal.SIGTERM)
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

    secret = _read_current_secret()
    if secret:
        link = get_proxy_link(port=port)
        status["link"]   = link
        status["secret"] = secret
        if running and link:
            status["qr"] = get_qr_base64(link)

    return status


def get_logs(lines: int = 60) -> list:
    if not PROXY_LOG.exists():
        return []
    try:
        return PROXY_LOG.read_text(errors="replace").splitlines()[-lines:]
    except Exception:
        return []
