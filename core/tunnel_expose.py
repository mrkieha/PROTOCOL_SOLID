"""
tunnel_expose.py — публичный доступ к локальному порту через bore-туннель.

bore (https://github.com/ekzhang/bore) — бесплатный TCP-туннель без регистрации.
Команда: bore local <local_port> --to <relay_host> [--port <relay_port>] [--secret <secret>]
Выход:   bore.pub:<random_port>
"""

import os
import re
import json
import shutil
import logging
import platform
import subprocess
import threading
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

logger = logging.getLogger("tunnel_expose")

SCRIPT_DIR  = Path(__file__).resolve().parent.parent
CONFIG_DIR  = SCRIPT_DIR / "config"
BORE_BIN    = Path("/usr/local/bin/bore")
STATE_FILE  = CONFIG_DIR / "bore_state.json"

# Публичный релей (fallback-адрес берётся первым)
DEFAULT_RELAY = "bore.pub"
DEFAULT_CTRL  = 7835   # порт управления bore (по умолчанию)

_proc:   Optional[subprocess.Popen] = None
_lock    = threading.Lock()
_endpoint: Optional[str] = None   # "host:port" назначенный релеем


# ---------------------------------------------------------------------------
# Установка бинарника
# ---------------------------------------------------------------------------

def _arch_suffix() -> str:
    m = platform.machine().lower()
    if   m in ("x86_64", "amd64"):   return "x86_64-unknown-linux-musl"
    elif m in ("aarch64", "arm64"):  return "aarch64-unknown-linux-musl"
    elif m.startswith("armv7"):      return "armv7-unknown-linux-musleabihf"
    return "x86_64-unknown-linux-musl"


def install_bore() -> dict:
    """Скачиваем актуальный бинарник bore с GitHub Releases."""
    if BORE_BIN.exists() and os.access(BORE_BIN, os.X_OK):
        ver = _bore_version()
        return {"ok": True, "msg": f"bore уже установлен ({ver})"}

    logger.info("Устанавливаем bore...")
    try:
        api = "https://api.github.com/repos/ekzhang/bore/releases/latest"
        req = urllib.request.Request(api, headers={"User-Agent": "tg-proxy"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())

        suffix = _arch_suffix()
        url = None
        for asset in data.get("assets", []):
            nm = asset.get("name", "")
            if suffix in nm and nm.endswith(".tar.gz"):
                url = asset["browser_download_url"]
                break

        if not url:
            return {"ok": False, "error": "Не нашли подходящий бинарник bore на GitHub"}

        import tempfile, tarfile
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "bore.tar.gz"
            logger.info(f"Скачиваем: {url}")
            urllib.request.urlretrieve(url, archive)
            with tarfile.open(archive) as tf:
                tf.extractall(tmp)
            bore_bin = next(Path(tmp).rglob("bore"), None)
            if not bore_bin:
                return {"ok": False, "error": "bore не найден в архиве"}
            shutil.copy2(bore_bin, BORE_BIN)
            BORE_BIN.chmod(0o755)

        ver = _bore_version()
        logger.info(f"bore установлен: {ver}")
        return {"ok": True, "msg": f"bore установлен ({ver})"}

    except Exception as e:
        logger.exception("Ошибка установки bore")
        return {"ok": False, "error": str(e)}


def _bore_version() -> str:
    try:
        r = subprocess.run([str(BORE_BIN), "--version"], capture_output=True, text=True, timeout=5)
        return r.stdout.strip() or r.stderr.strip() or "?"
    except Exception:
        return "?"


# ---------------------------------------------------------------------------
# Запуск / остановка
# ---------------------------------------------------------------------------

def _load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {}


def _save_state(d: dict):
    CONFIG_DIR.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(d, indent=2, ensure_ascii=False))


def start(local_port: int,
          relay_host: str = DEFAULT_RELAY,
          relay_ctrl: int = DEFAULT_CTRL,
          secret: str     = "") -> dict:
    """Запустить bore-туннель. Возвращает {ok, endpoint} или {ok, error}."""
    global _proc, _endpoint

    with _lock:
        if _proc and _proc.poll() is None:
            return {"ok": True, "endpoint": _endpoint, "msg": "уже запущен"}

        if not BORE_BIN.exists():
            res = install_bore()
            if not res["ok"]:
                return res

        cmd = [str(BORE_BIN), "local", str(local_port),
               "--to", relay_host,
               "--port", str(relay_ctrl)]
        if secret:
            cmd += ["--secret", secret]

        logger.info(f"Запуск bore: {' '.join(cmd)}")
        try:
            _proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            return {"ok": False, "error": f"bore не найден: {BORE_BIN}"}

        _endpoint = None
        endpoint_event = threading.Event()

        def _reader():
            global _endpoint
            pattern = re.compile(r"listening at ([\w.\-]+:\d+)", re.IGNORECASE)
            for line in _proc.stdout:
                line = line.rstrip()
                logger.debug(f"[bore] {line}")
                m = pattern.search(line)
                if m and not _endpoint:
                    _endpoint = m.group(1)
                    logger.info(f"bore endpoint: {_endpoint}")
                    endpoint_event.set()
                    _save_state({
                        "running": True,
                        "endpoint": _endpoint,
                        "relay": relay_host,
                        "local_port": local_port,
                    })

        threading.Thread(target=_reader, daemon=True).start()

        # Ждём до 8 сек пока bore сообщит endpoint
        if endpoint_event.wait(timeout=8):
            return {"ok": True, "endpoint": _endpoint}
        else:
            if _proc.poll() is not None:
                return {"ok": False, "error": "bore завершился сразу — возможно, релей недоступен"}
            # Процесс живёт, но endpoint ещё не распарсился — вернём что есть
            return {"ok": True, "endpoint": None, "msg": "запущен, ждём endpoint..."}


def stop() -> dict:
    global _proc, _endpoint
    with _lock:
        if _proc and _proc.poll() is None:
            _proc.terminate()
            try:
                _proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                _proc.kill()
        _proc     = None
        _endpoint = None
        _save_state({"running": False})
    return {"ok": True}


# ---------------------------------------------------------------------------
# Статус
# ---------------------------------------------------------------------------

def get_status() -> dict:
    global _proc, _endpoint
    running = bool(_proc and _proc.poll() is None)

    if not running:
        # Читаем из файла состояния на случай перезапуска процесса
        st = _load_state()
        return {
            "running":     False,
            "endpoint":    None,
            "installed":   BORE_BIN.exists(),
            "relay":       st.get("relay", DEFAULT_RELAY),
            "local_port":  st.get("local_port"),
            "version":     _bore_version() if BORE_BIN.exists() else None,
        }

    return {
        "running":    True,
        "endpoint":   _endpoint,
        "installed":  True,
        "relay":      DEFAULT_RELAY,
        "version":    _bore_version(),
    }


def get_config() -> dict:
    st = _load_state()
    return {
        "relay":      st.get("relay",      DEFAULT_RELAY),
        "relay_ctrl": st.get("relay_ctrl", DEFAULT_CTRL),
        "secret":     st.get("secret",     ""),
    }
