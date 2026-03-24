"""
awg_manager.py — управление AmneziaWG/WireGuard туннелем.
Генерирует конфиг с рандомными junk-параметрами обфускации,
поднимает/опускает туннель, читает статус и трафик.
"""

import os
import re
import random
import subprocess
import logging
import ipaddress
from pathlib import Path
from typing import Optional

logger = logging.getLogger("awg_manager")

SCRIPT_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR  = SCRIPT_DIR / "config"
AWG_CONF    = CONFIG_DIR / "awg0.conf"

# Имя интерфейса
IFACE = "awg0"


# ---------------------------------------------------------------------------
# Определение доступного бинарника (awg или wg как fallback)
# ---------------------------------------------------------------------------

def _find_bin(name: str) -> str:
    """Ищем бинарник в PATH и /usr/local/bin."""
    for path in [f"/usr/local/bin/{name}", f"/usr/bin/{name}", f"/sbin/{name}"]:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    # shutil.which
    import shutil
    found = shutil.which(name)
    return found or name


AWG_BIN       = _find_bin("awg")
AWG_QUICK_BIN = _find_bin("awg-quick")
WG_BIN        = _find_bin("wg")

# Флаг: настоящий AmneziaWG или fallback WireGuard
IS_AMNEZIA = os.path.basename(os.path.realpath(AWG_BIN)) != "wg"


# ---------------------------------------------------------------------------
# Генерация ключей
# ---------------------------------------------------------------------------

def _run(cmd: list[str], check=True, capture=True) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        check=check
    )


def generate_privkey() -> str:
    """Генерируем WireGuard private key."""
    if os.path.isfile(WG_BIN):
        try:
            r = _run([WG_BIN, "genkey"])
            return r.stdout.strip()
        except Exception:
            pass
    # Fallback через openssl
    import base64, secrets
    raw = secrets.token_bytes(32)
    # Зажимаем биты как в Curve25519
    raw_list = list(raw)
    raw_list[0]  &= 248
    raw_list[31] &= 127
    raw_list[31] |= 64
    return base64.b64encode(bytes(raw_list)).decode()


def derive_pubkey(privkey: str) -> str:
    """Из приватного ключа получаем публичный."""
    if os.path.isfile(WG_BIN):
        try:
            r = subprocess.run(
                [WG_BIN, "pubkey"],
                input=privkey,
                capture_output=True,
                text=True,
                check=True
            )
            return r.stdout.strip()
        except Exception:
            pass
    # Fallback: cryptography
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    import base64
    raw = base64.b64decode(privkey)
    priv_obj = X25519PrivateKey.from_private_bytes(raw)
    pub_raw  = priv_obj.public_key().public_bytes_raw()
    return base64.b64encode(pub_raw).decode()


def generate_preshared_key() -> str:
    """Генерируем preshared key."""
    if os.path.isfile(WG_BIN):
        try:
            r = _run([WG_BIN, "genpsk"])
            return r.stdout.strip()
        except Exception:
            pass
    import base64, secrets
    return base64.b64encode(secrets.token_bytes(32)).decode()


# ---------------------------------------------------------------------------
# Рандомные параметры обфускации AmneziaWG
# ---------------------------------------------------------------------------

def _random_awg_junk() -> dict:
    """
    Генерируем случайные Jc/Jmin/Jmax/S1/S2/H1-H4.
    Это ключевые параметры, которые делают трафик AWG
    неотличимым от случайных байт для DPI-систем (ТСПУ).

    Стандартные значения WireGuard намеренно исключаются из диапазона H1-H4,
    чтобы fingerprint отличался от дефолтного WG.
    """
    # Стандартные magic bytes WireGuard (исключаем их из H1-H4)
    WG_MAGIC = {0x01000000, 0x02000000, 0x03000000, 0x04000000}

    def rand_header() -> int:
        while True:
            v = random.randint(5, 2**32 - 1)
            if v not in WG_MAGIC:
                return v

    jc   = random.randint(3, 10)
    jmin = random.randint(10, 50)
    jmax = random.randint(jmin + 10, min(jmin + 100, 1280))

    return {
        "Jc":   jc,
        "Jmin": jmin,
        "Jmax": jmax,
        "S1":   random.randint(15, 150),
        "S2":   random.randint(15, 150),
        "H1":   rand_header(),
        "H2":   rand_header(),
        "H3":   rand_header(),
        "H4":   rand_header(),
    }


# ---------------------------------------------------------------------------
# Генерация конфига
# ---------------------------------------------------------------------------

def generate_config(
    server_ip: str,
    server_port: int,
    server_pubkey: str,
    preshared_key: Optional[str] = None,
    dns: str = "1.1.1.1",
    mtu: int = 1280
) -> dict:
    """
    Генерирует конфиг AWG/WG и сохраняет в CONFIG_DIR/awg0.conf.
    Возвращает словарь с параметрами (включая privkey/pubkey клиента).

    AllowedIPs = 0.0.0.0/0 с исключением серверного IP — split-tunneling:
    трафик прокси идёт через туннель, SSH/GUI остаются доступны.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    privkey = generate_privkey()
    pubkey  = derive_pubkey(privkey)

    # Исключаем серверный IP из туннеля, чтобы не потерять связь
    allowed = _split_tunnel_routes(server_ip)

    junk = _random_awg_junk() if IS_AMNEZIA else {}

    lines = ["[Interface]"]
    lines.append(f"PrivateKey = {privkey}")
    lines.append(f"Address = 10.66.66.2/32")
    lines.append(f"DNS = {dns}")
    lines.append(f"MTU = {mtu}")

    # AmneziaWG-специфичные параметры
    if junk:
        for key, val in junk.items():
            lines.append(f"{key} = {val}")

    # PostUp/PreDown: маршрутизируем через туннель только нужный трафик
    lines.append(f"PostUp = ip rule add fwmark 51820 table 51820 2>/dev/null || true")
    lines.append(f"PostUp = ip route add default dev {IFACE} table 51820 2>/dev/null || true")
    lines.append(f"PostUp = iptables -t mangle -A OUTPUT -p tcp --dport 443 -j MARK --set-mark 51820 2>/dev/null || true")
    lines.append(f"PreDown = ip rule del fwmark 51820 table 51820 2>/dev/null || true")
    lines.append(f"PreDown = ip route flush table 51820 2>/dev/null || true")
    lines.append(f"PreDown = iptables -t mangle -D OUTPUT -p tcp --dport 443 -j MARK --set-mark 51820 2>/dev/null || true")

    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server_pubkey}")
    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")
    lines.append(f"Endpoint = {server_ip}:{server_port}")
    lines.append(f"AllowedIPs = {allowed}")
    lines.append("PersistentKeepalive = 25")

    conf_text = "\n".join(lines) + "\n"

    # Сохраняем с правами 600 (содержит private key)
    AWG_CONF.write_text(conf_text)
    AWG_CONF.chmod(0o600)

    logger.info(f"Конфиг AWG сохранён: {AWG_CONF}")
    if junk:
        logger.info(f"Параметры обфускации: {junk}")

    return {
        "privkey":     privkey,
        "pubkey":      pubkey,
        "server_ip":   server_ip,
        "server_port": server_port,
        "junk_params": junk,
        "is_amnezia":  IS_AMNEZIA,
        "config_path": str(AWG_CONF),
    }


def _split_tunnel_routes(server_ip: str) -> str:
    """
    Возвращает AllowedIPs так, чтобы исключить serverIP
    (весь трафик через туннель, кроме самого хоста VPN-сервера).
    Это предотвращает разрыв самого туннеля.
    """
    try:
        # Делаем 0.0.0.0/0 минус server_ip/32
        full = ipaddress.ip_network("0.0.0.0/0")
        exclude = ipaddress.ip_network(f"{server_ip}/32")
        routes = [str(r) for r in full.address_exclude(exclude)]
        return ", ".join(routes)
    except Exception:
        return "0.0.0.0/0"


# ---------------------------------------------------------------------------
# Управление туннелем
# ---------------------------------------------------------------------------

def _conf_exists() -> bool:
    return AWG_CONF.exists()


def start_tunnel() -> dict:
    """Поднимаем AWG туннель."""
    if not _conf_exists():
        return {"ok": False, "error": "Конфиг не найден. Сначала сгенерируй его."}

    # Убиваем старый интерфейс если есть
    stop_tunnel(silent=True)

    cmd = [AWG_QUICK_BIN, "up", str(AWG_CONF)]
    try:
        r = _run(cmd, check=False)
        if r.returncode != 0:
            # Попытка 2: через системный путь
            r = subprocess.run(
                ["awg-quick", "up", str(AWG_CONF)],
                capture_output=True, text=True
            )
        if r.returncode == 0:
            logger.info("AWG туннель поднят")
            return {"ok": True, "output": r.stdout}
        else:
            err_msg = r.stderr or r.stdout or "Неизвестная ошибка"
            logger.error(f"Ошибка старта AWG: {err_msg}")
            return {"ok": False, "error": err_msg}
    except FileNotFoundError:
        return {"ok": False, "error": f"Не найден awg-quick. Установлен ли AmneziaWG?"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def stop_tunnel(silent: bool = False) -> dict:
    """Опускаем AWG туннель."""
    # Сначала через awg-quick down
    if _conf_exists():
        try:
            r = subprocess.run(
                [AWG_QUICK_BIN, "down", str(AWG_CONF)],
                capture_output=True, text=True
            )
            if r.returncode == 0:
                logger.info("AWG туннель остановлен")
                return {"ok": True}
        except Exception:
            pass

    # Fallback: ip link delete
    try:
        subprocess.run(["ip", "link", "delete", IFACE],
                       capture_output=True, check=False)
        return {"ok": True}
    except Exception as e:
        if not silent:
            return {"ok": False, "error": str(e)}
        return {"ok": False, "error": ""}


def get_status() -> dict:
    """Читаем статус туннеля через `awg show`."""
    # Проверяем наличие интерфейса
    iface_up = False
    try:
        r = subprocess.run(["ip", "link", "show", IFACE],
                           capture_output=True, text=True)
        iface_up = r.returncode == 0 and "UP" in r.stdout
    except Exception:
        pass

    if not iface_up:
        return {
            "running":    False,
            "iface":      IFACE,
            "is_amnezia": IS_AMNEZIA,
            "awg_bin":    AWG_BIN,
        }

    info = {
        "running":    True,
        "iface":      IFACE,
        "is_amnezia": IS_AMNEZIA,
        "awg_bin":    AWG_BIN,
        "endpoint":   "",
        "last_handshake": "",
    }

    try:
        r = subprocess.run([AWG_BIN, "show", IFACE],
                           capture_output=True, text=True)
        out = r.stdout

        m = re.search(r"endpoint:\s+(\S+)", out)
        if m: info["endpoint"] = m.group(1)

        m = re.search(r"latest handshake:\s+(.+)", out)
        if m: info["last_handshake"] = m.group(1).strip()
    except Exception:
        pass

    traffic = get_traffic()
    info.update(traffic)
    return info


def get_traffic() -> dict:
    """Читаем rx/tx байты с интерфейса."""
    result = {"rx_bytes": 0, "tx_bytes": 0, "rx_human": "0 B", "tx_human": "0 B"}
    try:
        rx_path = f"/sys/class/net/{IFACE}/statistics/rx_bytes"
        tx_path = f"/sys/class/net/{IFACE}/statistics/tx_bytes"
        if os.path.exists(rx_path):
            result["rx_bytes"] = int(Path(rx_path).read_text().strip())
            result["tx_bytes"] = int(Path(tx_path).read_text().strip())
            result["rx_human"] = _human_bytes(result["rx_bytes"])
            result["tx_human"] = _human_bytes(result["tx_bytes"])
    except Exception:
        pass
    return result


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def get_config_info() -> dict:
    """Возвращаем параметры текущего конфига (без приватного ключа)."""
    if not _conf_exists():
        return {"exists": False}
    try:
        text = AWG_CONF.read_text()
        info = {"exists": True, "is_amnezia": IS_AMNEZIA}
        for key in ("Endpoint", "PublicKey", "Jc", "Jmin", "Jmax"):
            m = re.search(rf"^{key}\s*=\s*(.+)", text, re.MULTILINE)
            if m:
                info[key.lower()] = m.group(1).strip()
        return info
    except Exception:
        return {"exists": True, "error": "Не удалось прочитать конфиг"}
