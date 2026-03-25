"""
awg_manager.py — управление AmneziaWG/WireGuard туннелем.

Ключевые изменения:
- Импорт конфига Cloudflare WARP (paste & go)
- Фикс маршрутизации: прокси-процесс идёт через туннель,
  но сам биндинг на порт и приём входящих соединений — через основной интерфейс
- Preshared key — полностью опционален
"""

import os
import re
import random
import subprocess
import logging
import configparser
import ipaddress
from pathlib import Path
from typing import Optional

logger = logging.getLogger("awg_manager")

SCRIPT_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR  = SCRIPT_DIR / "config"
AWG_CONF    = CONFIG_DIR / "awg0.conf"

IFACE       = "awg0"
FWMARK      = "51822"        # метка для трафика прокси через туннель
RT_TABLE    = "51822"        # отдельная таблица маршрутизации


# ---------------------------------------------------------------------------
# Поиск бинарников
# ---------------------------------------------------------------------------

def _find_bin(name: str) -> str:
    import shutil
    for path in [f"/usr/local/bin/{name}", f"/usr/bin/{name}", f"/sbin/{name}"]:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return shutil.which(name) or name


AWG_BIN       = _find_bin("awg")
AWG_QUICK_BIN = _find_bin("awg-quick")
WG_BIN        = _find_bin("wg")
IS_AMNEZIA    = os.path.basename(os.path.realpath(AWG_BIN)) not in ("wg", "wg-quick")


# ---------------------------------------------------------------------------
# Генерация ключей
# ---------------------------------------------------------------------------

def generate_privkey() -> str:
    if os.path.isfile(WG_BIN):
        try:
            return subprocess.run([WG_BIN, "genkey"], capture_output=True,
                                  text=True, check=True).stdout.strip()
        except Exception:
            pass
    import base64, secrets
    raw = list(secrets.token_bytes(32))
    raw[0] &= 248; raw[31] &= 127; raw[31] |= 64
    return base64.b64encode(bytes(raw)).decode()


def derive_pubkey(privkey: str) -> str:
    if os.path.isfile(WG_BIN):
        try:
            return subprocess.run(
                [WG_BIN, "pubkey"], input=privkey,
                capture_output=True, text=True, check=True
            ).stdout.strip()
        except Exception:
            pass
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    import base64
    priv = X25519PrivateKey.from_private_bytes(base64.b64decode(privkey))
    return base64.b64encode(priv.public_key().public_bytes_raw()).decode()


# ---------------------------------------------------------------------------
# Junk-параметры обфускации AmneziaWG
# ---------------------------------------------------------------------------

def _random_junk() -> dict:
    """
    Случайные Jc/Jmin/Jmax/S1/S2/H1-H4.
    Дефолтные WG magic-байты намеренно исключены из диапазона H1-H4 —
    именно это делает трафик неузнаваемым для ТСПУ.
    """
    WG_MAGIC = {0x01000000, 0x02000000, 0x03000000, 0x04000000}
    def rh():
        while True:
            v = random.randint(5, 2**32 - 1)
            if v not in WG_MAGIC:
                return v
    jmin = random.randint(10, 50)
    return {
        "Jc":   random.randint(3, 10),
        "Jmin": jmin,
        "Jmax": random.randint(jmin + 10, min(jmin + 100, 1280)),
        "S1":   random.randint(15, 150),
        "S2":   random.randint(15, 150),
        "H1":   rh(), "H2": rh(), "H3": rh(), "H4": rh(),
    }


# ---------------------------------------------------------------------------
# Импорт конфига Cloudflare WARP
# ---------------------------------------------------------------------------

def parse_warp_config(text: str) -> dict:
    """
    Парсит warp/wireguard конфиг в формате INI ([Interface] + [Peer]).
    Возвращает dict с полями: server_ip, server_port, server_pubkey,
    client_privkey, preshared_key (может быть None), dns, address.

    WARP-конфиг выглядит так:
        [Interface]
        PrivateKey = ...
        Address    = 172.16.0.2/32
        DNS        = 1.1.1.1

        [Peer]
        PublicKey  = ...
        Endpoint   = engage.cloudflareclient.com:2408
        AllowedIPs = 0.0.0.0/0
    """
    # configparser не любит дублирующиеся секции — читаем вручную
    current = None
    iface = {}
    peer  = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower() == "[interface]":
            current = iface; continue
        if line.lower() == "[peer]":
            current = peer; continue
        if "=" in line and current is not None:
            key, _, val = line.partition("=")
            current[key.strip()] = val.strip()

    # --- Разбираем Endpoint ---
    endpoint = peer.get("Endpoint", "")
    server_ip   = ""
    server_port = 2408  # дефолт WARP

    if endpoint:
        # Формат: host:port или [ipv6]:port
        m = re.match(r"^(.+):(\d+)$", endpoint)
        if m:
            server_ip   = m.group(1).strip("[]")
            server_port = int(m.group(2))

    result = {
        "server_ip":      server_ip,
        "server_port":    server_port,
        "server_pubkey":  peer.get("PublicKey", ""),
        "client_privkey": iface.get("PrivateKey", ""),
        "preshared_key":  peer.get("PresharedKey") or None,
        "dns":            iface.get("DNS", "1.1.1.1").split(",")[0].strip(),
        "address":        iface.get("Address", "10.66.66.2/32"),
        "allowed_ips":    peer.get("AllowedIPs", "0.0.0.0/0"),
    }

    # Базовая валидация
    errors = []
    if not result["server_ip"]:
        errors.append("Не найден Endpoint в [Peer]")
    if not result["server_pubkey"]:
        errors.append("Не найден PublicKey в [Peer]")
    if errors:
        raise ValueError("; ".join(errors))

    return result


# ---------------------------------------------------------------------------
# Генерация / импорт конфига
# ---------------------------------------------------------------------------

def _split_routes(server_ip: str) -> str:
    """0.0.0.0/0 минус IP сервера — чтобы не потерять сам туннель."""
    try:
        full    = ipaddress.ip_network("0.0.0.0/0")
        exclude = ipaddress.ip_network(f"{server_ip}/32")
        return ", ".join(str(r) for r in full.address_exclude(exclude))
    except Exception:
        return "0.0.0.0/0"


def _build_postup_predown(proxy_port: int) -> tuple[list[str], list[str]]:
    """
    Правила iptables для корректной маршрутизации:

    Проблема: при AllowedIPs=0.0.0.0/0 весь трафик идёт в туннель,
    включая трафик самого прокси-процесса при старте (он не может
    достучаться до ничего снаружи туннеля).

    Решение: используем отдельную таблицу маршрутизации + fwmark.
    - Трафик прокси (исходящий на Telegram) помечается маркером → идёт в туннель
    - Входящие соединения от клиентов и биндинг на порт — через основной интерфейс
    - SSH и GUI — без изменений

    Важно: прокси СЛУШАЕТ на порту proxy_port — это ВХОДЯЩИЙ трафик,
    он не должен попадать под правила туннеля.
    """
    up = [
        # Создаём отдельную таблицу маршрутизации для туннеля
        f"ip rule  add fwmark {FWMARK} table {RT_TABLE} priority 100 2>/dev/null || true",
        f"ip route add default dev {IFACE} table {RT_TABLE} 2>/dev/null || true",
        # Весь ИСХОДЯЩИЙ трафик (кроме уже помеченного и loopback) → через туннель
        # НО: не трогаем входящие соединения (PREROUTING/INPUT) и биндинг на порт
        f"iptables -t mangle -A OUTPUT ! -o lo -m mark ! --mark {FWMARK} -j MARK --set-mark {FWMARK} 2>/dev/null || true",
        # Исключаем трафик, адресованный самому себе (GUI :8080, SSH)
        f"iptables -t mangle -A OUTPUT -d 127.0.0.0/8 -j MARK --set-mark 0 2>/dev/null || true",
        # Исключаем исходящий трафик к локальной сети
        f"iptables -t mangle -A OUTPUT -d 10.0.0.0/8 -j MARK --set-mark 0 2>/dev/null || true",
        f"iptables -t mangle -A OUTPUT -d 192.168.0.0/16 -j MARK --set-mark 0 2>/dev/null || true",
        f"iptables -t mangle -A OUTPUT -d 172.16.0.0/12 -j MARK --set-mark 0 2>/dev/null || true",
        # Исключаем входящие → ответы (ESTABLISHED/RELATED) — не трогать
        f"iptables -t mangle -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j MARK --set-mark 0 2>/dev/null || true",
    ]
    down = [
        f"ip rule  del fwmark {FWMARK} table {RT_TABLE} 2>/dev/null || true",
        f"ip route flush table {RT_TABLE} 2>/dev/null || true",
        f"iptables -t mangle -F OUTPUT 2>/dev/null || true",
    ]
    return up, down


def generate_config(
    server_ip: str,
    server_port: int,
    server_pubkey: str,
    preshared_key: Optional[str] = None,
    client_privkey: Optional[str] = None,
    dns: str = "1.1.1.1",
    address: str = "10.66.66.2/32",
    proxy_port: int = 8443,
    mtu: int = 1280,
) -> dict:
    """
    Генерирует конфиг AWG/WG.
    client_privkey: если передан (из WARP), используем его; иначе генерируем новый.
    preshared_key:  полностью опционален — None = не включать в конфиг.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    privkey = client_privkey or generate_privkey()
    pubkey  = derive_pubkey(privkey)
    allowed = _split_routes(server_ip)
    junk    = _random_junk() if IS_AMNEZIA else {}
    postup, predown = _build_postup_predown(proxy_port)

    lines = [
        "[Interface]",
        f"PrivateKey = {privkey}",
        f"Address    = {address}",
        f"DNS        = {dns}",
        f"MTU        = {mtu}",
    ]

    if junk:
        for k, v in junk.items():
            lines.append(f"{k} = {v}")

    for rule in postup:
        lines.append(f"PostUp  = {rule}")
    for rule in predown:
        lines.append(f"PreDown = {rule}")

    lines += [
        "",
        "[Peer]",
        f"PublicKey  = {server_pubkey}",
    ]
    # preshared key ТОЛЬКО если передан непустой
    if preshared_key and preshared_key.strip():
        lines.append(f"PresharedKey = {preshared_key.strip()}")

    lines += [
        f"Endpoint   = {server_ip}:{server_port}",
        f"AllowedIPs = {allowed}",
        "PersistentKeepalive = 25",
    ]

    conf_text = "\n".join(lines) + "\n"
    AWG_CONF.write_text(conf_text)
    AWG_CONF.chmod(0o600)

    logger.info(f"AWG конфиг сохранён: {AWG_CONF} | AmneziaWG={IS_AMNEZIA}")

    return {
        "ok":           True,
        "privkey":      privkey,
        "pubkey":       pubkey,
        "server_ip":    server_ip,
        "server_port":  server_port,
        "junk_params":  junk,
        "is_amnezia":   IS_AMNEZIA,
        "config_path":  str(AWG_CONF),
    }


def import_warp_and_generate(warp_text: str, proxy_port: int = 8443) -> dict:
    """
    Высокоуровневый метод: принимает raw текст WARP/WG конфига,
    парсит его и генерирует финальный конфиг с junk-параметрами.
    """
    parsed = parse_warp_config(warp_text)
    result = generate_config(
        server_ip      = parsed["server_ip"],
        server_port    = parsed["server_port"],
        server_pubkey  = parsed["server_pubkey"],
        preshared_key  = parsed.get("preshared_key"),
        client_privkey = parsed.get("client_privkey"),
        dns            = parsed.get("dns", "1.1.1.1"),
        address        = parsed.get("address", "10.66.66.2/32"),
        proxy_port     = proxy_port,
    )
    result["source"] = "warp"
    result["endpoint_original"] = f"{parsed['server_ip']}:{parsed['server_port']}"
    return result


# ---------------------------------------------------------------------------
# Управление туннелем
# ---------------------------------------------------------------------------

def _run(*cmd, check=False) -> subprocess.CompletedProcess:
    return subprocess.run(list(cmd), capture_output=True, text=True, check=check)


def start_tunnel() -> dict:
    if not AWG_CONF.exists():
        return {"ok": False, "error": "Конфиг не найден. Сначала настрой или импортируй конфиг."}

    stop_tunnel(silent=True)

    # Пробуем awg-quick, потом wg-quick как fallback
    for quick in (AWG_QUICK_BIN, "awg-quick", "wg-quick"):
        try:
            r = _run(quick, "up", str(AWG_CONF))
            if r.returncode == 0:
                logger.info(f"Туннель поднят через {quick}")
                return {"ok": True, "output": r.stdout}
        except FileNotFoundError:
            continue

    err = r.stderr or r.stdout or "awg-quick/wg-quick не найден"
    logger.error(f"Ошибка старта туннеля: {err}")
    return {"ok": False, "error": err}


def stop_tunnel(silent: bool = False) -> dict:
    if AWG_CONF.exists():
        for quick in (AWG_QUICK_BIN, "awg-quick", "wg-quick"):
            try:
                r = _run(quick, "down", str(AWG_CONF))
                if r.returncode == 0:
                    return {"ok": True}
            except FileNotFoundError:
                continue

    # Fallback: ip link delete
    _run("ip", "link", "delete", IFACE)
    # Чистим правила маршрутизации вручную
    _run("ip", "rule",  "del", "fwmark", FWMARK, "table", RT_TABLE)
    _run("ip", "route", "flush", "table", RT_TABLE)
    _run("iptables", "-t", "mangle", "-F", "OUTPUT")

    return {"ok": True}


def get_status() -> dict:
    iface_up = _run("ip", "link", "show", IFACE).returncode == 0

    base = {"running": iface_up, "iface": IFACE, "is_amnezia": IS_AMNEZIA}
    if not iface_up:
        return base

    info = {**base, "endpoint": "", "last_handshake": ""}
    try:
        out = _run(AWG_BIN, "show", IFACE).stdout
        m = re.search(r"endpoint:\s+(\S+)", out)
        if m: info["endpoint"] = m.group(1)
        m = re.search(r"latest handshake:\s+(.+)", out)
        if m: info["last_handshake"] = m.group(1).strip()
    except Exception:
        pass

    info.update(get_traffic())
    return info


def get_traffic() -> dict:
    result = {"rx_bytes": 0, "tx_bytes": 0, "rx_human": "0 B", "tx_human": "0 B"}
    try:
        rx = int(Path(f"/sys/class/net/{IFACE}/statistics/rx_bytes").read_text())
        tx = int(Path(f"/sys/class/net/{IFACE}/statistics/tx_bytes").read_text())
        result.update(rx_bytes=rx, tx_bytes=tx,
                      rx_human=_hb(rx), tx_human=_hb(tx))
    except Exception:
        pass
    return result


def _hb(n: int) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"


def get_config_info() -> dict:
    if not AWG_CONF.exists():
        return {"exists": False}
    try:
        text = AWG_CONF.read_text()
        info = {"exists": True, "is_amnezia": IS_AMNEZIA}
        for key in ("Endpoint", "PublicKey", "Jc", "Jmin", "Jmax", "Address", "DNS"):
            m = re.search(rf"^{key}\s*=\s*(.+)", text, re.MULTILINE | re.IGNORECASE)
            if m:
                info[key.lower()] = m.group(1).strip()
        return info
    except Exception:
        return {"exists": True, "error": "Не удалось прочитать конфиг"}
