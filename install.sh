#!/bin/bash
# =============================================================================
# Установщик tg-proxy: MTProto + AmneziaWG
# Поддерживаемые дистрибутивы:
#   Debian, Ubuntu, Kali, Linux Mint, Pop!_OS, Parrot OS,
#   MX Linux, Zorin OS, Elementary OS, Raspbian, Armbian и другие Debian-based
# Запуск: sudo bash install.sh [--no-systemd]
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

NO_SYSTEMD=false
for arg in "${@:-}"; do
  [[ "$arg" == "--no-systemd" ]] && NO_SYSTEMD=true
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/install.log"

log()    { echo -e "${CYAN}[*]${NC} $1" | tee -a "$LOG_FILE"; }
ok()     { echo -e "${GREEN}[✓]${NC} $1" | tee -a "$LOG_FILE"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE"; }
err()    { echo -e "${RED}[✗]${NC} $1" | tee -a "$LOG_FILE"; exit 1; }
section(){ echo -e "\n${BOLD}${CYAN}=== $1 ===${NC}" | tee -a "$LOG_FILE"; }

[[ "$EUID" -ne 0 ]] && err "Запускай с sudo: sudo bash install.sh"

echo "" > "$LOG_FILE"
section "tg-proxy installer"
log "Лог: $LOG_FILE"

# =============================================================================
# Определение дистрибутива
# =============================================================================
section "Определение дистрибутива"

[[ -f /etc/os-release ]] || err "Не найден /etc/os-release"
. /etc/os-release
DISTRO_ID="${ID:-unknown}"
DISTRO_LIKE="${ID_LIKE:-}"
DISTRO_NAME="${NAME:-unknown}"
DISTRO_CODENAME="${VERSION_CODENAME:-$(lsb_release -cs 2>/dev/null || echo 'stable')}"

IS_DEBIAN_BASED=false
for id in $DISTRO_ID $DISTRO_LIKE; do
  case "$id" in
    debian|ubuntu|kali|linuxmint|mint|pop|parrot|mx|zorin|elementary|\
    raspbian|armbian|neon|lmde|deepin|peppermint|bodhi|tails|whonix)
      IS_DEBIAN_BASED=true; break;;
  esac
done

[[ "$IS_DEBIAN_BASED" == "false" ]] && \
  err "Дистрибутив '$DISTRO_NAME' не поддерживается. Нужна Debian/Ubuntu-based система."

ARCH=$(uname -m)
KERNEL=$(uname -r)
ok "Дистрибутив: $DISTRO_NAME | Codename: $DISTRO_CODENAME | Arch: $ARCH | Kernel: $KERNEL"

# Флаг: Ubuntu-based дистрибутивы могут использовать PPA
IS_UBUNTU_BASED=false
for id in $DISTRO_ID $DISTRO_LIKE; do
  [[ "$id" == "ubuntu" ]] && IS_UBUNTU_BASED=true
done

# =============================================================================
# apt-get обновление
# =============================================================================
section "Обновление индекса пакетов"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq 2>&1 | tee -a "$LOG_FILE" || warn "apt-get update завершился с ошибками, продолжаем"

# =============================================================================
# Вспомогательная функция установки пакета
# =============================================================================
pkg_install() {
  local pkg="$1"
  if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
    ok "$pkg — уже установлен"
  else
    log "Устанавливаем: $pkg"
    apt-get install -y "$pkg" 2>&1 | tee -a "$LOG_FILE" || warn "Не удалось установить $pkg"
  fi
}

# =============================================================================
# Базовые пакеты
# =============================================================================
section "Базовые зависимости"

for pkg in \
  python3 python3-pip python3-venv python3-dev \
  curl wget git \
  iptables iproute2 net-tools \
  openssl ca-certificates \
  gnupg2 lsb-release software-properties-common \
  build-essential pkg-config libelf-dev
do
  pkg_install "$pkg"
done

# На Kali/Debian python-is-python3 может не быть — не страшно
apt-get install -y python-is-python3 2>/dev/null || true

# Починка pip если сломан (актуально для Kali и Parrot)
if ! python3 -m pip --version &>/dev/null 2>&1; then
  log "pip не отвечает, пробуем починить..."
  apt-get install -y --reinstall python3-pip 2>/dev/null || \
    curl -fsSL https://bootstrap.pypa.io/get-pip.py | python3 - 2>&1 | tee -a "$LOG_FILE" || \
    err "Не удалось настроить pip"
fi

ok "Базовые зависимости установлены"

# =============================================================================
# WireGuard tools
# =============================================================================
section "WireGuard tools"

if command -v wg &>/dev/null; then
  ok "wireguard-tools уже установлен"
else
  log "Устанавливаем wireguard-tools..."
  if ! apt-get install -y wireguard-tools 2>&1 | tee -a "$LOG_FILE"; then
    # Debian stretch/buster backports
    cat > /etc/apt/sources.list.d/wg-backports.list \
      << EOF
deb http://deb.debian.org/debian ${DISTRO_CODENAME}-backports main
EOF
    apt-get update -qq 2>/dev/null || true
    apt-get install -y -t "${DISTRO_CODENAME}-backports" wireguard-tools 2>&1 | \
      tee -a "$LOG_FILE" || warn "wireguard-tools не установлен через backports"
    rm -f /etc/apt/sources.list.d/wg-backports.list
    apt-get update -qq 2>/dev/null || true
  fi
  command -v wg &>/dev/null && ok "wireguard-tools установлен" || warn "wg не найден"
fi

# =============================================================================
# AmneziaWG
# =============================================================================
section "AmneziaWG"

AWG_OK=false

try_awg_apt() {
  log "[AWG] Попытка 1: официальный APT репозиторий amnezia.org..."
  local KEYRING="/usr/share/keyrings/amneziawg.gpg"
  local SRCLIST="/etc/apt/sources.list.d/amneziawg.list"
  rm -f "$KEYRING" "$SRCLIST" 2>/dev/null || true

  if curl -fsSL --connect-timeout 10 https://apt.amnezia.org/amneziawg.gpg -o /tmp/_awg.gpg 2>/dev/null; then
    if file /tmp/_awg.gpg | grep -qi "PGP"; then
      gpg --dearmor < /tmp/_awg.gpg > "$KEYRING" 2>/dev/null || cp /tmp/_awg.gpg "$KEYRING"
    else
      cp /tmp/_awg.gpg "$KEYRING"
    fi
    rm -f /tmp/_awg.gpg
    echo "deb [signed-by=${KEYRING}] https://apt.amnezia.org/ amneziawg main" > "$SRCLIST"
    apt-get update -qq 2>&1 | tee -a "$LOG_FILE" || true
    if apt-get install -y amneziawg amneziawg-tools 2>&1 | tee -a "$LOG_FILE"; then
      command -v awg &>/dev/null && { ok "[AWG] Установлен через официальный репозиторий"; return 0; }
    fi
    rm -f "$KEYRING" "$SRCLIST" 2>/dev/null || true
    apt-get update -qq 2>/dev/null || true
  fi
  return 1
}

try_awg_github_release() {
  log "[AWG] Попытка 2: бинарник с GitHub Releases..."
  local API="https://api.github.com/repos/amnezia-vpn/amneziawg-tools/releases/latest"
  local DL_URL

  DL_URL=$(curl -fsSL --connect-timeout 10 "$API" 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    arch_map = {'x86_64': ['amd64', 'x86_64'], 'aarch64': ['arm64', 'aarch64'], 'armv7l': ['armhf', 'armv7']}
    import platform
    machine = platform.machine()
    aliases = arch_map.get(machine, [machine])
    for a in data.get('assets', []):
        nm = a.get('name', '').lower()
        if 'linux' in nm and any(al in nm for al in aliases) and nm.endswith(('.tar.gz', '.zip', '.deb')):
            print(a['browser_download_url'])
            break
except: pass
" 2>/dev/null || echo "")

  [[ -z "$DL_URL" ]] && return 1

  local TMP=$(mktemp -d)
  if curl -fsSL --connect-timeout 30 "$DL_URL" -o "$TMP/awg-release" 2>/dev/null; then
    # .deb пакет
    if [[ "$DL_URL" == *.deb ]]; then
      dpkg -i "$TMP/awg-release" 2>&1 | tee -a "$LOG_FILE" || true
    else
      tar xzf "$TMP/awg-release" -C "$TMP" 2>/dev/null || \
        unzip -q "$TMP/awg-release" -d "$TMP" 2>/dev/null || true
      find "$TMP" -maxdepth 3 \( -name "awg" -o -name "awg-quick" \) -type f | while read -r f; do
        chmod +x "$f"
        cp "$f" /usr/local/bin/
        ok "[AWG] Скопирован $(basename $f) → /usr/local/bin/"
      done
    fi
  fi
  rm -rf "$TMP"
  command -v awg &>/dev/null && { ok "[AWG] Установлен из GitHub Release"; return 0; }
  return 1
}

try_awg_build() {
  log "[AWG] Попытка 3: сборка из исходников (только userspace)..."
  local BUILD=$(mktemp -d)

  # Устанавливаем заголовки ядра нужной версии
  local HEADERS="linux-headers-$(uname -r)"
  apt-get install -y "$HEADERS" 2>/dev/null || \
    apt-get install -y linux-headers-generic 2>/dev/null || \
    warn "Заголовки ядра не установлены, модуль не соберём"

  if git clone --depth=1 https://github.com/amnezia-vpn/amneziawg-tools.git \
       "$BUILD/awg-tools" 2>&1 | tee -a "$LOG_FILE"; then
    cd "$BUILD/awg-tools/src" 2>/dev/null || cd "$BUILD/awg-tools" 2>/dev/null
    if make 2>&1 | tee -a "$LOG_FILE"; then
      find . -maxdepth 2 -name "awg" -type f -exec cp {} /usr/local/bin/awg \; 2>/dev/null || true
      find . -maxdepth 2 -name "awg-quick" -type f -exec cp {} /usr/local/bin/awg-quick \; 2>/dev/null || true
      chmod +x /usr/local/bin/awg /usr/local/bin/awg-quick 2>/dev/null || true
    fi
    cd "$SCRIPT_DIR"
  fi
  rm -rf "$BUILD"
  command -v awg &>/dev/null && { ok "[AWG] Собран из исходников"; return 0; }
  return 1
}

if command -v awg &>/dev/null; then
  ok "AmneziaWG уже установлен"
  AWG_OK=true
else
  try_awg_apt          && AWG_OK=true || \
  try_awg_github_release && AWG_OK=true || \
  try_awg_build        && AWG_OK=true || true

  if [[ "$AWG_OK" == "false" ]]; then
    warn "AmneziaWG не установлен. Используем WireGuard как fallback."
    warn "Без AmneziaWG junk-параметры обфускации не работают — DPI может детектировать трафик."
    warn "Инструкция по ручной установке: https://github.com/amnezia-vpn/amneziawg-tools"
    pkg_install wireguard 2>/dev/null || true
    if command -v wg &>/dev/null && ! command -v awg &>/dev/null; then
      ln -sf "$(which wg)" /usr/local/bin/awg 2>/dev/null || true
      ln -sf "$(which wg-quick)" /usr/local/bin/awg-quick 2>/dev/null || true
      warn "Создан symlink: awg → wg (fallback режим)"
    fi
  fi
fi

# =============================================================================
# ip_forward
# =============================================================================
section "Сетевые параметры"
grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf 2>/dev/null && \
  sed -i 's/^.*net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf || \
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1 &>/dev/null || true
ok "ip_forward=1"

# =============================================================================
# Python venv
# =============================================================================
section "Python виртуальное окружение"

VENV="$SCRIPT_DIR/venv"

[[ -d "$VENV" ]] || python3 -m venv "$VENV" 2>&1 | tee -a "$LOG_FILE" || \
  err "Не удалось создать venv. Проверь: sudo apt install python3-venv"

log "Обновляем pip..."
"$VENV/bin/pip" install --quiet --upgrade pip 2>&1 | tee -a "$LOG_FILE" || true

log "Устанавливаем зависимости Python..."
"$VENV/bin/pip" install --quiet \
  flask \
  flask-socketio \
  "qrcode[pil]" \
  Pillow \
  cryptography \
  psutil \
  2>&1 | tee -a "$LOG_FILE" || err "Ошибка установки Python-пакетов"

ok "Python venv готов: $VENV"

# =============================================================================
# mtprotoproxy
# =============================================================================
section "mtprotoproxy"

MTPROTO="$SCRIPT_DIR/mtprotoproxy"
if [[ -d "$MTPROTO" ]]; then
  git -C "$MTPROTO" pull --quiet 2>&1 | tee -a "$LOG_FILE" || warn "git pull не удался"
  ok "mtprotoproxy обновлён"
else
  git clone --depth=1 https://github.com/alexbers/mtprotoproxy.git "$MTPROTO" \
    2>&1 | tee -a "$LOG_FILE" || err "Не удалось клонировать mtprotoproxy"
  ok "mtprotoproxy скачан"
fi

# =============================================================================
# Директории
# =============================================================================
mkdir -p "$SCRIPT_DIR"/{config,logs}
chmod 700 "$SCRIPT_DIR/config"
ok "Директории подготовлены"

# =============================================================================
# Systemd сервис
# =============================================================================
if [[ "$NO_SYSTEMD" == "false" ]] && \
   command -v systemctl &>/dev/null && \
   systemctl is-system-running &>/dev/null 2>&1; then

  section "Systemd сервис"
  VENV_PY="$VENV/bin/python3"

  cat > /etc/systemd/system/tg-proxy.service << EOF
[Unit]
Description=Telegram MTProto Proxy with AmneziaWG
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${VENV_PY} ${SCRIPT_DIR}/main.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tg-proxy

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  ok "Systemd-сервис: tg-proxy.service"
  log "Автозапуск: sudo systemctl enable tg-proxy"
  log "Запуск:     sudo systemctl start tg-proxy"
fi

# =============================================================================
# Итог
# =============================================================================
section "Готово"

echo ""
printf "  %-20s %s\n" "Python3:"      "$(python3 --version 2>/dev/null || echo 'не найден')"
printf "  %-20s %s\n" "WireGuard:"    "$(command -v wg &>/dev/null && echo 'установлен' || echo 'не найден')"
printf "  %-20s %s\n" "AmneziaWG:"    "$(command -v awg &>/dev/null && echo 'установлен' || echo 'fallback (wg)')"
printf "  %-20s %s\n" "mtprotoproxy:" "$MTPROTO"
printf "  %-20s %s\n" "venv:"         "$VENV"
echo ""
echo -e "${BOLD}Запуск:${NC}"
echo -e "  ${CYAN}sudo $VENV/bin/python3 $SCRIPT_DIR/main.py${NC}"
echo -e "  Открой в браузере: ${CYAN}http://localhost:8080${NC}"
echo ""
