# tg-proxy

**MTProto-прокси для Telegram** с туннелированием через **AmneziaWG** и веб-интерфейсом.  
Оптимизирован для работы в РФ: fake-tls маскировка + obfuscation через AmneziaWG.

## Поддерживаемые системы

| Дистрибутив | Статус |
|---|---|
| Ubuntu 20.04 / 22.04 / 24.04 | ✅ |
| Debian 11 / 12 | ✅ |
| Kali Linux (rolling) | ✅ |
| Linux Mint 21+ | ✅ |
| Pop!_OS 22.04+ | ✅ |
| Parrot OS | ✅ |
| MX Linux | ✅ |
| Zorin OS | ✅ |
| Elementary OS | ✅ |
| Raspberry Pi OS (Debian-based) | ✅ |

## Требования

- Linux (Debian/Ubuntu-based)
- Python 3.9+
- Root-доступ (для управления сетевыми интерфейсами)
- Интернет-соединение (для установки зависимостей)

## Быстрый старт

```bash
# 1. Клонировать репозиторий
git clone <repo-url> tg-proxy
cd tg-proxy

# 2. Установка зависимостей (нужен sudo)
sudo bash install.sh

# 3. Запуск
sudo ./venv/bin/python3 main.py

# 4. Открыть в браузере
# http://localhost:8080
```

## Использование

### Через веб-интерфейс

1. Открой `http://localhost:8080`
2. В блоке **AmneziaWG туннель** введи данные своего AWG-сервера:
   - IP сервера
   - Порт (рекомендуем случайный из диапазона 49152–65535, **не 51820**)
   - Public Key сервера
   - Preshared Key (если есть)
3. Нажми **«Сгенерировать и применить конфиг»**
4. Нажми **«Поднять туннель»**
5. В блоке **MTProto прокси** выбери TLS-домен (или оставь авто)
6. Нажми **«Старт»**
7. Скопируй ссылку или отсканируй QR — добавь в Telegram

### Через командную строку

```bash
# Запуск с параметрами
sudo ./venv/bin/python3 main.py --host 127.0.0.1 --port 8080

# Без автооткрытия браузера
sudo ./venv/bin/python3 main.py --no-open

# Через systemd (после install.sh)
sudo systemctl start tg-proxy
sudo systemctl enable tg-proxy  # автозапуск
sudo journalctl -u tg-proxy -f  # логи
```

## Архитектура

```
Telegram-клиент
      │
      ▼ TCP :443 (fake-tls → маскируется под HTTPS)
┌─────────────────┐
│  mtprotoproxy   │  ← запускается на этой машине
└────────┬────────┘
         │ весь трафик через awg0
         ▼
┌─────────────────┐
│   AmneziaWG     │  ← obfuscated WireGuard туннель
│   (awg0)        │    Jc/Jmin/Jmax/S1/S2/H1-H4 случайные
└────────┬────────┘
         │
         ▼
   VPN-сервер (за рубежом)
         │
         ▼
   Telegram серверы
```

## Параметры обфускации AmneziaWG

При каждой генерации конфига создаются уникальные junk-параметры:

| Параметр | Описание |
|---|---|
| `Jc` | Количество junk-пакетов (3–10) |
| `Jmin/Jmax` | Размер junk-пакетов в байтах |
| `S1/S2` | Размер мусора в init/response пакетах |
| `H1–H4` | Magic bytes заголовков (не совпадают с дефолтным WG) |

Именно нестандартные значения этих параметров делают трафик неузнаваемым для ТСПУ.

## Структура проекта

```
tg-proxy/
├── install.sh          # установщик
├── main.py             # точка входа
├── core/
│   ├── awg_manager.py  # AmneziaWG: генерация конфига, управление туннелем
│   ├── proxy_manager.py # mtprotoproxy: запуск, секрет, QR
│   └── status.py       # агрегированный статус системы
├── web/
│   ├── app.py          # Flask API + маршруты
│   └── templates/
│       └── index.html  # веб-интерфейс
├── config/             # конфиги (awg0.conf, mtproto_config.py) — создаётся при первом запуске
├── logs/               # логи
├── mtprotoproxy/       # клонируется install.sh
└── venv/               # Python venv — создаётся install.sh
```

## Возможные проблемы

**AmneziaWG не установился** — используется WireGuard как fallback. Обфускация не работает.
Попробуй установить вручную: https://github.com/amnezia-vpn/amneziawg-tools

**"Permission denied" при старте туннеля** — нужен root: `sudo python3 main.py`

**Порт 443 занят** — на сервере может быть nginx/apache.
Отключи их или измени порт в `web/app.py` (переменная `MTPROTO_PORT`).

**Туннель поднялся, но Telegram не работает** — проверь, что VPN-сервер
доступен и firewall разрешает нужный порт.
