#!/usr/bin/env python3
"""
main.py — точка входа tg-proxy.
Запускает веб-GUI и следит за корректным завершением при Ctrl+C / SIGTERM.
"""

import sys
import os
import signal
import logging
import argparse
from pathlib import Path

# Добавляем корень в sys.path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(ROOT / "logs" / "main.log", encoding="utf-8"),
    ]
)
logger = logging.getLogger("main")

(ROOT / "logs").mkdir(exist_ok=True)
(ROOT / "config").mkdir(exist_ok=True)


def parse_args():
    p = argparse.ArgumentParser(description="tg-proxy: MTProto + AmneziaWG")
    p.add_argument("--host", default="127.0.0.1",
                   help="Адрес веб-интерфейса (по умолчанию: 127.0.0.1)")
    p.add_argument("--port", type=int, default=8080,
                   help="Порт веб-интерфейса (по умолчанию: 8080)")
    p.add_argument("--debug", action="store_true",
                   help="Режим отладки Flask")
    p.add_argument("--no-open", action="store_true",
                   help="Не открывать браузер автоматически")
    return p.parse_args()


def check_root():
    if os.geteuid() != 0:
        print("⚠  Для управления туннелем нужны права root.")
        print("   Запускай: sudo python3 main.py  или через systemd-сервис.")
        print("   Веб-интерфейс запустится, но AWG-команды могут не работать.")


def open_browser(host: str, port: int):
    """Пробуем открыть браузер через 1.5 секунды."""
    import threading, time, webbrowser
    def _open():
        time.sleep(1.5)
        try:
            webbrowser.open(f"http://{host}:{port}")
        except Exception:
            pass
    threading.Thread(target=_open, daemon=True).start()


def shutdown(sig, frame):
    logger.info("Получен сигнал завершения, останавливаем сервисы...")
    try:
        from core import proxy_manager
        proxy_manager.stop()
        logger.info("mtprotoproxy остановлен")
    except Exception as e:
        logger.warning(f"Ошибка при остановке прокси: {e}")
    sys.exit(0)


def main():
    args = parse_args()
    check_root()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT,  shutdown)

    logger.info("=" * 50)
    logger.info("tg-proxy запускается")
    logger.info(f"Веб-интерфейс: http://{args.host}:{args.port}")
    logger.info("=" * 50)

    if not args.no_open and args.host in ("127.0.0.1", "localhost"):
        open_browser(args.host, args.port)

    print(f"\n  Открой в браузере: \033[1;36mhttp://{args.host}:{args.port}\033[0m")
    print("  Для остановки: Ctrl+C\n")

    from web.app import run as web_run
    web_run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
