"""
app.py — Flask веб-интерфейс.
Новые эндпоинты: /api/tunnel/import-warp, /api/duckdns/*
"""

import sys
import logging
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from flask import Flask, jsonify, request, render_template
from core import awg_manager, proxy_manager
from core.status import get_full_status

# Порт прокси — читается из конфига или дефолт
MTPROTO_PORT = 8443

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("web")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["JSON_ENSURE_ASCII"] = False


# =============================================================================
# Главная
# =============================================================================

@app.route("/")
def index():
    return render_template("index.html")


# =============================================================================
# Статус
# =============================================================================

@app.route("/api/status")
def api_status():
    try:
        return jsonify(get_full_status(port=MTPROTO_PORT))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================================
# AmneziaWG — туннель
# =============================================================================

@app.route("/api/tunnel/start", methods=["POST"])
def api_tunnel_start():
    r = awg_manager.start_tunnel()
    return jsonify(r), 200 if r.get("ok") else 500

@app.route("/api/tunnel/stop", methods=["POST"])
def api_tunnel_stop():
    r = awg_manager.stop_tunnel()
    return jsonify(r), 200 if r.get("ok") else 500

@app.route("/api/tunnel/status")
def api_tunnel_status():
    return jsonify(awg_manager.get_status())

@app.route("/api/tunnel/config-info")
def api_tunnel_config_info():
    return jsonify(awg_manager.get_config_info())


@app.route("/api/tunnel/config", methods=["POST"])
def api_tunnel_config():
    """Ручной ввод параметров AWG."""
    data = request.get_json(force=True, silent=True) or {}

    server_ip     = data.get("server_ip", "").strip()
    server_pubkey = data.get("server_pubkey", "").strip()
    # preshared_key — опциональный, None если пустой
    psk           = data.get("preshared_key", "").strip() or None

    if not server_ip:
        return jsonify({"ok": False, "error": "server_ip обязателен"}), 400
    if not server_pubkey:
        return jsonify({"ok": False, "error": "server_pubkey обязателен"}), 400

    try:
        server_port = int(data.get("server_port", 51820))
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "server_port должен быть числом"}), 400

    try:
        result = awg_manager.generate_config(
            server_ip     = server_ip,
            server_port   = server_port,
            server_pubkey = server_pubkey,
            preshared_key = psk,
            proxy_port    = MTPROTO_PORT,
        )
        if server_port == 51820:
            result["warning"] = "Порт 51820 часто блокируется в РФ. Рекомендуем случайный 49152–65535."
        return jsonify(result)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/tunnel/import-warp", methods=["POST"])
def api_tunnel_import_warp():
    """
    Импорт Cloudflare WARP / любого WireGuard конфига.
    Тело: { "config": "<текст конфига>" }
    """
    data   = request.get_json(force=True, silent=True) or {}
    text   = data.get("config", "").strip()

    if not text:
        return jsonify({"ok": False, "error": "Передай поле 'config' с текстом конфига"}), 400

    try:
        result = awg_manager.import_warp_and_generate(text, proxy_port=MTPROTO_PORT)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        logger.error(f"Ошибка импорта WARP: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


# =============================================================================
# MTProto прокси
# =============================================================================

@app.route("/api/proxy/start", methods=["POST"])
def api_proxy_start():
    r = proxy_manager.start(port=MTPROTO_PORT)
    return jsonify(r), 200 if r.get("ok") else 500

@app.route("/api/proxy/stop", methods=["POST"])
def api_proxy_stop():
    return jsonify(proxy_manager.stop())

@app.route("/api/proxy/restart", methods=["POST"])
def api_proxy_restart():
    r = proxy_manager.restart(port=MTPROTO_PORT)
    return jsonify(r), 200 if r.get("ok") else 500

@app.route("/api/proxy/link")
def api_proxy_link():
    link = proxy_manager.get_proxy_link(port=MTPROTO_PORT)
    if not link:
        return jsonify({"ok": False, "error": "Прокси не настроен"}), 404
    return jsonify({"ok": True, "link": link, "qr": proxy_manager.get_qr_base64(link)})

@app.route("/api/proxy/config", methods=["POST"])
def api_proxy_config():
    data   = request.get_json(force=True, silent=True) or {}
    domain = data.get("domain") or None
    port   = int(data.get("port", MTPROTO_PORT))
    try:
        r = proxy_manager.generate_config(port=port, domain=domain)
        r["ok"] = True
        return jsonify(r)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/proxy/logs")
def api_proxy_logs():
    return jsonify({"lines": proxy_manager.get_logs(60)})

@app.route("/api/proxy/domains")
def api_proxy_domains():
    return jsonify({"domains": proxy_manager.TLS_DOMAINS})


# =============================================================================
# Duck DNS
# =============================================================================

@app.route("/api/duckdns/config", methods=["POST"])
def api_duck_config():
    """Сохранить настройки Duck DNS. { token, domain }"""
    data   = request.get_json(force=True, silent=True) or {}
    token  = data.get("token", "").strip()
    domain = data.get("domain", "").strip()
    r = proxy_manager.save_duck_config(token, domain)
    return jsonify(r), 200 if r.get("ok") else 400

@app.route("/api/duckdns/update", methods=["POST"])
def api_duck_update():
    """Принудительно обновить IP в Duck DNS."""
    r = proxy_manager.update_duck_dns()
    return jsonify(r), 200 if r.get("ok") else 500

@app.route("/api/duckdns/status")
def api_duck_status():
    cfg = proxy_manager.load_duck_config()
    return jsonify({
        "configured": bool(cfg),
        "hostname":   cfg["hostname"] if cfg else None,
    })


# =============================================================================
# Запуск
# =============================================================================

def run(host: str = "127.0.0.1", port: int = 8080, debug: bool = False):
    logger.info(f"Веб-интерфейс: http://{host}:{port}")
    app.run(host=host, port=port, debug=debug, use_reloader=False)
