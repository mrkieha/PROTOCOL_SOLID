"""
app.py — Flask веб-интерфейс управления tg-proxy.
Запускается на 127.0.0.1:8080.
"""

import sys
import logging
from pathlib import Path

# Добавляем корень проекта в sys.path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from flask import Flask, jsonify, request, render_template, abort
from core import awg_manager, proxy_manager
from core.status import get_full_status

# Порт MTProto: 443 по умолчанию
MTPROTO_PORT = 443

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("web")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["JSON_ENSURE_ASCII"] = False


# =============================================================================
# Главная страница
# =============================================================================

@app.route("/")
def index():
    return render_template("index.html")


# =============================================================================
# API — общий статус
# =============================================================================

@app.route("/api/status")
def api_status():
    try:
        status = get_full_status(port=MTPROTO_PORT)
        return jsonify(status)
    except Exception as e:
        logger.error(f"Ошибка /api/status: {e}")
        return jsonify({"error": str(e)}), 500


# =============================================================================
# API — AmneziaWG туннель
# =============================================================================

@app.route("/api/tunnel/start", methods=["POST"])
def api_tunnel_start():
    result = awg_manager.start_tunnel()
    return jsonify(result), 200 if result.get("ok") else 500


@app.route("/api/tunnel/stop", methods=["POST"])
def api_tunnel_stop():
    result = awg_manager.stop_tunnel()
    return jsonify(result), 200 if result.get("ok") else 500


@app.route("/api/tunnel/config", methods=["POST"])
def api_tunnel_config():
    """
    Сохраняем новый конфиг AWG.
    Тело JSON: { server_ip, server_port, server_pubkey, preshared_key? }
    """
    data = request.get_json(force=True, silent=True) or {}

    server_ip     = data.get("server_ip", "").strip()
    server_pubkey = data.get("server_pubkey", "").strip()
    preshared_key = data.get("preshared_key", "").strip() or None

    if not server_ip:
        return jsonify({"ok": False, "error": "server_ip обязателен"}), 400
    if not server_pubkey:
        return jsonify({"ok": False, "error": "server_pubkey обязателен"}), 400

    try:
        server_port = int(data.get("server_port", 51820))
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "server_port должен быть числом"}), 400

    # Предупреждаем про порт 51820 (в РФ заблокирован)
    port_warning = ""
    if server_port == 51820:
        port_warning = "Порт 51820 может быть заблокирован в РФ. Рекомендуем 49152–65535."

    try:
        result = awg_manager.generate_config(
            server_ip=server_ip,
            server_port=server_port,
            server_pubkey=server_pubkey,
            preshared_key=preshared_key,
        )
        result["ok"] = True
        if port_warning:
            result["warning"] = port_warning
        return jsonify(result)
    except Exception as e:
        logger.error(f"Ошибка генерации конфига AWG: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/tunnel/status")
def api_tunnel_status():
    return jsonify(awg_manager.get_status())


# =============================================================================
# API — MTProto прокси
# =============================================================================

@app.route("/api/proxy/start", methods=["POST"])
def api_proxy_start():
    result = proxy_manager.start(port=MTPROTO_PORT)
    return jsonify(result), 200 if result.get("ok") else 500


@app.route("/api/proxy/stop", methods=["POST"])
def api_proxy_stop():
    result = proxy_manager.stop()
    return jsonify(result)


@app.route("/api/proxy/restart", methods=["POST"])
def api_proxy_restart():
    result = proxy_manager.restart(port=MTPROTO_PORT)
    return jsonify(result), 200 if result.get("ok") else 500


@app.route("/api/proxy/link")
def api_proxy_link():
    """Возвращает tg:// ссылку и QR-код в base64."""
    link = proxy_manager.get_proxy_link(port=MTPROTO_PORT)
    if not link:
        return jsonify({"ok": False, "error": "Прокси не настроен"}), 404
    qr = proxy_manager.get_qr_base64(link)
    return jsonify({"ok": True, "link": link, "qr": qr})


@app.route("/api/proxy/config", methods=["POST"])
def api_proxy_config():
    """Перегенерировать секрет с нужным доменом."""
    data   = request.get_json(force=True, silent=True) or {}
    domain = data.get("domain") or None
    try:
        result = proxy_manager.generate_config(port=MTPROTO_PORT, domain=domain)
        result["ok"] = True
        return jsonify(result)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/proxy/logs")
def api_proxy_logs():
    lines = proxy_manager.get_logs(lines=60)
    return jsonify({"lines": lines})


@app.route("/api/proxy/domains")
def api_proxy_domains():
    return jsonify({"domains": proxy_manager.TLS_DOMAINS})


# =============================================================================
# Запуск (вызывается из main.py, не напрямую)
# =============================================================================

def run(host: str = "127.0.0.1", port: int = 8080, debug: bool = False):
    logger.info(f"Веб-интерфейс: http://{host}:{port}")
    app.run(host=host, port=port, debug=debug, use_reloader=False)
