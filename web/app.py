"""
app.py — Flask веб-интерфейс.
"""

import sys
import logging
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from flask import Flask, jsonify, request, render_template
from core import awg_manager, proxy_manager
from core.status import get_full_status
from core import tunnel_expose

MTPROTO_PORT = 8443

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("web")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["JSON_ENSURE_ASCII"] = False


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    try:
        st = get_full_status(port=MTPROTO_PORT)
        st["bore"] = tunnel_expose.get_status()
        return jsonify(st)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Туннель ──────────────────────────────────────────────────────────────────

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
    data = request.get_json(force=True, silent=True) or {}
    ip     = data.get("server_ip", "").strip()
    pubkey = data.get("server_pubkey", "").strip()
    psk    = data.get("preshared_key", "").strip() or None
    if not ip:
        return jsonify({"ok": False, "error": "server_ip обязателен"}), 400
    if not pubkey:
        return jsonify({"ok": False, "error": "server_pubkey обязателен"}), 400
    try:
        port = int(data.get("server_port", 51820))
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "server_port должен быть числом"}), 400
    try:
        r = awg_manager.generate_config(
            server_ip=ip, server_port=port, server_pubkey=pubkey,
            preshared_key=psk, proxy_port=MTPROTO_PORT)
        if port == 51820:
            r["warning"] = "Порт 51820 часто блокируется в РФ. Рекомендуем 49152–65535."
        return jsonify(r)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/tunnel/import-warp", methods=["POST"])
def api_tunnel_import_warp():
    data = request.get_json(force=True, silent=True) or {}
    text = data.get("config", "").strip()
    if not text:
        return jsonify({"ok": False, "error": "Передай поле 'config' с текстом конфига"}), 400
    try:
        return jsonify(awg_manager.import_warp_and_generate(text, proxy_port=MTPROTO_PORT))
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── Прокси ───────────────────────────────────────────────────────────────────

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


# ── bore (публичный доступ без проброса портов) ───────────────────────────────

@app.route("/api/bore/start", methods=["POST"])
def api_bore_start():
    data       = request.get_json(force=True, silent=True) or {}
    relay      = data.get("relay", "bore.pub").strip() or "bore.pub"
    relay_ctrl = int(data.get("relay_ctrl", 7835))
    secret     = data.get("secret", "").strip()
    local_port = int(data.get("local_port", MTPROTO_PORT))
    r = tunnel_expose.start(local_port=local_port, relay_host=relay,
                            relay_ctrl=relay_ctrl, secret=secret)
    return jsonify(r), 200 if r.get("ok") else 500

@app.route("/api/bore/stop", methods=["POST"])
def api_bore_stop():
    return jsonify(tunnel_expose.stop())

@app.route("/api/bore/status")
def api_bore_status():
    return jsonify(tunnel_expose.get_status())

@app.route("/api/bore/install", methods=["POST"])
def api_bore_install():
    r = tunnel_expose.install_bore()
    return jsonify(r), 200 if r.get("ok") else 500


# ── Диагностика ──────────────────────────────────────────────────────────────

@app.route("/api/diag/port")
def api_diag_port():
    return jsonify(proxy_manager.check_port_open(MTPROTO_PORT))

@app.route("/api/diag/telegram")
def api_diag_telegram():
    return jsonify(proxy_manager.check_awg_connectivity())

@app.route("/api/diag/all")
def api_diag_all():
    port_check = proxy_manager.check_port_open(MTPROTO_PORT)
    tg_check   = proxy_manager.check_awg_connectivity()
    duck       = proxy_manager.load_duck_config()
    public_ip  = proxy_manager.get_public_hostname()
    awg_status = awg_manager.get_status()
    bore_st    = tunnel_expose.get_status()

    issues = []
    if not awg_status.get("running"):
        issues.append("AWG туннель не поднят")
    if not tg_check.get("reachable"):
        issues.append("Telegram серверы недоступны через туннель")
    if not bore_st.get("running") and port_check.get("reachable") is False and not duck:
        issues.append(f"Порт {MTPROTO_PORT} недоступен снаружи — запусти bore или пробрось порт")
    if not awg_status.get("is_amnezia"):
        issues.append("AmneziaWG не найден — обфускация отсутствует")

    return jsonify({
        "ok":         len(issues) == 0,
        "issues":     issues,
        "public_ip":  public_ip,
        "port":       port_check,
        "telegram":   tg_check,
        "duck_dns":   {"configured": bool(duck), "hostname": duck["hostname"] if duck else None},
        "awg":        {"running": awg_status.get("running"), "is_amnezia": awg_status.get("is_amnezia")},
        "bore":       bore_st,
    })


# ── Duck DNS ─────────────────────────────────────────────────────────────────

@app.route("/api/duckdns/config", methods=["POST"])
def api_duck_config():
    data = request.get_json(force=True, silent=True) or {}
    r = proxy_manager.save_duck_config(
        data.get("token", "").strip(),
        data.get("domain", "").strip()
    )
    return jsonify(r), 200 if r.get("ok") else 400

@app.route("/api/duckdns/update", methods=["POST"])
def api_duck_update():
    r = proxy_manager.update_duck_dns()
    return jsonify(r), 200 if r.get("ok") else 500

@app.route("/api/duckdns/status")
def api_duck_status():
    cfg = proxy_manager.load_duck_config()
    return jsonify({"configured": bool(cfg), "hostname": cfg["hostname"] if cfg else None})


def run(host: str = "127.0.0.1", port: int = 8080, debug: bool = False):
    logger.info(f"Веб-интерфейс: http://{host}:{port}")
    app.run(host=host, port=port, debug=debug, use_reloader=False)
