"""Owner: Aron — Flask app: serves pages and the alerts/devices/health API.

Run it (from the repo root):

    python3 dashboard/app.py                # real data: Brady's analysis service, else Suricata's eve.json
    python3 dashboard/app.py --demo         # fake data, works on any computer
    python3 dashboard/app.py --check        # report what the analysis-service connection found

Then open http://localhost:8080  (the host and port come from config/settings.yaml when it loads).

Pages:   /  (alerts)      /devices  (every device, rename)      /setup  (name new devices)
API:     GET /api/state (everything)    GET /api/alerts   GET /api/devices   GET /api/health
         POST /api/devices/<mac>/name   POST /api/devices/<mac>/skip   POST /api/cards/<id>/ack
"""

import argparse
import os
import sys

from flask import Flask, jsonify, render_template, request

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import analysis_bridge as bridge  # noqa: E402  (needs HERE on the path first)
import dashboard_state as state  # noqa: E402

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096  # names are tiny; refuse anything bigger
app.config["DEMO"] = os.environ.get("SOC_DEMO") == "1"
app.config["EVE_PATH"] = os.environ.get("SOC_EVE") or "/var/log/suricata/eve.json"


def current_state():
    return state.build_state(app.config["DEMO"], app.config["EVE_PATH"])


# --- Pages --------------------------------------------------------------------

@app.get("/")
def index():
    return render_template("index.html")


@app.get("/devices")
def devices():
    return render_template("devices.html")


@app.get("/setup")
def setup():
    return render_template("setup.html")


# --- Data ---------------------------------------------------------------------

@app.get("/api/state")
def api_state():
    return jsonify(current_state())


@app.get("/api/alerts")
def api_alerts():
    return jsonify(current_state()["alerts"])


@app.get("/api/devices")
def api_devices():
    return jsonify(current_state()["devices"])


@app.get("/api/health")
def api_health():
    return jsonify(current_state()["health"])


# --- Actions ------------------------------------------------------------------

@app.post("/api/devices/<mac>/name")
def api_name_device(mac):
    if not state.valid_mac(mac):
        return jsonify({"error": "not found"}), 404
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Bad request"}), 400
    saved, error = state.set_device_name(mac, data.get("name"), data.get("icon"))
    if error:
        return jsonify({"error": error}), 400
    return jsonify(saved)


@app.post("/api/devices/<mac>/skip")
def api_skip_device(mac):
    if not state.valid_mac(mac):
        return jsonify({"error": "not found"}), 404
    return jsonify(state.skip_device(mac))


@app.post("/api/cards/<alert_id>/ack")
def api_acknowledge(alert_id):
    """The household pressed "Got it" on a card."""
    if not alert_id.replace("-", "").replace("_", "").isalnum() or len(alert_id) > 64:
        return jsonify({"error": "not found"}), 404
    try:
        ok = bridge.acknowledge_card(alert_id)
    except NotImplementedError:
        return jsonify({"error": "Acknowledging isn't connected"}), 501
    except Exception as e:
        print("acknowledge_card failed: %s" % e)
        return jsonify({"error": "Couldn't save that"}), 500
    return jsonify({"ok": bool(ok)}), (200 if ok else 404)


@app.after_request
def no_cache_for_api(response):
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# --- Command line -------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="SOC-In-a-Box dashboard")
    p.add_argument("--demo", action="store_true", help="use fake data (no Pi or Suricata needed)")
    p.add_argument("--check", action="store_true", help="report what the analysis-service connection found, then exit")
    p.add_argument("--eve", default=None, help="path to Suricata eve.json (default: from the settings)")
    p.add_argument("--host", default=None, help="address to listen on (default: from the settings, else all interfaces)")
    p.add_argument("--port", type=int, default=None, help="port (default: from the settings, else 8080)")
    args = p.parse_args()

    if args.check:
        print(bridge.check_report())
        return

    s = None
    if not args.demo:
        s = bridge.settings()
        if s is None:
            print("Note: analysis settings not loaded (%s); using defaults." % bridge._settings_cache.get("error"))
        try:
            bridge.start()
        except Exception as e:
            print("analysis_bridge.start() failed: %s" % e)

    app.config["DEMO"] = args.demo
    app.config["EVE_PATH"] = args.eve or (str(s.paths.eve_json) if s else app.config["EVE_PATH"])
    host = args.host or (s.dashboard.host if s else "0.0.0.0")
    port = args.port or (s.dashboard.port if s else 8080)
    print("Serving on http://%s:%d  (%s)" % (host, port, "DEMO data" if args.demo else "Suricata log " + app.config["EVE_PATH"]))
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
