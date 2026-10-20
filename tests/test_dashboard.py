"""Owner: Aron: tests for the dashboard (pages, JSON API, naming, "Got it", health).

Run from the repo root:   python -m pytest tests/test_dashboard.py

The "connected" tests run against Brady's real analysis code and a throwaway database,
so they will also catch it if his storage or health_score functions change.
"""

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("flask")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD_DIR = os.path.join(REPO_ROOT, "dashboard")
if DASHBOARD_DIR not in sys.path:
    sys.path.insert(0, DASHBOARD_DIR)

import analysis_bridge as bridge  # noqa: E402
import app as dashboard_app  # noqa: E402
import dashboard_state as state  # noqa: E402

MAC = "aa:bb:cc:00:00:04"


def reset_bridge():
    db = bridge._db_cache.pop("db", None)
    if db is not None:
        db.close()
    bridge._settings_cache.clear()
    bridge._health_cache.update(at=0.0, value=None)


@pytest.fixture
def demo(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "NAMES_PATH", str(tmp_path / "names.json"))
    monkeypatch.setattr(state, "ACKS_PATH", str(tmp_path / "acks.json"))
    monkeypatch.setitem(dashboard_app.app.config, "DEMO", True)
    return dashboard_app.app.test_client()


@pytest.fixture
def connected(tmp_path, monkeypatch):
    """The dashboard reading a real (temporary) analysis database."""
    pytest.importorskip("yaml")
    pytest.importorskip("analysis.storage.db")
    from analysis.models import Alert, AlertCard, AlertSource, Category, Device, Severity
    from analysis.storage.db import Database

    settings = tmp_path / "settings.yaml"
    settings.write_text("paths:\n  database: %s\n" % (tmp_path / "soc.db"))
    monkeypatch.setenv("SOC_SETTINGS", str(settings))
    monkeypatch.setattr(state, "NAMES_PATH", str(tmp_path / "names.json"))
    monkeypatch.setattr(state, "ACKS_PATH", str(tmp_path / "acks.json"))
    monkeypatch.setitem(dashboard_app.app.config, "DEMO", False)
    monkeypatch.setitem(dashboard_app.app.config, "EVE_PATH", str(tmp_path / "no-eve.json"))
    reset_bridge()

    db = Database(tmp_path / "soc.db")
    now = datetime.now(timezone.utc)
    db.upsert_device(Device(mac="aa:bb:cc:00:00:02", ip="192.168.1.23", friendly_name="Kitchen smart speaker"))
    db.upsert_device(Device(mac=MAC, ip="192.168.1.47"))

    def add(category, severity, mac, name, description):
        alert = Alert(category=category, source=AlertSource.PYTHON, device_mac=mac, severity=severity, timestamp=now)
        db.save_alert(alert)
        db.save_card(AlertCard(alert.id, category, name, severity, description, "Do something.", now))
        return alert.id

    ids = {
        "bad": add(Category.MALICIOUS_CONTACT, Severity.HIGH, "aa:bb:cc:00:00:02",
                   "Kitchen smart speaker", "This device contacted a known bad server."),
        "new": add(Category.NEW_DEVICE, Severity.MEDIUM, MAC, "Unrecognized device",
                   "A new device joined your network; was this you?"),
    }
    yield dashboard_app.app.test_client(), db, ids
    db.close()
    reset_bridge()


# --- Pages and files ---------------------------------------------------------------

@pytest.mark.parametrize("path, page", [("/", "alerts"), ("/devices", "devices"), ("/setup", "setup")])
def test_pages_render(demo, path, page):
    r = demo.get(path)
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert 'data-page="%s"' % page in html
    assert "/static/js/app.js" in html and "/static/css/style.css" in html


def test_history_page_renders(demo):
    r = demo.get("/history")
    assert r.status_code == 200 and 'data-page="history"' in r.get_data(as_text=True)


def test_static_files_are_served(demo):
    assert demo.get("/static/js/app.js").status_code == 200
    assert demo.get("/static/css/style.css").status_code == 200


def test_pages_need_no_internet(demo):
    for path in ("/", "/devices", "/setup", "/history"):
        assert "https://" not in demo.get(path).get_data(as_text=True)


# --- Demo data ---------------------------------------------------------------------

def test_demo_state_shape(demo):
    s = demo.get("/api/state").get_json()
    assert s["source"] == "demo" and s["analysis"]["error"] is None
    assert {a["severity"] for a in s["alerts"]} <= {"high", "medium", "low"}
    assert s["alerts"][0]["severity"] == "high"          # most severe first
    assert any(not d["named"] for d in s["devices"])
    assert [a["id"] for a in demo.get("/api/alerts").get_json()] == [a["id"] for a in s["alerts"]]
    assert len(demo.get("/api/devices").get_json()) == len(s["devices"])
    assert demo.get("/api/health").get_json()["grade"]


def test_naming_a_device(demo):
    r = demo.post("/api/devices/%s/name" % MAC, json={"name": "  Kid's Xbox ", "icon": "device-gamepad-2"})
    assert r.status_code == 200 and r.get_json()["name"] == "Kid's Xbox"
    device = [d for d in demo.get("/api/state").get_json()["devices"] if d["mac"] == MAC][0]
    assert device["named"] and device["name"] == "Kid's Xbox" and device["icon"] == "device-gamepad-2"


def test_unknown_icon_falls_back(demo):
    r = demo.post("/api/devices/%s/name" % MAC, json={"name": "TV", "icon": "<script>"})
    assert r.get_json()["icon"] == "device-unknown"


@pytest.mark.parametrize("body, code", [({"name": "   "}, 400), ({"name": "x" * 41}, 400), ({}, 400)])
def test_bad_names_are_refused(demo, body, code):
    assert demo.post("/api/devices/%s/name" % MAC, json=body).status_code == code


def test_bad_requests(demo):
    assert demo.post("/api/devices/not-a-mac/name", json={"name": "x"}).status_code == 404
    assert demo.post("/api/devices/%s/name" % MAC, data="not json").status_code == 400
    assert demo.post("/api/devices/%s/name" % MAC, json={"name": "x" * 5000}).status_code == 413   # too big to be a name


def test_skipping_keeps_the_device_unnamed(demo):
    assert demo.post("/api/devices/%s/skip" % MAC).status_code == 200
    device = [d for d in demo.get("/api/state").get_json()["devices"] if d["mac"] == MAC][0]
    assert device["skipped"] and not device["named"]


def test_ack_ids_are_checked(demo):
    assert demo.post("/api/cards/bad%20id/ack").status_code == 404
    assert demo.post("/api/cards/" + "a" * 65 + "/ack").status_code == 404
    assert demo.post("/api/cards/not-a-card/ack").status_code == 404
    assert demo.post("/api/cards/not-a-card/unack").status_code == 404


def test_got_it_and_undo_on_basic_alerts(demo):
    before = demo.get("/api/state").get_json()
    card = before["alerts"][0]
    assert demo.post("/api/cards/%s/ack" % card["id"]).status_code == 200
    s = demo.get("/api/state").get_json()
    assert card["id"] not in [a["id"] for a in s["alerts"]]
    assert [a["id"] for a in s["handled"]] == [card["id"]]
    assert demo.get("/api/health").get_json()["score"] > before["health"]["score"]

    assert demo.post("/api/cards/%s/unack" % card["id"]).status_code == 200   # "Not fixed yet"
    s = demo.get("/api/state").get_json()
    assert card["id"] in [a["id"] for a in s["alerts"]] and s["handled"] == []
    assert s["health"]["score"] == before["health"]["score"]


def test_history_keeps_a_copy_of_basic_alerts(demo, monkeypatch):
    card = demo.get("/api/state").get_json()["alerts"][0]
    demo.post("/api/cards/%s/ack" % card["id"])
    monkeypatch.setattr(state, "demo_events", lambda: [])   # the alert has aged out of eve.json
    s = demo.get("/api/state").get_json()
    assert [a["description"] for a in s["handled"]] == [card["description"]]
    assert demo.post("/api/cards/%s/unack" % card["id"]).status_code == 200
    assert demo.get("/api/state").get_json()["handled"] == []


def test_a_repeat_after_got_it_comes_back_and_can_be_handled_again(demo, monkeypatch):
    card = demo.get("/api/state").get_json()["alerts"][0]
    demo.post("/api/cards/%s/ack" % card["id"])
    later = state.datetime.now(state.timezone.utc)   # the same alert happens again, after "Got it"
    events = state.demo_events()
    for e in events:
        e["timestamp"] = later.strftime("%Y-%m-%dT%H:%M:%S.%f+0000")
    monkeypatch.setattr(state, "demo_events", lambda: events)
    assert card["id"] in [a["id"] for a in demo.get("/api/state").get_json()["alerts"]]
    assert demo.post("/api/cards/%s/ack" % card["id"]).status_code == 200
    assert card["id"] not in [a["id"] for a in demo.get("/api/state").get_json()["alerts"]]


def test_without_the_analysis_service_basic_alerts_are_used(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "NAMES_PATH", str(tmp_path / "names.json"))
    monkeypatch.setattr(state, "ACKS_PATH", str(tmp_path / "acks.json"))
    monkeypatch.setitem(dashboard_app.app.config, "DEMO", False)
    monkeypatch.setitem(dashboard_app.app.config, "EVE_PATH", str(tmp_path / "missing.json"))
    monkeypatch.setattr(bridge, "get_cards", lambda: (_ for _ in ()).throw(NotImplementedError))
    monkeypatch.setattr(bridge, "get_devices", lambda: (_ for _ in ()).throw(NotImplementedError))
    monkeypatch.setattr(bridge, "get_health", lambda: (_ for _ in ()).throw(NotImplementedError))
    monkeypatch.setattr(state, "get_neighbors", lambda: [])
    s = dashboard_app.app.test_client().get("/api/state").get_json()
    assert s["alert_source"] == "suricata" and s["analysis"]["error"] is None
    assert s["eve_readable"] is False and s["can_acknowledge"] is True   # "Got it" works on basic alerts too


# --- Connected to Brady's analysis service -----------------------------------------

def test_cards_devices_and_health_come_from_the_service(connected):
    client, db, ids = connected
    s = client.get("/api/state").get_json()
    assert s["alert_source"] == "analysis" and s["analysis"]["error"] is None
    assert s["analysis"]["status"] == {"cards": "ok", "devices": "ok", "health": "ok"}
    assert [a["category"] for a in s["alerts"]] == ["malicious_contact", "new_device"] or \
           {a["category"] for a in s["alerts"]} == {"malicious_contact", "new_device"}
    assert s["alerts"][0]["severity"] == "high"
    assert [d["name"] for d in s["devices"]][0] == "Unrecognized device"      # unnamed first
    assert s["health"]["score"] == 65 and s["health"]["label"] == "Fair"      # 100 - 25 - 10
    assert len(s["health"]["trend"]) == 7


def test_naming_reaches_the_analysis_database(connected):
    client, db, ids = connected
    assert client.post("/api/devices/%s/name" % MAC, json={"name": "Kid's Xbox"}).status_code == 200
    assert db.get_device(MAC).friendly_name == "Kid's Xbox"
    cards = {a["category"]: a for a in client.get("/api/state").get_json()["alerts"]}
    assert cards["new_device"]["device_name"] == "Kid's Xbox"        # even on the older card


def test_got_it_acknowledges_and_raises_the_score(connected):
    client, db, ids = connected
    assert client.get("/api/health").get_json()["score"] == 65
    r = client.post("/api/cards/%s/ack" % ids["bad"])
    assert r.status_code == 200 and r.get_json() == {"ok": True}
    s = client.get("/api/state").get_json()
    assert all(a["id"] != ids["bad"] for a in s["alerts"])
    assert s["health"]["score"] == 90
    assert [a["id"] for a in s["handled"]] == [ids["bad"]]
    assert client.post("/api/cards/does-not-exist/ack").status_code == 404


def test_not_fixed_yet_brings_a_card_back(connected):
    client, db, ids = connected
    client.post("/api/cards/%s/ack" % ids["bad"])
    r = client.post("/api/cards/%s/unack" % ids["bad"])
    assert r.status_code == 200 and r.get_json() == {"ok": True}
    s = client.get("/api/state").get_json()
    assert ids["bad"] in [a["id"] for a in s["alerts"]] and s["handled"] == []
    assert s["health"]["score"] == 65
    assert client.post("/api/cards/does-not-exist/unack").status_code == 404


def test_a_broken_service_falls_back_with_a_message(connected, monkeypatch):
    client, db, ids = connected
    monkeypatch.setenv("SOC_SETTINGS", "/nonexistent/settings.yaml")
    reset_bridge()
    monkeypatch.setattr(state, "get_neighbors", lambda: [])
    s = client.get("/api/state").get_json()
    assert s["alert_source"] == "suricata" and "ConfigError" in s["analysis"]["error"]
