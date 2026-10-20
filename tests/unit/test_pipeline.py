"""Owner: Brady — The pipeline runs every detector and reloads threat-intel feeds."""

import os

from analysis.config import Settings
from analysis.main import Pipeline
from analysis.models import Category
from analysis.storage.db import Database


def _settings(tmp_path):
    s = Settings()
    s.paths.malicious_domains = tmp_path / "malicious_domains.txt"
    s.paths.malicious_ips = tmp_path / "malicious_ips.txt"
    s.paths.tracker_domains = tmp_path / "tracker_domains.txt"
    return s


def _dns(name, ts="2026-10-20T12:00:00.000000+0000"):
    return {"timestamp": ts, "event_type": "dns", "src_ip": "192.168.1.23",
            "dest_ip": "192.168.1.1", "proto": "UDP",
            "dns": {"type": "query", "rrname": name}}


def _categories(db):
    return {c.category for c in db.list_cards()}


def test_new_device_and_reputation_alerts(tmp_path):
    s = _settings(tmp_path)
    s.paths.malicious_domains.write_text("bad.example\n")
    db = Database(":memory:")
    p = Pipeline(s, db)

    p.handle_event({"timestamp": "2026-10-20T12:00:00.000000+0000", "event_type": "dhcp",
                    "dhcp": {"client_mac": "aa:bb:cc:00:00:01", "assigned_ip": "192.168.1.23"}})
    p.handle_event(_dns("cdn.bad.example"))

    assert _categories(db) == {Category.NEW_DEVICE, Category.MALICIOUS_CONTACT}


def test_reputation_reloads_when_feed_changes(tmp_path):
    s = _settings(tmp_path)
    db = Database(":memory:")
    p = Pipeline(s, db)

    assert p.handle_event(_dns("bad.example")) == 0

    s.paths.malicious_domains.write_text("bad.example\n")
    os.utime(s.paths.malicious_domains, (1, 1))  #mtime differs from "missing" for sure
    p.reload_feeds_if_changed()

    assert p.handle_event(_dns("bad.example")) == 1
