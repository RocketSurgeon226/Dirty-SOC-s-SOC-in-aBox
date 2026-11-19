"""Owner: Brady — Port-scan cards say who scanned whom (not always "from outside")."""
from datetime import datetime, timezone

import pytest

from analysis.config import Settings
from analysis.main import Pipeline
from analysis.models import Alert, AlertSource, Category
from analysis.storage.db import Database
from analysis.translate.card_builder import build_card
from analysis.translate.templates import PORT_SCAN_BY_DIRECTION, TEMPLATES


@pytest.fixture
def pipeline(tmp_path):
    settings = Settings()
    settings.paths.malicious_domains = tmp_path / "malicious_domains.txt"
    settings.paths.malicious_ips = tmp_path / "malicious_ips.txt"
    settings.paths.tracker_domains = tmp_path / "tracker_domains.txt"
    db = Database(tmp_path / "tests.sqlite")
    try:
        yield Pipeline(settings, db)
    finally:
        db.close()


def scan(src, dest):
    return {
        "timestamp": datetime(2026, 11, 19, 18, tzinfo=timezone.utc).isoformat(),
        "event_type": "alert", "src_ip": src, "dest_ip": dest,
        "src_port": 45000, "dest_port": 22, "proto": "TCP",
        "alert": {"signature_id": 9000010, "signature": "SOCBOX Port scan test",
                  "category": "Detection of a Network Scan", "severity": 2},
    }


@pytest.mark.parametrize("src, dest, expected", [
    ("203.0.113.10", "192.168.1.25", TEMPLATES[Category.PORT_SCAN]),
    ("192.168.1.40", "192.168.1.25", PORT_SCAN_BY_DIRECTION["internal"]),
    ("192.168.1.40", "203.0.113.10", PORT_SCAN_BY_DIRECTION["outbound"]),
])
def test_scan_wording_follows_direction(pipeline, src, dest, expected):
    assert pipeline.handle_event(scan(src, dest)) == 1
    card = pipeline.db.list_cards()[0]
    assert (card.description, card.action) == (expected.description, expected.action)


def test_only_inbound_scans_say_outside():
    assert "outside" in TEMPLATES[Category.PORT_SCAN].description
    assert all("outside" not in t.description for t in PORT_SCAN_BY_DIRECTION.values())


def test_scan_without_direction_keeps_default():
    alert = Alert(category=Category.PORT_SCAN, source=AlertSource.PYTHON, src_ip="192.168.1.40")
    assert build_card(alert).description == TEMPLATES[Category.PORT_SCAN].description
