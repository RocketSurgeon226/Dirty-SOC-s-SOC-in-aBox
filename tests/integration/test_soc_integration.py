"""Quinn: offline integration checks for the current Python alert pipeline."""
from datetime import datetime, timedelta, timezone
import pytest
from analysis.config import Settings
from analysis.main import Pipeline
from analysis.models import Alert, AlertSource, Category
from analysis.storage.db import Database

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

def scan_event(dest="192.168.1.25", minutes=0):
    return {
        "timestamp": (datetime(2026, 10, 16, 18, tzinfo=timezone.utc) + timedelta(minutes=minutes)).isoformat(),
        "event_type": "alert", "src_ip": "203.0.113.10", "dest_ip": dest,
        "src_port": 45000, "dest_port": 22, "proto": "TCP",
        "alert": {"signature_id": 9000010, "signature": "SOCBOX Port Scan test",
                  "category": "Detection of a Network Scan", "severity": 2},
    }

def test_repeat_scans_are_one_card(pipeline):
    assert pipeline.handle_event(scan_event()) == 1
    assert pipeline.handle_event(scan_event(minutes=1)) == 1
    cards = pipeline.db.list_cards()
    assert len(cards) == 1
    assert cards[0].count == 2
    assert cards[0].severity.value == "medium"

def test_scans_of_two_home_devices_do_not_merge(pipeline):
    assert pipeline.handle_event(scan_event(dest="192.168.1.25")) == 1
    assert pipeline.handle_event(scan_event(dest="192.168.1.26", minutes=1)) == 1
    assert len(pipeline.db.list_cards()) == 2

def test_plaintext_credentials_redacted(pipeline):
    alert = Alert(category=Category.PLAINTEXT_CREDENTIALS, source=AlertSource.PYTHON,
                  src_ip="192.168.1.25", details={"password": "fake-secret", "payload": "raw"})
    pipeline.handle_alert(alert)
    stored = pipeline.db.get_alert(alert.id)
    assert stored.details == {"password": "[REDACTED]"}
    assert "fake-secret" not in str(pipeline.db.list_cards()[0].to_dict())

def test_scan_severity_and_action(pipeline):
    pipeline.handle_event(scan_event())
    card = pipeline.db.list_cards()[0]
    assert card.category == Category.PORT_SCAN
    assert card.severity.value == "medium"
    assert card.description and card.action
