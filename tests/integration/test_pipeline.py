"""Offline checks from Suricata-style events through the real SQLite pipeline."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from analysis.config import Settings
from analysis.main import Pipeline
from analysis.eve_reader import read_events
from analysis.models import Alert, AlertSource, Category
from analysis.storage.db import Database


@pytest.fixture
def pipeline(tmp_path):
    db = Database(tmp_path / "qa.db")
    settings = Settings()  # LLM disabled; no paid requests
    yield Pipeline(settings, db)
    db.close()


def scan_event(src="203.0.113.10", dest="192.168.1.25", minutes=0):
    return {
        "timestamp": (datetime(2026, 10, 16, 18, tzinfo=timezone.utc)
                      + timedelta(minutes=minutes)).isoformat(),
        "event_type": "alert", "src_ip": src, "dest_ip": dest,
        "src_port": 45000, "dest_port": 22, "proto": "TCP",
        "alert": {"signature_id": 9000010, "signature": "SOCBOX Port Scan test",
                  "category": "Detection of a Network Scan", "severity": 2},
    }


def test_repeat_event_is_stored_as_one_card(pipeline):
    assert pipeline.handle_event(scan_event()) == 1
    assert pipeline.handle_event(scan_event(minutes=1)) == 1
    cards = pipeline.db.list_cards()
    assert len(cards) == 1
    assert cards[0].count == 2
    assert cards[0].severity.value == "medium"
    assert pipeline.db.get_alert(cards[0].alert_id).count == 2


def test_credentials_are_redacted_before_database_storage(pipeline):
    alert = Alert(category=Category.PLAINTEXT_CREDENTIALS, source=AlertSource.PYTHON,
                  src_ip="192.168.1.25", details={"password": "fake-secret", "payload": "raw"})
    pipeline.handle_alert(alert)
    stored = pipeline.db.get_alert(alert.id)
    assert stored.details == {"password": "[REDACTED]"}
    assert "fake-secret" not in str(pipeline.db.list_cards()[0].to_dict())


def test_sample_log_produces_scan_and_credential_cards(pipeline):
    sample = Path(__file__).resolve().parents[1] / "fixtures" / "sample_eve.json"
    produced = sum(pipeline.handle_event(event) for event in read_events(sample))
    assert produced == 3  # Two scan occurrences and one credential alert; DNS is ignored.
    cards = {card.category: card for card in pipeline.db.list_cards()}
    assert set(cards) == {Category.PORT_SCAN, Category.PLAINTEXT_CREDENTIALS}
    assert cards[Category.PORT_SCAN].count == 2
    assert cards[Category.PLAINTEXT_CREDENTIALS].severity.value == "high"


def test_scans_of_two_home_devices_do_not_merge(pipeline):
    """Same outside scanner, two home targets, no Ethernet MAC in the event."""
    pipeline.handle_event(scan_event(dest="192.168.1.25"))
    pipeline.handle_event(scan_event(dest="192.168.1.26", minutes=1))
    cards = pipeline.db.list_cards()
    assert len(cards) == 2, "Separate home devices must keep separate alert cards"
