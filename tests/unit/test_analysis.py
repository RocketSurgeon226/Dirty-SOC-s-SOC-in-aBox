"""Offline analysis QA checks. Run: python -m pytest tests/unit/test_analysis.py -q

No Pi, live network traffic, API key, or paid API calls are required.
Expected severities come from the project README, not the implementation map.
"""

from datetime import datetime, timedelta, timezone

import pytest

from analysis.config import LlmSettings
from analysis.dedup import Deduplicator
from analysis.health_score import health_score
from analysis.models import Alert, AlertSource, Category, Device, Severity
from analysis.redact import redact_alert, redact_text
from analysis.severity import assign_severity
from analysis.translate.card_builder import build_card
from analysis.translate.llm import make_reworder


NOW = datetime(2026, 10, 16, 18, 0, tzinfo=timezone.utc)


def make_alert(category=Category.PORT_SCAN, minutes=0, ip="192.168.1.25", **kwargs):
    return Alert(category=category, source=AlertSource.SURICATA,
                 timestamp=NOW + timedelta(minutes=minutes), src_ip=ip, **kwargs)


@pytest.mark.parametrize("category, expected", [
    (Category.MALICIOUS_CONTACT, Severity.HIGH),
    (Category.PLAINTEXT_CREDENTIALS, Severity.HIGH),
    (Category.PORT_SCAN, Severity.MEDIUM),
    (Category.NEW_DEVICE, Severity.MEDIUM),
    (Category.OUTBOUND_VOLUME, Severity.MEDIUM),
    (Category.TRACKER_DNS, Severity.LOW),
])
def test_severity_matches_project_requirements(category, expected):
    alert = make_alert(category, severity=Severity.LOW)
    assert assign_severity(alert).severity == expected


def test_repeat_alert_updates_one_card_count():
    dedup = Deduplicator(15)
    first, is_new = dedup.add(make_alert())
    assert is_new
    repeat, is_new = dedup.add(make_alert(minutes=5))
    assert not is_new
    assert repeat.id == first.id
    assert repeat.count == 2
    assert repeat.last_seen == NOW + timedelta(minutes=5)


def test_different_devices_do_not_merge():
    dedup = Deduplicator(15)
    dedup.add(make_alert(ip="192.168.1.25"))
    _, is_new = dedup.add(make_alert(ip="192.168.1.26"))
    assert is_new
    assert len(dedup) == 2


def test_different_categories_do_not_merge():
    dedup = Deduplicator(15)
    dedup.add(make_alert())
    _, is_new = dedup.add(make_alert(Category.PLAINTEXT_CREDENTIALS))
    assert is_new
    assert len(dedup) == 2


def test_dedup_window_slides_from_most_recent_repeat():
    dedup = Deduplicator(15)
    first, _ = dedup.add(make_alert())
    dedup.add(make_alert(minutes=10))
    third, is_new = dedup.add(make_alert(minutes=20))
    assert not is_new
    assert third.id == first.id
    assert third.count == 3


@pytest.mark.parametrize("minutes, expected_new", [(15, False), (16, True)])
def test_dedup_window_boundary(minutes, expected_new):
    dedup = Deduplicator(15)
    dedup.add(make_alert())
    _, is_new = dedup.add(make_alert(minutes=minutes))
    assert is_new is expected_new


@pytest.mark.parametrize("value", [0, -1])
def test_invalid_dedup_window_is_rejected(value):
    with pytest.raises(ValueError):
        Deduplicator(value)


@pytest.mark.parametrize("text, secret", [
    ("password=fake-secret-123&user=test", "fake-secret-123"),
    ("Authorization: Basic dGVzdDpmYWtl", "dGVzdDpmYWtl"),
    ("https://tester:fake-secret-123@example.test/", "fake-secret-123"),
])
def test_credentials_are_removed_from_text(text, secret):
    result = redact_text(text)
    assert secret not in result
    assert "[REDACTED]" in result


def test_nested_secrets_and_raw_payloads_are_removed():
    alert = make_alert(Category.PLAINTEXT_CREDENTIALS, details={
        "payload": "raw-password", "password_seen": True,
        "nested": [{"api_key": "fake-key", "note": "password=fake-pass"}],
        "direction": "outbound",
    })
    redact_alert(alert)
    assert "payload" not in alert.details
    assert alert.details["password_seen"] is True
    assert alert.details["direction"] == "outbound"
    assert alert.details["nested"][0]["api_key"] == "[REDACTED]"
    assert "fake-pass" not in str(alert.details)


@pytest.mark.parametrize("category", list(Category))
def test_every_category_produces_a_four_part_card_without_ai(category):
    card = build_card(make_alert(category))
    assert card.device_name == "Unrecognized device"
    assert card.severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH)
    assert card.description.strip()
    assert card.action.strip()
    assert card.llm_enhanced is False


def test_named_device_appears_on_card():
    device = Device(mac="02:00:00:00:00:01", friendly_name="Living room TV")
    assert build_card(make_alert(), device).device_name == "Living room TV"


def test_llm_failure_keeps_template_card():
    alert = make_alert()
    expected = build_card(alert)

    def unavailable(*args):
        raise TimeoutError("Simulated offline API")

    actual = build_card(alert, reword=unavailable)
    assert actual.to_dict() == expected.to_dict()


@pytest.mark.parametrize("answer", [None, ("", "Do something"), ("Description", "  ")])
def test_empty_llm_answer_keeps_template_card(answer):
    alert = make_alert()
    assert build_card(alert, reword=lambda *args: answer).to_dict() == build_card(alert).to_dict()


@pytest.mark.parametrize("settings", [
    LlmSettings(enabled=False, api_key="fake-unused-key"),
    LlmSettings(enabled=True, api_key=None),
])
def test_ai_disabled_or_missing_key_uses_templates(settings):
    assert make_reworder(settings) is None


def test_health_score_counts_severity_once_per_card():
    cards = [build_card(make_alert(category)) for category in (
        Category.MALICIOUS_CONTACT, Category.PORT_SCAN, Category.TRACKER_DNS)]
    cards[0].count = 100
    result = health_score(cards, now=NOW)
    assert result.score == 62  # 100 - 25 - 10 - 3; repeats do not multiply it
    assert result.label == "Fair"


def test_health_score_ignores_acknowledged_old_and_future_cards():
    handled = build_card(make_alert(Category.MALICIOUS_CONTACT))
    handled.acknowledged = True
    old = build_card(make_alert(minutes=-1441))
    future = build_card(make_alert(minutes=1))
    assert health_score([handled, old, future], now=NOW).score == 100


def test_health_score_never_drops_below_zero():
    cards = [build_card(make_alert(Category.MALICIOUS_CONTACT)) for _ in range(5)]
    assert health_score(cards, now=NOW).score == 0
