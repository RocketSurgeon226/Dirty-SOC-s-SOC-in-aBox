"""Owner: Brady — One card per device + problem, a fair grade, mutes and reopening."""
from datetime import datetime, timedelta, timezone

import pytest

from analysis.config import Settings
from analysis.health_score import health_score, points_for
from analysis.issues import list_issues, set_issue_acknowledged
from analysis.main import Pipeline
from analysis.models import Alert, AlertCard, AlertSource, Category, Severity
from analysis.storage.db import Database

T0 = datetime(2026, 11, 19, 12, tzinfo=timezone.utc)


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


def burst(mac="aa:bb:cc:00:00:09", hours=0.0):
    return Alert(category=Category.OUTBOUND_VOLUME, source=AlertSource.PYTHON, device_mac=mac,
                 timestamp=T0 + timedelta(hours=hours), details={"home_ip": "192.168.1.9"})


def test_hours_apart_is_still_one_card(pipeline):
    for h in (0, 1, 5, 30):  # well past the 15-minute dedup window
        pipeline.handle_alert(burst(hours=h))
    cards = pipeline.db.list_cards()
    assert len(cards) == 1 and cards[0].count == 4


def test_two_devices_stay_apart(pipeline):
    pipeline.handle_alert(burst("aa:bb:cc:00:00:09"))
    pipeline.handle_alert(burst("aa:bb:cc:00:00:0a"))
    assert len(pipeline.db.list_cards()) == 2


def test_a_repeat_after_got_it_comes_back_as_a_new_card(pipeline):
    first = burst()
    pipeline.handle_alert(first)
    pipeline.db.acknowledge(first.id)
    pipeline.handle_alert(burst(hours=0.05))  # inside the dedup window
    open_cards = pipeline.db.list_cards(include_acknowledged=False)
    assert len(open_cards) == 1 and open_cards[0].alert_id != first.id


def test_muted_alerts_make_no_card(pipeline):
    pipeline.db.mute("aa:bb:cc:00:00:09", Category.OUTBOUND_VOLUME)
    pipeline.handle_alert(burst())
    assert pipeline.db.list_cards() == []
    pipeline.handle_alert(burst("aa:bb:cc:00:00:0a"))  # another device still alerts
    assert len(pipeline.db.list_cards()) == 1


def test_old_split_cards_group_into_one_issue_and_ack_together(tmp_path):
    db = Database(tmp_path / "old.sqlite")
    ids = []
    for h in (0, 3, 6):  # how older databases stored one noisy device
        a = burst(hours=h)
        a.severity = Severity.MEDIUM
        db.save_alert(a)
        db.save_card(AlertCard(a.id, a.category, "Unrecognized device", Severity.MEDIUM, "old text", "old", a.timestamp))
        ids.append(a.id)
    issues = list_issues(db, now=T0 + timedelta(hours=7))
    assert len(issues) == 1
    issue = issues[0]
    assert issue.count == 3 and issue.first_seen == T0 and issue.last_seen == T0 + timedelta(hours=6)
    assert issue.description == "This device is sending far more data than usual."  # current wording
    assert issue.meaning and issue.device_ip == "192.168.1.9"
    assert set_issue_acknowledged(db, ids[1], True)
    assert db.list_cards(include_acknowledged=False) == []
    assert len(list_issues(db, acknowledged=True, now=T0 + timedelta(hours=7))) == 1
    db.close()


class _Item:
    def __init__(self, severity, category="outbound_volume", hours=0):
        self.severity, self.category = severity, category
        self.first_seen = self.last_seen = T0 + timedelta(hours=hours)


def test_one_noisy_category_cannot_sink_the_grade():
    noisy = [_Item(Severity.MEDIUM) for _ in range(40)]
    assert health_score(noisy, now=T0).score == 81  # capped at two issues: 100 * .9 * .9
    high = _Item(Severity.HIGH, "malicious_contact")
    items = noisy + [high]
    assert health_score(items, now=T0).score == 61  # 81 * .75
    assert points_for(high, items, now=T0) == 20


def test_score_never_bottoms_out():
    many = [_Item(Severity.HIGH, c) for c in ("malicious_contact", "plaintext_credentials") for _ in range(5)]
    many += [_Item(Severity.MEDIUM, c) for c in ("outbound_volume", "port_scan", "new_device") for _ in range(5)]
    items = many + [_Item(Severity.LOW, "tracker_dns")]
    score = health_score(items, now=T0).score
    assert 0 < score < 20
    assert points_for(items[-1], items, now=T0) > 0  # the only tracker issue


def test_grade_counts_the_last_7_days():
    stale = _Item(Severity.HIGH, "malicious_contact", hours=-24 * 8)
    recent = _Item(Severity.HIGH, "malicious_contact", hours=-24 * 4)
    assert health_score([stale, recent], now=T0).score == 75
