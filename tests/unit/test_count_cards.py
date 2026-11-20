"""Owner: Brady — The baseline card count matches what the pipeline stored."""
from analysis.config import Settings
from analysis.count_cards import count_cards, main, open_read_only
from analysis.main import Pipeline
from analysis.storage.db import Database
from tests.unit.test_templates import scan


def test_counts_cards_and_repeats(tmp_path, capsys):
    path = tmp_path / "soc.db"
    db = Database(path)
    pipeline = Pipeline(Settings(), db)
    pipeline.handle_event(scan("203.0.113.10", "192.168.1.25"))
    pipeline.handle_event(scan("203.0.113.10", "192.168.1.25"))  #repeat -> same card
    pipeline.handle_event(scan("192.168.1.40", "192.168.1.25"))
    db.close()

    conn = open_read_only(path)
    r = count_cards(conn)
    assert (r["cards"], r["alerts"]) == (2, 3)
    assert r["by_category"] == [
        {"category": "port_scan", "severity": "medium", "cards": 2, "alerts": 3}
    ]
    assert count_cards(conn, since="2026-11-20")["cards"] == 0
    conn.close()

    assert main([str(path)]) == 0
    assert "Cards: 2" in capsys.readouterr().out


def test_missing_database(tmp_path):
    assert main([str(tmp_path / "nope.db")]) == 1
