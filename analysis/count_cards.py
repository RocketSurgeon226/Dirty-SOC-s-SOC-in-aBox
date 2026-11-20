"""Owner: Brady — Count alert cards in the SOC database, for the baseline write-up.

Usage (from the repo root):

    python3 -m analysis.count_cards                         # data/soc_in_a_box.db
    python3 -m analysis.count_cards backup.db               # any copy of it
    python3 -m analysis.count_cards --since 2026-11-20 --until 2026-11-27

"Cards" is what the household saw; "alerts" also counts repeats that dedup
folded into an existing card. --since / --until filter on the card's first
timestamp (UTC, --until is exclusive). The database is opened read-only, so
this is safe to run while the services are up. Standard library only.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path
from typing import Optional

DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "soc_in_a_box.db"

TOTALS_SQL = """
SELECT COUNT(*), COALESCE(SUM(count), 0), COALESCE(SUM(acknowledged), 0),
       COALESCE(SUM(llm_enhanced), 0), MIN(timestamp), MAX(timestamp)
FROM cards WHERE timestamp >= ? AND timestamp < ?
"""

BY_CATEGORY_SQL = """
SELECT category, severity, COUNT(*), SUM(count)
FROM cards WHERE timestamp >= ? AND timestamp < ?
GROUP BY category, severity
ORDER BY COUNT(*) DESC, category
"""


def open_read_only(path: Path) -> sqlite3.Connection:
    if not path.exists():
        raise FileNotFoundError(f"No database at {path}")
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.execute("SELECT 1 FROM cards LIMIT 1")
        return conn
    except sqlite3.OperationalError:
        #A WAL-mode copy with no -shm file can't open read-only. Nothing is
        #writing to a copy, so treat it as unchanging instead.
        conn = sqlite3.connect(f"file:{path}?immutable=1", uri=True)
        conn.execute("SELECT 1 FROM cards LIMIT 1")
        return conn


def count_cards(
    conn: sqlite3.Connection, since: Optional[str] = None, until: Optional[str] = None
) -> dict:
    window = (since or "", until or "￿")  #ISO strings sort as text
    cards, alerts, acked, llm, first, last = conn.execute(TOTALS_SQL, window).fetchone()
    rows = conn.execute(BY_CATEGORY_SQL, window).fetchall()
    return {
        "cards": cards, "alerts": alerts, "acknowledged": acked, "llm_enhanced": llm,
        "first": first, "last": last,
        "by_category": [
            {"category": c, "severity": s, "cards": n, "alerts": a} for c, s, n, a in rows
        ],
    }


def format_report(r: dict) -> str:
    lines = [
        f"Cards: {r['cards']}   Alerts incl. repeats: {r['alerts']}   "
        f"Acknowledged: {r['acknowledged']}   LLM-reworded: {r['llm_enhanced']}",
        f"From {r['first'] or '-'} to {r['last'] or '-'}",
        "",
        f"{'Category':<24}{'Severity':<10}{'Cards':>7}{'Alerts':>9}",
    ]
    for row in r["by_category"]:
        lines.append(
            f"{row['category']:<24}{row['severity']:<10}{row['cards']:>7}{row['alerts']:>9}"
        )
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Count alert cards in the SOC database.")
    p.add_argument("database", nargs="?", type=Path, default=DEFAULT_DB)
    p.add_argument("--since", help="UTC date/time to start from, e.g. 2026-11-20")
    p.add_argument("--until", help="UTC date/time to stop before, e.g. 2026-11-27")
    args = p.parse_args(argv)
    try:
        conn = open_read_only(args.database)
    except (FileNotFoundError, sqlite3.Error) as e:
        print(f"Can't read {args.database}: {e}", file=sys.stderr)
        return 1
    with conn:
        print(format_report(count_cards(conn, args.since, args.until)))
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
