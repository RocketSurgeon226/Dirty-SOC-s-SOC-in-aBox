"""Owner: Brady — Entry point: start the eve.json watcher and the processing pipeline.

Usage:

    python -m analysis.main                      # tail eve.json from settings
    python -m analysis.main --from-start         # process what's already there first
    python -m analysis.main --replay tests/fixtures/sample_eve.json --db :memory:
    python -m analysis.main --settings config/settings.yaml -v

Pipeline, one event at a time:

    eve.json -> eve_reader -> categorize ----------\
                           -> outbound_volume -----+-> Pipeline.handle_alert()

handle_alert(): redact -> severity -> dedup -> (new) device lookup + card + save
                                           -> (repeat) bump the count on the saved card

Old alerts are purged per settings.retention at startup and every hour.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from pathlib import Path
from threading import Event
from typing import Any, Iterable, Optional

from analysis.categorize import categorize
from analysis.config import ConfigError, Settings, load_settings
from analysis.dedup import Deduplicator
from analysis.detectors.outbound_volume import OutboundVolumeDetector
from analysis.eve_reader import follow, read_events
from analysis.models import Alert
from analysis.redact import redact_alert
from analysis.severity import assign_severity
from analysis.storage.db import Database
from analysis.translate.card_builder import build_card
from analysis.translate.llm import make_reworder

log = logging.getLogger("analysis")

PURGE_INTERVAL_SECONDS = 3600


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    try:
        settings = load_settings(args.settings)
    except ConfigError as e:
        log.error("Bad settings: %s", e)
        return 2

    stop = Event()
    _handle_shutdown_signals(stop)

    if args.replay:
        events: Iterable[dict[str, Any]] = read_events(args.replay)
        log.info("Replaying %s", args.replay)
    else:
        events = follow(settings.paths.eve_json, from_start=args.from_start, stop=stop)
        log.info("Watching %s", settings.paths.eve_json)

    db = Database(args.db or settings.paths.database)
    try:
        count = run(events, settings, stop, db=db)
    except KeyboardInterrupt:
        count = None
    finally:
        db.close()
    log.info("Stopped%s", f" after {count} alert(s)" if count is not None else "")
    return 0


def run(
    events: Iterable[dict[str, Any]],
    settings: Settings,
    stop: Optional[Event] = None,
    db: Optional[Database] = None,
) -> int:
    """Push every event through the pipeline. Returns how many alerts were produced."""
    pipeline = Pipeline(settings, db or Database(settings.paths.database))
    count = 0
    for event in events:
        if stop and stop.is_set():
            break
        count += pipeline.handle_event(event)
        pipeline.purge_if_due()
    return count


class Pipeline:
    """Everything that keeps state between events: dedup memory, detectors, the database."""

    def __init__(self, settings: Settings, db: Database) -> None:
        self.settings = settings
        self.db = db
        self.dedup = Deduplicator(settings.dedup.window_minutes)
        self.outbound = OutboundVolumeDetector(settings.detectors.outbound_volume, settings.network)
        self.reword = make_reworder(settings.llm)
        self._next_purge = 0.0

    def handle_event(self, event: dict[str, Any]) -> int:
        """Run one eve.json event through every detector. Returns alerts produced."""
        produced = 0
        for detect in (self._categorize, self.outbound.process):
            try:
                alert = detect(event)
                if alert is not None:
                    self.handle_alert(alert)
                    produced += 1
            except Exception:
                #One bad event must never take down the service.
                log.exception("Failed to process event: %.200s", event)
        return produced

    def handle_alert(self, alert: Alert) -> None:
        """Redact, score, dedup, and store one alert from any detector."""
        redact_alert(alert)  # first, so nothing downstream ever holds a credential
        assign_severity(alert)
        alert, is_new = self.dedup.add(alert)
        if not is_new:
            self.db.update_repeat(alert)
            log.debug("Repeat %s for %s (x%d)", alert.category.value, alert.device_key, alert.count)
            return

        device = self.db.find_device(mac=alert.device_mac, ip=alert.details.get("home_ip") or alert.src_ip)
        card = build_card(alert, device, reword=self.reword)
        self.db.save_alert(alert)
        self.db.save_card(card)
        log.info(
            "[%s] %s: %s (%s -> %s, %s)",
            card.severity.value,
            card.device_name,
            card.description,
            alert.src_ip,
            alert.dest_ip,
            alert.signature or alert.category.value,
        )

    def purge_if_due(self) -> None:
        if time.monotonic() < self._next_purge:
            return
        self._next_purge = time.monotonic() + PURGE_INTERVAL_SECONDS
        try:
            removed = self.db.purge_older_than(self.settings.retention.days)
        except Exception:
            log.exception("Retention purge failed")
            return
        if removed:
            log.info("Deleted %d alert(s) older than %d days", removed, self.settings.retention.days)

    def _categorize(self, event: dict[str, Any]) -> Optional[Alert]:
        return categorize(event, self.settings.network)


def _handle_shutdown_signals(stop: Event) -> None:
    """Let systemd's SIGTERM shut down as cleanly as Ctrl-C."""

    def handler(signum: int, _frame: Any) -> None:
        log.info("Received %s, shutting down", signal.Signals(signum).name)
        stop.set()

    signal.signal(signal.SIGTERM, handler)


def _parse_args(argv: Optional[list[str]]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="analysis.main", description=__doc__.splitlines()[0])
    p.add_argument("--settings", type=Path, help="settings YAML (default: config/settings.yaml)")
    p.add_argument("--from-start", action="store_true", help="read eve.json from the beginning")
    p.add_argument("--replay", type=Path, help="process a saved eve.json once and exit")
    p.add_argument("--db", help="database file to use instead of settings (':memory:' for none)")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return p.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())





