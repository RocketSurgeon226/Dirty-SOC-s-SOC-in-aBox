"""Owner: Brady — Entry point: start the eve.json watcher and the processing pipeline.

Usage:

    python -m analysis.main                      # tail eve.json from settings
    python -m analysis.main --from-start         # process what's already there first
    python -m analysis.main --replay tests/fixtures/sample_eve.json
    python -m analysis.main --settings config/settings.yaml -v

Pipeline, one event at a time:

    eve.json -> eve_reader -> categorize -> Alert -> process_alert()

process_alert() is where dedup, severity, redaction, card building, and storage
plug in as those modules are finished. Until then it logs each alert.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
from pathlib import Path
from threading import Event
from typing import Any, Iterable, Optional

from analysis.categorize import categorize
from analysis.config import ConfigError, Settings, load_settings
from analysis.eve_reader import follow, read_events
from analysis.models import Alert

log = logging.getLogger("analysis")


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

    try:
        count = run(events, settings, stop)
    except KeyboardInterrupt:
        count = None
    log.info("Stopped%s", f" after {count} alert(s)" if count is not None else "")
    return 0


def run(events: Iterable[dict[str, Any]], settings: Settings, stop: Optional[Event] = None) -> int:
    """Push every event through the pipeline. Returns how many alerts were produced."""
    count = 0
    for event in events:
        if stop and stop.is_set():
            break
        try:
            alert = categorize(event, settings.network)
            if alert is not None:
                process_alert(alert, settings)
                count += 1
        except Exception:
            #One bad event must never take down the service.
            log.exception("Failed to process event: %.200s", event)
    return count


def process_alert(alert: Alert, settings: Settings) -> None:
    """Handle one categorized alert.

    Next stages, in order: dedup -> severity -> redact -> card_builder -> storage.
    """
    log.info(
        "%s %s -> %s (%s)",
        alert.category.value,
        alert.src_ip,
        alert.dest_ip,
        alert.signature,
    )


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
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return p.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
