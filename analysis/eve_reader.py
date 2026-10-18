"""Owner: Brady — Tail Suricata's eve.json with inotify and yield parsed events.

Usage:

    from analysis.config import load_settings
    from analysis.eve_reader import follow

    settings = load_settings()
    for event in follow(settings.paths.eve_json):
        event["event_type"]  # -> "alert", "dns", "flow", ...

follow() runs until `stop` is set and survives:

  - file not existing yet: waits for it
  - rotation (rename + recreate): finishes the old file, then switches
  - truncation (copytruncate): restarts from the top
  - half-written lines: buffered until the newline arrives
  - malformed JSON: logged and skipped

Falls back to polling where inotify isn't available (macOS, or no inotify_simple).

read_events() reads a file once, for tests and replays.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from threading import Event
from typing import Any, BinaryIO, Container, Iterator, Optional, Union

try:
    from inotify_simple import INotify, flags
except ImportError:  #not Linux, or not installed
    INotify = None

log = logging.getLogger(__name__)

PathLike = Union[str, Path]

POLL_INTERVAL_SECONDS = 1.0  #also the max wait between inotify checks
READ_CHUNK_BYTES = 64 * 1024


def read_events(
    path: PathLike, event_types: Optional[Container[str]] = None
) -> Iterator[dict[str, Any]]:
    """Yield every event already in `path`, then stop."""
    with open(path, "rb") as f:
        for line in f:
            event = parse_line(line)
            if event is not None and _wanted(event, event_types):
                yield event


def follow(
    path: PathLike,
    from_start: bool = False,
    event_types: Optional[Container[str]] = None,
    stop: Optional[Event] = None,
    poll_interval: float = POLL_INTERVAL_SECONDS,
) -> Iterator[dict[str, Any]]:
    """Yield events as Suricata appends them to `path`.

    Starts at the end of the file so a restart doesn't replay old alerts,
    unless from_start=True. `event_types` filters, e.g. {"alert", "flow"}.
    Returns within poll_interval of `stop` being set.
    """
    path = Path(path)
    waiter = _Waiter(path.parent, poll_interval)
    f: Optional[BinaryIO] = None
    buffer = b""

    try:
        while not (stop and stop.is_set()):
            if f is None:
                f = _open(path, seek_end=not from_start)
                if f is None:
                    waiter.wait()
                    continue
                buffer = b""
                #Only the first file honors from_start; rotated files are all new data.
                from_start = True

            chunk = f.read(READ_CHUNK_BYTES)
            if chunk:
                buffer += chunk
                *lines, buffer = buffer.split(b"\n")
                for line in lines:
                    event = parse_line(line)
                    if event is not None and _wanted(event, event_types):
                        yield event
                continue

            #Caught up. Before sleeping, check whether the file was swapped out.
            status = _file_status(path, f)
            if status == "rotated":
                log.info("%s was rotated; switching to the new file", path)
                _warn_partial(buffer, path)
                f.close()
                f = None
            elif status == "truncated":
                log.info("%s was truncated; reading from the start", path)
                _warn_partial(buffer, path)
                f.seek(0)
                buffer = b""
            else:
                waiter.wait()
    finally:
        if f is not None:
            f.close()
        waiter.close()


def parse_line(line: Union[bytes, str]) -> Optional[dict[str, Any]]:
    """Parse one eve.json line, or return None if it's blank or not a JSON object."""
    if isinstance(line, bytes):
        line = line.decode("utf-8", errors="replace")
    line = line.strip()
    if not line:
        return None
    try:
        event = json.loads(line)
    except json.JSONDecodeError as e:
        log.warning("Skipping malformed eve.json line (%s): %.200s", e, line)
        return None
    if not isinstance(event, dict):
        log.warning("Skipping non-object eve.json line: %.200s", line)
        return None
    return event


def _wanted(event: dict[str, Any], event_types: Optional[Container[str]]) -> bool:
    return event_types is None or event.get("event_type") in event_types


def _open(path: Path, seek_end: bool) -> Optional[BinaryIO]:
    try:
        f = open(path, "rb")
    except FileNotFoundError:
        return None
    if seek_end:
        f.seek(0, os.SEEK_END)
    log.info("Reading %s from byte %d", path, f.tell())
    return f


def _file_status(path: Path, f: BinaryIO) -> str:
    """Return "rotated", "truncated", or "ok" for the open file vs. what's at `path`."""
    try:
        on_disk = os.stat(path)
    except FileNotFoundError:
        return "ok"  #renamed away and not recreated yet; keep the old one
    opened = os.fstat(f.fileno())
    if (on_disk.st_ino, on_disk.st_dev) != (opened.st_ino, opened.st_dev):
        return "rotated"
    if on_disk.st_size < f.tell():
        return "truncated"
    return "ok"


def _warn_partial(buffer: bytes, path: Path) -> None:
    if buffer.strip():
        log.warning("Dropping %d bytes of unfinished line from %s", len(buffer), path)


class _Waiter:
    """Blocks until the eve.json directory changes or poll_interval passes.

    Watches the directory, not the file, to catch creation and rotation.
    """

    def __init__(self, directory: Path, poll_interval: float) -> None:
        self.poll_interval = poll_interval
        self.inotify = None
        if INotify is None:
            log.info("inotify unavailable; polling %s every %ss", directory, poll_interval)
            return
        try:
            self.inotify = INotify()
            self.inotify.add_watch(
                str(directory),
                flags.MODIFY | flags.CREATE | flags.MOVED_TO | flags.MOVED_FROM | flags.DELETE,
            )
        except OSError as e:
            log.warning("Can't watch %s with inotify (%s); falling back to polling", directory, e)
            self.close()

    def wait(self) -> None:
        if self.inotify is None:
            time.sleep(self.poll_interval)
        else:
            self.inotify.read(timeout=int(self.poll_interval * 1000))

    def close(self) -> None:
        if self.inotify is not None:
            self.inotify.close()
            self.inotify = None
