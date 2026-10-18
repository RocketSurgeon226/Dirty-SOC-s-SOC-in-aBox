"""
vendors.py: guess who made a device from its MAC address, so households can tell
"Made by Amazon" apart from "Made by Apple" when naming devices.

The first three bytes of a MAC (the OUI) belong to the maker. This module reads the
maker list from a file that is already on most Linux systems; nothing is downloaded,
so it works on an isolated network. On the Pi, install one of them:

    sudo apt install nmap          # /usr/share/nmap/nmap-mac-prefixes (also used for testing)
    sudo apt install ieee-data     # /usr/share/ieee-data/oui.txt

If none is found, vendor_for() returns None and the dashboard just doesn't show a maker.
Only Python's standard library is used here.
"""

import os
import re
import threading

OUI_FILES = (
    "/usr/share/nmap/nmap-mac-prefixes",
    "/opt/homebrew/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
    "/usr/share/wireshark/manuf",
    "/usr/share/ieee-data/oui.txt",
)

# "Amazon Technologies Inc." -> "Amazon"
_SUFFIX = re.compile(r"[\s,.]+(inc|corp|corporation|co|company|ltd|llc|limited|gmbh|ag|sa|plc|"
                     r"technologies|technology|trading|electronics|international)\.?$", re.I)

_table = None
_lock = threading.Lock()


def _clean(name):
    name = name.strip()
    while True:
        shorter = _SUFFIX.sub("", name).strip(" ,.")
        if shorter == name or not shorter:
            return name
        name = shorter


def _parse_line(line):
    """(six hex digits, maker) from one line of any supported file, or None."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = re.match(r"^([0-9A-Fa-f]{2})[-:]?([0-9A-Fa-f]{2})[-:]?([0-9A-Fa-f]{2})(\s+\(hex\))?\s+(.+)$", line)
    if not m:
        return None  # includes Wireshark's /28 and /36 ranges, which have a "/" after the prefix
    name = m.group(5).split("\t")[-1]  # Wireshark: short name<TAB>long name
    return (m.group(1) + m.group(2) + m.group(3)).upper(), _clean(name)


def _load():
    table = {}
    for path in OUI_FILES:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    parsed = _parse_line(line)
                    if parsed:
                        table.setdefault(parsed[0], parsed[1])
        except OSError:
            continue
        if table:
            break
    return table


def vendor_for(mac):
    """Maker's short name for a MAC address, or None if unknown."""
    global _table
    if not mac or is_private(mac):
        return None
    with _lock:
        if _table is None:
            _table = _load()
    return _table.get(mac.replace(":", "").replace("-", "")[:6].upper())


def is_private(mac):
    """True for a randomized ("private") address, which phones, tablets and laptops use
    by default. Those have the locally-administered bit set, and no real maker."""
    try:
        return bool(int(mac.replace("-", ":").split(":")[0], 16) & 0x02)
    except (ValueError, IndexError, AttributeError):
        return False
