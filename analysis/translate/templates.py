"""Owner: Brady — One fixed description + recommended action per category (the reliable fallback).

Usage:

    from analysis.translate.templates import template_for, template_for_alert
    t = template_for(Category.PORT_SCAN)
    t.description  # -> "Computers outside your home checked your network for a way in."
    t.action       # -> "Nothing to do right now. ..."
    t.meaning      # -> how worried to be, in one sentence
    template_for_alert(alert)  # same, but picks the port-scan wording by direction

Descriptions match the category table in README.md; each action is one thing a
non-technical homeowner can do right now, and `meaning` says what it likely
means and how seriously to take it. No traffic details (IPs, ports, hostnames)
are filled in, so the usability tests measure exactly what ships.
"""

from __future__ import annotations

from dataclasses import dataclass

from analysis.models import Alert, Category


@dataclass(frozen=True)
class Template:
    description: str  #one sentence: what happened
    action: str  #one sentence: what to do about it
    meaning: str = ""  #one sentence: what it probably means, and how worried to be


TEMPLATES: dict[Category, Template] = {
    Category.MALICIOUS_CONTACT: Template(
        description="This device contacted a known bad server.",
        action="Disconnect this device from your network, then run a virus scan and update its software.",
        meaning="This often means unwanted software is on the device. Take it seriously, even if the device seems fine.",
    ),
    Category.PLAINTEXT_CREDENTIALS: Template(
        description="A device on your network sent a password without hiding it.",
        action="Change that password, and only sign in to sites that show a padlock in the address bar.",
        meaning="Anyone nearby on the same network could have read it, so treat that password as known to others.",
    ),
    #Inbound: the internet probing the home connection. Happens to everyone.
    Category.PORT_SCAN: Template(
        description="Computers outside your home checked your network for a way in.",
        action="Nothing to do right now. Most home routers turn these away on their own.",
        meaning="This happens to almost every home internet connection many times a day. It's usually nothing to worry about.",
    ),
    Category.NEW_DEVICE: Template(
        description="A new device joined your network; was this you?",
        action="If you recognize it, give it a name on the Devices page; if not, change your Wi-Fi password.",
        meaning="It's usually a guest's phone or something new you plugged in. If no one recognizes it, someone may be using your Wi-Fi.",
    ),
    Category.OUTBOUND_VOLUME: Template(
        description="This device is sending far more data than usual.",
        action="If no one is backing up, uploading or video calling on it, disconnect it and run a virus scan.",
        meaning="It's usually a backup, upload or video call. It's only a worry if nobody is using the device that way.",
    ),
    Category.TRACKER_DNS: Template(
        description="This device is sending an unusual amount of data to ad and tracking companies.",
        action="Turn on tracking protection in this device's browser or privacy settings.",
        meaning="This is common and not dangerous, but it means apps on the device share how it's used.",
    ),
}

#Port scans started by a home device, keyed by the alert's details["direction"].
#TEMPLATES[PORT_SCAN] is the inbound wording; it's also used when direction is
#unknown, e.g. a Python-built alert.
SCAN_FROM_HOME_ACTION = (
    "If no one here is running a network tool on this device, "
    "disconnect it and run a virus scan."
)
SCAN_FROM_HOME_MEANING = (
    "Some apps and printers do this, but it can also mean unwanted software "
    "is looking for other devices to spread to."
)
PORT_SCAN_BY_DIRECTION: dict[str, Template] = {
    "internal": Template(
        description="This device scanned other devices on your network.",
        action=SCAN_FROM_HOME_ACTION,
        meaning=SCAN_FROM_HOME_MEANING,
    ),
    "outbound": Template(
        description="This device scanned computers out on the internet.",
        action=SCAN_FROM_HOME_ACTION,
        meaning=SCAN_FROM_HOME_MEANING,
    ),
}


def template_for(category: Category) -> Template:
    return TEMPLATES[Category(category)]


def template_for_alert(alert: Alert) -> Template:
    """Like template_for, but port scans get wording that matches who scanned whom."""
    if alert.category == Category.PORT_SCAN:
        variant = PORT_SCAN_BY_DIRECTION.get(scan_direction(alert))
        if variant is not None:
            return variant
    return template_for(alert.category)


def scan_direction(alert: Alert) -> str:
    """"inbound", "internal" or "outbound"; inbound when the alert doesn't say."""
    direction = (alert.details or {}).get("direction")
    return direction if direction in PORT_SCAN_BY_DIRECTION else "inbound"
