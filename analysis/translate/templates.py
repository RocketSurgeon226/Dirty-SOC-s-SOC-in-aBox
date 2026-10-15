"""Owner: Brady — One fixed description + recommended action per category (the reliable fallback).

Usage:

    from analysis.translate.templates import template_for
    t = template_for(Category.PORT_SCAN)
    t.description  # -> "Someone or something scanned your network from outside."
    t.action       # -> "Make sure your router's software is up to date ..."

The descriptions match the alert category table in README.md. Each action is
one thing a homeowner with no security background can do right now. The text
never includes IPs, ports, or hostnames from the traffic, so it is always the
same reviewed wording, and the usability tests measure exactly what ships.
"""

from __future__ import annotations

from dataclasses import dataclass

from analysis.models import Category


@dataclass(frozen=True)
class Template:
    description: str  #one sentence: what happened
    action: str  #one sentence: what to do about it


TEMPLATES: dict[Category, Template] = {
    Category.MALICIOUS_CONTACT: Template(
        description="This device contacted a known bad server.",
        action="Disconnect this device from your network, then run a virus scan and update its software.",
    ),
    Category.PLAINTEXT_CREDENTIALS: Template(
        description="A device on your network sent a password in an unprotected way.",
        action="Change that password, and only sign in to sites that show a padlock in the address bar.",
    ),
    Category.PORT_SCAN: Template(
        description="Someone or something scanned your network from outside.",
        action="Make sure your router's software is up to date and its remote management is turned off.",
    ),
    Category.NEW_DEVICE: Template(
        description="A new device joined your network; was this you?",
        action="If you recognize it, give it a name on the Devices page; if not, change your Wi-Fi password.",
    ),
    Category.OUTBOUND_VOLUME: Template(
        description="This device is sending far more data than usual.",
        action="If you aren't uploading or backing up files right now, disconnect this device and run a virus scan.",
    ),
    Category.TRACKER_DNS: Template(
        description="This device is sending an unusual amount of data to ad and tracking companies.",
        action="Turn on tracking protection in this device's browser or privacy settings.",
    ),
}


def template_for(category: Category) -> Template:
    """Look up the fixed wording for a category."""
    return TEMPLATES[Category(category)]
