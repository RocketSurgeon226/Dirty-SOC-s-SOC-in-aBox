"""Owner: Brady — Assemble the four-part card: device name, severity, description, action.

Usage:

    from analysis.translate.card_builder import build_card
    card = build_card(alert, device)  # device from the inventory, or None

Description and action come from the category's template. `reword` is the
optional LLM hook (translate/llm.py): it gets the alert and template text and
returns a new (description, action), or None to keep the template. Any error
or empty answer also keeps the template, so a card is always produced.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from analysis.models import UNRECOGNIZED_DEVICE, Alert, AlertCard, Device
from analysis.severity import severity_for
from analysis.translate.templates import template_for

log = logging.getLogger(__name__)

Reworder = Callable[[Alert, str, str], Optional[tuple[str, str]]]


def build_card(
    alert: Alert, device: Optional[Device] = None, reword: Optional[Reworder] = None
) -> AlertCard:
    template = template_for(alert.category)
    description, action = template.description, template.action
    llm_enhanced = False

    if reword is not None:
        try:
            result = reword(alert, description, action)
        except Exception:
            log.warning("Rewording failed for %s; using template", alert.id, exc_info=True)
            result = None
        if result and all(isinstance(s, str) and s.strip() for s in result):
            description, action = (s.strip() for s in result)
            llm_enhanced = True

    return AlertCard(
        alert_id=alert.id,
        category=alert.category,
        device_name=device.display_name if device else UNRECOGNIZED_DEVICE,
        severity=alert.severity or severity_for(alert.category),
        description=description,
        action=action,
        timestamp=alert.timestamp,
        count=alert.count,
        llm_enhanced=llm_enhanced,
    )
