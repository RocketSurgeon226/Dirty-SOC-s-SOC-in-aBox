"""Owner: Brady — Optional LLM rewording; must fall back to templates on error/timeout.

Usage:

    from analysis.translate.llm import make_reworder
    from analysis.translate.card_builder import build_card

    reword = make_reworder(settings.llm)  # None if off, no API key, or no anthropic package
    card = build_card(alert, device, reword=reword)

The LLM only rewords the template text to read more naturally. It never sees
IPs, MACs, hostnames, device names, or anything else from the traffic: just
the category, the template's description and action, and how many times it
happened. So a homeowner's network details never leave the Pi.

Every failure returns None, which makes card_builder keep the template:
timeouts, network errors, bad JSON, answers that are empty or too long. After
a failure the LLM is skipped for a few minutes, so a dead internet connection
doesn't add a timeout to every alert. Answers are passed through
redact_text() before use, just in case.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Optional

from analysis.config import LlmSettings
from analysis.models import Alert
from analysis.redact import redact_text
from analysis.translate.card_builder import Reworder

log = logging.getLogger(__name__)

MAX_SENTENCE_CHARS = 200
COOLDOWN_SECONDS = 300  #how long to skip the LLM after a failure

SYSTEM_PROMPT = """\
You reword home network security alerts for people with no technical background.
You get a description of what happened and a recommended action.
Rewrite each as ONE short, calm, friendly sentence in plain everyday English.
Keep the exact meaning and the same recommended action. Do not add new facts,
steps, numbers, product names, or technical terms. Do not use jargon like IP,
DNS, port, packet, or protocol.
Reply with only JSON: {"description": "...", "action": "..."}"""

#Forces the reply into {"description": str, "action": str}
ANSWER_SCHEMA = {
    "type": "object",
    "properties": {
        "description": {"type": "string"},
        "action": {"type": "string"},
    },
    "required": ["description", "action"],
    "additionalProperties": False,
}


def make_reworder(settings: LlmSettings) -> Optional[Reworder]:
    """Build the reword hook for card_builder, or None if the LLM can't be used."""
    if not settings.usable:
        if settings.enabled:
            log.warning("LLM is enabled but ANTHROPIC_API_KEY isn't set; using templates only")
        return None
    try:
        from anthropic import Anthropic
    except ImportError:
        log.warning("LLM is enabled but the anthropic package isn't installed; using templates only")
        return None

    client = Anthropic(api_key=settings.api_key, timeout=settings.timeout_seconds, max_retries=0)
    return _LlmReworder(client, settings.model)


class _LlmReworder:
    def __init__(self, client, model: str) -> None:
        self.client = client
        self.model = model
        self._skip_until = 0.0

    def __call__(self, alert: Alert, description: str, action: str) -> Optional[tuple[str, str]]:
        if time.monotonic() < self._skip_until:
            return None
        try:
            result = self._ask(alert, description, action)
        except Exception as e:
            log.warning("LLM rewording failed (%s); using templates for %ds", e, COOLDOWN_SECONDS)
            self._skip_until = time.monotonic() + COOLDOWN_SECONDS
            return None
        if result is None:
            log.info("LLM answer for %s was unusable; using template", alert.category.value)
        return result

    def _ask(self, alert: Alert, description: str, action: str) -> Optional[tuple[str, str]]:
        prompt = json.dumps(
            {
                "alert_type": alert.category.value.replace("_", " "),
                "times_seen": alert.count,
                "description": description,
                "action": action,
            }
        )
        response = self.client.beta.messages.create(
            model=self.model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
            output_config={
                "effort": "low",  #short rewording; no deep reasoning needed
                "format": {"type": "json_schema", "schema": ANSWER_SCHEMA},
            },
            #if Claude declines, Anthropic retries on another model in the same call
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
        if response.stop_reason != "end_turn":  #refusal or cut off at max_tokens
            return None
        text = next((b.text for b in response.content if b.type == "text"), "")
        return _parse_answer(text)


def _parse_answer(content: str) -> Optional[tuple[str, str]]:
    """Pull (description, action) out of the model's JSON, or None if it's not usable."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    out = []
    for key in ("description", "action"):
        value = data.get(key)
        if not isinstance(value, str):
            return None
        value = " ".join(value.split())
        if not value or len(value) > MAX_SENTENCE_CHARS:
            return None
        out.append(redact_text(value))
    return out[0], out[1]
