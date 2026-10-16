"""Owner: Brady — Strip credentials before a plaintext-credential alert reaches its card.

Usage:

    from analysis.redact import redact_alert, redact_text

    redact_alert(alert)       # scrubs alert.details in place
    redact_text(description)  # scrub any string, e.g. before it goes to the LLM

categorize.py already avoids copying payloads, but the Python detectors and
future code can put anything in `details`, so every alert passes through here
before it is deduped, stored, shown, or sent anywhere. Three layers:

  1. Keys that can only hold raw traffic (payload, request body, ...) are dropped.
  2. Keys named like a secret (password, token, cookie, ...) keep the key but
     the value becomes "[REDACTED]", so the card can still say a password was sent.
  3. Every remaining string is scanned for credentials in the text itself:
     "Authorization: Basic ...", "Bearer ...", "password=...", "user:pass@host".
"""

from __future__ import annotations

import re
from typing import Any

from analysis.models import Alert

REDACTED = "[REDACTED]"

#Keys whose values are raw traffic. Removed outright.
DROP_KEYS = {
    "payload",
    "payload_printable",
    "packet",
    "packet_info",
    "http_request_body",
    "http_response_body",
    "request_body",
    "response_body",
    "body",
}

#A key is secret if it, or any _-separated part of it, is one of these.
#Matching whole parts keeps "pass" from catching "passive" or "auth" from
#catching "author".
SECRET_KEY_PARTS = {
    "password",
    "passwd",
    "passphrase",
    "pass",
    "pwd",
    "secret",
    "token",
    "authorization",
    "auth",
    "cookie",
    "session",
    "sessionid",
    "apikey",
    "credential",
    "credentials",
    "privatekey",
}
SECRET_KEYS = {"api_key", "private_key", "set_cookie", "http_user", "http_password"}

_TEXT_PATTERNS = [
    #Authorization: Basic dXNlcjpwYXNz -> everything after the colon goes
    (re.compile(r"(?i)\b((?:proxy-)?authorization\s*[:=]\s*)[^\r\n]+"), r"\1" + REDACTED),
    #A bare "Basic dXNlcjpwYXNz" / "Bearer eyJ...". The token must look encoded
    #(a digit, + / =, or a lowercase letter followed later by a capital) so
    #"HTTP Basic Auth" and "basic security" survive.
    (
        re.compile(
            r"(?i:\b(basic|bearer|digest|ntlm|negotiate))\s+"
            r"(?=[^\s,;]*[0-9+/=]|[^\s,;]*[a-z][^\s,;]*[A-Z])[\w+/=.~-]{6,}"
        ),
        r"\1 " + REDACTED,
    ),
    #password=hunter2, pwd: hunter2, "token":"abc"
    (
        re.compile(
            r"(?i)([\"']?\b(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|auth|"
            r"session(?:id)?|cookie)[\"']?\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s&;,\"']+)"
        ),
        r"\1" + REDACTED,
    ),
    #scheme://user:password@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s/:@]+:)[^\s/@]+@"), r"\1" + REDACTED + "@"),
]


def redact_alert(alert: Alert) -> Alert:
    """Scrub credentials from alert.details in place and return the alert.

    The signature is left alone: it's the rule's message, written by us or
    Emerging Threats, never traffic.
    """
    alert.details = redact_value(alert.details)
    return alert


def redact_value(value: Any) -> Any:
    """Return a scrubbed copy of a details value (dicts and lists are walked)."""
    if isinstance(value, dict):
        out = {}
        for key, v in value.items():
            name = _normalize_key(key)
            if name in DROP_KEYS:
                continue
            #True/False flags like password_seen can't leak anything; keep them.
            hideable = v is not None and v != "" and not isinstance(v, bool)
            out[key] = REDACTED if hideable and _is_secret_key(name) else redact_value(v)
        return out
    if isinstance(value, (list, tuple)):
        return [redact_value(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_text(text: str) -> str:
    """Replace credentials that appear inside free text."""
    for pattern, replacement in _TEXT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _normalize_key(key: Any) -> str:
    return re.sub(r"[\s.-]+", "_", str(key).strip().lower())


def _is_secret_key(name: str) -> bool:
    if name in SECRET_KEYS or name.replace("_", "") in SECRET_KEY_PARTS:
        return True
    return any(part in SECRET_KEY_PARTS for part in name.split("_"))


