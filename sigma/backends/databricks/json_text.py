"""Helpers for matching Sigma values against the JSON text of a VARIANT."""

import json

from sigma.types import SigmaString


def json_escape_string(value: SigmaString) -> SigmaString:
    """Return a copy of ``value`` whose plain-text parts are escaped as in a JSON string body.

    Wildcards and placeholders are kept as they are.
    """
    escaped = SigmaString("")
    escaped.s = [
        json.dumps(part, ensure_ascii=False)[1:-1] if isinstance(part, str) else part
        for part in value.s
    ]
    return escaped


def looks_like_json(value: SigmaString) -> bool:
    """Whether the plain text of ``value`` contains ``":`` or ``{`` (it targets JSON structure)."""
    text = "".join(part for part in value.s if isinstance(part, str))
    return '":' in text or "{" in text
