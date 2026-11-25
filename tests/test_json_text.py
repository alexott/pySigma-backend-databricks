"""Tests of the JSON text helpers."""
from sigma.types import SigmaString, SpecialChars

from sigma.backends.databricks.json_text import json_escape_string, looks_like_json


def _parts(value):
    return tuple(value.s)


def test_json_escape_keyword():
    # Sigma "\\" is one literal backslash; the JSON body doubles it.
    escaped = json_escape_string(SigmaString("*\\\\Temp\\\\*"))
    assert _parts(escaped) == (SpecialChars.WILDCARD_MULTI, "\\\\Temp\\\\", SpecialChars.WILDCARD_MULTI)
    assert _parts(json_escape_string(SigmaString('"Allow"'))) == ('\\"Allow\\"',)
    assert _parts(json_escape_string(SigmaString("a\tb"))) == ("a\\tb",)
    assert _parts(json_escape_string(SigmaString("é"))) == ("é",)


def test_json_escape_keeps_original():
    original = SigmaString('"a"')
    json_escape_string(original)
    assert _parts(original) == ('"a"',)


def test_looks_like_json():
    assert looks_like_json(SigmaString('"user":"x"'))
    assert looks_like_json(SigmaString("*{a*"))
    assert not looks_like_json(SigmaString("abc"))
