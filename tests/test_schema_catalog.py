"""Tests for the Lakewatch parser schema catalog."""

import json
from importlib.resources import files

import pytest
from sigma.exceptions import SigmaConfigurationError

from sigma.backends.databricks.schema_catalog import PathInfo, SchemaCatalog

CAT = {"generated_from": "test", "generated_at": "2026-11-24", "parsers": {"p1": {
    "uuid": "u-1", "version": 2, "paths": {
        "eventName": {"type": "STRING", "storage": "column", "required": True},
        "EventID": {"type": "STRING", "storage": "column", "allowed": ["1", "7"]},
        "userIdentity": {"type": "VARIANT", "storage": "column"},
        "userIdentity.arn": {"type": "STRING", "storage": "variant"},
        "resources": {"type": "ARRAY", "storage": "column", "element": "VARIANT"},
        "resources[].arn": {"type": "STRING", "storage": "variant"}}}}}


def _write(tmp_path, name, data):
    f = tmp_path / name
    f.write_text(json.dumps(data))
    return str(f)


def test_load_extra_file_and_lookup(tmp_path):
    cat = SchemaCatalog.load([_write(tmp_path, "s.json", CAT)])
    s = cat.get("p1")
    assert (s.uuid, s.version) == ("u-1", 2)
    assert s.get("userIdentity.arn") == PathInfo("STRING", "variant")
    assert s.get("eventName").required is True
    assert s.get("EventID").allowed == ("1", "7")
    assert s.get("resources").element == "VARIANT"
    assert s.get("nope") is None
    assert "p1" in cat.names()


def test_later_file_overrides_by_name(tmp_path):
    other = json.loads(json.dumps(CAT))
    other["parsers"]["p1"]["uuid"] = "u-2"
    cat = SchemaCatalog.load([_write(tmp_path, "a.json", CAT), _write(tmp_path, "b.json", other)])
    assert cat.get("p1").uuid == "u-2"


def test_unknown_parser_lists_names(tmp_path):
    with pytest.raises(SigmaConfigurationError, match="p1"):
        SchemaCatalog.load([_write(tmp_path, "s.json", CAT)]).get("missing")


@pytest.mark.skipif(
    not files("sigma.backends.databricks.lakewatch_schemas").joinpath("builtin.json").is_file(),
    reason="builtin.json not generated yet",
)
def test_builtin_catalog_loads():
    cat = SchemaCatalog.load()
    assert cat.get("aws_cloudtrail").uuid == "9fd018c6-a47f-499e-af80-f12f3db6f4fa"


@pytest.mark.parametrize("data, match", [
    ([], "top level must be a JSON object"),
    ({"parsers": []}, "'parsers' must be an object"),
    ({"parsers": {"p1": []}}, "parser 'p1' must be an object"),
    ({"parsers": {"p1": {"paths": []}}}, "parser 'p1': 'paths' must be an object"),
    ({"parsers": {"p1": {"paths": {"a": "STRING"}}}}, "parser 'p1': path 'a' must be an object"),
    ({"parsers": {"p1": {"paths": {"a": {"storage": "column"}}}}},
     "parser 'p1': path 'a': missing 'type'"),
    ({"parsers": {"p1": {"paths": {"a": {"type": "STRING", "storage": "column", "allowed": "x"}}}}},
     "parser 'p1': path 'a': 'allowed' must be a list"),
])
def test_malformed_schema_file(tmp_path, data, match):
    path = _write(tmp_path, "bad.json", data)
    with pytest.raises(SigmaConfigurationError, match=match) as exc:
        SchemaCatalog.load([path])
    assert path in str(exc.value)


def test_missing_schema_file(tmp_path):
    path = str(tmp_path / "missing.json")
    with pytest.raises(SigmaConfigurationError, match="Cannot load parser schema file") as exc:
        SchemaCatalog.load([path])
    assert path in str(exc.value)


def test_invalid_json_schema_file(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(SigmaConfigurationError, match="Cannot load parser schema file"):
        SchemaCatalog.load([str(path)])


def test_windows_custom_loads():
    s = SchemaCatalog.load().get("windows_sysmon_process")
    assert s.paths["EventData"].type == "VARIANT"
    assert {"1", "10"} <= set(s.paths["EventID"].allowed)
    assert s.paths["Provider"].allowed == ("Microsoft-Windows-Sysmon",)
    other = SchemaCatalog.load().get("windows_event_other")
    assert other.paths["raw_event"].type == "VARIANT"
    assert "EventData" in other.paths


def test_builtin_overrides_bundled_custom(tmp_path, monkeypatch):
    import sigma.backends.databricks.schema_catalog as sc

    def cat(t):
        return {"parsers": {"p": {"paths": {"f": {"type": t, "storage": "column"}}}}}

    _write(tmp_path, "one.json", cat("STRING"))
    _write(tmp_path, "two.json", cat("INT"))
    monkeypatch.setattr(sc, "_BUNDLED_FILES", ("one.json", "two.json"))
    monkeypatch.setattr(sc, "files", lambda _pkg: tmp_path)
    assert SchemaCatalog.load().get("p").paths["f"].type == "INT"
