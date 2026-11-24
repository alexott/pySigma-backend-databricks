import json

import pytest
from importlib.resources import files

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
