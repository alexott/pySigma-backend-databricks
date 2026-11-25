"""Tests for scaffold_profile.py and describe_to_schema.py."""

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

from sigma.backends.databricks.schema_catalog import SchemaCatalog
from sigma.pipelines.databricks.lakewatch.profile import parse_profile, validate_profile

ROOT = Path(__file__).parent.parent
DATA = Path(__file__).parent / "data"

CAT = {"generated_from": "test", "generated_at": "2026-11-24", "parsers": {"p1": {
    "uuid": "u-1", "version": 2, "paths": {
        "time": {"type": "TIMESTAMP", "storage": "column"},
        "lw_id": {"type": "STRING", "storage": "column"},
        "eventName": {"type": "STRING", "storage": "column", "required": True},
        "userIdentity": {"type": "VARIANT", "storage": "column"},
        "userIdentity.arn": {"type": "STRING", "storage": "variant"},
        "resources": {"type": "ARRAY", "storage": "column", "element": "VARIANT"},
        "resources[].arn": {"type": "STRING", "storage": "variant"},
        "event": {"type": "VARIANT", "storage": "column"}}}}}


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _schema(tmp_path):
    f = tmp_path / "s.json"
    f.write_text(json.dumps(CAT))
    return SchemaCatalog.load([str(f)]).get("p1")


def _scaffold(tmp_path):
    schema = _schema(tmp_path)
    text = _load("scaffold_profile").scaffold(
        schema, {"product": "aws", "service": "cloudtrail"}, DATA / "sigma_rules"
    )
    return schema, text


def test_scaffold_valid_profile(tmp_path):
    schema, text = _scaffold(tmp_path)
    profile = parse_profile(yaml.safe_load(text))
    validate_profile(profile, schema)
    assert "eventName: eventName  # used by 1 rules" in text
    assert "#   src_ip: 1" in text
    assert "# Sigma fields used by matching rules but not in the schema:" in text
    assert "Image" not in text


def test_scaffold_skips_containers(tmp_path):
    _, text = _scaffold(tmp_path)
    lines = [ln.split(":")[0].strip() for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    assert "userIdentity" not in lines
    assert "resources" not in lines
    assert "time" not in lines and "lw_id" not in lines
    assert "resources.arn: resources.arn" in text
    assert "userIdentity.arn: userIdentity.arn  # used by 1 rules" in text
    assert "event.*: event.*" in text


def test_describe_to_schema_types(capsys):
    describe = json.loads((DATA / "describe_table.json").read_text())
    out = _load("describe_to_schema").schema_from_describe(describe, "demo", uuid="u-9")
    parser = out["parsers"]["demo"]
    assert parser["uuid"] == "u-9"
    assert parser["paths"] == {
        "time": {"type": "TIMESTAMP", "storage": "column"},
        "actor": {"type": "STRUCT", "storage": "column"},
        "actor.id": {"type": "STRING", "storage": "struct"},
        "actor.n": {"type": "BIGINT", "storage": "struct"},
        "items": {"type": "ARRAY", "storage": "column", "element": "STRUCT"},
        "items[].arn": {"type": "STRING", "storage": "struct"},
        "tags": {"type": "ARRAY", "storage": "column", "element": "STRING"},
        "event": {"type": "VARIANT", "storage": "column"},
        "ok": {"type": "BOOLEAN", "storage": "column"},
    }
    assert "MAP is not supported" in capsys.readouterr().err


def test_describe_requires_time():
    describe = {"columns": [{"name": "a", "type": {"name": "string"}}]}
    with pytest.raises(ValueError, match="time"):
        _load("describe_to_schema").schema_from_describe(describe, "demo")
