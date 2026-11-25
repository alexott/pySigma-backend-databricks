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


def test_describe_main_missing_time_offline(tmp_path, capsys):
    describe = tmp_path / "d.json"
    describe.write_text(json.dumps({"columns": [{"name": "a", "type": {"name": "string"}}]}))
    out = tmp_path / "out.json"
    argv = ["--describe-json", str(describe), "--parser", "demo", "-o", str(out)]
    assert _load("describe_to_schema").main(argv) == 1
    assert "error: the table has no 'time' column" in capsys.readouterr().err
    assert not out.exists()


@pytest.mark.parametrize("word", ["on", "off", "yes", "no", "null", "true", "false", "123"])
def test_q_quotes_reserved_words(word):
    q = _load("scaffold_profile")._q(word)
    assert yaml.safe_load(q) == word and q.startswith('"')


def test_q_long_string_single_line():
    text = "word " * 40
    q = _load("scaffold_profile")._q(text)
    assert "\n" not in q and yaml.safe_load(q) == text


def test_scaffold_prefix_usage(tmp_path):
    rules = tmp_path / "r"
    rules.mkdir()
    (rules / "a.yml").write_text(
        "title: t\nlogsource: {product: aws, service: cloudtrail}\n"
        "detection:\n  s:\n    event.foo: 1\n    event.bar: 2\n  condition: s\n"
    )
    text = _load("scaffold_profile").scaffold(_schema(tmp_path), {"product": "aws"}, rules)
    assert "event.*: event.*  # used by 2 rules" in text
    assert "#   event.foo" not in text


def test_describe_live_errors(monkeypatch, capsys):
    mod = _load("describe_to_schema")

    def argv(table):
        return ["--table", table, "--profile", "p", "--warehouse-id", "w", "--parser", "x", "-o", "/dev/null"]

    assert mod.main(argv("a;b")) == 1
    assert "catalog.schema.table" in capsys.readouterr().err

    class R:
        returncode = 0
        stdout = json.dumps({"status": {"state": "FAILED", "error": {"message": "boom"}}})
        stderr = ""

    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: R())
    assert mod.main(argv("c.s.t")) == 1
    assert "boom" in capsys.readouterr().err
    R.stdout = "not json"
    assert mod.main(argv("c.s.t")) == 1

    def missing(*a, **k):
        raise FileNotFoundError

    monkeypatch.setattr(mod.subprocess, "run", missing)
    assert mod.main(argv("c.s.t")) == 1
    assert "not found" in capsys.readouterr().err
