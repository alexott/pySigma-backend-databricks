"""Tests for the Lakewatch summary overrides: the rule attribute and the -O overrides file."""

import json
import warnings

import pytest
import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaConfigurationError, SigmaConversionError

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.lakewatch_overrides import (
    OutputOverride,
    OverridesFile,
    parse_override,
    resolve_output,
)

SYSMON = "windows_sysmon_process"
CS = "crowdstrike_fdr_event"
RULE_ID = "11111111-2222-3333-4444-555555555555"
OTHER_ID = "99999999-2222-3333-4444-555555555555"


def _collection(lakewatch=None, rule_id=RULE_ID):
    data = {
        "title": "Tool Use",
        "id": rule_id,
        "status": "test",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"sel": {"Image|endswith": "\\powershell.exe"}, "condition": "sel"},
    }
    if lakewatch is not None:
        data["lakewatch"] = lakewatch
    return SigmaCollection.from_yaml(yaml.safe_dump(data, sort_keys=False))


def _backend(tmp_path=None, overrides=None, parsers=SYSMON, **options):
    if overrides is not None:
        path = tmp_path / "overrides.yml"
        path.write_text(overrides if isinstance(overrides, str) else yaml.safe_dump(overrides))
        options["overrides"] = str(path)
    return DatabricksBackend(parsers=parsers, table_name=None if "," in parsers else "t",
                             catalog_name="c", schema_name="s",
                             **({"table_map": ",".join(f"{p}:t_{p}" for p in parsers.split(","))}
                                if "," in parsers else {}), **options)


def _convert(backend, lakewatch=None, rule_id=RULE_ID):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        queries = backend.convert_rule(_collection(lakewatch, rule_id).rules[0], "lakewatch")
    return [json.loads(q) for q in queries]


def _expr(parser, field):
    from tests.test_lakewatch_summary import _resolver
    return _resolver(parser)._resolve_output_expr(field)


ATTR = {
    "summary": "Tool on {Computer} by {sigma_user}",
    "context": {"cmd": "{sigma_cmd}"},
    "select": {"sigma_user": "User", "sigma_cmd": "CommandLine"},
}


def test_rule_attribute_override():
    (out,) = _convert(_backend(), ATTR)
    output = out["doc"]["output"]
    assert output["summary"] == "Tool on {Computer} by {sigma_user}"
    assert output["context"] == {"cmd": "{sigma_cmd}"}
    assert output["default_context"] is False
    assert list(output)[:2] == ["summary", "context"]
    assert out["sql"].startswith(
        f"SELECT *, Computer AS sigma_entity, {_expr(SYSMON, 'User')} AS sigma_user, "
        f"{_expr(SYSMON, 'CommandLine')} AS sigma_cmd\nFROM")


def test_overrides_file_wins_over_rule_attribute(tmp_path):
    backend = _backend(tmp_path, {RULE_ID: {"summary": "File {sigma_entity}"}})
    (out,) = _convert(backend, ATTR)
    assert out["doc"]["output"]["summary"] == "File {sigma_entity}"
    assert out["doc"]["output"]["context"] == {"cmd": "{sigma_cmd}"}
    assert out["doc"]["output"]["default_context"] is False


def test_override_scoped_per_profile(tmp_path):
    backend = _backend(tmp_path, {RULE_ID: {
        "default": {"summary": "D {sigma_entity}"},
        CS: {"summary": "C {sigma_entity}"},
    }}, parsers=f"{SYSMON},{CS}")
    outs = {o["doc"]["rule_name"]: o for o in _convert(backend)}
    sysmon = next(o for n, o in outs.items() if n.endswith(SYSMON))
    cs = next(o for n, o in outs.items() if n.endswith(CS))
    assert sysmon["doc"]["output"]["summary"] == "D {sigma_entity}"
    assert cs["doc"]["output"]["summary"] == "C {sigma_entity}"
    assert "Computer AS sigma_entity" in sysmon["sql"]
    assert "coalesce(nullif(ComputerName, ''), aid) AS sigma_entity" in cs["sql"]


def test_select_alias_clash_fails():
    with pytest.raises(SigmaConversionError, match="select alias Computer clashes"):
        _convert(_backend(), {"select": {"Computer": "User"}})
    backend = _backend(collect_errors=True)
    assert _convert(backend, {"select": {"Computer": "User"}}) == []
    assert len(backend.errors) == 1
    assert "select alias Computer clashes" in str(backend.errors[0][1])


def test_expression_placeholder_fails():
    with pytest.raises(SigmaConversionError, match=r"placeholder \{lower\(Computer\)\} is not an output column"):
        _convert(_backend(), {"summary": "x {lower(Computer)}"})


def test_unknown_placeholder_fails():
    with pytest.raises(SigmaConversionError, match=r"placeholder \{NoSuchCol\} is not an output column"):
        _convert(_backend(), {"summary": "x {NoSuchCol}"})


def test_context_placeholder_checked():
    with pytest.raises(SigmaConversionError, match=r"placeholder \{nope\} is not an output column"):
        _convert(_backend(), {"context": {"k": "{nope}"}})


@pytest.mark.parametrize("content", [
    {"not-a-uuid": {"summary": "x"}},
    {RULE_ID: ["summary"]},
    {RULE_ID: {"summary": 3}},
    {RULE_ID: {"title": "x"}},
    {RULE_ID: {"summary": "x", "default": {"summary": "y"}}},
    {RULE_ID: {"context": {"a": 1}}},
    {RULE_ID: {"select": ["a"]}},
    {RULE_ID: {"default": "x"}},
])
def test_overrides_file_errors(tmp_path, content):
    backend = _backend(tmp_path, content)
    with pytest.raises(SigmaConfigurationError, match="overrides file"):
        _convert(backend)


def test_overrides_file_unreadable(tmp_path):
    backend = DatabricksBackend(parsers=SYSMON, table_name="t", catalog_name="c", schema_name="s",
                                overrides=str(tmp_path / "missing.yml"))
    with pytest.raises(SigmaConfigurationError, match="overrides file .*missing.yml"):
        _convert(backend)


def test_overrides_unknown_ids_and_profiles_warn(tmp_path):
    backend = _backend(tmp_path, {
        RULE_ID: {"no_such_profile": {"summary": "x"}, SYSMON: {"summary": "y {sigma_entity}"}},
        OTHER_ID: {"summary": "z"},
    })
    with pytest.warns(UserWarning) as record:
        backend.convert(_collection(), "lakewatch")
    messages = [str(w.message) for w in record]
    assert sum("overrides for unknown Sigma ids" in m for m in messages) == 1
    assert f"overrides for unknown Sigma ids: ['{OTHER_ID}']" in messages
    assert "overrides name unknown profiles: ['no_such_profile']" in messages


def test_overrides_ignored_in_ocsf_mode(tmp_path):
    path = tmp_path / "o.yml"
    path.write_text(yaml.safe_dump({RULE_ID: {"summary": "x"}}))
    backend = DatabricksBackend(table_name="t", catalog_name="c", schema_name="s", ocsf=True,
                                overrides=str(path))
    with pytest.warns(UserWarning) as record:
        out = backend.convert(_collection(), "lakewatch")
    assert sum("overrides" in str(w.message) for w in record) == 1
    assert "summary: Tool Use" in out


def test_bad_rule_attribute_fails_rule():
    with pytest.raises(SigmaConversionError, match="lakewatch") as info:
        _convert(_backend(), {"summary": [1]})
    assert not isinstance(info.value, SigmaConfigurationError)
    backend = _backend(collect_errors=True)
    assert _convert(backend, {"summary": [1]}) == []
    assert len(backend.errors) == 1


def test_unit_parse_and_resolve():
    assert parse_override({"summary": "a"}, "w") == OutputOverride(summary="a")
    with pytest.raises(ValueError, match="w"):
        parse_override({"bogus": 1}, "w")
    merged = resolve_output([OutputOverride(summary="a"), OutputOverride(summary="b", context={"k": "v"})])
    assert merged == OutputOverride(summary="a", context={"k": "v"})
    file = OverridesFile({RULE_ID: {"default": OutputOverride(summary="d"), CS: OutputOverride(summary="c")}})
    assert [o.summary for o in file.lookup(RULE_ID, CS)] == ["c", "d"]
    assert [o.summary for o in file.lookup(RULE_ID.upper(), SYSMON)] == ["d"]
    assert file.lookup(None, CS) == []
