"""Tests for the ``entries`` profile key: named entries with configurable member names."""

import json
import warnings

import pytest
import yaml
from sigma.collection import SigmaCollection

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.field_paths import EntrySpec
from sigma.backends.databricks.schema_catalog import ParserSchema, PathInfo
from sigma.pipelines.databricks.lakewatch.profile import ProfileError, parse_profile, validate_profile


def _backend(tmp_path, parser, fields, entries=None):
    profiles = tmp_path / "profiles"
    profiles.mkdir(exist_ok=True)
    data = {
        "profile": parser, "version": 1, "parser": parser,
        "fields": fields,
        "logsources": [{"match": {"product": "test", "service": "svc"}}],
    }
    if entries is not None:
        data["entries"] = entries
    (profiles / "inline.yml").write_text(yaml.safe_dump(data), encoding="utf-8")
    return DatabricksBackend(
        parsers=parser, table_name="t", catalog_name="c", schema_name="s",
        lakewatch_profiles_dir=str(profiles),
    )


def _where(tmp_path, parser, fields, entries, field, value, modifier=""):
    rule = SigmaCollection.from_yaml(f"""
title: T
status: test
logsource:
    product: test
    service: svc
detection:
    sel:
        {field}{modifier}: {value}
    condition: sel
""").rules[0]
    backend = _backend(tmp_path, parser, fields, entries)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        sql = json.loads(backend.convert_rule(rule, "lakewatch")[0])["sql"]
    marker = "AND ("
    return sql[sql.index(marker) + len(marker):-1]


def test_named_entry_default_sql_unchanged(tmp_path):
    # Captured before F4 was implemented: no `entries` declaration, same SQL as before.
    where = _where(tmp_path, "windows_sysmon_process", {"Image": "EventData[Image]"}, None, "Image", "x")
    assert where == (
        "lower(try_element_at(filter(coalesce(try_variant_get(EventData, '$', "
        "'ARRAY<STRUCT<_Name: STRING, _VALUE: STRING>>'), CASE WHEN try_variant_get(EventData, "
        "'$._Name', 'STRING') IS NOT NULL THEN array(try_variant_get(EventData, '$', "
        "'STRUCT<_Name: STRING, _VALUE: STRING>')) END), e -> e._Name = 'Image'), 1)._VALUE) = lower('x')"
    )


def test_entries_variant(tmp_path):
    where = _where(
        tmp_path, "google_workspace_reports", {"nv": "parameters[NEW_VALUE]"},
        {"parameters": {"name": "name", "value": ["value", "boolValue"]}}, "nv", "'false'",
    )
    entry = (
        "try_element_at(filter(try_variant_get(parameters, '$', 'ARRAY<VARIANT>'), "
        "e -> try_variant_get(e, '$.name', 'STRING') = 'NEW_VALUE'), 1)"
    )
    assert where == (
        f"lower(coalesce(try_variant_get({entry}, '$.value', 'STRING'), "
        f"try_variant_get({entry}, '$.boolValue', 'STRING'))) = lower('false')"
    )


def test_entries_variant_array_ignore_case(tmp_path):
    where = _where(
        tmp_path, "aws_waf_web_acl", {"ua": "httpRequest.headers[User-Agent]"},
        {"httpRequest.headers": {"name": "name", "value": "value", "ignore_case": True}},
        "ua", "curl", "|contains",
    )
    assert where == (
        "contains(lower(try_variant_get(try_element_at(filter("
        "try_variant_get(httpRequest, '$.headers', 'ARRAY<VARIANT>'), "
        "e -> lower(try_variant_get(e, '$.name', 'STRING')) = lower('User-Agent')), 1), "
        "'$.value', 'STRING')), lower('curl'))"
    )


def _struct_schema():
    return {
        "parsers": {
            "fx_kv": {
                "uuid": "u", "version": 1,
                "paths": {
                    "attrs": {"type": "ARRAY", "storage": "column", "element": "STRUCT"},
                    "attrs[].key": {"type": "STRING", "storage": "struct"},
                    "attrs[].str": {"type": "STRING", "storage": "struct"},
                    "attrs[].num": {"type": "BIGINT", "storage": "struct"},
                },
            }
        }
    }


def test_entries_array_struct(tmp_path):
    schema_file = tmp_path / "schema.json"
    schema_file.write_text(json.dumps(_struct_schema()), encoding="utf-8")
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    data = {
        "profile": "fx_kv", "version": 1, "parser": "fx_kv",
        "fields": {"a": "attrs[host]"},
        "entries": {"attrs": {"name": "key", "value": ["str", "num"], "ignore_case": True}},
        "logsources": [{"match": {"product": "test", "service": "svc"}}],
    }
    (profiles / "p.yml").write_text(yaml.safe_dump(data), encoding="utf-8")
    backend = DatabricksBackend(
        parsers="fx_kv", table_name="t", catalog_name="c", schema_name="s",
        lakewatch_schemas=str(schema_file), lakewatch_profiles_dir=str(profiles),
    )
    rule = SigmaCollection.from_yaml("""
title: T
status: test
logsource:
    product: test
    service: svc
detection:
    sel:
        a: web1
    condition: sel
""").rules[0]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        sql = json.loads(backend.convert_rule(rule, "lakewatch")[0])["sql"]
    entry = (
        "try_element_at(filter(attrs, e -> lower(e.key) = lower('host')), 1)"
    )
    assert f"lower(coalesce({entry}.str::string, {entry}.num::string)) = lower('web1')" in sql


def _schema():
    return ParserSchema("x", None, None, {
        "v": PathInfo("VARIANT", "column"),
        "v.arr": PathInfo("ARRAY", "variant", element="VARIANT"),
        "v.sarr": PathInfo("ARRAY", "variant", element="STRING"),
        "s": PathInfo("STRUCT", "column"),
        "s.k": PathInfo("STRING", "struct"),
        "a": PathInfo("STRING", "column"),
        "arr": PathInfo("ARRAY", "column", element="STRUCT"),
        "arr[].k": PathInfo("STRING", "struct"),
        "arr[].v": PathInfo("STRING", "struct"),
    })


def _profile(entries):
    return {
        "profile": "p", "version": 1, "parser": "x", "fields": {"A": "a"},
        "entries": entries, "logsources": [{"match": {"product": "aws"}}],
    }


def _validate(entries):
    profile = parse_profile(_profile(entries), "<dict>")
    validate_profile(profile, _schema())


def test_entries_parse():
    p = parse_profile(_profile({"v": {"name": "n", "value": ["a", "b"], "ignore_case": True}}), "<dict>")
    assert p.entries == {"v": EntrySpec("n", ("a", "b"), True)}
    p = parse_profile(_profile({"v": {"name": "n", "value": "a"}}), "<dict>")
    assert p.entries == {"v": EntrySpec("n", ("a",), False)}
    assert parse_profile({**_profile({}), "entries": {}}, "<dict>").entries == {}


def test_entries_valid_kinds():
    _validate({"v": {"name": "n", "value": "x"}})
    _validate({"v.arr": {"name": "n", "value": "x"}})
    _validate({"arr": {"name": "k", "value": "v"}})


@pytest.mark.parametrize("entries, match", [
    ({"v": {"name": "n", "value": "x", "bogus": 1}}, r"<dict>: entries 'v': unknown key 'bogus'"),
    ({"v": {"value": "x"}}, r"<dict>: entries 'v': missing required key 'name'"),
    ({"v": {"name": "n"}}, r"<dict>: entries 'v': missing required key 'value'"),
    ({"v": {"name": "n", "value": []}}, r"<dict>: entries 'v': 'value' must be a non-empty string or a list of"),
    ({"v": {"name": "n", "value": "x", "ignore_case": "yes"}}, r"<dict>: entries 'v': 'ignore_case' must be a boolean"),
    ({"v": "name"}, r"<dict>: entries 'v': must be a mapping"),
])
def test_entries_parse_errors(entries, match):
    with pytest.raises(ProfileError, match=match):
        parse_profile(_profile(entries), "<dict>")


@pytest.mark.parametrize("entries, match", [
    ({"a": {"name": "n", "value": "x"}},
     r"profile 'p': entries 'a\[x\]': .*'a' declared in entries must be a top-level VARIANT"),
    ({"v.sarr": {"name": "n", "value": "x"}},
     r"entries 'v.sarr\[x\]': .*'v.sarr' declared in entries must be a top-level VARIANT"),
    ({"s": {"name": "n", "value": "x"}},
     r"entries 's\[x\]': .*'s' declared in entries must be a top-level VARIANT"),
    ({"arr": {"name": "k", "value": "nope"}},
     r"entries 'arr\[x\]': .*'arr': entries member 'nope' is not declared in the ARRAY<STRUCT>"),
    ({"arr": {"name": "nope", "value": "v"}},
     r"entries 'arr\[x\]': .*'arr': entries member 'nope' is not declared in the ARRAY<STRUCT>"),
    ({"missing": {"name": "n", "value": "x"}},
     r"entries 'missing\[x\]': .*'missing' is not a declared field"),
])
def test_entries_validation(entries, match):
    with pytest.raises(ProfileError, match=match):
        _validate(entries)


def test_variant_array_named_entry_needs_declaration(tmp_path):
    with pytest.raises(Exception, match="needs a VARIANT or ARRAY<STRUCT<_Name, _VALUE>> field"):
        _where(tmp_path, "aws_waf_web_acl", {"ua": "httpRequest.headers[User-Agent]"}, None, "ua", "x")


def test_entries_entity_renders_through_declared_entry(tmp_path):
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    data = {
        "profile": "aws_waf_web_acl", "version": 1, "parser": "aws_waf_web_acl",
        "fields": {"ua": "httpRequest.headers[User-Agent]"},
        "entity": "httpRequest.headers[User-Agent]",
        "entries": {"httpRequest.headers": {"name": "name", "value": "value", "ignore_case": True}},
        "logsources": [{"match": {"product": "test", "service": "svc"}}],
    }
    (profiles / "p.yml").write_text(yaml.safe_dump(data), encoding="utf-8")
    backend = DatabricksBackend(
        parsers="aws_waf_web_acl", table_name="t", catalog_name="c", schema_name="s",
        lakewatch_profiles_dir=str(profiles),
    )
    rule = SigmaCollection.from_yaml("""
title: T
status: test
logsource:
    product: test
    service: svc
detection:
    sel:
        ua: x
    condition: sel
""").rules[0]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        sql = json.loads(backend.convert_rule(rule, "lakewatch")[0])["sql"]
    assert sql.startswith(
        "SELECT *, try_variant_get(try_element_at(filter(try_variant_get(httpRequest, '$.headers', "
        "'ARRAY<VARIANT>'), e -> lower(try_variant_get(e, '$.name', 'STRING')) = lower('User-Agent')), 1), "
        "'$.value', 'STRING') AS sigma_entity"
    )


def test_entries_validate_entity_and_undeclared_probe():
    schema = _schema()
    profile = parse_profile({**_profile({"v.arr": {"name": "n", "value": "x"}}),
                             "entity": "v.arr[h]"}, "<dict>")
    validate_profile(profile, schema)
    # 'undeclared' on a declared-entry target is flagged as not needed.
    data = _profile({"v.arr": {"name": "n", "value": "x"}})
    data["fields"] = {"A": {"field": "v.arr[h]", "undeclared": True}}
    with pytest.raises(ProfileError, match="'undeclared' is not needed"):
        validate_profile(parse_profile(data, "<dict>"), schema)


def test_entries_star_rejected_on_declared_columns(tmp_path):
    spec = {"name": "name", "value": "value"}
    with pytest.raises(Exception, match=r"'\[\*\]' isn't supported on 'parameters'.*declared in entries"):
        _where(tmp_path, "google_workspace_reports", {"nv": "parameters[*]"}, {"parameters": spec}, "nv", "x")
    with pytest.raises(Exception, match=r"'\[\*\]' isn't supported on 'httpRequest.headers'.*entries"):
        _where(
            tmp_path, "aws_waf_web_acl", {"ua": "httpRequest.headers[*]"}, {"httpRequest.headers": spec}, "ua", "x"
        )


def test_entries_key_matches_target_ignoring_case(tmp_path):
    spec = {"name": "name", "value": ["value", "boolValue"]}
    where = _where(
        tmp_path, "google_workspace_reports", {"nv": "Parameters[NEW_VALUE]"}, {"parameters": spec}, "nv", "'false'",
    )
    assert "try_variant_get(" in where and "'$.boolValue'" in where, where


@pytest.mark.parametrize("extra, key, match", [
    ({}, "EventData", r"entries key 'EventData' equals the event_data_column 'EventData'.*_Name/_VALUE"),
    ({"event_data_column": "Data"}, "Data", r"event_data_column 'Data': that column keeps the _Name/_VALUE members"),
    ({"raw": {"entries": "v.arr"}}, "v.arr", r"raw entries source 'v.arr': that column keeps the _Name/_VALUE"),
])
def test_entries_key_equal_to_special_column_rejected(extra, key, match):
    data = {**_profile({key: {"name": "n", "value": "x"}}), **extra}
    with pytest.raises(ProfileError, match=match):
        parse_profile(data, "<dict>")
