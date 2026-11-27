"""Tests for any-element matching on schema-declared arrays inside a VARIANT (parsed-table mode)."""

import json
import re
import warnings

import pytest
import yaml
from sigma.collection import SigmaCollection

from sigma.backends.databricks import DatabricksBackend
from sigma.pipelines.databricks.lakewatch.profile import ProfileError

GCP_FIELDS = [
    "protoPayload.authorizationInfo.permission",
    "protoPayload.authorizationInfo.granted",
    "protoPayload.authorizationInfo.resourceAttributes.name",
    "protoPayload.authorizationInfo",
    "protoPayload.resourceLocation.currentLocations",
    "protoPayload.methodName",
]
WAF_FIELDS = [
    "ruleGroupList.terminatingRule.ruleMatchDetails.conditionType",
    "ruleGroupList.terminatingRule.ruleMatchDetails.matchedData",
    "ruleGroupList.terminatingRule.action",
    "nonTerminatingMatchingRules.ruleMatchDetails.conditionType",
    "terminatingRuleMatchDetails.conditionType",
]


def _backend(tmp_path, parser, service, fields):
    profiles = tmp_path / "profiles"
    profiles.mkdir(exist_ok=True)
    data = {
        "profile": parser, "version": 1, "parser": parser,
        "fields": {f: f for f in fields},
        "logsources": [{"match": {"product": "test", "service": service}}],
    }
    (profiles / "inline.yml").write_text(yaml.safe_dump(data), encoding="utf-8")
    return DatabricksBackend(
        parsers=parser, table_name="t", catalog_name="c", schema_name="s",
        lakewatch_profiles_dir=str(profiles),
    )


def _sql(tmp_path, parser, fields, field, value="x", modifier="", service="svc"):
    rule = SigmaCollection.from_yaml(f"""
title: T
status: test
logsource:
    product: test
    service: {service}
detection:
    sel:
        {field}{modifier}: {value}
    condition: sel
""").rules[0]
    backend = _backend(tmp_path, parser, service, fields)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        queries = backend.convert_rule(rule, "lakewatch")
    sql = json.loads(queries[0])["sql"]
    marker = "AND ("
    return sql[sql.index(marker) + len(marker):-1]


def _gcp(tmp_path, field, value="x", modifier=""):
    return _sql(tmp_path, "gcp_audit_log", GCP_FIELDS, field, value, modifier)


def _waf(tmp_path, field, value="x", modifier=""):
    return _sql(tmp_path, "aws_waf_web_acl", WAF_FIELDS, field, value, modifier)


def test_variant_array_leaf(tmp_path):
    where = _gcp(tmp_path, "protoPayload.authorizationInfo.permission")
    assert where == (
        "exists(try_variant_get(protoPayload, '$.authorizationInfo', 'ARRAY<VARIANT>'), "
        "x0 -> lower(try_variant_get(x0, '$.permission', 'string')) = 'x')"
    )


def test_variant_array_bool(tmp_path):
    where = _gcp(tmp_path, "protoPayload.authorizationInfo.granted", "'true'")
    assert where == (
        "exists(try_variant_get(protoPayload, '$.authorizationInfo', 'ARRAY<VARIANT>'), "
        "x0 -> lower(try_variant_get(x0, '$.granted', 'boolean')) = 'true')"
    )


def test_variant_array_scalar(tmp_path):
    where = _gcp(tmp_path, "protoPayload.resourceLocation.currentLocations", "us")
    assert where == (
        "exists(try_variant_get(protoPayload, '$.resourceLocation.currentLocations', 'ARRAY<STRING>'), "
        "x0 -> lower(x0) = 'us')"
    )


def test_variant_array_nested_in_column_array(tmp_path):
    where = _waf(tmp_path, "ruleGroupList.terminatingRule.ruleMatchDetails.conditionType")
    assert where == (
        "exists(ruleGroupList, x0 -> exists("
        "try_variant_get(x0, '$.terminatingRule.ruleMatchDetails', 'ARRAY<VARIANT>'), "
        "x1 -> lower(try_variant_get(x1, '$.conditionType', 'string')) = 'x'))"
    )


def test_variant_array_nested_in_variant_array(tmp_path):
    where = _waf(tmp_path, "ruleGroupList.terminatingRule.ruleMatchDetails.matchedData", "evil")
    assert where == (
        "exists(ruleGroupList, x0 -> exists("
        "try_variant_get(x0, '$.terminatingRule.ruleMatchDetails', 'ARRAY<VARIANT>'), "
        "x1 -> exists(try_variant_get(x1, '$.matchedData', 'ARRAY<STRING>'), "
        "x2 -> lower(x2) = 'evil')))"
    )


def test_variant_array_inside_variant_array_only(tmp_path):
    # a VARIANT array in a VARIANT array's element, with no column array before them
    where = _waf(tmp_path, "nonTerminatingMatchingRules.ruleMatchDetails.conditionType")
    assert where == (
        "exists(nonTerminatingMatchingRules, x0 -> exists("
        "try_variant_get(x0, '$.ruleMatchDetails', 'ARRAY<VARIANT>'), "
        "x1 -> lower(try_variant_get(x1, '$.conditionType', 'string')) = 'x'))"
    )


def test_variant_array_contains(tmp_path):
    where = _gcp(tmp_path, "protoPayload.authorizationInfo.permission", "x", "|contains")
    assert where == (
        "exists(try_variant_get(protoPayload, '$.authorizationInfo', 'ARRAY<VARIANT>'), "
        "x0 -> contains(lower(try_variant_get(x0, '$.permission', 'string')), 'x'))"
    )


def test_variant_array_null(tmp_path):
    where = _gcp(tmp_path, "protoPayload.authorizationInfo.permission", "null")
    assert where == (
        "exists(try_variant_get(protoPayload, '$.authorizationInfo', 'ARRAY<VARIANT>'), "
        "x0 -> try_variant_get(x0, '$.permission', 'string') is null)"
    )


def test_variant_array_nested_variant_key(tmp_path):
    where = _gcp(tmp_path, "protoPayload.authorizationInfo.resourceAttributes.name")
    assert where == (
        "exists(try_variant_get(protoPayload, '$.authorizationInfo', 'ARRAY<VARIANT>'), "
        "x0 -> lower(try_variant_get(x0, '$.resourceAttributes.name', 'string')) = 'x')"
    )


def test_undeclared_array_unchanged(tmp_path):
    # a key that is not declared under the array element still fails closed
    with pytest.raises(ProfileError, match="'nope' is not declared under 'protoPayload.authorizationInfo\\[\\]'"):
        _sql(tmp_path, "gcp_audit_log", ["protoPayload.authorizationInfo.nope"],
             "protoPayload.authorizationInfo.nope")
    # an existing non-array VARIANT key renders as before
    assert _gcp(tmp_path, "protoPayload.methodName") == (
        "lower(try_variant_get(protoPayload, '$.methodName', 'string')) = 'x'"
    )


def test_variant_array_in_profile_validation(tmp_path):
    _backend(tmp_path, "gcp_audit_log", "svc", ["protoPayload.authorizationInfo.permission"])


def test_or_list_merges_on_variant_scalar(tmp_path):
    where = _gcp(tmp_path, "protoPayload.methodName", value="[x, y]")
    assert re.search(r"^lower\(try_variant_get\(.*\)\) IN \('x', 'y'\)$", where), where


def test_or_list_under_array_does_not_merge(tmp_path):
    where = _gcp(tmp_path, "protoPayload.authorizationInfo.permission", value="[x, y]")
    assert " IN (" not in where
    assert where.count("exists(") == 2
