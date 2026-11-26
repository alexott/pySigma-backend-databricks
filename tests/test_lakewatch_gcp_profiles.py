"""Tests for the built-in GCP and Google Workspace Lakewatch profiles."""

import json
import warnings

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.databricks import LakewatchConversionError


def _rule(service, detection):
    return SigmaCollection.from_yaml(
        f"""
title: T
status: test
logsource:
    product: gcp
    service: {service}
detection:
{detection}
"""
    ).rules[0]


def _convert(parser, service, detection):
    backend = DatabricksBackend(parsers=parser, table_name="t", catalog_name="c", schema_name="s")
    queries = backend.convert_rule(_rule(service, detection), "lakewatch")
    assert len(queries) == 1
    return json.loads(queries[0])["sql"]


def _sql(parser, service, detection):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return _convert(parser, service, detection)


def _convert_error(parser, service, detection):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with pytest.raises((SigmaTransformationError, LakewatchConversionError)) as exc:
            _convert(parser, service, detection)
    return str(exc.value)


def _sel(field, value="x"):
    return f"    sel:\n        {field}: '{value}'\n    condition: sel"


AUDIT = "gcp_audit_log"
REPORTS = "google_workspace_reports"

# --- gcp_audit_log --------------------------------------------------------------------------


def test_audit_method_name():
    sql = _sql(AUDIT, "gcp.audit", _sel("gcp.audit.method_name"))
    assert "lower(try_variant_get(protoPayload, '$.methodName', 'string')) = lower('x')" in sql


def test_audit_method_name_wildcard():
    sql = _sql(AUDIT, "gcp.audit", _sel("gcp.audit.method_name", "storage.*"))
    assert "startswith(lower(try_variant_get(protoPayload, '$.methodName', 'string')), lower('storage.'))" in sql


@pytest.mark.parametrize("leaf", ["serviceName", "methodName"])
def test_audit_prefix(leaf):
    sql = _sql(AUDIT, "gcp.audit", _sel(f"data.protoPayload.{leaf}"))
    assert f"lower(try_variant_get(protoPayload, '$.{leaf}', 'string')) = lower('x')" in sql


def test_audit_explicit_over_prefix():
    log = _sql(AUDIT, "gcp.audit", _sel("data.protoPayload.logName"))
    assert "AND (lower(logName) = lower('x'))" in log
    assert "$.methodName" not in log
    typ = _sql(AUDIT, "gcp.audit", _sel("data.protoPayload.resource.type"))
    assert "AND (lower(try_variant_get(resource, '$.type', 'string')) = lower('x'))" in typ
    assert "$.methodName" not in typ


@pytest.mark.parametrize("leaf", ["permission", "granted"])
def test_audit_authorization_info_fails(leaf):
    err = _convert_error(AUDIT, "gcp.audit", _sel(f"data.protoPayload.authorizationInfo.{leaf}"))
    assert f"field data.protoPayload.authorizationInfo.{leaf} is not supported by profile gcp_audit_log" in err


@pytest.mark.parametrize(
    "field,expected",
    [
        ("logName", "lower(logName) = lower('x')"),
        ("severity", "lower(severity) = lower('x')"),
        ("insertId", "lower(insertId) = lower('x')"),
        (
            "protoPayload.methodName",
            "lower(try_variant_get(protoPayload, '$.methodName', 'string')) = lower('x')",
        ),
    ],
)
def test_audit_identity_columns(field, expected):
    assert expected in _sql(AUDIT, "gcp.audit", _sel(field))


def test_audit_entity():
    sql = _sql(AUDIT, "gcp.audit", _sel("gcp.audit.method_name"))
    assert "try_variant_get(protoPayload, '$.authenticationInfo.principalEmail', 'string') AS sigma_entity" in sql


def test_gcp_audit_routes_to_audit_log_only():
    entries = DatabricksBackend().discover_parsers(SigmaCollection([_rule("gcp.audit", _sel("gcp.audit.method_name"))]))
    text = json.dumps(entries, default=str)
    assert AUDIT in text
    assert REPORTS not in text


def test_other_gcp_service_has_no_profile():
    entries = DatabricksBackend().discover_parsers(SigmaCollection([_rule("gcp.dns", _sel("query"))]))
    assert "no profile matches the logsource" in json.dumps(entries, default=str)


def test_audit_snapshot():
    detection = (
        "    sel:\n        gcp.audit.method_name:\n"
        "            - storage.buckets.list\n            - storage.buckets.listChannels\n"
        "    condition: sel"
    )
    assert _sql(AUDIT, "gcp.audit", detection) == (
        "SELECT *, try_variant_get(protoPayload, '$.authenticationInfo.principalEmail', 'string') "
        "AS sigma_entity\n"
        "FROM t\n"
        "WHERE IN_TIMERANGE(time)\n"
        "  AND (lower(try_variant_get(protoPayload, '$.methodName', 'string')) = lower('storage.buckets.list') "
        "OR lower(try_variant_get(protoPayload, '$.methodName', 'string')) = lower('storage.buckets.listChannels'))"
    )
