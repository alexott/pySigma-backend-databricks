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
    assert "lower(try_variant_get(protoPayload, '$.methodName', 'string')) = 'x'" in sql


def test_audit_method_name_wildcard():
    sql = _sql(AUDIT, "gcp.audit", _sel("gcp.audit.method_name", "storage.*"))
    assert "startswith(lower(try_variant_get(protoPayload, '$.methodName', 'string')), 'storage.')" in sql


@pytest.mark.parametrize("leaf", ["serviceName", "methodName"])
def test_audit_data_protopayload_aliases(leaf):
    sql = _sql(AUDIT, "gcp.audit", _sel(f"data.protoPayload.{leaf}"))
    assert f"lower(try_variant_get(protoPayload, '$.{leaf}', 'string')) = 'x'" in sql


def test_audit_data_protopayload_top_level_aliases():
    log = _sql(AUDIT, "gcp.audit", _sel("data.protoPayload.logName"))
    assert "AND (lower(logName) = 'x')" in log
    typ = _sql(AUDIT, "gcp.audit", _sel("data.protoPayload.resource.type"))
    assert "AND (lower(try_variant_get(resource, '$.type', 'string')) = 'x')" in typ


AUTH = "exists(try_variant_get(protoPayload, '$.authorizationInfo', 'ARRAY<VARIANT>'), "


@pytest.mark.parametrize(
    "leaf, value, expected",
    [
        ("permission", "x", "x0 -> lower(try_variant_get(x0, '$.permission', 'string')) = 'x'"),
        ("granted", "true", "x0 -> lower(try_variant_get(x0, '$.granted', 'boolean')) = 'true'"),
    ],
)
@pytest.mark.parametrize("prefix", ["data.protoPayload", "protoPayload"])
def test_audit_authorization_info(prefix, leaf, value, expected):
    sql = _sql(AUDIT, "gcp.audit", _sel(f"{prefix}.authorizationInfo.{leaf}", value))
    assert f"AND ({AUTH}{expected})" in sql


def test_audit_array_identity_paths():
    loc = _sql(AUDIT, "gcp.audit", _sel("protoPayload.resourceLocation.currentLocations", "us"))
    assert (
        "AND (exists(try_variant_get(protoPayload, '$.resourceLocation.currentLocations', 'ARRAY<STRING>'), "
        "x0 -> lower(x0) = 'us'))"
    ) in loc
    deleg_field = "protoPayload.authenticationInfo.serviceAccountDelegationInfo.principalSubject"
    deleg = _sql(AUDIT, "gcp.audit", _sel(deleg_field))
    assert (
        "AND (exists(try_variant_get(protoPayload, '$.authenticationInfo.serviceAccountDelegationInfo', "
        "'ARRAY<VARIANT>'), x0 -> lower(try_variant_get(x0, '$.principalSubject', 'string')) = 'x'))"
    ) in deleg


@pytest.mark.parametrize(
    "field,expected",
    [
        ("logName", "lower(logName) = 'x'"),
        ("severity", "lower(severity) = 'x'"),
        ("insertId", "lower(insertId) = 'x'"),
        (
            "protoPayload.methodName",
            "lower(try_variant_get(protoPayload, '$.methodName', 'string')) = 'x'",
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
        "  AND (lower(try_variant_get(protoPayload, '$.methodName', 'string')) "
        "IN ('storage.buckets.list', 'storage.buckets.listchannels'))"
    )

# --- google_workspace_reports ---------------------------------------------------------------

WS_SERVICES = ["google_workspace.admin", "google_workspace.login"]


@pytest.mark.parametrize("service", WS_SERVICES)
@pytest.mark.parametrize("field", ["eventName", "protoPayload.metadata.event.eventName"])
def test_workspace_event_name(service, field):
    sql = _sql(REPORTS, service, _sel(field))
    assert "AND (lower(name) = 'x')" in sql


@pytest.mark.parametrize(
    "field,value,mapped",
    [
        ("eventService", "admin.googleapis.com", "admin"),
        ("protoPayload.serviceName", "login.googleapis.com", "login"),
    ],
)
def test_workspace_service_value_map(field, value, mapped):
    sql = _sql(REPORTS, "google_workspace.admin", _sel(field, value))
    assert f"AND (lower(application) = '{mapped}')" in sql


@pytest.mark.parametrize("field", ["eventService", "protoPayload.serviceName"])
def test_workspace_unknown_service_fails(field):
    err = _convert_error(REPORTS, "google_workspace.admin", _sel(field, "drive.googleapis.com"))
    assert f"field {field}: transform map: value 'drive.googleapis.com' is not in the map" in err
    assert "(profile google_workspace_reports)" in err


def _param(name):
    entry = (
        "try_element_at(filter(try_variant_get(parameters, '$', 'ARRAY<VARIANT>'), "
        f"e -> try_variant_get(e, '$.name', 'STRING') = '{name}'), 1)"
    )
    return f"coalesce(try_variant_get({entry}, '$.value', 'STRING'), try_variant_get({entry}, '$.boolValue', 'STRING'))"


def test_workspace_parameters_converts():
    det = (
        "    sel:\n        setting_name|startswith: ContextAwareAccess\n        new_value: 'false'\n"
        "    condition: sel"
    )
    assert _sql(REPORTS, "google_workspace.admin", det) == (
        "SELECT *, actor.email AS sigma_entity\n"
        "FROM t\n"
        "WHERE IN_TIMERANGE(time)\n"
        f"  AND (startswith(lower({_param('SETTING_NAME')}), 'contextawareaccess') "
        f"AND lower({_param('NEW_VALUE')}) = 'false')"
    )


@pytest.mark.parametrize("field, name", [("setting_name", "SETTING_NAME"), ("new_value", "NEW_VALUE")])
def test_workspace_parameters_equality(field, name):
    assert f"AND (lower({_param(name)}) = 'x')" in _sql(REPORTS, "google_workspace.admin", _sel(field))


@pytest.mark.parametrize(
    "field,expected",
    [
        ("name", "lower(name) = 'x'"),
        ("application", "lower(application) = 'x'"),
        ("ipAddress", "lower(ipAddress) = 'x'"),
        ("actor.email", "lower(actor.email) = 'x'"),
    ],
)
def test_workspace_identity_columns(field, expected):
    assert f"AND ({expected})" in _sql(REPORTS, "google_workspace.admin", _sel(field))


def test_workspace_entity():
    sql = _sql(REPORTS, "google_workspace.login", _sel("eventName"))
    assert "actor.email AS sigma_entity" in sql


@pytest.mark.parametrize("service", WS_SERVICES)
def test_workspace_routes_to_reports_only(service):
    entries = DatabricksBackend().discover_parsers(SigmaCollection([_rule(service, _sel("eventName"))]))
    text = json.dumps(entries, default=str)
    assert REPORTS in text
    assert AUDIT not in text


def test_workspace_snapshot():
    detection = (
        "    selection:\n        protoPayload.serviceName: login.googleapis.com\n"
        "        protoPayload.metadata.event.eventName: suspicious_login\n"
        "    condition: selection"
    )
    assert _sql(REPORTS, "google_workspace.login", detection) == (
        "SELECT *, actor.email AS sigma_entity\n"
        "FROM t\n"
        "WHERE IN_TIMERANGE(time)\n"
        "  AND (lower(application) = 'login' AND lower(name) = 'suspicious_login')"
    )


@pytest.mark.parametrize(
    "parser,column,service",
    [(REPORTS, "parameters", "google_workspace.admin"), (AUDIT, "labels", "gcp.audit")],
)
def test_whole_variant_contains(parser, column, service):
    sql = _sql(parser, service, _sel(f"{column}|contains"))
    assert f"AND (contains(lower(to_json({column})), 'x'))" in sql


@pytest.mark.parametrize("field", ["parameters.SETTING_NAME", "resourceDetails.id"])
def test_workspace_array_columns_have_no_passthrough(field):
    err = _convert_error(REPORTS, "google_workspace.admin", _sel(field))
    assert f"field {field} is not mapped by profile google_workspace_reports" in err


@pytest.mark.parametrize(
    "modifier,value,seen",
    [("eventService|contains", "admin", "*admin*"), ("eventService", "admin*", "admin*")],
)
def test_workspace_value_map_modifiers_fail(modifier, value, seen):
    err = _convert_error(REPORTS, "google_workspace.admin", _sel(modifier, value))
    assert (
        f"field eventService: transform map: value '{seen}' is not in the map (profile google_workspace_reports)"
        in err
    )
