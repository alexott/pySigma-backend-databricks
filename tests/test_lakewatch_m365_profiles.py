"""Tests for the built-in Microsoft 365 Lakewatch profiles."""

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
    product: m365
    service: {service}
detection:
{detection}
"""
    ).rules[0]


def _convert(parser, service, detection):
    backend = DatabricksBackend(parsers=parser, table_name="t", catalog_name="c", schema_name="s", warehouse_id="w")
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


GENERAL = "microsoft365_audit_general"
AAD = "microsoft365_audit_azure_active_directory"
EXCHANGE = "microsoft365_audit_exchange"


# --- microsoft365_audit_general -------------------------------------------------------------


@pytest.mark.parametrize("field", ["Directionality", "DeliveryAction"])
def test_general_aliases(field):
    sql = _sql(GENERAL, "audit", _sel(field))
    assert f"lower(try_variant_get(payload, '$.{field}', 'string')) = 'x'" in sql


@pytest.mark.parametrize("field", ["Operation", "Workload", "ResultStatus", "ObjectId"])
def test_general_identity_columns(field):
    assert f"lower({field}) = 'x'" in _sql(GENERAL, "audit", _sel(field))


def test_general_directionality():
    alias = _sql(GENERAL, "audit", _sel("Directionality"))
    prefix = _sql(GENERAL, "audit", _sel("payload.Directionality"))
    pred = "lower(try_variant_get(payload, '$.Directionality', 'string')) = 'x'"
    assert pred in alias
    assert pred in prefix


def test_general_payload_contains():
    sql = _sql(GENERAL, "audit", "    sel:\n        payload|contains: x\n    condition: sel")
    assert "contains(lower(to_json(payload)), 'x')" in sql


def test_general_entity():
    assert "UserId AS sigma_entity" in _sql(GENERAL, "audit", _sel("Operation"))


def test_general_snapshot():
    detection = (
        "    sel:\n        Workload: ThreatIntelligence\n        Operation: TIMailData\n"
        "        Directionality: Inbound\n    condition: sel"
    )
    assert _sql(GENERAL, "audit", detection) == (
        "SELECT *, UserId AS sigma_entity\n"
        "FROM t\n"
        "WHERE IN_TIMERANGE(time)\n"
        "  AND (lower(Workload) = 'threatintelligence' "
        "AND lower(Operation) = 'timaildata' "
        "AND lower(try_variant_get(payload, '$.Directionality', 'string')) = 'inbound')"
    )


# --- microsoft365_audit_azure_active_directory ----------------------------------------------


def test_aad_aliases():
    assert "lower(ApplicationId) = 'x'" in _sql(AAD, "audit", _sel("ApplicationId"))
    assert "lower(Operation) = 'x'" in _sql(AAD, "audit", _sel("Operation"))
    sql = _sql(AAD, "audit", _sel("RequestType", "Cmsi:Cmsi"))
    assert "exists(ExtendedProperties, x0 -> lower(x0.Value) = 'cmsi:cmsi')" in sql


def test_aad_modified_properties():
    sql = _sql(AAD, "audit", "    sel:\n        ModifiedProperties|contains: x\n    condition: sel")
    assert "exists(ModifiedProperties, x0 -> contains(lower(to_json(x0)), 'x'))" in sql


def test_aad_entity():
    assert "UserId AS sigma_entity" in _sql(AAD, "audit", _sel("Operation"))


def test_aad_snapshot():
    detection = (
        "    sel:\n        Operation: UserLoggedIn\n"
        "        ApplicationId: '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223'\n"
        "        ResultStatus: Success\n    condition: sel"
    )
    assert _sql(AAD, "audit", detection) == (
        "SELECT *, UserId AS sigma_entity\n"
        "FROM t\n"
        "WHERE IN_TIMERANGE(time)\n"
        "  AND (lower(Operation) = 'userloggedin' "
        "AND lower(ApplicationId) = '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223' "
        "AND lower(ResultStatus) = 'success')"
    )


# --- microsoft365_audit_exchange ------------------------------------------------------------------


def test_exchange_parameters_name_or_value():
    sql = _sql(EXCHANGE, "audit", "    sel:\n        Parameters|contains: DeleteMessage\n    condition: sel")
    name = "exists(Parameters, x0 -> contains(lower(x0.Name), 'deletemessage'))"
    value = "exists(Parameters, x0 -> contains(lower(x0.Value), 'deletemessage'))"
    assert f"({name} OR {value})" in sql


def test_exchange_status_value_map():
    sql = _sql(EXCHANGE, "exchange", _sel("status", "success"))
    assert (
        "(lower(ResultStatus) IN ('true', 'succeeded', 'success'))"
    ) in sql


def test_exchange_status_failure_fails():
    msg = _convert_error(EXCHANGE, "exchange", _sel("status", "failure"))
    assert "not in the map" in msg
    assert "value 'failure' is not in the map (profile microsoft365_audit_exchange)" in msg


def test_exchange_result_status_has_no_value_map():
    sql = _sql(EXCHANGE, "audit", _sel("ResultStatus", "True"))
    assert "AND (lower(ResultStatus) = 'true')" in sql
    assert "Succeeded" not in sql
    assert " OR " not in sql


def test_exchange_ecs_aliases():
    assert "lower(Workload) = 'x'" in _sql(EXCHANGE, "exchange", _sel("eventSource"))
    assert "lower(Operation) = 'x'" in _sql(EXCHANGE, "exchange", _sel("eventName"))


def test_exchange_service_routes_to_exchange_only():
    entries = DatabricksBackend().discover_parsers(SigmaCollection([_rule("exchange", _sel("eventName"))]))
    text = json.dumps(entries, default=str)
    assert EXCHANGE in text
    assert GENERAL not in text
    assert AAD not in text


def test_exchange_entity():
    assert "UserId AS sigma_entity" in _sql(EXCHANGE, "exchange", _sel("eventName"))


def test_exchange_snapshot():
    detection = (
        "    sel:\n        Workload: Exchange\n        Operation: New-InboxRule\n"
        "        Parameters|contains: DeleteMessage\n    condition: sel"
    )
    assert _sql(EXCHANGE, "audit", detection) == (
        "SELECT *, UserId AS sigma_entity\n"
        "FROM t\n"
        "WHERE IN_TIMERANGE(time)\n"
        "  AND (lower(Workload) = 'exchange' "
        "AND lower(Operation) = 'new-inboxrule' "
        "AND (exists(Parameters, x0 -> contains(lower(x0.Name), 'deletemessage')) "
        "OR exists(Parameters, x0 -> contains(lower(x0.Value), 'deletemessage'))))"
    )


# --- shared -----------------------------------------------------------------------------------


@pytest.mark.parametrize("parser", [GENERAL, AAD, EXCHANGE])
def test_operation_properties_unmapped(parser):
    msg = _convert_error(parser, "audit", "    sel:\n        OperationProperties|contains: x\n    condition: sel")
    assert f"field OperationProperties is not mapped by profile {parser}" in msg


@pytest.mark.parametrize(
    "field, parser",
    [
        ("ApplicationId", GENERAL),
        ("ApplicationId", EXCHANGE),
        ("Directionality", AAD),
        ("Directionality", EXCHANGE),
        ("Parameters", GENERAL),
        ("Parameters", AAD),
    ],
)
def test_field_absent_on_other_parsers(field, parser):
    msg = _convert_error(parser, "audit", _sel(field))
    assert f"field {field} is not mapped by profile {parser}" in msg


@pytest.mark.parametrize("parser", [GENERAL, AAD, EXCHANGE])
def test_audit_operation_rule_converts_everywhere(parser):
    assert "lower(Operation) = 'x'" in _sql(parser, "audit", _sel("Operation"))


def test_audit_operation_rule_discovery_lists_three_profiles():
    entries = DatabricksBackend().discover_parsers(SigmaCollection([_rule("audit", _sel("Operation"))]))
    text = json.dumps(entries, default=str)
    for parser in (GENERAL, AAD, EXCHANGE):
        assert parser in text


def test_threat_management_has_no_profile():
    rule = _rule("threat_management", _sel("eventSource"))
    entries = DatabricksBackend().discover_parsers(SigmaCollection([rule]))
    assert "no profile matches the logsource" in json.dumps(entries, default=str)
