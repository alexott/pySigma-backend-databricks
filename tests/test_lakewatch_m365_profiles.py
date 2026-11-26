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


GENERAL = "microsoft365_audit_general"
AAD = "microsoft365_audit_azure_active_directory"


# --- microsoft365_audit_general -------------------------------------------------------------


@pytest.mark.parametrize("field", ["Directionality", "DeliveryAction"])
def test_general_aliases(field):
    sql = _sql(GENERAL, "audit", _sel(field))
    assert f"lower(try_variant_get(payload, '$.{field}', 'string')) = lower('x')" in sql


@pytest.mark.parametrize("field", ["Operation", "Workload", "ResultStatus", "ObjectId"])
def test_general_identity_columns(field):
    assert f"lower({field}) = lower('x')" in _sql(GENERAL, "audit", _sel(field))


def test_general_directionality():
    alias = _sql(GENERAL, "audit", _sel("Directionality"))
    prefix = _sql(GENERAL, "audit", _sel("payload.Directionality"))
    pred = "lower(try_variant_get(payload, '$.Directionality', 'string')) = lower('x')"
    assert pred in alias
    assert pred in prefix


def test_general_entity():
    assert "UserId AS sigma_entity" in _sql(GENERAL, "audit", _sel("Operation"))


# --- microsoft365_audit_azure_active_directory ----------------------------------------------


def test_aad_aliases():
    assert "lower(ApplicationId) = lower('x')" in _sql(AAD, "audit", _sel("ApplicationId"))
    assert "lower(Operation) = lower('x')" in _sql(AAD, "audit", _sel("Operation"))
    sql = _sql(AAD, "audit", _sel("RequestType", "Cmsi:Cmsi"))
    assert "exists(ExtendedProperties, x0 -> lower(x0.Value) = lower('Cmsi:Cmsi'))" in sql


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
        "  AND (lower(Operation) = lower('UserLoggedIn') "
        "AND lower(ApplicationId) = lower('9ba1a5c7-f17a-4de9-a1f1-6178c8d51223') "
        "AND lower(ResultStatus) = lower('Success'))"
    )


# --- shared -----------------------------------------------------------------------------------


@pytest.mark.parametrize("parser", [GENERAL, AAD])
def test_operation_properties_unmapped(parser):
    msg = _convert_error(parser, "audit", "    sel:\n        OperationProperties|contains: x\n    condition: sel")
    assert "not mapped" in msg


@pytest.mark.parametrize("parser", [GENERAL, AAD])
def test_audit_operation_rule_converts_everywhere(parser):
    assert "lower(Operation) = lower('x')" in _sql(parser, "audit", _sel("Operation"))
    backend = DatabricksBackend()
    entries = backend.discover_parsers(SigmaCollection([_rule("audit", _sel("Operation"))]))
    assert entries


def test_threat_management_has_no_profile():
    rule = _rule("threat_management", _sel("eventSource"))
    entries = DatabricksBackend().discover_parsers(SigmaCollection([rule]))
    assert "no profile matches the logsource" in json.dumps(entries, default=str)
