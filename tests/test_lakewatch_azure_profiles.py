"""Tests for the built-in Azure Lakewatch profiles."""

import json
import warnings

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.databricks import LakewatchConversionError
from sigma.backends.databricks.lakewatch_report import LakewatchApproximateWarning


def _rule(service, detection):
    return SigmaCollection.from_yaml(
        f"""
title: T
status: test
logsource:
    product: azure
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


# --- azure_audit ---------------------------------------------------------------------------

AUDIT = "azure_audit"
_ARRAY = "properties"
_AUDIT_ALIASES = {
    "activityDisplayName": [
        "properties.message",
        "ActivityDisplayName",
        "activityDisplayName",
        "ActivityType",
        "activityType",
    ],
    "operationName": ["OperationName", "operationName"],
    "auditCategory": ["Category", "category"],
    "result": ["Status", "properties.result", "Result"],
    "loggedByService": ["LoggedByService", "loggedByService"],
    "initiatedByUserPrincipalName": ["Initiatedby", "Initiatied.By", "properties.initiatedBy", "InitiatedBy"],
    _ARRAY: [
        "Target",
        "TargetResources",
        "targetResources",
        "properties.targetResources",
        "TargetResources.modifiedProperties",
        "TargetResources.ModifiedProperties.NewValue",
        "TargetResources.ModifiedProperties.DisplayName",
        "TargetResources.modifiedProperties.newValue",
        "targetResources.type",
        "additionalDetails.additionalInfo",
        "AdditionalDetails",
    ],
    "resultReason": ["ResultReason", "failure_status_reason"],
}
_AUDIT_PARAMS = [(a, t) for t, aliases in _AUDIT_ALIASES.items() for a in aliases]
# Array targets reject equality, so those aliases are checked through ``|contains``.
_AUDIT_ARRAY_TARGETS = {_ARRAY}


@pytest.mark.parametrize("alias,target", _AUDIT_PARAMS)
def test_audit_aliases(alias, target):
    if target in _AUDIT_ARRAY_TARGETS:
        sql = _sql(AUDIT, "auditlogs", _sel(f"{alias}|contains"))
    else:
        sql = _sql(AUDIT, "auditlogs", _sel(alias))
    assert target in sql
    if target == _ARRAY:
        assert "$." not in sql  # whole column, not a sub-path


def test_audit_properties_message_is_activity_display_name():
    sql = _sql(AUDIT, "auditlogs", _sel("properties.message", "Add member to role"))
    assert "activityDisplayName" in sql
    assert "properties:message" not in sql


def test_audit_category_is_audit_category():
    sql = _sql(AUDIT, "auditlogs", _sel("Category", "UserManagement"))
    assert "auditCategory" in sql
    assert "category = " not in sql.replace("auditCategory", "")


def test_audit_target_resources_contains_approximate():
    detection = (
        "    sel:\n        TargetResources|contains: 'x'\n"
        "        OperationName: 'Add member to role'\n    condition: sel"
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        sql = _convert(AUDIT, "auditlogs", detection)
    approx = [w for w in caught if issubclass(w.category, LakewatchApproximateWarning)]
    assert len(approx) == 1
    assert "operationName" in sql


def test_audit_array_equality_fails():
    msg = _convert_error(AUDIT, "auditlogs", _sel("targetResources.type", "Service Principal"))
    assert "supports only contains" in msg


def test_audit_unmapped_consent_context():
    msg = _convert_error(AUDIT, "auditlogs", _sel("ConsentContext.IsAdminConsent", "true"))
    assert "not mapped" in msg


def test_audit_entity():
    sql = _sql(AUDIT, "auditlogs", _sel("OperationName"))
    entity = "coalesce(initiatedByUserPrincipalName, initiatedByAppDisplayName)"
    assert f"{entity} AS sigma_entity" in sql
