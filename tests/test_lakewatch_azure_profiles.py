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
    if target == _ARRAY:
        assert "contains(lower(to_json(properties))" in sql
        assert "$." not in sql  # whole column, not a sub-path
    elif target.startswith("properties."):
        assert f"try_variant_get(properties, '$.{target[len('properties.'):]}', 'string')" in sql
    else:
        assert f"lower({target}) = 'x'" in sql


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
    assert report_approximate(detection, "auditlogs", AUDIT)


def report_approximate(detection, service, parser):
    backend = DatabricksBackend(parsers=parser, table_name="t", catalog_name="c", schema_name="s")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        backend.convert(SigmaCollection([_rule(service, detection)]), "lakewatch")
    return backend.last_report["rules"][0]["results"][0]["approximate"]


def test_audit_properties_contains_approximate():
    sql = _sql(AUDIT, "auditlogs", _sel("properties|contains"))
    assert "contains(lower(to_json(properties)), 'x')" in sql
    assert report_approximate(_sel("properties|contains"), "auditlogs", AUDIT) is True


def test_audit_snapshot():
    detection = "    sel:\n        Category: UserManagement\n        Status: Success\n    condition: sel"
    assert _sql(AUDIT, "auditlogs", detection) == (
        "SELECT *, coalesce(initiatedByUserPrincipalName, initiatedByAppDisplayName) AS sigma_entity\n"
        "FROM t\n"
        "WHERE IN_TIMERANGE(time)\n"
        "  AND (lower(auditCategory) = 'usermanagement' AND lower(result) = 'success')"
    )


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


# --- azure_signin --------------------------------------------------------------------------

SIGNIN = "azure_signin"
_SIGNIN_ALIASES = {
    "resultType": ["ResultType", "resultType"],
    "resultDescription": ["ResultDescription", "resultDescription"],
    "properties.authenticationRequirement": ["AuthenticationRequirement", "properties.authenticationRequirement"],
    "clientAppUsed": ["ClientApp", "ClientAppUsed", "clientAppUsed"],
    "userPrincipalName": ["Username", "UserPrincipalName", "userPrincipalName"],
    "riskState": ["RiskState", "riskState"],
    "properties.resourceDisplayName": ["ResourceDisplayName"],
    "appId": ["AppId", "properties.appId", "appId"],
    "deviceId": ["DeviceDetail.deviceId", "properties.deviceDetail.deviceId"],
    "deviceIsCompliant": ["DeviceDetail.isCompliant"],
    "properties.deviceDetail.trustType": ["DeviceDetail.trusttype", "DeviceDetail.trustType"],
    "properties.homeTenantId": ["homeTenantId", "HomeTenantId"],
    "properties.resourceTenantId": ["resourceTenantId", "ResourceTenantId"],
    "conditionalAccessStatus": ["ConditionalAccessStatus", "conditionalAccessStatus"],
    "userAgent": ["UserAgent", "userAgent"],
    "location": ["Location", "location"],
    "ipAddress": ["IPAddress", "ipAddress"],
}
_SIGNIN_PARAMS = [(a, t) for t, aliases in _SIGNIN_ALIASES.items() for a in aliases]


@pytest.mark.parametrize("alias,target", _SIGNIN_PARAMS)
def test_signin_aliases(alias, target):
    sql = _sql(SIGNIN, "signinlogs", _sel(alias))
    if target.startswith("properties."):
        expected = f"try_variant_get(properties, '$.{target[len('properties.'):]}', 'string')"
    else:
        expected = f"lower({target}) = 'x'"
    assert expected in sql
    if alias != target:
        # the alias text itself must not leak into the SQL as a column reference
        # (it may legitimately occur inside the expected target text, e.g. a JSON path)
        assert alias not in sql.replace(expected, "")


def test_signin_numeric_result_type():
    sql = _sql(SIGNIN, "signinlogs", "    sel:\n        ResultType: 50126\n    condition: sel")
    # Spark compares the STRING column with a quoted string literal, never a bare number.
    assert "lower(resultType) = '50126'" in sql


def test_signin_status_unmapped():
    assert "not mapped" in _convert_error(SIGNIN, "signinlogs", _sel("Status", "Success"))


def test_signin_properties_message_unsupported():
    msg = _convert_error(SIGNIN, "signinlogs", _sel("properties.message", "ROPC"))
    assert "not supported by profile azure_signin" in msg


def test_signin_activity_details_unmapped():
    assert "not mapped" in _convert_error(SIGNIN, "signinlogs", _sel("ActivityDetails"))


def test_signin_unknown_field_unmapped():
    assert "not mapped" in _convert_error(SIGNIN, "signinlogs", _sel("NoSuchField"))


def test_signin_network_location_details_contains():
    detection = "    sel:\n        NetworkLocationDetails|contains: '['\n    condition: sel"
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        sql = _convert(SIGNIN, "signinlogs", detection)
    assert [w for w in caught if issubclass(w.category, LakewatchApproximateWarning)]
    assert "$." not in sql


def test_signin_network_location_details_equality_fails():
    msg = _convert_error(SIGNIN, "signinlogs", _sel("NetworkLocationDetails"))
    assert "supports only contains" in msg


def test_signin_entity():
    sql = _sql(SIGNIN, "signinlogs", _sel("ResultType", "50126"))
    assert "userPrincipalName AS sigma_entity" in sql


# --- azure_monitor_activity ------------------------------------------------------------------

ACTIVITY = "azure_monitor_activity"
_ACTIVITY_ALIASES = {
    "operationName": ["OperationName", "operationName"],
    "resourceId": ["ResourceId", "resourceId"],
    "category": ["Category", "category"],
    "resultType": ["ResultType", "resultType"],
    "callerIpAddress": ["CallerIpAddress", "callerIpAddress"],
}
_ACTIVITY_PARAMS = [(a, t) for t, aliases in _ACTIVITY_ALIASES.items() for a in aliases]


@pytest.mark.parametrize("alias,target", _ACTIVITY_PARAMS)
def test_activity_aliases(alias, target):
    sql = _sql(ACTIVITY, "activitylogs", _sel(alias))
    assert f"lower({target}) = 'x'" in sql


def test_activity_operation_name():
    sql = _sql(ACTIVITY, "activitylogs", _sel("operationName", "MICROSOFT.KEYVAULT/VAULTS/WRITE"))
    assert "lower(operationName) = 'microsoft.keyvault/vaults/write'" in sql


def test_activity_entity():
    sql = _sql(ACTIVITY, "activitylogs", _sel("OperationName"))
    assert "resourceId AS sigma_entity" in sql


# --- azure_identity_protection ---------------------------------------------------------------

IDENTITY = "azure_identity_protection"
_IDENTITY_ALIASES = {
    "riskEventType": ["RiskEventType", "riskEventType"],
    "riskLevel": ["RiskLevel", "riskLevel"],
    "riskState": ["RiskState", "riskState"],
    "riskDetail": ["RiskDetail", "riskDetail"],
    "userPrincipalName": ["UserPrincipalName", "userPrincipalName"],
    "ipAddress": ["IpAddress", "IPAddress", "ipAddress"],
}
_IDENTITY_PARAMS = [(a, t) for t, aliases in _IDENTITY_ALIASES.items() for a in aliases]


@pytest.mark.parametrize("alias,target", _IDENTITY_PARAMS)
def test_identity_protection_aliases(alias, target):
    sql = _sql(IDENTITY, "riskdetection", _sel(alias))
    assert f"lower({target}) = 'x'" in sql


def test_identity_protection_entity():
    sql = _sql(IDENTITY, "riskdetection", _sel("RiskEventType"))
    assert "userPrincipalName AS sigma_entity" in sql


def test_pim_has_no_profile():
    rule = _rule("pim", _sel("riskEventType"))
    report = DatabricksBackend().discover_parsers(SigmaCollection([rule]))
    (entry,) = report["rules"]
    assert entry["note"] == "no profile matches the logsource"
