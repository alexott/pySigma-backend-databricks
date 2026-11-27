"""Tests for the built-in aws_cloudtrail and okta_system_log Lakewatch profiles."""

import json
import warnings

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaConversionError, SigmaTransformationError

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.schema_catalog import SchemaCatalog
from sigma.pipelines.databricks.lakewatch.profile import load_profiles, validate_profile


def _sql(parser, product, service, detection, title="T"):
    backend = DatabricksBackend(
        parsers=parser, table_name="t", catalog_name="c", schema_name="s", warehouse_id="w"
    )
    rule = SigmaCollection.from_yaml(
        f"""
title: {title}
status: test
logsource:
    product: {product}
    service: {service}
detection:
{detection}
"""
    ).rules[0]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        queries = backend.convert_rule(rule, "lakewatch")
    assert len(queries) == 1
    return json.loads(queries[0])["sql"]


def test_builtin_profiles_validate():
    profiles = load_profiles()
    catalog = SchemaCatalog.load()
    for pid in ("aws_cloudtrail", "okta_system_log"):
        profile = profiles[pid]
        assert profile.version == 1
        assert profile.parser == pid
        validate_profile(profile, catalog.get(profile.parser))


def test_cloudtrail_rule():
    sql = _sql(
        "aws_cloudtrail",
        "aws",
        "cloudtrail",
        """    sel:
        eventSource: s3.amazonaws.com
        eventName: PutBucketPolicy
        userIdentity.type: Root
    condition: sel""",
    )
    assert "try_variant_get(userIdentity, '$.type', 'string')" in sql
    assert "eventName" in sql


def test_cloudtrail_request_parameters_prefix():
    sql = _sql(
        "aws_cloudtrail",
        "aws",
        "cloudtrail",
        """    sel:
        requestParameters.bucketName: logs
    condition: sel""",
    )
    assert "try_variant_get(requestParameters, '$.bucketName', 'string')" in sql


def test_cloudtrail_unknown_field_fails():
    with pytest.raises(
        SigmaTransformationError, match="field src_ip is not mapped by profile aws_cloudtrail"
    ):
        _sql(
            "aws_cloudtrail",
            "aws",
            "cloudtrail",
            """    sel:
        src_ip: 1.2.3.4
    condition: sel""",
        )


def test_okta_array_target():
    sql = _sql(
        "okta_system_log",
        "okta",
        "okta",
        """    sel:
        target.displayName|contains: admin
    condition: sel""",
    )
    assert "exists(target, x0 -> contains(lower(x0.displayName), 'admin'))" in sql


def test_okta_debugdata_variant():
    sql = _sql(
        "okta_system_log",
        "okta",
        "okta",
        """    sel:
        debugContext.debugData.requestUri|endswith: /token
    condition: sel""",
    )
    assert "try_variant_get(debugContext.debugData, '$.requestUri', 'string')" in sql


def test_okta_bool_vs_struct_boolean():
    sql = _sql(
        "okta_system_log",
        "okta",
        "okta",
        """    sel:
        securityContext.isProxy: true
    condition: sel""",
    )
    assert "securityContext.isProxy = true" in sql


def test_cloudtrail_whole_variant_comparison_fails():
    with pytest.raises(
        SigmaConversionError,
        match=r"comparison against the whole VARIANT column requestParameters supports only "
        r"contains \(profile aws_cloudtrail\)",
    ):
        _sql(
            "aws_cloudtrail",
            "aws",
            "cloudtrail",
            """    sel:
        requestParameters|startswith: Suspended
    condition: sel""",
        )


def test_readme_profile_example_validates():
    import re
    from pathlib import Path

    import yaml

    from sigma.pipelines.databricks.lakewatch.profile import parse_profile

    readme = (Path(__file__).parent.parent / "docs" / "writing-profiles.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```yaml\n(profile: my_cloudtrail.*?)```", readme, re.S)
    assert len(blocks) == 1
    profile = parse_profile(yaml.safe_load(blocks[0]), "README")
    validate_profile(profile, SchemaCatalog.load().get(profile.parser))


def test_builtin_profiles_have_entity():
    profiles = load_profiles()
    catalog = SchemaCatalog.load()
    for profile in profiles.values():
        assert profile.entity, profile.profile
        validate_profile(profile, catalog.get(profile.parser))
    assert profiles["crowdstrike_fdr_event"].entity == "coalesce(nullif(ComputerName, ''), aid)"
    assert profiles["aws_cloudtrail"].entity == "userIdentity.arn"
    assert profiles["windows_sysmon_process"].entity == "Computer"
