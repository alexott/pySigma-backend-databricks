"""Tests for the Lakewatch v2 parsed-table mode of the Databricks backend."""

import json
import warnings

import pytest
import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaConfigurationError, SigmaConversionError, SigmaTransformationError
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

from sigma.backends.databricks import DatabricksBackend

SCHEMA = {
    "parsers": {
        "fx_ct": {
            "uuid": "u-fx",
            "version": 1,
            "paths": {
                "eventName": {"type": "STRING", "storage": "column"},
                "eventSource": {"type": "STRING", "storage": "column"},
                "eventType": {"type": "STRING", "storage": "column"},
                "EventID": {"type": "STRING", "storage": "column"},
                "userIdentity": {"type": "VARIANT", "storage": "column"},
                "userIdentity.arn": {"type": "STRING", "storage": "variant"},
                "userIdentity.type": {"type": "STRING", "storage": "variant"},
                "requestParameters": {"type": "VARIANT", "storage": "column"},
                "resources": {"type": "ARRAY", "storage": "column", "element": "VARIANT"},
                "resources[].arn": {"type": "STRING", "storage": "variant"},
                "readOnly": {"type": "BOOLEAN", "storage": "column"},
                "tlsDetails": {"type": "STRUCT", "storage": "column"},
                "tlsDetails.clientProvidedHostHeader": {"type": "STRING", "storage": "struct"},
                "tlsDetails.tls-version": {"type": "STRING", "storage": "struct"},
                "items": {"type": "ARRAY", "storage": "column", "element": "STRUCT"},
                "items[].name": {"type": "STRING", "storage": "struct"},
            },
        }
    }
}

BASE_FIELDS = {
    "eventName": "eventName",
    "eventSource": "eventSource",
    "EventID": "EventID",
    "userIdentity.arn": "userIdentity.arn",
    "requestParameters.*": "requestParameters.*",
}

EXTRA_FIELDS = {
    "resources.arn": "resources.arn",
    "readOnly": "readOnly",
    "Host": "tlsDetails.clientProvidedHostHeader",
    "TlsVersion": "tlsDetails.tls-version",
    "Src": "eventsource",
    "Tls": "tlsDetails",
    "Items": "items",
}


def _profile(pid, fields):
    return {
        "profile": pid,
        "version": 1,
        "parser": "fx_ct",
        "fields": fields,
        "logsources": [
            {
                "match": {"product": "aws", "service": "cloudtrail"},
                "conditions": {"eventType": "AwsApiCall"},
            }
        ],
    }


@pytest.fixture
def env(tmp_path):
    """Write the fixture schema and profiles; return a backend factory."""
    schema_file = tmp_path / "schema.json"
    schema_file.write_text(json.dumps(SCHEMA), encoding="utf-8")
    profiles = tmp_path / "profiles"
    profiles.mkdir()

    def write_profiles(extra_fields=None):
        fields = dict(BASE_FIELDS, **EXTRA_FIELDS)
        fields.update(extra_fields or {})
        for pid in ("p_ct", "p_ct2"):
            (profiles / f"{pid}.yml").write_text(yaml.safe_dump(_profile(pid, fields)), encoding="utf-8")

    write_profiles()

    def make(extra_fields=None, **kwargs):
        if extra_fields:
            write_profiles(extra_fields)
        kwargs.setdefault("catalog_name", "cat")
        kwargs.setdefault("schema_name", "sch")
        kwargs.setdefault("lakewatch_schemas", str(schema_file))
        kwargs.setdefault("lakewatch_profiles_dir", str(profiles))
        return DatabricksBackend(**kwargs)

    return make


def _rule(detection, product="aws", service="cloudtrail", title="CT Rule"):
    return SigmaCollection.from_yaml(
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


def _sqls(backend, rule):
    return [json.loads(q)["sql"] for q in backend.convert_rule(rule, "lakewatch_v2")]


def _sql(backend, detection):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        sqls = _sqls(backend, _rule(detection))
    assert len(sqls) == 1
    return sqls[0]


def _one(env, detection, **kwargs):
    kwargs.setdefault("parsers", "p_ct")
    kwargs.setdefault("table_name", "ct_table")
    return _sql(env(**kwargs), detection)


SEL = """    sel:
        eventName: ConsoleLogin
    condition: sel"""


# --- configuration -------------------------------------------------------------------------


def test_parsed_requires_parsers(env):
    with pytest.raises(SigmaConfigurationError, match="available: p_ct, p_ct2") as exc:
        _sqls(env(table_name="t"), _rule(SEL))
    assert "-O parsers=... is required for lakewatch_v2 parsed tables" in str(exc.value)


def test_parsed_requires_parsers_even_with_collect_errors(env):
    with pytest.raises(SigmaConfigurationError, match="parsers=... is required"):
        _sqls(env(table_name="t", collect_errors=True), _rule(SEL))


def test_parsed_unknown_parser(env):
    with pytest.raises(SigmaConfigurationError, match="nope"):
        _sqls(env(parsers="p_ct,nope", table_map="p_ct:a"), _rule(SEL))


def test_parsed_table_required(env):
    with pytest.raises(SigmaConfigurationError, match="p_ct2"):
        _sqls(env(parsers="p_ct,p_ct2", table_map="p_ct:a"), _rule(SEL))


def test_parsed_table_required_single(env):
    with pytest.raises(SigmaConfigurationError, match="p_ct"):
        _sqls(env(parsers="p_ct"), _rule(SEL))


def test_parsed_table_name_with_two_parsers_fails(env):
    with pytest.raises(SigmaConfigurationError, match="table_name"):
        _sqls(env(parsers="p_ct,p_ct2", table_name="t"), _rule(SEL))


@pytest.mark.parametrize("table_map", ["p_ct", "p_ct:", ":t"])
def test_parsed_table_map_malformed(env, table_map):
    with pytest.raises(SigmaConfigurationError, match="table_map"):
        _sqls(env(parsers="p_ct", table_map=table_map), _rule(SEL))


def test_parsed_table_map_unselected_profile(env):
    with pytest.raises(SigmaConfigurationError, match="p_ct2"):
        _sqls(env(parsers="p_ct", table_map="p_ct:a,p_ct2:b"), _rule(SEL))


def test_parsed_duplicate_parser(env):
    with pytest.raises(SigmaConfigurationError, match="p_ct"):
        _sqls(env(parsers="p_ct,p_ct", table_map="p_ct:a"), _rule(SEL))


def test_parsers_with_other_format_fails(env):
    backend = env(parsers="p_ct", table_name="t")
    with pytest.raises(SigmaConfigurationError, match="lakewatch_v2"):
        backend.convert_rule(_rule(SEL), "default")


def test_parsers_with_ocsf_mode_fails(env):
    with pytest.raises(SigmaConfigurationError, match="ocsf"):
        _sqls(env(parsers="p_ct", table_name="t", ocsf=True), _rule(SEL))


def test_parsed_options_whitespace_and_empty_items(env):
    sqls = _sqls(
        env(parsers=" p_ct , ,p_ct2 ", table_map=" p_ct : t1 ,, p_ct2:cat.s.t2 "),
        _rule(SEL),
    )
    assert "FROM t1\n" in sqls[0]
    assert "FROM cat.s.t2\n" in sqls[1]


def test_parsed_invalid_profile_is_configuration_error(env):
    with pytest.raises(SigmaConfigurationError, match="nosuch"):
        _sqls(env({"Bad": "nosuch"}, parsers="p_ct", table_name="t"), _rule(SEL))


# --- rendering -----------------------------------------------------------------------------


def test_parsed_plain_column_and_table(env):
    sql = _one(env, SEL)
    assert sql == (
        "SELECT *\nFROM ct_table\nWHERE IN_TIMERANGE(time)\n"
        "  AND (lower(eventType) = lower('AwsApiCall') AND lower(eventName) = lower('ConsoleLogin'))"
    )


def test_parsed_renders_variant_typed(env):
    sql = _one(env, """    sel:
        userIdentity.arn|endswith: ':root'
    condition: sel""")
    assert "endswith(lower(try_variant_get(userIdentity, '$.arn', 'string')), lower(':root'))" in sql


def test_parsed_freeform_variant_path(env):
    sql = _one(env, """    sel:
        requestParameters.bucketName: b
    condition: sel""")
    assert "lower(try_variant_get(requestParameters, '$.bucketName', 'string')) = lower('b')" in sql


def test_parsed_freeform_variant_number_and_bool(env):
    sql = _one(env, """    sel:
        requestParameters.count: 5
        requestParameters.force: true
        requestParameters.size|gte: 10
    condition: sel""")
    assert "try_variant_get(requestParameters, '$.count', 'double') = 5" in sql
    assert "try_variant_get(requestParameters, '$.force', 'boolean') = true" in sql
    assert "try_variant_get(requestParameters, '$.size', 'double') >= 10" in sql


def test_parsed_freeform_variant_null_exists_regex_cidr(env):
    sql = _one(env, """    sel:
        requestParameters.a: null
        requestParameters.b|exists: true
        requestParameters.c|re: '^x'
        requestParameters.d|cidr: 10.0.0.0/8
    condition: sel""")
    assert "try_variant_get(requestParameters, '$.a', 'string') is null" in sql
    assert "try_variant_get(requestParameters, '$.b', 'string') is not null" in sql
    assert "try_variant_get(requestParameters, '$.c', 'string') rlike '^x'" in sql
    assert (
        "ip_cidr_contains('10.0.0.0/8', try_ip_as_binary(try_variant_get(requestParameters, '$.d', 'string')))"
        in sql
    )
    assert "\x00" not in sql


def test_parsed_cidr_plain_column(env):
    sql = _one(env, """    sel:
        eventSource|cidr: 10.0.0.0/8
    condition: sel""")
    assert "ip_cidr_contains('10.0.0.0/8', try_ip_as_binary(eventSource))" in sql


def test_parsed_variant_key_quoting(env):
    sql = _one(env, """    sel:
        requestParameters.a b: x
        requestParameters.o.it's: y
    condition: sel""")
    assert "try_variant_get(requestParameters, '$[\\'a b\\']', 'string')" in sql
    assert "try_variant_get(requestParameters, '$.o[\\'it\\\\\\'s\\']', 'string')" in sql


def test_parsed_struct_dot_access_and_quoting(env):
    sql = _one(env, """    sel:
        Host|contains: evil
        TlsVersion: '1.0'
    condition: sel""")
    assert "contains(lower(tlsDetails.clientProvidedHostHeader), lower('evil'))" in sql
    assert "lower(tlsDetails.`tls-version`) = lower('1.0')" in sql


def test_parsed_uses_catalog_spelling(env):
    sql = _one(env, """    sel:
        Src: s3.amazonaws.com
    condition: sel""")
    assert "lower(eventSource) = lower('s3.amazonaws.com')" in sql


def test_parsed_number_vs_string_column_quoted(env):
    sql = _one(env, """    sel:
        EventID: 4688
    condition: sel""")
    assert "lower(EventID) = lower('4688')" in sql
    assert "= 4688" not in sql


def test_parsed_bool_vs_string_column_quoted(env):
    sql = _one(env, """    sel:
        EventID: true
    condition: sel""")
    assert "lower(EventID) = lower('true')" in sql


def test_parsed_number_vs_declared_string_variant_key(env):
    sql = _one(env, """    sel:
        userIdentity.arn: 42
    condition: sel""")
    assert "lower(try_variant_get(userIdentity, '$.arn', 'string')) = lower('42')" in sql


def test_parsed_bool_column_not_coerced(env):
    sql = _one(env, """    sel:
        readOnly: false
    condition: sel""")
    assert "readOnly = false" in sql


def test_parsed_whole_variant_fails(env):
    with pytest.raises(SigmaConversionError, match="whole VARIANT column requestParameters") as exc:
        _one(env, """    sel:
        requestParameters|contains: x
    condition: sel""", extra_fields={"requestParameters": "requestParameters"})
    assert "(profile p_ct)" in str(exc.value)


def test_parsed_whole_variant_regex_or_fails(env):
    with pytest.raises(SigmaConversionError, match="whole VARIANT column requestParameters"):
        _one(env, """    sel:
        requestParameters|contains: [a, b, c]
    condition: sel""", extra_fields={"requestParameters": "requestParameters"})


def test_parsed_regex_or_optimization_variant(env):
    sql = _one(env, """    sel:
        userIdentity.arn|contains: [a, b, c]
    condition: sel""")
    assert "try_variant_get(userIdentity, '$.arn', 'string') rlike '(?iu).*(a|b|c).*'" in sql
    assert sql.count("rlike") == 1


def test_parsed_array_of_variant(env):
    sql = _one(env, """    sel:
        resources.arn|endswith: x
    condition: sel""")
    assert "exists(resources, x0 -> endswith(lower(try_variant_get(x0, '$.arn', 'string')), lower('x')))" in sql


def test_parsed_negated_array_of_variant(env):
    sql = _one(env, """    sel:
        eventName: a
    flt:
        resources.arn: x
    condition: sel and not flt""")
    assert "NOT exists(resources, x0 -> lower(try_variant_get(x0, '$.arn', 'string')) = lower('x'))" in sql


def test_parsed_unknown_mapping_target_at_conversion(env):
    # Safety net: an undeclared path reaching the backend fails, naming the profile.
    backend = env(parsers="p_ct", table_name="t")
    backend._parsed_setup()
    profile, schema, table = backend._selected[0]
    backend._current_profile = (profile, schema, table)
    with pytest.raises(SigmaConversionError, match=r"nosuch.*\(profile p_ct\)"):
        backend._field_path("nosuch")


def test_parsed_fieldref_plain(env):
    sql = _one(env, """    sel:
        eventName|fieldref: eventSource
    condition: sel""")
    assert "eventName = eventSource" in sql


@pytest.mark.parametrize("field, ref", [
    ("eventName", "userIdentity.arn"),
    ("userIdentity.arn", "eventName"),
    ("resources.arn", "eventName"),
])
def test_parsed_fieldref_nested_fails(env, field, ref):
    with pytest.raises(SigmaConversionError, match="field references to nested ARRAY/VARIANT"):
        _one(env, f"""    sel:
        {field}|fieldref: {ref}
    condition: sel""")


def test_parsed_unmapped_field_fails(env):
    with pytest.raises(SigmaTransformationError, match="not mapped by profile p_ct"):
        _one(env, """    sel:
        Image: x
    condition: sel""")


# --- fan-out -------------------------------------------------------------------------------


def test_parsed_fan_out_two_profiles(env):
    backend = env(parsers="p_ct,p_ct2", table_map="p_ct:t1,p_ct2:t2")
    rule = _rule(SEL)
    sqls = _sqls(backend, rule)
    assert len(sqls) == 2
    assert "FROM t1\n" in sqls[0]
    assert "FROM t2\n" in sqls[1]
    # The rule itself is not modified by the per-profile pipelines.
    fields = [i.field for d in rule.detection.detections.values() for i in d.detection_items]
    assert fields == ["eventName"]
    assert backend.last_processing_pipeline is None
    assert backend._current_profile is None


def test_parsed_fan_out_order_follows_parsers(env):
    sqls = _sqls(env(parsers="p_ct2,p_ct", table_map="p_ct:t1,p_ct2:t2"), _rule(SEL))
    assert "FROM t2\n" in sqls[0]
    assert "FROM t1\n" in sqls[1]


def test_parsed_convert_collection(env):
    backend = env(parsers="p_ct,p_ct2", table_map="p_ct:t1,p_ct2:t2", warehouse_id="wh")
    rules = SigmaCollection.from_yaml(f"""
title: One
status: test
logsource: {{product: aws, service: cloudtrail}}
detection:
{SEL}
---
title: Two
status: test
logsource: {{product: aws, service: cloudtrail}}
detection:
{SEL}
""")
    docs = list(yaml.safe_load_all(backend.convert(rules, output_format="lakewatch_v2")))
    assert len(docs) == 4
    assert [d["batch"]["sql"]["query"].split("\n")[1] for d in docs] == [
        "FROM t1", "FROM t2", "FROM t1", "FROM t2",
    ]


def test_parsed_no_matching_profile_raises(env):
    match = "no selected Lakewatch parser profile matches logsource gcp/None/gcp.audit; selected: p_ct"
    with pytest.raises(SigmaConversionError, match=match):
        _sqls(env(parsers="p_ct", table_name="t"), _rule(SEL, product="gcp", service="gcp.audit"))


def test_parsed_no_matching_profile_collect_errors(env):
    backend = env(parsers="p_ct", table_name="t", collect_errors=True)
    rule = _rule(SEL, product="gcp", service="gcp.audit")
    assert backend.convert_rule(rule, "lakewatch_v2") == []
    assert len(backend.errors) == 1
    assert backend.errors[0][0] is rule
    assert "no selected Lakewatch parser profile" in str(backend.errors[0][1])


def test_parsed_profile_error_collected_with_original_rule(env):
    backend = env(parsers="p_ct", table_name="t", collect_errors=True)
    rule = _rule("""    sel:
        Image: x
    condition: sel""")
    assert backend.convert_rule(rule, "lakewatch_v2") == []
    assert len(backend.errors) == 1
    assert backend.errors[0][0] is rule
    assert "not mapped by profile p_ct" in str(backend.errors[0][1])


def test_user_pipeline_runs_before_profile(env):
    pipeline = ProcessingPipeline(
        name="user",
        priority=20,
        items=[ProcessingItem(transformation=FieldMappingTransformation({"Image": "eventName"}))],
    )
    sql = _one(env, """    sel:
        Image: x
    condition: sel""", processing_pipeline=pipeline)
    assert "lower(eventName) = lower('x')" in sql


def test_pipeline_vars_set_and_callback_passed(env):
    backend = env(parsers="p_ct", table_name="t", custom_opt="v")
    seen = {}

    def callback(rule, output_format, index, cond, result):
        seen.update(backend.last_processing_pipeline.vars)
        return result

    assert len(backend.convert_rule(_rule(SEL), "lakewatch_v2", callback)) == 1
    assert seen["backend"] == "databricks"
    assert seen["output_format"] == "lakewatch_v2"
    assert seen["backend_custom_opt"] == "v"


# --- mode selection ------------------------------------------------------------------------


OCSF_RULE = """
title: OCSF rule
status: test
logsource: {category: process_creation}
detection:
    sel:
        type_uid: 100701
        unmapped.Initiated: x
    condition: sel
"""


def test_ocsf_mode_unchanged_with_ocsf_option(env):
    backend = env(ocsf=True)
    rule = SigmaCollection.from_yaml(OCSF_RULE).rules[0]
    sql = json.loads(backend.convert_rule(rule, "lakewatch_v2")[0])["sql"]
    assert "unmapped:Initiated::string" in sql
    assert "FROM process_activity" in sql


def test_ocsf_mode_from_pipeline_identifier(env):
    pipeline = ProcessingPipeline(
        name="ocsf-like",
        items=[ProcessingItem(transformation=FieldMappingTransformation({}), identifier="ocsf_x")],
    )
    backend = env(processing_pipeline=pipeline)
    assert backend._parsed_mode("lakewatch_v2") is False
    rule = SigmaCollection.from_yaml(OCSF_RULE).rules[0]
    sql = json.loads(backend.convert_rule(rule, "lakewatch_v2")[0])["sql"]
    assert "unmapped:Initiated::string" in sql


def test_parsed_mode_selection(env):
    assert env()._parsed_mode("lakewatch_v2") is True
    assert env(ocsf=False)._parsed_mode("lakewatch_v2") is True
    assert env(ocsf=True)._parsed_mode("lakewatch_v2") is False
    assert env()._parsed_mode("lakewatch") is False
    assert env()._parsed_mode("default") is False


def test_v1_lakewatch_unchanged(env):
    backend = env()
    rule = SigmaCollection.from_yaml(OCSF_RULE).rules[0]
    sql = json.loads(backend.convert_rule(rule, "lakewatch")[0])["sql"]
    assert "unmapped:Initiated::string" in sql
    assert "FROM process_activity" in sql


def test_ocsf_cidr_on_free_form_field_renders_expression():
    # Regression: pySigma formats cidr_expression with the raw field name, which leaked the
    # internal placeholder for OCSF free-form and array fields.
    rule = SigmaCollection.from_yaml("""
title: t
logsource: {category: test}
detection:
    sel:
        class_uid: 4001
        unmapped.ip|cidr: 10.0.0.0/8
    condition: sel
""").rules[0]
    sql = json.loads(DatabricksBackend().convert_rule(rule, "lakewatch")[0])["sql"]
    assert "ip_cidr_contains('10.0.0.0/8', try_ip_as_binary(unmapped:ip::string))" in sql


def test_real_ocsf_pipeline_selects_ocsf_mode_without_option(env):
    ocsf = pytest.importorskip("sigma.pipelines.ocsf")
    backend = env(processing_pipeline=ocsf.ocsf_pipeline())
    assert backend._parsed_mode("lakewatch_v2") is False
    rule = SigmaCollection.from_yaml("""
title: Encoded PowerShell
status: test
logsource: {category: process_creation, product: windows}
detection:
    sel:
        Image|endswith: '\\\\powershell.exe'
    condition: sel
""").rules[0]
    sql = json.loads(backend.convert_rule(rule, "lakewatch_v2")[0])["sql"]
    assert "FROM process_activity" in sql


@pytest.mark.parametrize("detection, field", [
    ("Tls|contains: x", "tlsDetails"),
    ("Tls: 5", "tlsDetails"),
    ("Items: x", "items"),
    ("Tls|contains: [a, b, c]", "tlsDetails"),
])
def test_parsed_whole_struct_fails(env, detection, field):
    with pytest.raises(SigmaConversionError, match=f"whole STRUCT field {field} is not supported") as exc:
        _one(env, f"""    sel:
        {detection}
    condition: sel""")
    assert "(profile p_ct)" in str(exc.value)


def test_parsed_whole_struct_null_and_exists_allowed(env):
    sql = _one(env, """    sel:
        Tls: null
        Items|exists: true
    condition: sel""")
    assert "tlsDetails is null" in sql
    assert "exists(items, x0 -> x0 is not null)" in sql


def test_parsed_array_of_struct_member(env):
    sql = _one(env, """    sel:
        Items.name: n
    condition: sel""", extra_fields={"Items.name": "items.name"})
    assert "exists(items, x0 -> lower(x0.name) = lower('n'))" in sql
