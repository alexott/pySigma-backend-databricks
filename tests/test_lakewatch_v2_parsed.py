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
                "EventID": {"type": "STRING", "storage": "column", "allowed": ["1", "7"]},
                "userIdentity": {"type": "VARIANT", "storage": "column"},
                "userIdentity.arn": {"type": "STRING", "storage": "variant"},
                "userIdentity.type": {"type": "STRING", "storage": "variant"},
                "userIdentity.sessionContext": {"type": "VARIANT", "storage": "variant"},
                "userIdentity.webIdFederationData": {"type": "STRUCT", "storage": "variant"},
                "userIdentity.webIdFederationData.provider": {"type": "STRING", "storage": "variant"},
                "requestParameters": {"type": "VARIANT", "storage": "column"},
                "responseElements": {"type": "VARIANT", "storage": "column"},
                "resources": {"type": "ARRAY", "storage": "column", "element": "VARIANT"},
                "resources[].arn": {"type": "STRING", "storage": "variant"},
                "readOnly": {"type": "BOOLEAN", "storage": "column"},
                "tlsDetails": {"type": "STRUCT", "storage": "column"},
                "tlsDetails.clientProvidedHostHeader": {"type": "STRING", "storage": "struct"},
                "tlsDetails.tls-version": {"type": "STRING", "storage": "struct"},
                "items": {"type": "ARRAY", "storage": "column", "element": "STRUCT"},
                "items[].name": {"type": "STRING", "storage": "struct"},
                "EventData": {"type": "VARIANT", "storage": "column"},
                "Data": {"type": "ARRAY", "storage": "column", "element": "STRUCT"},
                "Data[]._Name": {"type": "STRING", "storage": "struct"},
                "Data[]._VALUE": {"type": "STRING", "storage": "struct"},
                "event": {"type": "VARIANT", "storage": "column"},
                "RegKey": {"type": "STRING", "storage": "column"},
                "RegVal": {"type": "STRING", "storage": "column"},
                "meta": {"type": "VARIANT", "storage": "column"},
                "meta.a": {"type": "STRING", "storage": "variant"},
                "hashes_arr": {"type": "ARRAY", "storage": "column", "element": "STRING"},
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
    "Image": "EventData[Image]",
    "QueryName": ["EventData[QueryName]", "Data[QueryName]"],
    "Quote": "EventData[O'Brien]",
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
    with pytest.raises(SigmaConfigurationError) as exc:
        _sqls(env(table_name="t"), _rule(SEL))
    msg = str(exc.value)
    assert msg.startswith("-O parsers=... is required for lakewatch_v2 parsed tables")
    for pid in ("p_ct", "p_ct2", "aws_cloudtrail", "okta_system_log"):
        assert pid in msg


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


EVENT_DATA = "try_variant_get(EventData, '$', 'ARRAY<STRUCT<_Name: STRING, _VALUE: STRING>>')"


def _entry(source, name):
    return f"try_element_at(filter({source}, e -> e._Name = '{name}'), 1)._VALUE"


def test_parsed_named_entry_variant(env):
    sql = _one(env, """    sel:
        Image|endswith: '\\cmd.exe'
    condition: sel""")
    assert f"endswith(lower({_entry(EVENT_DATA, 'Image')}), lower('\\\\cmd.exe'))" in sql


def test_parsed_named_entry_targets_ored(env):
    sql = _one(env, """    sel:
        QueryName: evil.com
    condition: sel""")
    assert (f"lower({_entry(EVENT_DATA, 'QueryName')}) = lower('evil.com') OR "
            f"lower({_entry('Data', 'QueryName')}) = lower('evil.com')") in sql


def test_parsed_named_entry_regex_or_number_and_null(env):
    sql = _one(env, """    sel:
        Image|contains: [a, b, c]
    num:
        Image: 22
    nul:
        Image: null
    condition: sel or num or nul""")
    assert f"{_entry(EVENT_DATA, 'Image')} rlike '(?iu).*(a|b|c).*'" in sql
    assert f"lower({_entry(EVENT_DATA, 'Image')}) = lower('22')" in sql   # STRING value
    assert f"{_entry(EVENT_DATA, 'Image')} is null" in sql


def test_parsed_named_entry_quotes_name(env):
    sql = _one(env, """    sel:
        Quote: x
    condition: sel""")
    assert _entry(EVENT_DATA, "O\\'Brien") in sql


def test_parsed_named_entry_fieldref_fails(env):
    with pytest.raises(SigmaConversionError, match="field references to nested ARRAY/VARIANT"):
        _one(env, """    sel:
        Image|fieldref: eventName
    condition: sel""")


def test_parsed_unmapped_field_fails(env):
    with pytest.raises(SigmaTransformationError, match="not mapped by profile p_ct"):
        _one(env, """    sel:
        Unmapped: x
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
        Unmapped: x
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


# --- finalizer -----------------------------------------------------------------------------


def _docs(backend, rule):
    return [json.loads(q)["doc"] for q in backend.convert_rule(rule, "lakewatch_v2")]


def test_v2_parsed_document(env):
    detection = """    sel:
        eventName: ConsoleLogin
    condition: sel"""
    backend = env(parsers="p_ct", table_name="main.sec.cloudtrail")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        (doc,) = _docs(backend, _rule(detection))
    assert doc["rule_name"] == "ct_rule__p_ct"
    sql = doc["batch"]["sql"]["query"]
    assert sql.startswith("SELECT *\nFROM main.sec.cloudtrail\nWHERE IN_TIMERANGE(time)\n  AND (")
    assert "lower(eventtype) = lower('awsapicall')" in sql.lower()
    assert doc["annotations"]["sigma_profile"] == "p_ct@1"
    keys = list(doc["annotations"])
    assert keys.index("sigma_profile") == keys.index("converter_version") - 1


def test_v2_parsed_rule_name_suffix_kept_when_truncated(env):
    rule = _rule(SEL)
    # pySigma rejects titles over 256 characters at parse time; set it afterwards.
    rule.title = "word " * 60
    assert len(rule.title) == 300
    backend = env(parsers="p_ct,p_ct2", table_map="p_ct:t1,p_ct2:t2")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        names = [d["rule_name"] for d in _docs(backend, rule)]
    assert names[0].endswith("__p_ct") and names[1].endswith("__p_ct2")
    assert all(len(n) <= 256 for n in names)
    assert names[0] != names[1]


# --- final review fixes ----------------------------------------------------------------------


def test_parsed_multi_target_prefix_ors_all_targets(env):
    sql = _one(env, """    sel:
        params.bucketName: b
    condition: sel""", extra_fields={"params.*": ["requestParameters.*", "responseElements.*"]})
    assert (
        "(lower(try_variant_get(requestParameters, '$.bucketName', 'string')) = lower('b') OR "
        "lower(try_variant_get(responseElements, '$.bucketName', 'string')) = lower('b'))"
    ) in sql


WHOLE_VARIANT_REASON = (
    "comparison against the whole VARIANT column requestParameters is not supported yet "
    "(profile p_ct)"
)


def test_parsed_error_message_starts_with_reason(env):
    with pytest.raises(SigmaConversionError) as exc:
        _one(env, """    sel:
        requestParameters|contains: x
    condition: sel""", extra_fields={"requestParameters": "requestParameters"})
    msg = str(exc.value)
    assert msg.startswith(WHOLE_VARIANT_REASON)
    assert " in rule " not in msg.split(WHOLE_VARIANT_REASON)[0]
    assert "CT Rule" in msg


def test_parsed_error_message_includes_rule_location(env, tmp_path):
    from sigma.exceptions import SigmaRuleLocation

    rule_file = tmp_path / "r.yml"
    rule = SigmaCollection.from_yaml("""
title: Located
status: test
logsource: {product: aws, service: cloudtrail}
detection:
    sel:
        requestParameters|contains: x
    condition: sel
""", source=SigmaRuleLocation(rule_file)).rules[0]
    backend = env(parsers="p_ct", table_name="t", extra_fields={"requestParameters": "requestParameters"},
                  collect_errors=True)
    assert backend.convert_rule(rule, "lakewatch_v2") == []
    (failed, error), = backend.errors
    assert failed is rule
    msg = str(error)
    assert msg.startswith(WHOLE_VARIANT_REASON)
    assert str(rule_file.resolve()) in msg
    assert error.source == rule.source
    assert error.rule is rule


@pytest.mark.parametrize("detection, extra, reason", [
    ("    sel:\n        Tls: x\n    condition: sel", None,
     "comparison against the whole STRUCT field tlsDetails is not supported (profile p_ct)"),
    ("    sel:\n        eventName|fieldref: resources.arn\n    condition: sel", None,
     "field references to nested ARRAY/VARIANT fields are not supported (profile p_ct)"),
])
def test_parsed_error_messages_start_with_reason(env, detection, extra, reason):
    with pytest.raises(SigmaConversionError) as exc:
        _one(env, detection, extra_fields=extra)
    assert str(exc.value).startswith(reason)


def test_parsed_unknown_field_error_starts_with_reason(env):
    backend = env(parsers="p_ct", table_name="t")
    backend._parsed_setup()
    backend._current_profile = backend._selected[0]
    backend._current_rule = _rule(SEL)
    with pytest.raises(SigmaConversionError) as exc:
        backend._field_path("nosuch")
    assert str(exc.value).startswith("fx_ct: field 'nosuch' is not usable")
    assert str(exc.value).endswith("(profile p_ct) (rule 'CT Rule')")


def test_parsed_no_match_error_starts_with_reason(env):
    backend = env(parsers="p_ct", table_name="t")
    with pytest.raises(SigmaConversionError) as exc:
        _sqls(backend, _rule(SEL, product="okta", service="okta"))
    assert str(exc.value).startswith("no selected Lakewatch parser profile matches logsource okta/None/okta")


@pytest.mark.parametrize("field", ["userIdentity.sessionContext", "userIdentity.webIdFederationData"])
def test_parsed_nested_variant_object_comparison_fails(env, field):
    with pytest.raises(SigmaConversionError) as exc:
        _one(env, f"""    sel:
        {field}|contains: x
    condition: sel""", extra_fields={field: field})
    assert str(exc.value).startswith(
        f"comparison against the whole VARIANT column {field} is not supported yet (profile p_ct)"
    )


def test_parsed_nested_variant_object_regex_or_fails(env):
    with pytest.raises(SigmaConversionError, match="whole VARIANT column userIdentity.sessionContext"):
        _one(env, """    sel:
        userIdentity.sessionContext|contains: [a, b, c]
    condition: sel""", extra_fields={"userIdentity.sessionContext": "userIdentity.sessionContext"})


def test_parsed_nested_variant_object_null_and_exists_allowed(env):
    sql = _one(env, """    sel:
        userIdentity.sessionContext: null
        userIdentity.webIdFederationData|exists: true
    condition: sel""", extra_fields={
        "userIdentity.sessionContext": "userIdentity.sessionContext",
        "userIdentity.webIdFederationData": "userIdentity.webIdFederationData",
    })
    assert "try_variant_get(userIdentity, '$.sessionContext', 'string') is null" in sql
    assert "try_variant_get(userIdentity, '$.webIdFederationData', 'string') is not null" in sql


def test_parsed_compare_string_column_casts_to_double(env):
    sql = _one(env, """    sel:
        eventName|gt: 5
    condition: sel""")
    assert "try_cast(eventName AS DOUBLE) > 5" in sql


def test_parsed_compare_declared_string_variant_key_casts_to_double(env):
    sql = _one(env, """    sel:
        userIdentity.arn|lte: 5
    condition: sel""")
    assert "try_cast(try_variant_get(userIdentity, '$.arn', 'string') AS DOUBLE) <= 5" in sql


def test_parsed_compare_freeform_variant_key_uses_double(env):
    sql = _one(env, """    sel:
        requestParameters.maxResults|gte: 5
    condition: sel""")
    assert "try_variant_get(requestParameters, '$.maxResults', 'double') >= 5" in sql
    assert "try_cast(try_variant_get" not in sql


@pytest.mark.parametrize("options", [
    {"catalog_name": ""},
    {"schema_name": "  "},
    {"catalog_name": None, "schema_name": None},
])
def test_parsed_missing_catalog_or_schema_is_configuration_error(env, options):
    backend = env(parsers="p_ct", table_name="t", collect_errors=True, **options)
    with pytest.raises(SigmaConfigurationError, match="catalog_name and schema_name"):
        backend.convert(SigmaCollection([_rule(SEL)]), "lakewatch_v2")
    assert backend.errors == []


# --- joins, undeclared VARIANT keys, allowed values -----------------------------------------

REG_SPLIT = {"TargetObject": {"transform": {"registry_path": {
    "hive": "kernel", "split": {"key": "RegKey", "value": "RegVal"}}}}}
REG_JOIN = "concat_ws('\\\\', nullif(RegKey, ''), nullif(RegVal, ''))"


def test_join_rendering_startswith(env):
    sql = _one(env, r"""    sel:
        TargetObject|startswith: 'HKLM\SOFTWARE\'
    condition: sel""", extra_fields=REG_SPLIT)
    assert (
        f"startswith(lower({REG_JOIN}), "
        r"lower('\\REGISTRY\\MACHINE\\SOFTWARE\\'))"
    ) in sql


def test_join_variant_parts(env):
    sql = _one(env, r"""    sel:
        TargetObject|contains: 'CurrentVersion\Run'
    condition: sel""", extra_fields={"TargetObject": {"transform": {"registry_path": {
        "hive": "kernel", "split": {"key": "event.RegObjectName", "value": "event.RegValueName"}}}}})
    assert "nullif(try_variant_get(event, '$.RegObjectName', 'string'), '')" in sql
    assert "nullif(try_variant_get(event, '$.RegValueName', 'string'), '')" in sql


def test_join_regex_or_optimization(env):
    sql = _one(env, """    sel:
        TargetObject|contains: [a, b, c]
    condition: sel""", extra_fields=REG_SPLIT)
    assert f"{REG_JOIN} rlike '(?iu).*(a|b|c).*'" in sql
    assert sql.count("rlike") == 1


def _parsed_backend(env, undeclared=()):
    """Return a backend set up for direct calls in parsed mode with profile p_ct."""
    backend = env(parsers="p_ct", table_name="ct_table")
    backend._parsed_setup()
    backend._current_profile = backend._selected[0]
    backend._current_rule = None
    backend._current_undeclared = frozenset(undeclared)
    return backend


def _convert_cond(backend, field, value):
    from sigma.conditions import ConditionFieldEqualsValueExpression
    from sigma.conversion.state import ConversionState

    cond = ConditionFieldEqualsValueExpression(field, value)
    return backend.convert_condition_field_eq_val(cond, ConversionState())


def _reg_join():
    from sigma.backends.databricks.field_paths import join_field_name

    return join_field_name("\\", ["RegKey", "RegVal"])


def test_join_number_bool_coerced_and_compare_cast(env):
    from sigma.types import CompareOperators, SigmaBool, SigmaCompareExpression, SigmaNumber

    backend = _parsed_backend(env)
    assert _convert_cond(backend, _reg_join(), SigmaNumber(5)) == f"lower({REG_JOIN}) = lower('5')"
    assert _convert_cond(backend, _reg_join(), SigmaBool(True)) == f"lower({REG_JOIN}) = lower('true')"
    expr = SigmaCompareExpression(SigmaNumber(3), CompareOperators.GT)
    assert _convert_cond(backend, _reg_join(), expr) == f"try_cast({REG_JOIN} AS DOUBLE) > 3"


def test_join_null(env):
    from sigma.types import SigmaNull

    assert _convert_cond(_parsed_backend(env), _reg_join(), SigmaNull()) == f"{REG_JOIN} is null"


@pytest.mark.parametrize("swap", [False, True])
def test_join_fieldref_fails(env, swap):
    from sigma.types import SigmaFieldReference

    backend = _parsed_backend(env)
    field, ref = (_reg_join(), "eventName")
    if swap:
        field, ref = ref, field
    with pytest.raises(SigmaConversionError, match="field references to joined fields are not supported"):
        _convert_cond(backend, field, SigmaFieldReference(ref))


def test_undeclared_mapping_renders(env):
    sql = _one(env, """    sel:
        X: foo
    condition: sel""", extra_fields={"X": {"field": "meta.custom", "undeclared": True}})
    assert "lower(try_variant_get(meta, '$.custom', 'string')) = lower('foo')" in sql


def test_undeclared_needs_mapping_flag(env):
    backend = _parsed_backend(env)
    with pytest.raises(SigmaConversionError, match="'custom' is not declared under 'meta'"):
        backend._resolve_parsed_field("meta.custom")
    backend._current_undeclared = frozenset({"meta.custom"})
    assert backend._resolve_parsed_field("meta.custom").json_path == ("custom",)


def test_undeclared_join_part(env):
    from sigma.backends.databricks.field_paths import join_field_name

    backend = _parsed_backend(env)
    name = join_field_name("\\", ["RegKey", "meta.custom"])
    with pytest.raises(SigmaConversionError, match="custom"):
        backend._resolve_parsed_field(name)
    backend._current_undeclared = frozenset({"meta.custom"})
    path = backend._resolve_parsed_field(name)
    assert path.join[1].json_path == ("custom",)
    backend._current_undeclared = frozenset({"RegKey"})
    with pytest.raises(SigmaConversionError, match="custom"):
        backend._resolve_parsed_field(name)


def test_allowed_value_warning(env):
    backend = env(parsers="p_ct", table_name="ct_table")
    rule = _rule("""    sel:
        EventID: '11'
    condition: sel""", title="Allowed Rule")
    with pytest.warns(UserWarning, match="never matches") as record:
        sqls = _sqls(backend, rule)
    assert len(sqls) == 1 and "lower(EventID) = lower('11')" in sqls[0]
    messages = [str(w.message) for w in record if "never matches" in str(w.message)]
    assert messages == [
        "rule 'Allowed Rule': EventID = '11' never matches parser fx_ct; allowed: ['1', '7']"
    ]


@pytest.mark.parametrize("value", ["'7'", "7", "'*1*'", "null"])
def test_allowed_value_no_warning(env, value):
    backend = env(parsers="p_ct", table_name="ct_table")
    rule = _rule(f"""    sel:
        EventID: {value}
    condition: sel""")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _sqls(backend, rule)


def test_allowed_value_warning_number(env):
    backend = env(parsers="p_ct", table_name="ct_table")
    with pytest.warns(UserWarning, match="EventID = '4688' never matches parser fx_ct"):
        _sqls(backend, _rule("""    sel:
        EventID: 4688
    condition: sel"""))


def test_hashes_end_to_end_array_column(env):
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sql = _one(env, f"""    sel:
        Hashes: 'MD5={md5}'
    condition: sel""", extra_fields={"Hashes": {"transform": {"hashes": {"algos": {"MD5": "hashes_arr"}}}}})
    assert f"exists(hashes_arr, x0 -> lower(x0) = lower('{md5}'))" in sql
