"""Tests for the per-profile Lakewatch processing pipeline."""

import json
import re

import pytest
import yaml
from sigma.collection import SigmaCollection
from sigma.conditions import ConditionAND, ConditionOR
from sigma.exceptions import SigmaTransformationError
from sigma.rule import SigmaDetection

from sigma.backends.databricks import DatabricksBackend
from sigma.pipelines.databricks.lakewatch.pipeline import (
    STATE_PARSER,
    STATE_PROFILE,
    STATE_PROFILE_VERSION,
    build_profile_pipeline,
)
from sigma.pipelines.databricks.lakewatch.profile import parse_profile


def make(fields, block_extra=None, top_fields=None):
    block = {"match": {"product": "aws"}, "fields": fields}
    block.update(block_extra or {})
    data = {"profile": "p1", "version": 3, "parser": "aws_cloudtrail", "logsources": [block]}
    if top_fields:
        data["fields"] = top_fields
    profile = parse_profile(data)
    return profile, profile.logsources[0]


def rule(detection_yaml):
    return SigmaCollection.from_yaml(
        f"""
title: t
status: test
logsource:
    product: aws
detection:
{detection_yaml}
"""
    ).rules[0]


def run(profile, block, detection_yaml):
    pipeline = build_profile_pipeline(profile, block)
    r = rule(detection_yaml)
    pipeline.apply(r)
    return pipeline, r


SEL = """    sel:
        Image: foo
    condition: sel"""


def test_mapping_and_conditions_applied():
    profile, block = make({"Image": "eventName"}, {"conditions": {"eventType": "AwsApiCall"}})
    pipeline, r = run(profile, block, SEL)
    fields = sorted(
        i.field for d in r.detection.detections.values() for i in d.detection_items
    )
    assert fields == ["eventName", "eventType"]
    assert pipeline.state[STATE_PROFILE] == "p1"
    assert pipeline.state[STATE_PROFILE_VERSION] == 3
    assert pipeline.state[STATE_PARSER] == "aws_cloudtrail"
    assert pipeline.name == "Lakewatch profile p1"
    assert pipeline.priority == 100


def test_or_mapping_two_targets():
    profile, block = make({"Details": ["a", "b"]})
    _, r = run(profile, block, "    sel:\n        Details: x\n    condition: sel")
    item = r.detection.detections["sel"].detection_items[0]
    assert isinstance(item, SigmaDetection)
    assert [i.field for i in item.detection_items] == ["a", "b"]


def test_unmapped_field_fails():
    profile, block = make({"Image": "eventName"})
    with pytest.raises(SigmaTransformationError, match="field Other is not mapped by profile p1"):
        run(profile, block, "    sel:\n        Other: x\n    condition: sel")


def test_unsupported_field_fails():
    profile, block = make({"Image": "eventName"}, {"unsupported": ["Bad"]})
    with pytest.raises(SigmaTransformationError, match="field Bad is not supported by profile p1"):
        run(profile, block, "    sel:\n        Bad: x\n    condition: sel")


def test_keyword_fails():
    profile, block = make({"Image": "eventName"})
    with pytest.raises(
        SigmaTransformationError, match="no raw event for keyword search in profile p1"
    ):
        run(profile, block, "    kw:\n        - foo\n    condition: kw")


def test_prefix_mapping_identity():
    profile, block = make({"requestParameters.*": "requestParameters.*"})
    _, r = run(profile, block, "    sel:\n        requestParameters.bucketName: x\n    condition: sel")
    assert r.detection.detections["sel"].detection_items[0].field == "requestParameters.bucketName"
    with pytest.raises(SigmaTransformationError, match="field responseElements.x is not mapped"):
        run(profile, block, "    sel:\n        responseElements.x: x\n    condition: sel")


def test_prefix_mapping_rewrite_and_exact_wins():
    profile, block = make(
        {"props.*": "requestParameters.*", "props.special": "eventName"}
    )
    _, r = run(
        profile,
        block,
        "    sel:\n        props.a: 1\n        props.special: 2\n    condition: sel",
    )
    fields = [i.field for i in r.detection.detections["sel"].detection_items]
    assert fields == ["requestParameters.a", "eventName"]


def test_nested_detection_checked_and_mapped():
    profile, block = make({"Image": "eventName"})
    nested = """    sel:
        - Image: a
        - Image: b
          Other: c
    condition: sel"""
    with pytest.raises(SigmaTransformationError, match="field Other is not mapped"):
        run(profile, block, nested)
    ok = """    sel:
        - Image: a
        - Image: b
    condition: sel"""
    _, r = run(profile, block, ok)
    sub = r.detection.detections["sel"].detection_items
    assert all(
        isinstance(d, SigmaDetection) and d.detection_items[0].field == "eventName" for d in sub
    )


def test_fieldref_unmapped_fails():
    profile, block = make({"A": "a"})
    with pytest.raises(SigmaTransformationError, match="field Zzz is not mapped by profile p1"):
        run(profile, block, "    sel:\n        A|fieldref: Zzz\n    condition: sel")


def test_fieldref_unsupported_fails():
    profile, block = make({"A": "a"}, {"unsupported": ["Bad"]})
    with pytest.raises(SigmaTransformationError, match="field Bad is not supported by profile p1"):
        run(profile, block, "    sel:\n        A|fieldref: Bad\n    condition: sel")


def test_fieldref_mapped_is_renamed():
    profile, block = make({"A": "a", "B": "b"})
    _, r = run(profile, block, "    sel:\n        A|fieldref: B\n    condition: sel")
    item = r.detection.detections["sel"].detection_items[0]
    assert item.field == "a"
    assert item.value[0].field == "b"


def test_raw_field_matching_exact_target_still_gets_prefix_rewrite():
    profile, block = make({"A": "props.x", "props.*": "req.*"})
    _, r = run(
        profile, block, "    sel:\n        props.x: 1\n        A: 2\n    condition: sel"
    )
    fields = [i.field for i in r.detection.detections["sel"].detection_items]
    assert fields == ["req.x", "props.x"]


def test_exact_multi_target_or_with_prefix_present():
    profile, block = make({"A": ["props.x", "b"], "props.*": "req.*"})
    _, r = run(profile, block, "    sel:\n        A: 1\n    condition: sel")
    item = r.detection.detections["sel"].detection_items[0]
    assert [i.field for i in item.detection_items] == ["props.x", "b"]


@pytest.mark.parametrize("name", ["requestParameters.", "requestParameters"])
def test_bare_prefix_and_root_rejected(name):
    profile, block = make({"requestParameters.*": "requestParameters.*"})
    with pytest.raises(SigmaTransformationError, match="is not mapped by profile p1"):
        run(profile, block, f"    sel:\n        {name}: x\n    condition: sel")


@pytest.mark.parametrize("targets, expected", [
    (["requestParameters.*", "responseElements.*"],
     ["requestParameters.bucketName", "responseElements.bucketName"]),
    (["params.*", "responseElements.*"], ["params.bucketName", "responseElements.bucketName"]),
])
def test_multi_target_prefix_mapping_keeps_every_target(targets, expected):
    profile, block = make({"params.*": targets})
    _, r = run(profile, block, "    sel:\n        params.bucketName: b\n    condition: sel")
    item = r.detection.detections["sel"].detection_items[0]
    assert isinstance(item, SigmaDetection)
    assert [i.field for i in item.detection_items] == expected


# --- transforms, select_condition, modifiers, products (Plan 2) ----------------------------


def make_win(fields, products=None, conditions=None, transforms=None, pid="p"):
    block = {"match": {"product": "windows", "category": "process_creation"}, "fields": fields}
    if conditions:
        block["conditions"] = conditions
    data = {"profile": pid, "version": 1, "parser": "fx", "logsources": [block]}
    if products:
        data["products"] = products
    if transforms:
        data["transforms"] = transforms
    profile = parse_profile(data)
    return profile, profile.logsources[0]


def win_rule(detection_yaml):
    return SigmaCollection.from_yaml(
        f"""
title: t
status: test
logsource:
    product: windows
    category: process_creation
detection:
{detection_yaml}
"""
    ).rules[0]


def run_win(profile, block, detection_yaml, with_logsource=True):
    r = win_rule(detection_yaml)
    pipeline = build_profile_pipeline(profile, block, r.logsource if with_logsource else None)
    pipeline.apply(r)
    return r


def leaves(node):
    """Return (field, value) pairs of a detection tree, depth first."""
    if isinstance(node, SigmaDetection):
        return [leaf for child in node.detection_items for leaf in leaves(child)]
    return [(node.field, str(v)) for v in node.value]


def sel_item(r, name="sel"):
    return r.detection.detections[name].detection_items[0]


def test_transform_map_or():
    profile, block = make_win({"Protocol": {"field": "p", "transform": {"map": {"values": {"both": [6, 17]}}}}})
    r = run_win(profile, block, "    sel:\n        Protocol: both\n    condition: sel")
    item = sel_item(r)
    assert isinstance(item, SigmaDetection)
    assert item.item_linking is ConditionOR
    assert leaves(item) == [("p", "6"), ("p", "17")]
    assert all(not i.modifiers for i in item.detection_items)


def test_transform_all_links_values_with_and():
    profile, block = make_win({"C": {"field": "c", "transform": {"case": "upper"}}})
    r = run_win(profile, block, "    sel:\n        C|contains|all: [a, b]\n    condition: sel")
    item = sel_item(r)
    assert isinstance(item, SigmaDetection)
    assert item.item_linking is ConditionAND
    assert leaves(item) == [("c", "*A*"), ("c", "*B*")]


def test_transform_several_targets_ored():
    profile, block = make_win({"C": {"field": ["c1", "c2"], "transform": {"case": "lower"}}})
    r = run_win(profile, block, "    sel:\n        C: X\n    condition: sel")
    assert leaves(sel_item(r)) == [("c1", "x"), ("c2", "x")]


def test_hashes_routes_columns():
    sha = "a" * 64
    md5 = "b" * 32
    profile, block = make_win({"Hashes": {"transform": {"hashes": {"algos": {"SHA256": "sha", "MD5": "md5"}}}}})
    r = run_win(
        profile, block, f"    sel:\n        Hashes|contains: ['SHA256={sha}', 'MD5={md5}']\n    condition: sel"
    )
    assert leaves(sel_item(r)) == [("sha", sha), ("md5", md5)]


def test_hashes_nothing_left_fails():
    profile, block = make_win({"Hashes": {"transform": {"hashes": {"algos": {"SHA256": "sha"}}}}})
    with pytest.warns(UserWarning), pytest.raises(
        SigmaTransformationError, match="field Hashes: no value left after transform hashes"
    ):
        run_win(profile, block, f"    sel:\n        Hashes: 'MD5={'b' * 32}'\n    condition: sel")


SELECT = {"Initiated": {"select_condition": {"true": {"t": "A"}, "false": {"t": "B", "u": 1}}}}


def test_select_condition_string_and_bool():
    profile, block = make_win(SELECT)
    r1 = run_win(profile, block, "    sel:\n        Initiated: 'true'\n    condition: sel")
    r2 = run_win(profile, block, "    sel:\n        Initiated: true\n    condition: sel")
    for r in (r1, r2):
        item = sel_item(r)
        assert isinstance(item, SigmaDetection)
        assert leaves(item) == [("t", "A")]
    assert sel_item(r1) == sel_item(r2)


def test_select_condition_conditions_anded_values_ored():
    profile, block = make_win(SELECT)
    r = run_win(profile, block, "    sel:\n        Initiated: ['true', 'FALSE']\n    condition: sel")
    item = sel_item(r)
    assert item.item_linking is ConditionOR
    first, second = item.detection_items
    assert leaves(first) == [("t", "A")]
    assert isinstance(second, SigmaDetection) and second.item_linking is ConditionAND
    assert leaves(second) == [("t", "B"), ("u", "1")]


@pytest.mark.parametrize("value", ["maybe", "tr*"])
def test_select_condition_miss_fails(value):
    profile, block = make_win(SELECT)
    with pytest.raises(SigmaTransformationError, match=r"value '.*' is not one of \['true', 'false'\]"):
        run_win(profile, block, f"    sel:\n        Initiated: '{value}'\n    condition: sel")


SCHEMA = {
    "parsers": {
        "fx": {
            "uuid": "u-fx",
            "version": 1,
            "paths": {
                "Image": {"type": "STRING", "storage": "column"},
                "t": {"type": "STRING", "storage": "column"},
                "event_platform": {"type": "STRING", "storage": "column"},
            },
        }
    }
}


def convert_sql(tmp_path, fields, detection_yaml):
    """Convert a windows rule through the backend with a one-profile fixture; return the SQL."""
    schema_file = tmp_path / "schema.json"
    schema_file.write_text(json.dumps(SCHEMA), encoding="utf-8")
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    profile = {
        "profile": "p_sel",
        "version": 1,
        "parser": "fx",
        "products": {"windows": {"event_platform": "Win"}},
        "fields": fields,
        "logsources": [{"match": {"category": "process_creation"}}],
    }
    (profiles / "p_sel.yml").write_text(yaml.safe_dump(profile), encoding="utf-8")
    backend = DatabricksBackend(
        parsers="p_sel",
        lakewatch_profiles_dir=str(profiles),
        lakewatch_schemas=str(schema_file),
        table_name="tbl",
        catalog_name="cat",
        schema_name="sch",
    )
    sqls = [json.loads(q)["sql"] for q in backend.convert_rule(win_rule(detection_yaml), "lakewatch_v2")]
    assert len(sqls) == 1
    return sqls[0]


def test_select_condition_under_not(tmp_path):
    fields = {
        "Image": "Image",
        "Initiated": {"select_condition": {"true": {"t": "A"}, "false": {"t": "B"}}},
    }
    sql = convert_sql(
        tmp_path,
        fields,
        "    sel:\n        Image: x\n    filter:\n        Initiated: 'false'\n    condition: sel and not filter",
    )
    assert "lower(event_platform) = lower('Win')" in sql
    assert re.search(r"NOT \(?lower\(t\) = lower\('B'\)", sql), sql
    assert "'A'" not in sql


def test_transform_linking_end_to_end(tmp_path):
    fields = {
        "Image": "Image",
        "T": {"field": ["t", "Image"], "transform": {"map": {"values": {"ab": ["a", "b"]}, "default": "keep"}}},
    }
    sql = convert_sql(tmp_path, fields, "    sel:\n        T|all: [ab, c]\n    condition: not sel")
    where = sql.split("WHERE", 1)[1]
    assert (
        "NOT ((lower(t) = lower('a') OR lower(Image) = lower('a') OR lower(t) = lower('b') "
        "OR lower(Image) = lower('b')) AND (lower(t) = lower('c') OR lower(Image) = lower('c')))"
    ) in where, where


def test_modifiers_restricted():
    profile, block = make_win({"X": {"field": "x", "modifiers": ["eq", "endswith"]}})
    r = run_win(profile, block, "    sel:\n        X|endswith: foo\n    condition: sel")
    assert leaves(r.detection.detections["sel"]) == [("x", "*foo")]
    r = run_win(profile, block, "    sel:\n        X: foo\n    condition: sel")
    assert leaves(r.detection.detections["sel"]) == [("x", "foo")]
    with pytest.raises(SigmaTransformationError, match=r"field X: modifier contains is not supported \(profile p\)"):
        run_win(profile, block, "    sel:\n        X|contains: foo\n    condition: sel")


def test_modifiers_restricted_eq_not_listed():
    profile, block = make_win({"X": {"field": "x", "modifiers": ["endswith"]}})
    with pytest.raises(SigmaTransformationError, match="field X: modifier eq is not supported"):
        run_win(profile, block, "    sel:\n        X: foo\n    condition: sel")


def test_transform_failure_message():
    profile, block = make_win({"ParentImage": {"field": "pi", "transform": "basename"}})
    with pytest.raises(SigmaTransformationError, match=r"field ParentImage: transform basename: .* \(profile p\)"):
        run_win(profile, block, "    sel:\n        ParentImage|startswith: 'C:\\Windows'\n    condition: sel")


def test_transform_failure_names_failing_step():
    profile, block = make_win({"N": {"field": "n", "transform": [{"case": "lower"}, "to_int"]}})
    with pytest.raises(SigmaTransformationError, match=r"field N: transform to_int: value 'abc' is not an integer"):
        run_win(profile, block, "    sel:\n        N: ABC\n    condition: sel")


def test_fieldref_on_transformed_field_fails():
    profile, block = make_win({"C": {"field": "c", "transform": {"case": "upper"}}, "D": "d"})
    msg = "field references are not supported for transformed fields"
    with pytest.raises(SigmaTransformationError, match=f"field C: {msg}"):
        run_win(profile, block, "    sel:\n        C|fieldref: D\n    condition: sel")
    # The message names the rule's field (D), and the referenced transformed field (C).
    ref = "field D: field reference to transformed field C is not supported"
    with pytest.raises(SigmaTransformationError, match=ref):
        run_win(profile, block, "    sel:\n        D|fieldref: C\n    condition: sel")


def test_fieldref_between_transformed_fields_names_rule_field():
    profile, block = make_win(
        {"C": {"field": "c", "transform": {"case": "upper"}}, "E": {"field": "e", "transform": "to_str"}}
    )
    with pytest.raises(SigmaTransformationError, match="field C: field reference to transformed field E"):
        run_win(profile, block, "    sel:\n        C|fieldref: E\n    condition: sel")


def test_cased_on_special_fields_fails():
    profile, block = make_win(
        {"C": {"field": "c", "transform": {"case": "upper"}}, "S": {"select_condition": {"a": {"k": "v"}}}, "P": "p"}
    )
    for field in ("C", "S"):
        msg = rf"field {field}: case-sensitive matching is not supported \(profile p\)"
        with pytest.raises(SigmaTransformationError, match=msg):
            run_win(profile, block, f"    sel:\n        {field}|cased: a\n    condition: sel")
    r = run_win(profile, block, "    sel:\n        P|cased: a\n    condition: sel")
    assert leaves(r.detection.detections["sel"]) == [("p", "a")]


def test_windash_on_transformed_field_message():
    profile, block = make_win({"C": {"field": "c", "transform": {"case": "upper"}}})
    msg = r"field C: transform case: expanded values \(windash/base64offset\) are not supported"
    with pytest.raises(SigmaTransformationError, match=msg):
        run_win(profile, block, "    sel:\n        C|windash|contains: ' -x '\n    condition: sel")


def test_named_transform_and_plain_fields_together():
    profile, block = make_win(
        {"C": {"field": "c", "transform": "up"}, "Image": "img"}, transforms={"up": {"case": "upper"}}
    )
    r = run_win(profile, block, "    sel:\n        C: a\n        Image: b\n    condition: sel")
    assert leaves(r.detection.detections["sel"]) == [("c", "A"), ("img", "b")]


def test_products_condition_added():
    profile, block = make_win({"Image": "img"}, products={"windows": {"event_platform": "Win"}}, conditions={"k": "v"})
    r = run_win(profile, block, "    sel:\n        Image: b\n    condition: sel")
    added = [leaf for name, d in r.detection.detections.items() if name != "sel" for leaf in leaves(d)]
    assert sorted(added) == [("event_platform", "Win"), ("k", "v")]
    r = run_win(profile, block, "    sel:\n        Image: b\n    condition: sel", with_logsource=False)
    added = [leaf for name, d in r.detection.detections.items() if name != "sel" for leaf in leaves(d)]
    assert added == [("k", "v")]


# --- lenient event_data: any, keyword gate, unmapped hint (Plan 3) ---------------------------


def make_top(top=None, block_extra=None, fields=None):
    block = {"match": {"product": "aws"}, "fields": fields or {"Image": "eventName"}}
    block.update(block_extra or {})
    data = {"profile": "p", "version": 1, "parser": "px", "logsources": [block]}
    data.update(top or {})
    profile = parse_profile(data)
    return profile, profile.logsources[0]


KW = "    kw:\n        - foo\n    condition: kw"


def test_keyword_without_raw_fails():
    profile, block = make_top()
    with pytest.raises(SigmaTransformationError, match="no raw event for keyword search in profile p"):
        run(profile, block, KW)


def test_keyword_with_raw_passes():
    profile, block = make_top({"raw": {"column": "raw_line"}})
    run(profile, block, KW)


def test_keyword_explicit_override():
    profile, block = make_top()
    pipeline = build_profile_pipeline(profile, block, keywords=True)
    pipeline.apply(rule(KW))


def test_any_maps_and_warns():
    profile, block = make_top(block_extra={"event_data": "any"})
    with pytest.warns(UserWarning, match="not in a field list"):
        _, r = run(profile, block, "    sel:\n        ServiceName: x\n    condition: sel")
    assert r.detection.detections["sel"].detection_items[0].field == "EventData[ServiceName]"


def test_any_warns_once_per_field_and_not_for_mapped():
    import warnings

    profile, block = make_top(block_extra={"event_data": "any"})
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        run(profile, block, "    sel:\n        Image: a\n        ServiceName: x\n    condition: sel")
    msgs = [str(x.message) for x in w if "not in a field list" in str(x.message)]
    assert len(msgs) == 1 and "ServiceName" in msgs[0]


def test_any_case_insensitive_explicit():
    profile, block = make_top(block_extra={"event_data": "any"}, fields={"Computer": "Computer"})
    _, r = run(profile, block, "    sel:\n        computer: x\n    condition: sel")
    assert r.detection.detections["sel"].detection_items[0].field == "Computer"


def test_any_rejects_brackets():
    profile, block = make_top(block_extra={"event_data": "any"})
    with pytest.raises(SigmaTransformationError, match="is not mapped"):
        run(profile, block, "    sel:\n        a[b]: x\n    condition: sel")


def test_any_fieldref_maps():
    profile, block = make_top(block_extra={"event_data": "any"})
    with pytest.warns(UserWarning, match="not in a field list"):
        _, r = run(profile, block, "    sel:\n        Image|fieldref: Other\n    condition: sel")
    item = r.detection.detections["sel"].detection_items[0]
    assert item.value[0].field == "EventData[Other]"


def test_unmapped_hint():
    profile, block = make_top({"unmapped_hint": "header only"})
    with pytest.raises(SigmaTransformationError, match="is not mapped by profile p1?; header only"):
        run(profile, block, "    sel:\n        Other: x\n    condition: sel")
