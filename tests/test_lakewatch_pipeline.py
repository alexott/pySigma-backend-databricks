import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.rule import SigmaDetection, SigmaDetectionItem

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
        SigmaTransformationError, match="keyword search is not supported by profile p1"
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
