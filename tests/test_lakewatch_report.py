"""Tests for the Lakewatch conversion report: field resolution, warnings, approximate flag and lint."""

import warnings
from pathlib import Path

import pytest
import yaml
from sigma.collection import SigmaCollection

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.lakewatch_report import (
    LakewatchApproximateWarning,
    capture_warnings,
    describe_fields,
    rule_fields,
)

PROFILES_DIR = Path(__file__).parent.parent / "sigma" / "pipelines" / "databricks" / "lakewatch" / "profiles"

SYSMON = "windows_sysmon_process"
APP = "windows_application"
CT = "aws_cloudtrail"


def _rules(text):
    return SigmaCollection.from_yaml(text)


def _rule_yaml(logsource, detection, condition="sel", title="Report Test"):
    ls = "\n".join(f"    {k}: {v}" for k, v in logsource.items())
    det = "\n".join(f"    {line}" for line in detection.splitlines())
    return f"""
title: {title}
id: 5f1b9c8e-1111-4a2b-8c3d-000000000001
status: test
logsource:
{ls}
detection:
{det}
    condition: {condition}
"""


SYSMON_LS = {"product": "windows", "category": "process_creation"}
SYSMON_RULE = _rule_yaml(SYSMON_LS, "sel:\n    Image|endswith: '\\powershell.exe'")


def _backend(parsers, **options):
    return DatabricksBackend(parsers=parsers, table_name="t", catalog_name="c", schema_name="s", **options)


def _resolve(backend, parser, rule):
    backend._parsed_setup()
    profile, schema, _ = next(s for s in backend._selected if s[0].profile == parser)
    return profile, schema, profile.block_for(rule.logsource)


def test_rule_fields_order():
    rule = _rules(_rule_yaml(
        SYSMON_LS,
        "sel1:\n    Image|endswith: x\n    CommandLine: y\nsel2:\n    Image: z",
        "sel1 or sel2",
    )).rules[0]
    assert rule_fields(rule) == ["Image", "CommandLine"]


def test_describe_fields_resolutions():
    rule = _rules(SYSMON_RULE).rules[0]
    profile, schema, block = _resolve(_backend(SYSMON), SYSMON, rule)
    fields, lint = describe_fields(profile, block, schema, ["Image", "Computer", "NoSuch"])
    assert fields["Image"] == {"targets": ["EventData[Image]"], "resolution": "event_data"}
    assert fields["Computer"] == {"targets": ["Computer"], "resolution": "mapped"}
    assert fields["NoSuch"] == {"targets": [], "resolution": "unmapped"}
    assert lint == []

    app_rule = _rules(_rule_yaml({"product": "windows", "service": "application"},
                                 "sel:\n    Foo: bar")).rules[0]
    profile, schema, block = _resolve(_backend(APP), APP, app_rule)
    fields, _ = describe_fields(profile, block, schema, ["Foo"])
    assert fields["Foo"] == {"targets": ["EventData[Foo]"], "resolution": "lenient"}

    ct_rule = _rules(_rule_yaml({"product": "aws", "service": "cloudtrail"},
                                "sel:\n    requestParameters.bucketName: b")).rules[0]
    profile, schema, block = _resolve(_backend(CT), CT, ct_rule)
    fields, _ = describe_fields(profile, block, schema, ["requestParameters.bucketName"])
    assert fields["requestParameters.bucketName"]["resolution"] == "prefix"
    assert fields["requestParameters.bucketName"]["targets"] == ["requestParameters.bucketName"]


def test_lint_any_matching_column(tmp_path):
    text = (PROFILES_DIR / f"{APP}.yml").read_text()
    text = "\n".join(line for line in text.splitlines() if not line.startswith("  Channel:"))
    (tmp_path / f"{APP}.yml").write_text(text)
    rule = _rules(_rule_yaml({"product": "windows", "service": "application"},
                             "sel:\n    channel: Application")).rules[0]
    profile, schema, block = _resolve(_backend(APP, lakewatch_profiles_dir=str(tmp_path)), APP, rule)
    fields, lint = describe_fields(profile, block, schema, ["channel"])
    assert fields["channel"]["resolution"] == "lenient"
    assert lint == [
        "field channel is read from EventData[channel] by event_data any, but Channel "
        "is a top-level column of parser windows_application; map it explicitly"
    ]


def test_report_records_profile_result():
    backend = _backend(SYSMON)
    backend.convert(_rules(SYSMON_RULE), "lakewatch")
    result = backend.last_report["rules"][0]["results"][0]
    assert result["profile"] == "windows_sysmon_process@1"
    assert result["rule_names"] == ["report_test__windows_sysmon_process"]
    assert "Image" in result["fields"]
    assert result["approximate"] is False


def test_approximate_flag():
    rule = _rule_yaml({"product": "windows", "service": "application"},
                      "sel:\n    - needle", "sel")
    backend = _backend(APP)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        backend.convert(_rules(rule), "lakewatch")
    result = backend.last_report["rules"][0]["results"][0]
    assert result["approximate"] is True
    assert any("is approximate" in w for w in result["warnings"])


def test_warnings_still_emitted(tmp_path):
    text = (PROFILES_DIR / f"{SYSMON}.yml").read_text()
    text = "\n".join(line for line in text.splitlines() if not line.startswith("entity:"))
    (tmp_path / f"{SYSMON}.yml").write_text(text)
    backend = _backend(SYSMON, lakewatch_profiles_dir=str(tmp_path))
    with pytest.warns(UserWarning, match="has no entity"):
        backend.convert(_rules(SYSMON_RULE), "lakewatch")
    result = backend.last_report["rules"][0]["results"][0]
    assert any("has no entity" in w for w in result["warnings"])
    assert result["approximate"] is False


def test_ocsf_result_has_no_profile():
    backend = DatabricksBackend(table_name="t", catalog_name="c", schema_name="s", ocsf=True)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        backend.convert(_rules(SYSMON_RULE), "lakewatch")
    result = backend.last_report["rules"][0]["results"][0]
    assert result["profile"] is None
    assert result["fields"] == {}


def test_capture_warnings_without_reemit():
    with warnings.catch_warnings(record=True) as outer:
        warnings.simplefilter("always")
        with capture_warnings(reemit=False) as caught:
            warnings.warn("quiet", LakewatchApproximateWarning, stacklevel=1)
        assert [str(w.message) for w in caught] == ["quiet"]
        assert outer == []
        with capture_warnings() as caught:
            warnings.warn("loud", UserWarning, stacklevel=1)
    assert [str(w.message) for w in outer] == ["loud"]


def test_last_report_is_plain_yaml_data():
    backend = _backend(SYSMON)
    backend.convert(_rules(SYSMON_RULE), "lakewatch")
    yaml.safe_dump(backend.last_report)
