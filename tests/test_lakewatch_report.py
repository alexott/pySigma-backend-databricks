"""Tests for the Lakewatch conversion report: field resolution, warnings, approximate flag and lint."""

import warnings
from pathlib import Path

import pytest
import yaml
from sigma.collection import SigmaCollection

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.lakewatch_report import (
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
    return DatabricksBackend(parsers=parsers, table_name="t", catalog_name="c", schema_name="s",
                           warehouse_id="w", **options)


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
        warnings.simplefilter("always")
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
    backend = DatabricksBackend(table_name="t", catalog_name="c", schema_name="s", warehouse_id="w", ocsf=True)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        backend.convert(_rules(SYSMON_RULE), "lakewatch")
    result = backend.last_report["rules"][0]["results"][0]
    assert result["profile"] is None
    assert result["fields"] == {}


def test_last_report_is_plain_yaml_data():
    backend = _backend(SYSMON)
    backend.convert(_rules(SYSMON_RULE), "lakewatch")
    yaml.safe_dump(backend.last_report)


def test_ocsf_errors_are_per_result():
    bad = _rule_yaml(SYSMON_LS, "sel:\n    Image|expand: '%foo%'", title="Bad Rule")
    good = _rule_yaml(SYSMON_LS, "sel:\n    Image: x", title="Good Rule").replace("000000000001", "000000000002")
    backend = DatabricksBackend(table_name="t", catalog_name="c", schema_name="s", warehouse_id="w", ocsf=True,
                                collect_errors=True)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        backend.convert(_rules(bad + "\n---\n" + good), "lakewatch")
    assert backend.errors
    first, second = (r["results"][0] for r in backend.last_report["rules"])
    assert first["status"] == "failed"
    assert second["status"] == "converted"
    assert second["reason"] is None


# --- statuses, failures, totals and conversion_report.yaml ---

import json  # noqa: E402

BUNDLED_SCHEMAS = (Path(__file__).parent.parent / "sigma" / "backends" / "databricks"
                   / "lakewatch_schemas" / "windows_custom.json")
UUID = "11111111-2222-3333-4444-555555555555"


def _convert_lw(backend, text):
    return backend.convert(_rules(text), "lakewatch")


def test_report_file_written(tmp_path):
    backend = _backend(SYSMON, output_dir=str(tmp_path))
    _convert_lw(backend, SYSMON_RULE)
    written = yaml.safe_load((tmp_path / "conversion_report.yaml").read_text())
    assert written == backend.last_report
    assert written["summary"] == {
        "rules": 1, "converted": 1, "failed": 0, "skipped": 0,
        "by_logsource": {"windows/process_creation/-": {"converted": 1, "failed": 0, "skipped": 0}}}
    assert list(written) == ["summary", "rules"]
    assert written["rules"][0]["status"] == "converted"
    assert written["rules"][0]["reason"] is None


def test_report_content_pack_file_written(tmp_path):
    data = json.loads(BUNDLED_SCHEMAS.read_text())
    entry = data["parsers"][SYSMON]
    entry["uuid"] = UUID
    schemas = tmp_path / "schemas.json"
    schemas.write_text(json.dumps({"parsers": {SYSMON: entry}}))
    out = tmp_path / "rules"
    backend = DatabricksBackend(target="content_pack", parsers=SYSMON, lakewatch_schemas=str(schemas),
                                output_dir=str(out))
    _convert_lw(backend, SYSMON_RULE)
    assert (out / "revisions.yaml").is_file()
    written = yaml.safe_load((out / "conversion_report.yaml").read_text())
    assert written == backend.last_report
    assert written["summary"]["converted"] == 1


def test_report_mixed_profile_results():
    rule = _rule_yaml({"product": "windows", "category": "process_creation"},
                      "sel:\n    OriginalFileName: 'x.exe'")
    backend = DatabricksBackend(
        parsers=f"{SYSMON},windows_security_process", catalog_name="c", schema_name="s", warehouse_id="w",
        table_map=f"{SYSMON}:t1,windows_security_process:t2", collect_errors=True)
    _convert_lw(backend, rule)
    record = backend.last_report["rules"][0]
    assert record["status"] == "converted"
    assert record["reason"] is None
    statuses = sorted(r["status"] for r in record["results"])
    assert statuses == ["converted", "failed"]
    failed = next(r for r in record["results"] if r["status"] == "failed")
    assert "OriginalFileName" in failed["reason"]


def test_report_no_matching_profile():
    rule = _rule_yaml({"product": "linux", "category": "nothing_here"}, "sel:\n    Image: x")
    backend = _backend(SYSMON, collect_errors=True)
    _convert_lw(backend, rule)
    record = backend.last_report["rules"][0]
    assert record["status"] == "failed"
    assert record["results"] == []
    assert record["reason"].startswith("no selected Lakewatch parser profile matches logsource")
    assert backend.last_report["summary"]["failed"] == 1


def test_report_correlation_rule_failed():
    text = SYSMON_RULE.replace("Report Test", "Base").replace("status: test", "name: base\nstatus: test") + """
---
title: Corr
id: 5f1b9c8e-1111-4a2b-8c3d-000000000002
status: test
correlation:
    type: event_count
    rules:
        - base
    group-by:
        - Image
    timespan: 5m
    condition:
        gte: 3
"""
    backend = _backend(SYSMON, collect_errors=True)
    _convert_lw(backend, text)
    report = backend.last_report
    assert report["summary"]["rules"] == 2
    corr = next(r for r in report["rules"] if r["title"] == "Corr")
    assert corr["status"] == "failed"
    assert corr["reason"] == "correlation rules not supported by the lakewatch format (rule 'Corr')"
    assert corr["logsource"] is None
    assert corr["results"] == []
    assert report["summary"]["by_logsource"]["correlation"]["failed"] == 1


def test_report_deprecated_skipped():
    rule = SYSMON_RULE.replace("status: test", "status: deprecated")
    backend = _backend(SYSMON)
    _convert_lw(backend, rule)
    record = backend.last_report["rules"][0]
    assert record["status"] == "skipped"
    assert record["reason"] == "status deprecated"
    assert record["results"][0]["status"] == "skipped"
    summary = backend.last_report["summary"]
    assert (summary["skipped"], summary["converted"]) == (1, 0)
    assert summary["by_logsource"]["windows/process_creation/-"]["skipped"] == 1


def test_report_not_written_without_output_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    backend = _backend(SYSMON)
    _convert_lw(backend, SYSMON_RULE)
    assert backend.last_report is not None
    assert list(tmp_path.iterdir()) == []


def test_report_correlation_rule_keeps_input_order():
    base = SYSMON_RULE.replace("Report Test", "Base").replace("status: test", "name: base\nstatus: test")
    corr = """
title: Corr
id: 5f1b9c8e-1111-4a2b-8c3d-000000000002
status: test
correlation:
    type: event_count
    rules:
        - base
    group-by:
        - Image
    timespan: 5m
    condition:
        gte: 3
"""
    other = SYSMON_RULE.replace("Report Test", "Other").replace("0001", "0003")
    backend = _backend(SYSMON, collect_errors=True)
    _convert_lw(backend, base + "\n---" + corr + "\n---" + other)
    assert [r["title"] for r in backend.last_report["rules"]] == ["Base", "Corr", "Other"]


# --- warning capture keeps filters and dedup; approximate comes from a flag ---

LENIENT = {"product": "windows", "service": "application"}


def _two_lenient_rules():
    one = _rule_yaml(LENIENT, "sel:\n    Foo: bar", title="First")
    two = _rule_yaml(LENIENT, "sel:\n    Foo: bar", title="Second").replace("000000000001", "000000000002")
    return _rules(one + "\n---\n" + two)


def test_untitled_warning_is_shown_once_under_default_filter():
    backend = _backend(APP)
    with warnings.catch_warnings(record=True) as shown:
        warnings.simplefilter("default")
        backend.convert(_two_lenient_rules(), "lakewatch")
    assert len([w for w in shown if "not in a field list" in str(w.message)]) == 1
    # only the warning that was shown is reported
    listed = [r["results"][0]["warnings"] for r in backend.last_report["rules"]]
    assert sum(any("not in a field list" in m for m in ws) for ws in listed) == 1


def test_module_filter_still_suppresses_pipeline_warning():
    backend = _backend(APP)
    with warnings.catch_warnings(record=True) as shown:
        warnings.simplefilter("always")
        warnings.filterwarnings("ignore", module=r"sigma\.pipelines\.databricks")
        backend.convert(_rules(_rule_yaml(LENIENT, "sel:\n    Foo: bar")), "lakewatch")
    assert not [w for w in shown if "not in a field list" in str(w.message)]
    assert backend.last_report["rules"][0]["results"][0]["warnings"] == []


def test_approximate_set_even_when_warning_is_ignored():
    rule = _rule_yaml(LENIENT, "sel:\n    - needle", "sel")
    backend = _backend(APP)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        backend.convert(_rules(rule), "lakewatch")
    result = backend.last_report["rules"][0]["results"][0]
    assert result["approximate"] is True
    assert result["warnings"] == []


def test_showwarning_is_restored():
    before = warnings.showwarning
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        _backend(SYSMON).convert(_rules(SYSMON_RULE), "lakewatch")
        assert warnings.showwarning is before


CORR_TEXT = SYSMON_RULE.replace("Report Test", "Base").replace("status: test", "name: base\nstatus: test") + """
---
title: Corr
id: 5f1b9c8e-1111-4a2b-8c3d-000000000002
status: test
correlation:
    type: event_count
    rules:
        - base
    group-by:
        - Image
    timespan: 5m
    condition:
        gte: 3
"""


def test_report_base_rule_of_correlation_is_skipped():
    backend = _backend(SYSMON, collect_errors=True)
    _convert_lw(backend, CORR_TEXT)
    base = next(r for r in backend.last_report["rules"] if r["title"] == "Base")
    assert base["status"] == "skipped"
    assert base["reason"] == "referenced by a correlation rule"
    assert base["results"][0]["status"] == "skipped"
    assert backend.last_report["summary"]["skipped"] == 1


def test_last_report_is_none_after_aborted_run():
    backend = _backend(SYSMON)
    _convert_lw(backend, SYSMON_RULE)
    assert backend.last_report is not None
    with pytest.raises(NotImplementedError):
        _convert_lw(backend, CORR_TEXT)
    assert backend.last_report is None


def test_report_file_does_not_overwrite_rule_named_conversion_report(tmp_path):
    rule = _rule_yaml(SYSMON_LS, "sel:\n    Image: x", title="Conversion Report")
    backend = DatabricksBackend(table_name="t", catalog_name="c", schema_name="s", warehouse_id="w", ocsf=True,
                                output_dir=str(tmp_path))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        _convert_lw(backend, rule)
    assert backend.last_report["rules"][0]["results"][0]["rule_names"] == ["conversion_report_2"]
    assert (tmp_path / "conversion_report_2.yaml").exists()
    assert yaml.safe_load((tmp_path / "conversion_report.yaml").read_text())["summary"]["rules"] == 1


def test_direct_convert_rule_does_not_grow_report():
    backend = _backend(SYSMON)
    rules = _rules(_rule_yaml(SYSMON_LS, "sel:\n    Image: a", title="One")
                   + "\n---\n" + _rule_yaml(SYSMON_LS, "sel:\n    Image: b", title="Two"
                                            ).replace("000000000001", "000000000002")).rules
    backend.convert_rule(rules[0], "lakewatch")
    backend.convert_rule(rules[1], "lakewatch")
    assert [r["title"] for r in backend._report._rules] == ["Two"]


def test_size_failure_in_report():
    values = "\n".join(f"  - '{i:05d}{'x' * 100}'" for i in range(700))
    rule = _rule_yaml(SYSMON_LS, f"sel:\n  Image|contains|all:\n{values}")
    backend = _backend(SYSMON, collect_errors=True)
    _convert_lw(backend, rule)
    record = backend.last_report["rules"][0]
    assert record["status"] == "failed"
    assert record["reason"].startswith("query is ")
    assert "over the Lakewatch limit of 65536 bytes" in record["reason"]
