"""Tests for Lakewatch parser discovery (DatabricksBackend.discover_parsers)."""

import json
import warnings
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.lakewatch_report import discovery_summary

PROFILES_DIR = Path(__file__).parent.parent / "sigma" / "pipelines" / "databricks" / "lakewatch" / "profiles"
SYSMON = "windows_sysmon_process"
SECURITY = "windows_security_process"

RULE_ID = "5f1b9c8e-1111-4a2b-8c3d-000000000001"


def _rule(detection="sel:\n    CommandLine|contains: x\n    OriginalFileName: y.exe", rule_id=RULE_ID,
          logsource="product: windows\n    category: process_creation", title="Discovery Test"):
    det = "\n".join(f"    {line}" for line in detection.splitlines())
    return f"""
title: {title}
name: {title.lower().replace(" ", "_")}
id: {rule_id}
status: test
logsource:
    {logsource}
detection:
{det}
    condition: sel
"""


def _rules(*texts):
    return SigmaCollection.from_yaml("\n---\n".join(texts))


def test_discovery_convertible_and_not():
    report = DatabricksBackend().discover_parsers(_rules(_rule()))
    (entry,) = report["rules"]
    assert entry["sigma_id"] == RULE_ID
    assert entry["title"] == "Discovery Test"
    assert SYSMON in entry["convertible"]
    assert entry["convertible"] == sorted(entry["convertible"])
    assert SECURITY in entry["not_convertible"]
    assert "OriginalFileName" in entry["not_convertible"][SECURITY]
    assert list(entry["not_convertible"]) == sorted(entry["not_convertible"])
    assert "note" not in entry


def test_discovery_no_match_note():
    report = DatabricksBackend().discover_parsers(_rules(_rule(logsource="product: nosuch")))
    (entry,) = report["rules"]
    assert entry["convertible"] == []
    assert entry["not_convertible"] == {}
    assert entry["note"] == "no profile matches the logsource"
    assert report["summary"]["suggested_option"] is None


def test_discovery_summary():
    other = "6f1b9c8e-1111-4a2b-8c3d-000000000002"
    report = DatabricksBackend().discover_parsers(_rules(_rule(), _rule(rule_id=other, title="Second")))
    summary = report["summary"]
    assert summary["rules"] == 2
    counts = summary["convertible_rules"]
    assert counts[SYSMON] == 2
    assert all(n > 0 for n in counts.values())
    assert list(counts) == sorted(counts)
    assert summary["suggested_option"] == "-O parsers=" + ",".join(sorted(counts))
    reason = report["rules"][0]["not_convertible"][SECURITY]
    assert summary["failure_reasons"][reason] == 2


def test_discovery_summary_caps_reasons():
    rules = [{"convertible": [], "not_convertible": {"p": f"r{i:02d}"}} for i in range(25)]
    rules.append({"convertible": [], "not_convertible": {"p": "r24"}})
    summary = discovery_summary(rules)
    reasons = summary["failure_reasons"]
    assert len(reasons) == 20
    assert next(iter(reasons)) == "r24"
    assert summary["suggested_option"] is None


def test_discovery_correlation_note():
    base = _rule(rule_id="7f1b9c8e-1111-4a2b-8c3d-000000000003", title="Base")
    corr = """
title: Corr
id: 8f1b9c8e-1111-4a2b-8c3d-000000000004
status: test
correlation:
    type: event_count
    rules:
        - base
    group-by:
        - Computer
    timespan: 1h
    condition:
        gte: 3
"""
    report = DatabricksBackend().discover_parsers(_rules(base, corr))
    entry = next(e for e in report["rules"] if e["title"] == "Corr")
    assert entry["note"] == "correlation rules are not supported"
    assert "convertible" not in entry


def test_discovery_is_isolated():
    backend = DatabricksBackend()
    errors = backend.errors
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        backend.discover_parsers(_rules(_rule()))
    assert backend.errors is errors
    assert backend.errors == []
    assert backend.last_report is None
    assert backend._selected is None
    backend.parsers = [SYSMON]
    backend.table_name = "t"
    backend.catalog_name = "c"
    backend.schema_name = "s"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        out = backend.convert(_rules(_rule()), "lakewatch")
    assert "catalog_name" in json.dumps(out)
    assert backend.last_report is not None


def test_discovery_applies_overrides(tmp_path):
    path = tmp_path / "overrides.yml"
    path.write_text(yaml.safe_dump({RULE_ID: {SYSMON: {"summary": "Bad {nosuchcol}"}}}))
    report = DatabricksBackend(overrides=str(path)).discover_parsers(
        _rules(_rule("sel:\n    CommandLine|contains: x")))
    (entry,) = report["rules"]
    assert SYSMON not in entry["convertible"]
    assert "placeholder {nosuchcol} is not an output column" in entry["not_convertible"][SYSMON]


def test_discovery_user_profiles_included(tmp_path):
    text = (PROFILES_DIR / f"{SYSMON}.yml").read_text().replace(f"profile: {SYSMON}", "profile: my_sysmon", 1)
    (tmp_path / "my_sysmon.yml").write_text(text)
    report = DatabricksBackend(lakewatch_profiles_dir=str(tmp_path)).discover_parsers(
        _rules(_rule("sel:\n    CommandLine|contains: x")))
    assert "my_sysmon" in report["rules"][0]["convertible"]


# --- convert() runs discovery when -O parsers is missing -----------------------------------

DISCOVERY_WARNING = ("no rules were converted: -O parsers=... was not given, so parser discovery ran "
                     "instead (report on stdout)")


def test_convert_without_parsers_runs_discovery():
    backend = DatabricksBackend()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        out = backend.convert(_rules(_rule()), output_format="lakewatch")
    report = yaml.safe_load(out)
    assert "rules" in report and "summary" in report
    assert [str(w.message) for w in caught] == [DISCOVERY_WARNING]
    assert caught[0].category is UserWarning
    assert backend.last_report is None


def test_discovery_writes_no_files(tmp_path):
    backend = DatabricksBackend(output_dir=str(tmp_path))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        backend.convert(_rules(_rule()), "lakewatch")
    assert list(tmp_path.iterdir()) == []


def test_convert_rule_without_parsers_still_errors():
    import pytest
    from sigma.exceptions import SigmaConfigurationError
    rule = _rules(_rule()).rules[0]
    with pytest.raises(SigmaConfigurationError, match=r"-O parsers=\.\.\. is required for lakewatch parsed tables"):
        DatabricksBackend(catalog_name="c", schema_name="s").convert_rule(rule, "lakewatch")


def test_ocsf_mode_not_discovery():
    backend = DatabricksBackend(catalog_name="c", schema_name="s", table_name="t", ocsf=True)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        out = backend.convert(_rules(_rule()), output_format="lakewatch")
    assert not [w for w in caught if "discovery" in str(w.message)]
    assert "batch:" in out and "FROM t" in out
    assert "summary" not in yaml.safe_load(out).get("rules", {})


def test_discovery_after_conversion_resets_last_report():
    backend = DatabricksBackend()
    backend.parsers = [SYSMON]
    backend.table_name = "t"
    backend.catalog_name = "c"
    backend.schema_name = "s"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        backend.convert(_rules(_rule()), "lakewatch")
    assert backend.last_report is not None
    backend.parsers = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        backend.convert(_rules(_rule()), "lakewatch")
    assert backend.last_report is None
