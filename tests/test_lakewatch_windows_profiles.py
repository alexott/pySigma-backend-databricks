"""Tests for the built-in Windows Lakewatch profiles (custom Windows parsers)."""

import json
import warnings
from pathlib import Path

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.schema_catalog import SchemaCatalog
from sigma.pipelines.databricks.lakewatch.profile import load_profiles, validate_profile

PROFILES_DIR = Path(__file__).parent.parent / "sigma" / "pipelines" / "databricks" / "lakewatch" / "profiles"
WINDOWS_PROFILES = sorted(p.stem for p in PROFILES_DIR.glob("windows_*.yml"))
SYSMON_PROFILES = sorted(p for p in WINDOWS_PROFILES if p.startswith("windows_sysmon_"))


def _rule(logsource, detection):
    return SigmaCollection.from_yaml(
        f"""
title: T
status: test
logsource:
{logsource}
detection:
{detection}
"""
    ).rules[0]


def _convert(parsers, logsource, detection, **options):
    backend = DatabricksBackend(parsers=parsers, catalog_name="c", schema_name="s", **options)
    queries = backend.convert_rule(_rule(logsource, detection), "lakewatch_v2")
    return queries


def _sql(parsers, logsource, detection):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        queries = _convert(parsers, logsource, detection, table_name="t")
    assert len(queries) == 1
    return json.loads(queries[0])["sql"]


def _cat(category):
    return f"    product: windows\n    category: {category}"


PROC = "windows_sysmon_process"


def test_windows_profiles_found():
    assert len(SYSMON_PROFILES) == 6


@pytest.mark.parametrize("profile_id", WINDOWS_PROFILES)
def test_windows_profiles_validate(profile_id):
    profile = load_profiles()[profile_id]
    assert profile.version == 1
    assert profile.parser == profile_id
    validate_profile(profile, SchemaCatalog.load().get(profile_id))


def test_sysmon_process_creation():
    sql = _sql(
        PROC,
        _cat("process_creation"),
        """    sel:
        Image|endswith: '\\rundll32.exe'
        CommandLine|contains: 'x'
    condition: sel""",
    )
    low = sql.lower()
    assert "lower(eventid) = lower('1')" in low
    assert "e._name = 'image'" in low
    assert "e._name = 'commandline'" in low


def test_sysmon_processid_is_eventdata():
    sql = _sql(PROC, _cat("process_creation"), "    sel:\n        ProcessId: 4\n    condition: sel")
    assert "e._Name = 'ProcessId'" in sql
    assert "ProcessID" not in sql.replace("e._Name = 'ProcessId'", "")


def test_sysmon_unknown_field_fails():
    with pytest.raises(SigmaTransformationError, match="field Foo is not mapped by profile windows_sysmon_process"):
        _sql(PROC, _cat("process_creation"), "    sel:\n        Foo: x\n    condition: sel")


def test_sysmon_registry_add_eventtype():
    sql = _sql(
        "windows_sysmon_registry",
        _cat("registry_add"),
        "    sel:\n        TargetObject|contains: 'Run'\n    condition: sel",
    )
    assert "e._Name = 'EventType'" in sql
    assert "createkey" in sql.lower()
    assert "lower(eventid) = lower('12')" in sql.lower()


def test_sysmon_service_routes():
    parsers = ",".join(SYSMON_PROFILES)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        queries = _convert(
            parsers,
            "    product: windows\n    service: sysmon",
            "    sel:\n        EventID: 16\n    condition: sel",
            table_map=",".join(f"{p}:t_{p}" for p in SYSMON_PROFILES),
        )
    assert len(queries) == 1
    assert "windows_sysmon_other" in queries[0]
    for other in SYSMON_PROFILES:
        if other != "windows_sysmon_other":
            assert other not in queries[0]


def test_sysmon_keyword_entries():
    sql = _sql(PROC, _cat("process_creation"), "    keywords:\n        - 'mimikatz'\n    condition: keywords")
    assert "array_join(transform(" in sql
