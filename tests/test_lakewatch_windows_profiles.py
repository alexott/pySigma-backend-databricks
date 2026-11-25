"""Tests for the built-in Windows Lakewatch profiles (custom Windows parsers)."""

import json
import re
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


SECURITY_PROFILES = sorted(p for p in WINDOWS_PROFILES if p.startswith("windows_security_"))
SEC_PROC = "windows_security_process"
SEC_ALL = ",".join(f"windows_security_{n}" for n in (
    "process", "authentication", "account_change", "group_management", "network", "user_access", "other"
))
SEC_TABLES = ",".join(f"windows_security_{n}:t_{n}" for n in (
    "process", "authentication", "account_change", "group_management", "network", "user_access", "other"
))


def _failure(parsers, logsource, detection):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with pytest.raises(SigmaTransformationError) as exc:
            _convert(parsers, logsource, detection, table_name="t")
    return str(exc.value)


def test_security_profiles_found():
    assert len(SECURITY_PROFILES) == 7


def test_security_4688_mapping():
    sql = _sql(
        SEC_PROC,
        _cat("process_creation"),
        """    sel:
        Image|endswith: '\\cmd.exe'
        ParentImage|endswith: '\\winword.exe'
        IntegrityLevel: High
    condition: sel""",
    )
    assert "e._Name = 'NewProcessName'" in sql
    assert "e._Name = 'ParentProcessName'" in sql
    assert "S-1-16-12288" in sql
    assert "lower(eventid) = lower('4688')" in sql.lower()


def test_security_4688_ids():
    sql = _sql(
        SEC_PROC,
        _cat("process_creation"),
        """    sel:
        ProcessId: 4120
        ParentProcessId: 255
    condition: sel""",
    )
    assert re.search(r"e\._Name = 'NewProcessId'\), 1\)\._VALUE\) = lower\('0x1018'\)", sql)
    assert re.search(r"e\._Name = 'ProcessId'\), 1\)\._VALUE\) = lower\('0xff'\)", sql)


def test_security_4688_user():
    sql = _sql(
        SEC_PROC,
        _cat("process_creation"),
        "    sel:\n        User|endswith: '\\alice'\n    condition: sel",
    )
    assert "CASE WHEN" in sql
    assert "e._Name = 'TargetUserName'" in sql
    assert "ELSE" in sql
    assert "e._Name = 'SubjectUserName'" in sql
    assert "e._Name = 'SubjectDomainName'" in sql
    reason = _failure(
        SEC_PROC, _cat("process_creation"), "    sel:\n        User|contains: 'AUTHORI'\n    condition: sel"
    )
    assert "LocalSystem" in reason


def test_security_4688_unsupported():
    reason = _failure(
        SEC_PROC, _cat("process_creation"), "    sel:\n        OriginalFileName: x\n    condition: sel"
    )
    assert "field OriginalFileName is not supported by profile windows_security_process" in reason


def _security_queries(eventid_detection, **options):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        queries = _convert(
            SEC_ALL,
            "    product: windows\n    service: security",
            eventid_detection,
            table_map=SEC_TABLES,
            **options,
        )
    return queries, [str(w.message) for w in caught]


def test_security_service_route():
    queries, _ = _security_queries("    sel:\n        EventID: 4625\n        TargetUserName: x\n    condition: sel")
    assert len(queries) == 1
    assert "t_authentication" in queries[0]
    assert "__windows_security_authentication" in queries[0]
    for n in ("process", "account_change", "group_management", "network", "user_access", "other"):
        assert f"__windows_security_{n}" not in queries[0]


def test_security_other_route():
    queries, warns = _security_queries(
        "    sel:\n        EventID: 1102\n        SubjectUserName: x\n    condition: sel"
    )
    assert len(queries) == 1
    assert "__windows_security_other" in queries[0]
    assert "__windows_security_process" not in queries[0]
    assert any("not in a field list" in w for w in warns)


def test_process_creation_fans_out():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        queries = _convert(
            "windows_sysmon_process,windows_security_process",
            _cat("process_creation"),
            "    sel:\n        Image|endswith: '\\cmd.exe'\n    condition: sel",
            table_map="windows_sysmon_process:t_sysmon,windows_security_process:t_sec",
        )
    assert len(queries) == 2


def test_security_4688_integrity_sid_literal():
    sql = _sql(
        SEC_PROC,
        _cat("process_creation"),
        "    sel:\n        IntegrityLevel: S-1-16-16384\n    condition: sel",
    )
    assert re.search(r"e\._Name = 'MandatoryLabel'\), 1\)\._VALUE\) = lower\('S-1-16-16384'\)", sql)


def test_security_service_route_multi_eventid():
    queries, _ = _security_queries("    sel:\n        EventID: [4624, 4688]\n    condition: sel")
    assert len(queries) == 2
    joined = "\n".join(queries)
    assert "__windows_security_authentication" in joined
    assert "__windows_security_process" in joined
    assert sum("__windows_security_authentication" in q for q in queries) == 1
    assert sum("__windows_security_process" in q for q in queries) == 1
    for n in ("account_change", "group_management", "network", "user_access", "other"):
        assert f"__windows_security_{n}" not in joined
