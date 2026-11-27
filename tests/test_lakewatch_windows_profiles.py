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
    queries = backend.convert_rule(_rule(logsource, detection), "lakewatch")
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
    assert "lower(eventid) = '1'" in low
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
    assert "lower(eventid) = '12'" in sql.lower()


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
    assert "array_join(concat(coalesce(transform(" in sql
    assert "schema_of_variant(v) = 'STRING'" in sql


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
    assert "s-1-16-12288" in sql
    assert "lower(eventid) = '4688'" in sql.lower()


def test_security_4688_ids():
    sql = _sql(
        SEC_PROC,
        _cat("process_creation"),
        """    sel:
        ProcessId: 4120
        ParentProcessId: 255
    condition: sel""",
    )
    assert re.search(r"e\._Name = 'NewProcessId'\), 1\)\._VALUE\) = '0x1018'", sql)
    assert re.search(r"e\._Name = 'ProcessId'\), 1\)\._VALUE\) = '0xff'", sql)


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
    assert re.search(r"e\._Name = 'MandatoryLabel'\), 1\)\._VALUE\) = 's-1-16-16384'", sql)


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


def _convert_warns(parsers, logsource, detection, **options):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        queries = _convert(parsers, logsource, detection, table_name="t", **options)
    return queries, [str(w.message) for w in caught]


def _svc(name):
    return f"    product: windows\n    service: {name}"


def test_task10_profiles_found():
    for name in (
        "powershell_script", "powershell_other", "system", "application", "taskscheduler",
        "defender_detection", "wmi_activity", "ntlm_authentication", "applocker", "event_other", "event_logs",
    ):
        assert f"windows_{name}" in WINDOWS_PROFILES


def test_ps_script_4104():
    sql = _sql(
        "windows_powershell_script",
        "    product: windows\n    category: ps_script",
        "    sel:\n        ScriptBlockText|contains: 'Invoke-Mimikatz'\n    condition: sel",
    )
    assert "lower(eventid) = '4104'" in sql.lower()
    assert "e._Name = 'ScriptBlockText'" in sql


def test_ps_module_4103():
    sql = _sql(
        "windows_powershell_script",
        "    product: windows\n    category: ps_module",
        "    sel:\n        ContextInfo|contains: 'x'\n    condition: sel",
    )
    assert "'4103'" in sql.lower()
    assert "e._Name = 'ContextInfo'" in sql


def test_system_any_warns():
    queries, warns = _convert_warns(
        "windows_system",
        _svc("system"),
        "    sel:\n        Provider_Name: Service Control Manager\n        ServiceName: x\n    condition: sel",
    )
    sql = json.loads(queries[0])["sql"]
    assert "Provider" in sql
    assert "e._Name = 'ServiceName'" in sql
    assert any("not in a field list" in w for w in warns)


def test_event_other_channel_and_keyword():
    queries, warns = _convert_warns(
        "windows_event_other",
        _svc("msexchange-management"),
        "    keywords:\n        - 'Set-Mailbox'\n    condition: keywords",
    )
    sql = json.loads(queries[0])["sql"]
    assert "Channel" in sql and "msexchange management" in sql
    assert "to_json(raw_event)" in sql
    assert any("approximate" in w.lower() for w in warns)


def test_event_logs_header_only():
    reason = _failure(
        "windows_event_logs", _svc("system"), "    sel:\n        ServiceName: x\n    condition: sel"
    )
    assert reason.endswith(
        "windows_event_logs has the event header only; EventData fields need the custom windows_* parsers"
    )
    sql = _sql("windows_event_logs", _svc("system"), "    sel:\n        EventID: 7045\n    condition: sel")
    assert "7045" in sql
    assert "lower(Channel) = 'system'" in sql


def test_ps_classic_start():
    sql = _sql(
        "windows_event_other",
        _cat("ps_classic_start"),
        "    sel:\n        Data|contains: 'HostName=ConsoleHost'\n    condition: sel",
    )
    assert "windows powershell" in sql
    assert "'400'" in sql.lower()
    assert "array_join(transform(filter(coalesce(try_variant_get(EventData, '$', 'ARRAY<VARIANT>')" in sql


def test_ps_classic_strict():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with pytest.raises(SigmaTransformationError) as exc:
            _convert(
                "windows_event_other",
                _cat("ps_classic_start"),
                "    sel:\n        HostApplication: x\n    condition: sel",
                table_name="t",
            )
    assert "field HostApplication is not mapped by profile windows_event_other" in str(exc.value)
    assert not any("not in a field list" in str(w.message) for w in caught)


def test_dns_client_channel_registered_name():
    queries, _ = _convert_warns(
        "windows_event_other",
        _svc("dns-client"),
        "    sel:\n        QueryName: x\n    condition: sel",
    )
    sql = json.loads(queries[0])["sql"]
    assert "microsoft-windows-dns-client/operational" in sql
    assert "DNS Client Events" not in sql


# --- final review fixes --------------------------------------------------------------------


def _svc(service):
    return f"    product: windows\n    service: {service}"


def _warns(parsers, logsource, detection):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        queries = _convert(parsers, logsource, detection, table_name="t")
    return json.loads(queries[0])["sql"], [str(w.message) for w in caught]


def test_lenient_header_column_not_event_data():
    sql, warns = _warns("windows_application", _svc("application"), "    sel:\n        Level: 4\n    condition: sel")
    assert "Level = 4" in sql or "Level = '4'" in sql
    assert "e._Name = 'Level'" not in sql
    assert not [w for w in warns if "field list" in w and "Level" in w]


def test_lenient_channel_process_id_is_header():
    sql, _ = _warns("windows_system", _svc("system"), "    sel:\n        ProcessId: 0\n    condition: sel")
    assert "ProcessID" in sql
    assert "e._Name = 'ProcessId'" not in sql


@pytest.mark.parametrize("profile_id", [p for p in WINDOWS_PROFILES if p != "windows_event_logs"])
def test_header_mappings_never_shadow_event_data(profile_id):
    profile = load_profiles()[profile_id]
    lowered = {k.lower() for k in profile.fields}
    for names in [profile.event_data] + [b.event_data for b in profile.logsources]:
        if isinstance(names, (list, tuple)):
            assert not [n for n in names if n.lower() in lowered], profile_id
    assert "Level" in profile.fields and "Message" in profile.fields
    if profile_id.startswith(("windows_sysmon_", "windows_security_", "windows_powershell_")):
        assert "ProcessId" not in profile.fields


def test_unnamed_data_or_named_data_application():
    sql, _ = _warns("windows_application", _svc("application"),
                    "    sel:\n        Data|contains: 'x'\n    condition: sel")
    assert "schema_of_variant(v) = 'STRING'" in sql
    assert "e._Name = 'Data'" in sql
    assert " OR " in sql


def test_unnamed_data_or_named_data_system():
    sql, _ = _warns("windows_system", _svc("system"), "    sel:\n        Data|contains: 'x'\n    condition: sel")
    assert "schema_of_variant(v) = 'STRING'" in sql and "e._Name = 'Data'" in sql


def test_unnamed_data_msexchange():
    sql, _ = _warns("windows_event_other", _svc("msexchange-management"),
                    "    sel:\n        Data|contains: 'x'\n    condition: sel")
    assert "schema_of_variant(v) = 'STRING'" in sql and "e._Name = 'Data'" in sql
