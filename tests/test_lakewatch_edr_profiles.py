"""Tests for the built-in EDR Lakewatch profiles (CrowdStrike FDR, ...)."""

import json
import re
import warnings

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError, SigmaTransformationError

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.databricks import LakewatchConversionError
from sigma.backends.databricks.schema_catalog import SchemaCatalog
from sigma.pipelines.databricks.lakewatch.profile import load_profiles, validate_profile

CS = "crowdstrike_fdr_event"


def _rule(product, category, detection):
    return SigmaCollection.from_yaml(
        f"""
title: T
status: test
logsource:
    product: {product}
    category: {category}
detection:
{detection}
"""
    ).rules[0]


def _convert(parser, product, category, detection):
    backend = DatabricksBackend(parsers=parser, table_name="t", catalog_name="c", schema_name="s", warehouse_id="w")
    queries = backend.convert_rule(_rule(product, category, detection), "lakewatch")
    assert len(queries) == 1
    return json.loads(queries[0])["sql"]


def _sql(parser, product, category, detection):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return _convert(parser, product, category, detection)


def _names_selected(sql, names):
    """Check that every event name is matched against ``event_simpleName`` in ``sql``."""
    low = sql.lower()
    selected = {
        v.strip()
        for m in re.finditer(r"lower\(event_simplename\) (?:in \(([^)]*)\)|= ('[^']*'))", low)
        for v in (m.group(1) or m.group(2)).split(",")
    }
    return all(f"'{n.lower()}'" in selected for n in names)


# --- crowdstrike_fdr_event -----------------------------------------------------------------


def test_cs_profile_validates():
    profile = load_profiles()[CS]
    assert profile.version == 1
    assert profile.parser == CS
    validate_profile(profile, SchemaCatalog.load().get(CS))


def test_cs_process_creation():
    with pytest.warns(UserWarning, match="directory dropped"):
        sql = _convert(
            CS,
            "windows",
            "process_creation",
            """    sel:
        Image|endswith: '\\rundll32.exe'
        ParentImage: 'C:\\Windows\\explorer.exe'
    condition: sel""",
        )
    low = sql.lower()
    assert "endswith(lower(try_variant_get(event, '$.imagefilename', 'string')), '\\\\rundll32.exe')" in low
    assert "lower(try_variant_get(event, '$.parentbasefilename', 'string')) = 'explorer.exe'" in low
    assert "lower(event_platform) = 'win'" in low
    assert _names_selected(sql, ["ProcessRollup2", "SyntheticProcessRollup2"])
    # The VARIANT key keeps the dictionary's spelling.
    assert "'$.ImageFileName'" in sql
    assert "'$.ParentBaseFileName'" in sql


def test_cs_image_startswith_device_path():
    sql = _sql(
        CS,
        "windows",
        "process_creation",
        """    sel:
        Image|startswith: 'C:\\Users\\'
    condition: sel""",
    )
    # A '*' inside the value turns startswith into a regex: '.*' stands for the volume number.
    assert (
        "try_variant_get(event, '$.ImageFileName', 'string') rlike "
        "'(?isu)^\\\\\\\\Device\\\\\\\\HarddiskVolume.*\\\\\\\\Users\\\\\\\\.*$'"
    ) in sql
    # The drive form is kept too: live FDR data holds both.
    assert "startswith(lower(try_variant_get(event, '$.ImageFileName', 'string')), 'c:\\\\users\\\\')" in sql


def test_cs_network_initiated():
    sql = _sql(
        CS,
        "windows",
        "network_connection",
        """    sel:
        Initiated: 'true'
        DestinationPort: 4444
    condition: sel""",
    )
    assert "try_variant_get(event, '$.RemotePort', 'double') = 4444" in sql
    assert _names_selected(sql, ["NetworkConnectIP4", "NetworkConnectIP6"])
    # Outbound only: inbound accept events are never selected.
    assert "NetworkReceiveAccept" not in sql


def test_cs_network_inbound_fails():
    with pytest.raises(SigmaTransformationError, match="field Initiated: value 'false' is not one of"):
        _sql(
            CS,
            "windows",
            "network_connection",
            """    sel:
        Initiated: 'false'
        DestinationPort: 4444
    condition: sel""",
        )


def test_cs_registry_join():
    sql = _sql(
        CS,
        "windows",
        "registry_set",
        """    sel:
        TargetObject|contains: '\\CurrentVersion\\Run\\'
    condition: sel""",
    )
    assert (
        "concat_ws('\\\\', nullif(try_variant_get(event, '$.RegObjectName', 'string'), ''), "
        "nullif(try_variant_get(event, '$.RegValueName', 'string'), ''))"
    ) in sql
    assert _names_selected(sql, ["AsepValueUpdate", "RegGenericValueUpdate"])


def test_cs_unsupported_user():
    with pytest.raises(SigmaError, match=f"field User is not supported by profile {CS}.*nothing is left once it's dropped"):
        _sql(
            CS,
            "windows",
            "process_creation",
            """    sel:
        User: x
    condition: sel""",
        )


def test_cs_linux_platform():
    sql = _sql(
        CS,
        "linux",
        "process_creation",
        """    sel:
        CommandLine|contains: 'curl'
    condition: sel""",
    )
    assert "lower(event_platform) = 'lin'" in sql.lower()
    assert "try_variant_get(event, '$.CommandLine', 'string')" in sql


def test_cs_integrity_level_names_and_sids():
    for value in ("High", "S-1-16-12288"):
        sql = _sql(
            CS,
            "windows",
            "process_creation",
            f"""    sel:
        IntegrityLevel: '{value}'
    condition: sel""",
        )
        assert "try_variant_get(event, '$.IntegrityLevel', 'double') = 12288" in sql


def test_cs_windash_on_variant_field():
    sql = _sql(
        CS,
        "windows",
        "process_creation",
        """    sel:
        CommandLine|windash|contains: ' -enc '
    condition: sel""",
    )
    assert "try_variant_get(event, '$.CommandLine', 'string') rlike '(?iu).*(" in sql
    assert "\\\\ /enc\\\\ " in sql
    assert "ocsf_inner_field" not in sql


def test_cs_image_null():
    sql = _sql(
        CS,
        "windows",
        "process_creation",
        """    sel:
        CommandLine|contains: 'x'
    filter:
        Image: null
    condition: sel and not filter""",
    )
    assert "try_variant_get(event, '$.imagefilename', 'string') is null" in sql.lower()


def test_cs_image_contains_drive_fails():
    with pytest.raises(SigmaTransformationError, match="field Image: transform path_prefix: .*cannot be rewritten"):
        _sql(
            CS,
            "windows",
            "process_creation",
            """    sel:
        Image|contains: 'C:\\Users\\'
    condition: sel""",
        )


def test_cs_file_event_device_path():
    sql = _sql(
        CS,
        "windows",
        "file_event",
        """    sel:
        TargetFilename|startswith: 'C:\\Users\\'
    condition: sel""",
    )
    assert (
        "try_variant_get(event, '$.TargetFileName', 'string') rlike "
        "'(?isu)^\\\\\\\\Device\\\\\\\\HarddiskVolume.*\\\\\\\\Users\\\\\\\\.*$'"
    ) in sql
    assert _names_selected(
        sql, ["NewExecutableWritten", "NewScriptWritten", "GenericFileWritten", "PeFileWritten", "FileCreateInfo"]
    )


def test_cs_dns_query_name():
    sql = _sql(CS, "windows", "dns_query", "    sel:\n        QueryName|endswith: '.onion'\n    condition: sel")
    assert "endswith(lower(try_variant_get(event, '$.DomainName', 'string')), '.onion')" in sql
    assert _names_selected(sql, ["DnsRequest"])


def _sel(key, value):
    """Return a one-item detection ``sel: {key: value}``."""
    return f"    sel:\n        {key}: '{value}'\n    condition: sel"


def test_cs_hashes_sha256():
    digest = "ab" * 32
    sql = _sql(CS, "windows", "process_creation", _sel("Hashes|contains", f"SHA256={digest}"))
    assert f"lower(try_variant_get(event, '$.SHA256HashData', 'string')) = '{digest}'" in sql


@pytest.mark.parametrize("parser", [CS, "sentinelone_deep_visibility"])
@pytest.mark.parametrize(
    "key, value",
    [
        ("Details", "DWORD (0x00000001)"),
        ("Details|contains", "QWORD (0x00000000)"),
        ("Details|startswith", "Binary Data"),
        ("Details|contains", "0x00000001"),
        ("Details|endswith", "(0x00000001)"),
    ],
)
def test_registry_numeric_details_fail(parser, key, value):
    msg = f"field Details: transform reject: numeric/binary registry values are not stored as text in {parser}"
    with pytest.raises(SigmaTransformationError, match=msg):
        _sql(parser, "windows", "registry_set", _sel(key, value))


@pytest.mark.parametrize("parser", [CS, "sentinelone_deep_visibility"])
def test_registry_regex_details_inline_flag_fails(parser):
    detection = "    sel:\n        Details|re: '(?i)^DWORD \\(0x'\n    condition: sel"
    with pytest.raises(SigmaTransformationError, match="numeric/binary registry values"):
        _sql(parser, "windows", "registry_set", detection)


@pytest.mark.parametrize("parser,expr", [
    (CS, "try_variant_get(event, '$.RegStringValue', 'string')"),
    ("sentinelone_deep_visibility", "registry_value"),
])
def test_registry_string_details_ok(parser, expr):
    sql = _sql(parser, "windows", "registry_set", _sel("Details|contains", "powershell"))
    assert f"contains(lower({expr}), 'powershell')" in sql


def test_cs_registry_hive_inside_pattern_fails():
    msg = "field TargetObject: transform registry_path: hive inside the pattern"
    with pytest.raises(SigmaTransformationError, match=msg):
        _sql(CS, "windows", "registry_set", _sel("TargetObject|contains", "HKLM\\SOFTWARE\\x"))


def test_cs_registry_default_value_fails():
    with pytest.raises(SigmaTransformationError, match=r"the \(Default\) value name cannot be matched"):
        _sql(CS, "windows", "registry_set", _sel("TargetObject|endswith", "\\Run\\(Default)"))


def test_cs_parent_image_contains_fails():
    msg = "field ParentImage: transform basename: basename cannot express"
    with pytest.raises(SigmaTransformationError, match=msg):
        _sql(CS, "windows", "process_creation", _sel("ParentImage|contains", "tomcat"))


def test_cs_image_startswith_drive_and_device():
    sql = _sql(CS, "windows", "process_creation", _sel("Image|startswith", "C:\\Windows\\"))
    drive = "startswith(lower(try_variant_get(event, '$.ImageFileName', 'string')), 'c:\\\\windows\\\\')"
    device = (
        "try_variant_get(event, '$.ImageFileName', 'string') rlike "
        "'(?isu)^\\\\\\\\Device\\\\\\\\HarddiskVolume.*\\\\\\\\Windows\\\\\\\\.*$'"
    )
    assert f"{drive} OR {device}" in sql


def test_cs_parent_image_base_name_or_full_path():
    sql = _sql(CS, "windows", "process_creation", _sel("ParentImage|endswith", "\\explorer.exe"))
    col = "lower(try_variant_get(event, '$.ParentBaseFileName', 'string'))"
    assert f"{col} = 'explorer.exe' OR endswith({col}, '\\\\explorer.exe')" in sql


def test_cs_parent_image_plain_name():
    sql = _sql(CS, "windows", "process_creation", _sel("ParentImage", "cmd.exe"))
    col = "lower(try_variant_get(event, '$.ParentBaseFileName', 'string'))"
    assert f"({col} = 'cmd.exe' OR endswith({col}, '\\\\cmd.exe'))" in sql


def test_cs_parent_image_alternatives_under_not_and_list():
    sql = _sql(
        CS,
        "windows",
        "process_creation",
        """    sel:
        CommandLine|contains: 'x'
    filter:
        ParentImage|endswith:
            - '\\explorer.exe'
            - '\\cmd.exe'
    condition: sel and not filter""",
    )
    col = "lower(try_variant_get(event, '$.ParentBaseFileName', 'string'))"
    explorer = f"{col} = 'explorer.exe' OR endswith({col}, '\\\\explorer.exe')"
    cmd = f"{col} = 'cmd.exe' OR endswith({col}, '\\\\cmd.exe')"
    # Both alternatives of every list value sit inside the NOT; the backend flattens the nested ORs.
    assert f"NOT ({explorer} OR {cmd})" in sql


def test_cs_file_event_file_create_info():
    sql = _sql(CS, "windows", "file_event", _sel("TargetFilename|endswith", ".dll"))
    assert _names_selected(sql, ["FileCreateInfo"])


def test_cs_cased_transformed_field_fails():
    with pytest.raises(SigmaTransformationError, match="field Image: case-sensitive matching is not supported"):
        _sql(CS, "windows", "process_creation", _sel("Image|cased", "C:\\x.exe"))


# --- sentinelone_deep_visibility -----------------------------------------------------------

S1 = "sentinelone_deep_visibility"


def test_s1_profile_validates():
    profile = load_profiles()[S1]
    assert profile.version == 1
    assert profile.parser == S1
    validate_profile(profile, SchemaCatalog.load().get(S1))


def test_s1_process_creation():
    sql = _sql(
        S1,
        "windows",
        "process_creation",
        """    sel:
        Image|endswith: '\\rundll32.exe'
        ParentCommandLine|contains: 'winword'
    condition: sel""",
    )
    low = sql.lower()
    assert "endswith(lower(tgt_process_image_path), '\\\\rundll32.exe')" in low
    assert "contains(lower(src_process_cmdline), 'winword')" in low
    assert "lower(endpoint_os) = 'windows'" in low
    assert "lower(event_type) = 'process creation'" in low


def test_s1_unverified_blocks_removed():
    # The selectors of these categories are unverified, so the blocks are removed.
    for category in ("pipe_created", "pipe_creation", "registry_add", "registry_delete", "registry_event"):
        with pytest.raises(LakewatchConversionError, match="no selected Lakewatch parser profile matches"):
            _sql(
                S1,
                "windows",
                category,
                """    sel:
        TargetObject: x
    condition: sel""",
            )


def test_s1_users():
    sql = _sql(
        S1,
        "windows",
        "process_creation",
        """    sel:
        User: bob
        ParentUser: alice
    condition: sel""",
    )
    low = sql.lower()
    assert "lower(tgt_process_user) = 'bob'" in low
    assert "lower(src_process_user) = 'alice'" in low


def test_s1_registry_set_and_dns_event_types():
    sql = _sql(S1, "windows", "registry_set", "    sel:\n        TargetObject|contains: 'Run'\n    condition: sel")
    assert "lower(event_type) = 'registry value modified'" in sql.lower()
    sql = _sql(S1, "windows", "dns_query", "    sel:\n        QueryName: x.test\n    condition: sel")
    assert "lower(event_type) = 'dns resolved'" in sql.lower()


def test_s1_network_hostname_unsupported():
    for category in ("network_connection", "firewall"):
        msg = f"field DestinationHostname is not supported by profile {S1}.*nothing is left once it's dropped"
        with pytest.raises(SigmaError, match=msg):
            _sql(S1, "windows", category, "    sel:\n        DestinationHostname: x.test\n    condition: sel")


def test_s1_hashes():
    sql = _sql(
        S1,
        "windows",
        "process_creation",
        """    sel:
        Hashes|contains: 'SHA256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    condition: sel""",
    )
    assert f"lower(tgt_process_image_sha256) = '{'a' * 64}'" in sql
    sql = _sql(
        S1,
        "windows",
        "image_load",
        """    sel:
        Hashes|contains: 'MD5=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    condition: sel""",
    )
    assert "lower(module_md5) = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'" in sql


def test_s1_unsupported_current_directory():
    with pytest.raises(SigmaError, match=f"field CurrentDirectory is not supported by profile {S1}.*nothing is left once it's dropped"):
        _sql(
            S1,
            "windows",
            "process_creation",
            """    sel:
        CurrentDirectory|contains: 'temp'
    condition: sel""",
        )


def test_s1_network_outgoing_only():
    sql = _sql(
        S1,
        "windows",
        "network_connection",
        """    sel:
        Initiated: 'true'
        DestinationPort: 4444
    condition: sel""",
    )
    low = sql.lower()
    assert "dst_port_number = 4444" in low
    assert "lower(event_network_direction) = 'outgoing'" in low
    with pytest.raises(SigmaTransformationError, match="field Initiated: value 'false' is not one of"):
        _sql(
            S1,
            "windows",
            "network_connection",
            """    sel:
        Initiated: 'false'
    condition: sel""",
        )


def test_s1_file_delete_event_type():
    sql = _sql(
        S1,
        "windows",
        "file_delete",
        """    sel:
        TargetFilename|endswith: '.log'
    condition: sel""",
    )
    assert "lower(event_type) = 'file deletion'" in sql.lower()


# --- carbonblack_endpoint_event ------------------------------------------------------------

CB = "carbonblack_endpoint_event"


def test_cb_profile_validates():
    profile = load_profiles()[CB]
    assert profile.version == 1
    assert profile.parser == CB
    validate_profile(profile, SchemaCatalog.load().get(CB))


def test_cb_process_creation_child_vs_parent():
    sql = _sql(
        CB,
        "windows",
        "process_creation",
        """    sel:
        Image|endswith: '\\cmd.exe'
        ParentImage|endswith: '\\winword.exe'
        CommandLine|contains: 'whoami'
        ParentCommandLine|contains: 'doc'
    condition: sel""",
    )
    # Image is the child process; the parent is the actor process.
    assert "endswith(lower(childproc_name), '\\\\cmd.exe')" in sql
    assert "endswith(lower(process_path), '\\\\winword.exe')" in sql
    assert "contains(lower(target_cmdline), 'whoami')" in sql
    assert "contains(lower(process_cmdline), 'doc')" in sql
    assert "parent_path" not in sql
    assert "lower(type) = 'endpoint.event.procstart'" in sql
    assert "lower(device_os) = 'windows'" in sql


def test_cb_hashes_array():
    for algo, digest in (("MD5", "A" * 32), ("SHA256", "b" * 64)):
        sql = _sql(CB, "windows", "process_creation", _sel("Hashes|contains", f"{algo}={digest}"))
        assert f"exists(childproc_hash, x0 -> lower(x0) = '{digest.lower()}')" in sql


def test_cb_initiated_bool_column():
    sql = _sql(
        CB,
        "windows",
        "network_connection",
        """    sel:
        Initiated: 'true'
        DestinationPort: 4444
    condition: sel""",
    )
    assert "netconn_inbound = false" in sql
    assert "remote_port = 4444" in sql


def test_cb_network_inbound_fails():
    with pytest.raises(SigmaTransformationError, match="field Initiated: value 'false' is not one of"):
        _sql(
            CB,
            "windows",
            "network_connection",
            """    sel:
        Initiated: 'false'
    condition: sel""",
        )


def test_cb_protocol_map_fail():
    with pytest.raises(SigmaTransformationError, match="not in the map"):
        _sql(
            CB,
            "windows",
            "network_connection",
            """    sel:
        Protocol: icmp
    condition: sel""",
        )


def test_cb_protocol_map_ok():
    sql = _sql(
        CB,
        "windows",
        "network_connection",
        """    sel:
        Protocol: udp
    condition: sel""",
    )
    assert "lower(netconn_protocol) = 'proto_udp'" in sql
    sql = _sql(CB, "windows", "network_connection", "    sel:\n        Protocol: TCP\n    condition: sel")
    assert "lower(netconn_protocol) = 'proto_tcp'" in sql


def test_cb_file_event_and_products():
    sql = _sql(
        CB,
        "linux",
        "file_event",
        """    sel:
        TargetFilename|endswith: '.sh'
    condition: sel""",
    )
    low = sql.lower()
    assert "filemod_name" in low
    assert "endpoint.event.filemod" in low
    assert "'linux'" in low
    sql = _sql(
        CB,
        "macos",
        "file_event",
        """    sel:
        TargetFilename|endswith: '.sh'
    condition: sel""",
    )
    assert "'mac'" in sql.lower()


def test_cb_unsupported_original_file_name():
    with pytest.raises(SigmaError, match=f"field OriginalFileName is not supported by profile {CB}.*nothing is left once it's dropped"):
        _sql(
            CB,
            "windows",
            "process_creation",
            """    sel:
        OriginalFileName: 'cmd.exe'
    condition: sel""",
        )
