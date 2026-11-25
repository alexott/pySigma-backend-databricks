"""Tests for the built-in EDR Lakewatch profiles (CrowdStrike FDR, ...)."""

import json
import warnings

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError

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
    backend = DatabricksBackend(parsers=parser, table_name="t", catalog_name="c", schema_name="s")
    queries = backend.convert_rule(_rule(product, category, detection), "lakewatch_v2")
    assert len(queries) == 1
    return json.loads(queries[0])["sql"]


def _sql(parser, product, category, detection):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return _convert(parser, product, category, detection)


def _names_selected(sql, names):
    """Check that every event name is matched against ``event_simpleName`` in ``sql``."""
    low = sql.lower()
    return all(f"lower(event_simplename) = lower('{n.lower()}')" in low for n in names)


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
    assert "endswith(lower(try_variant_get(event, '$.imagefilename', 'string')), lower('\\\\rundll32.exe'))" in low
    assert "lower(try_variant_get(event, '$.parentbasefilename', 'string')) = lower('explorer.exe')" in low
    assert "lower(event_platform) = lower('win')" in low
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
    assert "C:" not in sql


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
    with pytest.raises(SigmaTransformationError, match=f"field User is not supported by profile {CS}"):
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
    assert "lower(event_platform) = lower('lin')" in sql.lower()
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
    assert "endswith(lower(tgt_process_image_path), lower('\\\\rundll32.exe'))" in low
    assert "contains(lower(src_process_cmdline), lower('winword'))" in low
    assert "lower(endpoint_os) = lower('windows')" in low
    assert "lower(event_type) = lower('process creation')" in low


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
    assert "lower(tgt_process_user) = lower('bob')" in low
    assert "lower(src_process_user) = lower('alice')" in low


def test_s1_registry_set_and_dns_event_types():
    sql = _sql(S1, "windows", "registry_set", "    sel:\n        TargetObject|contains: 'Run'\n    condition: sel")
    assert "lower(event_type) = lower('registry value modified')" in sql.lower()
    sql = _sql(S1, "windows", "dns_query", "    sel:\n        QueryName: x.test\n    condition: sel")
    assert "lower(event_type) = lower('dns resolved')" in sql.lower()


def test_s1_network_hostname_unsupported():
    for category in ("network_connection", "firewall"):
        msg = f"field DestinationHostname is not supported by profile {S1}"
        with pytest.raises(SigmaTransformationError, match=msg):
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
    assert f"lower(tgt_process_image_sha256) = lower('{'A' * 64}')" in sql
    sql = _sql(
        S1,
        "windows",
        "image_load",
        """    sel:
        Hashes|contains: 'MD5=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    condition: sel""",
    )
    assert "lower(module_md5) = lower('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')" in sql


def test_s1_unsupported_current_directory():
    with pytest.raises(SigmaTransformationError, match=f"field CurrentDirectory is not supported by profile {S1}"):
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
    assert "lower(event_network_direction) = lower('outgoing')" in low
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
    assert "lower(event_type) = lower('file deletion')" in sql.lower()


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
    low = sql.lower()
    # Image is the child process; the parent is the actor process.
    assert "childproc_name" in low
    assert "process_path" in low
    assert "target_cmdline" in low
    assert "process_cmdline" in low
    assert "parent_path" not in low
    assert "type = 'endpoint.event.procstart'" in low or "lower(type) = lower('endpoint.event.procstart')" in low
    assert "device_os" in low


def test_cb_hashes_array():
    sql = _sql(
        CB,
        "windows",
        "process_creation",
        """    sel:
        Hashes|contains: 'MD5=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    condition: sel""",
    )
    assert "exists(childproc_hash, x0 ->" in sql


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
    assert "PROTO_UDP" in sql


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
    with pytest.raises(SigmaTransformationError, match=f"field OriginalFileName is not supported by profile {CB}"):
        _sql(
            CB,
            "windows",
            "process_creation",
            """    sel:
        OriginalFileName: 'cmd.exe'
    condition: sel""",
        )
