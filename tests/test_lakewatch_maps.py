"""Tests for the Lakewatch OCSF table and MITRE mapping utilities."""

from sigma.rule import SigmaRule

from sigma.backends.databricks.lakewatch_maps import (
    GOLD_TABLES,
    MITRE_TECHNIQUE_TACTICS,
    MITRE_TECHNIQUES,
    OCSF_CLASS_UID_TO_TABLE,
    SEVERITY_MAP,
    build_mitre_mapping,
    resolve_ocsf_table,
)


def _rule(detection: str) -> SigmaRule:
    return SigmaRule.from_yaml(f"""
        title: T
        logsource:
            category: test
        detection:
{detection}
            condition: sel
    """)


def test_maps_are_grounded():
    assert OCSF_CLASS_UID_TO_TABLE[1007] == "process_activity"
    assert OCSF_CLASS_UID_TO_TABLE[4003] == "dns_activity"
    assert OCSF_CLASS_UID_TO_TABLE[6003] == "api_activity"
    assert "authentication" in GOLD_TABLES
    assert SEVERITY_MAP["high"] == "High"


def test_resolve_from_type_uid():
    rule = _rule("            sel:\n                type_uid: 100701\n                foo: bar")
    assert resolve_ocsf_table(rule) == "process_activity"


def test_resolve_from_class_uid():
    rule = _rule("            sel:\n                class_uid: 4003\n                foo: bar")
    assert resolve_ocsf_table(rule) == "dns_activity"


def test_resolve_from_class_name_keeps_activity_suffix():
    rule = _rule("            sel:\n                class_name: 'API Activity'")
    assert resolve_ocsf_table(rule) == "api_activity"


def test_application_class_uids_follow_ocsf():
    # OCSF: 6005 Datastore Activity, 6006 File Hosting Activity (6004 is Web Resource Access).
    assert OCSF_CLASS_UID_TO_TABLE[6005] == "datastore_activity"
    assert OCSF_CLASS_UID_TO_TABLE[6006] == "file_hosting_activity"
    assert 6004 not in OCSF_CLASS_UID_TO_TABLE
    rule = _rule("            sel:\n                type_uid: 600601")
    assert resolve_ocsf_table(rule) == "file_hosting_activity"


def test_resolve_unmappable_returns_none():
    rule = _rule("            sel:\n                type_uid: 600200")  # class 6002, no gold table
    assert resolve_ocsf_table(rule) is None


def test_resolve_no_ocsf_fields_returns_none():
    rule = _rule("            sel:\n                foo: bar")
    assert resolve_ocsf_table(rule) is None


def test_mitre_table_has_known_names():
    assert MITRE_TECHNIQUES["T1059"] == "Command and Scripting Interpreter"
    assert MITRE_TECHNIQUES["T1059.001"] == "PowerShell"


def test_build_mitre_mapping_from_tags():
    rule = SigmaRule.from_yaml("""
        title: T
        logsource: {category: test}
        detection:
            sel: {foo: bar}
            condition: sel
        tags:
            - attack.execution
            - attack.t1059.001
    """)
    entries = build_mitre_mapping(rule)
    assert entries == [{
        "taxonomy": "Enterprise",
        "tactic": "Execution",
        "technique": "Command and Scripting Interpreter",
        "technique_id": "T1059",
        "sub_technique": "PowerShell",
        "sub_technique_id": "T1059.001",
    }]


def test_build_mitre_mapping_no_tags_is_empty():
    rule = SigmaRule.from_yaml("""
        title: T
        logsource: {category: test}
        detection:
            sel: {foo: bar}
            condition: sel
    """)
    assert build_mitre_mapping(rule) == []


def _tagged_rule(tags: str) -> SigmaRule:
    return SigmaRule.from_yaml(f"""
        title: T
        logsource: {{category: test}}
        detection:
            sel: {{foo: bar}}
            condition: sel
        tags:
{tags}
    """)


def test_build_mitre_mapping_technique_only_tag():
    # A bare technique tag with no sub-technique leaves the sub fields out.
    rule = _tagged_rule("            - attack.execution\n            - attack.t1059")
    assert build_mitre_mapping(rule) == [{
        "taxonomy": "Enterprise",
        "tactic": "Execution",
        "technique": "Command and Scripting Interpreter",
        "technique_id": "T1059",
    }]


def test_build_mitre_mapping_multiple_subtechniques_collapse():
    # Documented behaviour: siblings of one parent collapse, last tag wins.
    rule = _tagged_rule(
        "            - attack.execution\n"
        "            - attack.t1059.001\n"
        "            - attack.t1059.003"
    )
    entries = build_mitre_mapping(rule)
    assert len(entries) == 1
    assert entries[0]["technique_id"] == "T1059"
    assert entries[0]["sub_technique_id"] == "T1059.003"


def test_mitre_table_has_tactics():
    assert MITRE_TECHNIQUE_TACTICS["T1059"] == ["execution"]
    assert "command-and-control" in MITRE_TECHNIQUE_TACTICS["T1071.004"]


def test_build_mitre_mapping_multiple_tactics_picks_tactic_of_technique():
    # Two tactic tags: each technique gets the tagged tactic that ATT&CK lists for it.
    rule = _tagged_rule(
        "            - attack.command-and-control\n"
        "            - attack.t1071.004\n"
        "            - attack.execution\n"
        "            - attack.t1059.003"
    )
    tactics = {e["technique_id"]: e["tactic"] for e in build_mitre_mapping(rule)}
    assert tactics == {"T1059": "Execution", "T1071": "Command-And-Control"}


def test_build_mitre_mapping_tactic_from_attack_when_not_tagged():
    # No matching tactic tag: the first ATT&CK tactic of the technique is used.
    rule = _tagged_rule("            - attack.persistence\n            - attack.t1059")
    assert build_mitre_mapping(rule)[0]["tactic"] == "Execution"
    rule = _tagged_rule("            - attack.t1059")
    assert build_mitre_mapping(rule)[0]["tactic"] == "Execution"


def test_build_mitre_mapping_ignores_group_and_software_tags():
    rule = _tagged_rule(
        "            - attack.g0016\n            - attack.s0002\n            - attack.t9999"
    )
    assert build_mitre_mapping(rule) == []          # unknown technique, no tactic: entry dropped


def test_build_mitre_mapping_unknown_technique_uses_single_tactic():
    rule = _tagged_rule("            - attack.execution\n            - attack.t9999")
    assert build_mitre_mapping(rule)[0]["tactic"] == "Execution"
    rule = _tagged_rule("            - attack.command_and_control\n            - attack.t9999")
    assert build_mitre_mapping(rule)[0]["tactic"] == "Command-And-Control"


def test_resolve_non_numeric_uid_returns_none():
    # A non-numeric class_uid must not raise; it resolves to None.
    rule = _rule("            sel:\n                class_uid: notanumber")
    assert resolve_ocsf_table(rule) is None


def test_resolve_class_uid_falls_back_to_type_uid():
    # An unmappable class_uid falls through to a usable type_uid.
    rule = _rule("            sel:\n                class_uid: 9999\n                type_uid: 100701")
    assert resolve_ocsf_table(rule) == "process_activity"


def test_resolve_class_uid_falls_back_to_class_name():
    # An unmappable class_uid falls through to a usable class_name.
    rule = _rule("            sel:\n                class_uid: 9999\n                class_name: 'DNS Activity'")
    assert resolve_ocsf_table(rule) == "dns_activity"


def test_build_mitre_mapping_unknown_technique_leaves_technique_out():
    rule = _tagged_rule("            - attack.execution\n            - attack.t9999")
    assert build_mitre_mapping(rule) == [{
        "taxonomy": "Enterprise",
        "tactic": "Execution",
        "technique_id": "T9999",
    }]


def test_build_mitre_mapping_drops_entry_without_tactic():
    # Unknown technique with no tactic tag, or with two tactic tags: no tactic can be picked.
    assert build_mitre_mapping(_tagged_rule("            - attack.t9999")) == []
    two = _tagged_rule(
        "            - attack.execution\n            - attack.persistence\n            - attack.t9999"
    )
    assert build_mitre_mapping(two) == []
