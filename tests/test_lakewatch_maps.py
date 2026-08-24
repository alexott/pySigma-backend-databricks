from sigma.rule import SigmaRule
from sigma.backends.databricks.lakewatch_maps import (
    OCSF_CLASS_UID_TO_TABLE, GOLD_TABLES, SEVERITY_MAP, FIDELITY_MAP, resolve_ocsf_table,
    MITRE_TECHNIQUES, build_mitre_mapping,
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
    assert FIDELITY_MAP["experimental"] == "Investigative"


def test_resolve_from_type_uid():
    rule = _rule("            sel:\n                type_uid: 100701\n                foo: bar")
    assert resolve_ocsf_table(rule) == "process_activity"


def test_resolve_from_class_uid():
    rule = _rule("            sel:\n                class_uid: 4003\n                foo: bar")
    assert resolve_ocsf_table(rule) == "dns_activity"


def test_resolve_from_class_name_keeps_activity_suffix():
    rule = _rule("            sel:\n                class_name: 'API Activity'")
    assert resolve_ocsf_table(rule) == "api_activity"


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
        "techniqueId": "T1059",
        "subTechnique": "PowerShell",
        "subTechniqueId": "T1059.001",
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
