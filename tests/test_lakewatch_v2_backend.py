"""Tests for the Lakewatch v2 output format of the Databricks backend."""

import json

import pytest
import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaConversionError

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.lakewatch_maps import (
    to_v2_fidelity,
    to_v2_mitre,
    to_v2_references,
    to_v2_rule_name,
)


def _backend(**kwargs):
    """Backend with the required v2 catalog/schema options set."""
    kwargs.setdefault("catalog_name", "cat")
    kwargs.setdefault("schema_name", "sch")
    return DatabricksBackend(**kwargs)


def _doc(backend, rule_yaml):
    """Convert one rule and return the parsed Lakewatch v2 document."""
    rule = SigmaCollection.from_yaml(rule_yaml).rules[0]
    return json.loads(backend.convert_rule(rule, "lakewatch_v2")[0])["doc"]


BASE = """
title: Suspicious PowerShell
status: experimental
level: high
description: Detects suspicious powershell
references:
    - https://example.com/one
    - https://example.com/two
logsource: {category: process_creation}
detection:
    sel:
        type_uid: 100701
        process.name|endswith: '\\\\powershell.exe'
    condition: sel
tags:
    - attack.execution
    - attack.t1059.001
"""


def test_v2_document_shape():
    be = _backend(warehouse_id="wh123")
    doc = _doc(be, BASE)
    assert list(doc) == [
        "catalog_name", "schema_name", "rule_name", "description", "severity", "fidelity",
        "category", "objective", "references", "schedule", "batch", "output", "mitre",
    ]
    assert doc["catalog_name"] == "cat"
    assert doc["schema_name"] == "sch"
    assert doc["rule_name"] == "suspicious_powershell"
    assert doc["description"] == "Detects suspicious powershell"
    assert doc["severity"] == "High"
    assert doc["fidelity"] == "FIDELITY_INVESTIGATIVE"
    assert doc["category"] == "Static Signature"
    assert doc["references"] == ["https://example.com/one", "https://example.com/two"]
    assert doc["schedule"] == {"at_least_every": "24h", "compute_group": "automatic", "enabled": True}
    assert doc["batch"]["warehouse_id"] == "wh123"
    assert doc["batch"]["sql"]["default_catalog_name"] == "cat"
    assert doc["batch"]["sql"]["default_schema_name"] == "sch"
    assert doc["output"] == {"summary": "Suspicious PowerShell", "default_context": True}
    assert doc["mitre"] == [{
        "taxonomy": "Enterprise",
        "tactic": "Execution",
        "technique": "Command and Scripting Interpreter",
        "technique_id": "T1059",
        "sub_technique": "PowerShell",
        "sub_technique_id": "T1059.001",
    }]


def test_v2_sql_uses_in_timerange():
    sql = _doc(_backend(), BASE)["batch"]["sql"]["query"]
    assert sql.startswith("SELECT *\nFROM process_activity\nWHERE IN_TIMERANGE(time)\n  AND (")
    assert "INTERVAL" not in sql
    assert "endswith(lower(process.name)" in sql


def test_v2_optional_fields_omitted_by_default():
    doc = _doc(_backend(), BASE)
    assert "warehouse_id" not in doc["batch"]
    assert "timerange" not in doc
    assert "continuous" not in doc["schedule"]
    # v1-only fields are not emitted
    for key in ("apiVersion", "kind", "metadata", "spec", "observables"):
        assert key not in doc


def test_v2_options():
    be = _backend(table_name="main.sec.auth", schedule="12h", compute_group="dedicated",
                  default_fidelity="High", default_category="Behavioral",
                  extend_lookback="1h")
    doc = _doc(be, BASE)
    assert "FROM main.sec.auth\n" in doc["batch"]["sql"]["query"]
    assert doc["schedule"]["at_least_every"] == "12h"
    assert doc["schedule"]["compute_group"] == "dedicated"
    assert doc["fidelity"] == "FIDELITY_HIGH"
    assert doc["category"] == "Behavioral"
    assert doc["timerange"] == {"extend_lookback": "1h"}


def test_v2_mitre_drops_empty_sub_technique():
    doc = _doc(_backend(), BASE.replace("attack.t1059.001", "attack.t1059"))
    assert doc["mitre"][0]["technique_id"] == "T1059"
    assert "sub_technique" not in doc["mitre"][0]
    assert "sub_technique_id" not in doc["mitre"][0]


def test_v2_error_when_no_table_resolvable():
    rule_yaml = """
        title: No OCSF
        logsource: {category: test}
        detection:
            sel: {foo: bar}
            condition: sel
    """
    with pytest.raises(SigmaConversionError):
        _doc(_backend(), rule_yaml)


@pytest.mark.parametrize("options", [
    {},
    {"catalog_name": "cat"},
    {"schema_name": "sch"},
    {"catalog_name": "", "schema_name": "sch"},
    {"catalog_name": "cat", "schema_name": "  "},
])
def test_v2_error_without_catalog_or_schema(options):
    with pytest.raises(SigmaConversionError, match="catalog_name and schema_name"):
        _doc(DatabricksBackend(**options), BASE)


def test_v2_catalog_and_schema_stripped():
    doc = _doc(_backend(catalog_name=" cat ", schema_name=" sch "), BASE)
    assert (doc["catalog_name"], doc["schema_name"]) == ("cat", "sch")


TWO_RULES = """
title: Rule One
status: experimental
level: high
logsource: {category: test}
detection:
    sel: {class_uid: 4003, foo: bar}
    condition: sel
---
title: Rule One
status: stable
level: medium
logsource: {category: test}
detection:
    sel: {class_uid: 3002, baz: qux}
    condition: sel
---
title: Rule One 2
status: deprecated
level: medium
logsource: {category: test}
detection:
    sel: {class_uid: 3002, baz: qux}
    condition: sel
"""


def test_v2_multi_document_output_dedups_rule_names():
    out = _backend().convert(SigmaCollection.from_yaml(TWO_RULES), output_format="lakewatch_v2")
    docs = list(yaml.safe_load_all(out))
    assert len(docs) == 2                                  # deprecated rule skipped
    assert [d["rule_name"] for d in docs] == ["rule_one", "rule_one_2"]
    assert "FROM dns_activity" in docs[0]["batch"]["sql"]["query"]
    assert "FROM authentication" in docs[1]["batch"]["sql"]["query"]
    assert docs[1]["fidelity"] == "FIDELITY_HIGH"
    assert "query: |-" in out


def test_v2_dedup_avoids_existing_suffixed_names():
    be = _backend()
    envelopes = [
        json.dumps({"status": "test", "sql": "x", "doc": {"rule_name": name}})
        for name in ("a_2", "a", "a")
    ]
    docs = list(yaml.safe_load_all(be.finalize_output_lakewatch_v2(envelopes)))
    assert [d["rule_name"] for d in docs] == ["a_2", "a", "a_3"]


def test_v2_ocsf_rendering_enabled():
    rule_yaml = BASE.replace("process.name|endswith:", "unmapped.Initiated:")
    sql = _doc(_backend(), rule_yaml)["batch"]["sql"]["query"]
    assert "unmapped:Initiated::string" in sql


def test_to_v2_helpers():
    assert to_v2_fidelity("Investigative") == "FIDELITY_INVESTIGATIVE"
    assert to_v2_fidelity("FIDELITY_HIGH") == "FIDELITY_HIGH"
    assert to_v2_rule_name("NTLM Brute-Force (v2)!") == "ntlm_brute_force_v2"
    assert to_v2_rule_name("!!!") == "sigma_rule"
    assert len(to_v2_rule_name("a b " * 200)) <= 256
    assert not to_v2_rule_name("a b " * 200).endswith("_")
    assert to_v2_references(["u1", "x" * 513, "u2", "u3", "u4"]) == ["u1", "u2", "u3"]
    assert to_v2_mitre([{"techniqueId": "T1", "subTechnique": "", "subTechniqueId": ""}]) == [
        {"technique_id": "T1"}
    ]


def test_v2_end_to_end_with_real_ocsf_pipeline():
    ocsf = pytest.importorskip("sigma.pipelines.ocsf")
    be = _backend(processing_pipeline=ocsf.ocsf_pipeline())
    rule_yaml = """
        title: Encoded PowerShell
        status: experimental
        level: high
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Image|endswith: '\\\\powershell.exe'
                CommandLine|contains: '-enc'
            condition: sel
        tags:
            - attack.execution
            - attack.t1059.001
    """
    doc = yaml.safe_load(be.convert(SigmaCollection.from_yaml(rule_yaml), output_format="lakewatch_v2"))
    assert "FROM process_activity" in doc["batch"]["sql"]["query"]
    assert doc["rule_name"] == "encoded_powershell"
    assert doc["mitre"][0]["technique"] == "Command and Scripting Interpreter"
