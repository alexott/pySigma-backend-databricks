import json
import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaConversionError
from sigma.backends.databricks import DatabricksBackend


def _doc(backend, rule_yaml):
    """Convert one rule and return the parsed Lakewatch doc envelope."""
    col = SigmaCollection.from_yaml(rule_yaml)
    rule = col.rules[0]
    query = backend.convert_rule(rule, "lakewatch")[0]
    return json.loads(query)


BASE = """
title: Suspicious PowerShell
status: experimental
level: high
description: Detects suspicious powershell
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


def test_table_from_option_overrides_derivation():
    be = DatabricksBackend(table_name="my_catalog.my_table")
    env = _doc(be, BASE)
    assert "FROM my_catalog.my_table" in env["doc"]["spec"]["input"]["batch"]["sql"]


def test_table_derived_from_type_uid():
    be = DatabricksBackend()
    env = _doc(be, BASE)
    assert "FROM process_activity" in env["doc"]["spec"]["input"]["batch"]["sql"]


def test_batch_sql_shape_and_lookback_default():
    be = DatabricksBackend()
    sql = _doc(be, BASE)["doc"]["spec"]["input"]["batch"]["sql"]
    assert sql.startswith("SELECT *\nFROM process_activity\n")
    assert "WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 25 HOUR" in sql
    assert "endswith(lower(process.name)" in sql


def test_metadata_mapping():
    be = DatabricksBackend()
    meta = _doc(be, BASE)["doc"]["spec"]["metadata"]
    assert meta["severity"] == "High"
    assert meta["fidelity"] == "Investigative"       # from status: experimental
    assert meta["category"] == "Static Signature"
    assert meta["mitre"][0]["techniqueId"] == "T1059"
    assert meta["mitre"][0]["subTechniqueId"] == "T1059.001"


def test_metadata_overrides():
    be = DatabricksBackend(default_fidelity="High", default_category="Statistical")
    meta = _doc(be, BASE)["doc"]["spec"]["metadata"]
    assert meta["fidelity"] == "High"
    assert meta["category"] == "Statistical"


def test_schedule_and_omitted_name():
    be = DatabricksBackend(schedule="12h", compute_group="dedicated")
    doc = _doc(be, BASE)["doc"]
    assert doc["spec"]["schedule"]["atLeastEvery"] == "12h"
    assert doc["spec"]["schedule"]["computeGroup"] == "dedicated"
    assert "name" not in doc["metadata"]           # server assigns rl-xxxx


def test_error_when_no_table_resolvable():
    be = DatabricksBackend()
    rule_yaml = """
        title: No OCSF
        logsource: {category: test}
        detection:
            sel: {foo: bar}
            condition: sel
    """
    with pytest.raises(SigmaConversionError):
        _doc(be, rule_yaml)
