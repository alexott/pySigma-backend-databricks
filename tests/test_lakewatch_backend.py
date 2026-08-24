"""Tests for the Lakewatch output format of the Databricks backend."""

import json

import pytest
import yaml
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


# ---------------------------------------------------------------------------
# Task 4: finalize_output_lakewatch tests
# ---------------------------------------------------------------------------

TWO_RULES = """
title: Rule One
status: experimental
level: high
logsource: {category: test}
detection:
    sel: {class_uid: 4003, foo: bar}
    condition: sel
---
title: Rule Two
status: stable
level: medium
logsource: {category: test}
detection:
    sel: {class_uid: 3002, baz: qux}
    condition: sel
"""


def test_multi_document_output():
    be = DatabricksBackend()
    out = be.convert(SigmaCollection.from_yaml(TWO_RULES), output_format="lakewatch")
    docs = list(yaml.safe_load_all(out))
    assert len(docs) == 2
    assert docs[0]["metadata"]["displayName"] == "Rule One"
    assert "FROM dns_activity" in docs[0]["spec"]["input"]["batch"]["sql"]
    assert "FROM authentication" in docs[1]["spec"]["input"]["batch"]["sql"]


def test_sql_rendered_as_block_scalar():
    be = DatabricksBackend(table_name="t")
    out = be.convert(
        SigmaCollection.from_yaml(BASE.replace("type_uid: 100701", "foo: baz")),
        output_format="lakewatch",
    )
    # literal block scalar, not an escaped one-line double-quoted string
    assert "sql: |-" in out
    assert "\\n" not in out


def test_deprecated_rule_skipped():
    be = DatabricksBackend(table_name="t")
    rule_yaml = BASE.replace("status: experimental", "status: deprecated")
    out = be.convert(SigmaCollection.from_yaml(rule_yaml), output_format="lakewatch")
    assert out.strip() == ""


# ---------------------------------------------------------------------------
# Folded coverage: empty-sql is dropped; custom lookback in WHERE
# ---------------------------------------------------------------------------

def test_empty_sql_dropped_in_output():
    """finalize_output_lakewatch drops envelopes whose sql field is empty."""
    be = DatabricksBackend(table_name="t")
    # One envelope with empty sql, one with real sql.
    empty = '{"status":"test","sql":"","doc":{"kind":"Rule","a":1}}'
    real = '{"status":"test","sql":"SELECT * FROM t WHERE x = 1","doc":{"kind":"Rule","b":2}}'
    result = be.finalize_output_lakewatch([empty, real])
    # Empty-sql envelope should be absent; real one present.
    assert result.strip() != ""
    docs = list(yaml.safe_load_all(result))
    assert len(docs) == 1
    assert docs[0]["b"] == 2


def test_custom_lookback_in_where():
    """DatabricksBackend(lookback='48 HOUR') emits INTERVAL 48 HOUR in the batch SQL."""
    be = DatabricksBackend(table_name="t", lookback="48 HOUR")
    out = be.convert(SigmaCollection.from_yaml(BASE), output_format="lakewatch")
    assert "INTERVAL 48 HOUR" in out


# ---------------------------------------------------------------------------
# Task 5: End-to-end test with real OCSF pipeline
# ---------------------------------------------------------------------------


def test_end_to_end_with_real_ocsf_pipeline():
    """End-to-end: OCSF pipeline maps fields and injects type_uid; backend derives table."""
    ocsf = pytest.importorskip("sigma.pipelines.ocsf")
    be = DatabricksBackend(processing_pipeline=ocsf.ocsf_pipeline())
    rule_yaml = """
        title: Encoded PowerShell
        status: experimental
        level: high
        description: Detects encoded powershell
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
    out = be.convert(SigmaCollection.from_yaml(rule_yaml), output_format="lakewatch")
    doc = yaml.safe_load(out)
    sql = doc["spec"]["input"]["batch"]["sql"]
    assert "FROM process_activity" in sql               # derived from injected type_uid
    assert "endswith(lower(process.name)" in sql        # OCSF field mapping applied
    assert doc["spec"]["metadata"]["mitre"][0]["technique"] == "Command and Scripting Interpreter"
