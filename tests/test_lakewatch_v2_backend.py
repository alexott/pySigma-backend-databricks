"""Tests for the Lakewatch v2 output format of the Databricks backend."""

import json
import warnings
from importlib.metadata import version

import pytest
import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaBackendError, SigmaConfigurationError, SigmaConversionError

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.lakewatch_maps import (
    build_mitre_mapping,
    build_v2_annotations,
    to_v2_fidelity,
    to_v2_references,
    to_v2_rule_name,
)


def _backend(**kwargs):
    """Backend with the required v2 catalog/schema options set."""
    kwargs.setdefault("catalog_name", "cat")
    kwargs.setdefault("schema_name", "sch")
    kwargs.setdefault("ocsf", True)
    return DatabricksBackend(**kwargs)


def _doc(backend, rule_yaml):
    """Convert one rule and return the parsed Lakewatch v2 document."""
    rule = SigmaCollection.from_yaml(rule_yaml).rules[0]
    return json.loads(backend.convert_rule(rule, "lakewatch")[0])["doc"]


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
        "category", "objective", "references", "annotations", "schedule", "batch", "output",
        "mitre",
    ]
    assert doc["catalog_name"] == "cat"
    assert doc["schema_name"] == "sch"
    assert doc["rule_name"] == "suspicious_powershell"
    assert doc["description"] == "Detects suspicious powershell"
    assert doc["severity"] == "High"
    assert doc["fidelity"] == "FIDELITY_DEVELOPMENT"            # experimental
    assert doc["category"] == "Static Signature"
    assert doc["references"] == ["https://example.com/one", "https://example.com/two"]
    assert doc["schedule"] == {"at_least_every": "24h", "enabled": False}
    assert doc["annotations"] == {
        "sigma_status": "experimental",
        "converter_version": version("pySigma-backend-databricks"),
    }
    assert doc["batch"]["warehouse_id"] == "wh123"
    assert doc["batch"]["sql"]["default_catalog_name"] == "cat"
    assert doc["batch"]["sql"]["default_schema_name"] == "sch"
    assert doc["output"] == {
        "summary": "Suspicious PowerShell",
        "event_time_column": "time",
        "default_context": True,
    }
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
    assert "runbook" not in doc
    assert "continuous" not in doc["schedule"]
    assert "compute_group" not in doc["schedule"]
    # v1-only fields are not emitted
    for key in ("apiVersion", "kind", "metadata", "spec", "observables"):
        assert key not in doc


def test_v2_options():
    be = _backend(table_name="main.sec.auth", schedule="12h",
                  default_fidelity="High", default_category="Behavioral",
                  extend_lookback="1h")
    doc = _doc(be, BASE)
    assert "FROM main.sec.auth\n" in doc["batch"]["sql"]["query"]
    assert doc["schedule"]["at_least_every"] == "12h"
    assert "compute_group" not in doc["schedule"]            # removed from the v2 API
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
        _doc(DatabricksBackend(ocsf=True, **options), BASE)


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
    out = _backend(warehouse_id="wh").convert(SigmaCollection.from_yaml(TWO_RULES), output_format="lakewatch")
    docs = list(yaml.safe_load_all(out))
    assert len(docs) == 2                                  # deprecated rule skipped
    assert [d["rule_name"] for d in docs] == ["rule_one", "rule_one_2"]
    assert "FROM dns_activity" in docs[0]["batch"]["sql"]["query"]
    assert "FROM authentication" in docs[1]["batch"]["sql"]["query"]
    assert docs[0]["fidelity"] == "FIDELITY_DEVELOPMENT"     # experimental
    assert docs[1]["fidelity"] == "FIDELITY_INVESTIGATIVE"   # stable
    assert "query: |-" in out


def test_v2_dedup_avoids_existing_suffixed_names():
    be = _backend(warehouse_id="wh")
    envelopes = [
        json.dumps({"status": "test", "sql": "x", "doc": {"rule_name": name}})
        for name in ("a_2", "a", "a")
    ]
    docs = list(yaml.safe_load_all(be.finalize_output_lakewatch(envelopes)))
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
    assert to_v2_references(["https://u1", "https://" + "x" * 505, "https://u2", "https://u3",
                             "https://u4"]) == ["https://u1", "https://u2", "https://u3"]
    # Empty fields are left out; an entry without tactic or technique id is dropped.
    rule = SigmaCollection.from_yaml(BASE).rules[0]
    assert build_mitre_mapping(rule) == [{
        "taxonomy": "Enterprise", "tactic": "Execution",
        "technique": "Command and Scripting Interpreter", "technique_id": "T1059",
        "sub_technique": "PowerShell", "sub_technique_id": "T1059.001",
    }]
    # Only http(s) URLs are references in v2.
    assert to_v2_references(["Internal Research", "HTTPS://a", "ftp://b", "http://c"]) == [
        "HTTPS://a", "http://c"
    ]


def test_to_v2_rule_name_suffix():
    assert to_v2_rule_name("a b", "__x") == "a_b__x"
    assert to_v2_rule_name("!!!", "__x") == "sigma_rule__x"
    long = to_v2_rule_name("a b " * 200, "__profile")
    assert len(long) == 256 and long.endswith("__profile")
    assert "___" not in long


def test_v2_end_to_end_with_real_ocsf_pipeline():
    ocsf = pytest.importorskip("sigma.pipelines.ocsf")
    be = _backend(processing_pipeline=ocsf.ocsf_pipeline(), warehouse_id="wh")
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
    doc = yaml.safe_load(be.convert(SigmaCollection.from_yaml(rule_yaml), output_format="lakewatch"))
    assert "FROM process_activity" in doc["batch"]["sql"]["query"]
    assert doc["rule_name"] == "encoded_powershell"
    assert doc["mitre"][0]["technique"] == "Command and Scripting Interpreter"


@pytest.mark.parametrize("status, fidelity", [
    ("stable", "FIDELITY_INVESTIGATIVE"),
    ("test", "FIDELITY_DEVELOPMENT"),
    ("experimental", "FIDELITY_DEVELOPMENT"),
])
def test_v2_fidelity_from_status(status, fidelity):
    doc = _doc(_backend(), BASE.replace("status: experimental", f"status: {status}"))
    assert doc["fidelity"] == fidelity


def test_v2_fidelity_without_status():
    doc = _doc(_backend(), BASE.replace("status: experimental\n", ""))
    assert doc["fidelity"] == "FIDELITY_DEVELOPMENT"


@pytest.mark.parametrize("value, expected", [
    (None, False), (True, True), ("true", True), ("false", False), ("auto", False),
])
def test_v2_enabled_option(value, expected):
    kwargs = {} if value is None else {"enabled": value}
    assert _doc(_backend(**kwargs), BASE)["schedule"]["enabled"] is expected


def test_v2_enabled_option_invalid():
    with pytest.raises(ValueError, match="enabled"):
        _backend(enabled="maybe")


def _convert(backend, rule_yaml=BASE):
    return backend.convert(SigmaCollection.from_yaml(rule_yaml), output_format="lakewatch")


def test_v2_warns_without_warehouse_id():
    with pytest.warns(UserWarning, match="warehouse_id") as record:
        _convert(_backend(), BASE + "---\n" + BASE.replace("Suspicious", "Other"))
    assert len([w for w in record if "warehouse_id" in str(w.message)]) == 1


def test_v2_no_warnings_with_defaults_and_warehouse():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _convert(_backend(warehouse_id="wh"))


FULL = BASE.replace("status: experimental", """status: stable
id: 5f1b9c8e-3c1a-4f0e-9a43-1d2e3f4a5b6c
author: Jane Doe, John Roe
falsepositives:
    - Administrative scripts
    - Software installers""") + """    - cve.2021-44228
    - detection.threat-hunting
"""


def test_v2_runbook_and_annotations():
    doc = _doc(_backend(), FULL)
    assert doc["runbook"] == "Known false positives:\n- Administrative scripts\n- Software installers"
    assert doc["annotations"] == {
        "sigma_id": "5f1b9c8e-3c1a-4f0e-9a43-1d2e3f4a5b6c",
        "sigma_status": "stable",
        "sigma_author": "Jane Doe, John Roe",
        "sigma_tags": "cve.2021-44228, detection.threat-hunting",
        "converter_version": version("pySigma-backend-databricks"),
    }
    keys = list(doc)
    assert keys.index("references") < keys.index("runbook") < keys.index("annotations") < keys.index("schedule")


def test_v2_text_limits():
    long_rule = BASE.replace("description: Detects suspicious powershell",
                             "description: '" + "d" * 70000 + "'")
    doc = _doc(_backend(), long_rule)
    assert len(doc["description"]) == 4096
    assert doc["description"].endswith("...")
    assert len(doc["objective"]) == 65536
    assert doc["objective"].endswith("...")


def test_v2_runbook_limit():
    many = "\n".join(f"    - {'x' * 100} {i}" for i in range(100))
    doc = _doc(_backend(), BASE.replace("level: high", "level: high\nfalsepositives:\n" + many))
    assert len(doc["runbook"]) == 4096
    assert doc["runbook"].endswith("...")


def test_build_v2_annotations_limits():
    rule = SigmaCollection.from_yaml(
        BASE.replace("status: experimental", "status: test\nauthor: '" + "a" * 300 + "'")
    ).rules[0]
    ann = build_v2_annotations(rule)
    assert len(ann["sigma_author"]) == 256
    assert ann["sigma_author"].endswith("...")
    assert "sigma_tags" not in ann                      # only ATT&CK tags in BASE
    assert all(len(k) <= 64 and isinstance(v, str) and len(v) <= 256 for k, v in ann.items())


def test_v2_output_dir_writes_one_file_per_rule(tmp_path):
    out_dir = tmp_path / "nested" / "rules"                # created when missing
    collection = SigmaCollection.from_yaml(TWO_RULES)
    summary = _backend(warehouse_id="wh", output_dir=str(out_dir)).convert(
        collection, output_format="lakewatch")
    files = sorted(p.name for p in out_dir.iterdir())
    assert files == ["rule_one.yaml", "rule_one_2.yaml"]   # deduped names, deprecated skipped
    single = list(yaml.safe_load_all(_backend(warehouse_id="wh").convert(
        SigmaCollection.from_yaml(TWO_RULES), output_format="lakewatch")))
    written = [yaml.safe_load((out_dir / name).read_text(encoding="utf-8")) for name in files]
    assert written == single                               # same documents as the -o output
    assert "query: |-" in (out_dir / "rule_one.yaml").read_text(encoding="utf-8")
    assert summary == f"# Wrote 2 Lakewatch rule(s) to {out_dir}"
    assert yaml.safe_load(summary) is None                 # harmless if redirected with -o


def test_v2_output_dir_overwrites_existing_rule_files(tmp_path):
    (tmp_path / "suspicious_powershell.yaml").write_text("old", encoding="utf-8")
    _convert(_backend(warehouse_id="wh", output_dir=str(tmp_path)))
    doc = yaml.safe_load((tmp_path / "suspicious_powershell.yaml").read_text(encoding="utf-8"))
    assert doc["rule_name"] == "suspicious_powershell"


def test_v2_output_dir_is_a_file(tmp_path):
    target = tmp_path / "file.yaml"
    target.write_text("", encoding="utf-8")
    with pytest.raises(SigmaConfigurationError, match="output_dir"):
        _convert(_backend(warehouse_id="wh", output_dir=str(target)))


def test_v2_output_dir_blank_is_ignored():
    out = _convert(_backend(warehouse_id="wh", output_dir="  "))
    assert yaml.safe_load(out)["rule_name"] == "suspicious_powershell"


def test_output_dir_warns_for_other_formats(tmp_path):
    rules = SigmaCollection.from_yaml(BASE)
    with pytest.warns(UserWarning, match="supported only by the lakewatch format"):
        DatabricksBackend(output_dir=str(tmp_path)).convert(rules, output_format="dbsql")
    assert not any(tmp_path.iterdir())


@pytest.mark.parametrize("name, value", [("compute_group", "automatic"), ("lookback", "25 HOUR")])
def test_removed_v1_options_raise(name, value):
    with pytest.raises(SigmaConfigurationError, match=f"The {name} option was removed in 0.2.0"):
        DatabricksBackend(**{name: value})


def test_other_unknown_options_still_accepted():
    assert DatabricksBackend(some_future_option="x").backend_options == {"some_future_option": "x"}


def test_lakewatch_v2_format_is_unknown():
    assert "lakewatch_v2" not in DatabricksBackend.formats
    with pytest.raises(SigmaBackendError, match="Unknown output format 'lakewatch_v2'"):
        _backend().convert(SigmaCollection.from_yaml(BASE), output_format="lakewatch_v2")


def test_lakewatch_format_is_v2():
    assert DatabricksBackend.formats["lakewatch"] == "Lakewatch detection rules (Unity Catalog governed)"


def test_v2_unsupported_rule_skipped():
    rule_yaml = BASE.replace("status: experimental", "status: unsupported")
    out = _backend().convert(SigmaCollection.from_yaml(rule_yaml), output_format="lakewatch")
    assert out.strip() == ""


def test_v2_empty_sql_dropped():
    be = _backend(warehouse_id="wh")
    empty = json.dumps({"status": "test", "sql": "", "doc": {"rule_name": "a"}})
    real = json.dumps({"status": "test", "sql": "SELECT 1", "doc": {"rule_name": "b"}})
    docs = list(yaml.safe_load_all(be.finalize_output_lakewatch([empty, real])))
    assert docs == [{"rule_name": "b"}]
