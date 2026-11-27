"""Pruning of unsupported fields at the condition root (Lakewatch parsed mode)."""

import json
import warnings
from pathlib import Path

import pytest
import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError, SigmaTransformationError

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.lakewatch_report import LakewatchPrunedWarning

CB = "carbonblack_endpoint_event"
SEC_PROC = "windows_security_process"

LOGSOURCE = "    product: windows\n    category: process_creation"

CERTUTIL = """
    selection_img:
        - Image|endswith: '\\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_flags:
        CommandLine|contains:
            - 'urlcache'
            - 'verifyctl'
    condition: all of selection_*
"""

ADFIND = """
    selection_1:
        CommandLine|contains: 'objectcategory'
    selection_2:
        CommandLine|contains: 'trustdmp'
    selection_3:
        OriginalFileName: 'AdFind.exe'
    filter:
        Image|endswith: '\\adfind.exe'
    condition: 1 of selection* and not filter
"""

BOINC = """
    selection:
        OriginalFileName: 'boinc.exe'
    filter:
        Image|endswith: '\\boinc.exe'
    condition: selection and not filter
"""

IN_FILTER = """
    selection:
        CommandLine|contains: 'x'
    filter:
        OriginalFileName: 'a.exe'
    condition: selection and not filter
"""


def _rule(detection, logsource=LOGSOURCE):
    return SigmaCollection.from_yaml(
        f"title: T\nstatus: test\nlogsource:\n{logsource}\ndetection:{detection}"
    ).rules[0]


def _sql(parser, detection, **opts):
    backend = DatabricksBackend(
        parsers=parser, table_name="t", catalog_name="c", schema_name="s", warehouse_id="w", **opts
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        queries = backend.convert_rule(_rule(detection), "lakewatch")
    assert len(queries) == 1
    return json.loads(queries[0])["sql"]


def test_certutil_pruned_cb():
    sql = _sql(CB, CERTUTIL)
    assert "originalfilename" not in sql.lower()
    assert "certutil.exe" in sql
    assert "urlcache" in sql and "verifyctl" in sql
    assert "endswith(lower(childproc_name), '\\\\certutil.exe')" in sql
    assert "(contains(lower(target_cmdline), 'urlcache') OR contains(lower(target_cmdline), 'verifyctl'))" in sql


def test_renamed_adfind_pruned_cb():
    sql = _sql(CB, ADFIND)
    assert "originalfilename" not in sql.lower()
    assert "NOT" in sql
    assert "adfind.exe" in sql
    assert "objectcategory" in sql and "trustdmp" in sql


def test_renamed_boinc_fails_empty():
    with pytest.raises(SigmaError) as exc:
        _sql(CB, BOINC)
    assert str(exc.value).startswith(
        "field OriginalFileName is not supported by profile carbonblack_endpoint_event "
        "(nothing is left once it's dropped)"
    )


def test_unsupported_in_filter_fails_negation():
    with pytest.raises(SigmaError) as exc:
        _sql(CB, IN_FILTER)
    assert (
        "field OriginalFileName is not supported by profile carbonblack_endpoint_event "
        "(it is under a negation, so it can't be dropped)"
    ) in str(exc.value)


def test_option_off_keeps_old_error():
    with pytest.raises(SigmaTransformationError, match="field OriginalFileName is not supported by profile "
                       "carbonblack_endpoint_event"):
        _sql(CB, CERTUTIL, prune_unsupported=False)


def test_option_string_false():
    with pytest.raises(SigmaTransformationError, match="field OriginalFileName is not supported"):
        _sql(CB, CERTUTIL, prune_unsupported="false")
    assert DatabricksBackend(prune_unsupported="false").prune_unsupported is False
    assert DatabricksBackend().prune_unsupported is True


def test_security_4688_pruned():
    sql = _sql(SEC_PROC, CERTUTIL)
    assert "originalfilename" not in sql.lower()
    assert "urlcache" in sql


# --- visibility: warning, report key, annotation, discovery, snapshot -------------------------

WARNING_TAIL = (
    ": unsupported field(s) OriginalFileName dropped; the rule is narrower than written "
    "(-O prune_unsupported=false to fail instead)"
)

RULE_HEAD = "title: T\nid: 5f1b9c8e-1111-4a2b-8c3d-000000000001\nstatus: test\nlogsource:\n" + LOGSOURCE
PLAIN = "\n    sel:\n        CommandLine|contains: 'x'\n    condition: sel\n"


def _collection(detection, title="T", rule_id="5f1b9c8e-1111-4a2b-8c3d-000000000001"):
    return (f"title: {title}\nid: {rule_id}\nstatus: test\nlogsource:\n{LOGSOURCE}\n"
            f"detection:{detection}")


def _backend(parser=CB, **opts):
    return DatabricksBackend(
        parsers=parser, table_name="t", catalog_name="c", schema_name="s", warehouse_id="w", **opts
    )


def _documents(backend, *texts, mode="ignore"):
    with warnings.catch_warnings():
        warnings.simplefilter(mode)
        out = backend.convert(SigmaCollection.from_yaml("\n---\n".join(texts)), "lakewatch")
    return [yaml.safe_load(d) for d in out.split("\n---\n") if d.strip()]


def test_pruned_warning_text_and_category():
    with warnings.catch_warnings(record=True) as shown:
        warnings.simplefilter("always")
        _backend().convert_rule(_rule(CERTUTIL), "lakewatch")
    pruned = [w for w in shown if issubclass(w.category, LakewatchPrunedWarning)]
    assert len(pruned) == 1
    message = str(pruned[0].message)
    assert message.endswith(WARNING_TAIL)
    assert "(profile carbonblack_endpoint_event)" in message


def test_pruned_report_key():
    backend = _backend()
    other = _collection(PLAIN, title="Plain", rule_id="5f1b9c8e-1111-4a2b-8c3d-000000000002")
    _documents(backend, _collection(CERTUTIL), other, mode="always")
    first, second = (r["results"][0] for r in backend.last_report["rules"])
    assert first["pruned"] == ["OriginalFileName"]
    assert first["approximate"] is False
    assert any(w.endswith(WARNING_TAIL) for w in first["warnings"])
    assert second["pruned"] == []


def test_pruned_annotation_workspace():
    docs = _documents(_backend(), _collection(CERTUTIL), _collection(
        PLAIN, title="Plain", rule_id="5f1b9c8e-1111-4a2b-8c3d-000000000002"))
    annotations = docs[0]["annotations"]
    assert annotations["sigma_pruned_fields"] == "OriginalFileName"
    assert list(annotations)[-1] == "sigma_pruned_fields"
    assert list(annotations)[-2] == "converter_version"
    assert "sigma_pruned_fields" not in docs[1]["annotations"]


def test_pruned_annotation_content_pack(tmp_path):
    schema = tmp_path / "schemas.json"
    bundled = Path(__file__).parent.parent / "sigma" / "backends" / "databricks" / "lakewatch_schemas"
    cb_file = next(p for p in bundled.glob("*.json") if CB in p.read_text())
    entry = json.loads(cb_file.read_text())["parsers"][CB]
    entry["uuid"] = "11111111-2222-3333-4444-555555555555"
    schema.write_text(json.dumps({"parsers": {CB: entry}}))
    backend = _backend(target="content_pack", lakewatch_schemas=str(schema))
    docs = _documents(backend, _collection(CERTUTIL), _collection(
        PLAIN, title="Plain", rule_id="5f1b9c8e-1111-4a2b-8c3d-000000000002"))
    annotations = docs[0]["rule"]["annotations"]
    assert annotations["sigma_pruned_fields"] == "OriginalFileName"
    assert list(annotations)[-1] == "sigma_pruned_fields"
    assert "sigma_pruned_fields" not in docs[1]["rule"].get("annotations", {})


def test_multi_condition_one_warning():
    detection = """
    sel1:
        - Image|endswith: '\\a.exe'
        - OriginalFileName: 'a.exe'
    sel2:
        - Image|endswith: '\\b.exe'
        - IntegrityLevel: 'High'
    condition:
        - sel1
        - sel2
"""
    backend = _backend()
    with warnings.catch_warnings(record=True) as shown:
        warnings.simplefilter("always")
        out = backend.convert(SigmaCollection.from_yaml(_collection(detection)), "lakewatch")
    pruned = [w for w in shown if issubclass(w.category, LakewatchPrunedWarning)]
    assert len(pruned) == 1
    assert "unsupported field(s) OriginalFileName, IntegrityLevel dropped" in str(pruned[0].message)
    docs = [yaml.safe_load(d) for d in out.split("\n---\n") if d.strip()]
    assert len(docs) == 2
    for doc in docs:
        assert doc["annotations"]["sigma_pruned_fields"] == "OriginalFileName, IntegrityLevel"


def test_discovery_counts_pruned_rule():
    rules = SigmaCollection.from_yaml(_collection(CERTUTIL))
    (entry,) = DatabricksBackend().discover_parsers(rules)["rules"]
    assert CB in entry["convertible"]
    (strict,) = DatabricksBackend(prune_unsupported=False).discover_parsers(rules)["rules"]
    assert CB not in strict["convertible"]
    assert strict["not_convertible"][CB].startswith("field OriginalFileName is not supported")


def test_correlation_referenced_rule_pruned():
    base = _collection(CERTUTIL).replace("status: test", "name: base\nstatus: test")
    corr = """
title: Corr
id: 5f1b9c8e-1111-4a2b-8c3d-000000000009
status: test
correlation:
    type: event_count
    rules:
        - base
    group-by:
        - Image
    timespan: 5m
    condition:
        gte: 3
"""
    backend = _backend(collect_errors=True)
    _documents(backend, base, corr)
    record = next(r for r in backend.last_report["rules"] if r["title"] == "T")
    assert record["results"][0]["pruned"] == ["OriginalFileName"]


def test_pruned_snapshot():
    docs = _documents(_backend(), _collection(CERTUTIL))
    assert len(docs) == 1
    doc = docs[0]
    # The converter version changes with every release; check its position, not its value.
    assert list(doc["annotations"]) == [
        "sigma_id", "sigma_status", "sigma_profile", "converter_version", "sigma_pruned_fields"]
    del doc["annotations"]["converter_version"]
    assert doc == {
        "catalog_name": "c",
        "schema_name": "s",
        "rule_name": "t__carbonblack_endpoint_event",
        "description": "T",
        "severity": "Medium",
        "fidelity": "FIDELITY_DEVELOPMENT",
        "category": "Static Signature",
        "objective": "T",
        "annotations": {
            "sigma_id": "5f1b9c8e-1111-4a2b-8c3d-000000000001",
            "sigma_status": "test",
            "sigma_profile": "carbonblack_endpoint_event@1",
            "sigma_pruned_fields": "OriginalFileName",
        },
        "schedule": {"at_least_every": "24h", "enabled": False},
        "batch": {
            "warehouse_id": "w",
            "sql": {
                "query": (
                    "SELECT *, device_name AS sigma_entity\n"
                    "FROM t\n"
                    "WHERE IN_TIMERANGE(time)\n"
                    "  AND (lower(device_os) = 'windows' AND lower(type) = 'endpoint.event.procstart' "
                    "AND endswith(lower(childproc_name), '\\\\certutil.exe') "
                    "AND (contains(lower(target_cmdline), 'urlcache') "
                    "OR contains(lower(target_cmdline), 'verifyctl')))"
                ),
                "default_catalog_name": "c",
                "default_schema_name": "s",
            },
        },
        "output": {"summary": "T on {sigma_entity}", "event_time_column": "time", "default_context": True},
    }


FAILS_AFTER_PRUNE = """
    sel1:
        - Image|endswith: '\\a.exe'
        - OriginalFileName: 'a.exe'
    sel2:
        CommandLine|contains: 'x'
    filter:
        OriginalFileName: 'b.exe'
    condition:
        - sel1
        - sel2 and not filter
"""


def test_no_pruned_warning_when_conversion_fails():
    backend = _backend(collect_errors=True)
    with warnings.catch_warnings(record=True) as shown:
        warnings.simplefilter("always")
        backend.convert(SigmaCollection.from_yaml(_collection(FAILS_AFTER_PRUNE)), "lakewatch")
    assert not [w for w in shown if issubclass(w.category, LakewatchPrunedWarning)]
    result = backend.last_report["rules"][0]["results"][0]
    assert result["status"] == "failed"
    assert result["pruned"] == []
    assert not any("dropped" in m for m in result["warnings"])


def test_no_pruned_warning_when_conversion_raises():
    backend = _backend()
    with warnings.catch_warnings(record=True) as shown:
        warnings.simplefilter("always")
        with pytest.raises(SigmaError):
            backend.convert(SigmaCollection.from_yaml(_collection(FAILS_AFTER_PRUNE)), "lakewatch")
    assert not [w for w in shown if issubclass(w.category, LakewatchPrunedWarning)]
