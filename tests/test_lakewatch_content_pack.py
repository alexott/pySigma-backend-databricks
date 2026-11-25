"""Tests for -O target=content_pack|workspace and the content-pack document."""

import json
import warnings
from pathlib import Path

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaConfigurationError

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.lakewatch_pack import CONTENT_RESOURCE_NAMESPACE, content_resource_id

BUNDLED = (Path(__file__).parent.parent / "sigma" / "backends" / "databricks"
           / "lakewatch_schemas" / "windows_custom.json")
SIGMA_ID = "5f1b9c8e-3c1a-4f0e-9a43-1d2e3f4a5b6c"
UUID = "11111111-2222-3333-4444-555555555555"
SYSMON = "windows_sysmon_process"
CS = "crowdstrike_fdr_event"


def _rule(title="Encoded PowerShell", rule_id=SIGMA_ID, cond="Image|endswith: '\\powershell.exe'"):
    id_line = f"id: {rule_id}\n" if rule_id else ""
    return f"""
title: {title}
{id_line}status: test
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        {cond}
    condition: sel
"""


def _collection(*rules):
    return SigmaCollection.from_yaml("\n---\n".join(rules))


@pytest.fixture
def uuid_schema(tmp_path):
    data = json.loads(BUNDLED.read_text())
    entry = data["parsers"][SYSMON]
    entry["uuid"] = UUID
    path = tmp_path / "schemas.json"
    path.write_text(json.dumps({"parsers": {SYSMON: entry}}))
    return str(path)


def _docs(backend, collection, fmt="lakewatch"):
    import yaml
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        out = backend.convert(collection, fmt)
    return [yaml.safe_load(d) for d in out.split("\n---\n") if d.strip()]


def test_namespace_and_id():
    assert str(CONTENT_RESOURCE_NAMESPACE) == "674aac7d-2204-5e32-8cea-531a682c987b"
    assert content_resource_id(SIGMA_ID.upper(), SYSMON) == "5974b21f-2777-59c9-8945-d30f12810a8e"


def test_target_default_is_workspace():
    backend = DatabricksBackend(parsers=CS, table_name="t", catalog_name="c", schema_name="s")
    assert backend.target == "workspace"
    doc = _docs(backend, _collection(_rule()))[0]
    assert doc["catalog_name"] == "c"


def test_target_invalid():
    with pytest.raises(SigmaConfigurationError, match="expected content_pack or workspace"):
        DatabricksBackend(target="pack")


def test_content_pack_document_shape(uuid_schema):
    backend = DatabricksBackend(target="content_pack", parsers=SYSMON, lakewatch_schemas=uuid_schema)
    doc = _docs(backend, _collection(_rule()))[0]
    assert list(doc) == ["description", "metadata", "rule"]
    assert doc["metadata"] == {
        "rule_kind": "panther", "displayName": "Encoded PowerShell",
        "table_parameters": {"events": {"display_name": "Events", "parser_ids": [UUID]}},
    }
    rule = doc["rule"]
    assert list(rule)[:2] == ["rule_name", "content_resource_id"]
    assert rule["content_resource_id"] == "5974b21f-2777-59c9-8945-d30f12810a8e"
    assert "catalog_name" not in rule and "schema_name" not in rule
    assert "catalog_name" not in json.dumps(doc) and "schema_name" not in json.dumps(doc)
    assert rule["schedule"] == {"at_least_every": "24h"}
    assert list(rule["batch"]) == ["sql"]
    assert list(rule["batch"]["sql"]) == ["query"]
    assert "FROM {{table.events}}\nWHERE IN_TIMERANGE(time)" in rule["batch"]["sql"]["query"]


def test_content_pack_keeps_summary_and_context(uuid_schema):
    backend = DatabricksBackend(target="content_pack", parsers=SYSMON, lakewatch_schemas=uuid_schema)
    doc = _docs(backend, _collection(_rule()))[0]
    assert doc["rule"]["output"]["summary"] == "Encoded PowerShell on {sigma_entity}"
    assert "SELECT *, " in doc["rule"]["batch"]["sql"]["query"]


def test_content_pack_parser_without_uuid():
    backend = DatabricksBackend(target="content_pack", parsers=SYSMON)
    with pytest.raises(SigmaConfigurationError) as e:
        backend.convert(_collection(_rule()), "lakewatch")
    assert str(e.value) == (
        f"parser {SYSMON} of profile {SYSMON} has no parser uuid, which -O target=content_pack "
        f'needs: add "uuid" to its entry in a schema file (-O lakewatch_schemas=...) or use '
        f"-O target=workspace")


def test_content_pack_rejects_ocsf():
    backend = DatabricksBackend(target="content_pack", ocsf=True)
    with pytest.raises(SigmaConfigurationError, match="cannot be combined with OCSF mode"):
        backend.convert(_collection(_rule()), "lakewatch")


def test_content_pack_ignored_options_warn():
    backend = DatabricksBackend(target="content_pack", parsers=CS, catalog_name="c",
                                warehouse_id="w", enabled=False)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        backend.convert(_collection(_rule()), "lakewatch")
    messages = [str(w.message) for w in caught]
    assert messages.count("ignored with -O target=content_pack: catalog_name, enabled, warehouse_id") == 1
    assert not [m for m in messages if "warehouse_id" in m and "RULE_BATCH" in m]


def test_content_pack_no_warning_when_unset():
    backend = DatabricksBackend(target="content_pack", parsers=CS)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        backend.convert(_collection(_rule()), "lakewatch")
    assert not [w for w in caught if "ignored with" in str(w.message)]


def test_content_pack_rule_without_id_collected():
    backend = DatabricksBackend(target="content_pack", parsers=CS, collect_errors=True)
    docs = _docs(backend, _collection(_rule(), _rule(title="No id", rule_id=None)))
    assert len(docs) == 1
    assert len(backend.errors) == 1
    assert "content_pack mode needs a Sigma rule id (used for content_resource_id)" in str(backend.errors[0][1])


def test_content_pack_builtin_uuid():
    backend = DatabricksBackend(target="content_pack", parsers=CS)
    doc = _docs(backend, _collection(_rule()))[0]
    assert doc["metadata"]["table_parameters"]["events"]["parser_ids"] == [
        "683791ba-de8e-4fac-b202-a02c5a11aa8d"]


def test_content_pack_dedup_rule_names():
    backend = DatabricksBackend(target="content_pack", parsers=CS)
    other = "6f1b9c8e-3c1a-4f0e-9a43-1d2e3f4a5b6c"
    docs = _docs(backend, _collection(_rule(), _rule(rule_id=other)))
    names = [d["rule"]["rule_name"] for d in docs]
    assert names[0].endswith("__crowdstrike_fdr_event")
    assert names[1].endswith("__crowdstrike_fdr_event_2")


def test_target_with_other_format_warns():
    backend = DatabricksBackend(target="content_pack")
    with pytest.warns(UserWarning, match="target option is supported only by the lakewatch format"):
        backend.convert(_collection(_rule()), "default")
