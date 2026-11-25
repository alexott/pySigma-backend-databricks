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


# --- output_dir scaffolding (Ruling 2) ---

def _pack_convert(out_dir, description="d", uuid_schema_path=None, collection=None):
    backend = DatabricksBackend(target="content_pack", parsers=CS, output_dir=str(out_dir))
    rule = _rule().replace("status: test", f"status: test\ndescription: {description}")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return backend.convert(collection or _collection(rule), "lakewatch")


def _pack_name(out_dir):
    return [p.name for p in Path(out_dir).iterdir() if p.is_dir()][0]


def test_merge_revisions_new_unchanged_changed():
    from sigma.backends.databricks.lakewatch_pack import merge_revisions
    existing = {"rules": [
        {"name": "keep", "latestVersion": 2, "contentHash": "h1", "versionNote": "note"},
        {"name": "chg", "latestVersion": 3, "contentHash": "old", "versionNote": "x"},
        {"name": "absent", "latestVersion": 5, "contentHash": "z"},
    ]}
    merged = merge_revisions(existing, {"keep": "h1", "chg": "new", "fresh": "h9"})
    assert merged["rules"] == [
        {"name": "keep", "latestVersion": 2, "contentHash": "h1", "versionNote": "note"},
        {"name": "chg", "latestVersion": 4, "contentHash": "new"},
        {"name": "absent", "latestVersion": 5, "contentHash": "z"},
        {"name": "fresh", "latestVersion": 1, "contentHash": "h9"},
    ]
    assert merge_revisions(None, {"a": "h"}) == {
        "rules": [{"name": "a", "latestVersion": 1, "contentHash": "h"}]}


def test_pack_layout(tmp_path):
    import hashlib

    import yaml
    msg = _pack_convert(tmp_path)
    name = _pack_name(tmp_path)
    assert msg == f"# Wrote 1 Lakewatch content-pack rule(s) to {tmp_path}"
    file = tmp_path / name / f"{name}.yaml"
    assert list(yaml.safe_load(file.read_text())) == ["description", "metadata", "rule"]
    revisions = yaml.safe_load((tmp_path / "revisions.yaml").read_text())
    assert revisions == {"rules": [{
        "name": name, "latestVersion": 1,
        "contentHash": hashlib.sha256(file.read_bytes()).hexdigest()}]}
    assert yaml.safe_load((tmp_path / "appIndex.rules.yaml").read_text()) == {"rules": [{"name": name}]}
    assert not (tmp_path / f"{name}.yaml").exists()


def test_revisions_rerun_is_stable(tmp_path):
    import yaml
    _pack_convert(tmp_path)
    first = (tmp_path / "revisions.yaml").read_bytes()
    _pack_convert(tmp_path)
    assert (tmp_path / "revisions.yaml").read_bytes() == first
    assert yaml.safe_load(first)["rules"][0]["latestVersion"] == 1


def test_revisions_bump_once(tmp_path):
    import yaml
    _pack_convert(tmp_path)
    _pack_convert(tmp_path, description="changed")
    _pack_convert(tmp_path, description="changed")
    assert yaml.safe_load((tmp_path / "revisions.yaml").read_text())["rules"][0]["latestVersion"] == 2


def test_app_index_fragment_lists_existing_dirs(tmp_path):
    import yaml
    (tmp_path / "other_rule").mkdir()
    (tmp_path / "other_rule" / "other_rule.yaml").write_text("x: 1\n")
    (tmp_path / "empty_dir").mkdir()
    _pack_convert(tmp_path)
    name = _pack_name_with_file(tmp_path)
    fragment = yaml.safe_load((tmp_path / "appIndex.rules.yaml").read_text())
    assert fragment == {"rules": [{"name": n} for n in sorted(["other_rule", name])]}


def _pack_name_with_file(out_dir):
    return [p.name for p in Path(out_dir).iterdir()
            if p.is_dir() and p.name != "other_rule" and (p / f"{p.name}.yaml").exists()][0]


def test_malformed_revisions_not_overwritten(tmp_path):
    (tmp_path / "revisions.yaml").write_text("rules: notalist\n")
    with pytest.raises(SigmaConfigurationError, match="cannot merge"):
        _pack_convert(tmp_path)
    assert (tmp_path / "revisions.yaml").read_text() == "rules: notalist\n"


def test_workspace_output_dir_unchanged(tmp_path):
    backend = DatabricksBackend(parsers=CS, output_dir=str(tmp_path), catalog_name="c", schema_name="s",
                                 table_name="t")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        msg = backend.convert(_collection(_rule()), "lakewatch")
    assert msg.startswith("# Wrote 1 Lakewatch rule(s) to")
    files = [p.name for p in tmp_path.iterdir()]
    assert len(files) == 1 and files[0].endswith(".yaml") and "revisions.yaml" not in files


# --- hand-formatted revisions.yaml is preserved ---

OTHER_ID = "6f1b9c8e-3c1a-4f0e-9a43-1d2e3f4a5b6c"


def _two_rule_pack(out_dir, description="d"):
    rules = (_rule().replace("status: test", f"status: test\ndescription: {description}"),
             _rule(title="Second Rule", rule_id=OTHER_ID))
    _pack_convert(out_dir, collection=_collection(*rules))


def _styled_revisions(out_dir):
    """Run a conversion, then rewrite revisions.yaml in the hand-formatted crowdstrike style."""
    import hashlib
    _two_rule_pack(out_dir)
    names = sorted(p.name for p in Path(out_dir).iterdir() if p.is_dir())
    hashes = {n: hashlib.sha256((Path(out_dir) / n / f"{n}.yaml").read_bytes()).hexdigest() for n in names}
    first, second = names
    text = (f"rules:\n- name: {first}\n  latestVersion: 3\n  contentHash: {hashes[first]}\n"
            f"  versionNote: >\n    v3: first line of the note,\n    second line of the note.\n"
            f"- name: {second}\n  latestVersion: 1\n  contentHash: {hashes[second]}\n")
    (Path(out_dir) / "revisions.yaml").write_text(text)
    return first, second, hashes, text


def test_revisions_preserves_hand_formatting(tmp_path):
    _, _, _, text = _styled_revisions(tmp_path)
    _two_rule_pack(tmp_path)
    assert (tmp_path / "revisions.yaml").read_text() == text


def test_revisions_bump_drops_only_that_note(tmp_path):
    import hashlib
    first, second, hashes, text = _styled_revisions(tmp_path)
    _two_rule_pack(tmp_path, description="changed")
    new_hash = hashlib.sha256((tmp_path / first / f"{first}.yaml").read_bytes()).hexdigest()
    assert new_hash != hashes[first]
    expected = (f"rules:\n- name: {first}\n  latestVersion: 4\n  contentHash: {new_hash}\n"
                + text[text.index(f"- name: {second}"):])
    assert (tmp_path / "revisions.yaml").read_text() == expected


def test_revisions_new_entry_appended_in_style(tmp_path):
    import hashlib
    first, second, hashes, text = _styled_revisions(tmp_path)
    (tmp_path / second / f"{second}.yaml").unlink()
    (tmp_path / second).rmdir()
    text = text[:text.index(f"- name: {second}")]
    (tmp_path / "revisions.yaml").write_text(text)
    _two_rule_pack(tmp_path)
    new_hash = hashlib.sha256((tmp_path / second / f"{second}.yaml").read_bytes()).hexdigest()
    assert (tmp_path / "revisions.yaml").read_text() == (
        text + f"- name: {second}\n  latestVersion: 1\n  contentHash: {new_hash}\n")


def test_revisions_unsupported_layout_fails(tmp_path):
    _pack_convert(tmp_path)
    name = _pack_name(tmp_path)
    flow = f"rules: [{{name: {name}, latestVersion: 1, contentHash: stale}}]\n"
    (tmp_path / "revisions.yaml").write_text(flow)
    with pytest.raises(SigmaConfigurationError, match="unsupported revisions.yaml layout"):
        _pack_convert(tmp_path)
    assert (tmp_path / "revisions.yaml").read_text() == flow


def test_content_resource_id_index():
    first = content_resource_id(SIGMA_ID, SYSMON, 0)
    assert first == "5974b21f-2777-59c9-8945-d30f12810a8e" == content_resource_id(SIGMA_ID, SYSMON)
    assert content_resource_id(SIGMA_ID, SYSMON, 1) != first


def test_content_pack_multi_query_rule_unique_ids():
    rule = _rule(cond="Image|endswith: '\\powershell.exe'").replace(
        "condition: sel", "condition:\n        - sel\n        - sel and sel")
    backend = DatabricksBackend(target="content_pack", parsers=CS)
    docs = _docs(backend, _collection(rule))
    ids = [d["rule"]["content_resource_id"] for d in docs]
    assert len(ids) == 2 and len(set(ids)) == 2
    assert ids[0] == content_resource_id(SIGMA_ID, CS, 0)
    assert ids[1] == content_resource_id(SIGMA_ID, CS, 1)


def test_content_pack_duplicate_sigma_id_fails():
    backend = DatabricksBackend(target="content_pack", parsers=CS)
    with pytest.raises(SigmaConfigurationError) as e:
        _docs(backend, _collection(_rule(), _rule(title="Other")))
    assert str(e.value).startswith(
        f"duplicate content_resource_id {content_resource_id(SIGMA_ID, CS)} for rules ")
    assert str(e.value).endswith(": Sigma ids must be unique per profile")


def test_unsupported_layout_writes_nothing(tmp_path):
    _pack_convert(tmp_path)
    name = _pack_name(tmp_path)
    flow = f"rules: [{{name: {name}, latestVersion: 1, contentHash: stale}}]\n"
    (tmp_path / "revisions.yaml").write_text(flow)
    rule_file = tmp_path / name / f"{name}.yaml"
    before = rule_file.read_text()
    before_dirs = sorted(p.name for p in tmp_path.iterdir())
    index_before = (tmp_path / "appIndex.rules.yaml").read_text()
    other = _rule(title="Brand new", rule_id="6f1b9c8e-3c1a-4f0e-9a43-1d2e3f4a5b6c")
    with pytest.raises(SigmaConfigurationError, match="unsupported revisions.yaml layout"):
        _pack_convert(tmp_path, description="changed", collection=_collection(_rule(), other))
    assert rule_file.read_text() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == before_dirs
    assert (tmp_path / "appIndex.rules.yaml").read_text() == index_before
