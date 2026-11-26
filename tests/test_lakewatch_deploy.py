"""Tests for lakewatch-deploy packaging and rule file loading."""

import copy
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

import yaml

from sigma.backends.databricks.lakewatch_deploy import (
    EXIT_API,
    EXIT_LOCAL,
    EXIT_OK,
    EXIT_REJECTED,
    IDENTITY_KEYS,
    SKIPPED_NAMES,
    LocalError,
    RuleDoc,
    apply_location,
    load_documents,
    plan_rule,
    subset,
)

CONTENT_PACK_MSG = "content-pack documents can't be deployed with lakewatch-deploy; install the pack instead"


def _rule(name: str, catalog: str = "c", schema: str = "s", sigma_id: str = "id-1", **extra: Any) -> Dict[str, Any]:
    doc: Dict[str, Any] = {
        "catalog_name": catalog,
        "schema_name": schema,
        "rule_name": name,
        "annotations": {"sigma_id": sigma_id},
        "batch": {"sql": {"default_catalog_name": catalog, "default_schema_name": schema, "query": "select 1"}},
        "schedule": {"enabled": False},
    }
    doc.update(extra)
    return doc


def _write(path: Path, *docs: Any) -> str:
    path.write_text("---\n".join(yaml.safe_dump(d) for d in docs))
    return str(path)


def test_constants():
    assert (EXIT_OK, EXIT_LOCAL, EXIT_REJECTED, EXIT_API) == (0, 2, 3, 4)
    assert SKIPPED_NAMES == {"conversion_report.yaml", "revisions.yaml", "appIndex.rules.yaml"}
    assert issubclass(LocalError, Exception)


def test_load_single_and_multi_document(tmp_path):
    single = _write(tmp_path / "one.yaml", _rule("r1"))
    multi = tmp_path / "multi.yaml"
    multi.write_text(yaml.safe_dump(_rule("r2")) + "---\n---\n" + yaml.safe_dump(_rule("r3")))
    docs, errors = load_documents([single, str(multi)])
    assert errors == []
    assert [d.doc["rule_name"] for d in docs] == ["r1", "r2", "r3"]
    assert docs[0].path == single
    assert docs[0].key == ("c", "s", "r1")
    assert docs[0].label == "c.s.r1"


def test_load_directory_sorted_and_skips_reports(tmp_path):
    _write(tmp_path / "b.yaml", _rule("rb"))
    _write(tmp_path / "a.yaml", _rule("ra"))
    _write(tmp_path / "x.yml", _rule("rx"))
    for name in SKIPPED_NAMES:
        _write(tmp_path / name, _rule("skipped_" + name))
    (tmp_path / "sub").mkdir()
    _write(tmp_path / "sub" / "c.yaml", _rule("rc"))
    docs, errors = load_documents([str(tmp_path)])
    assert errors == []
    assert [d.doc["rule_name"] for d in docs] == ["ra", "rb"]


def test_content_pack_document_rejected(tmp_path):
    p1 = _write(tmp_path / "p1.yaml", {"rule": {"name": "x"}})
    p2 = _write(tmp_path / "p2.yaml", {"metadata": {"rule_kind": "panther"}})
    docs, errors = load_documents([p1, p2])
    assert docs == []
    assert errors == [f"{p1}: {CONTENT_PACK_MSG}", f"{p2}: {CONTENT_PACK_MSG}"]


def test_non_mapping_and_missing_keys(tmp_path):
    p1 = _write(tmp_path / "list.yaml", ["a", "b"])
    bad = _rule("r")
    del bad["schema_name"]
    p2 = _write(tmp_path / "nokey.yaml", bad)
    docs, errors = load_documents([p1, p2])
    assert docs == []
    assert errors[0] == f"{p1}: document 1 is not a mapping"
    assert errors[1] == f"{p2}: document 1 lacks schema_name"


def test_missing_keys_listed_and_empty_counts(tmp_path):
    p = _write(tmp_path / "m.yaml", _rule("ok"), {"catalog_name": "", "rule_name": "x"})
    docs, errors = load_documents([p])
    assert len(docs) == 1
    assert errors == [f"{p}: document 2 lacks catalog_name, schema_name"]


def test_bad_yaml_is_error(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("a: [unclosed\n")
    good = _write(tmp_path / "good.yaml", _rule("r"))
    docs, errors = load_documents([str(bad), good])
    assert len(docs) == 1
    assert len(errors) == 1
    assert errors[0].startswith(str(bad))


def test_missing_path_is_error(tmp_path):
    missing = str(tmp_path / "nope.yaml")
    docs, errors = load_documents([missing])
    assert docs == []
    assert len(errors) == 1 and errors[0].startswith(missing)


def test_duplicate_identity_is_local_error(tmp_path):
    multi = _write(tmp_path / "all.yaml", _rule("r1"), _rule("r2"))
    out = tmp_path / "out"
    out.mkdir()
    _write(out / "r1.yaml", _rule("r1"))
    docs, errors = load_documents([multi, str(out)])
    assert len(docs) == 2
    assert len(errors) == 1
    assert "duplicate rule c.s.r1" in errors[0]
    assert errors[0].startswith(str(out / "r1.yaml"))
    assert multi in errors[0]


def test_no_documents_is_error(tmp_path):
    assert load_documents([str(tmp_path)]) == ([], ["no rule documents found"])


def test_apply_location_overrides():
    doc = _rule("r")
    original = copy.deepcopy(doc)
    out = apply_location(doc, "c2", "s2")
    assert doc == original
    assert (out["catalog_name"], out["schema_name"]) == ("c2", "s2")
    assert out["batch"]["sql"]["default_catalog_name"] == "c2"
    assert out["batch"]["sql"]["default_schema_name"] == "s2"
    assert RuleDoc("p", out).key == ("c2", "s2", "r")


def test_apply_location_keeps_foreign_defaults():
    doc = _rule("r")
    doc["batch"]["sql"]["default_schema_name"] = "other"
    out = apply_location(doc, None, "s2")
    assert out["schema_name"] == "s2"
    assert out["catalog_name"] == "c"
    assert out["batch"]["sql"]["default_schema_name"] == "other"
    assert out["batch"]["sql"]["default_catalog_name"] == "c"


def test_load_documents_applies_location(tmp_path):
    p = _write(tmp_path / "r.yaml", _rule("r"))
    docs, errors = load_documents([p], catalog="c2", schema="s2")
    assert errors == []
    assert docs[0].label == "c2.s2.r"


def test_module_imports_without_sdk():
    code = (
        "import sys\n"
        "class Block:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name == 'databricks' or name.startswith('databricks.'):\n"
        "            raise ModuleNotFoundError(name)\n"
        "        return None\n"
        "sys.meta_path.insert(0, Block())\n"
        "import sigma.backends.databricks.lakewatch_deploy\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def _have(want: Dict[str, Any], **over: Any) -> Dict[str, Any]:
    """Build a rule as the server returns it: the document plus server-only keys."""
    have = copy.deepcopy(want)
    have.update(
        rule_id="r-1", name="rules/r-1", etag="e-1", create_time="2026-01-01T00:00:00Z", effective_rule_name="x"
    )
    have["batch"]["server_only"] = {"k": 1}
    have.update(over)
    return have


def test_plan_create():
    want = _rule("a", severity="LOW")
    plan = plan_rule(want, None, False)
    assert plan.action == "create"
    assert plan.body == want
    assert plan.update_mask == []
    assert plan.rule_id is None and plan.etag is None and plan.reason is None
    assert plan.rule_name == "a"


def test_noop_with_server_defaults_omitted():
    want = _rule("a", severity="LOW")
    have = _have(want)
    del have["schedule"]["enabled"]
    for force in (False, True):
        plan = plan_rule(want, have, force)
        assert plan.action == "noop"
        assert plan.body == {} and plan.update_mask == []


def test_subset_rules():
    assert subset({"a": 1}, {"a": 1, "b": 2})
    assert not subset([1, 2], [2, 1])
    assert subset(False, None)
    assert subset(0, None)
    assert subset({"x": ""}, None)
    assert not subset(True, None)
    assert not subset({"a": 1}, {"a": 2})
    assert not subset({"a": 1}, 5)


def test_update_mask_and_body():
    want = _rule("a", severity="LOW", output={"summary": "new"})
    have = _have(_rule("a", severity="HIGH", output={"summary": "old"}))
    plan = plan_rule(want, have, False)
    assert plan.action == "update"
    assert plan.update_mask == ["output", "severity"]
    assert set(plan.body) == {"output", "severity"}
    assert plan.rule_id == "r-1" and plan.etag == "e-1"


def test_identity_keys_never_in_mask():
    assert IDENTITY_KEYS == ("catalog_name", "schema_name", "rule_name")
    want = _rule("a")
    have = _have(want, catalog_name="x", schema_name="y", rule_name="z")
    assert plan_rule(want, have, False).action == "noop"


def test_update_keeps_server_enabled():
    want = _rule("a", title="new")
    have = _have(_rule("a", title="old"))
    have["schedule"]["enabled"] = True
    plan = plan_rule(want, have, False)
    assert plan.action == "update"
    assert plan.update_mask == ["title"]
    assert plan.want["schedule"]["enabled"] is True


def test_schedule_change_keeps_enabled_true():
    want = _rule("a")
    want["schedule"] = {"enabled": False, "interval": "5m"}
    snapshot = copy.deepcopy(want)
    have = _have(_rule("a"))
    have["schedule"] = {"enabled": True, "interval": "1h"}
    plan = plan_rule(want, have, False)
    assert plan.update_mask == ["schedule"]
    assert plan.body["schedule"] == {"enabled": True, "interval": "5m"}
    assert want == snapshot


def test_conflict_and_overwrite():
    want = _rule("a", severity="LOW")
    have = _have(_rule("a", sigma_id="other", severity="HIGH"))
    reason = "exists and was not made from this Sigma rule (server sigma_id: other, file sigma_id: id-1)"
    plan = plan_rule(want, have, False)
    assert plan.action == "conflict" and plan.body == {} and plan.reason == reason
    plan = plan_rule(want, have, True)
    assert plan.action == "overwrite" and plan.update_mask == ["annotations", "severity"]
    assert set(plan.body) == {"annotations", "severity"} and plan.reason == reason
    bare = _have(want)
    del bare["annotations"]
    plan = plan_rule(want, bare, False)
    assert plan.action == "conflict"
    assert plan.reason is not None and "server sigma_id: none" in plan.reason


def test_no_sigma_id_never_owned():
    want = _rule("a")
    del want["annotations"]
    have = _have(want)
    assert plan_rule(want, have, False).action == "conflict"
    assert plan_rule(want, have, True).action == "noop"
