"""Tests for lakewatch-rule-deploy packaging and rule file loading."""

import copy
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest
import yaml

from sigma.backends.databricks.lakewatch_rule_deploy import (
    EXIT_API,
    EXIT_LOCAL,
    EXIT_OK,
    EXIT_REJECTED,
    IDENTITY_KEYS,
    SKIPPED_NAMES,
    LocalError,
    Outcome,
    RuleDoc,
    SdkRuleClient,
    apply_location,
    build_parser,
    deploy,
    exit_code,
    format_json,
    format_text,
    load_documents,
    main,
    make_client,
    plan_rule,
    subset,
)

CONTENT_PACK_MSG = "content-pack documents can't be deployed with lakewatch-rule-deploy; install the pack instead"


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
        "import sigma.backends.databricks.lakewatch_rule_deploy\n"
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


MISSING_EXTRA_MSG = 'lakewatch-rule-deploy needs the deploy extra: pip install "pySigma-backend-databricks[deploy]"'


class FakeApi:
    """Record ``do`` calls and return queued responses."""

    def __init__(self, *responses: Any) -> None:
        """Queue the responses."""
        self.responses: List[Any] = list(responses)
        self.calls: List[Dict[str, Any]] = []

    def do(
        self,
        method: str,
        path: Optional[str] = None,
        query: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Record the call and return the next queued response."""
        self.calls.append(
            {
                "method": method,
                "path": path,
                "query": None if query is None else dict(query),
                "headers": headers,
                "body": body,
            }
        )
        return self.responses.pop(0) if self.responses else {}


def _client(*responses: Any, workspace_id: Optional[str] = "123") -> "tuple[SdkRuleClient, FakeApi]":
    api = FakeApi(*responses)
    w = SimpleNamespace(api_client=api, config=SimpleNamespace(workspace_id=workspace_id))
    return SdkRuleClient(w), api


def test_list_rules_pages_and_filters():
    client, api = _client(
        {
            "rules": [{"rule_name": "a", "schema_name": "s"}, {"rule_name": "b", "schema_name": "other"}],
            "next_page_token": "t",
        },
        {},
    )
    assert client.list_rules("c", "s") == [{"rule_name": "a", "schema_name": "s"}]
    assert len(api.calls) == 2
    assert all(c["method"] == "GET" and c["path"] == "/api/2.0/lakewatch/rules" for c in api.calls)
    assert all(
        c["query"]["catalog_name"] == "c" and c["query"]["schema_name"] == "s" and c["query"]["page_size"] == 100
        for c in api.calls
    )
    assert api.calls[1]["query"]["page_token"] == "t"


def test_headers():
    client, api = _client({})
    client.list_rules("c", "s")
    assert api.calls[0]["headers"] == {"Accept": "application/json", "X-Databricks-Workspace-Id": "123"}
    client, api = _client({})
    client.create({"rule_name": "a"})
    assert api.calls[0]["headers"] == {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Databricks-Workspace-Id": "123",
    }
    client, api = _client({}, workspace_id=None)
    client.list_rules("c", "s")
    assert api.calls[0]["headers"] == {"Accept": "application/json"}


def test_create_sends_unmodeled_fields():
    client, api = _client({"rule_id": "1"})
    rule = _rule("a", x_custom=1)
    assert client.create(rule) == {"rule_id": "1"}
    assert api.calls[0]["method"] == "POST"
    assert api.calls[0]["path"] == "/api/2.0/lakewatch/rules"
    assert api.calls[0]["body"] == rule
    assert api.calls[0]["body"]["x_custom"] == 1


def test_listed_unmodeled_fields_kept():
    client, _ = _client({"rules": [{"rule_name": "a", "schema_name": "s", "x_custom": {"a": 1}}]})
    assert client.list_rules("c", "s")[0]["x_custom"] == {"a": 1}


def test_update_request():
    client, api = _client({"rule_id": "42"}, {})
    assert client.update("42", {"severity": "High"}, ["severity"], "e1") == {"rule_id": "42"}
    call = api.calls[0]
    assert call["method"] == "PATCH"
    assert call["path"] == "/api/2.0/lakewatch/rules/42"
    assert call["query"] == {"update_mask": "severity", "etag": "e1"}
    assert call["body"] == {"severity": "High"}
    client.update("42", {"severity": "High", "title": "t"}, ["severity", "title"], "")
    assert api.calls[1]["query"] == {"update_mask": "severity,title"}


def test_validate_request_and_errors():
    errors = [{"error_code": "X", "field_path": "a", "message": "m"}]
    client, api = _client({"errors": errors}, {}, None, {"errors": []})
    r = _rule("a")
    assert client.validate(r, ["a", "b"], "w1") == errors
    call = api.calls[0]
    assert call["method"] == "POST"
    assert call["path"] == "/api/2.0/lakewatch/rules:validateRule"
    assert call["body"] == {"rule": r, "update_mask": "a,b", "warehouse": "w1"}
    assert client.validate(r, ["a"], "w1") == []
    assert client.validate(r, ["a"], "w1") == []
    assert client.validate(r, None, None) == []
    assert api.calls[3]["body"] == {"rule": r}
    client.validate(r, [], None)
    assert api.calls[4]["body"] == {"rule": r}


def test_make_client_missing_sdk(monkeypatch):
    monkeypatch.setitem(sys.modules, "databricks.sdk", None)
    monkeypatch.setitem(sys.modules, "databricks.sdk.errors", None)
    with pytest.raises(LocalError) as exc:
        make_client(None)
    assert str(exc.value) == MISSING_EXTRA_MSG


def _fake_sdk(monkeypatch, workspace_client):
    class DatabricksError(Exception):
        pass

    sdk = SimpleNamespace(WorkspaceClient=workspace_client)
    monkeypatch.setitem(sys.modules, "databricks", SimpleNamespace(sdk=sdk))
    monkeypatch.setitem(sys.modules, "databricks.sdk", sdk)
    monkeypatch.setitem(sys.modules, "databricks.sdk.errors", SimpleNamespace(DatabricksError=DatabricksError))


def test_make_client_bad_profile(monkeypatch):
    def boom(**kwargs: Any) -> Any:
        raise ValueError("no such profile")

    _fake_sdk(monkeypatch, boom)
    with pytest.raises(LocalError, match="no such profile"):
        make_client("missing")


def test_make_client_passes_profile(monkeypatch):
    seen: List[Dict[str, Any]] = []

    def fake(**kwargs: Any) -> Any:
        seen.append(kwargs)
        return SimpleNamespace(api_client=FakeApi(), config=SimpleNamespace(workspace_id=None))

    _fake_sdk(monkeypatch, fake)
    assert isinstance(make_client("p"), SdkRuleClient)
    make_client(None)
    assert seen == [{"profile": "p"}, {}]


NOTE = "note: creating or updating a rule starts a one-time run of it on the server"
SUMMARY = "created 1, updated 1, overwritten 0, unchanged 1, conflicts 0, invalid 0, errors 0"


class FakeClient:
    """An in-memory RuleClient that records its calls."""

    def __init__(self, listed=None, invalid=None, list_fails=(), write_fails=()):
        """Set up the listed rules, validate errors and failing operations."""
        self.listed = listed or {}
        self.invalid = invalid or {}
        self.list_fails = set(list_fails)
        self.write_fails = set(write_fails)
        self.calls: List[tuple] = []

    def list_rules(self, catalog, schema):
        """List the configured rules."""
        self.calls.append(("list", catalog, schema))
        if (catalog, schema) in self.list_fails:
            raise OSError("boom")
        return self.listed.get((catalog, schema), [])

    def create(self, rule):
        """Record a create."""
        self.calls.append(("create", rule))
        if rule["rule_name"] in self.write_fails:
            raise OSError("write boom")
        return rule

    def update(self, rule_id, fields, update_mask, etag):
        """Record an update."""
        self.calls.append(("update", rule_id, fields, update_mask, etag))
        if rule_id in self.write_fails:
            raise OSError("write boom")
        return fields

    def validate(self, rule, update_mask, warehouse):
        """Record a validation."""
        self.calls.append(("validate", rule, update_mask, warehouse))
        return self.invalid.get(rule["rule_name"], [])

    def of(self, kind):
        """Return the recorded calls of ``kind``."""
        return [c for c in self.calls if c[0] == kind]


def _docs(*rules):
    return [RuleDoc(f"{r['rule_name']}.yaml", r) for r in rules]


def _server(rule, rule_id, etag="e1", **over):
    have = copy.deepcopy(rule)
    have.update({"rule_id": rule_id, "etag": etag})
    have.update(over)
    return have


def _run(docs, client, mode="deploy", force=False, warehouse_id=None):
    return deploy(docs, client, mode=mode, force=force, warehouse_id=warehouse_id)


def _three():
    new, changed, same = _rule("new"), _rule("changed", sigma_id="a"), _rule("same")
    listed = {
        ("c", "s"): [
            _server(_rule("changed", sigma_id="a", extra_field=1), "id-changed", "etag-c") | {"batch": {"sql": {}}},
            _server(same, "id-same"),
        ]
    }
    return [new, changed, same], listed


def test_deploy_creates_updates_skips():
    rules, listed = _three()
    client = FakeClient(listed)
    outcomes = _run(_docs(*rules), client)
    assert [(o.rule, o.action, o.status) for o in outcomes] == [
        ("c.s.new", "create", "created"),
        ("c.s.changed", "update", "updated"),
        ("c.s.same", "noop", "unchanged"),
    ]
    assert len(client.of("create")) == 1 and len(client.of("update")) == 1
    _, rule_id, fields, mask, etag = client.of("update")[0]
    assert (rule_id, etag) == ("id-changed", "etag-c")
    assert mask == ["batch"] and set(fields) == {"batch"}
    text = format_text(outcomes, "deploy")
    assert SUMMARY in text
    assert text.rstrip().splitlines()[-1] == NOTE
    assert "  update_mask: batch" in text
    assert exit_code(outcomes, False) == EXIT_OK
    assert client.calls[0] == ("list", "c", "s") and len(client.of("list")) == 1


def test_validate_before_write():
    rules, listed = _three()
    client = FakeClient(listed)
    _run(_docs(*rules), client, warehouse_id="wh")
    kinds = [c[0] for c in client.calls]
    assert kinds == ["list", "validate", "create", "validate", "update"]
    upd_validate = client.of("validate")[1]
    assert upd_validate[1]["name"] == "rules/id-changed"
    assert upd_validate[2] == ["batch"] and upd_validate[3] == "wh"
    assert "name" not in client.of("validate")[0][1] and client.of("validate")[0][2] is None


def test_validate_not_called_for_noop_or_conflict():
    rule = _rule("x")
    client = FakeClient({("c", "s"): [_server(_rule("x", sigma_id="other"), "i")]})
    out = _run(_docs(rule), client)
    assert out[0].status == "conflict" and not client.of("validate")
    client = FakeClient({("c", "s"): [_server(rule, "i")]})
    assert _run(_docs(rule), client)[0].status == "unchanged" and not client.of("validate")


def test_warehouse_falls_back_to_rule():
    rule = _rule("x")
    rule["batch"]["warehouse_id"] = "rule-wh"
    client = FakeClient()
    _run(_docs(rule), client)
    assert client.of("validate")[0][3] == "rule-wh"


def test_invalid_rule_skipped():
    a, b = _rule("a"), _rule("b")
    err = {"error_code": "BAD", "field_path": "batch.sql", "message": "nope"}
    client = FakeClient(invalid={"a": [err]})
    out = _run(_docs(a, b), client)
    assert [o.status for o in out] == ["invalid", "created"]
    assert [c[1]["rule_name"] for c in client.of("create")] == ["b"]
    assert "  BAD batch.sql: nope" in format_text(out, "deploy")
    assert exit_code(out, False) == EXIT_REJECTED


def test_conflict_and_force():
    rule = _rule("x")
    listed = {("c", "s"): [_server(_rule("x", sigma_id="other", enabled=True), "i")]}
    client = FakeClient(listed)
    out = _run(_docs(rule), client)
    assert out[0].status == "conflict" and not client.of("create") and not client.of("update")
    assert exit_code(out, False) == EXIT_REJECTED
    assert "exists and was not made from this Sigma rule" in format_text(out, "deploy")
    client = FakeClient(listed)
    out = _run(_docs(rule), client, force=True)
    assert (out[0].action, out[0].status) == ("overwrite", "overwritten")
    assert exit_code(out, True) == EXIT_OK
    text = format_text(out, "deploy")
    assert "server sigma_id: other, file sigma_id: id-1" in text
    assert "overwritten 1" in text and len(client.of("update")) == 1


@pytest.mark.parametrize(
    "mode,prefix", [("dry_run", "dry run: would create 1"), ("validate_only", "validate only: would create 1")]
)
def test_dry_run_and_validate_only_write_nothing(mode, prefix):
    rules, listed = _three()
    client = FakeClient(listed)
    out = _run(_docs(*rules), client, mode=mode)
    assert not client.of("create") and not client.of("update")
    assert len(client.of("validate")) == 2
    assert [o.status for o in out] == ["planned", "planned", "unchanged"]
    text = format_text(out, mode)
    assert NOTE not in text
    summary = text.rstrip().splitlines()[-1]
    assert summary == prefix + ", would update 1, would overwrite 0, unchanged 1, conflicts 0, invalid 0, errors 0"
    if mode == "dry_run":
        assert '\n    {\n      "catalog_name": "c"' in text
    else:
        assert '"catalog_name"' not in text
        assert all(o.body is None for o in out)


def test_list_failure_isolated_per_schema():
    a, b, c = _rule("a", schema="s1"), _rule("b", schema="s1"), _rule("c", schema="s2")
    client = FakeClient(list_fails=[("c", "s1")])
    out = _run(_docs(a, b, c), client)
    assert [(o.action, o.status) for o in out] == [
        ("unplanned", "error"),
        ("unplanned", "error"),
        ("create", "created"),
    ]
    assert out[0].details == ["API error: boom"]
    assert exit_code(out, False) == EXIT_API
    assert [c_[2] for c_ in client.of("list")] == ["s1", "s2"]


def test_write_error_continues():
    a, b = _rule("a"), _rule("b")
    client = FakeClient(write_fails=["a"])
    out = _run(_docs(a, b), client)
    assert [o.status for o in out] == ["error", "created"]
    assert out[0].details == ["API error: write boom"]
    assert len(client.of("create")) == 2
    assert exit_code(out, False) == EXIT_API


def test_exit_code_precedence():
    def o(status):
        return Outcome("r", "a", status, [])

    assert exit_code([o("conflict"), o("invalid"), o("error")], False) == EXIT_API
    assert exit_code([o("conflict")], False) == EXIT_REJECTED
    assert exit_code([o("conflict")], True) == EXIT_OK
    assert exit_code([o("invalid")], True) == EXIT_REJECTED
    assert exit_code([], False) == EXIT_OK


def test_json_output():
    rules, listed = _three()
    out = _run(_docs(*rules), FakeClient(listed), mode="dry_run")
    data = json.loads(format_json(out, "dry_run"))
    assert set(data) == {"rules", "summary"}
    assert data["rules"][0]["body"]["rule_name"] == "new"
    assert set(data["rules"][0]) == {"rule", "action", "status", "details", "body"}
    assert data["summary"] == {
        "created": 1, "updated": 1, "overwritten": 0, "unchanged": 1,
        "conflicts": 0, "invalid": 0, "errors": 0, "mode": "dry_run",
    }  # fmt: skip
    out = _run(_docs(*rules), FakeClient(listed))
    data = json.loads(format_json(out, "deploy"))
    assert set(data["rules"][0]) == {"rule", "action", "status", "details"}
    assert data["summary"]["mode"] == "deploy" and data["summary"]["created"] == 1


def test_main_local_errors_before_client(tmp_path, capsys):
    pack = _write(tmp_path / "pack.yaml", {"rule": {}, "metadata": {"rule_kind": "x"}})

    def factory(profile):
        raise AssertionError("client must not be built")

    assert main([pack], client_factory=factory) == EXIT_LOCAL
    captured = capsys.readouterr()
    assert CONTENT_PACK_MSG in captured.err and captured.out == ""


def test_main_missing_sdk(tmp_path, capsys):
    path = _write(tmp_path / "r.yaml", _rule("r"))

    def factory(profile):
        raise LocalError("lakewatch-rule-deploy needs the deploy extra")

    assert main([path], client_factory=factory) == EXIT_LOCAL
    captured = capsys.readouterr()
    assert "needs the deploy extra" in captured.err and captured.out == ""


def test_main_flags(tmp_path, capsys):
    path = _write(tmp_path / "r.yaml", _rule("r"))
    client = FakeClient({("cat2", "sch2"): [_server(_rule("r", catalog="cat2", schema="sch2", sigma_id="z"), "rid")]})
    seen = []

    def factory(profile):
        seen.append(profile)
        return client

    rc = main(
        [path, "--catalog", "cat2", "--schema", "sch2", "--warehouse-id", "w1", "--force", "--json", "--profile", "p"],
        client_factory=factory,
    )
    assert rc == EXIT_OK and seen == ["p"]
    assert client.of("list")[0][1:] == ("cat2", "sch2")
    assert client.of("validate")[0][3] == "w1"
    assert client.of("update")[0][1] == "rid"
    data = json.loads(capsys.readouterr().out)
    assert data["rules"][0]["status"] == "overwritten" and data["summary"]["mode"] == "deploy"


def test_main_text_to_stdout_and_modes(tmp_path, capsys):
    path = _write(tmp_path / "r.yaml", _rule("r"))
    client = FakeClient()
    assert main([path, "--dry-run"], client_factory=lambda p: client) == EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("planned c.s.r") and "dry run: would create 1" in out
    assert not client.of("create")


def test_main_exclusive_modes(tmp_path):
    path = _write(tmp_path / "r.yaml", _rule("r"))
    with pytest.raises(SystemExit) as exc:
        main([path, "--dry-run", "--validate-only"], client_factory=lambda p: FakeClient())
    assert exc.value.code == 2
    assert build_parser().parse_args(["a", "b"]).paths == ["a", "b"]


def test_error_line_joins_present_parts():
    from sigma.backends.databricks.lakewatch_rule_deploy import _error_line

    assert _error_line({"message": "msg"}) == "msg"
    assert _error_line({"error_code": "CODE", "message": "msg"}) == "CODE: msg"
    assert _error_line({"field_path": "path", "message": "msg"}) == "path: msg"
    assert _error_line({"error_code": "CODE", "field_path": "path", "message": "msg"}) == "CODE path: msg"


def test_json_formatting_tolerates_dates():
    import datetime

    outcome = Outcome("c.s.r", "create", "planned", [], {"when": datetime.date(2026, 1, 2)})
    assert "2026-01-02" in format_text([outcome], "dry_run")
    assert "2026-01-02" in format_json([outcome], "dry_run")


def test_plan_rule_tolerates_non_dict_annotations_and_schedule():
    want = _rule("a", schedule={"enabled": True})
    plan = plan_rule(want, _server(want, "i", annotations="x"), False)
    assert plan.action == "conflict"
    plan = plan_rule(want, _server(want, "i", schedule="x"), False)
    assert plan.action == "update" and plan.want["schedule"]["enabled"] is False
    bad_file = _rule("a", annotations="x")
    assert plan_rule(bad_file, _server(_rule("a"), "i"), False).action == "conflict"


def test_planning_exception_becomes_error_outcome(monkeypatch):
    import sigma.backends.databricks.lakewatch_rule_deploy as mod

    real = mod.plan_rule

    def flaky(want, have, force):
        if want["rule_name"] == "bad":
            raise RuntimeError("kaboom")
        return real(want, have, force)

    monkeypatch.setattr(mod, "plan_rule", flaky)
    client = FakeClient()
    outcomes = _run(_docs(_rule("one"), _rule("bad"), _rule("two")), client)
    assert [(o.rule, o.action, o.status) for o in outcomes] == [
        ("c.s.one", "create", "created"),
        ("c.s.bad", "unplanned", "error"),
        ("c.s.two", "create", "created"),
    ]
    assert outcomes[1].details == ["error: kaboom"]
    assert exit_code(outcomes, False) == EXIT_API
