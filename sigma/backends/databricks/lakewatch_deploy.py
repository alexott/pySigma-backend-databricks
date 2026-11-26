"""lakewatch-deploy: upsert converted Lakewatch rule YAML files into a Databricks workspace.

The Databricks SDK is an optional dependency (the ``deploy`` extra) and is never imported at module level.
This part of the module loads the rule files and plans the upsert of each rule.
"""

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import yaml

EXIT_OK, EXIT_LOCAL, EXIT_REJECTED, EXIT_API = 0, 2, 3, 4

SKIPPED_NAMES = frozenset({"conversion_report.yaml", "revisions.yaml", "appIndex.rules.yaml"})

CONTENT_PACK_MESSAGE = "content-pack documents can't be deployed with lakewatch-deploy; install the pack instead"

IDENTITY_KEYS = ("catalog_name", "schema_name", "rule_name")


class LocalError(Exception):
    """An error in the input or the environment that is found before any API call (exit code 2)."""


@dataclass
class RuleDoc:
    """A workspace rule document together with the file it was read from."""

    path: str
    doc: Dict[str, Any]

    @property
    def key(self) -> Tuple[str, str, str]:
        """Return the identity ``(catalog_name, schema_name, rule_name)`` of the rule."""
        return (self.doc["catalog_name"], self.doc["schema_name"], self.doc["rule_name"])

    @property
    def label(self) -> str:
        """Return the identity as ``catalog.schema.rule``."""
        return ".".join(self.key)


def apply_location(doc: Dict[str, Any], catalog: Optional[str], schema: Optional[str]) -> Dict[str, Any]:
    """Return a deep copy of ``doc`` retargeted to ``catalog`` and ``schema``.

    The ``batch.sql`` default catalog and schema change only when they equal the value being replaced.
    """
    out = copy.deepcopy(doc)
    sql = (out.get("batch") or {}).get("sql")
    for value, key, default_key in (
        (catalog, "catalog_name", "default_catalog_name"),
        (schema, "schema_name", "default_schema_name"),
    ):
        if value is None:
            continue
        if isinstance(sql, dict) and sql.get(default_key) == out.get(key):
            sql[default_key] = value
        out[key] = value
    return out


def _expand(path: str) -> List[Path]:
    p = Path(path)
    if p.is_dir():
        return sorted(f for f in p.glob("*.yaml") if f.is_file() and f.name not in SKIPPED_NAMES)
    return [p]


def _is_content_pack(doc: Dict[str, Any]) -> bool:
    metadata = doc.get("metadata")
    return "rule" in doc or (isinstance(metadata, dict) and "rule_kind" in metadata)


def _read_file(path: Path, catalog: Optional[str], schema: Optional[str], errors: List[str]) -> List[RuleDoc]:
    try:
        raw_docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
        errors.append(f"{path}: {str(exc).strip() or type(exc).__name__}")
        return []
    found: List[RuleDoc] = []
    for number, raw in enumerate(raw_docs, start=1):
        if raw is None:
            continue
        if not isinstance(raw, dict):
            errors.append(f"{path}: document {number} is not a mapping")
        elif _is_content_pack(raw):
            errors.append(f"{path}: {CONTENT_PACK_MESSAGE}")
        else:
            missing = [k for k in IDENTITY_KEYS if not isinstance(raw.get(k), str) or not raw[k].strip()]
            if missing:
                errors.append(f"{path}: document {number} lacks {', '.join(missing)}")
            else:
                found.append(RuleDoc(str(path), apply_location(raw, catalog, schema)))
    return found


def load_documents(
    paths: Sequence[str], catalog: Optional[str] = None, schema: Optional[str] = None
) -> Tuple[List[RuleDoc], List[str]]:
    """Load workspace rule documents from files and directories.

    Returns ``(docs, errors)`` and never raises for bad input. Every error string starts with a path,
    except ``no rule documents found``.
    """
    docs: List[RuleDoc] = []
    errors: List[str] = []
    first_seen: Dict[Tuple[str, str, str], str] = {}
    for path in paths:
        try:
            files = _expand(path)
        except OSError as exc:
            errors.append(f"{path}: {exc}")
            continue
        for file in files:
            for rule in _read_file(file, catalog, schema, errors):
                if rule.key in first_seen:
                    errors.append(f"{rule.path}: duplicate rule {rule.label} (first seen in {first_seen[rule.key]})")
                else:
                    first_seen[rule.key] = rule.path
                    docs.append(rule)
    if not docs and not errors:
        errors.append("no rule documents found")
    return docs, errors


def subset(want: Any, have: Any) -> bool:
    """Return True when ``want`` is contained in ``have``.

    Dicts are compared recursively and extra server keys are ignored. A missing server value (``None``)
    matches a default ``want`` (``False``, ``0``, ``""``, ``[]``, ``{}`` or ``None``). Everything else uses ``==``.
    """
    if isinstance(want, dict):
        if have is None:
            have = {}
        if not isinstance(have, dict):
            return False
        return all(subset(value, have.get(key)) for key, value in want.items())
    if have is None:
        return not want
    return bool(want == have)


@dataclass
class Plan:
    """The action to take for one rule."""

    action: str
    rule_name: str
    update_mask: List[str]
    body: Dict[str, Any]
    rule_id: Optional[str]
    etag: Optional[str]
    reason: Optional[str]
    want: Dict[str, Any]


def _sigma_id(rule: Dict[str, Any]) -> Optional[str]:
    return (rule.get("annotations") or {}).get("sigma_id")


def plan_rule(want: Dict[str, Any], have: Optional[Dict[str, Any]], force: bool) -> Plan:
    """Decide how to upsert ``want`` given the server's rule ``have`` (``None`` when it doesn't exist)."""
    name = want["rule_name"]
    if have is None:
        return Plan("create", name, [], copy.deepcopy(want), None, None, None, want)

    rule_id, etag = have.get("rule_id"), have.get("etag")
    want_id, have_id = _sigma_id(want), _sigma_id(have)
    owned = have_id is not None and have_id == want_id
    reason = None
    if not owned:
        reason = (
            "exists and was not made from this Sigma rule "
            f"(server sigma_id: {have_id or 'none'}, file sigma_id: {want_id or 'none'})"
        )
        if not force:
            return Plan("conflict", name, [], {}, rule_id, etag, reason, want)

    adjusted = copy.deepcopy(want)
    if isinstance(adjusted.get("schedule"), dict):
        adjusted["schedule"]["enabled"] = bool((have.get("schedule") or {}).get("enabled", False))
    changed = sorted(k for k, v in adjusted.items() if k not in IDENTITY_KEYS and not subset(v, have.get(k)))
    if not changed:
        return Plan("noop", name, [], {}, rule_id, etag, None, adjusted)
    action = "update" if owned else "overwrite"
    return Plan(action, name, changed, {k: adjusted[k] for k in changed}, rule_id, etag, reason, adjusted)
