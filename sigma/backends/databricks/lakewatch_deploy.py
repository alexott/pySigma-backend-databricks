"""lakewatch-deploy: upsert converted Lakewatch rule YAML files into a Databricks workspace.

The Databricks SDK is an optional dependency (the ``deploy`` extra) and is never imported at module level.
This part of the module loads and checks the rule files.
"""

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import yaml

EXIT_OK, EXIT_LOCAL, EXIT_REJECTED, EXIT_API = 0, 2, 3, 4

SKIPPED_NAMES = frozenset({"conversion_report.yaml", "revisions.yaml", "appIndex.rules.yaml"})

CONTENT_PACK_MESSAGE = "content-pack documents can't be deployed with lakewatch-deploy; install the pack instead"

_IDENTITY_KEYS = ("catalog_name", "schema_name", "rule_name")


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
            missing = [k for k in _IDENTITY_KEYS if not isinstance(raw.get(k), str) or not raw[k].strip()]
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
