"""Identifiers for Lakewatch content-pack documents."""

import hashlib
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence
from uuid import NAMESPACE_URL, uuid5

import yaml
from sigma.exceptions import SigmaConfigurationError

CONTENT_RESOURCE_NAMESPACE = uuid5(
    NAMESPACE_URL, "https://github.com/alexott/databricks-sigma-backend#lakewatch-content-resource")


def content_resource_id(sigma_id: str, profile: str) -> str:
    """Stable content_resource_id of the rule converted for a profile (from the Sigma id)."""
    return str(uuid5(CONTENT_RESOURCE_NAMESPACE, f"{sigma_id.lower()}:{profile}"))


def merge_revisions(existing: Optional[Dict[str, Any]], hashes: Mapping[str, str]) -> Dict[str, Any]:
    """Merge content hashes into a ``revisions.yaml`` mapping (pure).

    Unchanged entries stay as they are, changed hashes bump ``latestVersion`` and drop
    ``versionNote``, new rules are appended with version 1, and entries not in ``hashes`` are kept.
    """
    entries = [dict(entry) for entry in (existing or {}).get("rules", [])]
    by_name = {entry["name"]: entry for entry in entries}
    for name, digest in hashes.items():
        entry = by_name.get(name)
        if entry is None:
            entry = {"name": name, "latestVersion": 1, "contentHash": digest}
            entries.append(entry)
            by_name[name] = entry
        elif entry.get("contentHash") != digest:
            entry["latestVersion"] = int(entry.get("latestVersion", 0)) + 1
            entry["contentHash"] = digest
            entry.pop("versionNote", None)
    return {"rules": entries}


def rule_dirs(directory: Path) -> List[str]:
    """Sorted names of subdirectories of ``directory`` that contain ``<name>.yaml``."""
    return sorted(p.name for p in directory.iterdir() if p.is_dir() and (p / f"{p.name}.yaml").is_file())


def _load_revisions(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise SigmaConfigurationError(f"cannot merge {path}: invalid YAML ({e})") from None
    if (not isinstance(data, dict) or not isinstance(data.get("rules"), list)
            or not all(isinstance(r, dict) and "name" in r for r in data["rules"])):
        raise SigmaConfigurationError(
            f"cannot merge {path}: expected a mapping with a 'rules' list of entries with a name")
    return data


def write_pack(documents: Sequence[Dict[str, Any]], output_dir: str,
               dump: Callable[[Dict[str, Any]], str]) -> str:
    """Write content-pack documents into a pack ``rules/`` directory.

    Writes ``<dir>/<rule_name>/<rule_name>.yaml``, merges ``<dir>/revisions.yaml`` and writes
    the ``<dir>/appIndex.rules.yaml`` fragment listing every rule directory.
    """
    directory = Path(output_dir).expanduser()
    try:
        directory.mkdir(parents=True, exist_ok=True)
        revisions_path = directory / "revisions.yaml"
        existing = _load_revisions(revisions_path)
        hashes: Dict[str, str] = {}
        for doc in documents:
            name = doc["rule"]["rule_name"]
            data = dump(doc).encode("utf-8")
            rule_dir = directory / name
            rule_dir.mkdir(exist_ok=True)
            (rule_dir / f"{name}.yaml").write_bytes(data)
            hashes[name] = hashlib.sha256(data).hexdigest()
        merged = yaml.safe_dump(merge_revisions(existing, hashes), sort_keys=False)
        if not revisions_path.is_file() or revisions_path.read_text(encoding="utf-8") != merged:
            revisions_path.write_text(merged, encoding="utf-8")
        fragment = yaml.safe_dump({"rules": [{"name": n} for n in rule_dirs(directory)]}, sort_keys=False)
        (directory / "appIndex.rules.yaml").write_text(fragment, encoding="utf-8")
    except OSError as e:
        raise SigmaConfigurationError(f"cannot write rules to output_dir {directory}: {e}") from None
    return f"# Wrote {len(documents)} Lakewatch content-pack rule(s) to {directory}"
