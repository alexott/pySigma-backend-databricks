"""Identifiers for Lakewatch content-pack documents."""

import hashlib
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from uuid import NAMESPACE_URL, uuid5

import yaml
from sigma.exceptions import SigmaConfigurationError

CONTENT_RESOURCE_NAMESPACE = uuid5(
    NAMESPACE_URL, "https://github.com/alexott/databricks-sigma-backend#lakewatch-content-resource")


def content_resource_id(sigma_id: str, profile: str, index: int = 0) -> str:
    """Stable content_resource_id of the rule converted for a profile (from the Sigma id).

    ``index`` is the position of the query when a rule yields several (a condition list); index 0
    keeps the plain ``<id>:<profile>`` name.
    """
    name = f"{sigma_id.lower()}:{profile}" + (f":{index}" if index else "")
    return str(uuid5(CONTENT_RESOURCE_NAMESPACE, name))


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


_ITEM_RE = re.compile(r"^(\s*)- name:\s*(.*?)\s*$")


def _scalar(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    return text


def _edit_revisions_text(text: str, existing: Dict[str, Any], hashes: Mapping[str, str]) -> str:
    """Apply the ``merge_revisions`` result to the text of ``revisions.yaml`` line by line.

    Only changed entries' ``latestVersion``/``contentHash`` lines are rewritten and their
    ``versionNote`` is removed; new entries are appended; everything else stays byte-identical.
    """
    lines = text.splitlines(keepends=True)
    start = next((i for i, ln in enumerate(lines) if re.match(r"^rules:\s*$", ln)), None)
    if start is None:
        return text
    items: List[Tuple[str, int, int, str]] = []  # name, first line, end line (exclusive), indent
    for i in range(start + 1, len(lines)):
        m = _ITEM_RE.match(lines[i])
        if m and (not items or m.group(1) == items[-1][3]):
            if items:
                items[-1] = (items[-1][0], items[-1][1], i, items[-1][3])
            items.append((_scalar(m.group(2)), i, len(lines), m.group(1)))
        elif lines[i].strip() and not lines[i][0].isspace() and not lines[i].startswith("- "):
            if items:
                items[-1] = (items[-1][0], items[-1][1], i, items[-1][3])
            break
    current = {e["name"]: e for e in existing["rules"]}
    out = lines[:]
    for name, first, end, indent in reversed(items):
        entry = current.get(name)
        if entry is None or name not in hashes or entry.get("contentHash") == hashes[name]:
            continue
        key = " " * (len(indent) + 2)
        block: List[str] = []
        skipping = False
        for ln in lines[first:end]:
            if skipping and (not ln.strip() or ln.startswith(key + " ") or ln.startswith(key + "\t")):
                continue
            skipping = False
            if ln.startswith(key + "versionNote:"):
                skipping = True
                continue
            m = re.match(rf"^({re.escape(key)}latestVersion:\s*)(\d+)(\s*)$", ln, re.S)
            if m:
                ln = f"{m.group(1)}{int(m.group(2)) + 1}{m.group(3)}"
            elif re.match(rf"^{re.escape(key)}contentHash:", ln):
                ln = f"{key}contentHash: {hashes[name]}\n"
            block.append(ln)
        out[first:end] = block
    new = [n for n in hashes if n not in current]
    if new and items:
        indent = items[-1][3]
        key = " " * (len(indent) + 2)
        last = max(i for i, ln in enumerate(out) if ln.strip() and i > start)
        # the last non-blank line within the rules section
        if not out[last].endswith("\n"):
            out[last] += "\n"
        added = [f"{indent}- name: {n}\n{key}latestVersion: 1\n{key}contentHash: {hashes[n]}\n" for n in new]
        out[last + 1:last + 1] = added
    return "".join(out)


def _merge_revisions_text(path: Path, existing: Optional[Dict[str, Any]], hashes: Mapping[str, str]) -> str:
    expected = merge_revisions(existing, hashes)
    if existing is None:
        return yaml.safe_dump(expected, sort_keys=False)
    text = path.read_text(encoding="utf-8")
    edited = _edit_revisions_text(text, existing, hashes)
    try:
        ok = yaml.safe_load(edited) == expected
    except yaml.YAMLError:
        ok = False
    if not ok:
        raise SigmaConfigurationError(f"cannot merge {path}: unsupported revisions.yaml layout")
    return edited


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
        payloads: Dict[str, bytes] = {}
        for doc in documents:
            name = doc["rule"]["rule_name"]
            payloads[name] = dump(doc).encode("utf-8")
            hashes[name] = hashlib.sha256(payloads[name]).hexdigest()
        # Validate the revisions layout before anything is written.
        merged = _merge_revisions_text(revisions_path, existing, hashes)
        for name, data in payloads.items():
            rule_dir = directory / name
            rule_dir.mkdir(exist_ok=True)
            (rule_dir / f"{name}.yaml").write_bytes(data)
        if not revisions_path.is_file() or revisions_path.read_text(encoding="utf-8") != merged:
            revisions_path.write_text(merged, encoding="utf-8")
        fragment = yaml.safe_dump({"rules": [{"name": n} for n in rule_dirs(directory)]}, sort_keys=False)
        (directory / "appIndex.rules.yaml").write_text(fragment, encoding="utf-8")
    except OSError as e:
        raise SigmaConfigurationError(f"cannot write rules to output_dir {directory}: {e}") from None
    return f"# Wrote {len(documents)} Lakewatch content-pack rule(s) to {directory}"
