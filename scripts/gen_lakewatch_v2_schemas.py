"""Generate a Lakewatch parser schema catalog (JSON) from a parser pack directory.

Dev-only, run manually to refresh the bundled catalog:
    python scripts/gen_lakewatch_v2_schemas.py <pack_dir> [--parsers-subdir parsers]
        [--include GLOB] [--exclude GLOB] -o <out.json>
Reads ``<pack_dir>/<parsers_subdir>/*/parser.yaml`` plus the optional ``appIndex.yaml`` (uuid) and
``<parsers_subdir>/revisions.yaml`` (latestVersion).
"""
import argparse
import fnmatch
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

import yaml

# Columns managed by Lakewatch itself; member paths of the STRUCT ones are not listed.
_MANAGED = {
    "time": {"type": "TIMESTAMP", "storage": "column"},
    "lw_id": {"type": "STRING", "storage": "column"},
    "lw_meta": {"type": "STRUCT", "storage": "column"},
    "lw_observables": {"type": "STRUCT", "storage": "column"},
}


def _load_yaml(path: Path) -> Any:
    if not path.is_file():
        return {}
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _walk(fields, prefix: str, container: str, out: Dict[str, Dict[str, Any]]) -> None:
    """Emit paths for ``fields``. ``container`` is the nearest container kind: column/struct/variant."""
    for fld in fields or []:
        name = fld.get("name")
        if not name:
            continue
        path = f"{prefix}{name}"
        ftype = str(fld.get("type") or "STRING").upper()
        info: Dict[str, Any] = {"type": ftype, "storage": container}
        if fld.get("required"):
            info["required"] = True
        allowed = (fld.get("validate") or {}).get("in")
        if allowed is not None:
            info["allowed"] = [str(v) for v in allowed]
        element = fld.get("element") if isinstance(fld.get("element"), dict) else None
        if ftype == "ARRAY" and element:
            info["element"] = str(element.get("type") or "STRING").upper()
        out[path] = info
        if ftype == "VARIANT":
            _walk(fld.get("fields"), f"{path}.", "variant", out)
        elif ftype == "STRUCT":
            # A STRUCT nested in a VARIANT is still addressed through the VARIANT.
            _walk(fld.get("fields"), f"{path}.", "variant" if container == "variant" else "struct", out)
        elif ftype == "ARRAY" and element:
            etype = info["element"]
            if etype == "VARIANT":
                kind = "variant"
            elif etype == "STRUCT":
                kind = "variant" if container == "variant" else "struct"
            else:
                continue
            _walk(element.get("fields"), f"{path}[].", kind, out)


def _git_sha(directory: Path) -> Optional[str]:
    try:
        res = subprocess.run(
            ["git", "-C", str(directory), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        return res.stdout.strip() or None
    except (OSError, subprocess.CalledProcessError):
        return None


def build_catalog(
    pack_dir: Path,
    parsers_subdir: str = "parsers",
    include: Optional[Sequence[str]] = None,
    exclude: Optional[Sequence[str]] = None,
) -> dict:
    pack_dir = Path(pack_dir)
    parsers_dir = pack_dir / parsers_subdir
    uuids = {p["name"]: p.get("uuid") for p in _load_yaml(pack_dir / "appIndex.yaml").get("parsers") or []}
    versions = {
        p["name"]: p.get("latestVersion")
        for p in _load_yaml(parsers_dir / "revisions.yaml").get("parsers") or []
    }
    parsers: Dict[str, Any] = {}
    for parser_file in sorted(parsers_dir.glob("*/parser.yaml")):
        name = parser_file.parent.name
        if include and not any(fnmatch.fnmatch(name, g) for g in include):
            continue
        if exclude and any(fnmatch.fnmatch(name, g) for g in exclude):
            continue
        paths: Dict[str, Dict[str, Any]] = {k: dict(v) for k, v in _MANAGED.items()}
        _walk(_load_yaml(parser_file).get("fields"), "", "column", paths)
        parsers[name] = {"uuid": uuids.get(name), "version": versions.get(name), "paths": paths}
    source = pack_dir.name
    sha = _git_sha(pack_dir)
    if sha:
        source = f"{source}@{sha}"
    return {
        "generated_from": source,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "parsers": parsers,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("pack_dir", type=Path)
    ap.add_argument("--parsers-subdir", default="parsers")
    ap.add_argument("--include", action="append", metavar="GLOB", help="keep only parser dirs matching (repeatable)")
    ap.add_argument("--exclude", action="append", metavar="GLOB", help="drop parser dirs matching (repeatable)")
    ap.add_argument("-o", "--output", type=Path, required=True)
    args = ap.parse_args()
    catalog = build_catalog(args.pack_dir.expanduser(), args.parsers_subdir, args.include, args.exclude)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {len(catalog['parsers'])} parsers to {args.output}")


if __name__ == "__main__":
    main()
