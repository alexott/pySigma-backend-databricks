"""Write a starting Lakewatch mapping profile from a parser schema and SigmaHQ field usage.

Usage: scaffold_profile.py PARSER [--schemas f.json ...] [--rules DIR]
       --match product=windows,category=process_creation [--profile-id ID] [-o out.yml]
"""
import argparse
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

import yaml

from sigma.backends.databricks.schema_catalog import ParserSchema, SchemaCatalog

_PLAIN = re.compile(r"[A-Za-z_][A-Za-z0-9_.*]*")


def _q(text: str) -> str:
    """Quote ``text`` for YAML when it isn't a plain safe scalar."""
    return text if _PLAIN.fullmatch(text) else yaml.safe_dump(text, default_style='"').splitlines()[0]


def _detection_fields(node: Any) -> Iterator[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            yield str(key).split("|", 1)[0]
            yield from _detection_fields(value)
    elif isinstance(node, list):
        for item in node:
            yield from _detection_fields(item)


def _rule_fields(rules_dir: Path, match: Dict[str, str]) -> Counter:
    """Count, per field name, the matching rules that use it."""
    counts: Counter = Counter()
    for path in sorted(rules_dir.rglob("*.yml")):
        try:
            with open(path, encoding="utf-8") as fh:
                docs = list(yaml.safe_load_all(fh))
        except (OSError, yaml.YAMLError, UnicodeDecodeError):
            continue
        for doc in docs:
            if not isinstance(doc, dict) or not isinstance(doc.get("logsource"), dict):
                continue
            logsource = {str(k).lower(): str(v).lower() for k, v in doc["logsource"].items()}
            if any(logsource.get(k.lower()) != v.lower() for k, v in match.items()):
                continue
            detection = doc.get("detection")
            if not isinstance(detection, dict):
                continue
            # Top-level keys are search identifiers; the fields are the keys inside them.
            found = {f for k, v in detection.items() if k != "condition" for f in _detection_fields(v) if f}
            counts.update(found)
    return counts


def scaffold(
    schema: ParserSchema,
    match: Dict[str, str],
    rules_dir: Optional[Path],
    profile_id: Optional[str] = None,
) -> str:
    """Return the starting profile YAML text for ``schema``."""
    usage = _rule_fields(rules_dir, match) if rules_dir else Counter()
    profile_id = profile_id or re.sub(r"[^a-z0-9_]+", "_", schema.name.lower())
    paths = schema.paths
    has_children = {p for p in paths for q in paths if q.startswith(p + ".") or q.startswith(p + "[].")}
    lines = [
        f"# Starting profile for parser '{schema.name}', generated {datetime.now(timezone.utc):%Y-%m-%d}.",
        "# Review every line: map Sigma field names (left) to schema paths (right).",
        f"profile: {_q(profile_id)}",
        "version: 1",
        f"parser: {_q(schema.name)}",
        "fields:",
    ]
    known = set()
    for path, info in paths.items():
        if path == "time" or path.startswith("lw_"):
            continue
        if info.type == "STRUCT" or (info.type == "ARRAY" and info.element in ("STRUCT", "VARIANT")):
            continue
        if info.type == "VARIANT" and path in has_children:
            continue
        name = path.replace("[]", "")
        target = f"{name}.*" if info.type == "VARIANT" else name
        known.add(name)
        count = usage.get(name, 0)
        comment = f"  # used by {count} rules" if count else ""
        lines.append(f"  {_q(target)}: {_q(target)}{comment}")
    lines.append("logsources:")
    lines.append("  - match: {" + ", ".join(f"{_q(k)}: {_q(v)}" for k, v in match.items()) + "}")
    lines.append("")
    lines.append("# Sigma fields used by matching rules but not in the schema:")
    missing = sorted(((f, c) for f, c in usage.items() if f not in known), key=lambda fc: (-fc[1], fc[0]))
    lines.extend(f"#   {f}: {c}" for f, c in missing)
    return "\n".join(lines) + "\n"


def _parse_match(text: str) -> Dict[str, str]:
    result = {}
    for pair in text.split(","):
        key, sep, value = pair.partition("=")
        if not sep or not key.strip():
            raise argparse.ArgumentTypeError(f"bad --match entry '{pair}', expected key=value")
        result[key.strip()] = value.strip()
    return result


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("parser", help="parser name")
    ap.add_argument("--schemas", nargs="*", default=[], help="extra schema catalog JSON files")
    ap.add_argument("--rules", help="directory of Sigma rules to count field usage in")
    ap.add_argument("--match", required=True, type=_parse_match, help="logsource match, key=value[,key=value]")
    ap.add_argument("--profile-id", help="profile id (default: derived from the parser name)")
    ap.add_argument("-o", "--output", help="output file (default: stdout)")
    args = ap.parse_args(argv)
    schema = SchemaCatalog.load(args.schemas).get(args.parser)
    rules = Path(args.rules).expanduser() if args.rules else None
    text = scaffold(schema, args.match, rules, args.profile_id)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
