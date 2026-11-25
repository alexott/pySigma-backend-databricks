"""Build a Lakewatch parser schema catalog (JSON) from ``DESCRIBE TABLE EXTENDED ... AS JSON``.

Offline:
    python scripts/describe_to_schema.py --describe-json describe.json --parser NAME -o out.json
Live (uses the ``databricks`` CLI; the profile is never defaulted):
    python scripts/describe_to_schema.py --table c.s.t --profile P --warehouse-id W --parser NAME -o out.json
"""
import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def _walk_type(path: str, type_: Dict[str, Any], storage: str, out: Dict[str, Dict[str, Any]]) -> None:
    """Emit ``path`` for ``type_`` and the paths below it."""
    kind = str(type_.get("name", "")).lower()
    if kind == "map":
        _warn(f"{path}: MAP is not supported, skipped")
        return
    info: Dict[str, Any] = {"type": kind.upper(), "storage": storage}
    if kind == "array":
        element = type_.get("element_type") or {}
        ekind = str(element.get("name", "")).lower()
        info["element"] = ekind.upper()
        out[path] = info
        if ekind == "struct":
            for member in element.get("fields") or []:
                _walk_type(f"{path}[].{member['name']}", member["type"], "struct", out)
        return
    out[path] = info
    if kind == "struct":
        for member in type_.get("fields") or []:
            _walk_type(f"{path}.{member['name']}", member["type"], "struct", out)


def schema_from_describe(describe: Dict[str, Any], parser: str, uuid: Optional[str] = None) -> Dict[str, Any]:
    """Return a catalog (Plan 1 format) holding one parser built from a DESCRIBE ... AS JSON result."""
    paths: Dict[str, Dict[str, Any]] = {}
    for column in describe.get("columns") or []:
        _walk_type(column["name"], column["type"], "column", paths)
    if "time" not in paths:
        raise ValueError("the table has no 'time' column; a Lakewatch parsed table must have one")
    return {
        "generated_from": "DESCRIBE TABLE EXTENDED AS JSON",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "parsers": {parser: {"uuid": uuid, "version": None, "paths": paths}},
    }


def _describe_live(table: str, profile: str, warehouse_id: str) -> Dict[str, Any]:
    body = {
        "statement": f"DESCRIBE TABLE EXTENDED {table} AS JSON",
        "warehouse_id": warehouse_id,
        "wait_timeout": "30s",
    }
    cmd: List[str] = [
        "databricks", "api", "post", "/api/2.0/sql/statements",
        "--profile", profile, "--json", json.dumps(body),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"databricks CLI failed: {proc.stderr.strip()}")
    response = json.loads(proc.stdout)
    try:
        return json.loads(response["result"]["data_array"][0][0])
    except (KeyError, IndexError, TypeError) as exc:
        state = (response.get("status") or {}).get("state")
        raise RuntimeError(f"no result in the statement response (state: {state})") from exc


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--describe-json", help="file with the DESCRIBE TABLE EXTENDED AS JSON output")
    src.add_argument("--table", help="catalog.schema.table to describe (live mode)")
    ap.add_argument("--profile", help="Databricks CLI profile (required with --table)")
    ap.add_argument("--warehouse-id", help="SQL warehouse id (required with --table)")
    ap.add_argument("--parser", required=True, help="parser name in the catalog")
    ap.add_argument("--uuid", help="parser uuid")
    ap.add_argument("-o", "--output", required=True, help="output JSON file")
    args = ap.parse_args(argv)
    if args.table:
        if not args.profile or not args.warehouse_id:
            ap.error("--table requires --profile and --warehouse-id")
        describe = _describe_live(args.table, args.profile, args.warehouse_id)
    else:
        with open(args.describe_json, encoding="utf-8") as fh:
            describe = json.load(fh)
    catalog = schema_from_describe(describe, args.parser, args.uuid)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(catalog, fh, indent=2)
        fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
