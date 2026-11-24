"""Generate mitre_techniques.json from the official MITRE ATT&CK STIX bundle.

Maps each technique id to its name and ATT&CK tactics (kill chain phase names, for example
``command-and-control``). Dev-only, run manually to refresh the bundled table:
    python scripts/gen_mitre_techniques.py
Requires internet access. Uses only the standard library.
"""
import json
import os
import urllib.request

URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
OUT = os.path.normpath(
    os.path.join(
        os.path.dirname(__file__),
        "..", "sigma", "backends", "databricks", "mitre_techniques.json",
    )
)


def main() -> None:
    with urllib.request.urlopen(URL) as resp:  # noqa: S310 - trusted MITRE host
        bundle = json.load(resp)
    mapping = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next(
            (r for r in obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack" and r.get("external_id")),
            None,
        )
        if ext:
            tactics = [
                p["phase_name"] for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ]
            mapping[ext["external_id"]] = {"name": obj["name"], "tactics": tactics}
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(dict(sorted(mapping.items())), fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"Wrote {len(mapping)} techniques to {OUT}")


if __name__ == "__main__":
    main()
