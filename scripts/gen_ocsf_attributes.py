"""Generate ocsf_attributes.json from the OCSF schema dictionary.

Dev-only, run manually to refresh the bundled OCSF attribute tables:
    python scripts/gen_ocsf_attributes.py [VERSION]
VERSION defaults to the release the backend targets (e.g. 1.9.0). Requires internet
access. Uses only the standard library.
"""
import json
import os
import sys
import urllib.request

DEFAULT_VERSION = "1.9.0"
URL = "https://raw.githubusercontent.com/ocsf/ocsf-schema/v{version}/dictionary.json"
OUT = os.path.normpath(
    os.path.join(
        os.path.dirname(__file__),
        "..", "sigma", "backends", "databricks", "ocsf_attributes.json",
    )
)
# Attribute types without a fixed schema: arbitrary keys, stored as VARIANT or JSON string.
FREE_FORM_TYPES = ("object", "json_t")


def main() -> None:
    version = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_VERSION
    with urllib.request.urlopen(URL.format(version=version)) as resp:  # noqa: S310 - trusted OCSF host
        attributes = json.load(resp)["attributes"]
    data = {
        "version": version,
        "arrays": sorted(name for name, attr in attributes.items() if attr.get("is_array")),
        "free_form": sorted(
            name for name, attr in attributes.items() if attr.get("type") in FREE_FORM_TYPES
        ),
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


if __name__ == "__main__":
    main()
