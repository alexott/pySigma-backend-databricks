"""OCSF attribute metadata used to render nested OCSF field paths in Databricks SQL."""
import json
import os
from typing import Optional, Tuple

from .field_paths import FieldPath

_ATTRIBUTES_PATH = os.path.join(os.path.dirname(__file__), "ocsf_attributes.json")
with open(_ATTRIBUTES_PATH, encoding="utf-8") as _fh:
    _ATTRIBUTES = json.load(_fh)

#: OCSF schema version the attribute tables were generated from.
OCSF_VERSION: str = _ATTRIBUTES["version"]
#: OCSF dictionary attributes that are arrays (e.g. ``hashes``, ``answers``, ``evidences``).
ARRAY_ATTRIBUTES: frozenset[str] = frozenset(_ATTRIBUTES["arrays"])
#: OCSF dictionary attributes without a fixed schema (``unmapped``, ``xattributes``, ``json_t``
#: attributes such as ``data``). On Databricks they are VARIANT or JSON string columns.
FREE_FORM_ATTRIBUTES: frozenset[str] = frozenset(_ATTRIBUTES["free_form"])


OcsfPath = FieldPath


def split_ocsf_path(field: str) -> Optional[OcsfPath]:
    """Split a dotted OCSF field name, or return None if it needs no special rendering."""
    arrays = []
    current = []
    json_path: Tuple[str, ...] = ()
    segments = field.split(".")
    for i, segment in enumerate(segments):
        current.append(segment)
        if segment in FREE_FORM_ATTRIBUTES:
            json_path = tuple(segments[i + 1:])
            break
        if segment in ARRAY_ATTRIBUTES:
            arrays.append(tuple(current))
            current = []
    if not arrays and not json_path:
        return None
    return OcsfPath(tuple(arrays), tuple(current), json_path)
