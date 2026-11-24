"""Resolve dotted Sigma field names against a Lakewatch parser schema."""
import warnings
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .schema_catalog import ParserSchema


@dataclass(frozen=True)
class FieldPath:
    """A dotted field name split at array and VARIANT boundaries.

    ``arrays`` holds one segment tuple per array level, relative to the previous level's
    element (the first one is relative to the row). ``leaf`` is the column/struct path inside
    the innermost element (ending at the VARIANT, if any), and ``json_path`` the keys inside
    that VARIANT. ``json_type`` is the declared type of the key inside a VARIANT (None if
    undeclared); ``leaf_type`` is the type of a column or STRUCT leaf.
    """

    arrays: Tuple[Tuple[str, ...], ...]
    leaf: Tuple[str, ...]
    json_path: Tuple[str, ...]
    json_type: Optional[str] = None
    leaf_type: Optional[str] = None

    @property
    def whole_variant(self) -> bool:
        """Whether the path ends at a VARIANT column or member itself (no key inside it)."""
        return not self.json_path and self.leaf_type == "VARIANT"


class UnknownFieldError(ValueError):
    """A field path that is not part of a parser's output schema."""

    def __init__(self, path: str, parser: str, reason: str):
        """Create the error for ``path`` of ``parser`` with a human-readable ``reason``."""
        self.path = path
        self.parser = parser
        super().__init__(f"{parser}: field '{path}' is not usable: {reason}")


def _find(schema: ParserSchema, prefix: str, segment: str) -> Optional[str]:
    """Return the declared key for ``segment`` below ``prefix`` (exact, then ignoring case)."""
    candidate = f"{prefix}.{segment}" if prefix else segment
    if candidate in schema.paths:
        return candidate
    lowered = candidate.lower()
    for key in schema.paths:
        if key.lower() == lowered:
            return key
    return None


def _has_children(schema: ParserSchema, key: str) -> bool:
    start = key + "."
    return any(k.startswith(start) for k in schema.paths)


def _resolve_variant(
    schema: ParserSchema,
    path: str,
    base: str,
    remaining: List[str],
    arrays: List[Tuple[str, ...]],
    leaf: Tuple[str, ...],
    leaf_type: str,
) -> FieldPath:
    if not remaining:
        return FieldPath(tuple(arrays), leaf, (), None, leaf_type)
    if not _has_children(schema, base):
        return FieldPath(tuple(arrays), leaf, tuple(remaining), None, None)
    prefix = base
    json_path: List[str] = []
    json_type: Optional[str] = None
    for i, segment in enumerate(remaining):
        if json_path and not _has_children(schema, prefix):
            # A declared free-form VARIANT member: the rest is unconstrained.
            if json_type == "VARIANT":
                return FieldPath(
                    tuple(arrays), leaf, tuple(json_path + remaining[i:]), None, None
                )
        key = _find(schema, prefix, segment)
        if key is None:
            raise UnknownFieldError(
                path, schema.name, f"'{segment}' is not declared under '{prefix}'"
            )
        declared = key[len(prefix) + 1:]
        if "." in declared or "[]" in declared:
            raise UnknownFieldError(path, schema.name, f"'{segment}' is not declared under '{prefix}'")
        if declared != segment:
            warnings.warn(
                f"{schema.name}: '{segment}' resolved to declared '{declared}'",
                UserWarning,
                stacklevel=2,
            )
        info = schema.paths[key]
        if info.type == "ARRAY":
            raise UnknownFieldError(
                path, schema.name, "arrays inside VARIANT are not supported"
            )
        json_path.append(declared)
        json_type = info.type
        prefix = key
    return FieldPath(tuple(arrays), leaf, tuple(json_path), json_type, None)


def resolve_schema_path(schema: ParserSchema, path: str) -> FieldPath:
    """Resolve a dotted field name against ``schema``, or raise UnknownFieldError."""
    segments = path.split(".")
    arrays: List[Tuple[str, ...]] = []
    since: List[str] = []
    prefix = ""
    for i, segment in enumerate(segments):
        key = _find(schema, prefix, segment)
        info = schema.paths.get(key) if key else None
        if key is None or info is None or info.storage == "variant":
            where = f" under '{prefix}'" if prefix else ""
            raise UnknownFieldError(
                path, schema.name, f"'{segment}' is not a declared field{where}"
            )
        declared = key[len(prefix) + 1:] if prefix else key
        rest = segments[i + 1:]
        if info.type == "ARRAY":
            arrays.append(tuple(since + [declared]))
            since = []
            prefix = key + "[]"
            if not rest:
                return FieldPath(tuple(arrays), (), (), None, info.element)
            if info.element == "VARIANT":
                return _resolve_variant(
                    schema, path, prefix, rest, arrays, (), "VARIANT"
                )
            continue
        since.append(declared)
        if info.type == "VARIANT":
            return _resolve_variant(
                schema, path, key, rest, arrays, tuple(since), "VARIANT"
            )
        prefix = key
        if not rest:
            return FieldPath(tuple(arrays), tuple(since), (), None, info.type)
    raise UnknownFieldError(path, schema.name, "empty path")  # pragma: no cover
