"""Resolve dotted Sigma field names against a Lakewatch parser schema."""
import json
import re
import warnings
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

from .schema_catalog import ParserSchema


@dataclass(frozen=True)
class FieldPath:
    """A dotted field name split at array and VARIANT boundaries.

    ``arrays`` holds one segment tuple per array level, relative to the previous level's
    element (the first one is relative to the row). ``leaf`` is the column/struct path inside
    the innermost element (ending at the VARIANT, if any), and ``json_path`` the keys inside
    that VARIANT. ``json_type`` is the declared type of the key inside a VARIANT (None if
    undeclared); ``leaf_type`` is the type of a column or STRUCT leaf.

    ``entry`` is set for a named entry ``Field[Name]``: the ``_VALUE`` of the element whose
    ``_Name`` is ``Name`` in a list of ``{_Name, _VALUE}`` (Windows ``EventData``). ``leaf`` is
    then the list itself, a VARIANT (``entry_variant``) or an ``ARRAY<STRUCT>``.

    ``allowed`` is the declared set of values of a column, STRUCT or declared VARIANT leaf.
    ``join`` holds the two resolved parts of a join field (see ``join_field_name``), which
    renders as the parts concatenated with ``join_sep``.
    """

    arrays: Tuple[Tuple[str, ...], ...]
    leaf: Tuple[str, ...]
    json_path: Tuple[str, ...]
    json_type: Optional[str] = None
    leaf_type: Optional[str] = None
    entry: Optional[str] = None
    entry_variant: bool = False
    allowed: Optional[Tuple[str, ...]] = None
    join: Tuple["FieldPath", ...] = ()
    join_sep: str = ""

    @property
    def whole_variant(self) -> bool:
        """Whether the path ends at a VARIANT column or member itself (no key inside it)."""
        return not self.json_path and self.leaf_type == "VARIANT"


JOIN_PREFIX = "__lakewatch_join__"


def join_field_name(sep: str, parts: Sequence[str]) -> str:
    """Return the synthetic field name for ``parts`` joined with ``sep``."""
    return JOIN_PREFIX + json.dumps([sep, *parts])


def split_join_field_name(name: str) -> Optional[Tuple[str, List[str]]]:
    """Return ``(sep, parts)`` of a name built by ``join_field_name``, or None if it isn't one.

    A name with the join prefix that doesn't decode to a separator and two parts gives None too.
    """
    if not name.startswith(JOIN_PREFIX):
        return None
    try:
        decoded = json.loads(name[len(JOIN_PREFIX):])
    except ValueError:
        return None
    if (
        not isinstance(decoded, list) or len(decoded) != 3
        or not all(isinstance(x, str) for x in decoded)
    ):
        return None
    return decoded[0], decoded[1:]


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
    allow_undeclared: bool = False,
    allowed: Optional[Tuple[str, ...]] = None,
) -> FieldPath:
    if not remaining:
        return FieldPath(tuple(arrays), leaf, (), None, leaf_type, allowed=allowed)
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
            if allow_undeclared:
                return FieldPath(
                    tuple(arrays), leaf, tuple(json_path + remaining[i:]), None, None
                )
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
    return FieldPath(tuple(arrays), leaf, tuple(json_path), json_type, None, allowed=info.allowed)


_NAMED_ENTRY = re.compile(r"(?P<base>.+)\[(?P<name>[^\[\]]+)\]")


def _resolve_named_entry(schema: ParserSchema, path: str, base: str, name: str) -> FieldPath:
    """Resolve ``base[name]``: a named entry of a VARIANT or ``ARRAY<STRUCT<_Name, _VALUE>>``.

    ``base[*]`` is the unnamed ``Data`` of a whole VARIANT (all plain strings, joined).
    """
    if name == "*":
        target = resolve_schema_path(schema, base)
        if target.arrays or not target.whole_variant:
            raise UnknownFieldError(path, schema.name, f"'[*]' needs a whole VARIANT field, '{base}' is not one")
        return FieldPath((), target.leaf, (), None, "STRING", entry="*", entry_variant=True)
    target = resolve_schema_path(schema, base)
    if not target.arrays and target.whole_variant:
        return FieldPath((), target.leaf, (), None, "STRING", entry=name, entry_variant=True)
    if (
        len(target.arrays) == 1 and not target.leaf and target.leaf_type == "STRUCT"
        and not target.arrays[0][:-1]  # a top-level column: struct members are not supported
    ):
        column = target.arrays[0]
        key = _find(schema, "", column[0])
        if key and all(_find(schema, key + "[]", member) for member in ("_Name", "_VALUE")):
            return FieldPath((), column, (), None, "STRING", entry=name, entry_variant=False)
    raise UnknownFieldError(
        path, schema.name, f"a named entry needs a VARIANT or ARRAY<STRUCT<_Name, _VALUE>> field, "
        f"'{base}' is not one",
    )


def _resolve_join(schema: ParserSchema, path: str, allow_undeclared: bool) -> FieldPath:
    """Resolve a name built by ``join_field_name`` into a FieldPath with two scalar parts."""
    not_scalar = "join parts must be scalar fields"
    split = split_join_field_name(path)
    if split is None:
        raise UnknownFieldError(path, schema.name, not_scalar + " (exactly 2 parts)")
    sep, names = split
    parts = []
    for name in names:
        part = resolve_schema_path(schema, name, allow_undeclared)
        scalar = (
            not part.join and part.entry is None and not part.arrays and not part.whole_variant
            and (part.json_path or part.leaf_type not in ("STRUCT", "ARRAY"))
            and part.json_type not in ("STRUCT", "ARRAY", "VARIANT")
        )
        if not scalar:
            raise UnknownFieldError(path, schema.name, f"{not_scalar} ('{name}' is not)")
        parts.append(part)
    return FieldPath((), (), (), None, "STRING", join=tuple(parts), join_sep=sep)


def resolve_schema_path(
    schema: ParserSchema, path: str, allow_undeclared: bool = False
) -> FieldPath:
    """Resolve a dotted field name against ``schema``, or raise UnknownFieldError.

    ``Field[Name]`` resolves to a named entry of a ``{_Name, _VALUE}`` list (see FieldPath).
    A name built by ``join_field_name`` resolves to a join of two scalar fields. With
    ``allow_undeclared``, keys not declared under a VARIANT that declares children are accepted.
    """
    if path.startswith(JOIN_PREFIX):  # before the named-entry pattern: a join name ends in ']'
        return _resolve_join(schema, path, allow_undeclared)
    named = _NAMED_ENTRY.fullmatch(path)
    if named:
        return _resolve_named_entry(schema, path, named["base"], named["name"])
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
                    schema, path, prefix, rest, arrays, (), "VARIANT", allow_undeclared
                )
            continue
        since.append(declared)
        if info.type == "VARIANT":
            return _resolve_variant(
                schema, path, key, rest, arrays, tuple(since), "VARIANT", allow_undeclared,
                info.allowed,
            )
        prefix = key
        if not rest:
            return FieldPath(
                tuple(arrays), tuple(since), (), None, info.type, allowed=info.allowed
            )
    raise UnknownFieldError(path, schema.name, "empty path")  # pragma: no cover
