"""Resolve dotted Sigma field names against a Lakewatch parser schema."""
import json
import re
import warnings
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple, Union

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

    ``variant_arrays`` holds the schema-declared arrays crossed *inside* a VARIANT, outermost
    first, each as ``(json_path, element_type)``: the keys from the level's container to the
    array, and the declared element type (``VARIANT`` or a scalar type). The container of the
    first level is the VARIANT ``leaf`` (read from the innermost ``arrays`` element, if any);
    the container of each further level is the previous level's element. Every level is one
    any-element ``exists`` level after those of ``arrays``. ``json_path`` then holds the keys
    inside the last element (empty for a scalar element, whose type is ``leaf_type``). A
    consumer that wants "the array inside a VARIANT at path P" takes
    ``variant_arrays[-1]`` of the path to the array itself, which has no ``json_path``.
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
    first: Tuple["FieldPath", ...] = ()
    first_unset: Tuple[str, ...] = ()
    variant_arrays: Tuple[Tuple[Tuple[str, ...], str], ...] = ()

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


FIRST_PREFIX = "__lakewatch_first__"


def first_set_field_name(
    candidates: Sequence[Union[str, Tuple[str, str]]], unset: Sequence[str]
) -> str:
    """Return the synthetic field name for the first set of ``candidates``.

    A candidate is a field path or a ``(domain, user)`` pair (joined with a backslash). A
    value counts as unset if it is NULL, empty or one of ``unset``.
    """
    return FIRST_PREFIX + json.dumps(
        {"candidates": [c if isinstance(c, str) else list(c) for c in candidates], "unset": list(unset)}
    )


def split_first_set_field_name(
    name: str,
) -> Optional[Tuple[List[Union[str, Tuple[str, str]]], List[str]]]:
    """Return ``(candidates, unset)`` of a name built by ``first_set_field_name``, or None."""
    if not name.startswith(FIRST_PREFIX):
        return None
    try:
        decoded = json.loads(name[len(FIRST_PREFIX):])
    except ValueError:
        return None
    if not isinstance(decoded, dict) or set(decoded) != {"candidates", "unset"}:
        return None
    raw, unset = decoded["candidates"], decoded["unset"]
    if not isinstance(raw, list) or not isinstance(unset, list) or not all(isinstance(u, str) for u in unset):
        return None
    candidates: List[Union[str, Tuple[str, str]]] = []
    for c in raw:
        if isinstance(c, str):
            candidates.append(c)
        elif isinstance(c, list) and len(c) == 2 and all(isinstance(x, str) for x in c):
            candidates.append((c[0], c[1]))
        else:
            return None
    return candidates, unset


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
    var_arrays: List[Tuple[Tuple[str, ...], str]] = []

    def result(json_path: Sequence[str], json_type: Optional[str] = None, ltype: Optional[str] = None,
               allowed: Optional[Tuple[str, ...]] = None) -> FieldPath:
        return FieldPath(
            tuple(arrays), leaf, tuple(json_path), json_type, ltype, allowed=allowed,
            variant_arrays=tuple(var_arrays),
        )

    if not remaining:
        return result((), None, leaf_type, allowed)
    if not _has_children(schema, base):
        return result(remaining)
    prefix = base
    json_path: List[str] = []
    json_type: Optional[str] = None
    info = None
    for i, segment in enumerate(remaining):
        if json_path and not _has_children(schema, prefix):
            # A declared free-form VARIANT member: the rest is unconstrained.
            if json_type == "VARIANT":
                return result(json_path + remaining[i:])
        key = _find(schema, prefix, segment)
        if key is None:
            if allow_undeclared:
                return result(json_path + remaining[i:])
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
            # A declared array: one any-element level; the rest is relative to its element.
            element = info.element or "VARIANT"
            var_arrays.append((tuple(json_path + [declared]), element))
            json_path, json_type, prefix = [], None, key + "[]"
            if i == len(remaining) - 1:
                return result((), None, element)
            continue
        json_path.append(declared)
        json_type = info.type
        prefix = key
    assert info is not None
    return result(json_path, json_type, None, info.allowed)


_NAMED_ENTRY = re.compile(r"(?P<base>.+)\[(?P<name>[^\[\]]+)\]")


def _resolve_named_entry(schema: ParserSchema, path: str, base: str, name: str) -> FieldPath:
    """Resolve ``base[name]``: a named entry of a VARIANT or ``ARRAY<STRUCT<_Name, _VALUE>>``.

    ``base[*]`` is the unnamed ``Data`` of a whole VARIANT (all plain strings, joined).
    """
    if name == "*":
        target = resolve_schema_path(schema, base)
        if target.arrays or target.variant_arrays or not target.whole_variant:
            raise UnknownFieldError(path, schema.name, f"'[*]' needs a whole VARIANT field, '{base}' is not one")
        return FieldPath((), target.leaf, (), None, "STRING", entry="*", entry_variant=True)
    target = resolve_schema_path(schema, base)
    if not target.arrays and not target.variant_arrays and target.whole_variant:
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
        if not _is_scalar(part):
            raise UnknownFieldError(path, schema.name, f"{not_scalar} ('{name}' is not)")
        parts.append(part)
    return FieldPath((), (), (), None, "STRING", join=tuple(parts), join_sep=sep)


def _is_scalar(part: FieldPath) -> bool:
    """Whether a path is a scalar (also a named entry, but not ``[*]``) usable as a join part."""
    return (
        not part.join and not part.first and part.entry != "*" and not part.arrays and not part.variant_arrays
        and not part.whole_variant
        and (part.entry is not None or part.json_path or part.leaf_type not in ("STRUCT", "ARRAY"))
        and part.json_type not in ("STRUCT", "ARRAY", "VARIANT")
    )


def _resolve_first_set(schema: ParserSchema, path: str) -> FieldPath:
    """Resolve a name built by ``first_set_field_name``: the first set of scalar candidates."""
    split = split_first_set_field_name(path)
    if split is None or len(split[0]) < 2:
        raise UnknownFieldError(path, schema.name, "a first-set field needs at least 2 candidates")
    candidates, unset = split
    resolved = []
    for candidate in candidates:
        name = candidate if isinstance(candidate, str) else join_field_name("\\", list(candidate))
        part = resolve_schema_path(schema, name)
        if not part.join and not _is_scalar(part):
            raise UnknownFieldError(path, schema.name, f"first-set candidates must be scalar fields ('{name}' is not)")
        resolved.append(part)
    return FieldPath((), (), (), None, "STRING", first=tuple(resolved), first_unset=tuple(unset))


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
    if path.startswith(FIRST_PREFIX):
        return _resolve_first_set(schema, path)
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
