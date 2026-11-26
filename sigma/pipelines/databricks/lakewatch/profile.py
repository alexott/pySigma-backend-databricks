"""Lakewatch mapping profiles: model, parsing, loading and validation."""

import re
import warnings
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import (
    Any,
    Collection,
    Dict,
    FrozenSet,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

import yaml
from sigma.exceptions import SigmaConfigurationError
from sigma.modifiers import modifier_mapping
from sigma.rule import SigmaLogSource

from sigma.backends.databricks.field_paths import EntrySpec, UnknownFieldError, join_field_name, resolve_schema_path
from sigma.backends.databricks.schema_catalog import ParserSchema
from sigma.pipelines.databricks.lakewatch.transforms import JoinTransform, Transform, parse_transform

_TOP_KEYS = {
    "profile",
    "version",
    "parser",
    "fields",
    "logsources",
    "transforms",
    "products",
    "event_data_column",
    "event_data",
    "raw",
    "entity",
    "unmapped_hint",
    "entries",
}
_BLOCK_KEYS = {"match", "conditions", "fields", "unsupported", "event_data", "route"}
_RAW_KEYS = ("column", "entries", "expr")
_ROUTE_KEYS = {"field", "in", "not_in"}
_MATCH_KEYS = ("product", "category", "service")
_ENTRY_KEYS = {"name", "value", "ignore_case"}
_MAPPING_KEYS = {"field", "transform", "undeclared", "modifiers", "select_condition"}
# Profile ids become part of Unity Catalog rule names: keep them short and UC-safe.
_PROFILE_ID = re.compile(r"[a-z0-9_]+")
_PROFILE_ID_MAX_LEN = 64
# A schema path (as opposed to an SQL expression) in an output setting such as ``entity``.
OUTPUT_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\])*$")

ConditionValue = Union[str, int, bool, List[Union[str, int, bool]]]


class ProfileError(SigmaConfigurationError):
    """An invalid mapping profile. Messages start with ``<source>: ``."""

    def __init__(self, source: str, message: str):
        """Create the error; ``source`` is the profile file (or ``<dict>``)."""
        super().__init__(f"{source}: {message}")


@dataclass(frozen=True)
class FieldMapping:
    """Target schema path(s) of a Sigma field; several targets are ORed."""

    targets: Tuple[str, ...]
    transforms: Tuple[Transform, ...] = ()
    undeclared: bool = False
    modifiers: Optional[FrozenSet[str]] = None
    select: Optional[Dict[str, Dict[str, ConditionValue]]] = None


@dataclass(frozen=True)
class RawSource:
    """Where the raw event text of a profile comes from (for keyword searches)."""

    kind: str  # column | entries | expr
    value: str
    encoding: str  # text | json

    @property
    def approximate(self) -> bool:
        """True when a search over the raw text only approximates a search over the fields."""
        return self.kind == "entries" or self.encoding == "json"


@dataclass(frozen=True)
class Route:
    """Routes rules to a block by the values of a field (lower-cased).

    Without ``include`` and ``exclude`` the schema's ``allowed`` list of the mapped target applies.
    """

    field: str
    include: Optional[FrozenSet[str]] = None
    exclude: FrozenSet[str] = frozenset()


EventDataNames = Union[Tuple[str, ...], str]


@dataclass(frozen=True)
class LogsourceBlock:
    """A profile block for the logsources it matches, with its conditions and fields."""

    match: Dict[str, str]
    conditions: Dict[str, ConditionValue] = field(default_factory=dict)
    fields: Dict[str, FieldMapping] = field(default_factory=dict)
    unsupported: Tuple[str, ...] = ()
    event_data: EventDataNames = ()
    route: Optional[Route] = None


@dataclass(frozen=True)
class Profile:
    """A mapping profile: Sigma fields of one parser's output and its logsource blocks."""

    profile: str
    version: int
    parser: str
    fields: Dict[str, FieldMapping]
    logsources: Tuple[LogsourceBlock, ...]
    source: str = "<dict>"
    transforms: Dict[str, Tuple[Transform, ...]] = field(default_factory=dict)
    products: Dict[str, Dict[str, ConditionValue]] = field(default_factory=dict)
    event_data_column: str = "EventData"
    event_data: EventDataNames = ()
    raw: Optional[RawSource] = None
    entity: Optional[str] = None
    unmapped_hint: Optional[str] = None
    entries: Mapping[str, EntrySpec] = field(default_factory=dict)

    def block_for(self, logsource: SigmaLogSource) -> Optional[LogsourceBlock]:
        """Return the most specific block matching ``logsource`` (first on ties), or None.

        With ``products`` set, a rule whose product is not listed matches nothing.
        """
        product = getattr(logsource, "product", None)
        if self.products and product is not None and product.lower() not in self.products:
            return None
        best: Optional[LogsourceBlock] = None
        for block in self.logsources:
            if all(
                (actual := getattr(logsource, key, None)) is not None and actual.lower() == value
                for key, value in block.match.items()
            ):
                if best is None or len(block.match) > len(best.match):
                    best = block
        return best

    def conditions_for(self, block: LogsourceBlock, logsource: SigmaLogSource) -> Dict[str, ConditionValue]:
        """Return the product conditions merged with those of ``block`` (the block wins)."""
        product = getattr(logsource, "product", None)
        merged: Dict[str, ConditionValue] = {}
        if product is not None:
            merged.update(self.products.get(product.lower(), {}))
        merged.update(block.conditions)
        return merged

    def mappings_for(self, block: LogsourceBlock) -> Dict[str, FieldMapping]:
        """Return the profile fields overridden by the fields of ``block``.

        The ``event_data`` names of the profile and the block follow as ``Column[Name]``
        mappings, unless a name is an explicit field.
        """
        merged = dict(self.fields)
        merged.update(block.fields)
        for names in (self.event_data, block.event_data):
            if isinstance(names, str):
                continue
            for name in names:
                if name not in merged:
                    merged[name] = FieldMapping((f"{self.event_data_column}[{name}]",))
        return merged

    def event_data_any(self, block: LogsourceBlock) -> bool:
        """Return True when the profile or ``block`` accepts any EventData name."""
        return self.event_data == "any" or block.event_data == "any"


# --- parsing -----------------------------------------------------------------------------


def _check_keys(data: Mapping, allowed: Collection[str], source: str, where: str) -> None:
    for key in data:
        if key not in allowed:
            raise ProfileError(source, f"{where}unknown key '{key}'")


def _targets(value: Any, source: str, name: str) -> Tuple[str, ...]:
    items = value if isinstance(value, list) else [value]
    if not items or not all(isinstance(i, str) and i for i in items):
        raise ProfileError(source, f"field '{name}': targets must be non-empty strings")
    return tuple(items)


def _parse_conditions(value: Any, source: str, where: str) -> Dict[str, ConditionValue]:
    if not isinstance(value, dict):
        raise ProfileError(source, f"{where}'conditions' must be a mapping")
    for key, v in value.items():
        values = v if isinstance(v, list) else [v]
        if not values or not all(isinstance(i, (str, int)) for i in values):
            raise ProfileError(source, f"{where}condition '{key}' must be a string, int, bool or list of them")
    return {str(k): v for k, v in value.items()}


def _parse_modifiers(value: Any, source: str, name: str) -> FrozenSet[str]:
    if not isinstance(value, list) or not value or not all(isinstance(m, str) for m in value):
        raise ProfileError(source, f"field '{name}': 'modifiers' must be a non-empty list of names")
    for m in value:
        if m != "eq" and m not in modifier_mapping:
            raise ProfileError(source, f"field '{name}': unknown modifier '{m}'")
    return frozenset(value)


def _parse_select(value: Any, source: str, name: str) -> Dict[str, Dict[str, ConditionValue]]:
    if not isinstance(value, dict) or not value:
        raise ProfileError(source, f"field '{name}': 'select_condition' must be a non-empty mapping")
    return {
        str(k).lower(): _parse_conditions(v, source, f"field '{name}': select_condition '{k}': ")
        for k, v in value.items()
    }


def _parse_mapping(value: Any, source: str, name: str, named: Mapping[str, Sequence[Transform]]) -> FieldMapping:
    if not isinstance(value, dict):
        return _parse_targets(value, source, name)
    _check_keys(value, _MAPPING_KEYS, source, f"field '{name}': ")
    prefix = name.endswith(".*")
    if prefix and set(value) != {"field"}:
        raise ProfileError(source, f"field '{name}': a prefix mapping allows only 'field'")
    transforms: Tuple[Transform, ...] = ()
    if "transform" in value:
        try:
            transforms = parse_transform(value["transform"], named)
        except ValueError as e:
            raise ProfileError(source, f"field '{name}': {e}") from None
    supplies = bool(transforms) and transforms[-1].supplies_targets
    select = None
    if "select_condition" in value:
        if "transform" in value or "field" in value:
            raise ProfileError(
                source, f"field '{name}': 'select_condition' cannot be combined with 'field' or 'transform'"
            )
        select = _parse_select(value["select_condition"], source, name)
    if select is not None or supplies:
        if "field" in value:
            raise ProfileError(
                source,
                f"field '{name}': 'field' is not allowed here: the targets come from "
                "'select_condition' or the last transform",
            )
        targets: Tuple[str, ...] = ()
    else:
        if "field" not in value:
            raise ProfileError(source, f"field '{name}': missing key 'field'")
        targets = _parse_targets(value["field"], source, name).targets
    undeclared = value.get("undeclared", False)
    if not isinstance(undeclared, bool):
        raise ProfileError(source, f"field '{name}': 'undeclared' must be true or false")
    if undeclared and not targets:
        raise ProfileError(source, f"field '{name}': 'undeclared' requires 'field'")
    modifiers = _parse_modifiers(value["modifiers"], source, name) if "modifiers" in value else None
    return FieldMapping(targets, transforms, undeclared, modifiers, select)


def _parse_targets(value: Any, source: str, name: str) -> FieldMapping:
    targets = _targets(value, source, name)
    if name.endswith(".*") and not all(t.endswith(".*") for t in targets):
        raise ProfileError(source, f"field '{name}': prefix mapping targets must end with '.*'")
    if not name.endswith(".*") and any(t.endswith(".*") for t in targets):
        raise ProfileError(source, f"field '{name}': a '.*' target requires a prefix key ending with '.*'")
    return FieldMapping(targets)


def _parse_fields(
    value: Any, source: str, where: str, named: Mapping[str, Sequence[Transform]]
) -> Dict[str, FieldMapping]:
    if not isinstance(value, dict):
        raise ProfileError(source, f"{where}'fields' must be a mapping")
    return {str(k): _parse_mapping(v, source, str(k), named) for k, v in value.items()}


def _parse_event_data(value: Any, source: str, where: str) -> EventDataNames:
    if value == "any":
        return "any"
    if not isinstance(value, list) or not all(isinstance(n, str) for n in value):
        raise ProfileError(source, f"{where}'event_data' must be a list of names or 'any'")
    for name in value:
        if not name or "[" in name or "]" in name:
            raise ProfileError(source, f"{where}'event_data' name '{name}' must be non-empty without '[' or ']'")
    if len(set(value)) != len(value):
        dup = next(n for n in value if value.count(n) > 1)
        raise ProfileError(source, f"{where}'event_data' lists '{dup}' twice")
    return tuple(value)


def _parse_raw(value: Any, source: str) -> RawSource:
    if not isinstance(value, dict):
        raise ProfileError(source, "'raw' must be a mapping")
    _check_keys(value, (*_RAW_KEYS, "encoding"), source, "raw: ")
    kinds = [k for k in _RAW_KEYS if k in value]
    if len(kinds) != 1:
        raise ProfileError(source, "raw: exactly one of 'column', 'entries' and 'expr' is required")
    kind = kinds[0]
    if not isinstance(value[kind], str) or not value[kind]:
        raise ProfileError(source, f"raw: '{kind}' must be a non-empty string")
    if kind == "expr":
        encoding = value.get("encoding")
        if encoding not in ("text", "json"):
            raise ProfileError(source, "raw: 'expr' requires 'encoding' to be 'text' or 'json'")
    elif "encoding" in value:
        raise ProfileError(source, f"raw: 'encoding' is allowed only with 'expr', not '{kind}'")
    else:
        encoding = "text"
    return RawSource(kind, value[kind], encoding)


def _lower_values(value: Any, source: str, key: str) -> FrozenSet[str]:
    if not isinstance(value, list) or not value or not all(isinstance(v, (str, int)) for v in value):
        raise ProfileError(source, f"route: '{key}' must be a non-empty list of strings or numbers")
    return frozenset(str(v).lower() for v in value)


def _parse_route(value: Any, source: str) -> Route:
    if not isinstance(value, dict):
        raise ProfileError(source, "logsource block: 'route' must be a mapping")
    _check_keys(value, _ROUTE_KEYS, source, "route: ")
    name = value.get("field")
    if not isinstance(name, str) or not name:
        raise ProfileError(source, "route: 'field' must be a non-empty string")
    if "in" in value and "not_in" in value:
        raise ProfileError(source, "route: 'in' and 'not_in' cannot be combined")
    include = _lower_values(value["in"], source, "in") if "in" in value else None
    exclude = _lower_values(value["not_in"], source, "not_in") if "not_in" in value else frozenset()
    return Route(name, include, exclude)


def _parse_block(
    data: Any,
    source: str,
    named: Mapping[str, Sequence[Transform]] = {},  # noqa: B006
) -> LogsourceBlock:
    if not isinstance(data, dict):
        raise ProfileError(source, "each 'logsources' entry must be a mapping")
    _check_keys(data, _BLOCK_KEYS, source, "logsource block: ")
    match = data.get("match")
    if not isinstance(match, dict) or not match:
        raise ProfileError(source, "logsource block: 'match' must be a non-empty mapping")
    for key, value in match.items():
        if key not in _MATCH_KEYS:
            raise ProfileError(source, f"logsource block: match has unknown key '{key}'")
        if not isinstance(value, str):
            raise ProfileError(source, f"logsource block: match '{key}' must be a string")
    conditions = _parse_conditions(data.get("conditions", {}), source, "logsource block: ")
    unsupported = data.get("unsupported", [])
    if not isinstance(unsupported, list) or not all(isinstance(u, str) for u in unsupported):
        raise ProfileError(source, "logsource block: 'unsupported' must be a list of strings")
    return LogsourceBlock(
        match={k: v.lower() for k, v in match.items()},
        conditions=conditions,
        fields=_parse_fields(data.get("fields", {}), source, "logsource block: ", named),
        unsupported=tuple(unsupported),
        event_data=_parse_event_data(data.get("event_data", ()), source, "logsource block: ")
        if "event_data" in data
        else (),
        route=_parse_route(data["route"], source) if "route" in data else None,
    )


def _parse_named_transforms(value: Any, source: str) -> Dict[str, Tuple[Transform, ...]]:
    if not isinstance(value, dict):
        raise ProfileError(source, "'transforms' must be a mapping")
    named: Dict[str, Tuple[Transform, ...]] = {}
    for name, spec in value.items():
        try:
            named[str(name)] = parse_transform(spec, named)
        except ValueError as e:
            raise ProfileError(source, f"transform '{name}': {e}") from None
    return named


def _parse_products(value: Any, source: str) -> Dict[str, Dict[str, ConditionValue]]:
    if not isinstance(value, dict):
        raise ProfileError(source, "'products' must be a mapping")
    return {str(k).lower(): _parse_conditions(v, source, f"product '{k}': ") for k, v in value.items()}


def _parse_entries(value: Any, source: str) -> Dict[str, EntrySpec]:
    """Parse the ``entries`` key: a mapping of column path to its ``{name, value, ignore_case}``."""
    if not isinstance(value, dict):
        raise ProfileError(source, "'entries' must be a mapping of column path to its members")
    entries: Dict[str, EntrySpec] = {}
    for column, spec in value.items():
        where = f"entries '{column}': "
        if not isinstance(column, str) or not column:
            raise ProfileError(source, f"entries keys must be non-empty column paths, got '{column}'")
        if not isinstance(spec, dict):
            raise ProfileError(source, f"{where}must be a mapping")
        _check_keys(spec, sorted(_ENTRY_KEYS), source, where)
        for key in ("name", "value"):
            if key not in spec:
                raise ProfileError(source, f"{where}missing required key '{key}'")
        name = spec["name"]
        if not isinstance(name, str) or not name:
            raise ProfileError(source, f"{where}'name' must be a non-empty string")
        members = spec["value"] if isinstance(spec["value"], list) else [spec["value"]]
        if not members or not all(isinstance(m, str) and m for m in members):
            raise ProfileError(source, f"{where}'value' must be a non-empty string or a list of non-empty strings")
        ignore_case = spec.get("ignore_case", False)
        if not isinstance(ignore_case, bool):
            raise ProfileError(source, f"{where}'ignore_case' must be a boolean")
        entries[column] = EntrySpec(name, tuple(members), ignore_case)
    return entries


def parse_profile(data: Any, source: str = "<dict>") -> Profile:
    if not isinstance(data, dict):
        raise ProfileError(source, "profile must be a mapping")
    _check_keys(data, sorted(_TOP_KEYS), source, "")
    for key in ("profile", "version", "parser", "logsources"):
        if key not in data:
            raise ProfileError(source, f"missing required key '{key}'")
    entity = data.get("entity")
    if "entity" in data and (not isinstance(entity, str) or not entity.strip()):
        raise ProfileError(source, "entity must be a string (a schema path or an SQL expression)")
    for key in ("profile", "parser"):
        if not isinstance(data[key], str) or not data[key]:
            raise ProfileError(source, f"'{key}' must be a non-empty string")
    if not _PROFILE_ID.fullmatch(data["profile"]) or len(data["profile"]) > _PROFILE_ID_MAX_LEN:
        raise ProfileError(
            source,
            f"'profile' must match [a-z0-9_]+ and be at most {_PROFILE_ID_MAX_LEN} characters, got '{data['profile']}'",
        )
    version = data["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ProfileError(source, "'version' must be an integer >= 1")
    raw_blocks = data["logsources"]
    if not isinstance(raw_blocks, list) or not raw_blocks:
        raise ProfileError(source, "'logsources' must be a non-empty list")
    named = _parse_named_transforms(data.get("transforms", {}), source)
    products = _parse_products(data.get("products", {}), source)
    column = data.get("event_data_column", "EventData")
    if not isinstance(column, str) or not column or "[" in column or "]" in column:
        raise ProfileError(source, "'event_data_column' must be a non-empty string without '[' or ']'")
    hint = data.get("unmapped_hint")
    if hint is not None and not isinstance(hint, str):
        raise ProfileError(source, "'unmapped_hint' must be a string")
    blocks = tuple(_parse_block(b, source, named) for b in raw_blocks)
    seen = set()
    for block in blocks:
        ident = tuple(sorted(block.match.items()))
        if ident in seen:
            raise ProfileError(source, f"duplicate logsource match {block.match}")
        seen.add(ident)
    return Profile(
        profile=data["profile"],
        version=version,
        parser=data["parser"],
        fields=_parse_fields(data.get("fields", {}), source, "", named),
        logsources=blocks,
        source=source,
        transforms=named,
        products=products,
        event_data_column=column,
        event_data=_parse_event_data(data["event_data"], source, "") if "event_data" in data else (),
        raw=_parse_raw(data["raw"], source) if "raw" in data else None,
        entity=entity,
        unmapped_hint=hint,
        entries=_parse_entries(data["entries"], source) if "entries" in data else {},
    )


# --- loading -----------------------------------------------------------------------------


def _read_dir(directory: Path) -> Dict[str, Profile]:
    result: Dict[str, Profile] = {}
    for path in sorted(directory.glob("*.yml"), key=lambda p: p.name):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            raise ProfileError(str(path), f"cannot read profile file: {e}") from None
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise ProfileError(str(path), f"invalid YAML: {e}") from None
        if data is None:
            raise ProfileError(str(path), "profile file is empty")
        profile = parse_profile(data, str(path))
        if profile.profile in result:
            raise ProfileError(
                str(path),
                f"profile '{profile.profile}' is already defined in {result[profile.profile].source}",
            )
        result[profile.profile] = profile
    return result


def load_profiles(extra_dirs: Sequence[str] = ()) -> Dict[str, Profile]:
    """Load built-in profiles, then those in ``extra_dirs`` (later ids replace earlier ones)."""
    builtin = Path(str(files("sigma.pipelines.databricks.lakewatch") / "profiles"))
    profiles: Dict[str, Profile] = {}
    if builtin.is_dir():
        profiles.update(_read_dir(builtin))
    for extra in extra_dirs:
        directory = Path(extra)
        if not directory.is_dir():
            raise ProfileError(str(extra), "profile directory does not exist")
        profiles.update(_read_dir(directory))
    return profiles


# --- validation --------------------------------------------------------------------------


def _resolve(
    profile: Profile,
    schema: ParserSchema,
    path: str,
    what: str,
    allow_undeclared: bool = False,
    entries: Optional[Mapping[str, EntrySpec]] = None,
):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return resolve_schema_path(
                schema, path, allow_undeclared, profile.entries if entries is None else entries
            )
    except UnknownFieldError as e:
        raise ProfileError(profile.source, f"profile '{profile.profile}': {what} '{path}': {e}") from None


def _validate_conditions(
    profile: Profile, schema: ParserSchema, conditions: Dict[str, ConditionValue], what: str
) -> None:
    for name, value in conditions.items():
        _resolve(profile, schema, name, f"{what}condition field")
        info = schema.get(name)
        if info is not None and info.allowed is not None:
            # Compared as the backend does: case-insensitive, booleans as true/false.
            allowed = {a.lower() for a in info.allowed}
            for v in value if isinstance(value, list) else [value]:
                text = ("true" if v else "false") if isinstance(v, bool) else str(v).lower()
                if text not in allowed:
                    raise ProfileError(
                        profile.source,
                        f"profile '{profile.profile}': {what}condition field '{name}': "
                        f"'{text}' not in allowed {list(info.allowed)}",
                    )


def _validate_mappings(profile: Profile, schema: ParserSchema, mappings: Dict[str, FieldMapping]):
    for name, mapping in mappings.items():
        for t in mapping.transforms:
            for path in t.required_paths():
                _resolve(profile, schema, path, f"field '{name}' transform {t.kind} path")
            if isinstance(t, JoinTransform):
                # Resolving the join name checks that both parts are scalar fields.
                _resolve(profile, schema, join_field_name(t.sep, t.parts), f"field '{name}' transform join")
        for sel, conditions in (mapping.select or {}).items():
            _validate_conditions(profile, schema, conditions, f"field '{name}' select_condition '{sel}': ")
        for target in mapping.targets:
            if not name.endswith(".*"):
                _resolve(profile, schema, target, f"field '{name}' target", mapping.undeclared)
                if mapping.undeclared:
                    try:
                        with warnings.catch_warnings():
                            warnings.simplefilter("ignore")
                            resolve_schema_path(schema, target)
                    except UnknownFieldError:
                        continue
                    raise ProfileError(
                        profile.source,
                        f"profile '{profile.profile}': field '{name}': 'undeclared' is not "
                        f"needed, target '{target}' resolves without it",
                    )
                continue
            prefix = target[:-2] if target.endswith(".*") else target
            fp = _resolve(profile, schema, prefix, f"field '{name}' target")
            info = schema.get(prefix)
            has_children = any(k.startswith(prefix + ".") for k in schema.paths)
            if not target.endswith(".*") or not fp.whole_variant or info is None or has_children:
                raise ProfileError(
                    profile.source,
                    f"profile '{profile.profile}': field '{name}': prefix mapping requires "
                    f"a free-form VARIANT target, got '{target}'",
                )


def _validate_raw(profile: Profile, schema: ParserSchema, raw: RawSource) -> None:
    if raw.kind == "column":
        fp = _resolve(profile, schema, raw.value, "raw column")
        if fp.arrays or fp.json_path or fp.entry or fp.whole_variant or fp.leaf_type != "STRING":
            raise ProfileError(
                profile.source,
                f"profile '{profile.profile}': raw column '{raw.value}' must be a scalar STRING",
            )
    elif raw.kind == "entries":
        _resolve(profile, schema, f"{raw.value}[x]", "raw entries", entries={})


def _validate_route(profile: Profile, schema: ParserSchema, block: LogsourceBlock, mapped) -> None:
    route = block.route
    if route is None:
        return
    mapping = mapped.get(route.field)
    if mapping is None:
        raise ProfileError(
            profile.source, f"profile '{profile.profile}': route field '{route.field}' is not a mapped field"
        )
    if route.include is None and not route.exclude:
        for target in mapping.targets or (None,):
            info = schema.get(target) if target else None
            if info is None or info.allowed is None:
                raise ProfileError(
                    profile.source,
                    f"profile '{profile.profile}': route field '{route.field}' needs 'in' or 'not_in': "
                    f"its target '{target}' has no schema 'allowed' list",
                )


def validate_profile(profile: Profile, schema: ParserSchema) -> None:
    uses_event_data = bool(profile.event_data) or any(b.event_data for b in profile.logsources)
    if uses_event_data:
        _resolve(profile, schema, f"{profile.event_data_column}[x]", "event_data column", entries={})
    for column in profile.entries:
        _resolve(profile, schema, f"{column}[x]", "entries")
    if profile.raw is not None:
        _validate_raw(profile, schema, profile.raw)
    if profile.entity is not None and OUTPUT_IDENTIFIER.fullmatch(profile.entity):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                fp = resolve_schema_path(schema, profile.entity)
        except UnknownFieldError as e:
            raise ProfileError(profile.source, f"profile '{profile.profile}': entity {profile.entity}: {e}") from None
        if fp.arrays:
            raise ProfileError(
                profile.source,
                f"profile '{profile.profile}': entity {profile.entity} crosses an array; use an SQL expression",
            )
    _validate_mappings(profile, schema, profile.fields)
    for product, conditions in profile.products.items():
        _validate_conditions(profile, schema, conditions, f"product '{product}': ")
    for block in profile.logsources:
        _validate_mappings(profile, schema, block.fields)
        _validate_conditions(profile, schema, block.conditions, "")
        mapped = profile.mappings_for(block)
        _validate_route(profile, schema, block, mapped)
        for name in block.unsupported:
            if name in mapped:
                raise ProfileError(
                    profile.source,
                    f"profile '{profile.profile}': field '{name}' is both mapped and unsupported",
                )
