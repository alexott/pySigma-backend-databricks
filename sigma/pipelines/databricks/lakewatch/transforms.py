"""Value transforms used by Lakewatch mapping profiles.

A transform takes one Sigma value (and the target fields of its condition) and returns
alternatives: pairs of target fields and a replacement value. ``parse_transform`` builds
chains from profile YAML, and ``apply_chain`` folds a chain over a value.
"""

import re
import warnings
from abc import ABC, abstractmethod
from typing import (
    Any,
    ClassVar,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    Union,
)

from sigma.types import (
    Placeholder,
    SigmaBool,
    SigmaNumber,
    SigmaString,
    SigmaType,
    SpecialChars,
)

from sigma.backends.databricks.field_paths import join_field_name


class TransformFailure(ValueError):  # noqa: N818
    """A transform cannot keep the meaning of a value; the message is only the reason."""


Alternative = Tuple[Tuple[str, ...], SigmaType]
_Part = Union[str, SpecialChars, Placeholder]
_WILD = SpecialChars.WILDCARD_MULTI


def _make(parts: Sequence[_Part]) -> SigmaString:
    """Build a SigmaString from parts, merging adjacent text."""
    merged: List[_Part] = []
    for part in parts:
        if isinstance(part, str):
            if not part:
                continue
            if merged and isinstance(merged[-1], str):
                merged[-1] = merged[-1] + part
                continue
        merged.append(part)
    result = SigmaString("")
    result.s = merged
    result.original = str(result)
    return result


def _from_text(text: str) -> SigmaString:
    """Build a SigmaString from literal text where ``*`` is a wildcard."""
    parts: List[_Part] = []
    for i, chunk in enumerate(text.split("*")):
        if i:
            parts.append(_WILD)
        parts.append(chunk)
    return _make(parts)


def _unsupported(value: SigmaType) -> TransformFailure:
    return TransformFailure(f"cannot be applied to {type(value).__name__}")


def _string(value: SigmaType) -> SigmaString:
    if not isinstance(value, SigmaString):
        raise _unsupported(value)
    return value


def _plain_text(value: SigmaType) -> str:
    string = _string(value)
    if string.contains_special():
        raise TransformFailure(f"value '{string}' contains wildcards")
    return "".join(p for p in string.s if isinstance(p, str))


def _require_params(kind: str, params: Any) -> Dict[str, Any]:
    if not isinstance(params, dict):
        raise ValueError(f"transform {kind}: parameters must be a mapping")
    return params


def _require_keys(kind: str, params: Dict[str, Any], required: Sequence[str], optional: Sequence[str] = ()) -> None:
    missing = [k for k in required if k not in params]
    unknown = [k for k in params if k not in (*required, *optional)]
    if missing:
        raise ValueError(f"transform {kind}: missing parameter(s) {', '.join(missing)}")
    if unknown:
        raise ValueError(f"transform {kind}: unknown parameter(s) {', '.join(map(str, unknown))}")


def _require_path(kind: str, name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"transform {kind}: {name} must be a non-empty field path")
    return value


class Transform(ABC):
    """One value transform."""

    kind: ClassVar[str]
    supplies_targets: ClassVar[bool] = False

    @classmethod
    @abstractmethod
    def from_params(cls, params: Any) -> "Transform":
        """Validate ``params`` and build the transform; raise ``ValueError`` if they are bad."""

    def required_paths(self) -> Tuple[str, ...]:
        """Return the schema paths the profile validator must resolve."""
        return ()

    @abstractmethod
    def apply(self, value: SigmaType, targets: Tuple[str, ...], *, field: str, all_values: bool) -> List[Alternative]:
        """Return the alternatives replacing ``value`` for ``targets``."""


class _NoParams(Transform):
    @classmethod
    def from_params(cls, params: Any) -> "Transform":
        """Build the transform from validated profile parameters."""
        if params not in (None, {}):
            raise ValueError(f"transform {cls.kind}: takes no parameters")
        return cls()


def _scalar(kind: str, v: Any) -> SigmaType:
    if isinstance(v, bool):
        return SigmaBool(v)
    if isinstance(v, int):
        return SigmaNumber(v)
    if isinstance(v, str):
        return SigmaString(v)
    raise ValueError(f"transform {kind}: map values must be strings, numbers or booleans")


class MapTransform(Transform):
    """Look values up in a table."""

    kind = "map"

    def __init__(self, table: Dict[str, Tuple[SigmaType, ...]], default: str):
        """Store the validated parameters."""
        self.table = table
        self.default = default

    @classmethod
    def from_params(cls, params: Any) -> "MapTransform":
        """Build the transform from validated profile parameters."""
        params = _require_params(cls.kind, params)
        _require_keys(cls.kind, params, ["values"], ["default"])
        default = params.get("default", "fail")
        if default not in ("keep", "fail"):
            raise ValueError("transform map: default must be keep or fail")
        values = params["values"]
        if not isinstance(values, dict) or not values:
            raise ValueError("transform map: values must be a non-empty mapping")
        table: Dict[str, Tuple[SigmaType, ...]] = {}
        for key, out in values.items():
            outs = out if isinstance(out, list) else [out]
            if not outs:
                raise ValueError(f"transform map: no output for '{key}'")
            table[str(key).lower()] = tuple(_scalar(cls.kind, o) for o in outs)
        return cls(table, default)

    def apply(self, value, targets, *, field, all_values):
        """Apply the transform to one value."""
        if isinstance(value, SigmaString) and not value.contains_special():
            key: Optional[str] = _plain_text(value).lower()
        elif isinstance(value, (SigmaNumber, SigmaBool)):
            key = str(value).lower()
        elif isinstance(value, SigmaString):
            key = None
        else:
            raise _unsupported(value)
        if key is not None and key in self.table:
            return [(targets, out) for out in self.table[key]]
        if self.default == "keep":
            return [(targets, value)]
        raise TransformFailure(f"value '{value}' is not in the map")


class CaseTransform(Transform):
    """Change the case of string values."""

    kind = "case"

    def __init__(self, mode: str):
        """Store the validated parameters."""
        self.mode = mode

    @classmethod
    def from_params(cls, params: Any) -> "CaseTransform":
        """Build the transform from validated profile parameters."""
        if params not in ("upper", "lower"):
            raise ValueError("transform case: parameter must be upper or lower")
        return cls(params)

    def apply(self, value, targets, *, field, all_values):
        """Apply the transform to one value."""
        string = _string(value)
        return [(targets, string.upper() if self.mode == "upper" else string.lower())]


class BasenameTransform(_NoParams):
    """Keep only the last path component."""

    kind = "basename"
    _CANNOT = "basename cannot express a pattern on the directory"

    def apply(self, value, targets, *, field, all_values):
        """Apply the transform to one value."""
        parts = _string(value).s
        index = pos = -1
        for i, part in enumerate(parts):
            if isinstance(part, str):
                found = max(part.rfind("\\"), part.rfind("/"))
                if found >= 0:
                    index, pos = i, found
        if index < 0:
            return [(targets, value)]
        head: List[_Part] = [*parts[:index], str(parts[index])[: pos + 1]]
        tail: List[_Part] = [str(parts[index])[pos + 1 :], *parts[index + 1 :]]
        tail = [p for p in tail if p != ""]
        if not tail or tail[-1] is _WILD:
            raise TransformFailure(self._CANNOT)
        if not (len(head) == 2 and head[0] is _WILD and head[1] in ("\\", "/")):
            warnings.warn(
                "basename: directory dropped; the match is broader than the rule's",
                UserWarning,
                stacklevel=2,
            )
        if any(not isinstance(p, str) for p in tail):
            warnings.warn(
                "basename: a wildcard in the file name may span directories; the match is narrower than the rule's",
                UserWarning,
                stacklevel=2,
            )
        return [(targets, _make(tail))]


class PathPrefixTransform(Transform):
    """Rewrite the start of a path."""

    kind = "path_prefix"

    def __init__(self, rules: Tuple[Tuple["re.Pattern[str]", str], ...]):
        """Store the validated parameters."""
        self.rules = rules

    @classmethod
    def from_params(cls, params: Any) -> "PathPrefixTransform":
        """Build the transform from validated profile parameters."""
        params = _require_params(cls.kind, params)
        _require_keys(cls.kind, params, ["rewrite"])
        rewrite = params["rewrite"]
        if not isinstance(rewrite, list) or not rewrite:
            raise ValueError("transform path_prefix: rewrite must be a non-empty list")
        rules = []
        for rule in rewrite:
            if not isinstance(rule, dict) or set(rule) != {"from", "to"}:
                raise ValueError("transform path_prefix: each rule needs from and to")
            if not isinstance(rule["from"], str) or not isinstance(rule["to"], str):
                raise ValueError("transform path_prefix: from and to must be strings")
            try:
                pattern = re.compile(rule["from"], re.IGNORECASE)
            except re.error as e:
                raise ValueError(f"transform path_prefix: bad regex '{rule['from']}': {e}") from e
            rules.append((pattern, rule["to"]))
        return cls(tuple(rules))

    def apply(self, value, targets, *, field, all_values):
        """Apply the transform to one value."""
        parts = _string(value).s
        if not parts or not isinstance(parts[0], str):
            return [(targets, value)]
        for pattern, to in self.rules:
            m = pattern.match(parts[0])
            if m:
                new = _from_text(to)
                return [(targets, _make([*new.s, parts[0][m.end() :], *parts[1:]]))]
        return [(targets, value)]


# (canonical name, short, long, kernel)
_HIVES = {
    "machine": ("HKLM", "HKEY_LOCAL_MACHINE", "\\REGISTRY\\MACHINE"),
    "users": ("HKU", "HKEY_USERS", "\\REGISTRY\\USER"),
    "current": ("HKU\\*", "HKEY_CURRENT_USER", "\\REGISTRY\\USER\\*"),
    "classes": (
        "HKCR",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes",
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes",
    ),
}
_HIVE_INPUTS = sorted(
    [
        ("HKLM", "machine"),
        ("HKEY_LOCAL_MACHINE", "machine"),
        ("\\REGISTRY\\MACHINE", "machine"),
        ("HKU", "users"),
        ("HKEY_USERS", "users"),
        ("\\REGISTRY\\USER", "users"),
        ("HKCU", "current"),
        ("HKEY_CURRENT_USER", "current"),
        ("HKCR", "classes"),
        ("HKEY_CLASSES_ROOT", "classes"),
        ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes", "classes"),
        ("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes", "classes"),
    ],
    key=lambda item: -len(item[0]),
)
_HIVE_STYLES = ("short", "long", "kernel")


class RegistryPathTransform(Transform):
    """Rewrite the hive of a registry path, optionally joining key and value name."""

    kind = "registry_path"

    def __init__(self, hive: str, split: Optional[Tuple[str, str]]):
        """Store the validated parameters."""
        self.hive = hive
        self.split = split

    @classmethod
    def from_params(cls, params: Any) -> "RegistryPathTransform":
        """Build the transform from validated profile parameters."""
        params = _require_params(cls.kind, params)
        _require_keys(cls.kind, params, ["hive"], ["split"])
        if params["hive"] not in _HIVE_STYLES:
            raise ValueError("transform registry_path: hive must be short, long or kernel")
        split = None
        if "split" in params:
            sp = _require_params(cls.kind, params["split"])
            _require_keys(cls.kind, sp, ["key", "value"])
            split = (
                _require_path(cls.kind, "key", sp["key"]),
                _require_path(cls.kind, "value", sp["value"]),
            )
        return (_RegistryPathSplit if split else cls)(params["hive"], split)

    def required_paths(self):
        """Return the schema paths named by the parameters."""
        return self.split or ()

    def apply(self, value, targets, *, field, all_values):
        """Apply the transform to one value."""
        if self.split is not None:
            targets = (join_field_name("\\", list(self.split)),)
        return [(targets, self._rewrite(_string(value)))]

    def _rewrite(self, value: SigmaString) -> SigmaString:
        parts = value.s
        if not parts or not isinstance(parts[0], str):
            return value
        first = parts[0]
        for spelling, hive in _HIVE_INPUTS:
            n = len(spelling)
            if first[:n].lower() != spelling.lower():
                continue
            rest = first[n:]
            if rest == "" and len(parts) > 1:
                continue
            if rest != "" and rest[0] != "\\":
                continue
            out = _HIVES[hive][_HIVE_STYLES.index(self.hive)]
            return _make([*_from_text(out).s, rest, *parts[1:]])
        return value


class _RegistryPathSplit(RegistryPathTransform):
    """Registry path transform that also supplies the joined key and value targets."""

    supplies_targets = True


_HASH_LENGTHS = {32: "MD5", 40: "SHA1", 64: "SHA256"}
_DIGEST_LENGTHS = {"MD5": 32, "IMPHASH": 32, "SHA1": 40, "SHA256": 64}
_HEX = re.compile(r"[0-9a-fA-F]+")


class HashesTransform(Transform):
    """Route a hash value to the column of its algorithm."""

    kind = "hashes"
    supplies_targets = True
    ALGOS = ("MD5", "SHA1", "SHA256", "IMPHASH")

    def __init__(self, algos: Dict[str, str]):
        """Store the validated parameters."""
        self.algos = algos

    @classmethod
    def from_params(cls, params: Any) -> "HashesTransform":
        """Build the transform from validated profile parameters."""
        params = _require_params(cls.kind, params)
        _require_keys(cls.kind, params, ["algos"])
        algos = _require_params(cls.kind, params["algos"])
        if not algos:
            raise ValueError("transform hashes: algos must not be empty")
        for name, path in algos.items():
            if name not in cls.ALGOS:
                raise ValueError(f"transform hashes: unknown algorithm {name}")
            _require_path(cls.kind, name, path)
        return cls(dict(algos))

    def required_paths(self):
        """Return the schema paths named by the parameters."""
        return tuple(self.algos.values())

    def apply(self, value, targets, *, field, all_values):
        """Apply the transform to one value."""
        parts = list(_string(value).s)
        if parts and parts[0] is _WILD:
            parts = parts[1:]
        if parts and parts[-1] is _WILD:
            parts = parts[:-1]
        texts = [p for p in parts if isinstance(p, str)]
        if len(texts) != len(parts):
            raise TransformFailure(f"value '{value}' is not a plain hash")
        text = "".join(texts)
        if "=" in text:
            algo, digest = text.split("=", 1)
            algo = algo.upper()
            if algo not in self.ALGOS:
                raise TransformFailure(f"value '{value}' is not a hash")
            if len(digest) != _DIGEST_LENGTHS[algo]:
                raise TransformFailure(f"{algo} digest must have {_DIGEST_LENGTHS[algo]} characters")
        else:
            digest = text
            algo = _HASH_LENGTHS.get(len(text), "")
            if not algo:
                raise TransformFailure(f"cannot tell the hash algorithm of '{value}'")
        if not _HEX.fullmatch(digest):
            raise TransformFailure(f"value '{value}' is not a hexadecimal digest")
        if algo not in self.algos:
            if all_values:
                raise TransformFailure(f"algorithm {algo} is not available")
            warnings.warn(f"hashes: algorithm {algo} dropped, it is not available", UserWarning, stacklevel=2)
            return []
        return [((self.algos[algo],), SigmaString(digest))]


class DomainUserTransform(Transform):
    r"""Match DOMAIN\user values against the joined domain and user fields."""

    kind = "domain_user"
    supplies_targets = True

    def __init__(self, domain: str, user: str):
        """Store the validated parameters."""
        self.domain = domain
        self.user = user

    @classmethod
    def from_params(cls, params: Any) -> "DomainUserTransform":
        """Build the transform from validated profile parameters."""
        params = _require_params(cls.kind, params)
        _require_keys(cls.kind, params, ["domain", "user"])
        return cls(_require_path(cls.kind, "domain", params["domain"]), _require_path(cls.kind, "user", params["user"]))

    def required_paths(self):
        """Return the schema paths named by the parameters."""
        return (self.domain, self.user)

    def apply(self, value, targets, *, field, all_values):
        """Apply the transform to one value."""
        return [((join_field_name("\\", [self.domain, self.user]),), _string(value))]


class RegexReplaceTransform(Transform):
    """Regex substitution on the plain parts of a string."""

    kind = "regex_replace"

    def __init__(self, pattern: "re.Pattern[str]", replacement: str):
        """Store the validated parameters."""
        self.pattern = pattern
        self.replacement = replacement

    @classmethod
    def from_params(cls, params: Any) -> "RegexReplaceTransform":
        """Build the transform from validated profile parameters."""
        params = _require_params(cls.kind, params)
        _require_keys(cls.kind, params, ["pattern", "replacement"])
        if not isinstance(params["pattern"], str) or not isinstance(params["replacement"], str):
            raise ValueError("transform regex_replace: pattern and replacement must be strings")
        try:
            return cls(re.compile(params["pattern"]), params["replacement"])
        except re.error as e:
            raise ValueError(f"transform regex_replace: bad regex: {e}") from e

    def apply(self, value, targets, *, field, all_values):
        """Apply the transform to one value."""
        return [(targets, _string(value).map_str_parts(lambda s: self.pattern.sub(self.replacement, s)))]


class ToIntTransform(_NoParams):
    """Turn digit strings into numbers."""

    kind = "to_int"

    def apply(self, value, targets, *, field, all_values):
        """Apply the transform to one value."""
        if isinstance(value, SigmaNumber):
            return [(targets, value)]
        text = _plain_text(value)
        if not (text.isascii() and text.isdigit()):
            raise TransformFailure(f"value '{text}' is not an integer")
        return [(targets, SigmaNumber(int(text)))]


class ToStrTransform(_NoParams):
    """Turn numbers and booleans into strings."""

    kind = "to_str"

    def apply(self, value, targets, *, field, all_values):
        """Apply the transform to one value."""
        if isinstance(value, (SigmaNumber, SigmaBool)):
            return [(targets, SigmaString(str(value).lower()))]
        if isinstance(value, SigmaString):
            return [(targets, value)]
        raise _unsupported(value)


KINDS: Dict[str, Type[Transform]] = {
    cls.kind: cls
    for cls in (
        MapTransform,
        CaseTransform,
        BasenameTransform,
        PathPrefixTransform,
        RegistryPathTransform,
        HashesTransform,
        DomainUserTransform,
        RegexReplaceTransform,
        ToIntTransform,
        ToStrTransform,
    )
}


def parse_transform(spec: Any, named: Mapping[str, Sequence[Transform]]) -> Tuple[Transform, ...]:
    """Parse a transform spec (name, ``{kind: params}`` or a list of those) into a chain."""
    chain = _parse(spec, named)
    for t in chain[:-1]:
        if t.supplies_targets:
            raise ValueError(f"transform {t.kind} supplies the targets and must be last in the chain")
    return chain


def _parse(spec: Any, named: Mapping[str, Sequence[Transform]]) -> Tuple[Transform, ...]:
    if isinstance(spec, str):
        if spec in named:
            return tuple(named[spec])
        if spec in KINDS:
            return (KINDS[spec].from_params(None),)
        raise ValueError(f"unknown transform '{spec}'")
    if isinstance(spec, dict):
        if len(spec) != 1:
            raise ValueError("a transform must be a single {kind: parameters} entry")
        ((kind, params),) = spec.items()
        if kind not in KINDS:
            raise ValueError(f"unknown transform kind '{kind}'")
        return (KINDS[kind].from_params(params),)
    if isinstance(spec, list):
        if not spec:
            raise ValueError("a transform list must not be empty")
        return tuple(t for item in spec for t in _parse(item, named))
    raise ValueError(f"bad transform spec: {spec!r}")


def apply_chain(
    chain: Sequence[Transform],
    value: SigmaType,
    targets: Tuple[str, ...],
    *,
    field: str,
    all_values: bool,
) -> List[Alternative]:
    """Apply ``chain`` in order, fanning out over the alternatives each step returns."""
    alternatives: List[Alternative] = [(targets, value)]
    for transform in chain:
        alternatives = [
            out for t, v in alternatives for out in transform.apply(v, t, field=field, all_values=all_values)
        ]
    return alternatives
