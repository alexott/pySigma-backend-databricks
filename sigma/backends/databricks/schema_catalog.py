"""Catalog of Lakewatch parser output schemas (paths, types and storage kinds)."""
import json
from dataclasses import dataclass, field
from importlib.resources import files
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from sigma.exceptions import SigmaConfigurationError

_BUILTIN_PACKAGE = "sigma.backends.databricks.lakewatch_schemas"
_BUNDLED_FILES = ("windows_custom.json", "builtin.json")


@dataclass(frozen=True)
class PathInfo:
    """A field path in a parser's output.

    ``storage`` is ``column`` (top level), ``struct`` (member of a STRUCT) or ``variant``
    (declared inside a VARIANT). ``element`` is the element type when ``type`` is ARRAY.
    """

    type: str
    storage: str
    required: bool = False
    allowed: Optional[Tuple[str, ...]] = None
    element: Optional[str] = None


@dataclass(frozen=True)
class ParserSchema:
    """Output schema of one parser. Paths use dots, with ``[]`` after an array segment."""

    name: str
    uuid: Optional[str]
    version: Optional[int]
    paths: Mapping[str, PathInfo] = field(default_factory=dict)

    def get(self, path: str) -> Optional[PathInfo]:
        """Return the declared path (exact spelling), or None."""
        return self.paths.get(path)


class _ShapeError(ValueError):
    """A schema file whose JSON does not have the catalog shape."""


def _parse_path(info: object, where: str) -> PathInfo:
    if not isinstance(info, dict):
        raise _ShapeError(f"{where} must be an object")
    for key in ("type", "storage"):
        if not isinstance(info.get(key), str):
            raise _ShapeError(f"{where}: missing '{key}' (a string)")
    allowed = info.get("allowed")
    if allowed is not None and (
        not isinstance(allowed, list) or not all(isinstance(a, str) for a in allowed)
    ):
        raise _ShapeError(f"{where}: 'allowed' must be a list of strings")
    element = info.get("element")
    if element is not None and not isinstance(element, str):
        raise _ShapeError(f"{where}: 'element' must be a string")
    return PathInfo(
        type=info["type"],
        storage=info["storage"],
        required=bool(info.get("required", False)),
        allowed=tuple(allowed) if allowed is not None else None,
        element=element,
    )


def _parse_catalog(data: object) -> Dict[str, ParserSchema]:
    """Parse a catalog document, raising _ShapeError if it is not shaped like one."""
    if not isinstance(data, dict):
        raise _ShapeError("top level must be a JSON object")
    parsers = data.get("parsers", {})
    if not isinstance(parsers, dict):
        raise _ShapeError("'parsers' must be an object")
    result = {}
    for name, parser in parsers.items():
        if not isinstance(parser, dict):
            raise _ShapeError(f"parser '{name}' must be an object")
        paths = parser.get("paths", {})
        if not isinstance(paths, dict):
            raise _ShapeError(f"parser '{name}': 'paths' must be an object")
        result[name] = ParserSchema(
            name=name,
            uuid=parser.get("uuid"),
            version=parser.get("version"),
            paths={p: _parse_path(i, f"parser '{name}': path '{p}'") for p, i in paths.items()},
        )
    return result


@dataclass
class SchemaCatalog:
    """Parser output schemas by parser name."""

    schemas: Dict[str, ParserSchema]

    def get(self, parser: str) -> ParserSchema:
        """Return the schema of ``parser``; SigmaConfigurationError if it is unknown."""
        try:
            return self.schemas[parser]
        except KeyError:
            raise SigmaConfigurationError(
                f"Unknown parser '{parser}'. Known parsers: {', '.join(self.names())}"
            ) from None

    def names(self) -> List[str]:
        """Return the sorted names of all known parsers."""
        return sorted(self.schemas)

    @classmethod
    def load(cls, extra_files: Sequence[str] = ()) -> "SchemaCatalog":
        """Load the bundled catalogs, then each extra file; later entries replace earlier ones."""
        schemas: Dict[str, ParserSchema] = {}
        for bundled_name in _BUNDLED_FILES:
            bundled = files(_BUILTIN_PACKAGE).joinpath(bundled_name)
            if bundled.is_file():
                schemas.update(_parse_catalog(json.loads(bundled.read_text(encoding="utf-8"))))
        for extra in extra_files:
            try:
                with open(extra, encoding="utf-8") as fh:
                    schemas.update(_parse_catalog(json.load(fh)))
            except _ShapeError as exc:
                raise SigmaConfigurationError(f"Invalid parser schema file '{extra}': {exc}") from None
            except (OSError, ValueError) as exc:
                raise SigmaConfigurationError(f"Cannot load parser schema file '{extra}': {exc}") from exc
        return cls(schemas)
