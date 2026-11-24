"""Catalog of Lakewatch parser output schemas (paths, types and storage kinds)."""
import json
from dataclasses import dataclass, field
from importlib.resources import files
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from sigma.exceptions import SigmaConfigurationError

_BUILTIN_PACKAGE = "sigma.backends.databricks.lakewatch_schemas"
_BUILTIN_FILE = "builtin.json"


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
        return self.paths.get(path)


def _parse_path(info: Mapping) -> PathInfo:
    allowed = info.get("allowed")
    return PathInfo(
        type=info["type"],
        storage=info["storage"],
        required=bool(info.get("required", False)),
        allowed=tuple(allowed) if allowed is not None else None,
        element=info.get("element"),
    )


def _parse_catalog(data: Mapping) -> Dict[str, ParserSchema]:
    result = {}
    for name, parser in data.get("parsers", {}).items():
        result[name] = ParserSchema(
            name=name,
            uuid=parser.get("uuid"),
            version=parser.get("version"),
            paths={p: _parse_path(i) for p, i in parser.get("paths", {}).items()},
        )
    return result


@dataclass
class SchemaCatalog:
    schemas: Dict[str, ParserSchema]

    def get(self, parser: str) -> ParserSchema:
        try:
            return self.schemas[parser]
        except KeyError:
            raise SigmaConfigurationError(
                f"Unknown parser '{parser}'. Known parsers: {', '.join(self.names())}"
            ) from None

    def names(self) -> List[str]:
        return sorted(self.schemas)

    @classmethod
    def load(cls, extra_files: Sequence[str] = ()) -> "SchemaCatalog":
        """Load the builtin catalog, then each extra file; later entries replace earlier ones."""
        schemas: Dict[str, ParserSchema] = {}
        builtin = files(_BUILTIN_PACKAGE).joinpath(_BUILTIN_FILE)
        if builtin.is_file():
            schemas.update(_parse_catalog(json.loads(builtin.read_text(encoding="utf-8"))))
        for extra in extra_files:
            try:
                with open(extra, encoding="utf-8") as fh:
                    schemas.update(_parse_catalog(json.load(fh)))
            except (OSError, ValueError, KeyError) as exc:
                raise SigmaConfigurationError(f"Cannot load parser schema file '{extra}': {exc}") from exc
        return cls(schemas)
