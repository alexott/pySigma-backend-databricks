"""Summary overrides for Lakewatch rules: the ``lakewatch:`` rule attribute and the overrides file."""

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import yaml
from sigma.exceptions import SigmaConfigurationError

OVERRIDE_KEYS = ("summary", "context", "select")
DEFAULT_SCOPE = "default"


@dataclass(frozen=True)
class OutputOverride:
    """Output settings of a rule: each key is None when it isn't set."""

    summary: Optional[str] = None
    context: Optional[Dict[str, str]] = None
    select: Optional[Dict[str, str]] = None


def _string_map(value: Any, key: str, where: str) -> Dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{where}: {key} must be a mapping of strings")
    for name, item in value.items():
        if not isinstance(name, str) or not isinstance(item, str):
            raise ValueError(f"{where}: {key} entry {name!r} must map a string to a string")
        if key == "context" and (not name.strip() or not item.strip()):
            raise ValueError(f"{where}: context entry {name!r} must have a non-empty key and value")
    return dict(value)


def parse_override(data: Any, where: str) -> OutputOverride:
    """Validate ``data`` as an override; raise ``ValueError`` with ``where`` in the message."""
    if not isinstance(data, dict):
        raise ValueError(f"{where}: expected a mapping with {', '.join(OVERRIDE_KEYS)}")
    unknown = [str(k) for k in data if k not in OVERRIDE_KEYS]
    if unknown:
        raise ValueError(f"{where}: unknown key {', '.join(unknown)}; expected {', '.join(OVERRIDE_KEYS)}")
    summary = data.get("summary")
    if "summary" in data and not isinstance(summary, str):
        raise ValueError(f"{where}: summary must be a string")
    if isinstance(summary, str) and not summary.strip():
        raise ValueError(f"{where}: summary must be a non-empty string")
    context = _string_map(data["context"], "context", where) if "context" in data else None
    select = _string_map(data["select"], "select", where) if "select" in data else None
    return OutputOverride(summary=summary, context=context, select=select)


def resolve_output(sources: Sequence[OutputOverride]) -> OutputOverride:
    """Merge ``sources`` per key: the first source that sets a key wins."""
    def first(name: str) -> Any:
        return next((getattr(s, name) for s in sources if getattr(s, name) is not None), None)

    return OutputOverride(summary=first("summary"), context=first("context"), select=first("select"))


@dataclass
class OverridesFile:
    """Overrides by lower-case Sigma id, then by ``default`` or a profile id."""

    entries: Dict[str, Dict[str, OutputOverride]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str) -> "OverridesFile":
        """Load and validate the file; raise SigmaConfigurationError naming the file."""
        prefix = f"overrides file {path}"
        try:
            data = yaml.safe_load(Path(path).expanduser().read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError, UnicodeDecodeError) as e:
            raise SigmaConfigurationError(f"{prefix}: cannot read: {e}") from None
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise SigmaConfigurationError(f"{prefix}: expected a mapping of Sigma ids to overrides")
        entries: Dict[str, Dict[str, OutputOverride]] = {}
        for key, value in data.items():
            try:
                sigma_id = str(uuid.UUID(key)) if isinstance(key, str) else None
            except ValueError:
                sigma_id = None
            if sigma_id is None:
                raise SigmaConfigurationError(f"{prefix}: key {key!r} is not a Sigma id (UUID)")
            where = f"{prefix}, {sigma_id}"
            inner = sigma_id
            if not isinstance(value, dict):
                raise SigmaConfigurationError(f"{where}: expected a mapping")
            has_override_keys = any(k in OVERRIDE_KEYS for k in value)
            if has_override_keys and any(k not in OVERRIDE_KEYS for k in value):
                raise SigmaConfigurationError(
                    f"{where}: mixes override keys ({', '.join(OVERRIDE_KEYS)}) and profile keys")
            try:
                if has_override_keys or not value:
                    scoped = {DEFAULT_SCOPE: parse_override(value, inner)}
                else:
                    scoped = {}
                    for scope, override in value.items():
                        if not isinstance(scope, str):
                            raise ValueError(f"{inner}: profile key {scope!r} must be a string")
                        scoped[scope] = parse_override(override, f"{inner}, {scope}")
            except ValueError as e:
                raise SigmaConfigurationError(f"{prefix}: {e}") from None
            entries[sigma_id] = scoped
        return cls(entries)

    def lookup(self, sigma_id: Optional[str], profile: str) -> List[OutputOverride]:
        """Return the entry scoped to ``profile``, then the ``default`` entry; skip missing ones."""
        scoped = self.entries.get(str(sigma_id).lower(), {}) if sigma_id else {}
        return [scoped[s] for s in (profile, DEFAULT_SCOPE) if s in scoped]
