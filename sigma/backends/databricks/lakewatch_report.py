"""Lakewatch conversion report: per-result recording, field resolution, warning capture and lint."""

import warnings
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Sequence, Tuple

from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule

from sigma.backends.databricks.schema_catalog import ParserSchema

if TYPE_CHECKING:
    from sigma.pipelines.databricks.lakewatch.profile import LogsourceBlock, Profile


class LakewatchApproximateWarning(UserWarning):
    """A conversion that only approximates the rule (raw keyword search, JSON text of a VARIANT)."""


@contextmanager
def capture_warnings(reemit: bool = True) -> Iterator[List[warnings.WarningMessage]]:
    """Record the warnings raised inside the block; re-emit them on exit unless ``reemit`` is False."""
    recorded: List[warnings.WarningMessage] = []
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            try:
                yield caught
            finally:
                recorded.extend(caught)
    finally:
        # Outside catch_warnings, so that the outer filters apply; also when the block raised.
        if reemit:
            for w in recorded:
                warnings.warn_explicit(w.message, w.category, w.filename, w.lineno)


def _collect_fields(detection: Any, found: List[str]) -> None:
    if isinstance(detection, SigmaDetection):
        for item in detection.detection_items:
            _collect_fields(item, found)
    elif isinstance(detection, SigmaDetectionItem):
        if detection.field is not None and detection.field not in found:
            found.append(detection.field)
        for value in detection.value:
            if isinstance(value, SigmaDetection):
                _collect_fields(value, found)


def rule_fields(rule: SigmaRule) -> List[str]:
    """Distinct detection-item field names of the rule (keywords excluded), in first-use order."""
    found: List[str] = []
    for detection in rule.detection.detections.values():
        _collect_fields(detection, found)
    return found


def _top_level_columns(schema: ParserSchema) -> Dict[str, str]:
    """Lower-case name -> declared name of the top-level columns of a parser schema."""
    columns: Dict[str, str] = {}
    for path, info in schema.paths.items():
        if info.storage == "column":
            name = path.split(".", 1)[0].replace("[]", "")
            columns.setdefault(name.lower(), name)
    return columns


def describe_fields(
    profile: "Profile", block: "LogsourceBlock", schema: ParserSchema, fields: Sequence[str]
) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    """Resolve each field the way the profile pipeline does; return the fields mapping and lint messages."""
    explicit = {**profile.fields, **block.fields}
    merged = profile.mappings_for(block)
    exact = {k: v for k, v in merged.items() if not k.endswith(".*")}
    prefixes = {k[:-1]: v for k, v in merged.items() if k.endswith(".*")}
    lenient = profile.event_data_any(block)
    unsupported = {u.lower() for u in block.unsupported} if lenient else set(block.unsupported)
    columns = _top_level_columns(schema)
    result: Dict[str, Dict[str, Any]] = {}
    lint: List[str] = []
    for name in fields:
        if (name.lower() if lenient else name) in unsupported:
            result[name] = {"targets": [], "resolution": "unmapped"}
            continue
        key: Optional[str] = name if name in exact else None
        if key is None and lenient:
            key = next((k for k in exact if k.lower() == name.lower()), None)
        if key is not None:
            resolution = "mapped" if key in explicit else "event_data"
            result[name] = {"targets": list(exact[key].targets), "resolution": resolution}
            continue
        prefix = next((p for p in prefixes if name.startswith(p) and len(name) > len(p)), None)
        if prefix is not None:
            rest = name[len(prefix):]
            result[name] = {"targets": [t[:-1] + rest for t in prefixes[prefix].targets], "resolution": "prefix"}
            continue
        if lenient and "[" not in name and "]" not in name:
            col = profile.event_data_column
            result[name] = {"targets": [f"{col}[{name}]"], "resolution": "lenient"}
            declared = columns.get(name.lower())
            if declared is not None:
                lint.append(
                    f"field {name} is read from {col}[{name}] by event_data any, but {declared} "
                    f"is a top-level column of parser {profile.parser}; map it explicitly")
            continue
        result[name] = {"targets": [], "resolution": "unmapped"}
    return result, lint


class ConversionReport:
    """Collects per-rule and per-profile-result records of one Lakewatch conversion."""

    def __init__(self) -> None:
        """Create an empty report."""
        self._rules: List[Dict[str, Any]] = []
        self._index: Dict[int, int] = {}
        self._keep: List[Any] = []  # keeps rules alive so that id() stays unique
        self._results: Dict[str, Dict[str, Any]] = {}

    def _rule_record(self, rule: Any) -> Tuple[int, Dict[str, Any]]:
        position = self._index.get(id(rule))
        if position is None:
            ls = getattr(rule, "logsource", None)
            source = getattr(rule, "source", None)
            path = getattr(source, "path", None)
            rule_id = getattr(rule, "id", None)
            record: Dict[str, Any] = {
                "sigma_id": str(rule_id) if rule_id is not None else None,
                "title": getattr(rule, "title", None),
                "source": str(path) if path is not None else None,
                "logsource": (
                    {"product": ls.product, "category": ls.category, "service": ls.service}
                    if ls is not None else None),
                "status": None,
                "reason": None,
                "results": [],
            }
            position = len(self._rules)
            self._index[id(rule)] = position
            self._keep.append(rule)
            self._rules.append(record)
        return position, self._rules[position]

    def result(self, rule: Any, profile_ref: Optional[str]) -> Tuple[str, Dict[str, Any]]:
        """Create the rule record on first use and a new result; return ``(report_key, result)``."""
        position, record = self._rule_record(rule)
        result: Dict[str, Any] = {
            "profile": profile_ref,
            "status": "converted",
            "rule_names": [],
            "reason": None,
            "approximate": False,
            "fields": {},
            "warnings": [],
            "lint": [],
        }
        key = f"{position}:{len(record['results'])}"
        record["results"].append(result)
        self._results[key] = result
        return key, result

    def rule_failed(self, rule: Any, reason: str) -> None:
        """Mark the rule as failed with ``reason`` (the first reason wins)."""
        _, record = self._rule_record(rule)
        record["status"] = "failed"
        if record["reason"] is None:
            record["reason"] = reason

    def set_rule_name(self, report_key: str, rule_name: str) -> None:
        """Record a final (deduplicated) rule name of the result."""
        self._results[report_key]["rule_names"].append(rule_name)

    def mark_skipped(self, report_key: str, reason: str) -> None:
        """Mark the result as skipped."""
        result = self._results[report_key]
        result["status"] = "skipped"
        result["reason"] = reason

    def to_dict(self) -> Dict[str, Any]:
        """Return the report as plain data (statuses and summary are completed by the caller)."""
        return {"rules": self._rules}
