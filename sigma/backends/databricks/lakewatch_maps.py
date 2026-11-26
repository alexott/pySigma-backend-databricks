"""Lookup tables and OCSF table resolution for the Lakewatch output format."""
import json
import os
import re
from importlib.metadata import PackageNotFoundError, version
from typing import Dict, List, Optional, Tuple

from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule

# OCSF class_uid -> Lakewatch gold-table name.
# Grounded in the Lakewatch gold-table list (OCSF class names in snake_case);
# class_uids follow the OCSF schema (category_uid * 1000 + class id).
OCSF_CLASS_UID_TO_TABLE: Dict[int, str] = {
    1001: "file_activity",
    1006: "scheduled_job_activity",
    1007: "process_activity",
    1009: "script_activity",
    2002: "vulnerability_finding",
    2004: "detection_finding",
    2005: "incident_finding",
    2006: "data_security_finding",
    3001: "account_change",
    3002: "authentication",
    3004: "entity_management",
    3005: "user_access",
    3006: "group_management",
    4001: "network_activity",
    4002: "http_activity",
    4003: "dns_activity",
    4004: "dhcp_activity",
    4007: "ssh_activity",
    4009: "email_activity",
    6003: "api_activity",
    6005: "datastore_activity",
    6006: "file_hosting_activity",
}

GOLD_TABLES: frozenset[str] = frozenset(OCSF_CLASS_UID_TO_TABLE.values())

# Sigma level name (lower-case) -> Lakewatch severity.
SEVERITY_MAP: Dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
}

_MITRE_PATH = os.path.join(os.path.dirname(__file__), "mitre_techniques.json")
with open(_MITRE_PATH, encoding="utf-8") as _fh:
    _MITRE_DATA: Dict[str, dict] = json.load(_fh)
#: MITRE ATT&CK technique/sub-technique ID -> human-readable name.
MITRE_TECHNIQUES: Dict[str, str] = {tid: info["name"] for tid, info in _MITRE_DATA.items()}
#: MITRE ATT&CK technique/sub-technique ID -> its tactics (``command-and-control``, ...).
MITRE_TECHNIQUE_TACTICS: Dict[str, List[str]] = {
    tid: list(info["tactics"]) for tid, info in _MITRE_DATA.items()
}
# Tactics that ATT&CK replaced, mapped to the tactics that took over their techniques. Sigma
# rules still use them as tags.
_LEGACY_TACTICS: Dict[str, Tuple[str, ...]] = {
    "defense-evasion": ("stealth", "defense-impairment"),
}
_MITRE_TACTICS = {t for tactics in MITRE_TECHNIQUE_TACTICS.values() for t in tactics} | set(
    _LEGACY_TACTICS
)


def _tactic_title(tactic: str) -> str:
    return tactic.replace("_", " ").title()


def _pick_tactic(technique: str, tagged: List[str]) -> str:
    """Tactic of ``technique``: a tagged one that ATT&CK lists for it, else its first ATT&CK one.

    For a technique missing from the table, the tagged tactic is used when there is exactly one.
    """
    known = MITRE_TECHNIQUE_TACTICS.get(technique)
    if not known:
        return _tactic_title(tagged[0]) if len(tagged) == 1 else ""
    for tactic in tagged:
        if tactic in known or set(_LEGACY_TACTICS.get(tactic, ())) & set(known):
            return _tactic_title(tactic)
    return _tactic_title(known[0])


def build_mitre_mapping(rule: SigmaRule) -> List[dict]:
    """Lakewatch MITRE entries of a rule: snake_case keys, empty fields left out.

    An entry without a tactic or a technique id is dropped.
    """
    tactics: List[str] = []
    techniques: Dict[str, Optional[str]] = {}
    for tag in rule.tags:
        if tag.namespace != "attack":
            continue
        name = tag.name
        if len(name) > 1 and name[0] == "t" and name[1].isdigit():
            tid = name.upper()
            if "." in tid:
                # Sibling sub-techniques of one parent collapse to a single
                # entry; the last tag encountered wins.
                techniques[tid.split(".")[0]] = tid
            else:
                techniques.setdefault(tid, None)
        elif name.replace("_", "-") in _MITRE_TACTICS:  # not groups (g0016) or software (s0002)
            tactics.append(name.replace("_", "-"))
    if not techniques:
        return []
    # Sigma tags do not bind a tactic to a technique: pick it per technique from ATT&CK.
    tagged = list(dict.fromkeys(tactics))
    entries: List[dict] = []
    for tid, sub in sorted(techniques.items()):
        entry = {
            "taxonomy": "Enterprise",
            "tactic": _pick_tactic(sub or tid, tagged),
            "technique": MITRE_TECHNIQUES.get(tid, ""),
            "technique_id": tid,
            "sub_technique": MITRE_TECHNIQUES.get(sub, "") if sub else "",
            "sub_technique_id": sub or "",
        }
        entry = {key: value for key, value in entry.items() if value}
        if entry.get("tactic") and entry.get("technique_id"):
            entries.append(entry)
    return entries


def _collect_ocsf_fields(rule: SigmaRule) -> Dict[str, str]:
    found: Dict[str, str] = {}
    for detection in rule.detection.detections.values():
        stack: List = list(detection.detection_items)
        while stack:
            item = stack.pop()
            if isinstance(item, SigmaDetection):
                stack.extend(item.detection_items)
            elif (
                isinstance(item, SigmaDetectionItem)
                and item.field in ("class_uid", "type_uid", "class_name")
                and item.value
            ):
                found[item.field] = str(item.value[0])
    return found


def _to_int(value: str) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def resolve_ocsf_table(rule: SigmaRule) -> Optional[str]:
    # Try each OCSF field in priority order and return the first that resolves,
    # so an unmappable or non-numeric class_uid falls through to type_uid then
    # class_name rather than short-circuiting to None or raising.
    found = _collect_ocsf_fields(rule)
    if "class_uid" in found:
        uid = _to_int(found["class_uid"])
        if uid is not None and uid in OCSF_CLASS_UID_TO_TABLE:
            return OCSF_CLASS_UID_TO_TABLE[uid]
    if "type_uid" in found:
        uid = _to_int(found["type_uid"])
        if uid is not None and uid // 100 in OCSF_CLASS_UID_TO_TABLE:
            return OCSF_CLASS_UID_TO_TABLE[uid // 100]
    if "class_name" in found:
        norm = "_".join(re.findall(r"[a-z0-9]+", found["class_name"].lower()))
        if norm in GOLD_TABLES:
            return norm
    return None


# Lakewatch v2 limits on the rule name and the references list.
V2_RULE_NAME_MAX_LEN = 256
V2_MAX_REFERENCES = 3
V2_REFERENCE_MAX_LEN = 512
# Lakewatch v2 limits on the text fields and annotations.
V2_DESCRIPTION_MAX_LEN = 4096
V2_OBJECTIVE_MAX_LEN = 65536
V2_RUNBOOK_MAX_LEN = 4096
V2_ANNOTATION_VALUE_MAX_LEN = 256

# Sigma status name (lower-case) -> Lakewatch v2 fidelity. Converted rules are untested against the
# target data, so they start at Investigative at most; everything else is Development.
V2_FIDELITY_MAP: Dict[str, str] = {
    "stable": "Investigative",
}

_ELLIPSIS = "..."


def truncate(text: str, limit: int) -> str:
    """Shorten text to at most ``limit`` characters, marking a cut with ``...``."""
    return text if len(text) <= limit else text[:limit - len(_ELLIPSIS)] + _ELLIPSIS


def _converter_version() -> str:
    try:
        return version("pySigma-backend-databricks")
    except PackageNotFoundError:  # pragma: no cover - running from a source tree without metadata
        return "unknown"


def build_v2_runbook(rule: SigmaRule) -> Optional[str]:
    """Runbook text listing the Sigma false positives, or None if the rule has none."""
    falsepositives = [str(fp).strip() for fp in rule.falsepositives or [] if str(fp).strip()]
    if not falsepositives:
        return None
    text = "Known false positives:\n" + "\n".join(f"- {fp}" for fp in falsepositives)
    return truncate(text, V2_RUNBOOK_MAX_LEN)


def build_v2_annotations(
    rule: SigmaRule, profile: Optional[str] = None, converter_version: bool = True
) -> Dict[str, str]:
    """Provenance annotations of a converted rule (Sigma id, status, author, tags, profile, converter).

    ``profile`` is the parser profile reference ``<id>@<version>`` (parsed mode only).
    ``converter_version=False`` leaves out the converter version (content packs: a converter
    release must not change the content hash of every rule).
    """
    tags = [f"{tag.namespace}.{tag.name}" for tag in rule.tags if tag.namespace != "attack"]
    candidates = {
        "sigma_id": str(rule.id) if rule.id else "",
        "sigma_status": rule.status.name.lower() if rule.status else "",
        "sigma_author": (rule.author or "").strip(),
        "sigma_tags": ", ".join(tags),
        "sigma_profile": profile or "",
        "converter_version": _converter_version() if converter_version else "",
    }
    return {
        key: truncate(value, V2_ANNOTATION_VALUE_MAX_LEN)
        for key, value in candidates.items()
        if value
    }


def to_v2_fidelity(fidelity: str) -> str:
    """Convert a fidelity short name (``Investigative``) into the v2 enum (``FIDELITY_INVESTIGATIVE``)."""
    value = fidelity.strip().upper()
    return value if value.startswith("FIDELITY_") else f"FIDELITY_{value}"


def to_v2_rule_name(title: str, suffix: str = "") -> str:
    """Derive a Unity Catalog-safe snake_case rule name from a rule title.

    The title part is cut so that title part plus ``suffix`` fits the name limit;
    the suffix itself is never cut.
    """
    limit = max(V2_RULE_NAME_MAX_LEN - len(suffix), 0)
    name = "_".join(re.findall(r"[a-z0-9]+", title.lower()))[:limit].strip("_")
    return (name or "sigma_rule") + suffix


def to_v2_references(references: List[str]) -> List[str]:
    """Select the references v2 accepts: http(s) URLs of at most 512 chars, at most 3."""
    return [
        ref for ref in references
        if len(ref) <= V2_REFERENCE_MAX_LEN and re.match(r"https?://", ref, re.IGNORECASE)
    ][:V2_MAX_REFERENCES]
