"""Lookup tables and OCSF table resolution for the Lakewatch output format."""
import json
import os
import re
from typing import Dict, List, Optional

from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule

# OCSF class_uid -> Lakewatch gold-table name.
# Grounded in the Lakewatch gold-table list (OCSF class names in snake_case).
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
    6004: "datastore_activity",
    6005: "file_hosting_activity",
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

# Sigma status name (lower-case) -> Lakewatch fidelity.
FIDELITY_MAP: Dict[str, str] = {
    "stable": "High",
    "test": "Medium",
    "experimental": "Investigative",
}

_MITRE_PATH = os.path.join(os.path.dirname(__file__), "mitre_techniques.json")
with open(_MITRE_PATH, encoding="utf-8") as _fh:
    #: MITRE ATT&CK technique/sub-technique ID -> human-readable name.
    MITRE_TECHNIQUES: Dict[str, str] = json.load(_fh)


def build_mitre_mapping(rule: SigmaRule) -> List[dict]:
    tactics: List[str] = []
    techniques: Dict[str, Optional[str]] = {}
    for tag in rule.tags:
        if tag.namespace != "attack":
            continue
        name = tag.name
        if len(name) > 1 and name[0] == "t" and name[1].isdigit():
            tid = name.upper()
            if "." in tid:
                techniques[tid.split(".")[0]] = tid
            else:
                techniques.setdefault(tid, None)
        else:
            tactics.append(name.replace("_", " ").title())
    if not techniques:
        return []
    tactic = tactics[0] if tactics else ""
    entries: List[dict] = []
    for tid, sub in sorted(techniques.items()):
        entries.append({
            "taxonomy": "Enterprise",
            "tactic": tactic,
            "technique": MITRE_TECHNIQUES.get(tid, ""),
            "techniqueId": tid,
            "subTechnique": MITRE_TECHNIQUES.get(sub, "") if sub else "",
            "subTechniqueId": sub or "",
        })
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


def resolve_ocsf_table(rule: SigmaRule) -> Optional[str]:
    found = _collect_ocsf_fields(rule)
    if "class_uid" in found:
        return OCSF_CLASS_UID_TO_TABLE.get(int(found["class_uid"]))
    if "type_uid" in found:
        return OCSF_CLASS_UID_TO_TABLE.get(int(found["type_uid"]) // 100)
    if "class_name" in found:
        norm = "_".join(re.findall(r"[a-z0-9]+", found["class_name"].lower()))
        return norm if norm in GOLD_TABLES else None
    return None
