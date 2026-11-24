"""Compile one Lakewatch mapping profile logsource block into a pySigma pipeline."""
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional, Tuple, Union

from sigma.exceptions import SigmaTransformationError
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldMappingTransformation,
    SetStateTransformation,
)
from sigma.processing.transformations.base import DetectionItemTransformation
from sigma.types import SigmaFieldReference

from .profile import LogsourceBlock, Profile

STATE_PROFILE = "lakewatch_profile"
STATE_PROFILE_VERSION = "lakewatch_profile_version"
STATE_PARSER = "lakewatch_parser"


@dataclass
class StrictFieldsTransformation(DetectionItemTransformation):
    """Fail closed on keywords, unsupported fields and fields the profile does not map."""

    profile_id: str
    allowed: FrozenSet[str]
    prefixes: Tuple[str, ...]
    unsupported: FrozenSet[str]

    def _check(self, field: str) -> None:
        if field in self.unsupported:
            raise SigmaTransformationError(
                f"field {field} is not supported by profile {self.profile_id}"
            )
        if field not in self.allowed and not any(
            field.startswith(p) and len(field) > len(p) for p in self.prefixes
        ):
            raise SigmaTransformationError(
                f"field {field} is not mapped by profile {self.profile_id}"
            )

    def apply_detection_item(self, detection_item):
        field = detection_item.field
        if field is None:
            raise SigmaTransformationError(
                f"keyword search is not supported by profile {self.profile_id}"
            )
        self._check(field)
        for value in detection_item.value:
            if isinstance(value, SigmaFieldReference):
                self._check(value.field)
        return None


@dataclass
class ProfileFieldMapping(FieldMappingTransformation):
    """Map original Sigma field names: exact keys first, then prefix rewrites.

    The decision is made on the original name in a single pass, so an exact mapping's
    output is never rewritten by a prefix rule. pySigma applies ``apply_field_name`` to
    field-reference values as well, so references are mapped the same way.
    """

    prefix_rewrites: Tuple[Tuple[str, str], ...] = ()

    def apply_field_name(self, field):
        if field is None:
            return None
        if field in self.mapping:
            return self.mapping[field]
        for src, dst in self.prefix_rewrites:
            if field.startswith(src) and len(field) > len(src):
                return dst + field[len(src):]
        return None


def build_profile_pipeline(profile: Profile, block: LogsourceBlock) -> ProcessingPipeline:
    pid = profile.profile
    mappings = profile.mappings_for(block)
    exact = {k: v for k, v in mappings.items() if not k.endswith(".*")}
    prefix_maps = {k[:-1]: v for k, v in mappings.items() if k.endswith(".*")}

    items: List[ProcessingItem] = [
        ProcessingItem(
            transformation=StrictFieldsTransformation(
                profile_id=pid,
                allowed=frozenset(exact),
                prefixes=tuple(prefix_maps),
                unsupported=frozenset(block.unsupported),
            ),
            identifier=f"lakewatch_{pid}_strict_fields",
        )
    ]

    exact_map: Dict[Optional[str], Union[str, List[str]]] = {
        k: (v.targets[0] if len(v.targets) == 1 else list(v.targets)) for k, v in exact.items()
    }
    rewrites = tuple(
        (src, v.targets[0][:-1])
        for src, v in prefix_maps.items()
        if v.targets[0][:-1] != src
    )
    items.append(
        ProcessingItem(
            transformation=ProfileFieldMapping(exact_map, prefix_rewrites=rewrites),
            identifier=f"lakewatch_{pid}_fields",
        )
    )

    if block.conditions:
        conditions: Dict[str, Any] = dict(block.conditions)
        items.append(
            ProcessingItem(
                transformation=AddConditionTransformation(conditions),
                identifier=f"lakewatch_{pid}_conditions",
            )
        )

    for key, value, ident in (
        (STATE_PROFILE, pid, "state_profile"),
        (STATE_PROFILE_VERSION, profile.version, "state_profile_version"),
        (STATE_PARSER, profile.parser, "state_parser"),
    ):
        items.append(
            ProcessingItem(
                transformation=SetStateTransformation(key, value),
                identifier=f"lakewatch_{pid}_{ident}",
            )
        )

    return ProcessingPipeline(name=f"Lakewatch profile {pid}", priority=100, items=items)
