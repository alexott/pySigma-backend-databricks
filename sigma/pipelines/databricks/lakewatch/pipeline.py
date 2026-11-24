"""Compile one Lakewatch mapping profile logsource block into a pySigma pipeline."""
from dataclasses import dataclass
from typing import FrozenSet, List, Optional, Tuple

from sigma.exceptions import SigmaTransformationError
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldFunctionTransformation,
    FieldMappingTransformation,
    SetStateTransformation,
)
from sigma.processing.transformations.base import DetectionItemTransformation

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

    def apply_detection_item(self, detection_item):
        field = detection_item.field
        if field is None:
            raise SigmaTransformationError(
                f"keyword search is not supported by profile {self.profile_id}"
            )
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

    exact_map = {
        k: (v.targets[0] if len(v.targets) == 1 else list(v.targets)) for k, v in exact.items()
    }
    items.append(
        ProcessingItem(
            transformation=FieldMappingTransformation(exact_map),
            identifier=f"lakewatch_{pid}_fields",
        )
    )

    rewrites = [
        (src, v.targets[0][:-1])
        for src, v in prefix_maps.items()
        if v.targets[0][:-1] != src
    ]
    if rewrites:
        # Fields produced by exact mappings are final and must not be rewritten again.
        exact_targets = {t for v in exact.values() for t in v.targets}

        def rewrite(name: Optional[str]) -> Optional[str]:
            if name is None or name in exact_targets:
                return name
            for src, dst in rewrites:
                if name.startswith(src) and len(name) > len(src):
                    return dst + name[len(src):]
            return name

        items.append(
            ProcessingItem(
                transformation=FieldFunctionTransformation({}, rewrite),
                identifier=f"lakewatch_{pid}_prefixes",
            )
        )

    if block.conditions:
        items.append(
            ProcessingItem(
                transformation=AddConditionTransformation(dict(block.conditions)),
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
