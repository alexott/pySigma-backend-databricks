"""Compile one Lakewatch mapping profile logsource block into a pySigma pipeline."""
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple, Union

from sigma.conditions import ConditionAND, ConditionOR
from sigma.exceptions import SigmaTransformationError
from sigma.modifiers import reverse_modifier_mapping
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldMappingTransformation,
    SetStateTransformation,
)
from sigma.processing.transformations.base import DetectionItemTransformation
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaLogSource
from sigma.types import SigmaBool, SigmaFieldReference, SigmaNumber, SigmaString, SigmaType

from .profile import FieldMapping, LogsourceBlock, Profile
from .transforms import Alternative, TransformFailure, apply_chain

_Node = Union[SigmaDetection, SigmaDetectionItem]


def _join(nodes: Sequence[_Node], linking: Any) -> _Node:
    """Link ``nodes`` with ``linking``; a single node is returned as it is."""
    if len(nodes) == 1:
        return nodes[0]
    return SigmaDetection(detection_items=list(nodes), item_linking=linking)

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
        """Check the item's field and field-reference values; the item is left unchanged."""
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

    Fields in ``special`` (mappings with transforms, ``select_condition`` or restricted
    modifiers) are handled by ``apply_detection_item``: their items are replaced by a
    detection with final values, which pySigma does not revisit.
    """

    prefix_rewrites: Tuple[Tuple[str, Tuple[str, ...]], ...] = ()
    special: Dict[str, FieldMapping] = field(default_factory=dict)
    profile_id: str = ""

    def apply_field_name(self, field):
        """Return the mapped name(s) of ``field``; several names are ORed by pySigma."""
        if field is None:
            return None
        if field in self.mapping:
            return self.mapping[field]
        for src, dsts in self.prefix_rewrites:
            if field.startswith(src) and len(field) > len(src):
                rest = field[len(src):]
                if len(dsts) == 1:
                    return dsts[0] + rest
                return [dst + rest for dst in dsts]
        return None

    def _transformed(self, field: Optional[str]) -> bool:
        mapping = self.special.get(field) if field is not None else None
        return mapping is not None and (bool(mapping.transforms) or mapping.select is not None)

    def apply_detection_item(self, detection_item):
        """Replace items of special fields; defer to the plain field mapping otherwise."""
        field = detection_item.field
        for value in detection_item.value:
            if isinstance(value, SigmaFieldReference) and self._transformed(value.field):
                self._fail(value.field, "field references are not supported for transformed fields")
        mapping = self.special.get(field) if field is not None else None
        if mapping is None:
            return super().apply_detection_item(detection_item)
        if mapping.modifiers is not None:
            names = [reverse_modifier_mapping.get(m.__name__, m.__name__) for m in detection_item.modifiers]
            for name in names or ["eq"]:
                if name not in mapping.modifiers:
                    self._fail(field, f"modifier {name} is not supported")
        if not self._transformed(field):
            return super().apply_detection_item(detection_item)
        if any(isinstance(v, SigmaFieldReference) for v in detection_item.value):
            self._fail(field, "field references are not supported for transformed fields")
        linking = ConditionAND if detection_item.value_linking is ConditionAND else ConditionOR
        if mapping.select is not None:
            nodes = self._select(field, mapping.select, detection_item.value)
        else:
            nodes = self._transform(field, mapping, detection_item.value, linking is ConditionAND)
        if len(nodes) == 1 and isinstance(nodes[0], SigmaDetection):
            return nodes[0]
        return SigmaDetection(detection_items=nodes, item_linking=linking)

    def _fail(self, field: str, reason: str) -> None:
        raise SigmaTransformationError(f"field {field}: {reason} (profile {self.profile_id})")

    def _select(self, field: str, select: Dict[str, Dict[str, Any]], values: List[SigmaType]) -> List[_Node]:
        nodes: List[_Node] = []
        for value in values:
            key: Optional[str] = None
            if isinstance(value, SigmaBool):
                key = "true" if value.boolean else "false"
            elif isinstance(value, SigmaNumber) or (
                isinstance(value, SigmaString) and not value.contains_special()
            ):
                key = str(value).lower()
            if key is None or key not in select:
                self._fail(field, f"value '{value}' is not one of {list(select)}")
            items: List[_Node] = [
                SigmaDetectionItem.from_mapping(name, cond) for name, cond in select[str(key)].items()
            ]
            nodes.append(_join(items, ConditionAND))
        return nodes

    def _transform(self, field: str, mapping: FieldMapping, values: List[SigmaType], all_values: bool) -> List[_Node]:
        nodes: List[_Node] = []
        kind = mapping.transforms[-1].kind
        for value in values:
            alternatives: List[Alternative] = [(mapping.targets, value)]
            for transform in mapping.transforms:
                try:
                    alternatives = [
                        out
                        for targets, v in alternatives
                        for out in apply_chain([transform], v, targets, field=field, all_values=all_values)
                    ]
                except TransformFailure as e:
                    raise SigmaTransformationError(
                        f"field {field}: transform {transform.kind}: {e} (profile {self.profile_id})"
                    ) from None
                if not alternatives:
                    kind = transform.kind
                    break
            items: List[_Node] = [
                SigmaDetectionItem(target, [], [v]) for targets, v in alternatives for target in targets
            ]
            if items:
                nodes.append(_join(items, ConditionOR))
        if not nodes:
            raise SigmaTransformationError(
                f"field {field}: no value left after transform {kind} (profile {self.profile_id})"
            )
        return nodes


def build_profile_pipeline(
    profile: Profile, block: LogsourceBlock, logsource: Optional[SigmaLogSource] = None
) -> ProcessingPipeline:
    """Build the pipeline for one profile block: strict fields, mapping, conditions, state.

    With ``logsource`` (the rule's), the conditions of its product in ``profile.products``
    are added as well as the block conditions.
    """
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

    # Mappings without targets (select_condition, or a transform that supplies them) are
    # handled only as special fields. Mapping them to [] would drop them from detections.
    exact_map: Dict[Optional[str], Union[str, List[str]]] = {
        k: (v.targets[0] if len(v.targets) == 1 else list(v.targets)) for k, v in exact.items() if v.targets
    }
    special = {
        k: v for k, v in exact.items() if v.transforms or v.select is not None or v.modifiers is not None
    }
    # Every target of a prefix mapping is kept: several targets become an OR. An identity
    # rewrite (one target equal to the source prefix) is a no-op and is skipped.
    rewrites = tuple(
        (src, tuple(t[:-1] for t in v.targets))
        for src, v in prefix_maps.items()
        if tuple(t[:-1] for t in v.targets) != (src,)
    )
    items.append(
        ProcessingItem(
            transformation=ProfileFieldMapping(exact_map, prefix_rewrites=rewrites, special=special, profile_id=pid),
            identifier=f"lakewatch_{pid}_fields",
        )
    )

    conditions: Dict[str, Any] = dict(
        profile.conditions_for(block, logsource) if logsource is not None else block.conditions
    )
    if conditions:
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
