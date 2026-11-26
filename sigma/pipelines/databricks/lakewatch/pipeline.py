"""Compile one Lakewatch mapping profile logsource block into a pySigma pipeline."""
import warnings
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
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaFieldReference,
    SigmaNumber,
    SigmaString,
    SigmaType,
)

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

# Modifiers that replace the implied equality comparison.
COMPARISON_MODIFIERS = frozenset(
    {"contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte", "exists", "fieldref"}
)


@dataclass
class StrictFieldsTransformation(DetectionItemTransformation):
    """Fail closed on keywords, unsupported fields and fields the profile does not map."""

    profile_id: str
    allowed: FrozenSet[str]
    prefixes: Tuple[str, ...]
    unsupported: FrozenSet[str]
    keywords: bool = False
    any_column: Optional[str] = None
    hint: Optional[str] = None

    def _check(self, field: str) -> None:
        if field in self.unsupported or (
            self.any_column is not None and field.lower() in {u.lower() for u in self.unsupported}
        ):
            raise SigmaTransformationError(
                f"field {field} is not supported by profile {self.profile_id}"
            )
        if field in self.allowed or any(
            field.startswith(p) and len(field) > len(p) for p in self.prefixes
        ):
            return
        if self.any_column is not None and "[" not in field and "]" not in field:
            return
        message = f"field {field} is not mapped by profile {self.profile_id}"
        if self.hint:
            message += f"; {self.hint}"
        raise SigmaTransformationError(message)

    def apply_detection_item(self, detection_item):
        """Check the item's field and field-reference values; the item is left unchanged."""
        field = detection_item.field
        if field is None:
            if self.keywords:
                return None
            raise SigmaTransformationError(
                f"no raw event for keyword search in profile {self.profile_id}"
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
    any_column: Optional[str] = None
    prefixes: Tuple[str, ...] = ()

    def _canonical(self, field: Optional[str]) -> Optional[str]:
        """Return the explicit mapping key equal to ``field`` when case is ignored, else ``field``."""
        if field is None or self.any_column is None or field in self.mapping or field in self.special:
            return field
        for key in (*self.mapping, *self.special):
            if key is not None and key.lower() == field.lower():
                return key
        return field

    def _warn_any(self, field: str, target: str) -> None:
        """Warn once per field and rule about a field resolved through the ``any`` fallback."""
        pipeline = getattr(self, "_pipeline", None)
        state = pipeline.state if pipeline is not None else None
        if state is not None:
            seen = state.setdefault("lakewatch_any_warned", set())
            if (self.profile_id, field) in seen:
                return
            seen.add((self.profile_id, field))
        warnings.warn(
            f"field {field} is not in a field list of profile {self.profile_id}; mapped to {target}",
            UserWarning,
            stacklevel=2,
        )

    def apply_field_name(self, field):
        """Return the mapped name(s) of ``field``; several names are ORed by pySigma."""
        if field is None:
            return None
        field = self._canonical(field)
        if field in self.mapping:
            return self.mapping[field]
        for src, dsts in self.prefix_rewrites:
            if field.startswith(src) and len(field) > len(src):
                rest = field[len(src):]
                if len(dsts) == 1:
                    return dsts[0] + rest
                return [dst + rest for dst in dsts]
        if self.any_column is not None and field not in self.special and not any(
            field.startswith(p) and len(field) > len(p) for p in self.prefixes
        ):
            target = f"{self.any_column}[{field}]"
            self._warn_any(field, target)
            return target
        return None

    def _transformed(self, field: Optional[str]) -> bool:
        mapping = self.special.get(field) if field is not None else None
        return mapping is not None and (bool(mapping.transforms) or mapping.select is not None)

    def apply_detection_item(self, detection_item):
        """Replace items of special fields; defer to the plain field mapping otherwise."""
        field = self._canonical(detection_item.field)
        if field != detection_item.field:
            detection_item.field = field
        for value in detection_item.value:
            if isinstance(value, SigmaFieldReference) and self._transformed(self._canonical(value.field)):
                # Name the rule's field; the referenced one is the transformed field.
                self._fail(
                    str(field), f"field reference to transformed field {value.field} is not supported"
                )
        mapping = self.special.get(field) if field is not None else None
        if mapping is None:
            return super().apply_detection_item(detection_item)
        if mapping.modifiers is not None:
            names = [reverse_modifier_mapping.get(m.__name__, m.__name__) for m in detection_item.modifiers]
            if not COMPARISON_MODIFIERS.intersection(names):
                names.append("eq")
            for name in names:
                if name not in mapping.modifiers:
                    self._fail(field, f"modifier {name} is not supported")
        if not self._transformed(field):
            return super().apply_detection_item(detection_item)
        if any(isinstance(v, SigmaFieldReference) for v in detection_item.value):
            self._fail(field, "field references are not supported for transformed fields")
        if any(isinstance(v, SigmaCasedString) for v in detection_item.value):
            self._fail(field, "case-sensitive matching is not supported")
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
    profile: Profile,
    block: LogsourceBlock,
    logsource: Optional[SigmaLogSource] = None,
    keywords: Optional[bool] = None,
) -> ProcessingPipeline:
    """Build the pipeline for one profile block: strict fields, mapping, conditions, state.

    With ``logsource`` (the rule's), the conditions of its product in ``profile.products``
    are added as well as the block conditions. Keywords are allowed when ``keywords`` is True,
    or, if it is None, when the profile has a raw source.
    """
    pid = profile.profile
    any_column = profile.event_data_column if profile.event_data_any(block) else None
    if keywords is None:
        keywords = profile.raw is not None
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
                keywords=keywords,
                any_column=any_column,
                hint=profile.unmapped_hint,
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
            transformation=ProfileFieldMapping(
                exact_map,
                prefix_rewrites=rewrites,
                special=special,
                profile_id=pid,
                any_column=any_column,
                prefixes=tuple(prefix_maps),
            ),
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
