"""Tests for pruning unsupported fields from condition trees."""

import pytest
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule

from sigma.backends.databricks.prune import (
    PruneFailure,
    mark,
    prune_condition,
    unmarked,
)


def tree(detection_yaml: str):
    rule = SigmaRule.from_yaml(
        "title: t\nlogsource:\n  category: x\ndetection:\n"
        + "".join(f"  {line}\n" for line in detection_yaml.strip().splitlines())
    )
    for det in rule.detection.detections.values():
        _rename(det)
    return rule.detection.parsed_condition[0].parsed


def _rename(det):
    for item in det.detection_items:
        if hasattr(item, "detection_items"):
            _rename(item)
        elif item.field and item.field.startswith("U_"):
            item.field = mark(item.field)


def render(node) -> str:
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return node.field
    if isinstance(node, ConditionValueExpression):
        return "kw"
    name = type(node).__name__.replace("Condition", "")
    return f"{name}({','.join(render(a) for a in node.args)})"


def test_mark_roundtrip():
    assert unmarked(mark("A.b")) == "A.b"
    assert unmarked("A.b") is None
    assert unmarked(None) is None


def test_or_drops_marked_alternative():
    node, names = prune_condition(tree("sel:\n  - Image: x\n  - U_Orig: y\ncondition: sel"))
    assert render(node) == "Image"
    assert names == ["U_Orig"]


def test_and_inside_or_drops_branch():
    node, names = prune_condition(
        tree("a:\n  Image: x\n  U_Orig: y\nb:\n  C: z\ncondition: a or b")
    )
    assert render(node) == "C"
    assert names == ["U_Orig"]


def test_one_of_drops_whole_selection():
    node, names = prune_condition(
        tree(
            "selection_1:\n  C: x\nselection_2:\n  U_O: y\nfilter:\n  Image: z\n"
            "condition: 1 of selection* and not filter"
        )
    )
    assert render(node) == "AND(C,NOT(Image))"
    assert names == ["U_O"]


def test_all_of_with_marked_selection_is_empty():
    t = tree("selection_1:\n  C: x\nselection_2:\n  U_O: y\ncondition: all of selection*")
    with pytest.raises(PruneFailure) as e:
        prune_condition(t)
    assert e.value.reason == "empty"
    assert e.value.field == "U_O"


def test_marked_under_not_fails():
    t = tree("selection:\n  Image: x\nfilter:\n  U_O: y\ncondition: selection and not filter")
    with pytest.raises(PruneFailure) as e:
        prune_condition(t)
    assert e.value.reason == "negation"
    assert e.value.field == "U_O"


def test_marked_under_double_not_fails():
    t = tree("sel:\n  U_O: y\ncondition: not (not sel)")
    with pytest.raises(PruneFailure) as e:
        prune_condition(t)
    assert e.value.reason == "negation"


def test_only_marked_is_empty():
    with pytest.raises(PruneFailure) as e:
        prune_condition(tree("sel:\n  U_O: x\ncondition: sel"))
    assert e.value.reason == "empty"


@pytest.mark.parametrize(
    "item", ["U_O:\n    - a\n    - b", "U_O: null", "U_O|exists: true"]
)
def test_value_list_null_and_exists_marked(item):
    node, names = prune_condition(
        tree(f"a:\n  {item}\nb:\n  Image: x\ncondition: a or b")
    )
    assert render(node) == "Image"
    assert names == ["U_O"]


def test_names_deduplicated_in_order():
    node, names = prune_condition(
        tree("sel:\n  - U_B: 1\n  - U_A: 2\n  - U_A: 3\n  - Image: x\ncondition: sel")
    )
    assert render(node) == "Image"
    assert names == ["U_B", "U_A"]


def test_no_marker_unchanged():
    t = tree("a:\n  Image: x\nb:\n  C: y\ncondition: a or not b")
    before = render(t)
    node, names = prune_condition(t)
    assert node is t
    assert render(node) == before
    assert names == []


def test_collapse_sets_parent():
    node, names = prune_condition(
        tree("a:\n  - Image: x\n  - U_O: y\nb:\n  C: z\ncondition: a and b")
    )
    assert isinstance(node, ConditionAND)
    image = node.args[0]
    assert render(image) == "Image"
    # The OR's parent was a ConditionIdentifier (kept in the parent chain), so the
    # collapsed leaf inherits it; the chain must still reach the AND, not the dropped OR.
    chain = []
    p = image.parent
    while p is not None:
        chain.append(p)
        p = p.parent
    assert node in chain
    assert not any(isinstance(p, ConditionOR) for p in chain)
