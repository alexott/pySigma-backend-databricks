"""Pruning of unsupported fields in a Sigma condition tree.

A field that a Lakewatch profile lists as ``unsupported`` is renamed with
:func:`mark`. :func:`prune_condition` then treats every leaf on a marked field
as FALSE and simplifies the tree:

* OR drops FALSE alternatives (all FALSE -> FALSE; one left collapses to it).
* AND with any FALSE argument is FALSE.
* A marked field below a NOT cannot be dropped soundly (dropping it would widen
  the rule), so it raises ``PruneFailure("negation")``.
* A FALSE root raises ``PruneFailure("empty")``.

Dropping only ever narrows the rule: the result matches a subset of what the
original would have matched had the field been available.

:func:`prune_condition` works in place: it mutates the tree it is given.
"""

from typing import Any, Iterator, List, Literal, Optional, Tuple

from sigma.conditions import (
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)

UNSUPPORTED_MARKER = "\x00lakewatch_unsupported\x00"


def mark(field: str) -> str:
    return UNSUPPORTED_MARKER + field


def unmarked(field: Optional[str]) -> Optional[str]:
    """Original field name for a marked field, else None."""
    if field is not None and field.startswith(UNSUPPORTED_MARKER):
        return field[len(UNSUPPORTED_MARKER) :]
    return None


class PruneFailure(Exception):  # noqa: N818
    """A marked field cannot be pruned soundly (negation) or nothing is left (empty)."""

    def __init__(self, field: str, reason: Literal["negation", "empty"]):  # noqa: D107
        super().__init__(f"unsupported field {field!r}: {reason}")
        self.field = field
        self.reason = reason


def _leaves(node: Any) -> Iterator[Any]:
    if isinstance(node, ConditionItem):
        for arg in node.args:
            yield from _leaves(arg)
    elif node is not None:
        yield node


def _prune(node: Any, dropped: List[str]) -> Any:
    """Return the simplified node, or None for FALSE."""
    if isinstance(node, (ConditionFieldEqualsValueExpression, ConditionValueExpression)):
        name = unmarked(getattr(node, "field", None))
        if name is None:
            return node
        if name not in dropped:
            dropped.append(name)
        return None
    if isinstance(node, ConditionNOT):
        for leaf in _leaves(node):
            name = unmarked(getattr(leaf, "field", None))
            if name is not None:
                raise PruneFailure(name, "negation")
        return node
    if isinstance(node, ConditionOR):
        kept = [k for k in (_prune(a, dropped) for a in node.args) if k is not None]
        if not kept:
            return None
        node.args = kept
        if len(kept) == 1:
            kept[0].parent = node.parent
            return kept[0]
        return node
    if isinstance(node, ConditionItem):  # AND and any other n-ary item
        pruned = [_prune(a, dropped) for a in node.args]
        if any(p is None for p in pruned):
            return None
        node.args = pruned
        return node
    return node


def prune_condition(node: Any) -> Tuple[Any, List[str]]:
    """Prune marked fields; return (tree, dropped original field names in tree order).

    The input tree is modified in place (``args`` and ``parent``); use the returned tree.
    """
    dropped: List[str] = []
    result = _prune(node, dropped)
    if result is None:
        raise PruneFailure(dropped[0], "empty")
    return result, dropped
