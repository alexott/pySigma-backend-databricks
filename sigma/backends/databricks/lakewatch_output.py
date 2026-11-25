"""Pure helpers for the output settings of Lakewatch rules (summary, context, select)."""

import re
from typing import List

# A placeholder in a summary or a context value must hold a bare column name.
PLACEHOLDER_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PLACEHOLDER = re.compile(r"\{([^{}]*)\}")


def escape_title(title: str) -> str:
    """Replace braces in a title: Lakewatch reads ``{...}`` in a summary as an SQL placeholder."""
    return title.replace("{", "(").replace("}", ")")


def placeholders(template: str) -> List[str]:
    """Return the stripped contents of each ``{...}`` in ``template``, in order."""
    return [m.group(1).strip() for m in _PLACEHOLDER.finditer(template)]


def unbalanced_braces(template: str) -> bool:
    """Return True when a ``{`` or ``}`` is left after removing the ``{...}`` placeholders."""
    rest = _PLACEHOLDER.sub("", template)
    return "{" in rest or "}" in rest
