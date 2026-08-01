"""Centralized output sanitization and escaping.

Nmap XML and YAML configuration are untrusted inputs.  Values derived from
them (hostnames, service banners, NSE output, owners, purposes, ...) may be
crafted to exploit the *consumers* of our reports:

- Spreadsheet applications interpret cells starting with ``=``, ``+``, ``-``
  or ``@`` (optionally after whitespace/control characters) as formulas
  ("CSV/Excel formula injection").
- Graphviz DOT and Mermaid have their own label syntax.
- HTML and Markdown can carry markup or script.

Every writer sanitizes through this module.  Spreadsheet protection is ON by
default and should stay on; ``--no-spreadsheet-sanitization`` exists only for
pipelines that post-process the raw values and understand the risk.
"""

from __future__ import annotations

import html as _html
from typing import Any

#: Characters that can begin a spreadsheet formula.
_FORMULA_TRIGGERS = ("=", "+", "-", "@")
#: Control characters that some spreadsheet apps also treat as triggers.
_CONTROL_TRIGGERS = ("\t", "\r", "\n")


def sanitize_spreadsheet_value(value: Any) -> Any:
    """Neutralize spreadsheet formula injection for one cell value.

    Non-string values (ints, floats, None, dates) pass through unchanged, so
    genuinely numeric negatives stay numeric.  A string is prefixed with a
    single quote when, ignoring leading whitespace, it begins with a formula
    trigger character, or when it begins with a control character.  The
    original content is preserved verbatim after the quote.
    """
    if not isinstance(value, str):
        return value
    if not value:
        return value
    if value.startswith(_CONTROL_TRIGGERS):
        return "'" + value
    stripped = value.lstrip(" \t\r\n")
    if stripped.startswith(_FORMULA_TRIGGERS):
        return "'" + value
    return value


def sanitize_row(row: dict, enabled: bool = True) -> dict:
    """Sanitize every string value of a flat row dict for CSV/Excel."""
    if not enabled:
        return row
    return {key: sanitize_spreadsheet_value(value) for key, value in row.items()}


# ---------------------------------------------------------------------------
# HTML / Markdown
# ---------------------------------------------------------------------------

def escape_html(value: Any) -> str:
    """Escape untrusted text for HTML element content and attributes."""
    return _html.escape(str(value), quote=True)


def escape_markdown_inline(value: Any) -> str:
    """Make untrusted text safe inside Markdown prose and table cells.

    Pipes would break tables, raw HTML could execute in permissive renderers,
    backticks/asterisks/underscores would re-style surrounding text, and
    newlines would break list items.  Content is encoded, never removed.
    """
    text = str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace("|", "\\|")
    text = text.replace("`", "\\`")
    text = text.replace("*", "\\*").replace("_", "\\_")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return text


# ---------------------------------------------------------------------------
# Graphviz DOT
# ---------------------------------------------------------------------------

def escape_dot_label(value: Any) -> str:
    """Escape untrusted text for use inside a double-quoted DOT label.

    Handles backslashes, quotes, braces, pipes, angle brackets (dangerous in
    record shapes and HTML-like labels), and converts real line breaks to the
    DOT ``\\n`` escape so a value can never terminate the quoted string or
    inject additional statements.
    """
    text = str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace('"', '\\"')
    for ch in "{}|<>":
        text = text.replace(ch, "\\" + ch)
    text = text.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")
    return text


# ---------------------------------------------------------------------------
# Mermaid
# ---------------------------------------------------------------------------

_MERMAID_ENTITIES = {
    '"': "#quot;",
    "'": "#39;",
    "<": "#lt;",
    ">": "#gt;",
    "[": "#91;",
    "]": "#93;",
    "{": "#123;",
    "}": "#125;",
    "(": "#40;",
    ")": "#41;",
    "|": "#124;",
    "`": "#96;",
    ";": "#59;",
    "&": "#38;",
    "\\": "#92;",
}


def escape_mermaid_label(value: Any) -> str:
    """Escape untrusted text for a quoted Mermaid node or edge label.

    Mermaid supports ``#<code>;`` entity escapes inside labels; every
    character that could close the label or introduce new diagram syntax is
    entity-encoded, and line breaks become ``<br/>`` (which Mermaid renders).
    """
    text = str(value)
    # Escape ';' and '&' first: every entity we emit ends in ';' (and none
    # contains any other mapped character), so later replacements can never
    # corrupt an already-emitted entity.
    text = text.replace(";", "#59;").replace("&", "#38;")
    for ch, entity in _MERMAID_ENTITIES.items():
        if ch in ("&", ";"):
            continue
        text = text.replace(ch, entity)
    text = text.replace("\r\n", "<br/>").replace("\n", "<br/>").replace("\r", "<br/>")
    return text
