"""Centralized pluralization and count-formatting helpers (v1.2.3).

Narrative report text should read naturally for zero, one, and many, instead
of mechanical "1 flow(s)" / "1 dependenc(ies)" / "was/were" constructions.
These helpers are the single place that logic lives; report writers call them
rather than hand-rolling singular/plural conditionals.
"""

from __future__ import annotations

from typing import Dict

#: Irregular plurals used in the reports. Anything not listed falls back to
#: the regular rules in ``plural`` below.
_IRREGULAR: Dict[str, str] = {
    "dependency": "dependencies",
    "discrepancy": "discrepancies",
    "anomaly": "anomalies",
}


def plural(noun: str, count: int) -> str:
    """Return the correctly pluralized noun for ``count`` (1 -> singular)."""
    if count == 1:
        return noun
    if noun in _IRREGULAR:
        return _IRREGULAR[noun]
    if noun.endswith("y") and noun[:-1] and noun[-2] not in "aeiou":
        return noun[:-1] + "ies"
    if noun.endswith(("s", "x", "z", "ch", "sh")):
        return noun + "es"
    return noun + "s"


def count_noun(count: int, noun: str) -> str:
    """Format ``count`` with its correctly pluralized noun, e.g. '1 flow'."""
    return f"{count} {plural(noun, count)}"


def were(count: int) -> str:
    """'was' for exactly one, 'were' otherwise."""
    return "was" if count == 1 else "were"


def has(count: int) -> str:
    """'has' for exactly one, 'have' otherwise."""
    return "has" if count == 1 else "have"


def verb(count: int, singular: str, plural_form: str) -> str:
    """Agree an arbitrary verb with ``count`` (e.g. verb(n, 'is', 'are'))."""
    return singular if count == 1 else plural_form
