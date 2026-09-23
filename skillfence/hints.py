"""Parses a lab's `hints.md` -- a numbered markdown list, one hint per
number, each revealing a little more than the last. Deliberately a plain
list format any lab author can write by hand, same as every other lab
document (SKILL.md, README.md) in this project -- no new schema.
"""

from __future__ import annotations

import re

_HINT_START = re.compile(r"^\d+\.\s+", re.MULTILINE)


def parse_hints(text: str) -> list[str]:
    """Splits on numbered list markers at the start of a line. A hint may
    wrap multiple lines; everything up to the next numbered marker (or end
    of file) belongs to it. Blank hints are dropped.
    """
    parts = _HINT_START.split(text)
    return [" ".join(p.split()) for p in parts[1:] if p.strip()]
