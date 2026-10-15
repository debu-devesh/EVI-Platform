#!/usr/bin/env python3
"""
Repair common UTF-8 / Windows-1252 mojibake in LLM output (OpenRouter, local, etc.).

Single source of truth for text cleanup — also mirrored in templates/enhanced_index.html
repairLlmMojibake() for live token display until stream completes.
"""

from __future__ import annotations

import re
from typing import Optional

_SP_AFTER_E2 = frozenset(
    {
        "well",
        "than",
        "else",
        "therefore",
        "though",
        "although",
        "and",
        "or",
        "but",
        "the",
        "for",
        "with",
        "from",
    }
)


def _compound_a_b(a: str, b: str) -> str:
    bl = b.lower()
    if bl in _SP_AFTER_E2:
        return f"{a} {b}"
    if bl == "to" and (a == "end" or a.endswith("end")):
        return f"{a}-to"
    if len(b) < 3 or len(a) < 3:
        return f"{a} {b}"
    return f"{a}-{b}"


def _lower_hyphen_compound(m: re.Match) -> str:
    return _compound_a_b(m.group(1), m.group(2))


def _spaced_lower_hyphen_compound(m: re.Match) -> str:
    return _compound_a_b(m.group(1), m.group(2))


def repair_llm_mojibake(text: Optional[str]) -> str:
    if text is None:
        return ""
    s = str(text)
    if not s:
        return s

    s = (
        s.replace("â€™", "'")
        .replace("â€œ", '"')
        .replace("â€", '"')
        .replace("\u00e2\u20ac\u201c", "\u2013")
        .replace("\u00e2\u20ac\u201d", "\u2014")
        .replace("â€¦", "\u2026")
        .replace("\u00e2\u20ac\u00af", " ")
        .replace("\u00e2\u20ac\u2018", "-")
        .replace("â‰ˆ", "~")
        .replace("Â°", "\u00b0")
        .replace("â°", "\u00b0")
        .replace("âˆ’", "-")
        .replace("\u2212", "-")
    )

    s = re.sub(r"(\d{4})\u00e2(\d{2})\u00e2(\d{2})", r"\1-\2-\3", s)
    # ISO dates with spaces: 2020â 09â 23
    s = re.sub(r"(\d{4})\u00e2\s*(\d{2})\u00e2\s*(\d{2})", r"\1-\2-\3", s)
    for _ in range(8):
        ns = re.sub(r"(\d)\s*\u00e2\s*(\d)", r"\1-\2", s)
        if ns == s:
            break
        s = ns

    # Integer ranges: "Messages 9â12" or "9â 12" (truncated en dash mojibake)
    s = re.sub(r"(?<![.\d])(\d{1,4})\s*\u00e2\s*(\d{1,4})(?!\d)", r"\1-\2", s)

    s = s.replace("(â", '("')
    # Line-start â + letter: truncated opening smart quote (UTF-8 read as Latin-1)
    s = re.sub(r"(?m)^(\s*)\u00e2([A-Za-z])", r'\1"\2', s)

    s = re.sub(r"\b(\w+)\u00e2s\b", r"\1's", s)
    s = re.sub(r"\b(\w+)\u00e2re\b", r"\1're", s)
    s = re.sub(r"\b(\w+)\u00e2ve\b", r"\1've", s)
    s = re.sub(r"\b(\w+)\u00e2ll\b", r"\1'll", s)
    s = re.sub(r"\b(\w+)\u00e2m\b", r"\1'm", s)
    s = re.sub(r"\b(\w+)\u00e2d\b", r"\1'd", s)
    s = re.sub(r"\b(\w+)\u00e2t\b", r"\1't", s)

    s = re.sub(
        r"([*A-Za-z ]+?)\u00e2(\s+)\u00e2(\s+)([A-Z\"*])",
        r'\1" <-> "\4',
        s,
    )
    s = re.sub(r"\s+\u00e2\s+\u00e2\s+", " <-> ", s)

    s = re.sub(r"(\w+)\u00e2\)", r'\1")', s)
    s = re.sub(r"(\w+)\u00e2([,;.])", r'\1"\2', s)
    # Word + â + space + digit (e.g. Messageâ 4)
    s = re.sub(r"(\w+)\u00e2\s+(\d)", r"\1 \2", s)
    s = re.sub(r"(\w+)\u00e2(\s+)(?=[A-Z\"*])", r'\1"\2', s)
    s = re.sub(r"(\s)â([A-Z\"*])", r'\1"\2', s)

    s = re.sub(r"([A-Z][a-z]{1,})\u00e2\s+([a-z]{2,})", r"\1-\2", s)
    s = re.sub(r"([A-Z][a-z]{1,})\u00e2([a-z]{2,})", r"\1-\2", s)
    s = re.sub(r"\b(\w+)\u00e2to\u00e2(\w+)\b", r"\1-to-\2", s)

    s = re.sub(r"([a-z]{2,})\u00e2\s+([a-z]{2,})", _spaced_lower_hyphen_compound, s)
    s = re.sub(r"([a-z]{2,})\u00e2([a-z]{2,})", _lower_hyphen_compound, s)

    s = re.sub(r"(\w+)\u00e2(\w+)", r"\1 \2", s)
    s = re.sub(r"(\w+)\u00e2\+", r"\1 +", s)

    s = re.sub(r"[\u2011\u2013\u2014]", "-", s)
    s = re.sub(r"[\u2018\u2019]", "'", s)
    s = re.sub(r"[\u201c\u201d]", '"', s)
    s = s.replace("\u202f", " ")
    s = s.replace("\u00a0", " ")
    s = re.sub(r"[\u2009\u2007\u2008]", " ", s)
    s = re.sub(
        r"\u00b0\s*([NSEW])",
        lambda m: "\u00b0 " + m.group(1),
        s,
        flags=re.I,
    )
    s = re.sub(r" {2,}", " ", s)

    return s
