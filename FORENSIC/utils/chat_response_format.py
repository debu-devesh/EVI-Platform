#!/usr/bin/env python3
"""
Mirror of templates/enhanced_index.html formatStructuredResponse() for server-side use.

Produces the same HTML fragment the chat bubble uses so PDF export matches on-screen answers.
"""

from __future__ import annotations

import html
import re
from typing import Optional

from utils.llm_text_repair import repair_llm_mojibake

_FORENSIC_SECTION_RE = re.compile(
    r"\*\*(SECURITY CONCERNS|EVIDENCE PATTERNS|INVESTIGATION FINDINGS|RECOMMENDATIONS|"
    r"ANALYSIS SUMMARY|KEY FINDINGS|SUSPICIOUS INDICATORS|PATTERNS DETECTED):\*\*",
    re.I,
)

_EMOJI_SECTION_PATTERNS = [
    r"🔍\s*EXECUTIVE\s+SUMMARY:",
    r"📋\s*EVIDENCE\s+DISCOVERED:",
    r"⏱️\s*TIMELINE\s+ANALYSIS:",
    r"🔗\s*RELATIONSHIP\s+MAPPING:",
    r"⚠️\s*SECURITY\s+CONCERNS\b",
    r"📊\s*PATTERN\s+ANALYSIS:",
    r"💡\s*INVESTIGATIVE\s+RECOMMENDATIONS:",
    r"🔬\s*EVIDENCE\s+INTEGRITY:",
    r"🔍\s*ANALYSIS\s+SUMMARY:",
    r"📊\s*KEY\s+FINDINGS:",
    r"⚠️\s*SUSPICIOUS\s+INDICATORS:",
    r"📈\s*PATTERNS\s+DETECTED:",
    r"💡\s*RECOMMENDATIONS:",
    r"🔍\s*EVIDENCE\s+ANALYSIS:",
    r"📋\s*KEY\s+DETAILS:",
    r"⚠️\s*NOTABLE\s+FINDINGS:",
]


def message_uses_forensic_card_layout(raw: str) -> bool:
    s = str(raw or "")
    if _FORENSIC_SECTION_RE.search(s):
        return True
    return any(re.search(p, s, re.I) for p in _EMOJI_SECTION_PATTERNS)


def split_gfm_table_row(line: str) -> Optional[list[str]]:
    s = str(line or "").strip()
    if not s.startswith("|"):
        return None
    if not s.endswith("|"):
        s = f"{s}|"
    inner = s[1:-1].split("|")
    return [c.strip() for c in inner]


def is_gfm_table_separator_line(line: str) -> bool:
    cells = split_gfm_table_row(line)
    if not cells or len(cells) < 2:
        return False
    return all(re.match(r"^:?-{3,}:?$", p.strip()) for p in cells)


def is_gfm_table_data_row(line: str) -> bool:
    cells = split_gfm_table_row(line)
    return bool(cells and len(cells) >= 2)


def gfm_table_block_to_html(block: list[str]) -> str:
    header_cells = split_gfm_table_row(block[0]) or []
    body_rows = block[2:]

    def esc_cell(c: str) -> str:
        return "&nbsp;" if c == "" else c

    thead = "<thead><tr>" + "".join(f"<th>{esc_cell(h)}</th>" for h in header_cells) + "</tr></thead>"
    tbody_parts = ["<tbody>"]
    for row_line in body_rows:
        cells = split_gfm_table_row(row_line) or []
        tbody_parts.append("<tr>")
        for c in range(len(header_cells)):
            val = cells[c] if c < len(cells) else ""
            tbody_parts.append(f"<td>{esc_cell(val)}</td>")
        tbody_parts.append("</tr>")
    tbody_parts.append("</tbody>")
    tbody = "".join(tbody_parts)
    return f'<div class="llm-md-table-wrap"><table class="llm-md-table">{thead}{tbody}</table></div>'


def convert_gfm_tables_to_html(escaped_text: str) -> str:
    if not escaped_text:
        return ""
    lines = escaped_text.split("\n")
    out: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        if (
            is_gfm_table_data_row(lines[i])
            and not is_gfm_table_separator_line(lines[i])
            and i + 1 < n
            and is_gfm_table_separator_line(lines[i + 1])
        ):
            block = [lines[i], lines[i + 1]]
            j = i + 2
            while j < n:
                line_j = lines[j]
                if not is_gfm_table_data_row(line_j):
                    break
                if is_gfm_table_separator_line(line_j):
                    break
                if j + 1 < n and is_gfm_table_separator_line(lines[j + 1]):
                    break
                block.append(line_j)
                j += 1
            if len(block) >= 2:
                out.append(gfm_table_block_to_html(block))
                i = j
                continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


_LEGACY_LINE_RE = re.compile(
    r"^\s*(?:-\s+)?\[([^\]]+)\]\s+(.+?)\s+->\s+(.+?):\s*(.*)$"
)


def convert_legacy_forensic_chat_lines_to_table(escaped_text: str) -> str:
    if not escaped_text:
        return ""
    lines = escaped_text.split("\n")
    out: list[str] = []
    i = 0

    def esc_cell(c: str) -> str:
        return "&nbsp;" if c in ("", None) else str(c)

    while i < len(lines):
        ln = lines[i]
        if _LEGACY_LINE_RE.match(ln):
            rows: list[list[str]] = []
            while i < len(lines):
                m = _LEGACY_LINE_RE.match(lines[i])
                if not m:
                    break
                rows.append([m.group(1), m.group(2), m.group(3), m.group(4)])
                i += 1
            thead = "<thead><tr>"
            for h in ("Timestamp (UTC)", "Sender", "Receiver", "Message"):
                thead += f"<th>{esc_cell(h)}</th>"
            thead += "</tr></thead>"
            tbody = "<tbody>"
            for r in rows:
                tbody += (
                    f"<tr><td>{esc_cell(r[0])}</td><td>{esc_cell(r[1])}</td>"
                    f"<td>{esc_cell(r[2])}</td><td>{esc_cell(r[3])}</td></tr>"
                )
            tbody += "</tbody>"
            out.append(
                f'<div class="llm-md-table-wrap"><table class="llm-md-table">{thead}{tbody}</table></div>'
            )
            continue
        out.append(ln)
        i += 1
    return "\n".join(out)


def format_structured_response_html(message: Optional[str]) -> str:
    """Same output shape as JS formatStructuredResponse (HTML fragment)."""
    raw = repair_llm_mojibake(message)
    safe_message = html.escape(str(raw), quote=True)
    use_forensic_cards = message_uses_forensic_card_layout(raw)
    formatted = convert_legacy_forensic_chat_lines_to_table(
        convert_gfm_tables_to_html(safe_message)
    )
    has_sections = False
    is_first_section = True

    if use_forensic_cards:

        def _sec_repl(match: re.Match) -> str:
            nonlocal has_sections, is_first_section
            section_name = match.group(1)
            has_sections = True
            if is_first_section:
                is_first_section = False
                return (
                    f'<div class="analysis-section"><h4 class="section-header">'
                    f"<strong>{html.escape(section_name.upper(), quote=True)}</strong></h4>"
                    f'<div class="section-content">'
                )
            is_first_section = False
            return (
                '</div></div><div class="analysis-section"><h4 class="section-header">'
                f"<strong>{html.escape(section_name.upper(), quote=True)}</strong></h4>"
                f'<div class="section-content">'
            )

        formatted = _FORENSIC_SECTION_RE.sub(_sec_repl, formatted)
        has_sections = True

        replacements = [
            (
                re.compile(r"🔍 EXECUTIVE SUMMARY:", re.I),
                '<div class="analysis-section"><h4 class="section-header executive-summary-header">'
                '<i class="fas fa-file-alt"></i> EXECUTIVE SUMMARY</h4><div class="section-content">',
            ),
            (
                re.compile(r"📋 EVIDENCE DISCOVERED:", re.I),
                '</div></div><div class="analysis-section"><h4 class="section-header evidence-header">'
                '<i class="fas fa-fingerprint"></i> EVIDENCE DISCOVERED</h4><div class="section-content">',
            ),
            (
                re.compile(r"⏱️ TIMELINE ANALYSIS:", re.I),
                '</div></div><div class="analysis-section"><h4 class="section-header timeline-header">'
                '<i class="fas fa-clock"></i> TIMELINE ANALYSIS</h4><div class="section-content">',
            ),
            (
                re.compile(r"🔗 RELATIONSHIP MAPPING:", re.I),
                '</div></div><div class="analysis-section"><h4 class="section-header relationship-header">'
                '<i class="fas fa-project-diagram"></i> RELATIONSHIP MAPPING</h4><div class="section-content">',
            ),
            (
                re.compile(r"⚠️ SECURITY CONCERNS & ANOMALIES:", re.I),
                '</div></div><div class="analysis-section"><h4 class="section-header security-header">'
                '<i class="fas fa-shield-alt"></i> SECURITY CONCERNS & ANOMALIES</h4><div class="section-content">',
            ),
            (
                re.compile(r"📊 PATTERN ANALYSIS:", re.I),
                '</div></div><div class="analysis-section"><h4 class="section-header pattern-header">'
                '<i class="fas fa-chart-line"></i> PATTERN ANALYSIS</h4><div class="section-content">',
            ),
            (
                re.compile(r"💡 INVESTIGATIVE RECOMMENDATIONS:", re.I),
                '</div></div><div class="analysis-section"><h4 class="section-header recommendation-header">'
                '<i class="fas fa-lightbulb"></i> INVESTIGATIVE RECOMMENDATIONS</h4><div class="section-content">',
            ),
            (
                re.compile(r"🔬 EVIDENCE INTEGRITY:", re.I),
                '</div></div><div class="analysis-section"><h4 class="section-header integrity-header">'
                '<i class="fas fa-certificate"></i> EVIDENCE INTEGRITY</h4><div class="section-content">',
            ),
            (
                re.compile(r"🔍 ANALYSIS SUMMARY:"),
                '<div class="analysis-section"><h4 class="section-header analysis-header">'
                '<i class="fas fa-search"></i> ANALYSIS SUMMARY</h4><div class="section-content">',
            ),
            (
                re.compile(r"📊 KEY FINDINGS:"),
                '</div></div><div class="analysis-section"><h4 class="section-header findings-header">'
                '<i class="fas fa-chart-bar"></i> KEY FINDINGS</h4><div class="section-content">',
            ),
            (
                re.compile(r"⚠️ SUSPICIOUS INDICATORS:"),
                '</div></div><div class="analysis-section"><h4 class="section-header warning-header">'
                '<i class="fas fa-exclamation-triangle"></i> SUSPICIOUS INDICATORS</h4><div class="section-content">',
            ),
            (
                re.compile(r"📈 PATTERNS DETECTED:"),
                '</div></div><div class="analysis-section"><h4 class="section-header pattern-header">'
                '<i class="fas fa-chart-line"></i> PATTERNS DETECTED</h4><div class="section-content">',
            ),
            (
                re.compile(r"💡 RECOMMENDATIONS:"),
                '</div></div><div class="analysis-section"><h4 class="section-header recommendation-header">'
                '<i class="fas fa-lightbulb"></i> RECOMMENDATIONS</h4><div class="section-content">',
            ),
            (
                re.compile(r"🔍 EVIDENCE ANALYSIS:"),
                '<div class="analysis-section"><h4 class="section-header analysis-header">'
                '<i class="fas fa-search"></i> EVIDENCE ANALYSIS</h4><div class="section-content">',
            ),
            (
                re.compile(r"📋 KEY DETAILS:"),
                '</div></div><div class="analysis-section"><h4 class="section-header details-header">'
                '<i class="fas fa-clipboard-list"></i> KEY DETAILS</h4><div class="section-content">',
            ),
            (
                re.compile(r"⚠️ NOTABLE FINDINGS:"),
                '</div></div><div class="analysis-section"><h4 class="section-header findings-header">'
                '<i class="fas fa-exclamation-circle"></i> NOTABLE FINDINGS</h4><div class="section-content">',
            ),
        ]
        for rx, repl in replacements:
            formatted = rx.sub(repl, formatted)
    else:
        formatted = re.sub(
            r"^###\s+(.+)$",
            r'<h5 class="llm-md-subheading">\1</h5>',
            formatted,
            flags=re.MULTILINE,
        )
        formatted = re.sub(
            r"^##\s+(.+)$",
            r'<h4 class="llm-md-heading">\1</h4>',
            formatted,
            flags=re.MULTILINE,
        )
        formatted = re.sub(
            r"^-\s+(.+)$",
            r'<div class="llm-md-li">\1</div>',
            formatted,
            flags=re.MULTILINE,
        )

    formatted = re.sub(
        r"• ([^\n]+)",
        r'<div class="bullet-point"><i class="fas fa-chevron-right"></i> \1</div>',
        formatted,
    )

    if use_forensic_cards:

        def _bold_colon_repl(match: re.Match) -> str:
            text = match.group(1)
            upper_text = text.upper()
            if any(
                k in upper_text
                for k in (
                    "SECURITY",
                    "EVIDENCE",
                    "INVESTIGATION",
                    "RECOMMENDATION",
                    "FINDING",
                    "PATTERN",
                )
            ):
                return f"<strong>{html.escape(text.upper(), quote=True)}</strong>"
            return f"<strong>{html.escape(text, quote=True)}</strong>"

        formatted = re.sub(r"\*\*([^*]+):\*\*", _bold_colon_repl, formatted)
    else:
        formatted = re.sub(
            r"\*\*([^*]+):\*\*",
            lambda m: f"<strong>{html.escape(m.group(1), quote=True)}</strong>",
            formatted,
        )

    formatted = re.sub(
        r"\*\*([^*]+)\*\*",
        lambda m: f"<strong>{html.escape(m.group(1), quote=True)}</strong>",
        formatted,
    )

    if use_forensic_cards and has_sections and "analysis-section" in formatted:
        formatted += "</div></div>"

    formatted = formatted.replace("\n", "<br>")
    return formatted
