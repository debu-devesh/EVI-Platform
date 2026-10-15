#!/usr/bin/env python3
"""
Convert chat answer HTML (same fragment as the UI) into ReportLab flowables for PDF export.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List

from bs4 import BeautifulSoup, NavigableString
from reportlab.lib import colors
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle


def _escape_pdf_markup(text: str) -> str:
    return (
        (text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _fa_icon_only(tag) -> bool:
    if not getattr(tag, "name", None) or tag.name.lower() != "i":
        return False
    classes = tag.get("class") or []
    cl = " ".join(classes)
    return "fa-" in cl or "fas" in cl or "far" in cl


def reportlab_xml_from_element(node) -> str:
    """Build ReportLab Paragraph markup (<b>, <i>, <br/>) from a BeautifulSoup subtree."""
    parts: list[str] = []
    for child in node.children:
        if isinstance(child, NavigableString):
            parts.append(_escape_pdf_markup(str(child)))
        elif getattr(child, "name", None):
            nm = child.name.lower()
            if nm == "br":
                parts.append("<br/>")
            elif nm in ("strong", "b"):
                inner = reportlab_xml_from_element(child)
                if inner:
                    parts.append(f"<b>{inner}</b>")
            elif nm in ("em", "i"):
                if _fa_icon_only(child):
                    continue
                inner = reportlab_xml_from_element(child)
                if inner:
                    parts.append(f"<i>{inner}</i>")
            elif nm == "span":
                parts.append(reportlab_xml_from_element(child))
            elif nm in ("code",):
                inner = reportlab_xml_from_element(child)
                if inner:
                    parts.append(f"<font name='Courier'>{inner}</font>")
            else:
                parts.append(reportlab_xml_from_element(child))
    return "".join(parts)


@dataclass
class ChatPdfStyles:
    body: ParagraphStyle
    md_heading: ParagraphStyle
    md_subheading: ParagraphStyle
    section_header: ParagraphStyle
    bullet: ParagraphStyle
    table_cell: ParagraphStyle
    table_header_cell: ParagraphStyle
    content_width: float


def _table_to_flowable(table, ctx: ChatPdfStyles) -> Table:
    rows_out: list[list[Any]] = []
    ncols = 0
    for tr in table.find_all("tr", recursive=True):
        cells = []
        for cell in tr.find_all(["th", "td"], recursive=False):
            xml = reportlab_xml_from_element(cell).strip() or " "
            is_th = cell.name.lower() == "th"
            st = ctx.table_header_cell if is_th else ctx.table_cell
            cells.append(Paragraph(xml, st))
        if cells:
            ncols = max(ncols, len(cells))
            rows_out.append(cells)

    if not rows_out or ncols == 0:
        return Table([[Paragraph(" ", ctx.table_cell)]], colWidths=[ctx.content_width])

    for row in rows_out:
        while len(row) < ncols:
            row.append(Paragraph(" ", ctx.table_cell))

    col_w = ctx.content_width / ncols
    col_widths = [col_w] * ncols

    repeat = 1 if len(rows_out) > 1 else 0
    tbl = Table(rows_out, colWidths=col_widths, repeatRows=repeat)
    tbl.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9ecef")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return tbl


_SKIP_DIV_CLASSES = frozenset(
    {
        "message-meta-chips",
        "confidence-indicator",
        "response-time-indicator",
        "image-citations-section",
        "image-gallery",
        "image-citations-header",
        "streaming-pipeline-status",
    }
)


def _emit_from_container(container, ctx: ChatPdfStyles, out: list) -> None:
    for child in getattr(container, "children", []):
        if isinstance(child, NavigableString):
            t = str(child).replace("\xa0", " ").strip()
            if t:
                out.append(Paragraph(_escape_pdf_markup(t), ctx.body))
            continue
        if not getattr(child, "name", None):
            continue
        nm = child.name.lower()
        classes = set(child.get("class") or [])

        if nm == "br":
            if out and isinstance(out[-1], Spacer):
                continue
            out.append(Spacer(1, 4))
            continue

        if classes & _SKIP_DIV_CLASSES:
            continue

        if nm in ("h4", "h5"):
            cls = child.get("class") or []
            if "section-header" in cls:
                style = ctx.section_header
            elif "llm-md-heading" in cls:
                style = ctx.md_heading
            elif "llm-md-subheading" in cls:
                style = ctx.md_subheading
            else:
                style = ctx.md_heading if nm == "h4" else ctx.md_subheading
            xml = reportlab_xml_from_element(child).strip()
            if xml:
                out.append(Paragraph(xml, style))
            continue

        if nm == "div":
            if "llm-md-table-wrap" in classes:
                tbl = child.find("table")
                if tbl is not None:
                    out.append(_table_to_flowable(tbl, ctx))
                    out.append(Spacer(1, 8))
                continue
            if "analysis-section" in classes:
                _emit_from_container(child, ctx, out)
                continue
            if "section-content" in classes:
                _emit_from_container(child, ctx, out)
                continue
            if "llm-md-li" in classes or "bullet-point" in classes:
                xml = reportlab_xml_from_element(child).strip()
                if xml:
                    prefix = "• " if "bullet-point" in classes or "llm-md-li" in classes else ""
                    out.append(Paragraph(f"{prefix}{xml}", ctx.bullet))
                continue
            if "followup-prefix" in classes:
                xml = reportlab_xml_from_element(child).strip()
                if xml:
                    out.append(Paragraph(f"<b>{xml}</b>", ctx.body))
                continue
            _emit_from_container(child, ctx, out)
            continue

        if nm == "table":
            out.append(_table_to_flowable(child, ctx))
            out.append(Spacer(1, 8))
            continue

        if nm == "p":
            xml = reportlab_xml_from_element(child).strip()
            if xml:
                out.append(Paragraph(xml, ctx.body))
            continue

        if nm in ("strong", "b", "span", "em", "i"):
            xml = reportlab_xml_from_element(child).strip()
            if xml:
                out.append(Paragraph(xml, ctx.body))
            continue

        _emit_from_container(child, ctx, out)


def chat_html_fragment_to_flowables(html_fragment: str, ctx: ChatPdfStyles) -> list:
    if not html_fragment or not str(html_fragment).strip():
        return []
    wrapped = f'<div class="pdf-chat-root">{html_fragment}</div>'
    soup = BeautifulSoup(wrapped, "html.parser")
    for bad in soup.find_all(["script", "style"]):
        bad.decompose()
    root = soup.select_one(".pdf-chat-root")
    if root is None:
        return []
    out: list = []
    _emit_from_container(root, ctx, out)
    return out
