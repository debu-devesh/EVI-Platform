#!/usr/bin/env python3
"""
Investigator-facing layout for deterministic outputs.

Pattern: title → short summary → counts → records
(no long legal-style caveats; keep copy factual and compact).
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence


def escape_md_table_cell(val: Any, max_len: int = 320) -> str:
    """Escape a value for use inside a GFM markdown table cell."""
    if val is None:
        s = ""
    else:
        s = str(val)
    s = s.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    s = s.replace("|", "\\|")
    s = s.strip()
    if len(s) > max_len:
        s = s[: max_len - 3] + "..."
    return s if s else " "


def short_time_from_timestamp(ts: str) -> str:
    """Prefer HH:MM:SS from ISO-8601 timestamps for scannable tables."""
    t = str(ts or "")
    if len(t) >= 19 and t[10:11] == "T":
        return t[11:19]
    return t[:19] if len(t) > 19 else t


def build_markdown_table(headers: List[str], rows: List[Sequence[Any]]) -> str:
    """GitHub-flavored markdown table (no leading blank line)."""
    if not headers:
        return ""
    esc = escape_md_table_cell
    head = "| " + " | ".join(esc(h) for h in headers) + " |"
    sep = "| " + " | ".join("---" for _ in headers) + " |"
    body_lines = []
    for row in rows:
        cells = list(row) + [""] * (len(headers) - len(row))
        cells = cells[: len(headers)]
        body_lines.append("| " + " | ".join(esc(c) for c in cells) + " |")
    return "\n".join([head, sep] + body_lines)


def format_correlation_report(result: dict) -> str:
    """
    Build correlation summary from build_v1_correlation_result + meta + paired_analysis samples.
    """
    lines: List[str] = []
    meta = result.get("meta") or {}
    domain_counts = meta.get("domain_event_counts") or {}
    chat_thread_counts = meta.get("chat_thread_counts") or {}
    evidence = result.get("evidence") or []
    doms = result.get("domains") or []
    requested_platform = meta.get("requested_platform") or ""
    plat_disp = requested_platform if requested_platform and str(requested_platform).lower() != "none" else ""
    date_one = meta.get("effective_date_filter") or ""
    samples = meta.get("evidence_samples") or {}
    paired_only = samples.get("paired_analysis") or []

    parts: List[str] = []
    if "chats" in doms or "messages" in doms:
        parts.append("chats")
    if "calls" in doms:
        parts.append("calls")
    if "locations" in doms:
        parts.append("locations")
    if "contacts" in doms:
        parts.append("contacts")
    pair_txt = " and ".join(parts) if parts else ", ".join(doms) or "requested domains"

    scope = plat_disp or "all sources in scope"
    date_bit = f" · {date_one}" if date_one else ""
    n_chats = int(domain_counts.get("chats") or 0)
    n_calls = int(domain_counts.get("calls") or 0)
    n_loc = int(domain_counts.get("locations") or 0)

    lines.append("# Correlation")
    lines.append("")
    if not domain_counts:
        lines.append(
            f"**Summary.** No rows matched this scope ({pair_txt}{', ' + plat_disp if plat_disp else ''}{date_bit})."
        )
    else:
        bits = []
        if n_chats:
            bits.append(f"{n_chats} chat message(s)")
        if n_loc:
            bits.append(f"{n_loc} location record(s)")
        if n_calls:
            bits.append(f"{n_calls} call log record(s)")
        lines.append(
            f"**Summary.** **{pair_txt}** ({scope}){date_bit} — "
            + (", ".join(bits) if bits else "see counts below.")
        )
    lines.append("")

    lines.append("**Counts**")
    if not domain_counts:
        lines.append("- No rows after filters.")
    for k in sorted(domain_counts.keys()):
        if k == "chats":
            thread_n = chat_thread_counts.get("chats")
            lines.append(
                f"- Chats: {domain_counts[k]} message(s)"
                + (f", {thread_n} thread(s)" if thread_n is not None else "")
            )
        elif k == "locations":
            lines.append(f"- Locations: {domain_counts[k]} record(s)")
        elif k == "calls":
            lines.append(f"- Calls: {domain_counts[k]} record(s)")
        elif k == "contacts":
            lines.append(f"- Contacts: {domain_counts[k]} record(s)")
        else:
            lines.append(f"- {k}: {domain_counts[k]} record(s)")

    for block in evidence:
        btype = block.get("type")
        rows = block.get("top_dates") or []
        if btype == "calls_chats_same_date" and rows:
            lines.append(
                "- Same-day overlap (calls vs chats): "
                + "; ".join(
                    f"{r.get('date')}: calls={r.get('count_a')}, chats={r.get('count_b')}"
                    for r in rows[:5]
                )
            )
        elif btype == "locations_chats_same_date" and rows:
            lines.append(
                "- Same-day overlap (locations vs chats): "
                + "; ".join(
                    f"{r.get('date')}: locations={r.get('count_a')}, chats={r.get('count_b')}"
                    for r in rows[:5]
                )
            )
        elif btype == "locations_calls_same_date" and rows:
            lines.append(
                "- Same-day overlap (locations vs calls): "
                + "; ".join(
                    f"{r.get('date')}: locations={r.get('count_a')}, calls={r.get('count_b')}"
                    for r in rows[:5]
                )
            )

    overlap_contacts: List[dict] = []
    for block in evidence:
        if block.get("type") == "same_contact_overlap":
            overlap_contacts = block.get("top_contacts") or []
            break
    if overlap_contacts:
        lines.append(
            "- Contacts in more than one domain: "
            + "; ".join(
                f"{c.get('contact')} ({', '.join(c.get('domains') or [])})"
                for c in overlap_contacts[:6]
            )
        )

    if not meta.get("query_constraint_match", True):
        lines.append("- Platform filter: no matching rows.")

    lines.append("")
    lines.append("**Records**")
    if paired_only:
        for ln in paired_only:
            lines.append(ln)
    else:
        lines.append("_No identical timestamps in this sample._")

    return "\n".join(lines)


def format_timeline_investigator(
    *,
    day: str,
    platform: str,
    timeline_events: List[Dict[str, Any]],
    total_events: int,
    want_chats: bool,
    want_locs: bool,
    truncated: bool = False,
    display_max: int = 0,
) -> str:
    """Wrap merged timeline output: markdown tables for scanability."""
    lines: List[str] = []
    facets = []
    if want_chats:
        facets.append("chats")
    if want_locs:
        facets.append("locations")
    facet_txt = " + ".join(facets) if facets else "events"

    lines.append(f"# Timeline · {day} · {platform}")
    lines.append("")
    shown_ct = len(timeline_events)
    lines.append(
        f"**Summary.** {total_events} {facet_txt} merged in time order"
        f"{f' (showing {shown_ct})' if truncated and display_max else ''}."
    )
    lines.append("")

    has_chat = any((e.get("kind") == "chat") for e in timeline_events)
    has_loc = any((e.get("kind") == "location") for e in timeline_events)

    if has_chat and has_loc:
        lines.append("### Merged timeline")
        urows: List[List[Any]] = []
        for e in timeline_events:
            tcell = short_time_from_timestamp(str(e.get("timestamp") or ""))
            plat = platform
            if e.get("kind") == "chat":
                fp = e.get("from_participant") or "Unknown"
                tp = e.get("to_participant") or "Unknown"
                msg = (e.get("text_content") or "").strip() or "[No text]"
                detail = f"{fp} → {tp}: {msg}"
                urows.append([tcell, "Chat", plat, detail])
            else:
                lat = e.get("latitude", "")
                lon = e.get("longitude", "")
                detail = f"({lat}, {lon})"
                urows.append([tcell, "Location", plat, detail])
        lines.append(
            build_markdown_table(["Time (UTC)", "Type", "Platform", "Details"], urows)
        )
    elif has_chat:
        lines.append("### Messages")
        crows: List[List[Any]] = []
        for e in timeline_events:
            tcell = short_time_from_timestamp(str(e.get("timestamp") or ""))
            crows.append(
                [
                    tcell,
                    e.get("from_participant") or "Unknown",
                    e.get("to_participant") or "Unknown",
                    (e.get("text_content") or "").strip() or "[No text]",
                ]
            )
        lines.append(
            build_markdown_table(["Time (UTC)", "Sender", "Receiver", "Message"], crows)
        )
    elif has_loc:
        lines.append("### Locations")
        lrows: List[List[Any]] = []
        for e in timeline_events:
            tcell = short_time_from_timestamp(str(e.get("timestamp") or ""))
            lrows.append(
                [
                    tcell,
                    e.get("latitude", ""),
                    e.get("longitude", ""),
                ]
            )
        lines.append(
            build_markdown_table(["Time (UTC)", "Latitude", "Longitude"], lrows)
        )
    else:
        lines.append("_No events in this view._")

    if truncated and display_max:
        lines.append("")
        lines.append(f"_… {max(0, total_events - display_max)} more not listed (total {total_events})._")

    return "\n".join(lines)
