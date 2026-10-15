#!/usr/bin/env python3
"""
Scoped evidence packaging for LLM calls — task-aware packets, metadata, and prompt contracts.

See docs/GOLD_LLM_QUERIES.md for regression-style investigator queries.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from core.evidence_scope import EvidenceScope, assess_evidence_sufficiency, compute_evidence_scope
from core.guarantee_class import GUARANTEE_FOLLOWUP_ANALYSIS, GUARANTEE_HYBRID
from core.query_intent_parser import parse_query_intent
from core.query_route import (
    PRIMARY_FOLLOWUP_ANALYSIS,
    PRIMARY_HYBRID_PERSON,
    PRIMARY_LLM_SYNTHESIS,
)

logger = logging.getLogger(__name__)

# --- Hard evidence contract (append to user message; Step 2) ---
EVIDENCE_CONTRACT_TEXT = """
EVIDENCE CONTRACT (MANDATORY):
- You must answer ONLY from the supplied FORENSIC DATA below.
- Do not assume that missing records exist outside what is shown.
- Do not mention platforms, contacts, or identifiers not present in this data.
- If evidence is insufficient to answer, say so clearly and list what is missing.
- Prefer factual description over speculation.
- Do NOT infer full cross-domain correlation, exact counts, or precise overlaps from broad
  undifferentiated blobs or global statistics alone—see system prompt (imperfect-packet safeguards).
- Sections labeled **DETERMINISTIC**, **PRE-COMPUTED**, **MATCHING_INSTANTS**, or explicit
  correlation / overlap tables in FORENSIC DATA are **authoritative ground truth for this turn**:
  do not contradict them or re-count with different totals; interpret and caveat them only.
""".strip()

# Injected into universal system prompt (llm_response_format) — not repeated in user message.
FORENSIC_PACKET_REASONING_SAFEGUARDS = """
══════════════════════════════════════════════════════════════════════════════
IMPERFECT / AMBIGUOUS EVIDENCE PACKAGES — REASONING SAFEGUARDS (MANDATORY)
══════════════════════════════════════════════════════════════════════════════
You are NOT a forensic computation engine. Do NOT infer or compute counts, joins,
cross-domain correlations, or “whole case” overlap from undifferentiated narrative blobs,
noisy snippets, or global statistics **unless** a deterministic block explicitly provides
aligned row-level facts.

1) **Missing platform/domain rows**
   If the question implies correlation across platforms/domains (e.g. app chats vs call logs)
   but FORENSIC DATA does **not** clearly show **both** sides with comparable row-level
   detail (timestamps, parties, identifiers), you **must** state that **correlation cannot
   be determined from the current slice**—do not guess alignment from prose or volume alone.

2) **Evidence strength (state explicitly when discussing overlap / correlation)**
   Pick the **strongest label the slice actually supports**—never upgrade:
   • **no evidence** — no rows for the requested domain, platform, contact, or timeframe.
   • **insufficient evidence** — data is fragmentary or ambiguous; cannot support the claim.
   • **weak overlap** — same calendar day (or coarse window) only; no precise time linkage.
   • **moderate overlap** — same identifiable contact **and** same day/window (still not exact instant).
   • **strong overlap** — **exact timestamp** (or equivalent) alignment, or explicit **MATCHING_INSTANTS**
     / pre-computed correlation rows that state a match.
   If labels do not apply, say what is missing instead of forcing a conclusion.

3) **Unspecified correlation scope**
   If **date**, **contact/party**, or **granularity** (day vs minute vs full case) is unclear
   in the question **and** not resolved by FORENSIC DATA, **explain the ambiguity** and what
   would be needed to test correlation—do **not** treat ambiguity as “no overlap” or absence.

4) **Deterministic / pre-computed summaries**
   Blocks headed **DETERMINISTIC**, **PRE-COMPUTED**, **MATCHING_INSTANTS**, or explicit
   correlation tables are **authoritative** for this turn. **Do not contradict** them;
   **do not re-derive** different counts. Summarize and interpret; add limits **around** them.

5) **Global statistics or full-case blobs**
   If the payload is mostly **aggregates**, **top-N**, or **large unstructured dumps** without
   aligned pairs, **avoid precise correlation conclusions**; stay descriptive; propose a
   **narrower** deterministic scope (date + platform + entities) in **Suggested Next Action**.
══════════════════════════════════════════════════════════════════════════════
""".strip()

# Step 7 — reduce speculative tone (also folded into system prompt where wired)
FORENSIC_SPECULATION_RULE = """
SPECULATION LIMITS:
- Do not infer motive, coordination, or relationship strength unless explicitly supported by strong, cited evidence in the FORENSIC DATA.
- Describe observable patterns and limits only.
""".strip()

# Step 8 — mandatory uncertainty structure (aligns with universal format tiers)
MANDATORY_UNCERTAINTY_SECTION_HINT = """
UNCERTAINTY SECTION (MANDATORY when not using the ultra-short tier):
- Include: **What the evidence supports**, **What cannot be concluded**, **Suggested next deterministic query** (one concrete example).
""".strip()


def _qlower(q: Optional[str]) -> str:
    return (q or "").strip().lower()


def normalize_entity_token(name: str) -> str:
    """Dedupe aliases: 'Josh Hickman' vs 'josh_hickman'."""
    if not name:
        return ""
    s = re.sub(r"[^\w\s@.+]", " ", name.lower())
    s = re.sub(r"\s+", " ", s).strip()
    s = s.replace(" ", "_")
    return s


# Same idea as web_interface._PERSON_NAME_TRAILING_STOPWORDS — avoid circular imports.
_PERSON_NAME_JUNK_TAIL = frozenset({
    "in", "on", "at", "for", "to", "from", "during", "after", "before", "between", "within",
    "the", "a", "an", "and", "or", "vs", "versus", "with", "about", "into", "by", "as", "of",
})


def sanitize_person_name_for_lookup(name: Optional[str]) -> Optional[str]:
    """
    Strip tokens like 'in' from 'Josh Hickman in' (from '... with Josh Hickman in 2020').
    """
    if not name or not str(name).strip():
        return None
    parts = str(name).strip().split()
    while len(parts) > 1 and parts[-1].lower() in _PERSON_NAME_JUNK_TAIL:
        parts.pop()
    out = " ".join(parts).strip()
    return out or None


def _extract_years_from_query(query: str) -> List[int]:
    years: List[int] = []
    for m in re.finditer(r"\b(19|20)\d{2}\b", query or ""):
        years.append(int(m.group(0)))
    return sorted(set(years))


def _detect_platform_scope(query: str, parsed_intent: Dict[str, Any]) -> str:
    pl = (parsed_intent or {}).get("platform") or (parsed_intent or {}).get("platforms")
    if isinstance(pl, list) and pl:
        return ",".join(str(x) for x in pl[:6])
    if isinstance(pl, str) and pl.strip():
        return pl.strip()
    q = _qlower(query)
    known = [
        "whatsapp", "telegram", "signal", "facebook", "messenger", "instagram",
        "snapchat", "twitter", "tiktok", "line", "skype", "discord", "sms",
        "native message", "imessage",
    ]
    found = [k for k in known if k in q]
    return ",".join(found) if found else "unspecified"


def _detect_date_scope(query: str) -> str:
    years = _extract_years_from_query(query)
    if years:
        return f"year(s)={','.join(str(y) for y in years)}"
    # crude month/day
    m = re.search(
        r"\b(\d{4})-(\d{2})-(\d{2})\b",
        query or "",
    )
    if m:
        return f"date={m.group(0)}"
    return "unspecified"


def _is_timeline_query(q: str) -> bool:
    return any(
        w in q
        for w in (
            "timeline",
            "chronolog",
            "sequence",
            "history of",
            "when did",
            "order of events",
        )
    )


def _is_pattern_query(q: str) -> bool:
    return any(
        w in q
        for w in (
            "pattern",
            "distribution",
            "frequency",
            "how often",
            "suspicious pattern",
            "communication pattern",
            "activity across",
        )
    )


def _is_comparison_query(q: str) -> bool:
    return bool(
        re.search(
            r"\b(compare|comparison|versus| vs |between .{2,40} and )\b",
            q,
            re.IGNORECASE,
        )
    )


def _is_correlation_query(q: str) -> bool:
    return any(
        w in q
        for w in (
            "correlate",
            "correlation",
            "correaltion",
            "correletion",
            "corrlation",
            "overlap",
            "overlapping",
            "same day",
            "same date",
            "timeline reconstruction",
            "reconstruct the timeline",
        )
    )


def extract_iso_date_from_query(text: str) -> Optional[str]:
    """Return YYYY-MM-DD from bracketed or bare ISO date in the query."""
    if not text:
        return None
    m = re.search(r"\[(\d{4}-\d{2}-\d{2})\]", text)
    if m:
        return m.group(1)
    m = re.search(r"\b(\d{4}-\d{2}-\d{2})\b", text)
    if m:
        return m.group(1)
    return None


def _infer_chat_platform_filter(query: str) -> Optional[str]:
    """Lowercase platform keyword for chat_messages.platform LIKE."""
    ql = _qlower(query)
    pairs = [
        ("whatsapp", "whatsapp"),
        ("telegram", "telegram"),
        ("signal", "signal"),
        ("instagram", "instagram"),
        ("facebook messenger", "facebook messenger"),
        ("messenger", "messenger"),
        ("line", "line"),
        ("snapchat", "snapchat"),
        ("skype", "skype"),
        ("tiktok", "tiktok"),
        ("twitter", "twitter"),
    ]
    for needle, plat in pairs:
        if needle in ql:
            return plat
    return None


def build_app_vs_calls_correlation_for_date(
    *,
    query: str,
    data_layer: Any,
    max_items: int,
) -> Optional[str]:
    """
    Deterministic same-day correlation: third-party chat_messages (optional platform filter)
    vs native call_logs. LLM should explain this table, not invent counts.
    """
    date = extract_iso_date_from_query(query)
    if not date:
        return None
    ql = _qlower(query)
    if not any(
        k in ql
        for k in (
            "correlate",
            "correlation",
            "correaltion",
            "correletion",
            "corrlation",
            "overlap",
            "cross-reference",
        )
    ):
        return None
    if "call" not in ql and "calls" not in ql:
        return None

    plat_kw = _infer_chat_platform_filter(query)
    conn = data_layer.get_connection()
    try:
        cur = conn.cursor()
        cm_rows: List[Any] = []
        cap = min(500, max(200, max_items * 10))
        if plat_kw:
            cur.execute(
                """
                SELECT * FROM chat_messages
                WHERE (
                    substr(COALESCE(timestamp, ''), 1, 10) = ?
                    OR substr(replace(COALESCE(timestamp, ''), 'T', ' '), 1, 10) = ?
                )
                AND LOWER(COALESCE(platform, '')) LIKE ?
                ORDER BY timestamp ASC
                LIMIT ?
                """,
                (date, date, f"%{plat_kw}%", cap),
            )
            cm_rows = cur.fetchall()
        else:
            # No app named: same-day all platforms, hard-capped (avoids unbounded dump).
            cur.execute(
                """
                SELECT * FROM chat_messages
                WHERE (
                    substr(COALESCE(timestamp, ''), 1, 10) = ?
                    OR substr(replace(COALESCE(timestamp, ''), 'T', ' '), 1, 10) = ?
                )
                ORDER BY timestamp ASC
                LIMIT ?
                """,
                (date, date, cap),
            )
            cm_rows = cur.fetchall()

        cur.execute(
            """
            SELECT * FROM call_logs
            WHERE (
                substr(COALESCE(timestamp, ''), 1, 10) = ?
                OR substr(replace(COALESCE(timestamp, ''), 'T', ' '), 1, 10) = ?
            )
            ORDER BY timestamp ASC
            LIMIT ?
            """,
            (date, date, max(200, max_items * 10)),
        )
        call_rows = cur.fetchall()
    finally:
        conn.close()

    plat_note = plat_kw or "(all platforms; capped)"

    def _row_as_dict(r: Any) -> Dict[str, Any]:
        return {k: r[k] for k in r.keys()}

    lines: List[Tuple[str, str]] = []

    def _cm_line(r: Any) -> str:
        d = _row_as_dict(r)
        ts = d.get("timestamp") or d.get("timestamp_formatted") or ""
        fp = d.get("from_participant") or d.get("from_identifier") or "?"
        tp = d.get("to_participant") or d.get("to_identifier") or "?"
        mt = d.get("message_type") or "?"
        body = (d.get("text_content") or "")[:220].replace("\n", " ")
        plat = d.get("platform") or "?"
        return f"[{ts}] CHAT_MSG | {plat} | type={mt} | {fp} → {tp} | {body}"

    def _call_line(r: Any) -> str:
        d = _row_as_dict(r)
        ts = d.get("timestamp") or d.get("timestamp_formatted") or ""
        fn = d.get("from_number") or "?"
        tn = d.get("to_number") or "?"
        dur = d.get("duration", "?")
        ct = d.get("call_type") or "?"
        return f"[{ts}] CALL_LOG | {fn} → {tn} | dur={dur}s | {ct}"

    def _ts_match_key(ts: str) -> str:
        """Normalize ISO-like timestamps so chat_messages vs call_logs can be paired."""
        if not ts:
            return ""
        m = re.search(
            r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)",
            str(ts).replace("Z", "+00:00"),
        )
        if m:
            return m.group(1).replace(" ", "T")
        return ""

    cm_keys = {_ts_match_key(_row_as_dict(r).get("timestamp")) for r in cm_rows}
    cm_keys.discard("")
    call_keys = {_ts_match_key(_row_as_dict(r).get("timestamp")) for r in call_rows}
    call_keys.discard("")
    matching_instants = sorted(cm_keys & call_keys)

    for r in cm_rows:
        ts = _row_as_dict(r).get("timestamp") or ""
        lines.append((ts, _cm_line(r)))
    for r in call_rows:
        ts = _row_as_dict(r).get("timestamp") or ""
        lines.append((ts, _call_line(r)))

    lines.sort(key=lambda x: (x[0] or "").replace("T", " "))

    align_lines: List[str] = []
    if matching_instants:
        align_lines.append(
            f"MATCHING_INSTANTS (same wall-clock time in BOTH chat_messages and call_logs): "
            f"{len(matching_instants)} — {', '.join(matching_instants)}"
        )
        align_lines.append(
            "These pairs are DETERMINISTIC: do NOT claim there is no correlation or no matching "
            "call log when the same instant appears as CHAT_MSG and CALL_LOG in the timeline."
        )
    else:
        align_lines.append(
            "MATCHING_INSTANTS: 0 (no identical normalized timestamps between chat_messages and "
            "call_logs for this slice — still describe both series separately)."
        )

    instr_model: List[str] = [
        "- These rows are the complete filtered slice for this date (within row limits).",
        (
            "- DETERMINISTIC_COUNTS.chat_messages_rows is the exact number of filtered app rows; "
            "never report fewer rows than that count unless you quote the same number."
        ),
        "- Align app-layer chat rows with CALL_LOG rows by timestamp where comparable.",
        "- App 'call' or system rows and native call_logs may both reflect voice/video activity for the same real-world call.",
        "- If MATCHING_INSTANTS is non-empty, you MUST acknowledge temporal alignment between app-layer rows and native call_logs at those instants.",
    ]
    if plat_kw:
        instr_model.append(
            "- Do NOT state that only one app message exists when DETERMINISTIC_COUNTS shows chat_messages_rows>1."
        )
    else:
        instr_model.append(
            "- CHAT_PLATFORM_FILTER is all platforms (capped): each line shows its platform; do not assume a single app."
        )

    parts: List[str] = [
        f"CORRELATION_SCOPE: calendar_date={date}",
        f"CHAT_PLATFORM_FILTER: {plat_note}",
        f"DETERMINISTIC_COUNTS: chat_messages_rows={len(cm_rows)} call_logs_rows={len(call_rows)}",
        "",
        "INSTRUCTIONS_FOR_MODEL:",
        *instr_model,
        "",
        *align_lines,
        "",
        "UNIFIED_TIMELINE (sorted by timestamp):",
    ]
    parts.extend(ln for _, ln in lines[: min(500, len(lines))])
    if len(lines) > 500:
        parts.append(f"\n[Note: timeline truncated to 500 of {len(lines)} rows for context size]")
    return "\n".join(parts)


def _extract_two_person_names(query: str) -> Optional[Tuple[str, str]]:
    """Best-effort extraction for comparison/correlation packets."""
    q = query or ""
    m = re.search(
        r"\b(?:between|compare)\s+([^,]+?)\s+(?:and|vs\.?|versus)\s+(.+?)(?:\?|$)",
        q,
        re.IGNORECASE,
    )
    if m:
        a, b = m.group(1).strip(), m.group(2).strip()
        a = re.sub(r"\s+(with|for)\s*$", "", a, flags=re.I).strip()
        b = re.sub(r"\s+(with|for)\s*$", "", b, flags=re.I).strip()
        if len(a) > 1 and len(b) > 1:
            return (a[:120], b[:120])
    return None


def infer_llm_packet_type(
    *,
    query: str,
    parsed_intent: Dict[str, Any],
    query_route: Optional[Dict[str, Any]],
    person_name_extracted: Optional[str],
    followup_llm_only: bool,
    followup_mode_active: bool,
) -> str:
    """Returns internal packet label used for logging and shaping."""
    if followup_llm_only or followup_mode_active:
        return "followup"
    qr = query_route or {}
    primary = qr.get("primary")
    gc = qr.get("guarantee_class")
    q = _qlower(query)

    if gc == GUARANTEE_FOLLOWUP_ANALYSIS or primary == PRIMARY_FOLLOWUP_ANALYSIS:
        return "followup"

    if _is_correlation_query(q):
        return "correlation"

    if _is_comparison_query(q) and (_extract_two_person_names(query) or " and " in q):
        return "comparison"

    if _is_pattern_query(q):
        return "pattern"

    if person_name_extracted and (
        _is_timeline_query(q)
        or primary == PRIMARY_HYBRID_PERSON
        or (gc == GUARANTEE_HYBRID and "person" in _qlower(qr.get("reason", "")))
    ):
        return "person_timeline"

    if person_name_extracted and any(
        x in q for x in ("communicat", "message", "chat", "call", "interaction")
    ):
        return "person_summary"

    if primary == PRIMARY_LLM_SYNTHESIS:
        return "hybrid_general"

    return "general"


def apply_smart_budget(text: str, max_chars: int) -> Tuple[str, bool]:
    """
    Prefer keeping earliest + latest sections over blind middle truncation (Step 6).
    """
    if max_chars <= 0 or len(text) <= max_chars:
        return text, False
    sep = "\n\n[... EVIDENCE TRUNCATED — middle omitted; earliest and latest regions preserved ...]\n\n"
    reserve = len(sep) + 80
    head = int((max_chars - reserve) * 0.55)
    tail = max_chars - reserve - head
    head = max(400, head)
    tail = max(400, tail)
    if head + tail + reserve > len(text):
        return text[:max_chars], True
    out = text[:head] + sep + text[-tail:]
    return out, True


def _dedupe_events(lines: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for ln in lines:
        key = hashlib.sha256(ln.encode("utf-8", errors="ignore")).hexdigest()[:24]
        if key in seen:
            continue
        seen.add(key)
        out.append(ln)
    return out


def build_person_timeline_packet(
    *,
    query: str,
    data_layer: Any,
    person_name: str,
    max_items: int,
) -> str:
    person_name = sanitize_person_name_for_lookup(person_name) or person_name
    comm = data_layer.get_all_communications_for_person(person_name, limit=max(200, max_items * 5))
    contact = comm.get("contact_info") or {}
    cid = contact.get("contact_id")
    aliases = sorted(
        {normalize_entity_token(person_name), normalize_entity_token(contact.get("name") or "")}
        - {""}
    )

    events: List[Tuple[str, str]] = []
    for msg in comm.get("messages") or []:
        ts = msg.get("timestamp") or msg.get("timestamp_formatted") or ""
        body = (
            (msg.get("text_content") or msg.get("text") or "")[:240]
            .replace("\n", " ")
            .strip()
        )
        plat = msg.get("platform") or msg.get("source") or "?"
        fp = msg.get("from_participant") or msg.get("from_number") or "?"
        tp = msg.get("to_participant") or msg.get("to_number") or "?"
        line = f"[{ts}] CHAT/SMS | {plat} | {fp} → {tp} | {body}"
        events.append((ts, line))

    for call in comm.get("calls") or []:
        ts = call.get("timestamp") or ""
        fn = call.get("from_number") or "?"
        tn = call.get("to_number") or "?"
        dur = call.get("duration", "")
        line = f"[{ts}] CALL | {fn} → {tn} | dur={dur}s"
        events.append((ts, line))

    events.sort(key=lambda x: x[0] or "")

    years = _extract_years_from_query(query)
    if years:

        def _in_years(ts: str) -> bool:
            return any(str(y) in (ts or "")[:12] for y in years)

        events = [e for e in events if _in_years(e[0])]

    lines = [e[1] for e in events]
    lines = _dedupe_events(lines)

    parts: List[str] = []
    parts.append("=== PERSON-SCOPED TIMELINE (deduplicated) ===")
    parts.append(f"SUBJECT: {person_name}")
    if cid is not None:
        parts.append(f"CANONICAL_CONTACT_ID: {cid}")
    if aliases:
        parts.append(f"NORMALIZED_ALIASES: {', '.join(aliases)}")
    summ = comm.get("summary") or {}
    parts.append(
        f"SUMMARY_COUNTS: chats={summ.get('total_chats', 0)} messages={summ.get('total_messages', 0)} "
        f"calls={summ.get('total_calls', 0)}"
    )
    dr = summ.get("date_range") or {}
    if dr.get("earliest") or dr.get("latest"):
        parts.append(f"EARLIEST_EVENT: {dr.get('earliest')} | LATEST_EVENT: {dr.get('latest')}")

    parts.append("")
    parts.append("CHRONOLOGY (observable; not a full device timeline):")
    parts.extend(lines[: min(400, len(lines))])
    return "\n".join(parts)


def _daily_message_activity(
    conn: Any, needle: str, limit_days: int = 120
) -> Dict[str, int]:
    """Count chat_messages rows per calendar day mentioning / involving needle."""
    needle = needle.strip()
    if not needle:
        return {}
    cur = conn.cursor()
    like = f"%{needle}%"
    cur.execute(
        """
        SELECT substr(COALESCE(timestamp, ''), 1, 10) AS d, COUNT(*) AS c
        FROM chat_messages
        WHERE timestamp IS NOT NULL AND timestamp != ''
          AND (
            from_participant LIKE ? OR LOWER(from_participant) LIKE ?
            OR to_participant LIKE ? OR LOWER(to_participant) LIKE ?
            OR text_content LIKE ? OR LOWER(text_content) LIKE ?
          )
        GROUP BY d
        ORDER BY d DESC
        LIMIT ?
        """,
        (like, like.lower(), like, like.lower(), like, like.lower(), limit_days * 3),
    )
    rows = cur.fetchall()
    out: Dict[str, int] = {}
    for r in rows:
        d = r["d"]
        c = r["c"]
        if d and len(str(d)) >= 10:
            out[str(d)[:10]] = int(c)
    return out


def build_comparison_packet(
    *,
    query: str,
    data_layer: Any,
    max_items: int,
    evidence_scope: Optional[EvidenceScope] = None,
) -> str:
    if evidence_scope is None:
        evidence_scope = compute_evidence_scope(query, parse_query_intent(query), None)
    pair = _extract_two_person_names(query)
    parts: List[str] = ["=== COMPARISON (STRUCTURED) ==="]
    if not pair:
        parts.append(
            "NOTE: Could not reliably extract two person names. "
            "Falling back to generic retrieval is recommended."
        )
        return (
            "\n".join(parts)
            + "\n"
            + data_layer.get_relevant_data_for_llm(
                query, max_items=max_items, evidence_scope=evidence_scope
            )
        )

    a, b = pair
    conn = data_layer.get_connection()
    try:
        da = _daily_message_activity(conn, a)
        db = _daily_message_activity(conn, b)
    finally:
        conn.close()

    common_days = sorted(set(da.keys()) & set(db.keys()))
    parts.append(f"ENTITIES: A={a!r} | B={b!r}")
    parts.append(f"DATE_SCOPE: {_detect_date_scope(query)}")
    parts.append("")
    parts.append("SIDE_BY_SIDE_DAILY_CHAT_ACTIVITY (chat_messages table; counts are deterministic):")
    parts.append(f"{'DATE':<12} | {a[:28]:<28} | {b[:28]:<28}")
    for d in sorted(set(list(da.keys()) + list(db.keys())))[-30:]:
        parts.append(f"{d:<12} | {da.get(d, 0):<28} | {db.get(d, 0):<28}")
    parts.append("")
    parts.append(f"OVERLAP_DAYS (both non-zero): {len(common_days)} (sample: {', '.join(common_days[-10:])})")
    return "\n".join(parts)


def build_correlation_packet(
    *,
    query: str,
    data_layer: Any,
    max_items: int,
    evidence_scope: Optional[EvidenceScope] = None,
) -> str:
    """Deterministic pre-correlation; LLM explains, does not re-count (Step 5)."""
    if evidence_scope is None:
        evidence_scope = compute_evidence_scope(query, parse_query_intent(query), None)
    pair = _extract_two_person_names(query)
    base = build_comparison_packet(
        query=query,
        data_layer=data_layer,
        max_items=max_items,
        evidence_scope=evidence_scope,
    )
    if pair:
        return "=== DETERMINISTIC CORRELATION / OVERLAP (PRE-COMPUTED) ===\n" + base

    cross = build_app_vs_calls_correlation_for_date(
        query=query, data_layer=data_layer, max_items=max_items
    )
    if cross:
        return (
            "=== DETERMINISTIC CROSS-DOMAIN CORRELATION (APP CHAT_MESSAGES vs CALL_LOGS) ===\n"
            + cross
        )

    # Single-subject or vague correlation: still avoid raw full-case dump — use scoped retrieval
    return (
        "=== DETERMINISTIC CORRELATION (PRE-COMPUTED SUMMARY) ===\n"
        "No two-person comparison or dated app-vs-calls correlation could be built from the query.\n"
        "Below is query-scoped forensic context (not a full case export).\n\n"
        + data_layer.get_relevant_data_for_llm(
            query, max_items=min(max_items, 80), evidence_scope=evidence_scope
        )
    )


def build_pattern_packet(
    *,
    query: str,
    data_layer: Any,
    max_items: int,
    evidence_scope: Optional[EvidenceScope] = None,
) -> str:
    if evidence_scope is None:
        evidence_scope = compute_evidence_scope(query, parse_query_intent(query), None)
    stats = ""
    if evidence_scope.mode == "case_overview":
        try:
            stats = data_layer.get_pattern_analysis_summary()
        except Exception as ex:
            logger.warning("get_pattern_analysis_summary failed: %s", ex)
            stats = ""
    scoped = data_layer.get_relevant_data_for_llm(
        query, max_items=min(max_items, 60), evidence_scope=evidence_scope
    )
    return (
        "=== PATTERN / DISTRIBUTION PACKET ===\n"
        f"{stats}\n\n"
        "=== QUERY-SCOPED SAMPLES (trimmed) ===\n"
        f"{scoped}"
    )


def build_followup_packet(
    *,
    query: str,
    data_layer: Any,
    max_items: int,
    evidence_scope: Optional[EvidenceScope] = None,
) -> str:
    """Narrow retrieval for follow-up analysis mode."""
    if evidence_scope is None:
        evidence_scope = compute_evidence_scope(query, parse_query_intent(query), None)
    return (
        "=== FOLLOW-UP SCOPED PACKET ===\n"
        "Use only this block plus any FOLLOW-UP BASE CONTENT the host prepends.\n\n"
        + data_layer.get_relevant_data_for_llm(
            query, max_items=min(max_items, 40), evidence_scope=evidence_scope
        )
    )


def build_person_summary_packet(
    *,
    data_layer: Any,
    person_name: str,
    max_items: int,
) -> str:
    person_name = sanitize_person_name_for_lookup(person_name) or person_name
    comm = data_layer.get_all_communications_for_person(
        person_name, limit=max(200, max_items * 5)
    )
    try:
        return data_layer.format_comprehensive_analysis(person_name, comm)
    except Exception:
        return build_person_timeline_packet(
            query="",
            data_layer=data_layer,
            person_name=person_name,
            max_items=max_items,
        )


@dataclass
class EvidencePacket:
    text: str
    metadata: Dict[str, Any] = field(default_factory=dict)


def _apply_packet_feedback_learning(
    pkt_type: str,
    *,
    query: str,
    person_name_extracted: Optional[str],
    followup_llm_only: bool,
    followup_mode_active: bool,
) -> Tuple[str, Dict[str, Any]]:
    """Bias packet label from policy + similar past corrections (guards for person/followup)."""
    from core.query_feedback import apply_feedback_to_packet_type

    new_p, meta = apply_feedback_to_packet_type(pkt_type, raw_query=query)
    if new_p in ("person_timeline", "person_summary") and not (person_name_extracted or "").strip():
        return pkt_type, {**meta, "packet_feedback_applied": False, "feedback_skipped": "no_person_name"}
    if new_p == "followup" and not (followup_llm_only or followup_mode_active):
        return pkt_type, {**meta, "packet_feedback_applied": False, "feedback_skipped": "not_followup_mode"}
    return new_p, meta


def build_llm_evidence_packet(
    *,
    query: str,
    parsed_intent: Dict[str, Any],
    data_layer: Any,
    query_route: Optional[Dict[str, Any]] = None,
    person_name_extracted: Optional[str] = None,
    max_items: int = 100,
    guarantee_class: Optional[str] = None,
    followup_llm_only: bool = False,
    followup_mode_active: bool = False,
    max_chars: int = 14000,
    apply_feedback_learning: bool = True,
) -> EvidencePacket:
    """
    Build a scoped evidence string + metadata for one LLM turn.
    """
    person_name_extracted = sanitize_person_name_for_lookup(person_name_extracted)

    pkt_type = infer_llm_packet_type(
        query=query,
        parsed_intent=parsed_intent or {},
        query_route=query_route,
        person_name_extracted=person_name_extracted,
        followup_llm_only=followup_llm_only,
        followup_mode_active=followup_mode_active,
    )
    packet_feedback_meta: Dict[str, Any] = {}
    if apply_feedback_learning:
        pkt_type, packet_feedback_meta = _apply_packet_feedback_learning(
            pkt_type,
            query=query,
            person_name_extracted=person_name_extracted,
            followup_llm_only=followup_llm_only,
            followup_mode_active=followup_mode_active,
        )

    entity_scope = person_name_extracted or "unspecified"
    platform_scope = _detect_platform_scope(query, parsed_intent or {})
    date_scope = _detect_date_scope(query)
    scope = compute_evidence_scope(query, parsed_intent or {}, query_route)

    text = ""
    try:
        if pkt_type == "followup":
            text = build_followup_packet(
                query=query,
                data_layer=data_layer,
                max_items=max_items,
                evidence_scope=scope,
            )
        elif pkt_type == "person_timeline" and (person_name_extracted or "").strip():
            text = build_person_timeline_packet(
                query=query,
                data_layer=data_layer,
                person_name=person_name_extracted.strip(),
                max_items=max_items,
            )
        elif pkt_type == "person_summary" and (person_name_extracted or "").strip():
            text = build_person_summary_packet(
                data_layer=data_layer,
                person_name=person_name_extracted.strip(),
                max_items=max_items,
            )
        elif pkt_type == "comparison":
            text = build_comparison_packet(
                query=query,
                data_layer=data_layer,
                max_items=max_items,
                evidence_scope=scope,
            )
        elif pkt_type == "correlation":
            text = build_correlation_packet(
                query=query,
                data_layer=data_layer,
                max_items=max_items,
                evidence_scope=scope,
            )
        elif pkt_type == "pattern":
            text = build_pattern_packet(
                query=query,
                data_layer=data_layer,
                max_items=max_items,
                evidence_scope=scope,
            )
        else:
            text = data_layer.get_relevant_data_for_llm(
                query, max_items=max_items, evidence_scope=scope
            )
    except Exception as ex:
        logger.error("build_llm_evidence_packet: primary builder failed: %s", ex, exc_info=True)
        text = data_layer.get_relevant_data_for_llm(
            query, max_items=max_items, evidence_scope=scope
        )
        pkt_type = f"{pkt_type}_fallback"

    text, truncated = apply_smart_budget(text, max_chars)
    suff_ok, substantive_rows = assess_evidence_sufficiency(text)
    row_estimate = len([ln for ln in text.splitlines() if ln.strip()])
    thin_note = ""
    if not suff_ok:
        thin_note = (
            "\nEVIDENCE_NOTE: Scoped evidence is very thin — state uncertainty clearly; "
            "do not infer strong patterns, covert coordination, or case-wide conclusions.\n"
        )
    text = (
        scope.scope_header_line(
            sufficient_for_analysis=suff_ok,
            evidence_rows=substantive_rows,
        )
        + thin_note
        + "\n"
        + text
    )

    meta: Dict[str, Any] = {
        "LLM_PACKET_TYPE": pkt_type,
        "ENTITY_SCOPE": entity_scope,
        "PLATFORM_SCOPE": platform_scope,
        "DATE_SCOPE": date_scope,
        "EVIDENCE_ROWS": row_estimate,
        "EVIDENCE_CHAR_COUNT": len(text),
        "EVIDENCE_TRUNCATED": truncated,
        "GUARANTEE_CLASS": guarantee_class or (query_route or {}).get("guarantee_class"),
        "CORRELATION_PRECOMPUTED": pkt_type == "correlation",
        "EVIDENCE_SCOPE_MODE": scope.mode,
        "EVIDENCE_SCOPE_DOMAINS": list(scope.effective_domains() or scope.domains),
        "EVIDENCE_SCOPE_PLATFORMS": list(scope.platforms),
        "INCLUDE_GLOBAL_PREAMBLE": scope.include_global_preamble,
        "SUFFICIENT_FOR_ANALYSIS": suff_ok,
        "EVIDENCE_SUBSTANTIVE_ROWS": substantive_rows,
        "IS_FOLLOWUP_SCOPE": scope.is_followup,
    }
    if packet_feedback_meta:
        meta["PACKET_FEEDBACK_META"] = packet_feedback_meta
    return EvidencePacket(text=text, metadata=meta)


def log_llm_packet_debug(packet: EvidencePacket, _logger: Optional[logging.Logger] = None) -> None:
    log = _logger or logger
    m = packet.metadata
    log.info(
        "LLM_PACKET_DEBUG "
        "LLM_PACKET_TYPE=%s ENTITY_SCOPE=%s PLATFORM_SCOPE=%s DATE_SCOPE=%s "
        "ROW_COUNT=%s CHAR_COUNT=%s EVIDENCE_TRUNCATED=%s GUARANTEE_CLASS=%s "
        "EVIDENCE_SCOPE_MODE=%s SUFFICIENT_FOR_ANALYSIS=%s SUBSTANTIVE_ROWS=%s GLOBAL_PREAMBLE=%s",
        m.get("LLM_PACKET_TYPE"),
        m.get("ENTITY_SCOPE"),
        m.get("PLATFORM_SCOPE"),
        m.get("DATE_SCOPE"),
        m.get("EVIDENCE_ROWS"),
        m.get("EVIDENCE_CHAR_COUNT"),
        m.get("EVIDENCE_TRUNCATED"),
        m.get("GUARANTEE_CLASS"),
        m.get("EVIDENCE_SCOPE_MODE"),
        m.get("SUFFICIENT_FOR_ANALYSIS"),
        m.get("EVIDENCE_SUBSTANTIVE_ROWS"),
        m.get("INCLUDE_GLOBAL_PREAMBLE"),
    )
