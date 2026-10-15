#!/usr/bin/env python3
"""
Universal structured response format for all forensic LLM answers.

Tiers:
  - ultra_short: 3 section headings (compact)
  - normal: 5 section headings (default depth)
  - extended: same 5 headings, deeper allowances for large / case-level questions
  - investigator_detail: same 5 headings; narrative depth, ### subsections, evidence excerpts allowed
  - skip: use alternate template (e.g. explicit pull-messages command)
"""

from __future__ import annotations

import re
from typing import Optional

from core.llm_evidence_packet import FORENSIC_PACKET_REASONING_SAFEGUARDS

EXTENDED_HINTS = re.compile(
    r"\b("
    r"comprehensive|full\s+case|entire\s+case|whole\s+case|deep\s+dive|exhaustive|full\s+analysis|"
    r"investigate\s+everything|all\s+aspects|case[-\s]?level|multi[-\s]?source|"
    r"thorough|in[-\s]?depth|detailed\s+report|complete\s+review"
    r")\b",
    re.I,
)

ULTRA_SHORT_HINTS = re.compile(
    r"\b("
    r"brief|briefly|short\s+answer|one\s+sentence|one\s+line|tldr|tl;dr|quick|summary\s+only|"
    r"in\s+a\s+few\s+words|just\s+the|keep\s+it\s+short"
    r")\b",
    re.I,
)

# Investigator asked for narrative depth — prefer this tier over default compact layouts.
DETAIL_REQUEST_HINTS = re.compile(
    r"\b("
    r"in\s+detail|more\s+detail|greater\s+detail|with\s+detail|"
    r"detailed(?:\s+explanation|\s+analysis|\s+breakdown)?|"
    r"explain\s+(?:this|that|it|the\s+\w+)\s+in\s+detail|explain\s+in\s+detail|"
    r"walk\s+me\s+through|step\s+by\s+step|elaborate|expand\s+on|break\s+(?:it|this)\s+down|"
    r"as\s+much\s+detail|go\s+deep|thoroughly|at\s+length|"
    r"deep\s+dive\s+into|fully\s+explain"
    r")\b",
    re.I,
)


def select_response_format_tier(
    *,
    query: str,
    data_context_chars: int = 0,
    should_be_brief: bool = False,
    should_be_comprehensive: bool = False,
    classification_type: Optional[str] = None,
    primary_intent: str = "exploratory",
    is_pull_messages: bool = False,
) -> str:
    """
    Adaptive layout for universal forensic responses.

    Returns one of: 'ultra_short' | 'normal' | 'extended' | 'investigator_detail' | 'skip'
    """
    if is_pull_messages:
        return "skip"

    q = (query or "").strip()
    ql = q.lower()

    wants_brief = bool(should_be_brief or ULTRA_SHORT_HINTS.search(ql))
    wants_narrative_detail = bool(DETAIL_REQUEST_HINTS.search(ql))

    # Investigator asked for depth — do not force ultra_short just because context is small.
    if wants_narrative_detail and not wants_brief:
        return "investigator_detail"

    # Explicit comprehensive / case-level
    if should_be_comprehensive or EXTENDED_HINTS.search(ql):
        return "extended"

    if wants_brief:
        return "ultra_short"

    if data_context_chars and data_context_chars < 2200:
        return "ultra_short"

    if data_context_chars > 16000:
        return "extended"

    if classification_type == "hybrid" and len(q) > 220:
        return "extended"

    if primary_intent in ("analytical", "exploratory") and len(q) > 400 and data_context_chars > 8000:
        return "extended"

    return "normal"


def format_universal_response_instructions(tier: str) -> str:
    """Prompt block injected into the system message (empty when tier == 'skip')."""
    if tier == "skip":
        return ""

    if tier == "investigator_detail":
        return _format_investigator_detail_instructions()

    guardrails = """
══════════════════════════════════════════════════════════════════════════════
MANDATORY RESPONSE STRUCTURE (ALL NON-PULL ANSWERS)
══════════════════════════════════════════════════════════════════════════════
- Use ONLY the section headings given below for this tier.
- Use Markdown ## for each top-level section title EXACTLY as written (same wording and order).
- Do NOT rename, merge, split, skip, or reorder sections.
- Do NOT add extra top-level sections (no "Introduction", "Conclusion", "Hypotheses", or duplicate headings).
- **Deterministic parity:** If FORENSIC DATA begins with a pre-computed block (counts, correlation, merged timeline), treat those counts and overlap totals as authoritative. Lead **Direct Answer / Core Finding** with the same factual takeaway, put row-level detail under **Key Supporting Observations**, and do not contradict stated numbers.
- Ground every factual claim in the FORENSIC DATA / base content; if data is missing, say so in Uncertainty / Limits.
- If evidence is thin but partially relevant, do NOT return a hard "no data" summary:
  report the related signals that are present, explicitly label confidence as limited, and state what is missing for a stronger conclusion.
- You do NOT execute deterministic queries — describe one next investigative step or query as plain text only.
- Tone: analytical, cautious, professional. Avoid generic disclaimers ("as an AI…", "for educational purposes…").
- Avoid overusing hypothesis-style lists; if alternatives are needed, fold them into **Interpretation / Insight** as careful prose.
══════════════════════════════════════════════════════════════════════════════
EVIDENCE TYPE CLASSIFICATION (INTERNAL — BEFORE YOU WRITE)
══════════════════════════════════════════════════════════════════════════════
Silently classify the PRIMARY evidence type of the FORENSIC DATA / user question, then use the matching reasoning style.
You do NOT need to print the label unless the user explicitly asks how you classified it.

• **timeline events** — Chronology, ordering, gaps, overlaps, simultaneity; what can/cannot be inferred about duration or sequence.
• **listing / aggregation** — Inventories, counts, tables (contacts, chats, calls, etc.); emphasize structure and metrics, not invented relationships. See **LISTING / AGGREGATION OUTPUT RULES** below.
• **correlation output** — Cross-domain joins, overlaps, time-window matches; state linkage strength; do NOT imply causation without support.
• **reconstruction output** — Narrative built from fragments; mark uncertainty; never fill gaps with invented detail.
• **content messages** — Substantive text/media; anchor claims on quoted or clearly paraphrased content; avoid over-reading intent or tone.
• **contact profile** — Names, numbers, IDs, account fields; separate record attributes from communication behavior unless both are present.

If several types appear, lead with the dominant one; mention secondary types only when it helps the investigation.
══════════════════════════════════════════════════════════════════════════════
LISTING / AGGREGATION OUTPUT RULES (CONTACTS, CHATS, CALLS LISTS, COUNTS)
══════════════════════════════════════════════════════════════════════════════
When the evidence is primarily a **list** or **aggregate** (not full message bodies), focus on:

1) **Recurrence patterns** — repeats, top entities, who/what appears most often, re-engagement frequency.
2) **Concentration vs dispersion** — few high-volume counterparts vs many low-touch entries; skew vs even spread.
3) **Time distribution** — bursts, clusters, streaks, gaps, quiet periods; spread across days/hours when timestamps exist.
4) **Activity intensity** — relative volume or rate per bucket/entity using ONLY what the data shows (counts, durations, frequencies).

**ANTI-HALLUCINATION (CRITICAL):** Do NOT invent social, organizational, or relationship interpretations
(e.g. "team coordination", "close collaboration", "professional partnership", "they work together") unless the **evidence explicitly supports** them
(stated roles, project names in content, shared thread labels, org fields, etc.). Prefer neutral forensic phrasing:
"high message frequency", "repeated contact", "bidirectional vs one-sided traffic", "concentrated among N entities".

If the data is only structural (names + counts + times), stay at the **structural/metric** level in **Interpretation / Insight**.

**DATA AVAILABILITY / INVENTORY:** When FORENSIC DATA includes `=== DATA AVAILABILITY ===` or `=== AVAILABLE DATA ===`,
preserve the distinction between **`messages`** (root-level InstantMessage rows; often a small count) and **`chat_messages`**
(thread / app messages; usually the large corpus). Summarize platform or source breakdowns from the evidence when present;
do **not** state that platform or identifier detail is unavailable if those breakdown lines are in the block.
""" + FORENSIC_PACKET_REASONING_SAFEGUARDS + """
══════════════════════════════════════════════════════════════════════════════
FORENSIC QUALITY BAR (APPLIES TO EVERY ANSWER)
══════════════════════════════════════════════════════════════════════════════
1) DIRECT ANSWER / CORE FINDING — pattern, not task
   - Lead with WHAT THE EVIDENCE SHOWS (behavior, structure, timing, relationships)—not with task echo.
   - FORBIDDEN openers: "Here are the…", "The following…", "In response to your query…", "This lists…", restating the user request.
   - The core finding must summarize the investigative pattern (e.g. brief text then rapid shift to calls, clustered activity, one-way vs bidirectional traffic)—never repeat or narrate the assignment.

2) KEY SUPPORTING OBSERVATIONS — depth over listing
   - Prefer analytic dimensions visible in the data (skip any that are absent):
     • clustering in time (same window, bursts, gaps)
     • frequency / volume (how many events; relative density)
     • directionality (who initiates; inbound vs outbound where shown)
     • modality transitions (e.g. text → voice/video; system vs user content)
     • platform or thread context when relevant
   - One bullet may combine related facts; avoid empty inventory-style bullets.

3) INTERPRETATION / INSIGHT
   - Connect observations to meaning: what the pattern may imply for how communication unfolded (cautious wording).
   - If the payload was **listing / aggregation**, keep interpretation tied to **metrics and structure** (recurrence, concentration, time spread, intensity)—not speculative social roles unless explicitly evidenced (see LISTING / AGGREGATION OUTPUT RULES).

4) UNCERTAINTY / LIMITS
   - What this slice does NOT show (e.g. call audio, other platforms, earlier history).
   - If partially relevant evidence exists, distinguish:
     • what is supported now,
     • what is suggestive but unconfirmed,
     • what missing slice would confirm/refute it.

5) SUGGESTED NEXT ACTION — forward motion only
   - The next step must move the investigation DEEPER (same thread/topic, more detail), NARROWER (specific entity/date/platform), or MORE CORRELATED (cross-domain: e.g. chats ↔ calls ↔ locations)—never SIDEWAYS.
   - FORBIDDEN: generic "list all messages" / "show everything" when the user already has a focused slice—unless the data is empty and broader retrieval is the only honest fix.
   - Prefer imperative phrasing: "Run: …" with a concrete deterministic query (e.g. correlate WhatsApp activity with calls for [date range or chat]).
══════════════════════════════════════════════════════════════════════════════
"""

    if tier == "ultra_short":
        return guardrails + """
Use EXACTLY three sections (in this order):

## 1) Direct Answer / Core Finding
- 1–3 sentences: the main **pattern** or conclusion from the evidence (see FORENSIC QUALITY BAR—no task echo).

## 2) Key Supporting Observations & Interpretation
- 2–4 bullets emphasizing clustering, frequency, directionality, and/or text→call (or modality) transitions where visible; then 1 short paragraph of interpretation.

## 3) Uncertainty / Limits & Suggested Next Action
- What cannot be concluded from current evidence (brief).
- **Suggested Next Action:** exactly ONE step that is deeper, narrower, or more correlated—not sideways (see FORENSIC QUALITY BAR).
"""

    if tier == "normal":
        return guardrails + """
Use EXACTLY five sections (in this order):

## 1) Direct Answer / Core Finding
- Short paragraph: **pattern-level** bottom line (what the communication/activity suggests). Never open with task narration or "here are the messages."

## 2) Key Supporting Observations
- 3–6 bullets; each tied to data. Weight: clustering, frequency, directionality, transitions (text↔call), time windows, platform/thread context—when present.

## 3) Interpretation / Insight
- One or two short paragraphs: what the pattern may imply (cautious: "consistent with", "may suggest").
- Do NOT use a subsection titled "Hypotheses".

## 4) Uncertainty / Limits
- Explicit gaps, weak linkage, or what cannot be concluded from this evidence alone.

## 5) Suggested Next Action
- Exactly ONE next step: **deeper**, **narrower**, or **more correlated** (see FORENSIC QUALITY BAR). Name a concrete deterministic query, e.g. "Run: correlate WhatsApp chats with calls for [date/chat]."
"""

    # extended
    return guardrails + """
Use EXACTLY five sections (in this order). This is the expanded analytical layout for large or case-level questions.

## 1) Direct Answer / Core Finding
- Bottom-line **pattern** first (case-level or multi-facet synthesis). No task restatement; no "here is the data you asked for."

## 2) Key Supporting Observations
- 5–10 bullets grouped by theme if helpful; emphasize clustering, frequency, directionality, modality/time transitions, cross-entity contrast—when data supports it.
- Stay evidence-anchored; cite counts, names, times, platforms when present.

## 3) Interpretation / Insight
- Up to three short paragraphs: patterns, relationships, investigative meaning. Neutral, non-accusatory.
- Prefer integrated reasoning over bullet lists labeled "hypotheses".

## 4) Uncertainty / Limits
- Separate supported vs. speculative; weak evidence (e.g. day-level overlap only, missing identity linkage).

## 5) Suggested Next Action
- ONE primary follow-up; optionally up to two sub-bullets as alternates—all must be **deeper**, **narrower**, or **more correlated** (never sideways). Plain text only—no execution.
"""


def _format_investigator_detail_instructions() -> str:
    """
    Same five ## headings as extended, but relaxes compression: narrative depth,
    ### sub-headings, short verbatim evidence excerpts, and walk-throughs when warranted.
    """
    overlay = """
══════════════════════════════════════════════════════════════════════════════
INVESTIGATOR DETAIL MODE (OVERRIDES DEFAULT COMPRESSION RULES)
══════════════════════════════════════════════════════════════════════════════
The user asked for **in detail**, **elaborate**, **walk me through**, or similar. Deliver **depth**, not a minimal outline.

- Keep the **five ## section headings** below **in the same order** (required for scan-ability).
- **Inside** sections 2–4: you MAY use ### sub-headings, multiple paragraphs, small Markdown tables, and **short verbatim excerpts**
  from FORENSIC DATA (block quotes or indented lines) when they add investigative value.
- **Prioritize concrete anchors** from the evidence: timestamps, identifiers, durations, message types, platforms, parties.
- When FORENSIC DATA includes a unified timeline or correlation table, you may **walk through** representative rows;
  do not collapse into a single sentence when more detail is warranted.
- Sections 2 and 3 may be **long**; avoid padding, but do not artificially shorten to satisfy a “compact” habit.
- Do NOT add new **top-level ##** sections beyond the five in the extended template.
- All other rules (evidence grounding, anti-hallucination, LISTING rules) still apply.
══════════════════════════════════════════════════════════════════════════════
"""
    return overlay + format_universal_response_instructions("extended")


def describe_tier_for_logging(tier: str) -> str:
    return {
        "ultra_short": "universal 3-section (compact)",
        "normal": "universal 5-section",
        "extended": "universal 5-section (expanded)",
        "investigator_detail": "universal 5-section (investigator detail / narrative depth)",
        "skip": "alternate template (e.g. pull messages)",
    }.get(tier, tier)
