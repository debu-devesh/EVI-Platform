#!/usr/bin/env python3
"""
Guarantee class (3-bucket model) — top-level routing contract.

strict_retrieval   — facts from DB / deterministic operators; LLM does not own facts.
followup_analysis — bounded to selected evidence only (follow-up / Analyze this result).
hybrid            — scoped retrieval + synthesis (person-of-interest, case questions, interpretation).
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple

GUARANTEE_STRICT_RETRIEVAL = "strict_retrieval"
GUARANTEE_FOLLOWUP_ANALYSIS = "followup_analysis"
GUARANTEE_HYBRID = "hybrid"


def _qlower(q: Optional[str]) -> str:
    return (q or "").strip().lower()


def _has_explicit_raw_pull(q: str) -> bool:
    """User explicitly asked for rows / counts from the DB (deterministic-friendly)."""
    if not q:
        return False
    patterns = [
        r"\bpull\s+messages?\b",
        r"\blist\s+all\s+(messages|chats|calls|contacts)\b",
        r"\bshow\s+all\s+(messages|chats|calls)\b",
        r"\b(get|fetch|retrieve|display)\s+(messages|chats|calls)\b",
        # "Find all LINE messages …" — platform word sits between "all" and "messages".
        r"\bfind\s+all\s+\S+\s+(messages|chats|conversations)\b",
        # "Find WhatsApp messages …" / "find telegram chats …" (platform word between verb and facet)
        r"\bfind\s+\S+\s+(messages|chats|conversations)\b",
        # "Find messages …" / "find chats …"
        r"\bfind\s+(all\s+)?(the\s+)?(messages|chats|conversations)\b",
        r"\bfind\s+(messages|chats|calls|contacts)\b",
        r"\bcount\s+(messages|chats|calls|contacts)\b",
        r"\bhow\s+many\s+(messages|chats|calls|contacts)\b",
        r"\bwhich\s+contacts\s+appear\b",
        r"\b(state|list)\s+the\s+names\b",
    ]
    return any(re.search(p, q) for p in patterns)


def _analysis_primary_without_raw_dump(q: str) -> bool:
    """Interpretation / narrative / assessment, not a raw table dump."""
    if not q:
        return False
    if re.match(
        r"^\s*(explain|summarize|summarise|interpret|assess|describe)\b",
        q,
    ):
        if not _has_explicit_raw_pull(q):
            return True
    if re.match(
        r"^\s*(what\s+are\s+the\s+limitations|what\s+does\s+this\s+mean|why\s+might|how\s+would\s+you\s+interpret)\b",
        q,
    ):
        return True
    if re.match(
        r"^\s*what\s+is\s+the\s+(device|model|os|phone|carrier|imei|imsi|msisdn|android\s+id)\b",
        q,
    ):
        if not _has_explicit_raw_pull(q):
            return True
    if re.match(r"^\s*(give|provide)\s+(me\s+)?(the\s+)?(device|model|os)\b", q):
        if not _has_explicit_raw_pull(q):
            return True
    if re.search(r"\btimeline\s+of\s+(interactions|communications|activity)\b", q):
        if not re.search(r"\b(show|list|pull|display)\s+messages\b", q):
            return True
    return False


def infer_guarantee_class(
    *,
    followup_llm_only: bool,
    parsed_intent: Dict[str, Any],
    query_plan: Dict[str, Any],
    user_query_original: str,
    canonical_query: str,
    has_xml_data: bool,
    person_name_extracted: Optional[str],
    is_person_investigation: bool,
) -> Tuple[str, str]:
    """
    Returns (guarantee_class, reason) for logging and routing.
    """
    if followup_llm_only:
        return GUARANTEE_FOLLOWUP_ANALYSIS, "followup_mode_active"

    q = _qlower(user_query_original) or _qlower(canonical_query)
    plan_intent = (query_plan.get("intent") or "").lower()
    action = (parsed_intent.get("action") or "retrieve").lower()
    domains = list(parsed_intent.get("domains") or [])

    # Person-of-interest: retrieve bundle + synthesize (hybrid)
    if (
        has_xml_data
        and is_person_investigation
        and (person_name_extracted or "").strip()
    ):
        return GUARANTEE_HYBRID, f"person_of_interest:{person_name_extracted.strip()}"

    # Interpretation / synthesis — always LLM on forensic packet, not basic deterministic list-only.
    # (Skip only when planner owns a numeric/reconstruct path that must stay factual-first.)
    if action == "analyze" and plan_intent not in ("reconstruct", "count", "contact_intersection"):
        return GUARANTEE_HYBRID, "parsed_action_analyze"

    # Planner-owned deterministic operations (facts only)
    if plan_intent in ("reconstruct", "correlation", "contact_intersection", "count"):
        return GUARANTEE_STRICT_RETRIEVAL, f"planner_intent={plan_intent}"
    if plan_intent == "clarify":
        return GUARANTEE_STRICT_RETRIEVAL, "planner_clarify"

    if action in ("count", "reconstruct"):
        return GUARANTEE_STRICT_RETRIEVAL, f"parsed_action={action}"
    if action == "cross_reference" and len(domains) >= 2:
        return GUARANTEE_STRICT_RETRIEVAL, "cross_reference_multi_domain"

    # Interpretation without explicit pull → hybrid (LLM on forensic context)
    if _analysis_primary_without_raw_dump(q) and not _has_explicit_raw_pull(q):
        return GUARANTEE_HYBRID, "analysis_primary_no_explicit_pull"

    # Default: listing / show / count style → strict retrieval
    return GUARANTEE_STRICT_RETRIEVAL, "default_listing_or_count"
