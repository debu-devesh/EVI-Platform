#!/usr/bin/env python3
"""
Lightweight fact vs analysis scores for routing hints.

Merges with query_plan / guarantee_class — does not replace them.
Scores are 0–10; route_hint biases hybrid vs deterministic-heavy vs analysis-heavy.

`apply_route_score_bias` runs after decide_query_route + feedback: nudges execution only
when safe (no follow-up lock, ASCII query, no feedback override, not person-hybrid).
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from core.guarantee_class import (
    GUARANTEE_FOLLOWUP_ANALYSIS,
    GUARANTEE_HYBRID,
    GUARANTEE_STRICT_RETRIEVAL,
)
from core.query_route import (
    PRIMARY_DETERMINISTIC_LIST,
    PRIMARY_HYBRID_PERSON,
    PRIMARY_LLM_SYNTHESIS,
)

logger = logging.getLogger(__name__)

# Fact-seeking signals (deterministic-friendly)
_FACT_VERBS = (
    "show",
    "list",
    "find",
    "count",
    "retrieve",
    "give me",
    "pull",
    "display",
    "correlate",
    "cross-reference",
    "cross reference",
    "compare",
    "overlap",
    "timeline",
    "chronolog",
    "reconstruct",
)

_ANALYSIS_VERBS = (
    "explain",
    "summarize",
    "summarise",
    "interpret",
    "what does",
    "what do",
    "why ",
    "suggest",
    "suspicious",
    "relationship",
    "pattern",
    "meaning",
    "insight",
    "analyze",
    "analysis",
    "behavior",
    "imply",
    "seem",
)

_HYBRID_MARKERS = (
    " and explain",
    " and summarize",
    " and interpret",
    " then explain",
    " what does this suggest",
    " what it means",
)


def _clamp(n: float) -> int:
    return max(0, min(10, int(round(n))))


def compute_route_scores(
    query: str,
    parsed_intent: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Returns:
        det_score, analysis_score (0–10)
        route_hint: 'deterministic' | 'llm' | 'hybrid'
        expects_records, expects_meaning (booleans, coarse)
    """
    q = (query or "").strip().lower()
    pi = parsed_intent or {}
    det = 3.0
    ana = 2.0

    for w in _FACT_VERBS:
        if w in q:
            det += 1.2
    if re.search(r"\bget\b", q) or re.search(r"\bfetch\b", q):
        det += 1.0
    for w in _ANALYSIS_VERBS:
        if w in q:
            ana += 1.3
    for m in _HYBRID_MARKERS:
        if m in q:
            det += 1.0
            ana += 1.5

    if re.search(r"\b(19|20)\d{2}-\d{2}-\d{2}\b", query or ""):
        det += 1.5
    filt = pi.get("filters") or {}
    if filt.get("dates"):
        det += 1.0

    plats = pi.get("platforms") or []
    if pi.get("platform") or plats:
        det += 1.0

    doms = pi.get("domains") or []
    if doms:
        det += 0.8

    act = (pi.get("action") or "").lower()
    if act in ("cross_reference", "reconstruct", "count"):
        det += 1.5
    if act == "analyze":
        ana += 2.0

    if len(q) < 12 and not re.search(r"\d{4}-\d{2}-\d{2}", q):
        ana += 0.5

    det_s = _clamp(det)
    ana_s = _clamp(ana)

    if det_s >= 6 and ana_s >= 6:
        hint = "hybrid"
    elif det_s >= 5 and ana_s >= 5 and (det_s + ana_s) >= 12:
        hint = "hybrid"
    elif det_s >= ana_s + 3:
        hint = "deterministic"
    elif ana_s >= det_s + 3:
        hint = "llm"
    elif det_s >= 6:
        hint = "deterministic"
    elif ana_s >= 6:
        hint = "llm"
    else:
        hint = "hybrid"

    return {
        "det_score": det_s,
        "analysis_score": ana_s,
        "route_hint": hint,
        "expects_records": det_s >= 5,
        "expects_meaning": ana_s >= 5,
    }


def apply_route_score_bias(
    base_route: Dict[str, Any],
    route_scores: Dict[str, Any],
    *,
    followup_llm_only: bool,
    user_query: str,
    feedback_bias_applied: bool = False,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Merge score hints onto an existing route from decide_query_route + apply_feedback.

    Does not replace guarantee logic wholesale — only nudges when no hard override applies.
    Returns (merged_route, meta) where meta documents what changed.
    """
    meta: Dict[str, Any] = {
        "score_bias_applied": False,
        "phase": None,
        "reason": None,
    }
    if not base_route:
        return base_route, meta

    if followup_llm_only:
        meta["reason"] = "followup_llm_only"
        return dict(base_route), meta

    if feedback_bias_applied:
        meta["reason"] = "feedback_bias_preserved"
        return dict(base_route), meta

    q = user_query or ""
    if any(ord(ch) > 127 for ch in q):
        meta["reason"] = "non_ascii_query"
        return dict(base_route), meta

    gc = base_route.get("guarantee_class")
    primary = base_route.get("primary")
    reason_b = str(base_route.get("reason") or "")

    if gc == GUARANTEE_FOLLOWUP_ANALYSIS:
        meta["reason"] = "guarantee_followup_analysis"
        return dict(base_route), meta

    if primary == PRIMARY_HYBRID_PERSON or "person_of_interest" in reason_b:
        meta["reason"] = "person_hybrid_preserved"
        return dict(base_route), meta

    det_s = int(route_scores.get("det_score") or 0)
    ana_s = int(route_scores.get("analysis_score") or 0)
    hint = str(route_scores.get("route_hint") or "")

    out = dict(base_route)
    pure_env = os.environ.get("EVI_PURE_DETERMINISTIC", "").lower() in ("1", "true", "yes")

    # --- Phase 1: both signals strong → hybrid (evidence packet + LLM), skip raw basic list path ---
    if (
        hint == "hybrid"
        and det_s >= 6
        and ana_s >= 6
        and gc == GUARANTEE_STRICT_RETRIEVAL
    ):
        out["guarantee_class"] = GUARANTEE_HYBRID
        out["primary"] = PRIMARY_LLM_SYNTHESIS
        out["skip_basic_deterministic"] = True
        out["run_person_comprehensive"] = False
        out["reason"] = f"{reason_b}|score_bias:both_high_hybrid"
        meta["score_bias_applied"] = True
        meta["phase"] = "1_both_high_hybrid"
        meta["reason"] = "both_high_hybrid"
        logger.info(
            "ROUTE_SCORE_BIAS phase=1 both_high det=%s ana=%s -> hybrid synthesis",
            det_s,
            ana_s,
        )
        return out, meta

    # --- Phase 2: fact-heavy → prefer strict retrieval (basic deterministic list first) ---
    if (
        hint == "deterministic"
        and det_s >= 7
        and ana_s <= 4
        and gc == GUARANTEE_HYBRID
        and primary == PRIMARY_LLM_SYNTHESIS
    ):
        out["guarantee_class"] = GUARANTEE_STRICT_RETRIEVAL
        out["primary"] = PRIMARY_DETERMINISTIC_LIST
        out["skip_basic_deterministic"] = False
        out["run_person_comprehensive"] = False
        out["reason"] = f"{reason_b}|score_bias:prefer_deterministic_first"
        meta["score_bias_applied"] = True
        meta["phase"] = "2_prefer_deterministic"
        meta["reason"] = "prefer_deterministic_first"
        logger.info(
            "ROUTE_SCORE_BIAS phase=2 det-strong det=%s ana=%s -> strict_retrieval",
            det_s,
            ana_s,
        )
        return out, meta

    # --- Case C: analysis-forward — LLM-led path with evidence packet, skip basic list ---
    if (
        hint == "llm"
        and ana_s >= 6
        and det_s <= 5
        and gc == GUARANTEE_STRICT_RETRIEVAL
    ):
        out["guarantee_class"] = GUARANTEE_HYBRID
        out["primary"] = PRIMARY_LLM_SYNTHESIS
        out["skip_basic_deterministic"] = True
        out["run_person_comprehensive"] = False
        out["reason"] = f"{reason_b}|score_bias:analysis_forward"
        meta["score_bias_applied"] = True
        meta["phase"] = "C_analysis_forward"
        meta["reason"] = "analysis_forward"
        logger.info(
            "ROUTE_SCORE_BIAS case=C analysis-forward ana=%s det=%s -> hybrid synthesis",
            ana_s,
            det_s,
        )
        return out, meta

    # --- Phase 3 (telemetry + optional future hook): pure-deterministic preference ---
    if (
        pure_env
        and hint == "deterministic"
        and det_s >= 8
        and ana_s <= 3
        and gc == GUARANTEE_STRICT_RETRIEVAL
    ):
        out["score_prefers_pure_deterministic"] = True
        out["reason"] = f"{reason_b}|score_bias:pure_det_hint"
        meta["score_bias_applied"] = True
        meta["phase"] = "3_pure_det_env"
        meta["reason"] = "pure_deterministic_hint"
        logger.info(
            "ROUTE_SCORE_BIAS phase=3 EVI_PURE_DETERMINISTIC det=%s ana=%s (hint only)",
            det_s,
            ana_s,
        )
        return out, meta

    meta["reason"] = "no_bias_match"
    return dict(base_route), meta
