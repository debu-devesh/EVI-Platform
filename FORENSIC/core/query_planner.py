#!/usr/bin/env python3
"""
Query planning layer: convert parsed intent into executable plan.
"""

from __future__ import annotations


def build_query_plan(parsed_intent: dict, followup_mode_active: bool = False, has_base: bool = False) -> dict:
    action = parsed_intent.get("action") or "retrieve"
    domains = list(parsed_intent.get("domains") or [])
    filters = dict(parsed_intent.get("filters") or {})
    # Carry platform into plan filters so deterministic correlation can enforce it.
    if parsed_intent.get("platform"):
        filters["platform"] = parsed_intent.get("platform")
    plats = list(parsed_intent.get("platforms") or [])
    if plats:
        filters["platforms"] = plats
    # Intent parser stores ISO dates under filters["dates"]; correlation runner uses filters["date"].
    _dates = filters.get("dates") or []
    if _dates and not filters.get("date"):
        filters["date"] = str(_dates[0])[:10]
    analysis_type = parsed_intent.get("analysis_type")
    confidence = parsed_intent.get("confidence", 0.0)
    special = parsed_intent.get("special")

    mode = "deterministic"
    intent = "retrieve"
    operators = []
    granularity = "day"
    needs_explanation = False
    fallback_reason = None

    if special == "ambiguous_contact_overlap":
        intent = "clarify"
        mode = "deterministic"
        operators = []
        fallback_reason = "ambiguous_contact_overlap_need_two_platforms"
    elif special == "contact_platform_intersection":
        if len(plats) >= 2:
            intent = "contact_intersection"
            mode = "deterministic"
            operators = ["normalized_contact_key_overlap"]
        else:
            intent = "clarify"
            mode = "deterministic"
            operators = []
            fallback_reason = "contact_intersection_insufficient_platforms"
    elif action == "reconstruct":
        intent = "reconstruct"
        mode = "deterministic"
        operators = ["merge_chronological_timeline"]
        needs_explanation = False
    elif action == "cross_reference":
        # Deterministic cross-reference can run in two modes:
        # 1) Multi-domain correlation (classic): >=2 domains
        # 2) Same-domain cross-platform comparison: 1 domain + >=2 platforms
        same_domain_cross_platform = len(domains) == 1 and len(plats) >= 2
        if len(domains) < 2 and not same_domain_cross_platform:
            if followup_mode_active and has_base:
                intent = "analysis"
                mode = "llm"
                needs_explanation = True
            else:
                intent = "retrieve"
                mode = "deterministic"
                needs_explanation = False
        else:
            intent = "correlation"
            mode = "deterministic"
            operators.extend(["temporal_overlap", "entity_overlap"])
            if same_domain_cross_platform:
                operators.append("same_domain_cross_platform")
            needs_explanation = True
    elif action == "analyze":
        intent = "analysis"
        # If domains are structured and confidence good, use hybrid (deterministic evidence + llm explain).
        if domains and confidence >= 0.6:
            mode = "hybrid"
            operators.extend(["temporal_overlap", "entity_overlap"])
            needs_explanation = True
        else:
            mode = "llm"
    elif action == "count":
        intent = "count"
        mode = "deterministic"
    else:
        intent = "retrieve"
        mode = "deterministic"

    return {
        "mode": mode,
        "intent": intent,
        "domains": domains,
        "operators": operators,
        "filters": filters,
        "granularity": granularity,
        "analysis_type": analysis_type,
        "anchors": {
            "from_followup_base": bool(followup_mode_active and has_base),
        },
        "confidence": confidence,
        "needs_explanation": needs_explanation,
        "fallback_reason": fallback_reason,
        "special": special,
    }
