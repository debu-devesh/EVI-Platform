#!/usr/bin/env python3
"""
Maps guarantee_class → concrete pipeline flags (skip basic deterministic, person bundle, etc.).

See core/guarantee_class.py for the 3-bucket contract.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from core.guarantee_class import (
    GUARANTEE_FOLLOWUP_ANALYSIS,
    GUARANTEE_HYBRID,
    GUARANTEE_STRICT_RETRIEVAL,
    infer_guarantee_class,
)

# Primary path labels (logged + API metadata)
PRIMARY_DETERMINISTIC_LIST = "deterministic_list"
PRIMARY_LLM_SYNTHESIS = "llm_synthesis"
PRIMARY_HYBRID_PERSON = "hybrid_person"
PRIMARY_FOLLOWUP_ANALYSIS = "followup_analysis"


def decide_query_route(
    *,
    followup_llm_only: bool,
    user_query_original: str,
    canonical_query: str,
    parsed_intent: Dict[str, Any],
    query_plan: Dict[str, Any],
    has_xml_data: bool,
    person_name_extracted: Optional[str],
    is_person_investigation: bool,
) -> Dict[str, Any]:
    """
    Returns:
        guarantee_class, guarantee_reason — top-level bucket
        primary — routing label for logs/UI
        skip_basic_deterministic — run_basic_deterministic_retrieval
        run_person_comprehensive — get_all_communications_for_person hint
        reason — human-readable summary
    """
    gc, gc_reason = infer_guarantee_class(
        followup_llm_only=followup_llm_only,
        parsed_intent=parsed_intent,
        query_plan=query_plan,
        user_query_original=user_query_original,
        canonical_query=canonical_query,
        has_xml_data=has_xml_data,
        person_name_extracted=person_name_extracted,
        is_person_investigation=is_person_investigation,
    )
    base: Dict[str, Any] = {
        "guarantee_class": gc,
        "guarantee_reason": gc_reason,
    }

    if gc == GUARANTEE_FOLLOWUP_ANALYSIS:
        return {
            **base,
            "primary": PRIMARY_FOLLOWUP_ANALYSIS,
            "skip_basic_deterministic": True,
            "run_person_comprehensive": False,
            "reason": f"followup_analysis:{gc_reason}",
        }

    if gc == GUARANTEE_HYBRID:
        if (
            has_xml_data
            and is_person_investigation
            and (person_name_extracted or "").strip()
        ):
            return {
                **base,
                "primary": PRIMARY_HYBRID_PERSON,
                "skip_basic_deterministic": True,
                "run_person_comprehensive": True,
                "reason": f"hybrid_person:{person_name_extracted}",
            }
        return {
            **base,
            "primary": PRIMARY_LLM_SYNTHESIS,
            "skip_basic_deterministic": True,
            "run_person_comprehensive": False,
            "reason": f"hybrid_synthesis:{gc_reason}",
        }

    # GUARANTEE_STRICT_RETRIEVAL (default)
    return {
        **base,
        "primary": PRIMARY_DETERMINISTIC_LIST,
        "skip_basic_deterministic": False,
        "run_person_comprehensive": False,
        "reason": f"strict_retrieval:{gc_reason}",
    }
