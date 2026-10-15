#!/usr/bin/env python3
"""Analyze-style queries must route to LLM synthesis, not basic deterministic listing."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.guarantee_class import GUARANTEE_HYBRID, GUARANTEE_STRICT_RETRIEVAL, infer_guarantee_class
from core.query_intent_parser import parse_query_intent, to_canonical_query
from core.query_route import PRIMARY_LLM_SYNTHESIS, decide_query_route


class GuaranteeAnalyzeRoutingTests(unittest.TestCase):
    def test_typo_analzye_still_routes_to_hybrid(self):
        intent = parse_query_intent("analzye whatsapp messages")
        self.assertEqual(intent.get("action"), "analyze")
        route = decide_query_route(
            followup_llm_only=False,
            user_query_original="analzye whatsapp messages",
            canonical_query=to_canonical_query(intent),
            parsed_intent=intent,
            query_plan={},
            has_xml_data=True,
            person_name_extracted=None,
            is_person_investigation=False,
        )
        self.assertTrue(route.get("skip_basic_deterministic"))
        self.assertEqual(route.get("primary"), PRIMARY_LLM_SYNTHESIS)

    def test_typo_nalzye_still_routes_to_hybrid(self):
        intent = parse_query_intent("nalzye whatsapp messages")
        self.assertEqual(intent.get("action"), "analyze")
        route = decide_query_route(
            followup_llm_only=False,
            user_query_original="nalzye whatsapp messages",
            canonical_query=to_canonical_query(intent),
            parsed_intent=intent,
            query_plan={},
            has_xml_data=True,
            person_name_extracted=None,
            is_person_investigation=False,
        )
        self.assertTrue(route.get("skip_basic_deterministic"))
        self.assertEqual(route.get("primary"), PRIMARY_LLM_SYNTHESIS)

    def test_infer_analyze_messages_is_hybrid(self):
        intent = parse_query_intent("analyze whatsapp messages")
        self.assertEqual(intent.get("action"), "analyze")
        gc, reason = infer_guarantee_class(
            followup_llm_only=False,
            parsed_intent=intent,
            query_plan={},
            user_query_original="analyze whatsapp messages",
            canonical_query=to_canonical_query(intent),
            has_xml_data=True,
            person_name_extracted=None,
            is_person_investigation=False,
        )
        self.assertEqual(gc, GUARANTEE_HYBRID, msg=reason)

    def test_decide_route_skips_basic_deterministic_for_analyze(self):
        intent = parse_query_intent("analyze whatsapp messages")
        route = decide_query_route(
            followup_llm_only=False,
            user_query_original="analyze whatsapp messages",
            canonical_query=to_canonical_query(intent),
            parsed_intent=intent,
            query_plan={},
            has_xml_data=True,
            person_name_extracted=None,
            is_person_investigation=False,
        )
        self.assertTrue(route.get("skip_basic_deterministic"))
        self.assertEqual(route.get("primary"), PRIMARY_LLM_SYNTHESIS)

    def test_to_canonical_preserves_analyze_with_limit(self):
        intent = {
            "action": "analyze",
            "domains": ["messages"],
            "platform": "whatsapp",
            "filters": {"limit": 50, "dates": [], "time_window": None},
            "original_query": "analyze 50 whatsapp messages",
        }
        cq = to_canonical_query(intent)
        self.assertTrue(cq.lower().startswith("analyze 50"))
        self.assertIn("whatsapp", cq.lower())

    def test_reconstruct_stays_strict_when_planner_says_reconstruct(self):
        intent = parse_query_intent("analyze whatsapp messages")
        intent["action"] = "analyze"
        gc, _ = infer_guarantee_class(
            followup_llm_only=False,
            parsed_intent=intent,
            query_plan={"intent": "reconstruct"},
            user_query_original="analyze timeline",
            canonical_query="analyze messages",
            has_xml_data=True,
            person_name_extracted=None,
            is_person_investigation=False,
        )
        self.assertEqual(gc, GUARANTEE_STRICT_RETRIEVAL)


if __name__ == "__main__":
    unittest.main()
