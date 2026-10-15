#!/usr/bin/env python3
"""Tests for query_route_scores."""

import unittest

from core.guarantee_class import GUARANTEE_HYBRID, GUARANTEE_STRICT_RETRIEVAL
from core.query_route import PRIMARY_DETERMINISTIC_LIST, PRIMARY_LLM_SYNTHESIS
from core.query_route_scores import apply_route_score_bias, compute_route_scores


class TestQueryRouteScores(unittest.TestCase):
    def test_pure_listing_high_det(self):
        q = "show whatsapp chats on 2020-10-03"
        r = compute_route_scores(
            q,
            {"action": "retrieve", "domains": ["chats"], "platform": "whatsapp", "filters": {"dates": ["2020-10-03"]}},
        )
        self.assertGreaterEqual(r["det_score"], 6)
        self.assertIn(r["route_hint"], ("deterministic", "hybrid"))

    def test_pure_explain_high_analysis(self):
        q = "what does this conversation suggest about their relationship"
        r = compute_route_scores(q, {"action": "analyze", "domains": []})
        self.assertTrue(r["analysis_score"] >= r["det_score"] or r["route_hint"] == "llm")

    def test_correlate_and_explain_hybrid(self):
        q = "correlate whatsapp with calls on 2020-10-03 and explain what it suggests"
        r = compute_route_scores(
            q,
            {
                "action": "cross_reference",
                "domains": ["chats", "calls"],
                "platform": "whatsapp",
                "filters": {"dates": ["2020-10-03"]},
            },
        )
        self.assertEqual(r["route_hint"], "hybrid")
        self.assertTrue(r["expects_records"] and r["expects_meaning"])

    def test_cross_reference_boosts_det(self):
        q = "cross-reference locations and chats from telegram"
        r = compute_route_scores(q, {"action": "cross_reference", "domains": ["locations", "chats"]})
        self.assertGreaterEqual(r["det_score"], 5)


class TestApplyRouteScoreBias(unittest.TestCase):
    def test_phase1_strict_to_hybrid_when_both_scores_high(self):
        base = {
            "guarantee_class": GUARANTEE_STRICT_RETRIEVAL,
            "primary": PRIMARY_DETERMINISTIC_LIST,
            "skip_basic_deterministic": False,
            "run_person_comprehensive": False,
            "reason": "strict_retrieval:default_listing_or_count",
        }
        scores = {"det_score": 8, "analysis_score": 7, "route_hint": "hybrid"}
        out, meta = apply_route_score_bias(
            base,
            scores,
            followup_llm_only=False,
            user_query="correlate whatsapp with calls on 2020-10-03 and explain",
            feedback_bias_applied=False,
        )
        self.assertTrue(meta.get("score_bias_applied"))
        self.assertEqual(out["guarantee_class"], GUARANTEE_HYBRID)
        self.assertEqual(out["primary"], PRIMARY_LLM_SYNTHESIS)
        self.assertTrue(out["skip_basic_deterministic"])

    def test_feedback_override_skips_bias(self):
        base = {
            "guarantee_class": GUARANTEE_STRICT_RETRIEVAL,
            "primary": PRIMARY_DETERMINISTIC_LIST,
            "skip_basic_deterministic": False,
            "reason": "x",
        }
        scores = {"det_score": 9, "analysis_score": 9, "route_hint": "hybrid"}
        out, meta = apply_route_score_bias(
            base,
            scores,
            followup_llm_only=False,
            user_query="show all",
            feedback_bias_applied=True,
        )
        self.assertFalse(meta.get("score_bias_applied"))
        self.assertEqual(out["primary"], PRIMARY_DETERMINISTIC_LIST)

    def test_followup_skips_bias(self):
        base = {
            "guarantee_class": GUARANTEE_STRICT_RETRIEVAL,
            "primary": PRIMARY_DETERMINISTIC_LIST,
            "reason": "x",
        }
        out, meta = apply_route_score_bias(
            base,
            {"det_score": 9, "analysis_score": 9, "route_hint": "hybrid"},
            followup_llm_only=True,
            user_query="explain",
        )
        self.assertFalse(meta.get("score_bias_applied"))


if __name__ == "__main__":
    unittest.main()
