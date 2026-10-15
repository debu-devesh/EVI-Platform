#!/usr/bin/env python3
"""Regression / unit tests for pipeline query feedback (not LLM fine-tuning)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure FORENSIC (parent of tests/) is on path when run as script
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.guarantee_class import GUARANTEE_STRICT_RETRIEVAL
from core.query_feedback import (
    ALL_FAILURE_TYPES,
    ANSWER_BAD,
    ANSWER_GOOD,
    QueryFeedbackRecord,
    append_feedback_record,
    apply_feedback_to_query_route,
    find_similar_corrected_feedback,
    invalidate_feedback_cache,
    normalize_query,
    query_similarity,
    run_feedback_regression_checks,
)
from core.query_route import PRIMARY_DETERMINISTIC_LIST, PRIMARY_LLM_SYNTHESIS, decide_query_route


class QueryFeedbackLearningTests(unittest.TestCase):
    def test_normalize_query_stable(self):
        self.assertEqual(normalize_query("  Hello,   WORLD!!  "), "hello world")

    def test_similarity_self_is_one(self):
        q = "correlate whatsapp with calls on 2024-01-02"
        self.assertGreaterEqual(query_similarity(q, q), 0.99)

    def test_failure_taxonomy_complete(self):
        self.assertIn("wrong_bucket", ALL_FAILURE_TYPES)
        self.assertGreaterEqual(len(ALL_FAILURE_TYPES), 8)

    def test_policy_biases_correlate_seed(self):
        base = decide_query_route(
            followup_llm_only=False,
            user_query_original="correlate whatsapp with call logs for overlap",
            canonical_query="correlate whatsapp with call logs for overlap",
            parsed_intent={},
            query_plan={},
            has_xml_data=True,
            person_name_extracted=None,
            is_person_investigation=False,
        )
        routed, meta = apply_feedback_to_query_route(
            base,
            raw_query="correlate whatsapp with call logs for overlap",
            parsed_intent={},
        )
        self.assertTrue(meta.get("policy_hits"), "expected seed policy to match")
        self.assertEqual(routed.get("guarantee_class"), GUARANTEE_STRICT_RETRIEVAL)

    def test_similar_correction_overrides_route(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "fb.jsonl"
            rec = QueryFeedbackRecord(
                id="test-id-001",
                ts_iso="2099-01-01T00:00:00Z",
                raw_query="unique query xyzabc123 for feedback test",
                normalized_query=normalize_query("unique query xyzabc123 for feedback test"),
                parsed_intent={"action": "retrieve"},
                guarantee_class=GUARANTEE_STRICT_RETRIEVAL,
                route_primary=PRIMARY_DETERMINISTIC_LIST,
                packet_type="general",
                llm_used=True,
                answer_quality=ANSWER_BAD,
                failure_type="wrong_bucket",
                corrected_expected_route_primary=PRIMARY_LLM_SYNTHESIS,
                corrected_expected_packet=None,
                corrected_notes="unit test",
            )
            append_feedback_record(rec, path=p)
            invalidate_feedback_cache()

            base = decide_query_route(
                followup_llm_only=False,
                user_query_original=rec.raw_query,
                canonical_query=rec.raw_query,
                parsed_intent={},
                query_plan={},
                has_xml_data=True,
                person_name_extracted=None,
                is_person_investigation=False,
            )
            self.assertNotEqual(base.get("primary"), PRIMARY_LLM_SYNTHESIS)

            routed, meta = apply_feedback_to_query_route(base, raw_query=rec.raw_query, parsed_intent={})
            best, sc = find_similar_corrected_feedback(rec.raw_query, path=p)
            self.assertIsNotNone(best)
            self.assertGreaterEqual(sc, 0.72)
            self.assertTrue(meta.get("feedback_bias_applied"))
            self.assertEqual(routed.get("primary"), PRIMARY_LLM_SYNTHESIS)

    def test_regression_harness_empty_store(self):
        failures = run_feedback_regression_checks(path=Path("/nonexistent/feedback.jsonl"))
        self.assertEqual(failures, [])

    def test_append_writes_jsonl(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "q.jsonl"
            rec = QueryFeedbackRecord(
                id="r2",
                ts_iso="2099-01-01T00:00:00Z",
                raw_query="sample",
                normalized_query="sample",
                answer_quality=ANSWER_GOOD,
            )
            append_feedback_record(rec, path=p)
            self.assertTrue(p.read_text(encoding="utf-8").strip())
            row = json.loads(p.read_text(encoding="utf-8").strip().splitlines()[0])
            self.assertEqual(row["id"], "r2")


if __name__ == "__main__":
    unittest.main()
