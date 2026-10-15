#!/usr/bin/env python3
"""Tests for same-domain cross-platform deterministic planning."""

import unittest

from core.query_intent_parser import parse_query_intent
from core.query_planner import build_query_plan


class TestQueryPlannerCrossPlatform(unittest.TestCase):
    def test_cross_reference_same_domain_two_platforms_is_correlation(self):
        intent = parse_query_intent("co-relate whatsapp messages with line messages")
        plan = build_query_plan(intent, followup_mode_active=False, has_base=False)
        self.assertEqual(plan.get("intent"), "correlation")
        self.assertEqual(plan.get("mode"), "deterministic")
        self.assertIn("same_domain_cross_platform", plan.get("operators") or [])
        self.assertIn("platforms", plan.get("filters") or {})
        plats = (plan.get("filters") or {}).get("platforms") or []
        self.assertGreaterEqual(len(plats), 2)


if __name__ == "__main__":
    unittest.main()
