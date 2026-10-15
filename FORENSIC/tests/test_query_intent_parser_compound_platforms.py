#!/usr/bin/env python3
"""Regression tests for compact platform+domain token parsing."""

import unittest

from core.query_intent_parser import parse_query_intent


class TestQueryIntentParserCompoundPlatforms(unittest.TestCase):
    def test_compound_line_messages_detects_platform_and_domain(self):
        intent = parse_query_intent("find LINEmessages on 2020-09-22")
        self.assertEqual(intent.get("platform"), "line")
        self.assertIn("messages", intent.get("domains") or [])
        self.assertIn("2020-09-22", (intent.get("filters") or {}).get("dates") or [])

    def test_timeline_does_not_false_match_line_platform(self):
        intent = parse_query_intent("show timeline for 2020-10-03")
        self.assertNotEqual(intent.get("platform"), "line")

    def test_snap_chat_alias_detected_as_snapchat(self):
        intent = parse_query_intent("find locations for snap chat and google maps")
        plats = intent.get("platforms") or []
        self.assertIn("snapchat", plats)
        self.assertIn("google maps", plats)

    def test_snapchat_name_does_not_inject_chats_domain(self):
        intent = parse_query_intent("analyze same locations across google photos,snapchat and google maps")
        domains = intent.get("domains") or []
        self.assertIn("locations", domains)
        self.assertNotIn("chats", domains)

    def test_correlation_common_typo_maps_to_cross_reference_action(self):
        intent = parse_query_intent("show correaltion between whatsapp messages and calls on 2020-10-03")
        self.assertEqual(intent.get("action"), "cross_reference")


if __name__ == "__main__":
    unittest.main()
