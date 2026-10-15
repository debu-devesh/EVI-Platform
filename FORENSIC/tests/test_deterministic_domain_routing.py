"""Routing: platform names like 'LINE chat' must not imply a messages facet."""

from __future__ import annotations

import unittest


class TestPlatformChatNotMessagesFacet(unittest.TestCase):
    def test_location_from_line_chat_is_locations_only(self):
        import web_interface as wi  # noqa: WPS433

        q = "location from line chat"
        self.assertEqual(wi._collect_forensic_domain_mentions(q), {"locations"})
        self.assertEqual(wi._detect_basic_deterministic_domain(q), "locations")

    def test_locations_and_messages_still_multibundle(self):
        import web_interface as wi  # noqa: WPS433

        q = "locations and messages from line"
        m = wi._collect_forensic_domain_mentions(q)
        self.assertIn("locations", m)
        self.assertIn("messages", m)
        self.assertEqual(wi._detect_basic_deterministic_domain(q), "forensic_multibundle")

    def test_parse_intent_line_chat_not_extra_chats_domain(self):
        from core.query_intent_parser import parse_query_intent, to_canonical_query

        q = "can you find locations from line chat"
        intent = parse_query_intent(q)
        self.assertEqual(intent.get("domains"), ["locations"])
        self.assertNotIn("chats", intent.get("domains") or [])
        self.assertEqual(to_canonical_query(intent), "show locations from line")

    def test_locations_google_photos_snapchat_maps_not_multibundle(self):
        import web_interface as wi  # noqa: WPS433

        q = "find locations of google Photos ,snapchat and google maps"
        mentions = wi._collect_forensic_domain_mentions(q)
        self.assertEqual(mentions, {"locations"})
        self.assertEqual(wi._detect_basic_deterministic_domain(q), "locations")


if __name__ == "__main__":
    unittest.main()
