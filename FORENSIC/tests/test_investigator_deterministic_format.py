#!/usr/bin/env python3
"""Tests for investigator deterministic formatting."""

import unittest

from utils.investigator_deterministic_format import (
    build_markdown_table,
    format_correlation_report,
    format_timeline_investigator,
)


class TestInvestigatorFormat(unittest.TestCase):
    def test_correlation_report_has_core_sections(self):
        result = {
            "domains": ["chats", "locations"],
            "evidence": [
                {
                    "type": "locations_chats_same_date",
                    "top_dates": [
                        {"date": "2020-10-03", "count_a": 1, "count_b": 4, "combined": 5}
                    ],
                },
                {"type": "same_contact_overlap", "top_contacts": []},
            ],
            "stats": {},
            "meta": {
                "domain_event_counts": {"chats": 4, "locations": 1},
                "chat_thread_counts": {"chats": 1},
                "requested_platform": "telegram",
                "query_constraint_match": True,
                "effective_date_filter": "",
                "evidence_samples": {
                    "paired_analysis": [
                        "[2020-10-03T12:00:00+00:00] lat=1.0 lon=2.0",
                        "[2020-10-03T12:00:00+00:00] A → B | hello",
                    ]
                },
            },
        }
        text = format_correlation_report(result)
        self.assertIn("# Correlation", text)
        self.assertIn("**Summary.**", text)
        self.assertIn("**Counts**", text)
        self.assertIn("**Records**", text)
        self.assertIn("lat=1.0", text)
        self.assertIn("hello", text)
        self.assertNotIn("Suggested next", text)
        self.assertNotIn("causation", text.lower())

    def test_build_markdown_table_basic(self):
        md = build_markdown_table(
            ["Time", "Sender", "Message"],
            [["15:11:56", "+1", "Hello | world"]],
        )
        self.assertIn("| Time |", md)
        self.assertIn("| --- |", md)
        self.assertIn("Hello \\| world", md)

    def test_format_timeline_chat_only_table(self):
        text = format_timeline_investigator(
            day="2020-10-03",
            platform="textnow",
            timeline_events=[
                {
                    "kind": "chat",
                    "timestamp": "2020-10-03T15:11:56.000+00:00",
                    "from_participant": "A",
                    "to_participant": "B",
                    "text_content": "Hi",
                }
            ],
            total_events=1,
            want_chats=True,
            want_locs=True,
        )
        self.assertIn("# Timeline · 2020-10-03 · textnow", text)
        self.assertIn("### Messages", text)
        self.assertIn("| Sender |", text)
        self.assertIn("| 15:11:56 |", text)

    def test_format_timeline_merged_chat_and_location(self):
        text = format_timeline_investigator(
            day="2020-10-03",
            platform="app",
            timeline_events=[
                {
                    "kind": "chat",
                    "timestamp": "2020-10-03T12:00:00+00:00",
                    "from_participant": "X",
                    "to_participant": "Y",
                    "text_content": "ok",
                },
                {
                    "kind": "location",
                    "timestamp": "2020-10-03T12:05:00+00:00",
                    "latitude": 1.0,
                    "longitude": 2.0,
                },
            ],
            total_events=2,
            want_chats=True,
            want_locs=True,
        )
        self.assertIn("### Merged timeline", text)
        self.assertIn("| Type |", text)
        self.assertIn("Chat", text)
        self.assertIn("Location", text)


if __name__ == "__main__":
    unittest.main()
