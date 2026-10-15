#!/usr/bin/env python3
"""DAL must not treat 'ig' inside 'insights' as Instagram (mis-filters LINE queries)."""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.cellebrite_data_access_layer import CellebriteDataAccessLayer
from core.evidence_scope import compute_evidence_scope
from core.query_intent_parser import parse_query_intent


class DalPlatformSubstringTests(unittest.TestCase):
    def test_snapchat_google_photos_locations_does_not_force_chat_domain(self):
        q = "analyze same locations across google photos,snapchat and google maps"
        intent = parse_query_intent(q)
        self.assertIn("locations", (intent.get("domains") or []), msg=intent)
        self.assertNotIn("chats", (intent.get("domains") or []), msg=intent)
        self.assertNotIn("media", (intent.get("domains") or []), msg=intent)

        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            layer = CellebriteDataAccessLayer(path)
            dal_intent = layer._analyze_query_intent(q)
            self.assertIn("locations", (dal_intent.get("data_types") or []), msg=dal_intent)
            self.assertNotIn("chats", (dal_intent.get("data_types") or []), msg=dal_intent)
            self.assertNotIn("files", (dal_intent.get("data_types") or []), msg=dal_intent)
        finally:
            os.unlink(path)

    def test_line_insights_query_filters_line_not_instagram(self):
        q = "analyze Line messages and generate some insights"
        intent = parse_query_intent(q)
        self.assertIn("line", (intent.get("platforms") or []), msg=intent)
        self.assertNotIn(
            "instagram",
            (intent.get("platforms") or []),
            msg="substring 'ig' in insights must not add instagram",
        )

        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            conn = sqlite3.connect(path)
            conn.execute(
                """
                CREATE TABLE chat_messages (
                    id INTEGER PRIMARY KEY,
                    chat_id TEXT,
                    chat_name TEXT,
                    from_participant TEXT,
                    to_participant TEXT,
                    text_content TEXT,
                    timestamp TEXT,
                    platform TEXT,
                    message_type TEXT,
                    is_deleted INTEGER DEFAULT 0,
                    attachments TEXT
                )
                """
            )
            conn.executemany(
                """
                INSERT INTO chat_messages (
                    chat_id, chat_name, from_participant, to_participant,
                    text_content, timestamp, platform, message_type, is_deleted
                ) VALUES (?,?,?,?,?,?,?,?,?)
                """,
                [
                    ("c1", "t", "a", "b", "hi", "2020-01-01T00:00:00Z", "LINE", "text", 0),
                    ("c2", "u", "a", "b", "yo", "2020-01-02T00:00:00Z", "Instagram", "text", 0),
                ],
            )
            conn.commit()
            conn.close()

            scope = compute_evidence_scope(q, intent, None)
            self.assertEqual(scope.mode, "platform_isolated")
            self.assertEqual(scope.platforms, ("line",))

            layer = CellebriteDataAccessLayer(path)
            out = layer.get_relevant_data_for_llm(q, max_items=50, evidence_scope=scope)
            self.assertIn("LINE", out)
            self.assertNotIn("Instagram", out)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
