"""Tests for evidence scoping (Phase 1)."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from core.evidence_scope import EvidenceScope, assess_evidence_sufficiency, compute_evidence_scope
from core.cellebrite_data_access_layer import CellebriteDataAccessLayer


class TestComputeEvidenceScope(unittest.TestCase):
    def test_native_analyze_platform_isolated_no_preamble(self):
        s = compute_evidence_scope(
            "analyze native messages",
            {
                "domains": (),
                "platforms": ("native messages",),
                "action": "analyze",
            },
            None,
        )
        self.assertEqual(s.mode, "platform_isolated")
        self.assertFalse(s.include_global_preamble)
        self.assertIn("native messages", s.platforms)

    def test_what_platforms_case_overview(self):
        s = compute_evidence_scope(
            "what messaging apps are on this phone",
            {"domains": (), "platforms": (), "action": "retrieve"},
            None,
        )
        self.assertEqual(s.mode, "case_overview")
        self.assertTrue(s.include_global_preamble)

    def test_what_data_available_case_overview(self):
        s = compute_evidence_scope(
            "what data is available in this extraction",
            {"domains": (), "platforms": (), "action": "retrieve"},
            None,
        )
        self.assertEqual(s.mode, "case_overview")
        self.assertTrue(s.include_global_preamble)

    def test_correlate_cross_domain_no_global_preamble(self):
        s = compute_evidence_scope(
            "correlate whatsapp messages with calls",
            {
                "domains": ("messages", "calls"),
                "platforms": ("whatsapp",),
                "action": "cross_reference",
            },
            None,
        )
        self.assertEqual(s.mode, "cross_domain_scoped")
        self.assertFalse(s.include_global_preamble)

    def test_assess_sufficiency(self):
        ok, n = assess_evidence_sufficiency("=== A ===\n" + "\n".join(f"row {i} data here" for i in range(8)))
        self.assertTrue(ok)
        short_ok, short_n = assess_evidence_sufficiency("hi")
        self.assertFalse(short_ok)


class TestDalGating(unittest.TestCase):
    def test_get_chat_data_for_display_includes_chat_platform(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "t.db")
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute(
                "CREATE TABLE chats (chat_id TEXT, chat_name TEXT, platform TEXT, participants TEXT, last_message_time TEXT)"
            )
            cur.execute(
                "CREATE TABLE chat_messages (id INTEGER PRIMARY KEY, chat_id TEXT, chat_name TEXT, platform TEXT, text_content TEXT, timestamp TEXT, from_participant TEXT, to_participant TEXT, message_type TEXT, attachments TEXT)"
            )
            cur.execute(
                "INSERT INTO chats VALUES ('wa1','WA Thread','WhatsApp','[]','2020-10-03T10:00:00+00:00')"
            )
            cur.execute(
                "INSERT INTO chats VALUES ('ig1','IG Thread','Instagram','[]','2020-10-03T11:00:00+00:00')"
            )
            cur.execute(
                "INSERT INTO chat_messages VALUES (1,'wa1','WA Thread','WhatsApp','hello','2020-10-03T10:00:00+00:00','A','B','text',NULL)"
            )
            cur.execute(
                "INSERT INTO chat_messages VALUES (2,'ig1','IG Thread','Instagram','hi','2020-10-03T11:00:00+00:00','C','D','text',NULL)"
            )
            conn.commit()
            conn.close()

            layer = CellebriteDataAccessLayer(db_path)
            out = layer.get_chat_data_for_display(platform=None, chat_id=None, limit=20)
            chats = out.get("chats") or []
            self.assertTrue(chats)
            self.assertTrue(all("platform" in c for c in chats))
            plats = {str(c.get("platform") or "").lower() for c in chats}
            self.assertIn("whatsapp", plats)
            self.assertIn("instagram", plats)

    def test_whatsapp_messages_use_chat_messages_not_sms_table(self):
        """Compound 'whatsappmessages' must not read SMS `messages` table (wrong source)."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "t.db")
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute(
                "CREATE TABLE messages (id INTEGER PRIMARY KEY, from_number TEXT, to_number TEXT, "
                "text_content TEXT, timestamp TEXT, source TEXT)"
            )
            cur.execute(
                "INSERT INTO messages VALUES (1,NULL,NULL,NULL,NULL,'Native Messages')"
            )
            cur.execute(
                "CREATE TABLE chats (chat_id TEXT, chat_name TEXT, platform TEXT, participants TEXT, last_message_time TEXT)"
            )
            cur.execute(
                "INSERT INTO chats VALUES ('w1','Group','WhatsApp','[]','2021-06-01')"
            )
            cur.execute(
                "CREATE TABLE chat_messages (id INTEGER PRIMARY KEY, chat_id TEXT, chat_name TEXT, "
                "platform TEXT, text_content TEXT, timestamp TEXT, from_participant TEXT, "
                "to_participant TEXT, message_type TEXT, attachments TEXT)"
            )
            cur.execute(
                "INSERT INTO chat_messages VALUES (1,'w1','Group','WhatsApp','secret','2021-06-01',"
                "'Alice','Bob','text',NULL)"
            )
            conn.commit()
            conn.close()

            layer = CellebriteDataAccessLayer(db_path)
            scope = compute_evidence_scope(
                "analyze whatsappmessages suspicious patterns",
                {"domains": ("messages",), "platforms": ("whatsapp",)},
                None,
            )
            out = layer.get_relevant_data_for_llm(
                "analyze whatsappmessages suspicious patterns",
                max_items=30,
                evidence_scope=scope,
            )
            self.assertIn("=== CHAT MESSAGES", out)
            self.assertIn("WhatsApp", out)
            self.assertIn("secret", out)
            self.assertNotIn("Source: Native Messages", out)

    def test_platform_isolated_skips_classification_banner(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "t.db")
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute(
                "CREATE TABLE messages (id INTEGER PRIMARY KEY, from_number TEXT, to_number TEXT, text_content TEXT, timestamp TEXT, source TEXT)"
            )
            cur.execute("CREATE TABLE chats (chat_id TEXT, chat_name TEXT, platform TEXT, participants TEXT, last_message_time TEXT)")
            cur.execute(
                "CREATE TABLE chat_messages (id INTEGER PRIMARY KEY, chat_id TEXT, chat_name TEXT, platform TEXT, text_content TEXT, timestamp TEXT, from_participant TEXT, to_participant TEXT, message_type TEXT)"
            )
            cur.execute(
                "INSERT INTO chats VALUES ('1','n','Native Messaging','[]','2020-01-01')",
            )
            cur.execute(
                "INSERT INTO chat_messages (chat_id, chat_name, platform, text_content, timestamp, from_participant, to_participant, message_type) VALUES ('1','n','Native Messaging','hello','2020-01-01','a','b','text')",
            )
            conn.commit()
            conn.close()

            layer = CellebriteDataAccessLayer(db_path)
            scope = compute_evidence_scope(
                "show native messages",
                {"domains": ("messages", "chats"), "platforms": ("native messages",)},
                None,
            )
            out = layer.get_relevant_data_for_llm(
                "show native messages",
                max_items=20,
                evidence_scope=scope,
            )
            self.assertNotIn("=== PLATFORM CLASSIFICATION ===", out)
            self.assertNotIn("PLATFORM CLASSIFICATION ===", out)

    def test_cross_domain_day_bundle_injects_calendar_slice(self):
        """cross_domain_scoped + ISO date must pull chat_messages/calls/locations/messages for that day."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "t.db")
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute(
                "CREATE TABLE chat_messages (id INTEGER PRIMARY KEY, chat_id TEXT, from_participant TEXT, "
                "to_participant TEXT, text_content TEXT, timestamp TEXT, platform TEXT)"
            )
            cur.execute(
                "INSERT INTO chat_messages VALUES (1,'c1','A','B','meet at noon','2020-10-03T12:00:00+00:00','WhatsApp')"
            )
            cur.execute(
                "CREATE TABLE call_logs (id INTEGER PRIMARY KEY, from_number TEXT, to_number TEXT, "
                "timestamp TEXT, duration INTEGER, call_type TEXT, source_table TEXT)"
            )
            cur.execute(
                "INSERT INTO call_logs VALUES (1,'+1','+2','2020-10-03T15:00:00+00:00',60,'Outgoing','Call')"
            )
            cur.execute(
                "CREATE TABLE locations (id INTEGER PRIMARY KEY, latitude REAL, longitude REAL, timestamp TEXT, source_table TEXT)"
            )
            cur.execute(
                "INSERT INTO locations VALUES (1,35.0,-78.0,'2020-10-03T16:00:00+00:00','WhatsApp')"
            )
            cur.execute(
                "CREATE TABLE messages (id INTEGER PRIMARY KEY, from_number TEXT, to_number TEXT, "
                "text_content TEXT, timestamp TEXT, source TEXT)"
            )
            # Simulate placeholder-style timestamps that include brackets.
            cur.execute(
                "INSERT INTO messages VALUES (1,'+111','+222','hello native','[2020-10-03T12:34:56+00:00]','Native Messages')"
            )
            conn.commit()
            conn.close()

            layer = CellebriteDataAccessLayer(db_path)
            scope = EvidenceScope(mode="cross_domain_scoped", domains=(), platforms=())
            out = layer.get_relevant_data_for_llm(
                "suspicious communication across platforms for 2020-10-03",
                max_items=30,
                evidence_scope=scope,
            )
            self.assertIn("CROSS-DOMAIN DAY BUNDLE", out)
            self.assertIn("meet at noon", out)
            self.assertIn("WhatsApp", out)
            self.assertIn("call_logs rows=1", out)
            self.assertIn("locations rows=1", out)
            self.assertIn("messages (SMS/native table) rows=1", out)
            self.assertIn("hello native", out)


if __name__ == "__main__":
    unittest.main()
