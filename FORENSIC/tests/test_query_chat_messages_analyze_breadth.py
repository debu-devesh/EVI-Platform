"""Regression: analyze + platform must not apply content LIKE on 'analyze' / platform name."""
import os
import sqlite3
import tempfile

from core.cellebrite_data_access_layer import CellebriteDataAccessLayer


def test_analyze_whatsapp_messages_matches_show_breadth():
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
                is_deleted INTEGER DEFAULT 0
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
                (
                    "c1",
                    "Thread",
                    "A",
                    "B",
                    "Here I am!",
                    "2020-10-03T22:45:17Z",
                    "WhatsApp",
                    "text",
                    0,
                ),
                (
                    "c1",
                    "Thread",
                    "A",
                    "B",
                    "On WhatsApp now.",
                    "2020-09-23T14:09:03Z",
                    "WhatsApp",
                    "text",
                    0,
                ),
            ],
        )
        conn.commit()
        conn.close()

        dal = CellebriteDataAccessLayer(path)
        analyze_rows = dal.query_chat_messages(
            "analyze whatsapp messages", limit=100, platform_filter="WhatsApp"
        )
        show_rows = dal.query_chat_messages(
            "show whatsapp messages", limit=100, platform_filter="WhatsApp"
        )
        assert len(analyze_rows) == len(show_rows) == 2
    finally:
        os.unlink(path)


if __name__ == "__main__":
    test_analyze_whatsapp_messages_matches_show_breadth()
    print("ok")
