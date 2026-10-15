#!/usr/bin/env python3
"""
Normalize forensic domain records into a shared event schema for correlation.
"""

from __future__ import annotations

import re

# Prefer embedded YYYY-MM-DD so prefixes like metadata text do not break day bucketing.
_ISO_DATE = re.compile(r"\b(19|20)\d{2}-\d{2}-\d{2}\b")


def _date_key(ts: str) -> str:
    if not ts:
        return ""
    s = str(ts)
    m = _ISO_DATE.search(s)
    if m:
        return m.group(0)
    if len(s) >= 10 and s[4] == "-" and s[7] == "-" and s[:4].isdigit():
        return s[:10]
    if len(s) >= 10:
        return s[:10]
    return ""


def _event_id(domain: str, idx: int) -> str:
    return f"{domain}:{idx}"


def normalize_calls(call_rows):
    events = []
    for i, r in enumerate(call_rows or []):
        ts = r.get("timestamp") or ""
        events.append({
            "event_id": _event_id("calls", i),
            "domain": "calls",
            "platform": r.get("platform") or r.get("source_db") or "Unknown",
            "timestamp": ts,
            "date_key": _date_key(ts),
            "contact_label": (r.get("from_number") or "Unknown"),
            "counterparty_label": (r.get("to_number") or "Unknown"),
            "direction": r.get("call_type") or "",
            "conversation_id": "",
            "thread_id": "",
            "message_text": "",
            "call_type": r.get("call_type") or "",
            "file_name": "",
            "location_lat": None,
            "location_lon": None,
            "raw_source_reference": r.get("source_table") or "call_logs",
        })
    return events


def normalize_chat_messages(chat_rows):
    events = []
    for i, r in enumerate(chat_rows or []):
        ts = r.get("timestamp") or ""
        events.append({
            "event_id": _event_id("chats", i),
            "domain": "chats",
            "platform": r.get("platform") or "Unknown",
            "timestamp": ts,
            "date_key": _date_key(ts),
            "contact_label": (r.get("from_participant") or "Unknown"),
            "counterparty_label": (r.get("to_participant") or "Unknown"),
            "direction": "",
            "conversation_id": r.get("chat_id") or r.get("chat_name") or "",
            "thread_id": r.get("chat_id") or "",
            "message_text": r.get("text_content") or "",
            "call_type": "",
            "file_name": "",
            "location_lat": None,
            "location_lon": None,
            "raw_source_reference": r.get("source_table") or "chat_messages",
        })
    return events


def normalize_locations(location_rows):
    events = []
    for i, r in enumerate(location_rows or []):
        ts = r.get("timestamp") or ""
        events.append({
            "event_id": _event_id("locations", i),
            "domain": "locations",
            "platform": r.get("platform") or r.get("source_db") or "Unknown",
            "timestamp": ts,
            "date_key": _date_key(ts),
            "contact_label": "",
            "counterparty_label": "",
            "direction": "",
            "conversation_id": "",
            "thread_id": "",
            "message_text": "",
            "call_type": "",
            "file_name": "",
            "location_lat": r.get("latitude"),
            "location_lon": r.get("longitude"),
            "raw_source_reference": r.get("source_table") or "locations",
        })
    return events


def normalize_contacts(contact_rows):
    events = []
    for i, r in enumerate(contact_rows or []):
        label = r.get("name") or r.get("phone") or r.get("email") or "Unknown"
        events.append({
            "event_id": _event_id("contacts", i),
            "domain": "contacts",
            "platform": r.get("platform") or r.get("source_db") or "Unknown",
            "timestamp": "",
            "date_key": "",
            "contact_label": label,
            "counterparty_label": "",
            "direction": "",
            "conversation_id": "",
            "thread_id": "",
            "message_text": "",
            "call_type": "",
            "file_name": "",
            "location_lat": None,
            "location_lon": None,
            "raw_source_reference": r.get("source_table") or "contacts",
        })
    return events
