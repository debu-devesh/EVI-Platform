#!/usr/bin/env python3
"""
Deterministic correlation operator library (minimal v1).
"""

from __future__ import annotations

from collections import Counter


def filter_by_date(events, date_value):
    if not date_value:
        return events
    d = str(date_value)[:10]
    return [e for e in (events or []) if (e.get("date_key") or "") == d]


def temporal_overlap(events_a, events_b, label_a: str = "series_a", label_b: str = "series_b"):
    dates_a = Counter([e.get("date_key") for e in (events_a or []) if e.get("date_key")])
    dates_b = Counter([e.get("date_key") for e in (events_b or []) if e.get("date_key")])
    overlap = []
    for d in sorted(set(dates_a.keys()) & set(dates_b.keys())):
        overlap.append({
            "date": d,
            "count_a": dates_a[d],
            "count_b": dates_b[d],
            "combined": dates_a[d] + dates_b[d],
            "label_a": label_a,
            "label_b": label_b,
        })
    overlap.sort(key=lambda x: x["combined"], reverse=True)
    return overlap


def same_contact_across_domains(events_by_domain):
    counters = {}
    for d, events in (events_by_domain or {}).items():
        c = Counter()
        for e in events or []:
            label = (e.get("contact_label") or "").strip()
            if label:
                c[label] += 1
        counters[d] = c

    labels = set()
    for _, c in counters.items():
        labels |= set(c.keys())

    rows = []
    for label in labels:
        present_domains = []
        total = 0
        for d, c in counters.items():
            if c.get(label, 0) > 0:
                present_domains.append(d)
                total += c[label]
        if len(present_domains) >= 2:
            rows.append({
                "contact": label,
                "domains": sorted(present_domains),
                "total_mentions": total,
            })
    rows.sort(key=lambda x: x["total_mentions"], reverse=True)
    return rows


def build_v1_correlation_result(plan, events_by_domain):
    domains = plan.get("domains") or []
    result = {
        "intent": "correlation",
        "domains": domains,
        "operators": [],
        "evidence": [],
        "stats": {},
    }

    has_chat_events = "chats" in domains or "messages" in domains

    # calls <-> chats same date
    if "calls" in domains and has_chat_events:
        overlap = temporal_overlap(
            events_by_domain.get("calls"), events_by_domain.get("chats"),
            label_a="call_logs", label_b="chat_messages",
        )
        result["operators"].append("calls_chats_same_date")
        result["stats"]["calls_chats_overlap_days"] = len(overlap)
        result["evidence"].append({
            "type": "calls_chats_same_date",
            "top_dates": overlap[:5],
        })

    # locations <-> chats same date
    if "locations" in domains and has_chat_events:
        overlap = temporal_overlap(
            events_by_domain.get("locations"), events_by_domain.get("chats"),
            label_a="location_events", label_b="chat_messages",
        )
        result["operators"].append("locations_chats_same_date")
        result["stats"]["locations_chats_overlap_days"] = len(overlap)
        result["evidence"].append({
            "type": "locations_chats_same_date",
            "top_dates": overlap[:5],
        })

    # locations <-> calls same date
    if "locations" in domains and "calls" in domains:
        overlap = temporal_overlap(
            events_by_domain.get("locations"), events_by_domain.get("calls"),
            label_a="location_events", label_b="call_logs",
        )
        result["operators"].append("locations_calls_same_date")
        result["stats"]["locations_calls_overlap_days"] = len(overlap)
        result["evidence"].append({
            "type": "locations_calls_same_date",
            "top_dates": overlap[:5],
        })

    # same-contact overlap across domains
    contact_overlap = same_contact_across_domains(events_by_domain)
    result["operators"].append("same_contact_overlap")
    result["stats"]["same_contact_overlap_count"] = len(contact_overlap)
    result["evidence"].append({
        "type": "same_contact_overlap",
        "top_contacts": contact_overlap[:10],
    })

    return result
