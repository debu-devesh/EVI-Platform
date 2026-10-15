#!/usr/bin/env python3
"""
Pipeline learning from investigator feedback (not model fine-tuning).

Stores query outcomes, failure taxonomies, and optional corrections; biases future
routing / packet selection toward corrected behavior when similar queries recur.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from core.guarantee_class import (
    GUARANTEE_FOLLOWUP_ANALYSIS,
    GUARANTEE_HYBRID,
    GUARANTEE_STRICT_RETRIEVAL,
)
from core.query_route import (
    PRIMARY_DETERMINISTIC_LIST,
    PRIMARY_FOLLOWUP_ANALYSIS,
    PRIMARY_HYBRID_PERSON,
    PRIMARY_LLM_SYNTHESIS,
)

logger = logging.getLogger(__name__)

# --- Failure taxonomy (structured labels for review + regression metadata) ---

FAILURE_WRONG_BUCKET = "wrong_bucket"
FAILURE_WRONG_PACKET_TYPE = "wrong_packet_type"
FAILURE_BROAD_FALLBACK_BLOB = "broad_fallback_blob"
FAILURE_DETERMINISTIC_QUERY_SENT_TO_LLM = "deterministic_query_sent_to_llm"
FAILURE_SPECULATIVE_INTERPRETATION = "speculative_interpretation"
FAILURE_ALIAS_DUPLICATION = "alias_duplication"
FAILURE_CONTRADICTION_WITH_DETERMINISTIC_RESULT = "contradiction_with_deterministic_result"
FAILURE_POOR_SCOPE_DEFAULT = "poor_scope_default"

ALL_FAILURE_TYPES: Tuple[str, ...] = (
    FAILURE_WRONG_BUCKET,
    FAILURE_WRONG_PACKET_TYPE,
    FAILURE_BROAD_FALLBACK_BLOB,
    FAILURE_DETERMINISTIC_QUERY_SENT_TO_LLM,
    FAILURE_SPECULATIVE_INTERPRETATION,
    FAILURE_ALIAS_DUPLICATION,
    FAILURE_CONTRADICTION_WITH_DETERMINISTIC_RESULT,
    FAILURE_POOR_SCOPE_DEFAULT,
)

ANSWER_GOOD = "good"
ANSWER_BAD = "bad"


def _forensic_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_feedback_path() -> Path:
    return Path(os.environ.get("EVI_QUERY_FEEDBACK_PATH", str(_forensic_root() / "data" / "query_feedback.jsonl")))


def default_policy_memory_path() -> Path:
    return Path(os.environ.get("EVI_QUERY_POLICY_MEMORY_PATH", str(_forensic_root() / "data" / "query_policy_memory.json")))


# --- Normalization & similarity ---

_WS_RE = re.compile(r"\s+")
_PUNCT_RE = re.compile(r"[^\w\s@.+:/-]")


def normalize_query(text: str) -> str:
    """Stable key for dedupe / similarity (not semantic canonicalization)."""
    if not text:
        return ""
    s = text.strip().lower()
    s = _PUNCT_RE.sub(" ", s)
    s = _WS_RE.sub(" ", s).strip()
    return s


def token_jaccard(a: str, b: str) -> float:
    ta = set(normalize_query(a).split())
    tb = set(normalize_query(b).split())
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / float(len(ta | tb))


def query_similarity(a: str, b: str) -> float:
    """Blend token overlap + sequence ratio for short forensic queries."""
    a_n, b_n = normalize_query(a), normalize_query(b)
    if not a_n or not b_n:
        return 0.0
    j = token_jaccard(a_n, b_n)
    r = SequenceMatcher(None, a_n, b_n).ratio()
    return 0.55 * j + 0.45 * r


# --- Record ---


@dataclass
class QueryFeedbackRecord:
    """One reviewed query outcome (append-only JSONL)."""

    id: str
    ts_iso: str
    raw_query: str
    normalized_query: str
    parsed_intent: Dict[str, Any] = field(default_factory=dict)
    guarantee_class: Optional[str] = None
    route_primary: Optional[str] = None
    packet_type: Optional[str] = None
    llm_used: Optional[bool] = None
    answer_quality: str = ANSWER_GOOD
    failure_type: Optional[str] = None
    corrected_expected_guarantee_class: Optional[str] = None
    corrected_expected_route_primary: Optional[str] = None
    corrected_expected_packet: Optional[str] = None
    corrected_notes: Optional[str] = None
    # Optional replay context for regression harness (minimal)
    replay_context: Dict[str, Any] = field(default_factory=dict)
    # Provenance
    source: str = "api"
    policy_rule_hits: List[str] = field(default_factory=list)

    def to_json_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    @staticmethod
    def from_json_dict(d: Dict[str, Any]) -> "QueryFeedbackRecord":
        return QueryFeedbackRecord(
            id=str(d.get("id") or uuid.uuid4()),
            ts_iso=str(d.get("ts_iso") or ""),
            raw_query=str(d.get("raw_query") or ""),
            normalized_query=str(d.get("normalized_query") or normalize_query(d.get("raw_query") or "")),
            parsed_intent=dict(d.get("parsed_intent") or {}),
            guarantee_class=d.get("guarantee_class"),
            route_primary=d.get("route_primary") or d.get("route_decision"),
            packet_type=d.get("packet_type"),
            llm_used=d.get("llm_used"),
            answer_quality=str(d.get("answer_quality") or ANSWER_GOOD),
            failure_type=d.get("failure_type"),
            corrected_expected_guarantee_class=d.get("corrected_expected_guarantee_class"),
            corrected_expected_route_primary=d.get("corrected_expected_route_primary"),
            corrected_expected_packet=d.get("corrected_expected_packet"),
            corrected_notes=d.get("corrected_notes"),
            replay_context=dict(d.get("replay_context") or {}),
            source=str(d.get("source") or "import"),
            policy_rule_hits=list(d.get("policy_rule_hits") or []),
        )


_store_lock = threading.Lock()
_cached_records: Optional[List[QueryFeedbackRecord]] = None
_cached_mtime: float = 0.0


def _load_jsonl(path: Path) -> List[QueryFeedbackRecord]:
    global _cached_records, _cached_mtime
    if not path.exists():
        return []
    try:
        mtime = path.stat().st_mtime
    except OSError:
        mtime = 0.0
    if _cached_records is not None and mtime == _cached_mtime:
        return _cached_records
    rows: List[QueryFeedbackRecord] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(QueryFeedbackRecord.from_json_dict(json.loads(line)))
            except Exception as ex:
                logger.warning("query_feedback: skip bad jsonl line: %s", ex)
    _cached_records = rows
    _cached_mtime = mtime
    return rows


def invalidate_feedback_cache() -> None:
    global _cached_records, _cached_mtime
    _cached_records = None
    _cached_mtime = 0.0


def append_feedback_record(rec: QueryFeedbackRecord, path: Optional[Path] = None) -> Path:
    p = path or default_feedback_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(rec.to_json_dict(), ensure_ascii=False) + "\n"
    with _store_lock:
        with p.open("a", encoding="utf-8") as f:
            f.write(line)
        invalidate_feedback_cache()
    try:
        merge_correction_into_policy_memory(rec)
    except Exception as ex:
        logger.warning("policy memory merge failed: %s", ex)
    return p


def iter_feedback_records(path: Optional[Path] = None) -> Iterator[QueryFeedbackRecord]:
    yield from _load_jsonl(path or default_feedback_path())


# --- Route patching ---

_VALID_PRIMARIES = frozenset({
    PRIMARY_DETERMINISTIC_LIST,
    PRIMARY_LLM_SYNTHESIS,
    PRIMARY_HYBRID_PERSON,
    PRIMARY_FOLLOWUP_ANALYSIS,
})

_VALID_GC = frozenset({
    GUARANTEE_STRICT_RETRIEVAL,
    GUARANTEE_HYBRID,
    GUARANTEE_FOLLOWUP_ANALYSIS,
})


def _reconcile_route_flags(primary: str) -> Dict[str, Any]:
    if primary == PRIMARY_FOLLOWUP_ANALYSIS:
        return {"skip_basic_deterministic": True, "run_person_comprehensive": False}
    if primary == PRIMARY_HYBRID_PERSON:
        return {"skip_basic_deterministic": True, "run_person_comprehensive": True}
    if primary == PRIMARY_LLM_SYNTHESIS:
        return {"skip_basic_deterministic": True, "run_person_comprehensive": False}
    return {"skip_basic_deterministic": False, "run_person_comprehensive": False}


def patch_query_route(
    base_route: Dict[str, Any],
    *,
    guarantee_class: Optional[str] = None,
    route_primary: Optional[str] = None,
    reason_suffix: str = "feedback",
) -> Dict[str, Any]:
    """Apply optional GC / primary overrides; keeps other keys from base_route."""
    out = dict(base_route)
    if guarantee_class and guarantee_class in _VALID_GC:
        out["guarantee_class"] = guarantee_class
        if guarantee_class == GUARANTEE_FOLLOWUP_ANALYSIS:
            out["primary"] = PRIMARY_FOLLOWUP_ANALYSIS
            out.update(_reconcile_route_flags(PRIMARY_FOLLOWUP_ANALYSIS))
    if route_primary and route_primary in _VALID_PRIMARIES:
        out["primary"] = route_primary
        out.update(_reconcile_route_flags(route_primary))
    prev = out.get("reason") or ""
    out["reason"] = f"{prev}|{reason_suffix}".strip("|")
    return out


# --- Policy memory (lightweight keyword / condition rules) ---

DEFAULT_POLICY_RULES: List[Dict[str, Any]] = [
    {
        "id": "seed_correlate_app_calls_no_date",
        "if_all": ["correlate", "call"],
        "if_any": ["whatsapp", "telegram", "signal", "app"],
        "unless_any": ["[20"],  # bracketed ISO date in query
        "bias": {
            "prefer_packet": "correlation",
            "prefer_guarantee": GUARANTEE_STRICT_RETRIEVAL,
            "prefer_primary": PRIMARY_DETERMINISTIC_LIST,
            "notes": "Cross-domain correlate → correlation packet + strict retrieval list path",
        },
    },
    {
        "id": "seed_timeline_person_year",
        "if_all": ["timeline"],
        "if_any": ["20"],
        "bias": {"prefer_packet": "person_timeline"},
    },
    {
        "id": "seed_tell_me_more_person",
        "if_any": ["tell me more", "more about", "who is", "background on"],
        "unless_any": ["pull messages", "list all"],
        "bias": {"prefer_packet": "person_summary"},
    },
    {
        "id": "seed_followup_summarize",
        "if_any": ["followup", "follow up", "summarize this", "analyze this result"],
        "bias": {"prefer_packet": "followup"},
    },
]


def _policy_path() -> Path:
    return default_policy_memory_path()


def load_policy_memory() -> Dict[str, Any]:
    p = _policy_path()
    if not p.exists():
        return {"version": 1, "rules": list(DEFAULT_POLICY_RULES)}
    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or "rules" not in data:
            return {"version": 1, "rules": list(DEFAULT_POLICY_RULES)}
        # Merge defaults that are missing ids (idempotent seed)
        existing_ids = {r.get("id") for r in data.get("rules", []) if isinstance(r, dict)}
        for seed in DEFAULT_POLICY_RULES:
            if seed["id"] not in existing_ids:
                data.setdefault("rules", []).append(dict(seed))
        return data
    except Exception as ex:
        logger.warning("load_policy_memory failed: %s", ex)
        return {"version": 1, "rules": list(DEFAULT_POLICY_RULES)}


def save_policy_memory(data: Dict[str, Any]) -> None:
    p = _policy_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    tmp.replace(p)


def merge_correction_into_policy_memory(rec: QueryFeedbackRecord) -> None:
    """When a bad answer includes corrections, add a narrow similarity rule (best-effort)."""
    if rec.answer_quality != ANSWER_BAD:
        return
    if not rec.corrected_expected_route_primary and not rec.corrected_expected_packet:
        return
    data = load_policy_memory()
    rules: List[Dict[str, Any]] = list(data.get("rules") or [])
    rid = f"learned_{rec.id[:12]}"
    if any(r.get("id") == rid for r in rules):
        return
    nq = rec.normalized_query or normalize_query(rec.raw_query)
    toks = [t for t in nq.split() if len(t) > 2][:12]
    rule = {
        "id": rid,
        "learned_from_feedback_id": rec.id,
        "if_all": toks[:5] if len(toks) >= 3 else toks,
        "bias": {},
    }
    if rec.corrected_expected_packet:
        rule["bias"]["prefer_packet"] = rec.corrected_expected_packet
    if rec.corrected_expected_route_primary:
        rule["bias"]["prefer_primary"] = rec.corrected_expected_route_primary
    if rec.corrected_expected_guarantee_class:
        rule["bias"]["prefer_guarantee"] = rec.corrected_expected_guarantee_class
    rules.append(rule)
    data["rules"] = rules
    save_policy_memory(data)


def _match_policy_rules(normalized_query: str, rules: List[Dict[str, Any]]) -> Tuple[List[str], Dict[str, Any]]:
    hits: List[str] = []
    merged: Dict[str, Any] = {}
    q = normalized_query
    ql = q.split()
    ql_set = set(ql)
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        ok = True
        for w in rule.get("if_all") or []:
            if w not in q:
                ok = False
                break
        if not ok:
            continue
        if rule.get("if_any"):
            if not any(x in q for x in rule["if_any"]):
                continue
        elif rule.get("if_all"):
            pass
        for w in rule.get("unless_any") or []:
            if w in q:
                ok = False
                break
        if not ok:
            continue
        uall = rule.get("unless_all") or []
        if uall and all(u in ql_set for u in uall):
            continue
        rid = rule.get("id", "?")
        hits.append(str(rid))
        bias = rule.get("bias") or {}
        merged.update({k: v for k, v in bias.items() if v is not None})
    return hits, merged


# --- Similar-query lookup ---

SIMILARITY_THRESHOLD = 0.72


def find_similar_corrected_feedback(
    raw_query: str,
    *,
    path: Optional[Path] = None,
    min_score: float = SIMILARITY_THRESHOLD,
) -> Tuple[Optional[QueryFeedbackRecord], float]:
    """Best past bad review with corrections, by normalized similarity."""
    best: Optional[QueryFeedbackRecord] = None
    best_score = 0.0
    nq = normalize_query(raw_query)
    for rec in iter_feedback_records(path):
        if rec.answer_quality != ANSWER_BAD:
            continue
        if not (rec.corrected_expected_route_primary or rec.corrected_expected_packet or rec.corrected_expected_guarantee_class):
            continue
        cand = rec.normalized_query or normalize_query(rec.raw_query)
        sc = query_similarity(nq, cand)
        if sc > best_score:
            best_score = sc
            best = rec
    if best is None or best_score < min_score:
        return None, best_score
    return best, best_score


# --- Public integration: route + packet ---


def apply_feedback_to_query_route(
    base_route: Dict[str, Any],
    *,
    raw_query: str,
    parsed_intent: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    After decide_query_route(), optionally bias toward policy + similar corrections.

    Returns (route, meta) where meta includes what was applied (for logging / SSE).
    """
    meta: Dict[str, Any] = {"feedback_bias_applied": False, "policy_hits": [], "similar_feedback_id": None, "similarity": None}
    nq = normalize_query(raw_query)
    policy = load_policy_memory()
    hits, bias = _match_policy_rules(nq, list(policy.get("rules") or []))
    meta["policy_hits"] = hits

    route = dict(base_route)
    applied = False

    pg = bias.get("prefer_guarantee")
    pp = bias.get("prefer_primary")
    if pg in _VALID_GC:
        route = patch_query_route(
            route,
            guarantee_class=str(pg),
            route_primary=str(pp) if pp in _VALID_PRIMARIES else None,
            reason_suffix="policy_memory",
        )
        applied = True
    elif pp in _VALID_PRIMARIES:
        route = patch_query_route(
            route,
            route_primary=str(pp),
            reason_suffix="policy_memory",
        )
        applied = True

    sim_rec, sim_sc = find_similar_corrected_feedback(raw_query)
    meta["similarity"] = sim_sc
    if sim_rec and sim_sc >= SIMILARITY_THRESHOLD:
        meta["similar_feedback_id"] = sim_rec.id
        if sim_rec.corrected_expected_guarantee_class or sim_rec.corrected_expected_route_primary:
            route = patch_query_route(
                route,
                guarantee_class=sim_rec.corrected_expected_guarantee_class,
                route_primary=sim_rec.corrected_expected_route_primary,
                reason_suffix=f"similar_feedback:{sim_rec.id[:8]}",
            )
            applied = True

    if applied:
        meta["feedback_bias_applied"] = True
    return route, meta


def apply_feedback_to_packet_type(
    base_packet: str,
    *,
    raw_query: str,
) -> Tuple[str, Dict[str, Any]]:
    """After infer_llm_packet_type(), apply policy + similar correction packet hints."""
    meta: Dict[str, Any] = {"packet_feedback_applied": False, "policy_hits": [], "similar_feedback_id": None}
    nq = normalize_query(raw_query)
    policy = load_policy_memory()
    hits, bias = _match_policy_rules(nq, list(policy.get("rules") or []))
    meta["policy_hits"] = hits

    pkt = base_packet
    if bias.get("prefer_packet"):
        pkt = str(bias["prefer_packet"])
        meta["packet_feedback_applied"] = True

    sim_rec, sim_sc = find_similar_corrected_feedback(raw_query)
    if sim_rec and sim_sc >= SIMILARITY_THRESHOLD and sim_rec.corrected_expected_packet:
        meta["similar_feedback_id"] = sim_rec.id
        pkt = sim_rec.corrected_expected_packet
        meta["packet_feedback_applied"] = True
        meta["similarity"] = sim_sc

    return pkt, meta


def build_feedback_record_from_pipeline(
    *,
    raw_query: str,
    parsed_intent: Dict[str, Any],
    query_route: Dict[str, Any],
    packet_type: str,
    llm_used: bool,
    answer_quality: str = ANSWER_GOOD,
    failure_type: Optional[str] = None,
    corrected_expected_guarantee_class: Optional[str] = None,
    corrected_expected_route_primary: Optional[str] = None,
    corrected_expected_packet: Optional[str] = None,
    corrected_notes: Optional[str] = None,
    replay_context: Optional[Dict[str, Any]] = None,
) -> QueryFeedbackRecord:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return QueryFeedbackRecord(
        id=str(uuid.uuid4()),
        ts_iso=now,
        raw_query=raw_query,
        normalized_query=normalize_query(raw_query),
        parsed_intent=dict(parsed_intent or {}),
        guarantee_class=query_route.get("guarantee_class"),
        route_primary=query_route.get("primary"),
        packet_type=packet_type,
        llm_used=llm_used,
        answer_quality=answer_quality,
        failure_type=failure_type,
        corrected_expected_guarantee_class=corrected_expected_guarantee_class,
        corrected_expected_route_primary=corrected_expected_route_primary,
        corrected_expected_packet=corrected_expected_packet,
        corrected_notes=corrected_notes,
        replay_context=dict(replay_context or {}),
        source="api",
    )


def regression_cases(path: Optional[Path] = None) -> List[QueryFeedbackRecord]:
    """All bad + corrected rows are regression candidates."""
    out: List[QueryFeedbackRecord] = []
    for rec in iter_feedback_records(path):
        if rec.answer_quality != ANSWER_BAD:
            continue
        if not (rec.corrected_expected_route_primary or rec.corrected_expected_packet or rec.corrected_expected_guarantee_class):
            continue
        out.append(rec)
    return out


def run_feedback_regression_checks(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """
    Replay stored corrections against the live pipeline helpers.

    For each regression case, checks that similarity-based routing/packet hints match
    corrected_expected_* when applied on top of a deliberately wrong base route.
    Returns a list of failure dicts (empty if all pass).
    """
    from core.query_route import decide_query_route

    failures: List[Dict[str, Any]] = []
    for rec in regression_cases(path):
        ctx = dict(rec.replay_context or {})
        try:
            base_route = decide_query_route(
                followup_llm_only=bool(ctx.get("followup_llm_only", False)),
                user_query_original=rec.raw_query,
                canonical_query=str(ctx.get("canonical_query") or rec.raw_query),
                parsed_intent=dict(rec.parsed_intent or {}),
                query_plan=dict(ctx.get("query_plan") or {}),
                has_xml_data=bool(ctx.get("has_xml_data", True)),
                person_name_extracted=ctx.get("person_name_extracted"),
                is_person_investigation=bool(ctx.get("is_person_investigation", False)),
            )
            routed, _ = apply_feedback_to_query_route(base_route, raw_query=rec.raw_query, parsed_intent=rec.parsed_intent or {})
            pkt_base = "general"
            pkt, _ = apply_feedback_to_packet_type(pkt_base, raw_query=rec.raw_query)
        except Exception as ex:
            failures.append({"id": rec.id, "raw_query": rec.raw_query, "phase": "replay", "error": str(ex)})
            continue

        if rec.corrected_expected_guarantee_class and routed.get("guarantee_class") != rec.corrected_expected_guarantee_class:
            failures.append(
                {
                    "id": rec.id,
                    "raw_query": rec.raw_query,
                    "field": "guarantee_class",
                    "expected": rec.corrected_expected_guarantee_class,
                    "got": routed.get("guarantee_class"),
                }
            )
        if rec.corrected_expected_route_primary and routed.get("primary") != rec.corrected_expected_route_primary:
            failures.append(
                {
                    "id": rec.id,
                    "raw_query": rec.raw_query,
                    "field": "route_primary",
                    "expected": rec.corrected_expected_route_primary,
                    "got": routed.get("primary"),
                }
            )
        if rec.corrected_expected_packet and pkt != rec.corrected_expected_packet:
            failures.append(
                {
                    "id": rec.id,
                    "raw_query": rec.raw_query,
                    "field": "packet_type",
                    "expected": rec.corrected_expected_packet,
                    "got": pkt,
                }
            )
    return failures


def record_from_api_payload(data: Dict[str, Any]) -> QueryFeedbackRecord:
    """Build a feedback row from POST /api/query-feedback JSON."""
    raw = str(data.get("raw_query") or data.get("query") or "").strip()
    qr = {
        "guarantee_class": data.get("guarantee_class"),
        "primary": data.get("route_primary") or data.get("route_decision"),
        "guarantee_reason": data.get("guarantee_reason") or "",
        "reason": data.get("route_reason") or data.get("reason") or "",
        "skip_basic_deterministic": data.get("skip_basic_deterministic"),
        "run_person_comprehensive": data.get("run_person_comprehensive"),
    }
    return build_feedback_record_from_pipeline(
        raw_query=raw,
        parsed_intent=dict(data.get("parsed_intent") or {}),
        query_route=qr,
        packet_type=str(data.get("packet_type") or ""),
        llm_used=data.get("llm_used"),
        answer_quality=str(data.get("answer_quality") or ANSWER_GOOD),
        failure_type=data.get("failure_type"),
        corrected_expected_guarantee_class=data.get("corrected_expected_guarantee_class"),
        corrected_expected_route_primary=data.get("corrected_expected_route_primary") or data.get("corrected_expected_route"),
        corrected_expected_packet=data.get("corrected_expected_packet"),
        corrected_notes=data.get("corrected_notes"),
        replay_context=dict(data.get("replay_context") or {}),
    )
