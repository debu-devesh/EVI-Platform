#!/usr/bin/env python3
"""
Lightweight query intent parser for deterministic routing.
Converts messy user phrasing into a structured intent object.
"""

from __future__ import annotations

import re
from difflib import get_close_matches


ACTION_SYNONYMS = {
    "retrieve": [
        "show", "list", "get", "find", "pull", "fetch", "retrieve", "display", "view", "open",
        "दिखाओ", "दिखाएं", "निकालो", "निकालें", "प्राप्त", "प्राप्त करें", "खोज", "ढूंढ", "ढूँढ",
    ],
    "count": ["count", "how many", "total", "number of", "कितने", "गिनती"],
    "cross_reference": [
        "cross-reference", "cross reference", "correlate", "correlation", "relate", "relationship",
        "link", "connect", "compare", "coordination", "associated with", "related to", "across domains",
        # Common typos / variants users type
        "co-relation", "co relation", "corelation", "co-relate", "co relate",
        "co-realation", "co realation", "corealation",
        "correaltion", "correletion", "corrlation",
    ],
    "analyze": [
        "analyze", "analysis", "insight", "insights", "explain", "interpret", "suspicious", "pattern",
        "summarize", "summarise", "summary", "recap", "limitations", "limitation",
        # Common typos / variants so routing stays "analyze" not bare retrieve
        "expalain", "expain", "explanations", "explanation",
        "analzye", "nalzye", "anaylze", "analize", "anlyze", "analsis",
    ],
}

DOMAIN_KEYWORDS = {
    "messages": ["message", "messages", "sms", "mms", "text", "texts", "संदेश", "मैसेज"],
    "chats": ["chat", "chats", "conversation", "conversations", "thread", "threads", "चैट", "बातचीत"],
    "calls": ["call", "calls", "calllog", "calllogs", "dialed", "incomingcall", "outgoingcall", "कॉल", "कॉललॉग"],
    "contacts": ["contact", "contacts", "phonebook", "addressbook", "संपर्क", "कॉन्टैक्ट"],
    "locations": ["location", "locations", "gps", "coordinate", "coordinates", "map", "maps", "लोकेशन", "स्थान"],
    "media": ["media", "image", "images", "photo", "photos", "video", "videos", "attachment", "मीडिया", "फोटो"],
}

PLATFORM_ALIASES = {
    "whatsapp": ["whatsapp", "whats app", "व्हाट्सएप"],
    "telegram": ["telegram", "टेलीग्राम"],
    # Do NOT use bare "messenger" — it matches the trailing word in "kik messenger" and mis-routes to Facebook Messenger.
    "facebook messenger": ["facebook messenger", "fb messenger", "facebook messager"],
    "instagram": ["instagram", "इंस्टाग्राम"],
    "snapchat": ["snapchat", "snap chat", "स्नैपचैट"],
    "discord": ["discord"],
    "line": ["line", "लाइन"],
    "skype": ["skype", "स्काइप"],
    "viber": ["viber", "वाइबर"],
    "kik": ["kik messenger", "kik"],
    "textnow": ["textnow", "text now"],
    "tiktok": ["tiktok", "tik tok"],
    "wickr pro": ["wickr pro", "wickr", "wickrpro"],
    "native messages": ["native messages", "native message", "native sms", "native"],
    "google photos": ["google photos", "google photo", "गूगल फोटो", "गूगल फ़ोटो"],
    "google maps": ["google maps", "गूगल मैप्स"],
    "gmail": ["gmail", "जीमेल"],
    "twitter": ["twitter", "ट्विटर"],
}

TIME_ALIASES = {
    "late_night": ["late night", "overnight", "after midnight", "रात"],
    "morning": ["morning", "सुबह"],
    "afternoon": ["afternoon", "दोपहर"],
    "evening": ["evening", "शाम"],
}

# Single-token platform names that appear inside normal English words if matched naïvely (substring).
_PLATFORM_SUBSTRING_RISK = frozenset(
    {"line", "kik", "native", "viber", "skype", "gmail", "tiktok"}
)

_STUCK_DOMAIN_SUFFIXES = (
    "message",
    "messages",
    "chat",
    "chats",
    "conversation",
    "conversations",
    "call",
    "calls",
    "location",
    "locations",
    "contact",
    "contacts",
    "media",
)


def normalize_platform_typos(text: str) -> str:
    """Expand common user typos before platform extraction (preserve non-matching casing)."""
    if not text:
        return text
    low = text.lower()
    typo_map = (
        ("facmebook messager", "facebook messenger"),
        ("facebook messager", "facebook messenger"),
        ("facbook messenger", "facebook messenger"),
        ("facbook messager", "facebook messenger"),
        ("facmebook", "facebook messenger"),
    )
    for wrong, right in typo_map:
        if wrong in low:
            return re.compile(re.escape(wrong), re.I).sub(right, text)
    return text


def _alias_matches_query(q: str, alias: str) -> bool:
    """True if alias occurs in q with safe boundaries (avoids 'line' in 'timeline')."""
    if not q or not alias:
        return False
    al = alias.strip().lower()
    if not al:
        return False
    if " " in al:
        return al in q
    token = al
    if token in _PLATFORM_SUBSTRING_RISK or len(token) <= 4:
        # Also allow compact forms like "linemessages" while still avoiding "timeline".
        suffix_union = "|".join(map(re.escape, _STUCK_DOMAIN_SUFFIXES))
        return bool(
            re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", q)
            or re.search(rf"(?<![a-z0-9]){re.escape(token)}(?={suffix_union}\b)", q)
        )
    return token in q


def extract_platforms_ordered(query: str) -> list:
    """
    Return canonical platform names in order of first occurrence in the query.
    Longest alias wins overlapping spans (e.g. 'facebook messenger' before 'messenger').
    """
    q = _normalize_for_lookup(normalize_platform_typos(query or ""))
    candidates = []
    for canonical, aliases in PLATFORM_ALIASES.items():
        for al in aliases:
            candidates.append((len(al), canonical, al.lower()))
    candidates.sort(key=lambda x: -x[0])
    spans = []  # (start, end, canonical)

    def overlaps_any(s: int, e: int) -> bool:
        for us, ue, _ in spans:
            if not (e <= us or s >= ue):
                return True
        return False

    for _, canonical, al in candidates:
        pos = 0
        while pos < len(q):
            if " " in al:
                idx = q.find(al, pos)
                if idx < 0:
                    break
                end = idx + len(al)
            elif al in _PLATFORM_SUBSTRING_RISK or len(al) <= 4:
                suffix_union = "|".join(map(re.escape, _STUCK_DOMAIN_SUFFIXES))
                m = re.search(
                    rf"(?<![a-z0-9]){re.escape(al)}((?![a-z0-9])|(?={suffix_union}\b))",
                    q[pos:],
                )
                if not m:
                    break
                idx = pos + m.start()
                end = idx + len(al)
            else:
                idx = q.find(al, pos)
                if idx < 0:
                    break
                end = idx + len(al)
            if not overlaps_any(idx, end):
                spans.append((idx, end, canonical))
            pos = idx + 1

    spans.sort(key=lambda x: x[0])
    out = []
    seen = set()
    for _, _, c in spans:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _normalize_for_lookup(text: str) -> str:
    t = (text or "").lower()
    t = t.replace("‑", "-").replace("–", "-").replace("—", "-")
    return t


# "LINE chat" names the app — substring "chat" must not add chats/messages domains alone.
_PLATFORM_CHAT_APP_SCRUB_RES = tuple(
    re.compile(p, re.I)
    for p in (
        r"\bline\s+chats?\b",
        r"\bwhatsapp\s+chats?\b",
        r"\bwhats\s+app\s+chats?\b",
        r"\btelegram\s+chats?\b",
        r"\bsignal\s+chats?\b",
        r"\bdiscord\s+chats?\b",
        r"\bsnapchat\s+chats?\b",
        r"\bwechat\s+chats?\b",
        r"\bviber\s+chats?\b",
        r"\bkik\s+chats?\b",
        r"\bskype\s+chats?\b",
        r"\bimessage\s+chats?\b",
        r"\bfb\s+messenger\s+chats?\b",
        r"\bfacebook\s+messenger\s+chats?\b",
        r"\bgoogle\s+chats?\b",
        r"\bteams\s+chats?\b",
        r"\bslack\s+chats?\b",
    )
)


def scrub_platform_chat_labels_for_domain_parsing(q: str) -> str:
    """Strip '<platform> chat(s)' before chats/messages domain keyword matching."""
    s = (q or "").lower()
    for rx in _PLATFORM_CHAT_APP_SCRUB_RES:
        s = rx.sub(" ", s)
    return s


def scrub_platform_aliases_for_domain_parsing(q: str) -> str:
    """
    Remove explicit platform aliases before domain keyword detection so
    platform names like 'snapchat'/'google photos' do not inject 'chats'/'media' domains.
    """
    s = (q or "").lower()
    alias_list = sorted(
        {a.lower() for aliases in PLATFORM_ALIASES.values() for a in aliases if a},
        key=len,
        reverse=True,
    )
    for alias in alias_list:
        if " " in alias:
            s = re.sub(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", " ", s)
        else:
            s = re.sub(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", " ", s)
    return s


def _domain_keyword_matches(q_text: str, keyword: str) -> bool:
    """Boundary-safe keyword check to avoid substring false positives."""
    kw = (keyword or "").strip().lower()
    if not kw:
        return False
    if " " in kw:
        return bool(re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", q_text))
    return bool(re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", q_text))


def _extract_limit(query: str):
    q = _normalize_for_lookup(query)
    for p in [r"\b(?:top|first|last|limit)\s+(\d{1,5})\b", r"\b(?:show|list|get|find|pull|fetch|retrieve)\s+(\d{1,5})\b"]:
        m = re.search(p, q)
        if m:
            try:
                n = int(m.group(1))
                if n > 0:
                    return n
            except Exception:
                pass
    return None


def _fuzzy_contains_token(tokens, candidates):
    for c in candidates:
        if c in tokens:
            return True
        near = get_close_matches(c, tokens, n=1, cutoff=0.86)
        if near:
            return True
    return False


def parse_query_intent(query: str) -> dict:
    raw_in = normalize_platform_typos(query or "")
    q = _normalize_for_lookup(raw_in)
    raw_tokens = re.findall(r"[a-zA-Z0-9_\-\u0900-\u097F]+", q)
    tokens = [t.replace(" ", "") for t in raw_tokens]
    q_no_platform = scrub_platform_aliases_for_domain_parsing(q)
    # Preserve "<platform> chat(s)" scrubbing behavior before generic platform alias removal.
    q_scrub = scrub_platform_aliases_for_domain_parsing(
        scrub_platform_chat_labels_for_domain_parsing(q)
    )
    raw_tokens_no_platform = re.findall(r"[a-zA-Z0-9_\-\u0900-\u097F]+", q_no_platform)
    tokens_no_platform = [t.replace(" ", "") for t in raw_tokens_no_platform]
    raw_tokens_scrub = re.findall(r"[a-zA-Z0-9_\-\u0900-\u097F]+", q_scrub)
    tokens_scrub = [t.replace(" ", "") for t in raw_tokens_scrub]
    text_no_space = q.replace(" ", "")

    iso_dates = []
    for m in re.finditer(r"\b(\d{4}-\d{2}-\d{2})\b", query or ""):
        d = m.group(1)
        if d not in iso_dates:
            iso_dates.append(d)

    # Timeline reconstruction (deterministic path in web_interface)
    _recon_re = re.compile(
        r"\b(reconstruct|rebuild)\b.*\b(sequence|timeline|chronolog)|"
        r"\bmerged?\s+(chronological\s+)?(timeline|sequence)\b|"
        r"\breconstruct\s+sequence\b",
        re.I,
    )
    if _recon_re.search(q):
        action = "reconstruct"
    else:
        action = "retrieve"

    # Action: prefer explicit analysis/explanation over the word "correlation" alone
    # (e.g. "explain this correlation" should be analyze + LLM on base, not empty deterministic correlation).
    analysis_markers = (
        "explain", "interpret", "break down", "what does this mean", "what do these mean",
        "walk me through", "clarify", "describe",
    )
    correl_markers = (
        "correlation", "co-relation", "corelation", "co-realation", "corealation",
        "cross-reference", "cross reference", "correaltion", "correletion", "corrlation",
    )
    if action != "reconstruct":
        if (
            any(m in q for m in analysis_markers) or re.search(r"\banalyze\s+(this|the|that)\s+correlation", q)
        ) and any(c in q for c in correl_markers):
            action = "analyze"
        else:
            # Order matters: e.g. "analyze correlation ..." must be analyze, not cross_reference.
            for a in ("count", "analyze", "cross_reference", "retrieve"):
                syns = ACTION_SYNONYMS.get(a, ())
                if any(s in q for s in syns):
                    action = a
                    break
        # Regex catch: co-relat... without relying on exact spelling
        if action == "retrieve" and re.search(r"\bco[\s_-]*r?elat", q):
            action = "cross_reference"

    domains = []
    for d, kws in DOMAIN_KEYWORDS.items():
        flat_kws = [k.replace(" ", "") for k in kws]
        # Use platform-scrubbed text for all domain inference to avoid alias collisions
        # (e.g. "snapchat" -> chat, "google photos" -> photos/media).
        if d in ("chats", "messages"):
            q_dom, tok_dom = q_scrub, tokens_scrub
        else:
            q_dom, tok_dom = q_no_platform, tokens_no_platform
        if any(_domain_keyword_matches(q_dom, k) for k in kws) or _fuzzy_contains_token(tok_dom, flat_kws):
            domains.append(d)

    plat_ordered = extract_platforms_ordered(raw_in)
    platform = plat_ordered[0] if len(plat_ordered) == 1 else None

    # Fuzzy platform fallback for typos in latin scripts (single-token collapsed query)
    if not plat_ordered:
        all_aliases = []
        alias_to_platform = {}
        for canonical, aliases in PLATFORM_ALIASES.items():
            for a in aliases:
                a2 = a.replace(" ", "")
                if re.fullmatch(r"[a-z0-9_\-]+", a2):
                    all_aliases.append(a2)
                    alias_to_platform[a2] = canonical
        near = get_close_matches(text_no_space, all_aliases, n=1, cutoff=0.75)
        if near:
            platform = alias_to_platform.get(near[0])
            plat_ordered = [platform] if platform else []

    special = None
    overlap_phrase = bool(
        re.search(
            r"\b(appear in both|in both|both\s+\w+\s+and|intersection|overlap|in common)\b",
            q,
        )
    )
    contacts_mention = bool(re.search(r"\bcontacts?\b", q)) or ("contacts" in domains)
    if contacts_mention and overlap_phrase:
        if len(plat_ordered) >= 2:
            special = "contact_platform_intersection"
        elif re.search(r"\bboth\b", q):
            special = "ambiguous_contact_overlap"

    time_window = None
    for k, vals in TIME_ALIASES.items():
        if any(v in q for v in vals):
            time_window = k
            break

    if not domains and platform and action != "reconstruct":
        domains = ["messages"]

    return {
        "action": action,
        "domains": domains,
        "platform": platform,
        "platforms": plat_ordered,
        "special": special,
        "filters": {
            "limit": _extract_limit(query),
            "time_window": time_window,
            "dates": iso_dates,
        },
        "analysis_type": "cross_reference" if action == "cross_reference" else None,
        "confidence": 1.0 if domains else 0.6,
        "original_query": query,
    }


def to_canonical_query(intent: dict) -> str:
    action = intent.get("action") or "retrieve"
    domains = intent.get("domains") or []
    platform = intent.get("platform")
    filt = intent.get("filters") or {}
    limit = filt.get("limit")
    time_window = filt.get("time_window")

    if not domains:
        return intent.get("original_query", "")

    domain_text = " and ".join(domains)
    if action == "count":
        q = f"count {domain_text}"
    elif action == "cross_reference":
        q = f"cross-reference {domain_text}"
    elif action == "analyze":
        q = f"analyze {domain_text}"
    else:
        q = f"show {domain_text}"

    if platform:
        q += f" from {platform}"
    if time_window:
        q += f" {time_window}"
    if limit:
        # Preserve analyze vs show; previous code always rewrote to "show", which forced deterministic listing.
        verb = "analyze" if action == "analyze" else "show"
        q = f"{verb} {limit} {domain_text}"
        if platform:
            q += f" from {platform}"
        if time_window:
            q += f" {time_window}"

    return q
