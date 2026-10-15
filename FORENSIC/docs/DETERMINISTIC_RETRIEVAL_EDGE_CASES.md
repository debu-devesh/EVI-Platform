# Deterministic retrieval — edge cases & behavior

This document describes how **basic deterministic** routing in `web_interface.py` behaves, known limitations, and queries worth testing manually.

## Multi-facet: `forensic_multibundle`

When the query mentions **two or more** of: locations, calls, messages/chats, contacts, media — joined with `and`, `or`, commas, `/`, `&`, `+` — routing uses **`forensic_multibundle`** (checked **after** `calls_and_chats`).

- Output sections appear in order: **Locations → Calls → Messages → Contacts → Media**.
- Each facet has its own row cap (`per_cap`) so one domain does not exhaust the whole budget.
- **Dates / time:** the same **temporal rules** as single-domain (see below) apply to locations, calls, and messages inside the bundle.

## Temporal wording (`after` / `before` / `between`)

Extracted `YYYY-MM-DD` values plus query text drive filtering:

| Wording | Effect on `timestamp` (calendar day = first 10 chars of ISO string) |
|--------|----------------------------------------------------------------------|
| `on 2020-09-23` / single day | Exact match on that calendar day. |
| `after 2020-09-23` | **Strictly after** that day (e.g. from `2020-09-24` onward). |
| `before 2020-09-23` | **Strictly before** that day. |
| `between A and B` | **Inclusive** range from `min(A,B)` through `max(A,B)` (needs ≥2 extracted dates). |

**Locations**, **calls**, **calls_and_chats** (both halves), **messages** (platform path), and **forensic_multibundle** use this logic. **Full ISO timestamps** are still shown in list lines so local/UTC offset remains visible.

If the user says `after` / `before` / `between` but **no ISO date is extracted**, no date filter is applied (falls back to platform / caps only).

## Combined domain: `calls_and_chats`

### When it triggers

- Query must mention **calls** (e.g. `calls`, `call log`, `phone calls`) **and** **chats/messages** (`chats`, `messages`, `sms`, `texts`, …).
- It must also show an **explicit link** between the two ideas: `and`, `or`, `,`, `/`, `&`, `+`, `plus`, `with`, `as well as`, `along with` (within ~240 characters between the two sides).
- Examples that **do** combine:
  - `show calls and chats from whatsapp on 2020-09-23`
  - `show calls or chats from whatsapp on 2020-09-23` (still returns **both** sections)
  - `messages and calls for telegram on 2021-01-01`
  - `call logs, conversations from line`
- Examples that **do not** combine (falls through to **calls** or **messages** only):
  - `show calls in the chat app` (both words appear but no coordinated “calls … chat/messages” pattern)
  - `call log for this chat` (no explicit dual listing)
  - `show whatsapp calls` only

### Scoped vs unscoped

- **Best results:** include **platform** (e.g. WhatsApp) and/or **ISO date** (`YYYY-MM-DD`).
- **No platform and no date:** response is **capped** (calls: last N rows from DB; messages: limited query) and an advisory line is prepended.

### Dates

- Only **`YYYY-MM-DD`** strings are kept after merge (sanitized list). Malformed or partial dates from parsers are dropped.

---

## Domain priority (`_detect_basic_deterministic_domain`)

Order matters; **first match wins**:

1. **calls_and_chats** — coordinated calls + chats/messages only (narrow regex).
2. **forensic_multibundle** — 2+ facets with list-style coordination (see above).
3. **locations** — e.g. `location`, `gps`, `map`, …
4. **calls**
5. **contacts**
6. **media**
7. **messages** (keyword `message`, `sms`, `text`, …)
8. **chats** (keyword `chat`, `conversation`, `thread`, …)

### Cross-domain edge cases

| Scenario | Typical outcome |
|----------|------------------|
| “locations **and** calls” | **forensic_multibundle** (both sections). |
| “media **and** messages” | **Media only**. |
| “contacts **and** calls” | **Contacts only** (no `contacts_and_calls` domain). |
| Query has non-ASCII (e.g. Hindi) in the **main** deterministic path | Deterministic layer **skipped** for that query (LLM handles). |
| No retrieval verb (`show`, `list`, `find`, …) | `_is_basic_deterministic_intent` is false → **no** basic deterministic handling. |
| Planner / route sets `skip_basic_deterministic` | Basic deterministic **not** run. |
| **Follow-up mode** (analysis-only) | Deterministic data ops **blocked** upstream in stream handler. |

---

## Per-domain notes

### Calls

- **Date filter:** `substr(timestamp,1,10)` must match; timezone offsets in full ISO strings still match **calendar date** prefix when stored as ISO.
- **Platform:** derived from `raw_data` / source fields; mismatched labels vs user text (“WhatsApp” vs `WhatsApp Business`) rely on `_platform_match` normalization.

### Chats (thread list)

- Uses `get_chat_data_for_display` — **not** the same as flat `chat_messages` listing.
- **Date filters** from intent are **not** applied in the simple `chats` domain (threads are summarized).

### Messages

- Uses `chat_messages` with optional platform filter and deduplication.
- **“text”** keyword uses **word-boundary** phrases in combined detection; substring traps (e.g. inside unrelated words) are reduced but not impossible for very short tokens.

### Contacts / locations / media

- Platform derivation varies by table; empty or unknown platform fields reduce filter accuracy.
- **Limits:** user can request explicit `show 20 …`; else large default caps apply.

---

## Potential edge cases to test (checklist)

1. **calls_and_chats:** `calls + chats` with only `and` in the middle of unrelated clause (should **not** falsely combine).
2. **calls_and_chats:** Semicolon or slash: `calls; chats`, `calls / messages`.
3. **Dates:** `2020-9-23` vs `2020-09-23` in free text — extraction depends on `_extract_dates_from_text`.
4. **Multi-day:** several ISO dates in one query — `IN (...)` for calls; message rows must match **any** listed date.
5. **Empty DB / no rows:** both sections should show “no matching …” without error.
6. **Huge row counts:** verify UI and timeouts with caps; deterministic text can be very long.
7. **Negative phrasing:** `don't show calls` still contains `show` — may still look like retrieval intent (LLM / planner should correct downstream).
8. **Snapchat / WhatsApp:** `chat` inside **Snapchat** does not use naive substring for `chat` keyword (`has_phrase` word boundaries).
9. **Stop mid-stream:** client abort should not leave timers hanging (see chat UI simulated stream).
10. **Concurrent sessions:** same browser, rapid sends — streaming wrappers cleared on new `start` event.

---

## Related code

- `_detect_basic_deterministic_domain`, `_wants_combined_calls_and_chats_query`
- `_merge_iso_date_filters`, `_sanitized_iso_date_filters`
- `run_basic_deterministic_retrieval`
- Stream handler: `skip_basic_deterministic`, follow-up mode, `_sse_deterministic_done`
