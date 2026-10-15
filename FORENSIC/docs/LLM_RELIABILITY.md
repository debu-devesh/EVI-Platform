# LLM stability & reliability (EVI)

LLMs are **not** deterministic. You make the system **reliable** by controlling **what they see**, **what they may conclude**, and **how you verify** outputs.

## 1. Architecture (most important)

| Layer | Role |
|--------|------|
| **Deterministic retrieval** (DB, parsers, `CellebriteDataAccessLayer`) | **Source of truth** for rows, counts, timestamps, participants. |
| **LLM** | **Reasoning / explanation / formatting** on the provided block only — not a second search engine. |

Routing (`guarantee_class`, `query_route`) exists to keep this split explicit. See `docs/GUARANTEE_CLASS.md` and `docs/QUERY_ROUTING.md`.

## 2. Evidence packet quality

Unreliable answers usually trace to **bad or contradictory context**, not “the model forgot.”

- **Avoid mixed signals**: e.g. “91 chat messages” vs “no messages matched” from a **different** table was misleading; native/SMS vs chat app sections are now labeled clearly in `cellebrite_data_access_layer.py`.
- **Truncate safely**: large dumps + vague questions → more hallucination risk. Prefer **narrow queries** (person + platform + date).
- **Debug visibility**: use **Show LLM forensic input** to inspect the exact user message (see `docs/DEBUG_LLM_CONTEXT.md`).

## 3. Prompting (already in `web_interface.py`)

- **Evidence-lock** rules (correlation safety, no contradicting deterministic counters).
- **Multi-table note**: chat vs SMS/native sections must not be read as “no communications” when chat rows exist.
- **Low temperature** (e.g. 0.3) for the chat completion call.

Tighten further for your deployment by shortening system text or adding **domain-specific** “must cite section headers” rules if needed.

## 4. Automated checks (post-response)

`utils/response_validator.py` runs **after** each streamed LLM reply:

- Compares **claimed** timestamps / phones / quoted snippets to the **full user message** (question + FORENSIC DATA) sent to the model.
- Logs warnings server-side; SSE `done` may include:
  - `response_validation_ok` (boolean)
  - `response_validation_warnings` (short list)

This does **not** block the answer; it flags possible fabrication for **review and tuning**. Expect some false positives (e.g. timestamp formatting). Use logs to refine prompts or extraction.

## 5. Operational practices

1. **Same model + settings** in LM Studio (temperature, context length).
2. **Restart Flask** after changing `web_interface.py` or data layer code.
3. **Version your prompts** (git) and note which build produced a given report.
4. For **court / formal reports**, treat LLM text as **draft narrative**; verify against raw exports and DB queries.

## 6. What “stable” can mean here

- **Stable process**: deterministic data + bounded prompts + validation + logging.
- **Not guaranteed**: identical wording every time, or 100% factual novelty without human review.

Use validation warnings + manual spot-checks on high-stakes answers.

## 7. Recent product improvements (data layer)

- **Person name deduplication**: `Josh Hickman` vs `Josh Hickman.jpg` are merged into one logical subject so the LLM does not see duplicate contradicting blocks.
- **SMS vs chat labeling**: Native `messages` table results are explicitly labeled and must not be read as “no chat communications.”
- **Timeline + year**: If the query mentions a year (e.g. 2020), the generic **TIMELINE OF EVENTS** slice (SMS/calls/locations) is filtered to that year, or replaced with a short note instead of unrelated rows.
- **Post-response validation**: `response_validation_ok` / `response_validation_warnings` on SSE `done` (see section 4).

Further ideas (not all implemented): entity-scoped timeline from `chat_messages`, RAG over chats only, structured JSON answers for “facts” vs narrative.
