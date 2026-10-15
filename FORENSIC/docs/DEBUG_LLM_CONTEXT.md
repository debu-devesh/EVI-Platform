# Debug: see what the LLM receives

The model is called with:

1. **System message** — instructions, language, format tiers, evidence-lock rules (see `web_interface.py` around the `messages.append({"role": "system", ...})` block).
2. **User message** — `QUESTION:` / `FOLLOW-UP QUESTION:` plus **`FORENSIC DATA`** (or follow-up base scope). This string is built after **truncation** (e.g. `MAX_DATA_SIZE` / context limits).

## UI (recommended)

1. **Easiest:** above the chat box (next to “Message EVI…”), check **Show LLM forensic input under each AI reply**.  
   (Same switch exists under **Settings → Preferences → Show LLM evidence (debug)** — the two stay in sync.)
2. Send a **new** query (the flag must be on when you press Send).
3. When the reply finishes, expand **LLM input (user message sent to model)** at the bottom of that AI bubble.

If debug is on but the block is missing, check the browser **Console** for `[EVI] stream done:` — `has_llm_evidence` should be `true` when the server returned the text.

The panel shows the **exact last user turn** sent to LM Studio (not the system prompt). Case data may be sensitive; it stays in the browser session unless you copy it.

## API

`POST /api/chat/stream` accepts:

```json
{ "query": "...", "debug_llm_context": true }
```

On the final SSE event (`type: "done"`), when enabled:

- `llm_evidence_text` — capped copy of that user message (server cap ~80k chars).
- `llm_evidence_truncated` — boolean if longer than the cap.
- `llm_evidence_char_count` — full length before cap.

## Logs

Server logs already include short previews of `data_context` and the user message prefix; use debug mode for the **full** post-truncation user block.
