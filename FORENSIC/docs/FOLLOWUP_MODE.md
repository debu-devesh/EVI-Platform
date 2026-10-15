# Follow-up mode (LLM with selected context)

When **Analyze this result** is used, the UI stores the selected assistant message as **`followup_base`**. The next request is sent with **`followup_mode: true`**; the server sets **`followup_llm_only`** so **early stream deterministic branches** are skipped and the **LLM** builds the answer from the prompt (base + optional snapshot + optional supplementary rows).

## Cross-domain follow-up (automatic supplementary rows)

If the follow-up question looks like a **deterministic retrieval** (show/list/find/get/…) and targets a **different domain** than the selected base (e.g. base = WhatsApp message listing, question = “find locations around 2020-10-03”), `web_interface.py` runs **`run_basic_deterministic_retrieval`** for that question and appends **SUPPLEMENTARY DETERMINISTIC FORENSIC DATA** to the LLM prompt.

**Similar phrasing** is covered by the same domain keywords + retrieval verbs (e.g. locations / GPS / “where was” / “whereabouts” + ISO dates). Multibundle / calls+chats follow the same detector as direct queries.

## UI

- **View** — scroll to the base message
- **Clear** — remove follow-up context

## Backend

- `core/followup_policy.py` — `evaluate_followup_mode_policy()` always allows (legacy hook).
- `web_interface.py` — `followup_llm_only` skips stream-level basic deterministic handlers; supplementary deterministic text may still be merged into the LLM user message as above.

For **pure deterministic SQL** without anchoring a prior bubble, you can still send a normal query with follow-up **cleared**.
