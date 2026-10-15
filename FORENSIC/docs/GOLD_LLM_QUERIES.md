# Gold LLM regression queries (ambiguous investigator phrasing)

Run after changes to `core/llm_evidence_packet.py`, routing, or LLM prompts.  
For each query, verify **packet metadata** in logs (`LLM_PACKET_DEBUG …`) and **answer shape** (evidence-bound, uncertainty section).

| # | Query | Expected packet / behavior |
|---|--------|----------------------------|
| 1 | Timeline of interactions with **John Smith** in **2020** | `person_timeline` or `person_summary`; date scope; no unrelated device-wide location dump |
| 2 | **Chronological** sequence of messages and calls involving **Jane Doe** | Chronological rows; deduped; canonical contact id if present |
| 3 | **Compare** communication activity **between Alice** and **Bob** last month | `comparison`; side-by-side or daily table; no raw full-case export |
| 4 | **Correlate** chat activity with **Carlos** and **Dana** | `correlation`; pre-computed overlap/daily stats; LLM explains, does not invent counts |
| 5 | **Overlap** in **dates** between WhatsApp and SMS for **Eve** | Scoped platforms; deterministic overlap if applicable |
| 6 | Show **suspicious communication patterns** across **all platforms** | `pattern`; aggregated stats + trimmed samples |
| 7 | **Analyze communication pattern** for **Frank** | `pattern` or `person_summary`; observable patterns only |
| 8 | Summarize **cross-platform** usage for this device | Hybrid general; overview without inventing apps not in data |
| 9 | **What does this prove?** (follow-up, base message selected) | `followup`; only base content + narrow packet; no broad retrieval |
| 10 | **Explain** the prior result (short follow-up) | `followup`; interpretation-only discipline |
| 11 | **List all** WhatsApp messages with **Bob** | May use larger `max_items`; still bounded by smart budget |
| 12 | **Device info** in brief | Brief tier; no extra stats unless in data |
| 13 | **International phone numbers** in the case | Only numbers present in FORENSIC DATA |
| 14 | **Correlate WhatsApp** activity **with calls** for **[2020-09-23]** | `correlation` → **dated app vs call_logs** unified timeline (not “CHATS INVOLVING Correlate WhatsApp”); LLM must not claim “no activity” when rows exist |
| 15 | **Josh Hickman** vs **josh_hickman** — same person? | Alias normalization; single subject scope |

## Checklist (manual)

- [ ] Log line `LLM_PACKET_DEBUG` includes: `LLM_PACKET_TYPE`, `ENTITY_SCOPE`, `PLATFORM_SCOPE`, `DATE_SCOPE`, `ROW_COUNT`, `CHAR_COUNT`, `EVIDENCE_TRUNCATED`, `GUARANTEE_CLASS`.
- [ ] User prompt ends with **EVIDENCE CONTRACT** block.
- [ ] Answer includes uncertainty when appropriate (per universal format tier).
- [ ] **Follow-up “examples”**: After a direct query, assistant history stores `evidence_snapshot`; follow-up prompts merge **DETERMINISTIC FORENSIC SNAPSHOT** so the model can cite rows (re-run the parent query once if snapshot missing).
