# LLM vs deterministic — role architecture

This document defines **where the LLM adds value** vs **where code must own truth**, and how to wire behaviour in EVI.

## Core principle

| Layer | Responsibility |
|--------|----------------|
| **Deterministic** | Pull rows, counts, filters, merges, timelines, correlation **tables**, capped listings. **Ground truth.** |
| **LLM** | Explain **why** patterns might matter, propose **hypotheses** (labelled as hypotheses), suggest **next checks**, summarize **pre-computed** stats in natural language. **Never invent rows.** |

The LLM should **only** see forensic text that already came from deterministic (or XML-normalized) pipelines — via `build_llm_evidence_packet` / `FORENSIC DATA` / snapshots — plus your **EVIDENCE CONTRACT** (`core/llm_evidence_packet.py`).

---

## 1. Pattern understanding (VERY IMPORTANT)

**Goal:** Deterministic detects structure; LLM explains **investigative meaning** (with uncertainty).

| Deterministic | LLM |
|---------------|-----|
| Time-bucketed counts, spike detection, repeated-call detection, location delta sequences (whatever your engine exposes) | “Why this might matter”, “what to verify”, “limits of this signal” |

**How to implement in this codebase**

- Route “pattern / spike / burst / anomaly” style queries to **`hybrid`** or **`llm_synthesis`** with a packet type that includes **pre-aggregated** metrics (`core/llm_evidence_packet.py`, `query_classifier` / planner).
- **Do not** ask the LLM to “scan all calls”; pass **summaries + small exemplar rows** from SQL.

**Prompt shape (conceptual)**

- Input: `PRE-COMPUTED PATTERN STATS` + optional 5–20 example rows.  
- Instruction: Interpret only; label speculation; cite numbers from the block.

---

## 2. Cross-domain insight (“wow moment”)

**Goal:** Deterministic aligns **calls + chats + locations** on time (or overlap tables); LLM narrates **coordination hypotheses** cautiously.

| Deterministic | LLM |
|---------------|-----|
| Unified timeline, MATCHING_INSTANTS, correlation tables, capped rows | “Possible coordination”, “movement ↔ comms”, **hypothesis** language |

**How to implement**

- Use existing **correlation / timeline reconstruction** paths in `web_interface.py` + `correlation_engine` so the model receives **explicit** “authoritative” tables (your prompts already say not to contradict those).
- LLM prompt must say: **no physical co-presence** unless identity+time linkage is in data (you already have similar guardrails in long system text).

---

## 3. Investigation guidance

**Goal:** Actionable next steps **without** fabricating facts.

| Allowed | Not allowed |
|---------|-------------|
| “Check X contact on Y date”, “compare Z platforms”, “re-run with date range A–B” | Inventing that a contact exists or a date had activity not in evidence |

**How to implement**

- Prefer **`strict_retrieval`** or small deterministic pulls first; then **follow-up** or a second turn with **snapshot** of what was shown.
- System prompt: next steps must be **tied to entities/dates present** in `FORENSIC DATA`.

---

## 4. Summarization of large structured findings

**Goal:** Compress 200/80/70 rows into **dominant period, top contacts, clusters** — from **aggregates you pass in**.

| Deterministic | LLM |
|---------------|-----|
| Full list (or paginated), **totals**, histograms, top-N by count | Narrative summary, “most active window”, “dominant peer” **if** pre-computed or clearly derivable from supplied totals |

**How to implement**

- Never paste 200 rows raw if you can pass **top-K + distribution** from the data layer.
- LLM instruction: if only samples are present, say totals are **partial** / **capped**.

---

## 5. Vague / natural language (“anything suspicious?”)

**Goal:** UX + scoping; **not** magic detection without data.

| Behaviour | Implementation |
|-----------|----------------|
| High-level overview | Route to LLM with **broad but bounded** packet (quick stats + samples) |
| State limits | Universal format + uncertainty section |
| Guide next step | Suggest **deterministic** queries by name (dates, platforms) |

**How to implement**

- `classify_query` / planner: vague intent → **`hybrid`** with **small** evidence packet, not full DB.
- Prompt: “If data insufficient, say so and suggest 2–3 **specific** queries.”

---

## Where the LLM must NOT be used

| User asks | Route |
|-----------|--------|
| “Show / list / find / count …” (plain retrieval) | **`strict_retrieval`** → `run_basic_deterministic_retrieval` / data layer |
| Heavy correlation over huge raw tables | Deterministic SQL + correlation engine; LLM only gets **result** |
| Anything requiring **exact** counts across full DB | Deterministic |

Enforce with:

- `infer_guarantee_class()` + `decide_query_route()` (`core/guarantee_class.py`, `core/query_route.py`).
- `followup_llm_only` still **skips** stream deterministic branches but **supplementary** pulls can attach DB rows (see `FOLLOWUP_MODE.md`) — interpretation remains LLM; **rows** are still from SQL.

---

## Trust / anti-hallucination

1. **EVIDENCE CONTRACT** — answer only from supplied blocks (`core/llm_evidence_packet.py`).
2. **Response validation** — optional `utils/response_validator.py` checks claims vs evidence.
3. **Wording** — “Hypothesis”, “may”, “suggests”, “requires verification” for non-forensic inferences.
4. **Never** — criminal intent, “proof” of guilt, or contacts not in data.

---

## Practical checklist (for demos)

1. **Demo A:** Run deterministic “calls + messages + locations on date D” → show table → LLM: “interpret coordination **hypothesis**.”
2. **Demo B:** Pattern stats from code → LLM: “why night spikes matter.”
3. **Demo C:** Vague question → LLM outlines limits + **exact** next queries to run.
4. **Never demo:** Asking LLM to “list all calls” without deterministic path.

---

## Files to touch when tightening behaviour

| Concern | Location |
|---------|----------|
| Guarantee / routing | `core/guarantee_class.py`, `core/query_route.py` |
| Packet contents | `core/llm_evidence_packet.py` |
| Stream: deterministic vs LLM | `web_interface.py` (`chat_query_stream`, `followup_llm_only`) |
| Query intent | `core/query_classifier.py`, `core/query_planner.py` |
| Prompt copy | System message construction in `web_interface.py`, `llm_response_format.py` |

This is the intended split: **deterministic = truth engine**, **LLM = explanation + hypothesis + guidance** on top of that truth.
