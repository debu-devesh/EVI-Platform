# Query feedback learning (pipeline memory)

This layer **does not fine-tune** the LLM. It stores investigator reviews and uses them to bias **routing**, **evidence packet selection**, and (indirectly) explanation style via the same packets.

## Storage

| File | Purpose |
|------|---------|
| `FORENSIC/data/query_feedback.jsonl` | Append-only JSON lines; one `QueryFeedbackRecord` per review |
| `FORENSIC/data/query_policy_memory.json` | Keyword / condition rules (seed rules + auto-merged corrections) |

Override paths with `EVI_QUERY_FEEDBACK_PATH` and `EVI_QUERY_POLICY_MEMORY_PATH`.

## Record fields

- `raw_query`, `normalized_query`, `parsed_intent`
- `guarantee_class`, `route_primary` (alias: `route_decision` on ingest)
- `packet_type`, `llm_used`, `answer_quality` (`good` \| `bad`)
- `failure_type` (see below)
- `corrected_expected_guarantee_class`, `corrected_expected_route_primary`, `corrected_expected_packet`, `corrected_notes`
- `replay_context` — optional JSON for regression replay (`followup_llm_only`, `has_xml_data`, `person_name_extracted`, `query_plan`, etc.)

## Failure taxonomy

Constants in `core/query_feedback.py` (`ALL_FAILURE_TYPES`):

- `wrong_bucket`
- `wrong_packet_type`
- `broad_fallback_blob`
- `deterministic_query_sent_to_llm`
- `speculative_interpretation`
- `alias_duplication`
- `contradiction_with_deterministic_result`
- `poor_scope_default`

## Runtime behavior

1. **Routing** — After `decide_query_route()`, `apply_feedback_to_query_route()` applies:
   - **Policy rules** (`query_policy_memory.json`, including seeds such as correlate+app+calls → strict + correlation packet bias).
   - **Similar past corrections** — if a prior **bad** review with `corrected_*` is similar enough (≥ ~0.72), patch `guarantee_class` / `primary`.

2. **Packet type** — After `infer_llm_packet_type()`, `apply_feedback_to_packet_type()` applies the same policy + similarity (with guards: no `person_*` packet without a person; no `followup` packet outside follow-up mode).

3. **Learned rules** — Appending a **bad** record with corrections triggers `merge_correction_into_policy_memory()` (narrow `if_all` token rule).

## API

- `POST /api/query-feedback` — submit a review JSON (see `record_from_api_payload` in `core/query_feedback.py`).
- `GET /api/query-feedback/failure-types` — list allowed `failure_type` values.

Streaming `done` events may include `feedback_route_meta` when a bias was applied.

## UI workflow (Enhanced chat)

After each **streamed** assistant answer, the **same row** as Confidence and Response time shows **thumbs up / thumbs down** (Font Awesome). Up sends a quick “good” review; down opens the **What went wrong?** form.

1. **Helpful** — sends `answer_quality: good` plus the current `guarantee_class`, `route_primary`, packet type (from `evidence_packet`), and `llm_used`. Use when routing + evidence packet + explanation matched the question.
2. **Needs improvement** — opens **What went wrong?** with:
   - **Best match** — plain-language categories (the same taxonomy codes are still stored; a collapsible **Technical label** shows the internal name).
   - **Notes (recommended)** — free text; most useful for investigators.
   - **Optional: suggest routing** — collapsed “power user” section with friendly labels for preferred pipeline path, evidence layout, and guarantee/mode (still stored as the same backend values).

Submissions append to `query_feedback.jsonl` and may merge a narrow rule into `query_policy_memory.json`. Similar future queries bias toward your corrections.

### Example: “Correlate WhatsApp activity with calls”

| Step | What you do |
|------|----------------|
| 1 | Ask: *Correlate WhatsApp activity with calls for [date]* (or add an ISO date in the query). |
| 2 | Read the answer. If the system used the wrong **packet** (e.g. generic blob instead of correlation), or wrong **route** (e.g. follow-up when you wanted a direct deterministic correlation), click **Needs improvement**. |
| 3 | Set **Failure type** e.g. `wrong_packet_type` or `poor_scope_default`. |
| 4 | Set **Expected packet** → `correlation`, **Expected route** → often `deterministic_list` for strict listing/correlation-first behavior, or adjust per your deployment. |
| 5 | Add notes: *“Should use dated app vs call_logs correlation slice, not a broad case dump.”* → **Submit feedback**. |

**Note:** The UI bar is attached when the stream sends a normal `done` with query context; purely deterministic short-circuit responses may not show the bar until the same flow is unified.

## Regression harness

`run_feedback_regression_checks()` in `core/query_feedback.py` replays all **bad + corrected** rows and compares `guarantee_class`, `route_primary`, and `packet_type` to `corrected_expected_*`.

Pytest: `FORENSIC/tests/test_query_feedback_learning.py`

```bash
cd FORENSIC
python tests/test_query_feedback_learning.py -v
```
(Or `python -m pytest …` if pytest is installed.)

## Seed policy examples (defaults)

- Correlate + app + calls + no bracketed date → bias correlation packet + strict retrieval list path.
- Timeline + year + person cues → `person_timeline` packet.
- “Tell me more / who is …” → `person_summary` packet (unless explicit pull/list).
- Follow-up phrasing → `followup` packet.
