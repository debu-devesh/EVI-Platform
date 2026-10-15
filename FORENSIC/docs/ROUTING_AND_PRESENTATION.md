# Routing and investigator presentation

## Query buckets

| Bucket | User intent | Typical route |
|--------|-------------|----------------|
| A — Facts | show, list, count, correlate, date + platform | Deterministic SQL / correlation / lists |
| B — Meaning | explain, summarize, suspicious, relationship | LLM on evidence |
| C — Mixed | correlate and explain, timeline and summarize | Hybrid: deterministic evidence first, then LLM |

## Score-based hints (`core/query_route_scores.py`)

- **`det_score` (0–10):** boosts for fact verbs, ISO dates, platforms, domains, `cross_reference` / `reconstruct`.
- **`analysis_score` (0–10):** boosts for explain, analyze, pattern, suspicious, etc.
- **`route_hint`:** `deterministic` | `llm` | `hybrid` from score balance.

Scores **do not replace** the core guarantee contract; after `decide_query_route` and `apply_feedback_to_query_route`, **`apply_route_score_bias`** may nudge the route when safe:

- **Phase 1 — both high:** `route_hint == hybrid`, both scores ≥ 6, base was `strict_retrieval` → bias to **`hybrid`** + `llm_synthesis` (skip basic list path; LLM uses evidence packet).
- **Phase 2 — fact-heavy:** `route_hint` deterministic, det ≥ 7, ana ≤ 4, base was `hybrid` + `llm_synthesis` → bias back to **`strict_retrieval`** (run basic deterministic first).
- **Case C — analysis-forward:** `route_hint == llm`, ana ≥ 6, det ≤ 5, base `strict_retrieval` → bias to **hybrid** synthesis (LLM-led with packet).
- **Phase 3 (telemetry):** with `EVI_PURE_DETERMINISTIC=1`, very strong det / weak ana may set `score_prefers_pure_deterministic` on the route for logging.

**Hard skips (no bias):** follow-up-only mode, `feedback_bias_applied`, non-ASCII query, `followup_analysis` guarantee, person-hybrid primary.

## Merge order

1. `parse_query_intent`
2. `build_query_plan`
3. `compute_route_scores`
4. `decide_query_route` (after person / XML checks)
5. `apply_feedback_to_query_route`
6. `apply_route_score_bias`
7. Execute deterministic branches (clarify, intersection, reconstruct, correlation, basic retrieval) or LLM with evidence packet

## Deterministic presentation (`utils/investigator_deterministic_format.py`)

Correlation and merged timelines use a compact layout:

- **# Correlation** / **# Timeline · date · platform**
- **Summary** — short outcome line
- **Counts** — bullets (counts, same-day overlap where applicable)
- **Records** — paired rows or event lines (italic line when no timestamp-aligned pairs in the sample)

Basic list retrieval in `web_interface.run_basic_deterministic_retrieval` uses the same style: `#` / `**Summary**` headers, short scope suffixes (` · YYYY-MM-DD`), and no long caveat blocks.

## LLM alignment

`core/llm_response_format.py` instructs the model not to contradict pre-computed deterministic blocks and to align section vocabulary with the same pattern.
