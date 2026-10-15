# Guarantee class (3-bucket routing)

Implemented in `core/guarantee_class.py` as **`infer_guarantee_class()`**.  
Applied in `core/query_route.py` via **`decide_query_route()`**.

## Values

| `guarantee_class` | Meaning |
|-------------------|--------|
| `strict_retrieval` | Facts from DB / deterministic operators. LLM must not invent factual rows or counts. |
| `followup_analysis` | **Analyze this result** mode: bounded evidence only, no broad new pulls. |
| `hybrid` | Scoped retrieval + synthesis (person-of-interest bundle, or interpretation on context). |

## Pipeline order

```
parse_query_intent
    → infer_guarantee_class (uses planner + query text + person extraction + follow-up flag)
    → decide_query_route (maps to skip_basic_deterministic, primary path)
```

## Logging

Streaming logs:

`GUARANTEE_CLASS=<class> (<reason>) | ROUTE primary=...`

## Client metadata

SSE `done` events may include:

- `guarantee_class`
- `guarantee_reason`
- `route_primary`

Use these for debugging and UI badges — not for security enforcement (server still enforces follow-up policy separately).
