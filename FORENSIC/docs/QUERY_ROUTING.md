# Query routing (deterministic vs LLM)

**Top-level bucket:** `core/guarantee_class.py` → `infer_guarantee_class()`  
**Concrete flags:** `core/query_route.py` → `decide_query_route()`

See **`GUARANTEE_CLASS.md`** for the three-bucket contract.

## Guarantee → primary path

| `guarantee_class` | Typical `primary` |
|-------------------|-------------------|
| `strict_retrieval` | `deterministic_list` |
| `followup_analysis` | `followup_analysis` |
| `hybrid` | `hybrid_person` or `llm_synthesis` |

## Logging

`GUARANTEE_CLASS=… | ROUTE primary=… skip_basic_det=…`

and `PIPELINE[…] query_route: …` for structured traces.
