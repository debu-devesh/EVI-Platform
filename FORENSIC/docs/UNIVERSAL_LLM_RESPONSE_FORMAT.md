# Universal LLM response format

All standard forensic LLM answers (streaming `/api/chat` stream and non-streaming LLM path) use a **single universal structure** defined in `core/llm_response_format.py`.

## Tiers (adaptive length)

| Tier | When selected | Layout |
|------|----------------|--------|
| `skip` | Explicit `pull messages …` command | Uses the dedicated Pulled Messages / Analysis Context / Recommendations template (not the universal headings). |
| `ultra_short` | Brief/simple qualifiers, short queries, or small evidence payload (~&lt; 2.2k chars) | **3** `##` sections (compact). |
| `normal` | Default | **5** `##` sections. |
| `extended` | Comprehensive qualifiers, case-level phrasing, very large context (~&gt; 16k chars), or broad hybrid queries | **5** `##` sections with deeper allowances. |

Selection is logged as: `📐 Universal response format tier: …`.

## Fixed order (guardrails)

Models are instructed to:

- Use **Markdown `##` headers exactly as specified** for each tier.
- **Never reorder, rename, merge, or add** extra top-level sections (no separate “Hypotheses” heading).
- Ground claims in provided FORENSIC DATA; **Uncertainty / Limits** holds what cannot be concluded.
- **Suggested Next Action** is **one** clear deterministic query or step (wording only — no execution in the LLM layer).

## Consistency

Explanation, summary, insight, and conceptual answers all use the same headings so investigators see a predictable flow: **answer → evidence → interpretation → limits → next step**.

## Evidence type classification (internal, prompt-enforced)

Before writing, the model is instructed to **silently** classify the primary evidence type and use the matching reasoning style:

| Mode | Reasoning focus |
|------|-----------------|
| **timeline events** | Sequencing, gaps, ordering, simultaneity; duration inferences only when supported. |
| **listing / aggregation** | Inventories, counts, lists—see **Listing rules** below. |
| **correlation output** | Cross-domain joins/overlaps; linkage strength; no implied causation without support. |
| **reconstruction output** | Fragment-based narrative; explicit uncertainty; no gap-filling fiction. |
| **content messages** | Substantive text/media; anchored paraphrase; avoid over-reading intent. |
| **contact profile** | Record attributes (names, numbers, IDs); separate from comms behavior unless both exist. |

## Listing / aggregation output rules (anti-hallucination)

When the payload is mainly a **list** (contacts, chats, calls, counts), analysis must emphasize:

1. **Recurrence patterns** — repeats, top entities, re-engagement frequency.  
2. **Concentration vs dispersion** — few heavy counterparts vs many light touches.  
3. **Time distribution** — bursts, clusters, gaps, spread across time when timestamps exist.  
4. **Activity intensity** — relative volume/rate **from the data only**.

**Do not** invent social or organizational stories (e.g. “team coordination”, “close collaboration”) unless the evidence **explicitly** supports them. Prefer neutral forensic language: “high frequency”, “repeated contact”, “bidirectional vs one-sided traffic”.

## Forensic quality bar (prompt-enforced)

- **Direct Answer / Core Finding:** Summarize the **pattern** (what the evidence shows about behavior, timing, structure)—do **not** echo the user’s task (“here are the messages…”) or open with inventory language.
- **Key Supporting Observations:** Prefer analytic dimensions when visible: **clustering**, **frequency**, **directionality**, **text↔call / modality transitions**, **time windows**, platform/thread context—avoid empty list-style bullets.
- **Interpretation / Insight:** For listing-heavy inputs, tie interpretation to **metrics and structure**, not speculative relationship labels.
- **Suggested Next Action:** Must move the case **deeper**, **narrower**, or **more correlated** (e.g. correlate chats with calls for a date/chat)—not **sideways** (e.g. generic “list all messages” when a focused slice already exists).
