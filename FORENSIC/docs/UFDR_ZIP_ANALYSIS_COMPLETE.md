# UFDR ZIP Analysis - Complete Technical Reference

This document covers the complete ZIP-based UFDR path in EVI, including parser selection, ZIP classification, Cellebrite SQLite handling, normalization, retrieval integration, and operational constraints.

---

## 1) Scope and Purpose

EVI processes ZIP forensic exports through layered parser logic to handle both:

- generic JSON-artifact style UFDR ZIPs
- Cellebrite lightweight ZIPs containing many `.db` files

Primary objective:

- extract reliable, query-ready forensic records into a normalized structure/database
- support deterministic and AI-assisted analysis paths with the same downstream interfaces

---

## 2) ZIP Pipeline Architecture

### Core files involved

- `FORENSIC/core/hybrid_zip_parser.py` - main ZIP classification + parsing orchestration
- `FORENSIC/core/cellebrite_sqlite_parser.py` - standard Cellebrite lightweight DB parser
- `FORENSIC/core/fast_cellebrite_parser.py` - optimized large-file parser path
- `FORENSIC/core/cellebrite_data_access_layer.py` - unified retrieval/query layer
- `FORENSIC/web_interface.py` - upload and API integration

### Hybrid parser philosophy

`HybridZipParser` uses:

1. fast heuristics first
2. content sampling for uncertain cases
3. optional LLM fallback only when needed
4. rule-based field transformation for normalization

This keeps parsing speed high while preserving flexibility for edge structures.

---

## 3) ZIP Type Detection and Routing

### Cellebrite lightweight detection

`HybridZipParser._is_cellebrite_lightweight()` checks archive composition (notably `.db` density).  
If detected and parser is available:

- route to `CellebriteSQLiteParser.parse_ufdr_zip(...)`

### Large-file strategy

For large ZIPs (threshold-based), parser behavior shifts to:

- essential-file prioritization
- reduced costly sampling
- heuristic-first classification acceptance

This is designed to control latency and memory usage.

---

## 4) UFDR ZIP Classification Model

`HybridZipParser` classification uses:

- **Path patterns** (highest confidence)
- **Filename patterns** (medium confidence)
- **Schema field signatures** from sampled JSON records
- fallback classification when ambiguity remains

### Data domains classified

- calls
- contacts
- messages
- location
- device info
- case info

### Transformation mapping

Field maps normalize aliases like:

- `sender` -> `from`
- `receiver` -> `to`
- `message/content/body` -> `text`
- `date/time/datetime` -> `timestamp`

Similar mapping sets exist for contacts and calls.

---

## 5) Cellebrite ZIP Parsing Paths

### A) `CellebriteSQLiteParser` (standard lightweight path)

Designed for structured Cellebrite ZIPs; features include:

- selective extraction of essential files
- database discovery and category inference by table names
- parsing across contacts/messages/calls/locations/device info
- normalization to UFDR-style output dict
- deferred/controlled media handling

Typical output keys:

- `contacts`
- `messages`
- `call_logs`
- `locations`
- `device`
- `files`
- `images`
- `videos`
- metadata flags (`tampered`, `format_version`, `source_format`)

### B) `FastCellebriteParser` (large/high-volume path)

Optimized for very large extractions:

- parallel processing for major artifact groups
- direct SQLite output schema creation
- report metadata ingestion
- separate handling for chats vs chat_messages
- media/file indexing

---

## 6) Normalized Data Model from ZIP Workflows

ZIP parsing converges on a common evidence model used by downstream retrieval:

- contacts
- messages
- chats
- chat_messages
- call_logs
- locations
- files
- device metadata

Schema alignment with XML path allows shared querying and response logic.

---

## 7) Integration with Query/Chat Layer

After ZIP processing:

- `CellebriteDataAccessLayer` executes evidence retrieval
- query analyzer + route scoring determine deterministic/hybrid/synthesis flow
- response formatting enforces consistency and grounding
- `/api/chat` and `/api/chat/stream` serve investigator-facing answers

Related routing and reliability modules:

- `FORENSIC/core/query_classifier.py`
- `FORENSIC/core/query_intent_parser.py`
- `FORENSIC/core/query_planner.py`
- `FORENSIC/core/query_route.py`
- `FORENSIC/core/query_route_scores.py`
- `FORENSIC/core/followup_policy.py`

---

## 8) Performance Considerations for ZIP Parsing

### Optimizations in place

- structure scan before heavy content parsing
- skip non-essential files in large archives
- confidence-based short-circuiting
- minimal LLM dependency in parsing stage
- cached pattern/heuristic behavior

### Trade-offs

- strict essential-file filtering can defer long-tail artifacts
- fallback sophistication depends on available metadata quality
- very heterogeneous exports may still require iterative heuristic tuning

---

## 9) Edge Cases and Failure Modes

Important ZIP-side edge conditions:

- deeply nested or non-standard artifact paths
- mixed-format archives (JSON + DB + media with unusual naming)
- truncated/corrupt JSON files
- inconsistent field naming across app artifacts
- partial Cellebrite exports with missing expected DB tables

Mitigations:

- layered confidence + sampling classification
- robust field mapping transforms
- fallback paths and logging for unresolved files
- preserving raw evidence context where possible

---

## 10) Reliability and Grounding Controls

ZIP-derived evidence is protected by:

- deterministic format helpers
- response validator checks
- route-level strict retrieval pathways
- feedback learning hooks (`query_feedback`, policy memory artifacts)

Relevant data artifacts:

- `FORENSIC/data/query_feedback.jsonl`
- `FORENSIC/data/query_policy_memory.json`

---

## 11) Validation and Test Targets

Recommended ZIP-focused verification:

1. classification accuracy per artifact domain
2. parse completeness by table/entity counts
3. cross-source timestamp consistency
4. participant/identifier mapping in chat records
5. deterministic response quality on known benchmark queries

Related tests:

- `FORENSIC/tests/test_query_classifier_platforms.py`
- `FORENSIC/tests/test_query_intent_parser_compound_platforms.py`
- `FORENSIC/tests/test_query_route_scores.py`
- `FORENSIC/tests/test_query_feedback_learning.py`

---

## 12) Operational Guidance for Investigations

For ZIP-heavy cases:

- use deterministic retrieval first for factual extracts
- use hybrid/synthesis for interpretation after packet construction
- maintain schema parity across parser updates
- keep large transient extraction outputs ignored in git
- monitor parser logs for low-confidence classifications

---

## 13) UFDR ZIP-Related Files Inventory

- `FORENSIC/core/hybrid_zip_parser.py`
- `FORENSIC/core/cellebrite_sqlite_parser.py`
- `FORENSIC/core/fast_cellebrite_parser.py`
- `FORENSIC/core/cellebrite_data_access_layer.py`
- `FORENSIC/core/enhanced_data_extractor.py`
- `FORENSIC/core/semantic_data_extractor.py`
- `FORENSIC/engines/enhanced_nl_query_engine.py`
- `FORENSIC/web_interface.py`
- `FORENSIC/docs/QUERY_ROUTING.md`
- `FORENSIC/docs/ROUTING_AND_PRESENTATION.md`
- `FORENSIC/docs/LLM_RELIABILITY.md`

---

## 14) Summary

The UFDR ZIP path is built as a layered, resilient ingestion system:

- adaptive classification for varied archive structures,
- specialized Cellebrite handling for DB-heavy exports,
- normalized output for shared query logic,
- and evidence-first reliability controls for forensic use.
