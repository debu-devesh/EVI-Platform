# How Data is Fed to the LLM in EVI

## Overview
EVI uses a multi-stage pipeline to extract, process, and feed UFDR data to the LLM (Qwen/Qwen2.5-7B-Instruct via LM Studio).

## Complete Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. USER UPLOADS UFDR FILE                                       │
│    (JSON, ZIP, or .ufdr)                                        │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. FILE PARSING                                                 │
│    - HybridZipParser extracts ZIP/UFDR                         │
│    - CellebriteSQLiteParser handles SQLite databases            │
│    - Data normalized to UFDR format                            │
│    - Stored in ACTIVE_DATA (session storage)                   │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. USER SENDS CHAT QUERY                                        │
│    POST /api/chat or /api/chat/stream                          │
│    { "query": "Who did John call?" }                           │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. QUERY PREPROCESSING                                         │
│    - rewrite_vague_query() - prevents hallucination            │
│    - Language detection (for multilingual support)              │
│    - Query intent detection                                    │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. DATA EXTRACTION (Query-Aware)                               │
│                                                                 │
│    ┌──────────────────────────────────────────────────────┐   │
│    │ Option A: Summary Query Detection                    │   │
│    │ - is_query_too_broad(query)                          │   │
│    │ - generate_forensic_overview(data_src)               │   │
│    │ - Returns: High-level statistics only                │   │
│    └──────────────────────────────────────────────────────┘   │
│                                                                 │
│    ┌──────────────────────────────────────────────────────┐   │
│    │ Option B: JSON Extraction Mode                       │   │
│    │ - use_json_extraction = True                         │   │
│    │ - prepare_json_for_llm(data, query, max_chars=8000) │   │
│    │ - LLM extracts directly from JSON                   │   │
│    │ - Query-intent based truncation                      │   │
│    └──────────────────────────────────────────────────────┘   │
│                                                                 │
│    ┌──────────────────────────────────────────────────────┐   │
│    │ Option C: Semantic Extraction (DEFAULT)              │   │
│    │ - semantic_extractor.extract_relevant_data()          │   │
│    │   ├─ Uses intelligent_analyzer for query analysis    │   │
│    │   ├─ Entity-specific extraction                       │   │
│    │   ├─ Semantic search (if RAG available)              │   │
│    │   └─ Keyword-based fallback                          │   │
│    │ - Falls back to enhanced_extractor if fails          │   │
│    └──────────────────────────────────────────────────────┘   │
│                                                                 │
│    ┌──────────────────────────────────────────────────────┐   │
│    │ Option D: Enhanced Extraction (Fallback)              │   │
│    │ - enhanced_extractor.extract_relevant_data()          │   │
│    │ - Query-intent based filtering                        │   │
│    │ - Max 50 items per data type                          │   │
│    │ - Includes: contacts, messages, calls, locations      │   │
│    └──────────────────────────────────────────────────────┘   │
│                                                                 │
│    ┌──────────────────────────────────────────────────────┐   │
│    │ Image Citations (if image query)                       │   │
│    │ - image_citation_extractor.extract_image_citations() │   │
│    │ - Added to data_context if relevant                    │   │
│    └──────────────────────────────────────────────────────┘   │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. CONTEXT TRUNCATION                                           │
│    - truncate_for_context(data_context, max_tokens=3500)        │
│    - Dynamic calculation based on:                              │
│      • System message size                                     │
│      • Query size                                              │
│      • Response buffer (200 tokens)                           │
│      • Total context: 4096 tokens (LLM_CONTEXT_LENGTH)        │
│    - Formula: available = 4096 - system - query - 200          │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ 7. MESSAGE CONSTRUCTION                                         │
│                                                                 │
│    messages = [                                                │
│      {                                                          │
│        "role": "system",                                       │
│        "content": "You are an elite digital forensics..."     │
│        + language_instruction                                  │
│      },                                                         │
│      ...chat_history (all previous messages),                │
│      {                                                          │
│        "role": "user",                                         │
│        "content": f"{query}\n\nFORENSIC DATA:\n{data_context}"│
│      }                                                          │
│    ]                                                            │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ 8. LLM API CALL (LM Studio)                                    │
│                                                                 │
│    POST http://localhost:1234/v1/chat/completions             │
│    {                                                            │
│      "model": "Qwen/Qwen2.5-7B-Instruct",                     │
│      "messages": [...],                                         │
│      "temperature": 0.2,  # Low for accuracy                  │
│      "max_tokens": 1200,  # Prevent fabrication                │
│      "stream": true/false                                      │
│    }                                                            │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ 9. RESPONSE PROCESSING                                         │
│    - Stream tokens or full response                            │
│    - Save to chat history                                      │
│    - Persist to database                                       │
│    - Return to frontend                                         │
└─────────────────────────────────────────────────────────────────┘
```

## Key Components

### 1. Data Extractors

#### **SemanticDataExtractor** (Primary)
- **Location**: `FORENSIC/core/semantic_data_extractor.py`
- **Method**: `extract_relevant_data(ufdr_data, query)`
- **Features**:
  - Uses `intelligent_analyzer` for query analysis
  - Entity-specific extraction (person/contact focused)
  - Semantic search via RAG engine (if available)
  - Keyword-based fallback
  - Extracts ALL relevant chunks (no arbitrary limits)
- **Use Case**: Default extraction method for most queries

#### **EnhancedDataExtractor** (Fallback)
- **Location**: `FORENSIC/core/enhanced_data_extractor.py`
- **Method**: `extract_relevant_data(ufdr_data, query)`
- **Features**:
  - Query-intent detection (contacts/messages/calls/locations)
  - Max 50 items per data type
  - Structured formatting
  - Handles both v2 (devices array) and flat structures
- **Use Case**: Fallback when semantic extraction fails

#### **prepare_json_for_llm()** (JSON Mode)
- **Location**: `FORENSIC/web_interface.py` (line 1334)
- **Features**:
  - Sends raw JSON to LLM
  - Query-intent based truncation
  - Removes internal metadata
  - Max 8000 characters (≈3000-4000 tokens)
- **Use Case**: When `use_json_extraction=True`

### 2. Query Processing

#### **rewrite_vague_query()**
- Prevents hallucination by rewriting vague questions
- Example: "analyze" → "analyze contacts, messages, and calls"

#### **is_query_too_broad()**
- Detects summary/overview queries
- Triggers `generate_forensic_overview()` instead of raw data

#### **intelligent_analyzer**
- Analyzes query intent
- Detects: ranking, statistics, patterns, relationships
- Generates structured analysis for LLM

### 3. Context Management

#### **truncate_for_context()**
- **Location**: `FORENSIC/web_interface.py` (line 1302)
- **Purpose**: Ensures data fits within LLM context window
- **Parameters**:
  - `max_tokens`: Total context size (4096)
  - `reserved_tokens`: Space for system message, query, response
- **Method**: Truncates text while preserving structure

#### **Dynamic Context Calculation**
```python
# Calculate available space
system_tokens = len(system_message) / 1.67
query_tokens = len(query) / 1.67
response_reserve = 200
available_tokens = 4096 - system_tokens - query_tokens - response_reserve
available_chars = available_tokens * 1.67
```

### 4. LLM Configuration

- **Model**: `Qwen/Qwen2.5-7B-Instruct`
- **Endpoint**: `http://localhost:1234/v1/chat/completions`
- **Context Length**: 4096 tokens (`LLM_CONTEXT_LENGTH`)
- **Temperature**: 0.2 (low for accuracy, less hallucination)
- **Max Tokens**: 1200 (prevents fabrication)

## Data Extraction Strategies

### Strategy Selection Logic

```python
if is_summary_query:
    # Use overview (statistics only)
    data_context = generate_forensic_overview(data_src)
elif use_json_extraction:
    # Send JSON directly to LLM
    data_context = prepare_json_for_llm(data, query)
else:
    # Use semantic extraction (default)
    try:
        data_context = semantic_extractor.extract_relevant_data(data, query)
    except:
        # Fallback to enhanced extractor
        data_context = enhanced_extractor.extract_relevant_data(data, query)
```

### Query-Intent Based Filtering

Both extractors analyze the query to determine what data to include:

- **Contact queries**: Keywords like "contact", "name", "phone", "who", "people"
- **Message queries**: Keywords like "message", "text", "sms", "chat", "said"
- **Call queries**: Keywords like "call", "dial", "phone", "ring", "spoke"
- **Location queries**: Keywords like "location", "gps", "coordinates", "where"
- **File queries**: Keywords like "file", "document", "photo", "attachment"

If no specific intent is detected, all data types are included.

## Example Flow

### Query: "Who did John call on March 15th?"

1. **Query Preprocessing**
   - Detected as call query
   - Language: English

2. **Data Extraction** (Semantic Extractor)
   - Searches for contacts named "John"
   - Extracts all calls from John
   - Filters by date (March 15th)
   - Includes related contact information

3. **Context Construction**
   ```
   FORENSIC DATA:
   === CONTACTS ===
   - John Smith (phone: +1234567890)
   
   === CALL LOGS ===
   - From: John Smith (+1234567890)
     To: Jane Doe (+0987654321)
     Date: 2024-03-15 14:30:00
     Duration: 5 minutes
     Type: Outgoing
   
   - From: John Smith (+1234567890)
     To: Bob Johnson (+1122334455)
     Date: 2024-03-15 18:45:00
     Duration: 12 minutes
     Type: Outgoing
   ```

4. **LLM Prompt**
   ```
   System: You are an elite digital forensics analyst...
   User: Who did John call on March 15th?
   
   FORENSIC DATA:
   [extracted context above]
   ```

5. **LLM Response**
   - Analyzes the extracted data
   - Identifies all calls from John on March 15th
   - Lists recipients with timestamps and durations

## Performance Optimizations

1. **Deferred Media Extraction**: Images/videos not loaded initially
2. **Selective File Extraction**: Only essential files extracted from ZIP
3. **Query-Aware Truncation**: Only relevant data sent to LLM
4. **Caching**: Data index built once per session
5. **Fast Mode**: For large files (>500MB), limits database queries to 50,000 records

## Notes

- **Chat History**: All previous messages included (no limit) for conversational context
- **Image Citations**: Added automatically if query is image-related
- **Multilingual**: Language detection ensures LLM responds in user's language
- **Error Handling**: Multiple fallback strategies ensure data is always extracted

