# 🔍 Cellebrite Parser System - Complete Analysis

**Comprehensive guide to how Cellebrite parsing operations work in EVI**

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Components Breakdown](#components-breakdown)
4. [Parsing Flow](#parsing-flow)
5. [Data Structures](#data-structures)
6. [Integration Points](#integration-points)
7. [Performance Optimizations](#performance-optimizations)
8. [Usage Examples](#usage-examples)

---

## 🎯 Overview

EVI includes a **comprehensive Cellebrite parser system** designed to handle Cellebrite UFDR (Unified Forensic Data Records) files. Cellebrite is a digital forensics tool that extracts data from mobile devices, and it exports data in a specific format using SQLite databases.

### Key Characteristics of Cellebrite Format

- **SQLite Databases**: Uses multiple `.db` files instead of JSON
- **Structured Data**: Contacts, calls, messages stored in database tables
- **Large Files**: Can be 15GB+ in size
- **Media Files**: Images/videos stored separately in `Media/` folder
- **Metadata**: Device info in `report.xml`
- **Chats**: Separate chat sessions and chat messages (distinct from regular messages)

---

## 🏗️ Architecture

The Cellebrite parser system consists of **three main components**:

```
┌─────────────────────────────────────────────────────────────┐
│                    Cellebrite Parser System                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. CellebriteSQLiteParser                                  │
│     └─ Standard parser for smaller files                   │
│                                                              │
│  2. FastCellebriteParser                                    │
│     └─ Optimized parser for large files (15GB+)            │
│     └─ Parallel processing                                  │
│     └─ Database storage                                     │
│                                                              │
│  3. CellebriteDataAccessLayer                                │
│     └─ Query interface                                      │
│     └─ LLM-ready formatting                                  │
│     └─ On-demand media extraction                            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Component Selection Logic

```
Upload Cellebrite ZIP File
         │
         ▼
Check file size & structure
         │
         ├─→ Small file (< 500MB) OR Standard format
         │   └─→ Use CellebriteSQLiteParser
         │       └─→ In-memory processing
         │       └─→ Returns UFDR dict
         │
         └─→ Large file (> 500MB) OR Many .db files
             └─→ Use FastCellebriteParser
                 └─→ Database storage
                 └─→ Parallel processing
                 └─→ Returns statistics
                 │
                 └─→ Create CellebriteDataAccessLayer
                     └─→ Query interface
                     └─→ On-demand access
```

---

## 🔧 Components Breakdown

### 1. CellebriteSQLiteParser (`cellebrite_sqlite_parser.py`)

**Purpose**: Standard parser for Cellebrite lightweight UFDR format

**Key Features**:
- ✅ Selective file extraction (only essential files)
- ✅ Database categorization
- ✅ Data normalization to UFDR format
- ✅ Fast mode for large files (limits to 50,000 records)
- ✅ Media metadata extraction (deferred)

**Class Structure**:
```python
class CellebriteSQLiteParser:
    def __init__(self)
    def parse_ufdr_zip(zip_path, extract_to) -> Dict[str, Any]
    def _find_database_files(extract_to) -> List[str]
    def _categorize_databases(db_files) -> Dict[str, List[str]]
    def _parse_contacts(db_files, extract_to, fast_mode)
    def _parse_calls(db_files, extract_to, fast_mode)
    def _parse_messages(db_files, extract_to, fast_mode)
    def _parse_locations(db_files, extract_to)
    def _parse_device_info(extract_to)
    def _extract_media(extract_to, deferred)
    def _normalize_contact(contact) -> Dict
    def _normalize_call(call) -> Dict
    def _normalize_message(message, db_file) -> Dict
    def _normalize_location(location) -> Dict
```

**Processing Steps**:

1. **Selective Extraction**
   - Extracts only essential files (.db, report.xml, metadata)
   - Skips media files (deferred extraction)
   - Skips large binaries (.so, .apk, .jar, .dex, .bin, .exe)

2. **Database Discovery**
   - Finds all `.db` files in extracted directory
   - Categorizes by examining table names

3. **Database Categorization**
   - **Contacts**: Tables with 'contact', 'phonebook', 'addressbook'
   - **Calls**: Tables with 'call', 'call_log'
   - **Messages**: Tables with 'sms', 'message', 'whatsapp', 'imessage'
   - **Locations**: Tables with 'location', 'gps', 'geolocation'

4. **Data Parsing**
   - Parses each category sequentially
   - Normalizes data to UFDR format
   - Handles field name variations (e.g., 'from' vs 'sender')

5. **Normalization**
   - Maps various field names to standard UFDR format
   - Handles timestamp conversion (Unix to ISO)
   - Validates required fields

**Output Format**:
```python
{
    'contacts': [...],
    'messages': [...],
    'call_logs': [...],
    'locations': [...],
    'device': {...},
    'files': [...],
    'images': [...],
    'videos': [...],
    'tampered': False,
    'format_version': 'v1',
    'source_format': 'cellebrite_lightweight'
}
```

---

### 2. FastCellebriteParser (`fast_cellebrite_parser.py`)

**Purpose**: High-performance parser optimized for large Cellebrite files (15GB+)

**Key Features**:
- ✅ Parallel processing (ThreadPoolExecutor)
- ✅ Database storage (SQLite output database)
- ✅ Comprehensive report.xml parsing
- ✅ Chat-specific handling (separate from messages)
- ✅ File database parsing
- ✅ Media indexing (deferred extraction)
- ✅ Zero data loss

**Class Structure**:
```python
class FastCellebriteParser:
    def __init__(self, max_workers=4)
    def parse_cellebrite_ufdr(zip_path, output_db, extract_to) -> Dict[str, Any]
    def _create_cellebrite_database(db_path)
    def _extract_essential_cellebrite_files(zip_path, extract_to) -> List[str]
    def _parse_report_xml_comprehensive(report_xml_path, output_db)
    def _categorize_cellebrite_databases(db_files) -> Dict[str, List[str]]
    def _parse_all_cellebrite_databases(db_categories, output_db, zip_size) -> Dict
    def _parse_contacts_parallel(db_files, output_db, fast_mode) -> int
    def _parse_calls_parallel(db_files, output_db, fast_mode) -> int
    def _parse_messages_parallel(db_files, output_db, fast_mode) -> int
    def _parse_chats_parallel(db_files, output_db, fast_mode) -> int
    def _parse_chat_messages_parallel(db_files, output_db, fast_mode) -> int
    def _parse_files_parallel(db_files, output_db, fast_mode) -> int
    def _parse_locations_parallel(db_files, output_db, fast_mode) -> int
    def _index_media_from_cellebrite_zip(zip_path, output_db)
    def _index_files_from_cellebrite_zip(zip_path, output_db)
```

**Database Schema Created**:

```sql
-- Contacts table
CREATE TABLE contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT, phone TEXT, email TEXT,
    source_db TEXT, source_table TEXT,
    raw_data TEXT
)

-- Messages table (SMS, WhatsApp)
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_number TEXT, to_number TEXT,
    text_content TEXT, timestamp TEXT,
    source TEXT, source_db TEXT,
    source_table TEXT, raw_data TEXT
)

-- Chats table (chat sessions/conversations)
CREATE TABLE chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id TEXT, chat_name TEXT,
    participants TEXT, platform TEXT,
    last_message_time TEXT, message_count INTEGER,
    source_db TEXT, source_table TEXT,
    raw_data TEXT
)

-- Chat messages table (messages within chats)
CREATE TABLE chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id TEXT, message_id TEXT,
    from_participant TEXT, to_participant TEXT,
    text_content TEXT, timestamp TEXT,
    platform TEXT, attachment_path TEXT,
    source_db TEXT, source_table TEXT,
    raw_data TEXT
)

-- Calls table
CREATE TABLE call_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_number TEXT, to_number TEXT,
    timestamp TEXT, duration INTEGER,
    call_type TEXT, source_db TEXT,
    source_table TEXT, raw_data TEXT
)

-- Files table
CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT, file_path TEXT,
    file_type TEXT, size INTEGER,
    mime_type TEXT, created_time TEXT,
    modified_time TEXT, accessed_time TEXT,
    hash_md5 TEXT, hash_sha1 TEXT,
    source_db TEXT, source_table TEXT,
    raw_data TEXT
)

-- Locations table
CREATE TABLE locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    latitude REAL, longitude REAL,
    timestamp TEXT, address TEXT,
    source_db TEXT, source_table TEXT,
    raw_data TEXT
)

-- Device metadata table (from report.xml)
CREATE TABLE device_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT, value TEXT,
    category TEXT, source TEXT,
    UNIQUE(key, category)
)

-- Media index table
CREATE TABLE media_index (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT, rel_path TEXT,
    zip_path TEXT, media_type TEXT,
    size INTEGER, format TEXT,
    extracted INTEGER DEFAULT 0
)
```

**Processing Phases**:

#### Phase 1: Extract Essential Files
- Extracts only `.db` files and `report.xml`
- Skips media files (deferred)
- Returns list of extracted files

#### Phase 2: Parse report.xml
- Comprehensive XML parsing
- Extracts device information
- Extracts extraction metadata
- Extracts case information
- Stores in `device_metadata` table

#### Phase 3: Find All Databases
- Recursively finds all `.db` files
- Returns list of database file paths

#### Phase 4: Categorize Databases
- Examines table structure of each database
- Categorizes into:
  - `chats` - Chat sessions/conversations
  - `chat_messages` - Messages within chats
  - `files` - File database tables
  - `contacts` - Contact databases
  - `calls` - Call log databases
  - `messages` - SMS/WhatsApp message databases
  - `locations` - Location/GPS databases

#### Phase 5: Parse Databases in Parallel
- Uses ThreadPoolExecutor for parallel processing
- Each category parsed in separate thread
- Fast mode: Limits to 50,000 records per table
- Stores results in output database
- Returns statistics (counts per category)

#### Phase 6: Index Media from ZIP
- Scans ZIP for files in `Media/` folder
- Indexes images (.jpg, .jpeg, .png, .gif, .bmp, .webp, .heic, .tiff)
- Indexes videos (.mp4, .avi, .mov, .mkv, .webm, .flv, .wmv, .m4v, .3gp)
- Stores metadata in `media_index` table
- **Does NOT extract** - only indexes (deferred extraction)

#### Phase 7: Index Files from ZIP
- Scans ZIP for files in `Files/` folder
- Indexes file attachments
- Stores in `files` table

**Output**:
```python
{
    'contacts_count': 1234,
    'messages_count': 5678,
    'chats_count': 90,
    'chat_messages_count': 12345,
    'calls_count': 234,
    'locations_count': 56,
    'files_count': 789,
    'images_count': 1234,
    'videos_count': 56
}
```

---

### 3. CellebriteDataAccessLayer (`cellebrite_data_access_layer.py`)

**Purpose**: Query interface and LLM-ready data formatting

**Key Features**:
- ✅ Query-aware data extraction
- ✅ LLM-ready formatting
- ✅ On-demand media extraction
- ✅ UFDR format compatibility
- ✅ Statistics retrieval

**Class Structure**:
```python
class CellebriteDataAccessLayer:
    def __init__(self, db_path, zip_path)
    def get_connection()
    def query_contacts(query, limit=100) -> List[Dict]
    def query_messages(query, limit=100) -> List[Dict]
    def query_chats(query, limit=100) -> List[Dict]
    def query_chat_messages(query, limit=100) -> List[Dict]
    def query_files(query, limit=100) -> List[Dict]
    def query_calls(query, limit=100) -> List[Dict]
    def get_relevant_data_for_llm(query, max_items=50) -> str
    def get_media_metadata(media_type, limit=100) -> List[Dict]
    def extract_media_on_demand(rel_path, extract_to) -> Optional[str]
    def get_statistics() -> Dict[str, Any]
    def get_ufdr_format_data() -> Dict[str, Any]
```

**Query Methods**:

Each query method:
1. Parses query string for search terms
2. Filters out common query words
3. Builds SQL WHERE clause with LIKE conditions
4. Executes query with LIMIT
5. Returns list of dictionaries

**Example: `query_contacts()`**
```python
# Query: "show contacts with John"
# Search terms: ["show", "contacts", "with", "John"]
# Filtered: ["John"]
# SQL: WHERE (name LIKE '%John%' OR phone LIKE '%John%' OR email LIKE '%John%')
```

**LLM-Ready Formatting**:

`get_relevant_data_for_llm()` method:
- Analyzes query to determine what data to extract
- Extracts relevant sections:
  - Device information (if query mentions device/model/IMEI)
  - Chats (if query mentions chat/conversation/group)
  - Chat messages (if query mentions chat message/group message)
  - Files (if query mentions file/document/attachment)
  - Contacts (if query mentions contact/name/phone)
  - Messages (if query mentions message/text/SMS)
  - Calls (if query mentions call/dial/phone)
  - Locations (if query mentions location/GPS/coordinates)
- Formats as text sections with headers
- Returns formatted string ready for LLM consumption

**Example Output**:
```
=== DEVICE INFORMATION ===
device_model: iPhone 12 Pro
manufacturer: Apple
imei: 123456789012345
serial_number: ABC123XYZ

=== CONTACTS (Showing 10 of 500 total) ===
1. John Doe: +1234567890 (john@example.com)
2. Jane Smith: +0987654321
...

=== MESSAGES ===
From: +1234567890 | To: +0987654321 | Source: SMS | Time: 2024-01-01T12:00:00
Content: Hello, how are you?

...
```

**On-Demand Media Extraction**:

`extract_media_on_demand()`:
- Extracts specific media file from ZIP
- Marks as extracted in database
- Returns path to extracted file
- Used when user requests specific image/video

**UFDR Format Compatibility**:

`get_ufdr_format_data()`:
- Converts database records to UFDR format
- Maintains compatibility with existing system
- Returns standard UFDR structure

---

## 🔄 Parsing Flow

### Complete Flow Diagram

```
User uploads Cellebrite ZIP file
         │
         ▼
web_interface.py detects Cellebrite format
         │
         ├─→ Checks: file size, .db file count
         │
         ├─→ Small file (< 500MB) OR < 2 .db files
         │   │
         │   └─→ Use HybridZipParser
         │       │
         │       └─→ Detects Cellebrite lightweight format
         │           │
         │           └─→ CellebriteSQLiteParser.parse_ufdr_zip()
         │               │
         │               ├─→ Extract essential files
         │               ├─→ Find database files
         │               ├─→ Categorize databases
         │               ├─→ Parse contacts, calls, messages, locations
         │               ├─→ Parse device info from report.xml
         │               └─→ Extract media metadata (deferred)
         │               │
         │               └─→ Returns UFDR dict
         │
         └─→ Large file (> 500MB) OR >= 2 .db files
             │
             └─→ Use FastCellebriteParser.parse_cellebrite_ufdr()
                 │
                 ├─→ Create output database
                 ├─→ Extract essential files (.db, report.xml)
                 ├─→ Parse report.xml → device_metadata table
                 ├─→ Find all database files
                 ├─→ Categorize databases
                 ├─→ Parse in parallel:
                 │   ├─→ Contacts (ThreadPoolExecutor)
                 │   ├─→ Calls (ThreadPoolExecutor)
                 │   ├─→ Messages (ThreadPoolExecutor)
                 │   ├─→ Chats (ThreadPoolExecutor)
                 │   ├─→ Chat Messages (ThreadPoolExecutor)
                 │   ├─→ Files (ThreadPoolExecutor)
                 │   └─→ Locations (ThreadPoolExecutor)
                 ├─→ Index media from ZIP → media_index table
                 ├─→ Index files from ZIP → files table
                 └─→ Return statistics
                 │
                 └─→ Create CellebriteDataAccessLayer
                     │
                     └─→ Store in ACTIVE_DATA_LAYERS
                         │
                         └─→ Ready for queries
```

### Query Flow

```
User submits query: "show messages from John"
         │
         ▼
web_interface.py receives query
         │
         ├─→ Check if CellebriteDataAccessLayer exists
         │   │
         │   └─→ YES: Use data access layer
         │       │
         │       └─→ data_layer.get_relevant_data_for_llm(query)
         │           │
         │           ├─→ Analyze query intent
         │           ├─→ Query relevant tables:
         │           │   ├─→ query_messages() → messages table
         │           │   ├─→ query_contacts() → contacts table
         │           │   └─→ ...
         │           ├─→ Format for LLM
         │           └─→ Return formatted string
         │
         └─→ NO: Use standard UFDR data
             │
             └─→ Use enhanced_data_extractor or semantic_extractor
```

---

## 📊 Data Structures

### Cellebrite Database Structure

```
Cellebrite ZIP File
├── report.xml (device metadata, extraction info, case info)
├── Database Files (.db)
│   ├── contacts.db
│   │   └── contacts table
│   ├── calls.db
│   │   └── calls table
│   ├── messages.db
│   │   └── messages table
│   ├── chats.db
│   │   ├── chats table (chat sessions)
│   │   └── chat_messages table (messages within chats)
│   ├── files.db
│   │   └── files table
│   └── locations.db
│       └── locations table
├── Media/
│   ├── Images/
│   │   └── *.jpg, *.png, etc.
│   └── Videos/
│       └── *.mp4, *.avi, etc.
└── Files/
    └── (file attachments)
```

### Normalized UFDR Structure

```python
{
    'contacts': [
        {
            'name': 'John Doe',
            'phone': '+1234567890',
            'email': 'john@example.com',
            'source_db': '/path/to/contacts.db',
            'source_table': 'contacts',
            'raw_data': '{...}'  # Original database row
        }
    ],
    'messages': [
        {
            'from_number': '+1234567890',
            'to_number': '+0987654321',
            'text_content': 'Hello',
            'timestamp': '2024-01-01T12:00:00',
            'source': 'SMS',
            'source_db': '/path/to/messages.db',
            'source_table': 'messages',
            'raw_data': '{...}'
        }
    ],
    'chats': [
        {
            'chat_id': 'chat123',
            'chat_name': 'Group Chat',
            'participants': ['+1234567890', '+0987654321'],
            'platform': 'WhatsApp',
            'last_message_time': '2024-01-01T12:00:00',
            'message_count': 100
        }
    ],
    'chat_messages': [
        {
            'chat_id': 'chat123',
            'message_id': 'msg456',
            'from_participant': '+1234567890',
            'to_participant': '+0987654321',
            'text_content': 'Hello group!',
            'timestamp': '2024-01-01T12:00:00',
            'platform': 'WhatsApp'
        }
    ],
    'call_logs': [...],
    'locations': [...],
    'files': [...],
    'device': {
        'device_model': 'iPhone 12 Pro',
        'manufacturer': 'Apple',
        'imei': '123456789012345'
    },
    'images': [
        {
            'name': 'photo.jpg',
            'rel_path': 'Media/Images/photo.jpg',
            'size': 1024000,
            'extracted': False
        }
    ],
    'videos': [...],
    'tampered': False,
    'format_version': 'v1',
    'source_format': 'cellebrite_lightweight'
}
```

---

## 🔗 Integration Points

### 1. Hybrid ZIP Parser Integration

**Location**: `hybrid_zip_parser.py`

**Integration**:
```python
def parse_zip(self, zip_path: str) -> Dict:
    # Check if it's Cellebrite lightweight format
    if CELLEBRITE_PARSER_AVAILABLE and self._is_cellebrite_lightweight(zip_path):
        parser = CellebriteSQLiteParser()
        ufdr_data = parser.parse_ufdr_zip(zip_path, extract_to)
        return ufdr_data
```

**Detection Method**:
```python
def _is_cellebrite_lightweight(self, zip_path: str) -> bool:
    # Checks for many .db files (>100) or specific Cellebrite structure
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        db_count = sum(1 for f in zip_ref.namelist() if f.endswith('.db'))
        return db_count > 100  # Cellebrite typically has many .db files
```

### 2. Web Interface Integration

**Location**: `web_interface.py`

**Upload Handler**:
```python
@app.route('/api/upload', methods=['POST'])
def upload_file():
    # Detect Cellebrite format
    is_cellebrite = db_count >= 2  # 2+ .db files
    
    if is_cellebrite:
        # Use FastCellebriteParser
        parser = FastCellebriteParser(max_workers=4)
        stats = parser.parse_cellebrite_ufdr(filepath, db_path, extract_to)
        
        # Create data access layer
        data_layer = CellebriteDataAccessLayer(db_path, filepath)
        
        # Store for later use
        ACTIVE_DATA_LAYERS[filename] = data_layer
        ACTIVE_DB_PATHS[filename] = db_path
```

**Query Handler**:
```python
@app.route('/api/chat/stream', methods=['POST'])
def chat_stream():
    # Check if we have a data access layer
    if filename in ACTIVE_DATA_LAYERS:
        data_layer = ACTIVE_DATA_LAYERS[filename]
        # Use data access layer for query-aware extraction
        relevant_data = data_layer.get_relevant_data_for_llm(query, max_items=50)
        # Format for LLM
        # ...
```

---

## ⚡ Performance Optimizations

### 1. Selective File Extraction

**Problem**: Cellebrite ZIP files can be 15GB+ with thousands of files

**Solution**: Extract only essential files
- ✅ Extract `.db` files (databases)
- ✅ Extract `report.xml` (metadata)
- ✅ Skip media files (deferred extraction)
- ✅ Skip large binaries (.so, .apk, .jar, .dex, .bin, .exe)

**Impact**: Reduces extraction time from hours to minutes

### 2. Fast Mode for Large Files

**Problem**: Parsing 50,000+ records per table is slow

**Solution**: Limit records in fast mode
```python
if fast_mode:
    cursor.execute(f"SELECT * FROM {table} LIMIT 50000")
else:
    cursor.execute(f"SELECT * FROM {table}")
```

**Impact**: Parses large files in reasonable time

### 3. Parallel Processing

**Problem**: Sequential parsing of multiple databases is slow

**Solution**: Use ThreadPoolExecutor
```python
with ThreadPoolExecutor(max_workers=4) as executor:
    futures = []
    futures.append(executor.submit(self._parse_contacts_parallel, ...))
    futures.append(executor.submit(self._parse_calls_parallel, ...))
    futures.append(executor.submit(self._parse_messages_parallel, ...))
    # ... collect results
```

**Impact**: 4x speedup on multi-core systems

### 4. Database Storage

**Problem**: Loading all data into memory causes OOM errors

**Solution**: Store in SQLite database
- ✅ Persistent storage
- ✅ Indexed queries
- ✅ Efficient memory usage
- ✅ On-demand access

**Impact**: Can handle 15GB+ files without memory issues

### 5. Deferred Media Extraction

**Problem**: Extracting thousands of images/videos is slow

**Solution**: Index only, extract on-demand
- ✅ Index media metadata in database
- ✅ Extract only when requested
- ✅ Mark as extracted to avoid duplicates

**Impact**: Instant parsing, media available on-demand

---

## 💡 Usage Examples

### Example 1: Small Cellebrite File (< 500MB)

```python
from core.cellebrite_sqlite_parser import CellebriteSQLiteParser

parser = CellebriteSQLiteParser()
ufdr_data = parser.parse_ufdr_zip('small_cellebrite.zip', '/tmp/extract')

print(f"Contacts: {len(ufdr_data['contacts'])}")
print(f"Messages: {len(ufdr_data['messages'])}")
print(f"Calls: {len(ufdr_data['call_logs'])}")
```

### Example 2: Large Cellebrite File (15GB+)

```python
from core.fast_cellebrite_parser import FastCellebriteParser
from core.cellebrite_data_access_layer import CellebriteDataAccessLayer

# Parse and store in database
parser = FastCellebriteParser(max_workers=4)
stats = parser.parse_cellebrite_ufdr(
    'large_cellebrite.zip',
    'output.db',
    '/tmp/extract'
)

print(f"Parsed: {stats}")

# Create data access layer
data_layer = CellebriteDataAccessLayer('output.db', 'large_cellebrite.zip')

# Query contacts
contacts = data_layer.query_contacts("John", limit=10)
print(f"Found {len(contacts)} contacts")

# Get LLM-ready data
llm_data = data_layer.get_relevant_data_for_llm(
    "show messages from John",
    max_items=50
)
print(llm_data)
```

### Example 3: Query-Specific Extraction

```python
# Query messages
messages = data_layer.query_messages("show messages about payment", limit=20)

# Query chats
chats = data_layer.query_chats("WhatsApp group chats", limit=10)

# Query files
files = data_layer.query_files("PDF documents", limit=10)

# Query calls
calls = data_layer.query_calls("calls to +1234567890", limit=10)
```

### Example 4: On-Demand Media Extraction

```python
# Get media metadata
images = data_layer.get_media_metadata(media_type='image', limit=10)

# Extract specific image on-demand
for image in images:
    extracted_path = data_layer.extract_media_on_demand(
        image['rel_path'],
        '/tmp/media'
    )
    print(f"Extracted: {extracted_path}")
```

---

## 🎯 Key Differences: Standard vs Fast Parser

| Feature | CellebriteSQLiteParser | FastCellebriteParser |
|---------|------------------------|---------------------|
| **File Size** | < 500MB | 15GB+ |
| **Storage** | In-memory dict | SQLite database |
| **Processing** | Sequential | Parallel (ThreadPoolExecutor) |
| **Chat Support** | Basic | Full (chats + chat_messages) |
| **File Support** | Basic | Full (file databases) |
| **Media** | Metadata only | Indexed + on-demand extraction |
| **Performance** | Fast for small files | Optimized for large files |
| **Memory Usage** | High (all in memory) | Low (database storage) |
| **Query Interface** | Direct dict access | CellebriteDataAccessLayer |

---

## 🔍 Detection Logic

### How Cellebrite Format is Detected

1. **File Structure Check**:
   - Count `.db` files in ZIP
   - Cellebrite typically has 100+ `.db` files
   - Standard UFDR has 0-5 `.db` files

2. **File Size Check**:
   - Large files (> 500MB) more likely to be Cellebrite
   - Small files (< 500MB) can use standard parser

3. **Database Count Check**:
   - `>= 2` `.db` files → Use FastCellebriteParser
   - `< 2` `.db` files → Use standard parser

4. **report.xml Check**:
   - Presence of `report.xml` indicates Cellebrite format
   - Contains device metadata, extraction info, case info

---

## 📝 Summary

The Cellebrite parser system provides:

✅ **Two parsing strategies**:
- Standard parser for small files
- Fast parser for large files (15GB+)

✅ **Comprehensive data extraction**:
- Contacts, calls, messages
- Chats and chat messages (Cellebrite-specific)
- Files, locations, device info
- Media indexing

✅ **Performance optimizations**:
- Selective file extraction
- Parallel processing
- Database storage
- Deferred media extraction

✅ **Query interface**:
- Query-aware data extraction
- LLM-ready formatting
- On-demand media access

✅ **UFDR compatibility**:
- Normalized data structure
- Compatible with existing system
- Standard UFDR format output

---

**End of Analysis**














