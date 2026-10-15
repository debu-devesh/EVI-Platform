# Database - Complete Documentation

This folder contains all database-related files, documentation, and database files for EVI.

## 📁 Folder Structure

```
database/
├── README.md (this file)
├── code/          # Database implementation files
├── docs/          # Database documentation
└── data/          # Database files (.db)
```

## 💻 Code Files

### 1. **session_db.py**
**Location**: `FORENSIC/session_db.py` (original)

**Purpose**: Main database module for EVI session management

**Features**:
- SQLite database connection and management
- Session persistence (create, get, update, delete)
- Chat history storage and retrieval
- Case management (create, get, update, delete)
- Session preferences storage
- Query history tracking
- Uploaded files tracking
- Cross-session context loading

**Key Functions**:
- `init_session_db()` - Initialize database tables
- `create_session()` - Create new session
- `get_session()` - Get session by ID
- `save_chat_message()` - Save chat message
- `get_chat_history()` - Get all messages for session
- `get_chat_history_from_related_sessions()` - Cross-session context
- `create_case()` - Create new case
- `get_case()` - Get case by ID
- `get_all_cases()` - List all cases
- `update_case()` - Update case information
- `delete_case()` - Delete case

**Database Schema**:
- `cases` - Case management
- `sessions` - Session management
- `chat_history` - Chat messages
- `session_preferences` - User preferences
- `query_history` - Query tracking
- `uploaded_files` - File tracking
- `session_files` - Session-file relationships

### 2. **setup_database.py**
**Location**: `Authentication/setup_database.py` (original)

**Purpose**: Database setup script for authentication system

**Features**:
- PostgreSQL database initialization
- Table creation for authentication
- User management tables
- Database connection configuration

**Note**: This is for the authentication system (separate from main EVI database)

## 📚 Documentation

For comprehensive database documentation, see:
- **PROJECT_ANALYSIS.md** (root directory) - Complete technical documentation including database schema
- **README.md** (root directory) - Main project documentation

## 💾 Database Files

### 1. **sessions.db**
**Location**: `FORENSIC/sessions.db` (original)

**Type**: SQLite database

**Purpose**: Main database for EVI
- Stores all sessions
- Chat history
- Cases
- Preferences
- Query history
- Uploaded files metadata

**Tables**:
- `cases` - Case information
- `sessions` - Session information
- `chat_history` - All chat messages
- `session_preferences` - User preferences per session
- `query_history` - All queries asked
- `uploaded_files` - UFDR file metadata
- `session_files` - Session-file relationships

### 2. **evi_scan.db**
**Location**: `Authentication/evi_scan.db` (original)

**Type**: SQLite database

**Purpose**: Authentication system database
- User accounts
- Authentication data
- Login sessions

**Note**: Separate from main EVI database

## 🔗 Database Relationships

```
Case (1) ──→ (Many) Sessions
  │
  └── Each Session has:
      ├── Chat History (Many messages)
      ├── Preferences (Theme, model, etc.)
      ├── Query History (All queries)
      └── Uploaded Files (UFDR files)
```

## 📊 Database Schema

### Cases Table
```sql
CREATE TABLE cases (
    case_id TEXT PRIMARY KEY,
    case_name TEXT NOT NULL,
    status TEXT DEFAULT 'Active',
    evidence_device TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT,
    description TEXT,
    metadata TEXT
)
```

### Sessions Table
```sql
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    case_id TEXT,
    title TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active INTEGER DEFAULT 1,
    metadata TEXT
)
```

### Chat History Table
```sql
CREATE TABLE chat_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata TEXT
)
```

### Session Preferences Table
```sql
CREATE TABLE session_preferences (
    session_id TEXT PRIMARY KEY,
    preferences TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

### Query History Table
```sql
CREATE TABLE query_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    query TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata TEXT
)
```

### Uploaded Files Table
```sql
CREATE TABLE uploaded_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    file_path TEXT,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata TEXT
)
```

### Session Files Table
```sql
CREATE TABLE session_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    file_path TEXT,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

## 🚀 Usage

### Initialization
```python
from session_db import init_session_db

# Initialize database (creates tables if they don't exist)
success, error = init_session_db()
if not success:
    print(f"Error: {error}")
```

### Creating a Session
```python
from session_db import create_session

session_id = "unique-session-id"
case_id = "C-2025-ABC"
title = "Investigation Session"

success, error = create_session(session_id, case_id=case_id, title=title)
```

### Saving Chat Messages
```python
from session_db import save_chat_message

save_chat_message(session_id, "user", "Hello, analyze this case")
save_chat_message(session_id, "assistant", "I'll help you analyze...")
```

### Getting Chat History
```python
from session_db import get_chat_history

history = get_chat_history(session_id)
for msg in history:
    print(f"{msg['role']}: {msg['content']}")
```

### Cross-Session Context
```python
from session_db import get_chat_history_from_related_sessions

# Get chat history from all sessions in the same case
all_history = get_chat_history_from_related_sessions(session_id)
```

## 🔧 Database Configuration

### SQLite (Default)
- **File**: `sessions.db`
- **Location**: `FORENSIC/` directory
- **Connection**: Automatic via `session_db.py`
- **Thread Safety**: `check_same_thread=False`

### PostgreSQL (Authentication)
- **Config**: Environment variables
- **Host**: `DB_HOST` (default: localhost)
- **Database**: `DB_NAME` (default: evi_scan_db)
- **User**: `DB_USER` (default: postgres)
- **Password**: `DB_PASSWORD` (default: postgres)
- **Port**: `DB_PORT` (default: 5432)

## 📝 Notes

- **Database files** (`.db`) are copies - originals remain in their original locations
- **Code files** are copies - originals remain functional
- **Documentation** is organized here for easy reference
- All database operations use SQLite for main EVI functionality
- PostgreSQL is only used for authentication system

## 🔍 Related Files

- `FORENSIC/web_interface.py` - Uses `session_db.py` for session management
- `FORENSIC/templates/case_manager/case_manager.html` - Case Manager UI
- `Authentication/app.py` - Authentication system

## 🧪 Testing

To test database functionality:
1. Initialize database: `init_session_db()`
2. Create a test session
3. Save test messages
4. Retrieve chat history
5. Verify cross-session context loading

---

**Last Updated**: After database organization
**Status**: ✅ All database files organized






