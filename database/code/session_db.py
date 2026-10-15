import sqlite3
import json
import logging
import os
from datetime import datetime

# Security enhancements for encryption
try:
    import sys
    _forensic_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'FORENSIC')
    if _forensic_dir not in sys.path:
        sys.path.insert(0, _forensic_dir)
    from security.security_enhancements import encrypt_sensitive_field, decrypt_sensitive_field
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    # Fallback functions if encryption not available
    def encrypt_sensitive_field(data):
        return data
    def decrypt_sensitive_field(data):
        return data

logger = logging.getLogger(__name__)

# Use absolute path for database to avoid issues with working directory
# Database will be in the FORENSIC directory (original location)
# Get the EVI-SCAN root directory (2 levels up from database/code/)
_DATABASE_CODE_DIR = os.path.dirname(os.path.abspath(__file__))
_DATABASE_DIR = os.path.dirname(_DATABASE_CODE_DIR)
_EVI_SCAN_ROOT = os.path.dirname(_DATABASE_DIR)
FORENSIC_DIR = os.path.join(_EVI_SCAN_ROOT, 'FORENSIC')
DB_PATH = os.path.join(FORENSIC_DIR, 'sessions.db')

def get_db_connection():
    """Create and return database connection"""
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        logger.error(f"Database connection error: {e}")
        return None

def init_session_db():
    """Initialize session database tables
    Returns: (success: bool, error_message: str or None)
    """
    conn = get_db_connection()
    if not conn:
        error_msg = f"Failed to connect to database at {DB_PATH}"
        logger.error(error_msg)
        return False, error_msg
    
    try:
        cur = conn.cursor()
        
        # Cases table - case management
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cases (
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
        """)
        
        # Sessions table - main session metadata
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                case_id TEXT,
                user_id INTEGER,
                title TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                metadata TEXT
            )
        """)
        
        # Migration: Add user_id column to existing sessions table if it doesn't exist
        # This must happen BEFORE creating indexes that depend on user_id
        try:
            # Check if column exists by querying table info
            cur.execute("PRAGMA table_info(sessions)")
            columns = [row[1] for row in cur.fetchall()]  # Column name is at index 1
            
            if 'user_id' not in columns:
                # Column doesn't exist, add it
                cur.execute("ALTER TABLE sessions ADD COLUMN user_id INTEGER")
                logger.info("Added user_id column to sessions table (migration)")
            else:
                logger.debug("user_id column already exists in sessions table")
        except sqlite3.Error as e:
            logger.warning(f"Error checking/adding user_id column: {e}")
        
        # Create index for user_id for faster queries (after ensuring column exists)
        try:
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
        except sqlite3.OperationalError as e:
            logger.warning(f"Could not create user_id index: {e}")
        
        # Chat history table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS chat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
            )
        """)
        
        # Preferences table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS session_preferences (
                session_id TEXT PRIMARY KEY,
                theme TEXT DEFAULT 'dark',
                model_id TEXT,
                sound_enabled INTEGER DEFAULT 0,
                sound_chime TEXT,
                export_format TEXT DEFAULT 'txt',
                other_preferences TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
            )
        """)
        
        # Query history table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS query_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                query TEXT NOT NULL,
                response_summary TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                query_type TEXT,
                metadata TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
            )
        """)
        
        # Uploaded files per session
        cur.execute("""
            CREATE TABLE IF NOT EXISTS session_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
            )
        """)
        
        # Create indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_session ON chat_history(session_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_timestamp ON chat_history(timestamp)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_query_session ON query_history(session_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_query_timestamp ON query_history(timestamp)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_case ON sessions(case_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_last_accessed ON sessions(last_accessed)")
        # Note: idx_sessions_user index is created earlier, right after user_id column migration
        cur.execute("CREATE INDEX IF NOT EXISTS idx_session_files_session ON session_files(session_id)")
        
        conn.commit()
        cur.close()
        conn.close()
        return True, None
    except sqlite3.Error as e:
        error_msg = f"Database error initializing tables: {str(e)}"
        logger.error(error_msg)
        if conn:
            try:
                conn.close()
            except:
                pass
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error initializing database: {str(e)}"
        logger.error(error_msg)
        if conn:
            try:
                conn.close()
            except:
                pass
        return False, error_msg

def create_session(session_id, case_id=None, title=None, metadata=None, user_id=None):
    """Create a new session
    Returns: (success: bool, error_message: str or None)
    """
    conn = get_db_connection()
    if not conn:
        error_msg = f"Failed to connect to database at {DB_PATH}"
        logger.error(error_msg)
        return False, error_msg
    
    try:
        cur = conn.cursor()
        metadata_json = json.dumps(metadata) if metadata else None
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cur.execute("""
            INSERT OR REPLACE INTO sessions (session_id, case_id, user_id, title, metadata, created_at, last_accessed)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (session_id, case_id, user_id, title, metadata_json, current_time, current_time))
        conn.commit()
        cur.close()
        conn.close()
        return True, None
    except sqlite3.Error as e:
        error_msg = f"Database error creating session: {str(e)}"
        logger.error(error_msg)
        if conn:
            try:
                conn.close()
            except:
                pass
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error creating session: {str(e)}"
        logger.error(error_msg)
        if conn:
            try:
                conn.close()
            except:
                pass
        return False, error_msg

def update_session_access(session_id):
    """Update last_accessed timestamp for a session"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cur.execute("""
            UPDATE sessions SET last_accessed = ?
            WHERE session_id = ?
        """, (current_time, session_id))
        conn.commit()
        cur.close()
        conn.close()
        return True
    except sqlite3.Error as e:
        logger.error(f"Error updating session access: {e}")
        return False

def get_session(session_id, user_id=None):
    """Get session by ID, optionally filtered by user_id for security"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cur = conn.cursor()
        if user_id is not None:
            # Filter by user_id to ensure user can only access their own sessions
            cur.execute("SELECT * FROM sessions WHERE session_id = ? AND user_id = ?", (session_id, user_id))
        else:
            cur.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        
        if row:
            sess = dict(row)
            if sess.get('metadata'):
                try:
                    sess['metadata'] = json.loads(sess['metadata'])
                except:
                    sess['metadata'] = {}
            return sess
        return None
    except sqlite3.Error as e:
        logger.error(f"Error getting session: {e}")
        return None

def save_chat_message(session_id, role, content, metadata=None):
    """Save a chat message to history"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        metadata_json = json.dumps(metadata) if metadata else None
        cur.execute("""
            INSERT INTO chat_history (session_id, role, content, metadata)
            VALUES (?, ?, ?, ?)
        """, (session_id, role, content, metadata_json))
        conn.commit()
        cur.close()
        conn.close()
        return True
    except sqlite3.Error as e:
        logger.error(f"Error saving chat message: {e}")
        return False

def get_chat_history(session_id, limit=None):
    """Get chat history for a session"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cur = conn.cursor()
        query = "SELECT * FROM chat_history WHERE session_id = ? ORDER BY timestamp ASC"
        if limit:
            query += f" LIMIT {limit}"
        cur.execute(query, (session_id,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        
        messages = []
        for row in rows:
            msg = dict(row)
            if msg.get('metadata'):
                try:
                    msg['metadata'] = json.loads(msg['metadata'])
                except:
                    msg['metadata'] = {}
            messages.append(msg)
        return messages
    except sqlite3.Error as e:
        logger.error(f"Error getting chat history: {e}")
        return []

def get_chat_history_from_related_sessions(session_id, include_current=True, limit_per_session=50):
    """Get chat history from related sessions (same case) for context continuity.
    
    Args:
        session_id: Current session ID
        include_current: Whether to include current session's history
        limit_per_session: Maximum messages per session (to avoid token bloat)
    
    Returns:
        List of messages from all related sessions, sorted by timestamp
    """
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cur = conn.cursor()
        
        # Get current session to find case_id
        cur.execute("SELECT case_id FROM sessions WHERE session_id = ?", (session_id,))
        session_row = cur.fetchone()
        
        if not session_row:
            cur.close()
            conn.close()
            return []
        
        case_id = session_row['case_id']
        
        # If no case_id, only return current session's history
        if not case_id:
            if include_current:
                return get_chat_history(session_id, limit=limit_per_session)
            return []
        
        # Get all sessions for this case (excluding current if requested)
        if include_current:
            cur.execute("""
                SELECT session_id FROM sessions 
                WHERE case_id = ? 
                ORDER BY last_accessed DESC
            """, (case_id,))
        else:
            cur.execute("""
                SELECT session_id FROM sessions 
                WHERE case_id = ? AND session_id != ?
                ORDER BY last_accessed DESC
            """, (case_id, session_id))
        
        related_sessions = [row['session_id'] for row in cur.fetchall()]
        
        # Collect chat history from all related sessions
        all_messages = []
        for related_session_id in related_sessions:
            cur.execute("""
                SELECT * FROM chat_history 
                WHERE session_id = ? 
                ORDER BY timestamp ASC
                LIMIT ?
            """, (related_session_id, limit_per_session))
            
            rows = cur.fetchall()
            for row in rows:
                msg = dict(row)
                # Add session_id to message for context
                msg['source_session_id'] = related_session_id
                if msg.get('metadata'):
                    try:
                        msg['metadata'] = json.loads(msg['metadata'])
                    except:
                        msg['metadata'] = {}
                all_messages.append(msg)
        
        # Sort all messages by timestamp
        all_messages.sort(key=lambda x: x.get('timestamp', ''))
        
        cur.close()
        conn.close()
        
        logger.info(f"📜 Retrieved {len(all_messages)} messages from {len(related_sessions)} related session(s) for case {case_id}")
        return all_messages
        
    except sqlite3.Error as e:
        logger.error(f"Error getting chat history from related sessions: {e}")
        return []

def clear_chat_history(session_id):
    """Clear chat history for a session"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM chat_history WHERE session_id = ?", (session_id,))
        conn.commit()
        cur.close()
        conn.close()
        return True
    except sqlite3.Error as e:
        logger.error(f"Error clearing chat history: {e}")
        return False

def save_preference(session_id, key, value):
    """Save a preference for a session"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        # Get existing preferences
        cur.execute("SELECT * FROM session_preferences WHERE session_id = ?", (session_id,))
        row = cur.fetchone()
        
        # Standard columns that have their own database columns
        # NOTE: sound_enabled is now stored in other_preferences JSON to avoid SQLite type issues
        standard_columns = ['theme', 'model_id', 'sound_chime', 'export_format']
        
        # Special handling: sound_enabled goes to JSON, not a column
        if key == 'sound_enabled':
            # Store in other_preferences JSON to avoid SQLite type conversion issues
            other_prefs = {}
            if row and row['other_preferences']:
                try:
                    other_prefs = json.loads(row['other_preferences'])
                except:
                    other_prefs = {}
            
            # Convert to boolean for JSON storage (cleaner than int)
            if isinstance(value, bool):
                other_prefs['sound_enabled'] = value
            elif isinstance(value, str):
                other_prefs['sound_enabled'] = value.lower() in ('true', '1', 'yes', 'on')
            else:
                other_prefs['sound_enabled'] = bool(value)
            
            other_prefs_json = json.dumps(other_prefs)
            if row:
                cur.execute("""
                    UPDATE session_preferences 
                    SET other_preferences = ?
                    WHERE session_id = ?
                """, (other_prefs_json, session_id))
            else:
                # Create new row
                cur.execute("""
                    INSERT INTO session_preferences (session_id, theme, model_id, sound_enabled, sound_chime, export_format, other_preferences)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (session_id, 'dark', None, 0, None, 'txt', other_prefs_json))
            logger.info(f"💾 Saved sound_enabled = {other_prefs['sound_enabled']} (bool) in JSON for session {session_id}")
        
        elif key in standard_columns:
            # Update standard column directly
            if row:
                # Update existing row
                cur.execute(f"""
                    UPDATE session_preferences 
                    SET {key} = ?
                    WHERE session_id = ?
                """, (value, session_id))
                logger.info(f"💾 Updated {key} = {value} for session {session_id}")
            else:
                # Create new row with standard column
                defaults = {
                    'theme': 'dark',
                    'model_id': None,
                    'sound_chime': None,
                    'export_format': 'txt'
                }
                defaults[key] = value
                cur.execute("""
                    INSERT INTO session_preferences (session_id, theme, model_id, sound_enabled, sound_chime, export_format)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (session_id, defaults.get('theme', 'dark'), defaults.get('model_id'), 0, defaults.get('sound_chime'), defaults.get('export_format', 'txt')))
        else:
            # Store in other_preferences JSON
            other_prefs = {}
            if row and row['other_preferences']:
                try:
                    other_prefs = json.loads(row['other_preferences'])
                except:
                    other_prefs = {}
            
            other_prefs[key] = value
            other_prefs_json = json.dumps(other_prefs)
            
            if row:
                cur.execute("""
                    UPDATE session_preferences 
                    SET other_preferences = ?
                    WHERE session_id = ?
                """, (other_prefs_json, session_id))
            else:
                cur.execute("""
                    INSERT INTO session_preferences (session_id, other_preferences)
                    VALUES (?, ?)
                """, (session_id, other_prefs_json))
        
        conn.commit()
        cur.close()
        conn.close()
        return True
    except sqlite3.Error as e:
        logger.error(f"Error saving preference: {e}")
        return False

def get_preferences(session_id):
    """Get preferences for a session"""
    conn = get_db_connection()
    if not conn:
        return {}
    
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM session_preferences WHERE session_id = ?", (session_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        
        if row:
            # Convert Row to dict - SQLite Row may return integers as booleans for 0/1 values
            prefs = {}
            for key in row.keys():
                value = row[key]
                # For sound_enabled, we'll handle it specially below
                prefs[key] = value
            logger.debug(f"📋 Raw row from database for session {session_id}")
            
            # Parse other_preferences JSON if it exists
            if prefs.get('other_preferences'):
                try:
                    other_prefs = json.loads(prefs['other_preferences'])
                    # Merge other_preferences into main prefs dict
                    prefs.update(other_prefs)
                except:
                    pass
            # Remove the raw other_preferences key (we've merged it)
            prefs.pop('other_preferences', None)
            
            # Ensure sound_enabled is a boolean (from JSON) or convert legacy integer column
            if 'sound_enabled' in prefs:
                val = prefs['sound_enabled']
                # If it's from JSON, it should already be a boolean
                # If it's from the old INTEGER column, convert it
                if isinstance(val, bool):
                    # Already correct (from JSON)
                    pass
                elif isinstance(val, int):
                    # Legacy integer column - convert to boolean
                    prefs['sound_enabled'] = bool(val)
                elif isinstance(val, str):
                    prefs['sound_enabled'] = val.lower() in ('true', '1', 'yes', 'on')
                else:
                    prefs['sound_enabled'] = bool(val)
                logger.info(f"🔊 Final sound_enabled: {prefs['sound_enabled']} (type: {type(prefs['sound_enabled']).__name__})")
            else:
                # Default to False if not found
                prefs['sound_enabled'] = False
            
            logger.info(f"📋 Final preferences for session {session_id}: sound_enabled={prefs.get('sound_enabled')} (type: {type(prefs.get('sound_enabled')).__name__})")
            return prefs
        return {}
    except sqlite3.Error as e:
        logger.error(f"Error getting preferences: {e}")
        return {}

def save_query(session_id, query, response_summary=None, query_type='chat', metadata=None):
    """Save a query to history"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        metadata_json = json.dumps(metadata) if metadata else None
        cur.execute("""
            INSERT INTO query_history (session_id, query, response_summary, query_type, metadata)
            VALUES (?, ?, ?, ?, ?)
        """, (session_id, query, response_summary, query_type, metadata_json))
        conn.commit()
        cur.close()
        conn.close()
        return True
    except sqlite3.Error as e:
        logger.error(f"Error saving query: {e}")
        return False

def get_query_history(session_id, limit=None):
    """Get query history for a session"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cur = conn.cursor()
        query = "SELECT * FROM query_history WHERE session_id = ? ORDER BY timestamp DESC"
        if limit:
            query += f" LIMIT {limit}"
        cur.execute(query, (session_id,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        
        queries = []
        for row in rows:
            q = dict(row)
            if q.get('metadata'):
                try:
                    q['metadata'] = json.loads(q['metadata'])
                except:
                    q['metadata'] = {}
            queries.append(q)
        return queries
    except sqlite3.Error as e:
        logger.error(f"Error getting query history: {e}")
        return []

def get_sessions_by_case(case_id, user_id=None):
    """Get all sessions for a case, optionally filtered by user_id"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cur = conn.cursor()
        if user_id is not None:
            # Filter by user_id to ensure user only sees their own sessions
            cur.execute("SELECT * FROM sessions WHERE case_id = ? AND user_id = ? ORDER BY last_accessed DESC", (case_id, user_id))
        else:
            cur.execute("SELECT * FROM sessions WHERE case_id = ? ORDER BY last_accessed DESC", (case_id,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        
        sessions = []
        for row in rows:
            sess = dict(row)
            if sess.get('metadata'):
                try:
                    sess['metadata'] = json.loads(sess['metadata'])
                except:
                    sess['metadata'] = {}
            sessions.append(sess)
        return sessions
    except sqlite3.Error as e:
        logger.error(f"Error getting sessions by case: {e}")
        return []

def get_all_sessions(limit=None, user_id=None):
    """Get all sessions, optionally filtered by user_id"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cur = conn.cursor()
        if user_id is not None:
            query = "SELECT * FROM sessions WHERE user_id = ? ORDER BY last_accessed DESC"
            params = (user_id,)
        else:
            query = "SELECT * FROM sessions ORDER BY last_accessed DESC"
            params = ()
        
        if limit:
            query += f" LIMIT {limit}"
        
        cur.execute(query, params)
        rows = cur.fetchall()
        cur.close()
        conn.close()
        
        sessions = []
        for row in rows:
            sess = dict(row)
            if sess.get('metadata'):
                try:
                    sess['metadata'] = json.loads(sess['metadata'])
                except:
                    sess['metadata'] = {}
            sessions.append(sess)
        return sessions
    except sqlite3.Error as e:
        logger.error(f"Error getting all sessions: {e}")
        return []

def create_case(case_id, case_name, evidence_device=None, created_by=None, description=None, status='Active', metadata=None):
    """Create a new case"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        # Encrypt sensitive fields
        if description and ENCRYPTION_AVAILABLE:
            description = encrypt_sensitive_field(description)
        if metadata:
            # Encrypt metadata JSON string
            metadata_json = json.dumps(metadata)
            if ENCRYPTION_AVAILABLE:
                metadata_json = encrypt_sensitive_field(metadata_json)
        else:
            metadata_json = None
        
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Check if case exists
        cur.execute("SELECT case_id FROM cases WHERE case_id = ?", (case_id,))
        exists = cur.fetchone()
        
        if exists:
            # Update existing case
            cur.execute("""
                UPDATE cases
                SET case_name = ?, status = ?, evidence_device = ?, created_by = ?,
                    description = ?, metadata = ?, updated_at = ?
                WHERE case_id = ?
            """, (case_name, status, evidence_device, created_by, description, metadata_json, current_time, case_id))
        else:
            # Insert new case
            cur.execute("""
                INSERT INTO cases (case_id, case_name, status, evidence_device, created_by, description, metadata, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (case_id, case_name, status, evidence_device, created_by, description, metadata_json, current_time, current_time))
        
        conn.commit()
        cur.close()
        conn.close()
        return True
    except sqlite3.Error as e:
        logger.error(f"Error creating case: {e}")
        return False

def get_case(case_id):
    """Get case by ID"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
        row = cur.fetchone()
        
        if row:
            case = dict(row)
            # Decrypt sensitive fields (handle legacy unencrypted data)
            if case.get('description') and ENCRYPTION_AVAILABLE:
                try:
                    # Try to decrypt, but if it fails, keep original (might be legacy unencrypted data)
                    decrypted = decrypt_sensitive_field(case['description'])
                    # If decryption returns None, it means wrong key or corrupted data
                    if decrypted is None:
                        # Wrong encryption key - show error message instead of encrypted data
                        case['description'] = "[ERROR: Could not decrypt description - encryption key mismatch]"
                    elif decrypted != case['description']:
                        # Successfully decrypted (was encrypted)
                        case['description'] = decrypted
                    # If decrypted == original, it was already unencrypted (legacy data)
                except Exception as e:
                    # Keep original if decryption fails (legacy data)
                    logger.debug(f"Description decryption failed (may be legacy unencrypted): {e}")
                    pass
            if case.get('metadata'):
                try:
                    metadata_str = case['metadata']
                    # Try to decrypt if encrypted
                    if ENCRYPTION_AVAILABLE:
                        try:
                            decrypted_meta = decrypt_sensitive_field(metadata_str)
                            # If decryption returns None, it means wrong key
                            if decrypted_meta is None:
                                # Wrong encryption key - use empty dict (warning already logged by decrypt function)
                                metadata_str = '{}'  # Use empty metadata
                            elif decrypted_meta != metadata_str:
                                # Successfully decrypted
                                metadata_str = decrypted_meta
                            # If decrypted == original, it was already unencrypted (legacy data)
                        except Exception as e:
                            logger.debug(f"Metadata decryption failed (may be legacy unencrypted): {e}")
                            pass  # May not be encrypted (legacy data)
                    case['metadata'] = json.loads(metadata_str)
                except Exception as e:
                    logger.warning(f"Could not parse metadata: {e}")
                    case['metadata'] = {}
            
            # Get last_opened from most recent session
            cur.execute("""
                SELECT last_accessed
                FROM sessions
                WHERE case_id = ?
                ORDER BY last_accessed DESC
                LIMIT 1
            """, (case_id,))
            session_row = cur.fetchone()
            if session_row:
                case['last_opened'] = session_row['last_accessed']
            else:
                case['last_opened'] = None
            
            cur.close()
            conn.close()
            return case
        
        cur.close()
        conn.close()
        return None
    except sqlite3.Error as e:
        logger.error(f"Error getting case: {e}")
        return None

def get_all_cases(status_filter=None, user_id=None, created_by=None):
    """Get all cases, optionally filtered by user (created_by)"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cur = conn.cursor()
        # Filter by created_by (username) if provided
        if created_by:
            if status_filter:
                cur.execute("SELECT * FROM cases WHERE created_by = ? AND status = ? ORDER BY updated_at DESC", (created_by, status_filter))
            else:
                cur.execute("SELECT * FROM cases WHERE created_by = ? ORDER BY updated_at DESC", (created_by,))
        elif status_filter:
            cur.execute("SELECT * FROM cases WHERE status = ? ORDER BY updated_at DESC", (status_filter,))
        else:
            cur.execute("SELECT * FROM cases ORDER BY updated_at DESC")
        rows = cur.fetchall()
        
        cases = []
        for row in rows:
            case = dict(row)
            # Decrypt sensitive fields (handle legacy unencrypted data)
            if case.get('description') and ENCRYPTION_AVAILABLE:
                try:
                    # Try to decrypt, but if it fails, keep original (might be legacy unencrypted data)
                    decrypted = decrypt_sensitive_field(case['description'])
                    # If decryption returns None, it means wrong key or corrupted data
                    if decrypted is None:
                        # Wrong encryption key - show error message instead of encrypted data
                        case['description'] = "[ERROR: Could not decrypt description - encryption key mismatch]"
                    elif decrypted != case['description']:
                        # Successfully decrypted (was encrypted)
                        case['description'] = decrypted
                    # If decrypted == original, it was already unencrypted (legacy data)
                except Exception as e:
                    # Keep original if decryption fails (legacy data)
                    logger.debug(f"Description decryption failed (may be legacy unencrypted): {e}")
                    pass
            if case.get('metadata'):
                try:
                    metadata_str = case['metadata']
                    # Try to decrypt if encrypted
                    if ENCRYPTION_AVAILABLE:
                        try:
                            decrypted_meta = decrypt_sensitive_field(metadata_str)
                            # If decryption returns None, it means wrong key
                            if decrypted_meta is None:
                                # Wrong encryption key - use empty dict (warning already logged by decrypt function)
                                metadata_str = '{}'  # Use empty metadata
                            elif decrypted_meta != metadata_str:
                                # Successfully decrypted
                                metadata_str = decrypted_meta
                            # If decrypted == original, it was already unencrypted (legacy data)
                        except Exception as e:
                            logger.debug(f"Metadata decryption failed (may be legacy unencrypted): {e}")
                            pass  # May not be encrypted (legacy data)
                    case['metadata'] = json.loads(metadata_str)
                except Exception as e:
                    logger.warning(f"Could not parse metadata: {e}")
                    case['metadata'] = {}
            
            # Get last_opened from most recent session
            case_id = case['case_id']
            cur.execute("""
                SELECT last_accessed
                FROM sessions
                WHERE case_id = ?
                ORDER BY last_accessed DESC
                LIMIT 1
            """, (case_id,))
            session_row = cur.fetchone()
            if session_row:
                case['last_opened'] = session_row['last_accessed']
            else:
                case['last_opened'] = None
            
            cases.append(case)
        
        cur.close()
        conn.close()
        return cases
    except sqlite3.Error as e:
        logger.error(f"Error getting all cases: {e}")
        return []

def update_case(case_id, **updates):
    """Update case information"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        set_clauses = []
        values = []
        
        for key, value in updates.items():
            # Encrypt sensitive fields
            if key == 'description' and value and ENCRYPTION_AVAILABLE:
                value = encrypt_sensitive_field(value)
            elif key == 'metadata' and isinstance(value, dict):
                metadata_json = json.dumps(value)
                if ENCRYPTION_AVAILABLE:
                    metadata_json = encrypt_sensitive_field(metadata_json)
                values.append(metadata_json)
                set_clauses.append(f"{key} = ?")
                continue
            
            # Append value and set clause for all other fields
            values.append(value)
            set_clauses.append(f"{key} = ?")
        
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        set_clauses.append("updated_at = ?")
        values.append(current_time)
        values.append(case_id)
        
        query = f"UPDATE cases SET {', '.join(set_clauses)} WHERE case_id = ?"
        cur.execute(query, values)
        conn.commit()
        cur.close()
        conn.close()
        return True
    except sqlite3.Error as e:
        logger.error(f"Error updating case: {e}")
        return False

def delete_case(case_id):
    """Delete a case"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"Case {case_id} deleted")
        return True
    except sqlite3.Error as e:
        logger.error(f"Error deleting case: {e}")
        return False

# Session file management functions
def save_session_file(session_id, filename, file_path=None):
    """Save a file record to session_files table"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO session_files (session_id, filename, file_path, is_active)
            VALUES (?, ?, ?, 1)
        """, (session_id, filename, file_path or filename,))
        conn.commit()
        cur.close()
        conn.close()
        return True
    except sqlite3.Error as e:
        logger.error(f"Error saving session file: {e}")
        return False

def get_session_files(session_id):
    """Get all files for a session"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT filename, file_path, uploaded_at, is_active
            FROM session_files
            WHERE session_id = ? AND is_active = 1
            ORDER BY uploaded_at DESC
        """, (session_id,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        
        files = []
        for row in rows:
            files.append({
                'filename': row['filename'],
                'file_path': row['file_path'],
                'uploaded_at': row['uploaded_at'],
                'is_active': row['is_active']
            })
        return files
    except sqlite3.Error as e:
        logger.error(f"Error getting session files: {e}")
        return []

def delete_session_file(session_id, filename):
    """Mark a file as inactive for a session (soft delete)"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE session_files
            SET is_active = 0
            WHERE session_id = ? AND filename = ?
        """, (session_id, filename))
        conn.commit()
        cur.close()
        conn.close()
        return True
    except sqlite3.Error as e:
        logger.error(f"Error deleting session file: {e}")
        return False

def clear_session_files(session_id):
    """Mark all files as inactive for a session"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE session_files
            SET is_active = 0
            WHERE session_id = ?
        """, (session_id,))
        conn.commit()
        cur.close()
        conn.close()
        return True
    except sqlite3.Error as e:
        logger.error(f"Error clearing session files: {e}")
        return False

# Initialize database on import
init_session_db()
