#!/usr/bin/env python3
"""
Security Enhancements Module
Provides encryption, audit logging, and RBAC functionality
"""

import os
import logging
import json
from datetime import datetime
from functools import wraps
from flask import session, request, redirect, url_for, flash

try:
    from cryptography.fernet import Fernet
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    Fernet = None

logger = logging.getLogger(__name__)

# ============================================================================
# 1. ENCRYPTION
# ============================================================================

class DataEncryption:
    """Handle encryption/decryption of sensitive data"""
    
    def __init__(self):
        self._decryption_warning_logged = False  # Track if we've already warned about wrong key
        # Get encryption key from environment variable
        key = os.environ.get('ENCRYPTION_KEY')
        
        if not key:
            # Try to load from persistent key file
            key_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.encryption_key')
            if os.path.exists(key_file):
                try:
                    with open(key_file, 'rb') as f:
                        key = f.read()
                    logger.info("✅ Loaded encryption key from persistent storage")
                except Exception as e:
                    logger.warning(f"⚠️  Could not load encryption key from file: {e}")
                    key = None
            
            # Generate new key if still not available
            if not key:
                key = Fernet.generate_key()
                # Save key to file for persistence across restarts
                try:
                    key_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.encryption_key')
                    with open(key_file, 'wb') as f:
                        f.write(key)
                    # Set restrictive permissions (owner read/write only)
                    os.chmod(key_file, 0o600)
                    logger.warning("⚠️  Generated new encryption key and saved to .encryption_key file")
                    logger.warning("⚠️  IMPORTANT: Backup this key file! If lost, encrypted data cannot be recovered!")
                except Exception as e:
                    logger.error(f"❌ Could not save encryption key to file: {e}")
                    logger.warning("⚠️  Encryption key will change on each restart - encrypted data may become unrecoverable!")
        else:
            key = key.encode() if isinstance(key, str) else key
        
        self.cipher = Fernet(key)
    
    def encrypt(self, data: str) -> str:
        """Encrypt sensitive data"""
        if not data:
            return data
        try:
            return self.cipher.encrypt(data.encode()).decode()
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            return data
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not encrypted_data:
            return encrypted_data
        try:
            return self.cipher.decrypt(encrypted_data.encode()).decode()
        except Exception as e:
            # Check if this is a signature mismatch (wrong key) vs invalid token (not encrypted)
            error_type = type(e).__name__
            if "InvalidSignature" in error_type or "InvalidToken" in error_type:
                # Check if data looks like encrypted data (base64-like, starts with gAAAAA)
                if encrypted_data.startswith('gAAAAA') or len(encrypted_data) > 50:
                    # Only log warning once per session to avoid spam
                    if not self._decryption_warning_logged:
                        logger.warning("⚠️  Decryption failed for some data - encryption key mismatch detected.")
                        logger.warning("   This usually means data was encrypted with a different key (legacy data).")
                        logger.warning("   Affected data will show error messages. New data will use the current key.")
                        self._decryption_warning_logged = True
                    # Return None to indicate decryption failure (caller will handle gracefully)
                    return None
                else:
                    # Data doesn't look encrypted, probably legacy unencrypted data
                    return encrypted_data
            else:
                # Other decryption errors - return original data (might be unencrypted)
                return encrypted_data

# Global encryption instance
encryption = DataEncryption()

# ============================================================================
# 2. AUDIT LOGGING
# ============================================================================

class AuditLogger:
    """Log security-relevant actions for chain of custody"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Use the same database as session_db (sessions.db in FORENSIC directory)
            # This ensures audit logs are in the same database that the audit logs view reads from
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            # session_db uses: FORENSIC/sessions.db
            db_path = os.path.join(base_dir, 'sessions.db')
            logger.info(f"AuditLogger initialized with database: {db_path}")
        
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize audit log database table"""
        import sqlite3
        try:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cur = conn.cursor()
            
            # Create table matching the schema used in session_db
            # Note: SQLite doesn't have native BOOLEAN, use INTEGER (0/1)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT,
                    resource TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    success INTEGER,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
            conn.close()
            logger.info(f"✅ Audit logs table initialized in {self.db_path}")
        except Exception as e:
            logger.error(f"❌ Failed to initialize audit logs table: {e}", exc_info=True)
    
    def log_action(self, action: str, resource: str = None, success: bool = True, 
                   details: dict = None, user_id: str = None):
        """Log a security-relevant action"""
        import sqlite3
        from flask import session, request
        
        try:
            # Get user_id from session if not provided
            try:
                user_id = user_id or session.get('user_id', 'unknown')
            except RuntimeError:
                # Session not available (outside request context)
                user_id = user_id or 'unknown'
            
            # Get IP address
            try:
                ip_address = request.remote_addr if request else None
            except RuntimeError:
                ip_address = None
            
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cur = conn.cursor()
            
            # Ensure table exists (in case it wasn't created yet)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT,
                    resource TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    success INTEGER,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cur.execute("""
                INSERT INTO audit_logs (timestamp, action, user_id, resource, success, details, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                action,
                str(user_id),
                resource,
                1 if success else 0,  # SQLite uses INTEGER for boolean
                json.dumps(details) if details else None,
                ip_address
            ))
            
            conn.commit()
            conn.close()
            logger.debug(f"✅ Audit log written: action={action}, user_id={user_id}, success={success}")
        except Exception as e:
            logger.error(f"❌ Failed to write audit log: {e}", exc_info=True)

# Global audit logger instance
audit_logger = AuditLogger()

# ============================================================================
# 3. ROLE-BASED ACCESS CONTROL (RBAC)
# ============================================================================

class RBAC:
    """Role-Based Access Control"""
    
    ROLES = {
        'admin': ['create_case', 'edit_case', 'delete_case', 'view_all_cases', 
                  'assign_investigator', 'view_audit_logs', 'manage_users'],
        'investigator': ['create_case', 'edit_own_case', 'delete_case', 'view_assigned_cases', 
                        'upload_files', 'create_session'],
        'viewer': ['view_assigned_cases'],
        'auditor': ['view_audit_logs', 'view_all_cases']
    }
    
    @staticmethod
    def get_user_role(user_id: int = None) -> str:
        """Get user's role from database"""
        import sqlite3
        from flask import session
        
        if user_id is None:
            user_id = session.get('user_id')
        
        if not user_id:
            logger.warning("No user_id provided or in session, returning default role 'viewer'")
            return 'viewer'  # Default role
        
        # Ensure user_id is an integer (session might store it as string)
        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            logger.warning(f"Invalid user_id type: {user_id} (type: {type(user_id)})")
            return 'investigator'  # Default on invalid type
        
        # Get role from users table
        # Use the same database path as web_interface.py
        # security_enhancements.py is in: EVI-SCAN/FORENSIC/security/security_enhancements.py
        # Database is in: EVI-SCAN/Authentication/evi_scan.db
        # Go up 2 levels from security/ to get to FORENSIC/, then up 1 more to get to EVI-SCAN/
        current_file = os.path.abspath(__file__)
        # current_file: .../EVI-SCAN/FORENSIC/security/security_enhancements.py
        security_dir = os.path.dirname(current_file)  # .../EVI-SCAN/FORENSIC/security/
        forensic_dir = os.path.dirname(security_dir)  # .../EVI-SCAN/FORENSIC/
        evi_scan_dir = os.path.dirname(forensic_dir)  # .../EVI-SCAN/
        auth_db = os.path.join(evi_scan_dir, 'Authentication', 'evi_scan.db')
        
        logger.debug(f"Calculated auth_db path: {auth_db} (from {current_file})")
        
        logger.debug(f"Getting user role for user_id={user_id} from database: {auth_db}")
        
        try:
            if not os.path.exists(auth_db):
                logger.warning(f"Auth database not found at {auth_db}, returning default role 'investigator'")
                return 'investigator'
            
            conn = sqlite3.connect(auth_db)
            cur = conn.cursor()
            
            # Check if role column exists
            cur.execute("PRAGMA table_info(users)")
            columns = [col[1] for col in cur.fetchall()]
            
            if 'role' in columns:
                cur.execute("SELECT role FROM users WHERE id = ?", (user_id,))
                result = cur.fetchone()
                role = result[0] if result else 'investigator'
                logger.debug(f"User {user_id} has role: {role}")
            else:
                logger.warning(f"Role column not found in users table, returning default role 'investigator'")
                role = 'investigator'  # Default if column doesn't exist
            
            conn.close()
            return role
        except Exception as e:
            logger.error(f"Error getting user role from {auth_db}: {e}", exc_info=True)
            return 'investigator'  # Default on error
    
    @staticmethod
    def has_permission(permission: str, user_id: int = None) -> bool:
        """Check if user has a specific permission"""
        # Ensure user_id is an integer if provided
        if user_id is not None:
            try:
                user_id = int(user_id)
            except (ValueError, TypeError):
                logger.warning(f"Invalid user_id type in has_permission: {user_id} (type: {type(user_id)})")
                return False  # Deny on invalid type
        
        role = RBAC.get_user_role(user_id)
        return permission in RBAC.ROLES.get(role, [])
    
    @staticmethod
    def require_permission(permission: str):
        """Decorator to require a specific permission"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if not RBAC.has_permission(permission):
                    flash('🔒 Access Denied: You do not have permission to perform this action.', 'error')
                    return redirect(url_for('case_manager'))
                return f(*args, **kwargs)
            return decorated_function
        return decorator

# ============================================================================
# 4. HELPER FUNCTIONS
# ============================================================================

def encrypt_sensitive_field(data: str) -> str:
    """Encrypt a sensitive field"""
    if not ENCRYPTION_AVAILABLE or not encryption:
        return data
    return encryption.encrypt(data)

def decrypt_sensitive_field(encrypted_data: str) -> str:
    """Decrypt a sensitive field"""
    if not ENCRYPTION_AVAILABLE or not encryption:
        return encrypted_data
    return encryption.decrypt(encrypted_data)

def audit_action(action: str, resource: str = None):
    """Decorator to audit an action"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            result = f(*args, **kwargs)
            if audit_logger:
                audit_logger.log_action(action, resource=resource, success=True)
            return result
        return decorated_function
    return decorator

# Check if security features are available
SECURITY_AVAILABLE = ENCRYPTION_AVAILABLE and encryption is not None
