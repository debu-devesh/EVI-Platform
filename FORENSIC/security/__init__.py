"""
Security Module for EVI
Contains all security-related functionality including encryption, RBAC, and audit logging
"""

from .security_enhancements import (
    encryption, audit_logger, RBAC,
    audit_action, encrypt_sensitive_field, decrypt_sensitive_field
)

# require_permission is a method of RBAC class, access it via RBAC.require_permission
require_permission = RBAC.require_permission

# Create stub functions for missing imports (if needed elsewhere)
def require_case_access(f):
    """Stub for require_case_access decorator"""
    return f

def configure_secure_sessions(app):
    """Stub for configure_secure_sessions"""
    pass

def sanitize_input(data, max_length=None):
    """Sanitize input data by trimming and limiting length"""
    if data is None:
        return None
    if not isinstance(data, str):
        data = str(data)
    # Trim whitespace
    data = data.strip()
    # Limit length if specified
    if max_length and len(data) > max_length:
        data = data[:max_length]
    return data

def calculate_file_hash(filepath):
    """Stub for calculate_file_hash"""
    return None

def create_audit_table():
    """Create audit table in session database"""
    # This is handled by AuditLogger._init_db() automatically
    # But we provide this function for explicit initialization
    if audit_logger:
        audit_logger._init_db()

__all__ = [
    'encryption',
    'audit_logger',
    'RBAC',
    'require_permission',
    'require_case_access',
    'audit_action',
    'configure_secure_sessions',
    'sanitize_input',
    'encrypt_sensitive_field',
    'decrypt_sensitive_field',
    'create_audit_table',
    'calculate_file_hash'
]


