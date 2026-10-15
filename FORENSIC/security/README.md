# Security Module

This folder contains all security-related functionality for EVI.

## Structure

```
security/
├── __init__.py                    # Module initialization
├── security_enhancements.py      # Core security features (encryption, RBAC, audit logging)
├── set_user_role.py              # Script to set user roles
├── add_role_column.py            # Database migration for RBAC
├── create_test_user.py            # Create test admin user
├── templates/
│   └── audit_logs.html           # Audit log viewer template
└── docs/
    ├── SECURITY_IMPLEMENTATION_SUMMARY.md
    ├── SECURITY_IMPLEMENTATION.md
    ├── SECURITY_CHECKLIST.md
    └── QUICK_SECURITY_SETUP.md
```

## Features

### 1. **Encryption**
- File encryption (AES-256)
- Field-level encryption for sensitive database fields
- File integrity checks (SHA-256)

### 2. **Audit Logging**
- Complete chain of custody tracking
- All security-relevant actions logged
- Viewable via `/audit-logs` route

### 3. **Role-Based Access Control (RBAC)**
- Admin, Investigator, Viewer, Auditor roles
- Permission-based access control
- Case-level access restrictions

## Usage

### Setting User Roles
```bash
# Using batch file (from FORENSIC directory)
cd security
set_user_role.bat 4 admin

# Using Python script
python security\set_user_role.py 4 admin
```

### Creating Test User
```bash
python security\create_test_user.py
```

### Database Migration
```bash
python security\add_role_column.py
```

## Import in Code

```python
from security.security_enhancements import (
    encryption, audit_logger, RBAC, require_permission,
    require_case_access, audit_action, configure_secure_sessions,
    sanitize_input, encrypt_sensitive_field, decrypt_sensitive_field,
    create_audit_table, calculate_file_hash
)
```


