#!/usr/bin/env python3
"""
Set user role in database
Usage: python set_user_role.py <user_id> <role>
Roles: admin, investigator, viewer, auditor
"""
import sqlite3
import os
import sys

# Get authentication database path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FORENSIC_DIR = os.path.dirname(BASE_DIR)
EVI_SCAN_DIR = os.path.dirname(FORENSIC_DIR)
AUTH_DB_PATH = os.path.join(EVI_SCAN_DIR, 'Authentication', 'evi_scan.db')

def set_user_role(user_id, role):
    """Set user role"""
    if role not in ['admin', 'investigator', 'viewer', 'auditor']:
        print(f"Error: Invalid role '{role}'. Must be one of: admin, investigator, viewer, auditor")
        return False
    
    if not os.path.exists(AUTH_DB_PATH):
        print(f"Error: Database not found at {AUTH_DB_PATH}")
        return False
    
    try:
        conn = sqlite3.connect(AUTH_DB_PATH)
        cur = conn.cursor()
        
        # Check if role column exists
        cur.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cur.fetchall()]
        
        if 'role' not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'investigator'")
            conn.commit()
            print("✓ Role column added")
        
        # Check if user exists
        cur.execute("SELECT id, email, username, role FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        
        if not user:
            print(f"Error: User with ID {user_id} not found")
            cur.close()
            conn.close()
            return False
        
        old_role = user[3] if len(user) > 3 else 'investigator'
        
        # Update user role
        cur.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        conn.commit()
        
        # Log role change to audit logs
        try:
            # Get sessions database path
            _database_code_path = os.path.join(FORENSIC_DIR, 'database', 'code')
            if _database_code_path not in sys.path:
                sys.path.insert(0, _database_code_path)
            from session_db import get_db_connection
            
            sessions_conn = get_db_connection()
            if sessions_conn:
                sessions_cur = sessions_conn.cursor()
                # Check if audit_logs table exists
                sessions_cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_logs'")
                if sessions_cur.fetchone():
                    import json
                    from datetime import datetime
                    sessions_cur.execute("""
                        INSERT INTO audit_logs (user_id, action, resource, ip_address, 
                                              user_agent, success, details, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        user_id, 'role_changed', f"user_{user_id}", '127.0.0.1',
                        'CLI/set_user_role.py', True,
                        json.dumps({
                            'target_user_id': user_id,
                            'target_email': user[1],
                            'target_username': user[2],
                            'old_role': old_role,
                            'new_role': role,
                            'changed_by': 'system_cli'
                        }),
                        datetime.now()
                    ))
                    sessions_conn.commit()
                sessions_cur.close()
                sessions_conn.close()
        except Exception as e:
            # Don't fail if audit logging fails, just print warning
            print(f"Warning: Could not log role change to audit logs: {e}")
        
        cur.close()
        conn.close()
        
        print("=" * 50)
        print("User Role Updated Successfully!")
        print("=" * 50)
        print(f"User ID: {user_id}")
        print(f"Email: {user[1]}")
        print(f"Username: {user[2]}")
        print(f"New Role: {role}")
        print("=" * 50)
        return True
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python set_user_role.py <user_id> <role>")
        print("Roles: admin, investigator, viewer, auditor")
        print("\nExample: python set_user_role.py 4 admin")
        sys.exit(1)
    
    user_id = int(sys.argv[1])
    role = sys.argv[2].lower()
    
    if set_user_role(user_id, role):
        print("\n✓ Done!")
    else:
        print("\n✗ Failed!")
        sys.exit(1)

