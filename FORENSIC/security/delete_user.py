#!/usr/bin/env python3
"""
Delete or deactivate a user in the database
Usage: python delete_user.py <user_id> [--permanent]
       python delete_user.py <user_id> [--deactivate] (default)
"""
import sqlite3
import os
import sys

# Get authentication database path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FORENSIC_DIR = os.path.dirname(BASE_DIR)
EVI_SCAN_DIR = os.path.dirname(FORENSIC_DIR)
AUTH_DB_PATH = os.path.join(EVI_SCAN_DIR, 'Authentication', 'evi_scan.db')

def delete_user(user_id, permanent=False):
    """Delete or deactivate a user"""
    if not os.path.exists(AUTH_DB_PATH):
        print(f"Error: Database not found at {AUTH_DB_PATH}")
        return False
    
    try:
        conn = sqlite3.connect(AUTH_DB_PATH)
        cur = conn.cursor()
        
        # Check if user exists
        cur.execute("SELECT id, email, username, role, is_active FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        
        if not user:
            print(f"Error: User with ID {user_id} not found")
            cur.close()
            conn.close()
            return False
        
        user_email = user[1]
        user_username = user[2]
        user_role = user[3]
        is_active = user[4]
        
        # Prevent deleting yourself
        print(f"Found user: ID={user_id}, Email={user_email}, Username={user_username}, Role={user_role}, Active={bool(is_active)}")
        
        if permanent:
            # Hard delete - permanently remove from database
            confirm = input(f"\n⚠️  WARNING: This will PERMANENTLY DELETE user {user_email} (ID: {user_id}).\n"
                          f"   This action cannot be undone!\n"
                          f"   Type 'DELETE' to confirm: ")
            
            if confirm != 'DELETE':
                print("Deletion cancelled.")
                cur.close()
                conn.close()
                return False
            
            cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            print(f"✓ User {user_email} (ID: {user_id}) permanently deleted from database")
        else:
            # Soft delete - deactivate user
            if not is_active:
                print(f"User {user_email} (ID: {user_id}) is already deactivated")
                cur.close()
                conn.close()
                return True
            
            cur.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
            conn.commit()
            print(f"✓ User {user_email} (ID: {user_id}) deactivated (soft delete)")
            print(f"   User can no longer log in, but data is preserved")
        
        cur.close()
        conn.close()
        return True
    except sqlite3.Error as e:
        print(f"Error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False

if __name__ == '__main__':
    print("=" * 50)
    print("  EVI - Delete User")
    print("=" * 50)
    print()
    
    if len(sys.argv) < 2:
        print("Usage: python delete_user.py <user_id> [--permanent]")
        print()
        print("Options:")
        print("  --permanent   Permanently delete user (cannot be undone)")
        print("  --deactivate   Deactivate user (default, can be reactivated)")
        print()
        print("Examples:")
        print("  python delete_user.py 5              # Deactivate user ID 5")
        print("  python delete_user.py 5 --deactivate # Same as above")
        print("  python delete_user.py 5 --permanent  # Permanently delete user ID 5")
        print()
        sys.exit(1)
    
    user_id = sys.argv[1]
    
    try:
        user_id = int(user_id)
    except ValueError:
        print(f"Error: Invalid user ID '{user_id}'. Must be a number.")
        sys.exit(1)
    
    # Check for permanent flag
    permanent = '--permanent' in sys.argv
    
    success = delete_user(user_id, permanent=permanent)
    
    if success:
        print()
        print("=" * 50)
        print("Operation completed successfully!")
        print("=" * 50)
        sys.exit(0)
    else:
        print()
        print("=" * 50)
        print("Operation failed!")
        print("=" * 50)
        sys.exit(1)

