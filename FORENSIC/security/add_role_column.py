#!/usr/bin/env python3
"""
Migration script to add role column to users table
Run this once to enable RBAC functionality
"""
import sqlite3
import os
import sys

# Get authentication database path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FORENSIC_DIR = os.path.dirname(BASE_DIR)
EVI_SCAN_DIR = os.path.dirname(FORENSIC_DIR)
AUTH_DB_PATH = os.path.join(EVI_SCAN_DIR, 'Authentication', 'evi_scan.db')

def add_role_column():
    """Add role column to users table if it doesn't exist"""
    if not os.path.exists(AUTH_DB_PATH):
        print(f"Error: Database not found at {AUTH_DB_PATH}")
        return False
    
    try:
        conn = sqlite3.connect(AUTH_DB_PATH)
        cur = conn.cursor()
        
        # Check if role column exists
        cur.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cur.fetchall()]
        
        if 'role' in columns:
            print("Role column already exists in users table")
        else:
            # Add role column
            cur.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'investigator'")
            conn.commit()
            print("✓ Role column added successfully")
            
            # Set first user as admin
            cur.execute("UPDATE users SET role = 'admin' WHERE id = 1")
            conn.commit()
            print("✓ First user set as admin")
            
            # Set all other users as investigator (default)
            cur.execute("UPDATE users SET role = 'investigator' WHERE role IS NULL")
            conn.commit()
            print("✓ All users set as investigator by default")
        
        cur.close()
        conn.close()
        return True
    except sqlite3.Error as e:
        print(f"Error adding role column: {e}")
        return False

if __name__ == '__main__':
    print("=" * 50)
    print("Adding Role Column to Users Table")
    print("=" * 50)
    print()
    
    if add_role_column():
        print()
        print("=" * 50)
        print("Migration completed successfully!")
        print("=" * 50)
    else:
        print()
        print("=" * 50)
        print("Migration failed!")
        print("=" * 50)
        sys.exit(1)

