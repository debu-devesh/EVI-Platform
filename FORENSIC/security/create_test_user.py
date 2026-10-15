#!/usr/bin/env python3
"""
Create a test user for EVI
Run this script to create a default admin user
"""
import sqlite3
import bcrypt
import os
import sys

# Get authentication database path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FORENSIC_DIR = os.path.dirname(BASE_DIR)
EVI_SCAN_DIR = os.path.dirname(FORENSIC_DIR)
AUTH_DB_PATH = os.path.join(EVI_SCAN_DIR, 'Authentication', 'evi_scan.db')

def create_test_user():
    """Create a test user if database exists"""
    if not os.path.exists(AUTH_DB_PATH):
        print(f"Error: Database not found at {AUTH_DB_PATH}")
        print("Please run the application first to initialize the database.")
        return False
    
    try:
        conn = sqlite3.connect(AUTH_DB_PATH)
        cur = conn.cursor()
        
        # Check if users table exists
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not cur.fetchone():
            print("Users table does not exist. Initializing database...")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active INTEGER DEFAULT 1,
                    role TEXT DEFAULT 'investigator'
                )
            """)
            conn.commit()
            print("✓ Users table created")
        
        # Check if role column exists
        cur.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cur.fetchall()]
        if 'role' not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'investigator'")
            conn.commit()
            print("✓ Role column added")
        
        # Check if test user already exists
        cur.execute("SELECT id FROM users WHERE email = ?", ('admin@eviscan.com',))
        existing = cur.fetchone()
        
        if existing:
            print("Test user already exists!")
            print("Email: admin@eviscan.com")
            print("Password: Admin@123")
            print("\nYou can use these credentials to login.")
            cur.close()
            conn.close()
            return True
        
        # Create test user
        password = "Admin@123"  # Default password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        cur.execute("""
            INSERT INTO users (first_name, last_name, email, username, password_hash, role)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ('Admin', 'User', 'admin@eviscan.com', 'admin', password_hash, 'admin'))
        
        user_id = cur.lastrowid
        conn.commit()
        cur.close()
        conn.close()
        
        print("=" * 50)
        print("Test User Created Successfully!")
        print("=" * 50)
        print(f"User ID: {user_id}")
        print("Email: admin@eviscan.com")
        print("Username: admin")
        print("Password: Admin@123")
        print("Role: admin")
        print("=" * 50)
        print("\nYou can now login with these credentials.")
        return True
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == '__main__':
    print("=" * 50)
    print("Creating Test User for EVI")
    print("=" * 50)
    print()
    
    if create_test_user():
        print("\n✓ Done!")
    else:
        print("\n✗ Failed!")
        sys.exit(1)

