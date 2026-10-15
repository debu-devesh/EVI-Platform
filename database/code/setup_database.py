"""
Database Setup Script for EVI
Run this script to initialize the PostgreSQL database
"""
import psycopg2
import os
import sys

# Database Configuration
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'database': os.environ.get('DB_NAME', 'evi_scan_db'),
    'user': os.environ.get('DB_USER', 'postgres'),
    'password': os.environ.get('DB_PASSWORD', 'postgres'),
    'port': os.environ.get('DB_PORT', '5432')
}

def create_database():
    """Create the database if it doesn't exist"""
    # Connect to default postgres database
    config = DB_CONFIG.copy()
    config['database'] = 'postgres'
    
    try:
        conn = psycopg2.connect(**config)
        conn.autocommit = True
        cur = conn.cursor()
        
        # Check if database exists
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB_CONFIG['database'],))
        exists = cur.fetchone()
        
        if not exists:
            print(f"Creating database '{DB_CONFIG['database']}'...")
            cur.execute(f"CREATE DATABASE {DB_CONFIG['database']}")
            print(f"Database '{DB_CONFIG['database']}' created successfully!")
        else:
            print(f"Database '{DB_CONFIG['database']}' already exists.")
        
        cur.close()
        conn.close()
        return True
    except psycopg2.Error as e:
        print(f"Error creating database: {e}")
        return False

def init_tables():
    """Initialize database tables"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        
        # Create users table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                first_name VARCHAR(100) NOT NULL,
                last_name VARCHAR(100) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                username VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        """)
        
        # Create login_logs table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS login_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                email VARCHAR(255),
                login_attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN,
                ip_address VARCHAR(45)
            )
        """)
        
        conn.commit()
        cur.close()
        conn.close()
        
        print("Database tables initialized successfully!")
        return True
    except psycopg2.Error as e:
        print(f"Error initializing tables: {e}")
        return False

if __name__ == '__main__':
    print("=" * 50)
    print("EVI Database Setup")
    print("=" * 50)
    print()
    
    print("Step 1: Creating database...")
    if not create_database():
        print("Failed to create database. Please check your PostgreSQL connection.")
        sys.exit(1)
    
    print()
    print("Step 2: Initializing tables...")
    if not init_tables():
        print("Failed to initialize tables.")
        sys.exit(1)
    
    print()
    print("=" * 50)
    print("Database setup completed successfully!")
    print("=" * 50)
    print()
    print("You can now run the Flask application with:")
    print("  python app.py")







