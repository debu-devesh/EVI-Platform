from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import re
import secrets
import os
from functools import wraps
import bcrypt
from datetime import datetime, timedelta
from jinja2 import FileSystemLoader, ChoiceLoader

app = Flask(__name__)
_sk = os.environ.get("SECRET_KEY", "")
if not _sk or _sk.startswith("your-secret-key"):
    _sk = secrets.token_hex(32)  # unset or placeholder: random per start
app.secret_key = _sk

# Configure template and static folders BEFORE routes
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Point to workspace root (parent of Authentication directory)
EVI_SCAN_DIR = os.path.dirname(BASE_DIR)  # Parent of Authentication = workspace root
FORENSIC_TEMPLATES = os.path.join(EVI_SCAN_DIR, 'FORENSIC', 'templates')
AUTH_TEMPLATES = os.path.join(BASE_DIR, 'templates')  # Templates in Authentication/templates

# Use Jinja2 loader to search multiple template directories
app.jinja_loader = ChoiceLoader([
    FileSystemLoader(FORENSIC_TEMPLATES),
    FileSystemLoader(AUTH_TEMPLATES)
])

# Set static folder
app.static_folder = os.path.join(EVI_SCAN_DIR, 'FORENSIC', 'static')

# SQLite Database Configuration (No installation required!)
DB_PATH = os.path.join(BASE_DIR, 'evi_scan.db')

# Simple CAPTCHA storage (in production, use Redis or similar)
captcha_storage = {}

def get_db_connection():
    """Create and return a database connection"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row  # This allows column access by name
        return conn
    except sqlite3.Error as e:
        print(f"Database connection error: {e}")
        return None

def init_db():
    """Initialize database tables"""
    conn = get_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            # Create users table
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
                    is_active INTEGER DEFAULT 1
                )
            """)
            
            # Create login_logs table for tracking login attempts
            cur.execute("""
                CREATE TABLE IF NOT EXISTS login_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER REFERENCES users(id),
                    email TEXT,
                    login_attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success INTEGER,
                    ip_address TEXT
                )
            """)
            
            conn.commit()
            cur.close()
            conn.close()
            print("Database initialized successfully")
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")

def validate_password(password):
    """
    Validate password requirements:
    - At least 8 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 number
    - At least 1 special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is valid"

def login_required(f):
    """Decorator to require login for routes with 20 min session timeout"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        login_time_str = session.get('login_time')
        if not login_time_str:
            session.clear()
            flash('Session timed out. Please log in again.', 'warning')
            return redirect(url_for('login'))
        try:
            login_time = datetime.fromisoformat(login_time_str)
        except ValueError:
            session.clear()
            flash('Session corrupted. Please log in again.', 'warning')
            return redirect(url_for('login'))
        if datetime.now() - login_time > timedelta(minutes=20):
            session.clear()
            flash('Session timed out after 20 minutes. Please log in again.', 'warning')
            return redirect(url_for('login'))
        # Sliding expiration: refresh login_time on each request
        session['login_time'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

def generate_captcha():
    """Generate a simple CAPTCHA"""
    import random
    import string
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    captcha_id = secrets.token_hex(8)
    captcha_storage[captcha_id] = captcha_text
    return captcha_id, captcha_text

def verify_captcha(captcha_id, user_input):
    """Verify CAPTCHA input"""
    if captcha_id not in captcha_storage:
        return False
    stored_captcha = captcha_storage.pop(captcha_id)  # Remove after use
    return stored_captcha.upper() == user_input.upper()

@app.route('/')
def index():
    """Redirect to login if not authenticated, else to dashboard"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page with CAPTCHA"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        captcha_id = request.form.get('captcha_id', '')
        captcha_input = request.form.get('captcha', '').strip()
        remember_me = request.form.get('rememberMe') == 'on'
        
        # Verify CAPTCHA
        if not verify_captcha(captcha_id, captcha_input):
            flash('Invalid CAPTCHA. Please try again.', 'error')
            captcha_id, captcha_text = generate_captcha()
            return render_template('forensic_auth.html', 
                                 captcha_id=captcha_id, 
                                 captcha_text=captcha_text,
                                 error='Invalid CAPTCHA')
        
        # Validate input
        if not email or not password:
            flash('Please fill in all fields.', 'error')
            captcha_id, captcha_text = generate_captcha()
            return render_template('forensic_auth.html', 
                                 captcha_id=captcha_id, 
                                 captcha_text=captcha_text)
        
        # Check user in database
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            captcha_id, captcha_text = generate_captcha()
            return render_template('forensic_auth.html', 
                                 captcha_id=captcha_id, 
                                 captcha_text=captcha_text)
        
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE email = ? AND is_active = 1", (email,))
            user = cur.fetchone()
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                # Successful login
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['email'] = user['email']
                session['name'] = f"{user['first_name']} {user['last_name']}"
                session['login_time'] = datetime.now().isoformat()  # Store login time as ISO format
                
                # Update last login
                cur.execute("UPDATE users SET last_login = ? WHERE id = ?", 
                          (datetime.now(), user['id']))
                
                # Log successful login
                ip_address = request.remote_addr
                cur.execute("""
                    INSERT INTO login_logs (user_id, email, success, ip_address)
                    VALUES (?, ?, ?, ?)
                """, (user['id'], email, 1, ip_address))
                
                conn.commit()
                cur.close()
                conn.close()
                
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Failed login
                ip_address = request.remote_addr
                cur.execute("""
                    INSERT INTO login_logs (email, success, ip_address)
                    VALUES (?, ?, ?)
                """, (email, 0, ip_address))
                conn.commit()
                cur.close()
                conn.close()
                
                flash('Invalid email or password.', 'error')
                captcha_id, captcha_text = generate_captcha()
                return render_template('forensic_auth.html', 
                                     captcha_id=captcha_id, 
                                     captcha_text=captcha_text)
        except Exception as e:
            cur.close()
            conn.close()
            flash('An error occurred. Please try again.', 'error')
            captcha_id, captcha_text = generate_captcha()
            return render_template('forensic_auth.html', 
                                 captcha_id=captcha_id, 
                                 captcha_text=captcha_text)
    
    # GET request - show login form
    captcha_id, captcha_text = generate_captcha()
    return render_template('forensic_auth.html', 
                         captcha_id=captcha_id, 
                         captcha_text=captcha_text)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Signup page with password validation"""
    if request.method == 'POST':
        first_name = request.form.get('firstName', '').strip()
        last_name = request.form.get('lastName', '').strip()
        email = request.form.get('email', '').strip().lower()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirmPassword', '')
        terms_accepted = request.form.get('termsCheck') == 'on'
        
        # Validate all fields
        errors = []
        
        if not first_name:
            errors.append('First name is required')
        if not last_name:
            errors.append('Last name is required')
        if not email or '@' not in email:
            errors.append('Valid email is required')
        if not username or len(username) < 4:
            errors.append('Username must be at least 4 characters')
        if password != confirm_password:
            errors.append('Passwords do not match')
        
        # Validate password requirements
        is_valid, password_error = validate_password(password)
        if not is_valid:
            errors.append(password_error)
        
        if not terms_accepted:
            errors.append('You must accept the terms and conditions')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('signup.html')
        
        # Check if email or username already exists
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return render_template('signup.html')
        
        try:
            cur = conn.cursor()
            cur.execute("SELECT email FROM users WHERE email = ?", (email,))
            if cur.fetchone():
                flash('Email already registered.', 'error')
                cur.close()
                conn.close()
                return render_template('signup.html')
            
            cur.execute("SELECT username FROM users WHERE username = ?", (username,))
            if cur.fetchone():
                flash('Username already taken.', 'error')
                cur.close()
                conn.close()
                return render_template('signup.html')
            
            # Hash password with bcrypt
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Insert new user
            cur.execute("""
                INSERT INTO users (first_name, last_name, email, username, password_hash)
                VALUES (?, ?, ?, ?, ?)
            """, (first_name, last_name, email, username, password_hash))
            
            user_id = cur.lastrowid
            conn.commit()
            cur.close()
            conn.close()
            
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            cur.close()
            conn.close()
            flash(f'An error occurred: {str(e)}', 'error')
            return render_template('signup.html')
    
    # GET request - show signup form
    return render_template('signup.html')

from datetime import datetime, timedelta

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard - enhanced_index.html"""
    login_time_str = session.get('login_time')
    session_timeout_seconds = 0
    if login_time_str:
        try:
            login_time = datetime.fromisoformat(login_time_str)
            elapsed = datetime.now() - login_time
            timeout = timedelta(minutes=20)
            remaining = timeout - elapsed
            session_timeout_seconds = max(int(remaining.total_seconds()), 0)
        except ValueError:
            session_timeout_seconds = 0
    return render_template('enhanced_index.html', 
                         username=session.get('username'),
                         name=session.get('name'),
                         session_timeout_seconds=session_timeout_seconds)

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/api/validate-password', methods=['POST'])
def api_validate_password():
    """API endpoint for real-time password validation"""
    data = request.get_json()
    password = data.get('password', '')
    
    is_valid, message = validate_password(password)
    return jsonify({
        'valid': is_valid,
        'message': message
    })

if __name__ == '__main__':
    # Initialize database on startup
    print("Initializing database...")
    init_db()
    
    print("Starting Flask application...")
    print(f"Database: {DB_PATH}")
    print(f"Forensic templates: {FORENSIC_TEMPLATES}")
    print(f"Auth templates: {AUTH_TEMPLATES}")
    
    # Run the app
    app.run(debug=True, port=5001, host='0.0.0.0')
