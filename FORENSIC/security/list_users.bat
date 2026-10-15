@echo off
setlocal enabledelayedexpansion

echo ========================================
echo   EVI - List All Users
echo ========================================
echo.

REM Change to FORENSIC directory (parent of security)
cd /d "%~dp0.."

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH!
    pause
    exit /b 1
)

REM Get authentication database path
set AUTH_DB=..\Authentication\evi_scan.db

if not exist "%AUTH_DB%" (
    echo [INFO] Database not found at %AUTH_DB% - will initialize schema
    echo.
    REM pause
    REM continue listing (schema will be created below)
)

echo [INFO] Ensuring auth DB schema exists...
python -c "import sqlite3; db=r'%AUTH_DB%'; conn=sqlite3.connect(db); cur=conn.cursor(); cur.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, first_name TEXT NOT NULL, last_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_login TIMESTAMP, is_active INTEGER DEFAULT 1)'); cur.execute('PRAGMA table_info(users)'); cols=[row[1] for row in cur.fetchall()]; ('role' in cols) or cur.execute('ALTER TABLE users ADD COLUMN role TEXT'); cur.execute('CREATE TABLE IF NOT EXISTS login_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER REFERENCES users(id), email TEXT, login_attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, success INTEGER, ip_address TEXT)'); conn.commit(); conn.close()"
echo Listing all users...
echo.

python -c "import sqlite3; import os; conn = sqlite3.connect(r'%AUTH_DB%'); cur = conn.cursor(); cur.execute('SELECT id, email, username, role, is_active FROM users ORDER BY id'); users = cur.fetchall(); print('ID | Email                          | Username          | Role          | Status'); print('-' * 85); [print(f'{r[0]:3} | {r[1]:30} | {r[2]:17} | {r[3] or \"None\":13} | {\"Active\" if r[4] else \"Inactive\"}') for r in users]; conn.close()"

python -c "import sqlite3; conn = sqlite3.connect(r'%AUTH_DB%'); cur = conn.cursor(); cur.execute('SELECT COUNT(*) FROM users'); total = cur.fetchone()[0]; conn.close(); print(f'\nTotal users: {total}')"

echo.
echo ========================================
echo.
echo User Management Commands:
echo.
echo To set a user role:
echo   set_user_role.bat [user_id] [role]
echo   Example: set_user_role.bat 4 admin
echo.
echo To delete/deactivate a user:
echo   delete_user.bat [user_id] [--deactivate or --permanent]
echo   Example: delete_user.bat 5 --deactivate
echo   Example: delete_user.bat 5 --permanent
echo.
pause


