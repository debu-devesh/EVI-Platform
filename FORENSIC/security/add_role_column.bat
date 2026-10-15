@echo off
setlocal enabledelayedexpansion

echo ========================================
echo   EVI - Add Role Column Migration
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

echo [OK] Python is installed
echo.

REM Check if add_role_column.py exists
if not exist "security\add_role_column.py" (
    echo [ERROR] security\add_role_column.py not found!
    echo Current directory: %CD%
    echo.
    pause
    exit /b 1
)

python security\add_role_column.py

echo.
pause


