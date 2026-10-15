@echo off
setlocal enabledelayedexpansion

echo ========================================
echo   EVI - Create Test User
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

REM Check if create_test_user.py exists
if not exist "security\create_test_user.py" (
    echo [ERROR] security\create_test_user.py not found!
    echo Current directory: %CD%
    echo.
    pause
    exit /b 1
)

python security\create_test_user.py

echo.
pause


