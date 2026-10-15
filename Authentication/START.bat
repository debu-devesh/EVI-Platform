@echo off
setlocal enabledelayedexpansion
title EVI - Authentication Server
color 0A

cls
echo.
echo ========================================
echo   EVI - Starting Server
echo ========================================
echo.

REM Change to script directory first (Authentication folder)
cd /d "%~dp0"
echo Current directory: %CD%
echo.

REM Check Python installation
echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo.
    echo Please install Python from https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation
    echo.
    pause
    exit /b 1
)
echo [OK] Python found
python --version
echo.

REM Check dependencies
echo Checking dependencies...
python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Flask not found, installing...
    pip install Flask
    if errorlevel 1 (
        echo [ERROR] Failed to install Flask
        pause
        exit /b 1
    )
)

python -c "import bcrypt" >nul 2>&1
if errorlevel 1 (
    echo [INFO] bcrypt not found, installing...
    pip install bcrypt
    if errorlevel 1 (
        echo [ERROR] Failed to install bcrypt
        pause
        exit /b 1
    )
)
echo [OK] All dependencies installed
echo.

REM Check if app file exists
if not exist "app.py" (
    echo [ERROR] app.py not found in current directory
    echo Current directory: %CD%
    echo.
    echo Note: app_sqlite.py has been removed. Using app.py instead.
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Server Information
echo ========================================
echo.
echo Server URL: http://localhost:5001
echo.
echo Features:
echo   - User Authentication (Login/Signup)
echo   - Forensic Analysis Dashboard
echo   - Protected API Routes
echo.
echo Press Ctrl+C to stop the server
echo ========================================
echo.

REM Start the server
echo Starting server...
echo.
python app.py

REM If we get here, server stopped
echo.
echo Server stopped.
pause

