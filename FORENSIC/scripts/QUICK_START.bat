@echo off
setlocal enabledelayedexpansion
echo ========================================
echo   EVI - Quick Start Setup
echo ========================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH!
    echo.
    echo Please install Python from: https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [OK] Python is installed
python --version
echo.

REM Change to FORENSIC directory (parent of scripts)
cd /d "%~dp0.."

REM Check if we're in the right directory
if not exist "web_interface.py" (
    echo [ERROR] Please ensure the project structure is correct!
    echo.
    pause
    exit /b 1
)

echo [OK] Running in correct directory
echo.

REM Check and install dependencies
echo Checking dependencies...
python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing dependencies...
    echo.
    echo Choose setup option:
    echo   1. Minimal setup (core features only, no AI Chat)
    echo   2. Complete setup (includes AI Chat, requires LM Studio)
    echo.
    set /p setup_choice="Enter choice (1 or 2): "
    if "!setup_choice!"=="2" (
        python scripts\setup_with_lm_studio.py
    ) else (
        python scripts\setup_minimal.py
    )
    if errorlevel 1 (
        echo.
        echo [ERROR] Failed to install dependencies!
        echo Please run manually: pip install Flask pandas rapidfuzz orjson requests
        echo.
        pause
        exit /b 1
    )
) else (
    echo [OK] Dependencies are installed
)

echo.
echo ========================================
echo   Checking LM Studio Server...
echo ========================================
echo.

REM Check if LM Studio server is running
python -c "import requests; r=requests.get('http://localhost:1234/v1/models', timeout=2); exit(0 if r.ok else 1)" >nul 2>&1
if errorlevel 1 (
    echo [INFO] LM Studio server is not running
    echo [INFO] Attempting to start LM Studio server...
    echo.
    python scripts\start_lm_studio_server.py
    if errorlevel 1 (
        echo.
        echo [WARNING] Could not start LM Studio server automatically
        echo [INFO] You may need to manually start it:
        echo   1. Open LM Studio
        echo   2. Go to "Local Server" tab
        echo   3. Click "Start Server"
        echo.
        echo [INFO] Continuing anyway - AI Chat may not work without LM Studio
        echo.
        timeout /t 3 /nobreak >nul
    ) else (
        echo.
        echo [OK] LM Studio server is ready!
        echo.
    )
) else (
    echo [OK] LM Studio server is already running
    echo.
)

echo ========================================
echo   Starting EVI...
echo ========================================
echo.
echo Web Interface: http://localhost:5000
echo Press Ctrl+C to stop
echo.

REM Avoid blocking startup on Hugging Face network timeouts (bart-large-mnli is optional).
REM Rule-based NL queries still work. To enable HF zero-shot later:
REM   set EVI_ENABLE_HF_ZERO_SHOT=1
REM   set EVI_HF_LOCAL_FILES_ONLY=0
REM   (or pre-download the model when your network is stable)
set HF_HUB_DOWNLOAD_TIMEOUT=60
set EVI_SKIP_HF_MODELS=1

python scripts\start_enhanced_web_interface.py

pause

