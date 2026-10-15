@echo off
setlocal

echo ========================================
echo   EVI - List Users (Scripts)
echo ========================================
echo.

REM Change to FORENSIC directory (parent of scripts)
cd /d "%~dp0.."

if not exist "security\list_users.bat" (
    echo [ERROR] security\list_users.bat not found!
    echo Current directory: %CD%
    echo.
    pause
    exit /b 1
)

call security\list_users.bat

