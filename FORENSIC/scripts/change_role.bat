@echo off
setlocal

echo ========================================
echo   EVI - Change User Role (Scripts)
echo ========================================
echo.

REM Change to FORENSIC directory (parent of scripts)
cd /d "%~dp0.."

if not exist "security\set_user_role.bat" (
    echo [ERROR] security\set_user_role.bat not found!
    echo Current directory: %CD%
    echo.
    pause
    exit /b 1
)

REM Forward all args; if none provided, security script runs interactive mode
call security\set_user_role.bat %*

