@echo off
setlocal enabledelayedexpansion

echo ========================================
echo   EVI - Set User Role
echo ========================================
echo.

REM Change to FORENSIC directory (parent of security)
cd /d "%~dp0.."

REM Check if Python is available
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
echo.

REM Check if set_user_role.py exists
if not exist "security\set_user_role.py" (
    echo [ERROR] security\set_user_role.py not found!
    echo Current directory: %CD%
    echo.
    pause
    exit /b 1
)

REM Check if user provided arguments
if "%~1"=="" (
    echo Usage: set_user_role.bat [user_id] [role]
    echo.
    echo Roles: admin, investigator, viewer, auditor
    echo.
    echo Examples:
    echo   set_user_role.bat 4 admin
    echo   set_user_role.bat 2 investigator
    echo   set_user_role.bat 3 viewer
    echo   set_user_role.bat 5 auditor
    echo.
    echo.
    echo ========================================
    echo   Interactive Mode
    echo ========================================
    echo.
    
    REM Interactive mode
    set /p user_id="Enter User ID: "
    if "!user_id!"=="" (
        echo [ERROR] User ID is required!
        pause
        exit /b 1
    )
    
    echo.
    echo Available Roles:
    echo   1. admin         - Full access, manage users
    echo   2. investigator  - Create/edit cases, view audit logs
    echo   3. viewer        - Read-only access
    echo   4. auditor       - View audit logs, all cases (read-only)
    echo.
    set /p role_choice="Select role (1-4) or type role name: "
    
    REM Convert number to role name
    if "!role_choice!"=="1" set role=admin
    if "!role_choice!"=="2" set role=investigator
    if "!role_choice!"=="3" set role=viewer
    if "!role_choice!"=="4" set role=auditor
    
    REM If user typed role name directly
    if "!role_choice!"=="admin" set role=admin
    if "!role_choice!"=="investigator" set role=investigator
    if "!role_choice!"=="investigatorr" set role=investigator
    if "!role_choice!"=="viewer" set role=viewer
    if "!role_choice!"=="auditor" set role=auditor
    
    if "!role!"=="" set role=!role_choice!
    
    echo.
    python security\set_user_role.py !user_id! !role!
) else (
    REM Command-line mode
    if "%~2"=="" (
        echo [ERROR] Both user_id and role are required!
        echo.
        echo Usage: set_user_role.bat [user_id] [role]
        echo Example: set_user_role.bat 4 admin
        echo.
        pause
        exit /b 1
    )
    
    set role_arg=%2
    if /i "%role_arg%"=="investigatorr" set role_arg=investigator
    python security\set_user_role.py %1 %role_arg%
)

echo.
pause


