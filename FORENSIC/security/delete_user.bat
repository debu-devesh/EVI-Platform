@echo off
setlocal enabledelayedexpansion

echo ========================================
echo   EVI - Delete User
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
    echo [ERROR] Database not found at %AUTH_DB%
    echo.
    pause
    exit /b 1
)

REM Check if user provided arguments
if "%~1"=="" (
    echo Usage: delete_user.bat [user_id] [--permanent]
    echo.
    echo Options:
    echo   --permanent   Permanently delete user (cannot be undone)
    echo   --deactivate   Deactivate user (default, can be reactivated)
    echo.
    echo Examples:
    echo   delete_user.bat 5              # Deactivate user ID 5
    echo   delete_user.bat 5 --deactivate # Same as above
    echo   delete_user.bat 5 --permanent  # Permanently delete user ID 5
    echo.
    echo ========================================
    echo   Interactive Mode
    echo ========================================
    echo.
    
    REM Interactive mode
    set /p user_id="Enter User ID to delete: "
    if "!user_id!"=="" (
        echo [ERROR] User ID is required!
        pause
        exit /b 1
    )
    
    echo.
    echo Delete Options:
    echo   1. Deactivate (soft delete) - User cannot log in, data preserved
    echo   2. Permanent Delete - User removed completely (cannot be undone)
    echo.
    set /p delete_type="Select option (1 or 2): "
    
    if "!delete_type!"=="2" (
        python security\delete_user.py !user_id! --permanent
    ) else (
        python security\delete_user.py !user_id! --deactivate
    )
) else (
    REM Command-line mode
    if "%~2"=="" (
        REM Only user_id provided, default to deactivate
        python security\delete_user.py %1 --deactivate
    ) else (
        REM Both user_id and option provided
        python security\delete_user.py %1 %2
    )
)

echo.
pause

