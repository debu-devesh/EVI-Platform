@echo off
echo ========================================
echo Start LM Studio Server
echo ========================================
echo.

cd /d "%~dp0\.."
python scripts\start_lm_studio_server.py

echo.
pause
