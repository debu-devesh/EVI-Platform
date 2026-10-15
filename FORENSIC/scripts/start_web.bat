@echo off
echo 🔍 UFDR Forensic Command Engine - Enhanced Web Interface
echo ========================================================
echo.
echo Starting enhanced web interface with NL Query Engine...
echo.
echo 📱 Web Interface will be available at: http://localhost:5000
echo 🔍 Open your browser and navigate to the URL above
echo ⏹️  Press Ctrl+C to stop the server
echo.
echo 💡 Enhanced Features:
echo    • Scenario Detection (Insider Data Leak, Scam Network, SIM Swap)
echo    • Comprehensive Keyword Recognition (ALL keywords from UFDR v2)
echo    • Enhanced NL Query Processing with Pattern Matching
echo    • Relevance Scoring and Ranking
echo    • Entity Recognition for Key People and Organizations
echo    • Financial and Time-based Pattern Detection
echo    • Comprehensive Analysis with Detailed Statistics
echo.
echo ========================================================
echo.

REM Change to FORENSIC directory (parent of scripts)
cd /d "%~dp0.."

REM Check if required files exist
if not exist "web_interface.py" (
    echo ❌ Error: web_interface.py not found!
    echo Please ensure you're in the FORENSIC directory.
    pause
    exit /b 1
)

if not exist "engines\enhanced_nl_query_engine.py" (
    echo ❌ Error: enhanced_nl_query_engine.py not found!
    echo Please ensure the enhanced query engine is available.
    pause
    exit /b 1
)

REM comprehensive_nl_query_engine.py removed - using enhanced_nl_query_engine.py instead

if not exist "templates\enhanced_index.html" (
    echo ❌ Error: Enhanced template not found!
    echo Please ensure templates\enhanced_index.html exists.
    pause
    exit /b 1
)

echo ✅ All enhanced components found!
echo 🚀 Starting enhanced web server...
echo.

python scripts\start_enhanced_web_interface.py

echo.
echo 👋 Enhanced web interface stopped
pause

