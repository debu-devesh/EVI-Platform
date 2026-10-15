@echo off
echo 🔍 Testing Comprehensive UFDR Web Interface Components
echo ========================================================
echo.

REM Change to FORENSIC directory (parent of scripts)
cd /d "%~dp0.."

REM Test 1: Check if enhanced query engine exists
echo Testing enhanced query engine...

REM Test 2: Check if enhanced query engine exists
echo Testing enhanced query engine...
if exist "engines\enhanced_nl_query_engine.py" (
    echo ✅ engines\enhanced_nl_query_engine.py found
) else (
    echo ❌ engines\enhanced_nl_query_engine.py not found
    pause
    exit /b 1
)

REM Test 3: Check if web interface exists
echo Testing web interface...
if exist "web_interface.py" (
    echo ✅ web_interface.py found
) else (
    echo ❌ web_interface.py not found
    pause
    exit /b 1
)

REM Test 4: Check if enhanced template exists
echo Testing enhanced template...
if exist "templates\enhanced_index.html" (
    echo ✅ templates\enhanced_index.html found
) else (
    echo ❌ templates\enhanced_index.html not found
    pause
    exit /b 1
)

REM Test 5: Check if startup script exists
echo Testing enhanced startup script...
if exist "scripts\start_enhanced_web_interface.py" (
    echo ✅ scripts\start_enhanced_web_interface.py found
) else (
    echo ❌ scripts\start_enhanced_web_interface.py not found
    pause
    exit /b 1
)

REM Test 6: Check if comprehensive test script exists
echo Testing comprehensive test script...
if exist "test_comprehensive_keywords.py" (
    echo ✅ test_comprehensive_keywords.py found
) else (
    echo ❌ test_comprehensive_keywords.py not found
    pause
    exit /b 1
)

REM Test 7: Check Python syntax for engines
echo Testing Python syntax for query engines...

REM Test 8: Check Python syntax for enhanced engine
echo Testing Python syntax for enhanced engine...
python -m py_compile engines\enhanced_nl_query_engine.py
if %errorlevel% equ 0 (
    echo ✅ engines\enhanced_nl_query_engine.py syntax OK
) else (
    echo ❌ engines\enhanced_nl_query_engine.py syntax error
    pause
    exit /b 1
)

REM Test 9: Check Python syntax for startup script
echo Testing Python syntax for startup script...
python -m py_compile scripts\start_enhanced_web_interface.py
if %errorlevel% equ 0 (
    echo ✅ scripts\start_enhanced_web_interface.py syntax OK
) else (
    echo ❌ scripts\start_enhanced_web_interface.py syntax error
    pause
    exit /b 1
)

REM Test 10: Check if ZIP UFDR files exist
echo Testing ZIP UFDR files...
if exist "data\UFDR's(new)\case 1 Kidnapping Conspiracy.zip" (
    echo ✅ ZIP UFDR files found
) else (
    echo ⚠️  ZIP UFDR files not found - optional test data
)

echo.
echo ✅ All web interface components are ready!
echo 🚀 You can now run scripts\QUICK_START.bat to start the web interface
echo 🔍 Run tests\test_keyword_recognition.py to test keyword recognition
echo.
echo Available features:
echo    • Natural language query processing
echo    • ZIP UFDR file support
echo    • Enhanced scenario detection
echo    • Pattern matching for forensic indicators
echo    • Entity recognition
echo    • Relevance scoring and ranking
echo    • AI-powered analysis with LM Studio integration
echo.
pause

