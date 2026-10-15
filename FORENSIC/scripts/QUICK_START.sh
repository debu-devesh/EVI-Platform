#!/bin/bash

echo "========================================"
echo "  EVI - Quick Start Setup"
echo "========================================"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed!"
    echo ""
    echo "Please install Python 3:"
    echo "  Ubuntu/Debian: sudo apt-get install python3 python3-pip"
    echo "  Mac: brew install python3"
    echo "  Or download from: https://www.python.org/downloads/"
    echo ""
    exit 1
fi

echo "[OK] Python is installed"
python3 --version
echo ""

# Change to FORENSIC directory (parent of scripts)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
FORENSIC_DIR="$(dirname "$SCRIPT_DIR")"
cd "$FORENSIC_DIR"

# Check if we're in the right directory
if [ ! -f "web_interface.py" ]; then
    echo "[ERROR] Please ensure the project structure is correct!"
    echo ""
    exit 1
fi

echo "[OK] Running in correct directory"
echo ""

# Check and install dependencies
echo "Checking dependencies..."
if ! python3 -c "import flask" &> /dev/null; then
    echo "[INFO] Installing dependencies..."
    echo ""
    python3 scripts/setup_minimal.py
    if [ $? -ne 0 ]; then
        echo ""
        echo "[ERROR] Failed to install dependencies!"
        echo "Please run manually: pip3 install Flask pandas rapidfuzz orjson"
        echo ""
        exit 1
    fi
else
    echo "[OK] Dependencies are installed"
fi

echo ""
echo "========================================"
echo "  Starting EVI..."
echo "========================================"
echo ""
echo "Web Interface: http://localhost:5000"
echo "Press Ctrl+C to stop"
echo ""

python3 scripts/start_enhanced_web_interface.py

