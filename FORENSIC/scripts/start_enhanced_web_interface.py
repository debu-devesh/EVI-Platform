#!/usr/bin/env python3
"""
Enhanced UFDR Forensic Command Engine - Web Interface Startup Script

This script starts the enhanced web interface with the new NL Query Engine capabilities.
"""

import subprocess
import sys
import os
from pathlib import Path

def check_requirements():
    """Check if required packages are installed."""
    required_packages = ['flask', 'pandas', 'rapidfuzz']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package} is installed")
        except ImportError:
            print(f"❌ {package} is not installed")
            missing_packages.append(package)
    
    return missing_packages

def install_requirements():
    """Install required packages."""
    print("📦 Installing required packages...")
    try:
        # Get FORENSIC directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        forensic_dir = os.path.dirname(script_dir)
        requirements_path = os.path.join(forensic_dir, "requirements.txt")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", requirements_path])
        print("✅ Requirements installed successfully")
        return True
    except subprocess.CalledProcessError:
        print("❌ Failed to install requirements")
        return False

def check_enhanced_components():
    """Check if enhanced components are available."""
    # Get FORENSIC directory (parent of scripts)
    forensic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    required_files = [
        os.path.join(forensic_dir, "engines", "enhanced_nl_query_engine.py"),
        os.path.join(forensic_dir, "web_interface.py"),
        os.path.join(forensic_dir, "templates", "enhanced_index.html")
    ]
    
    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(os.path.relpath(file_path, forensic_dir))
    
    return missing_files

def start_enhanced_web_interface():
    """Start the enhanced web interface."""
    print("Starting Enhanced UFDR Forensic Command Engine Web Interface...")
    print("=" * 70)
    print("Web Interface will be available at: http://localhost:5000")
    print("Open your browser and navigate to the URL above")
    print("Press Ctrl+C to stop the server")
    print()
    print("Enhanced Features Available:")
    print("   • Scenario Detection (Insider Data Leak, Scam Network, SIM Swap)")
    print("   • Intelligent Keyword Recognition")
    print("   • Enhanced NL Query Processing")
    print("   • Relevance Scoring and Ranking")
    print("   • Pattern Matching for Forensic Indicators")
    print("   • Entity Recognition for Key People and Organizations")
    print("=" * 70)
    
    try:
        # Ensure FORENSIC directory is in Python path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        forensic_dir = os.path.dirname(script_dir)
        if forensic_dir not in sys.path:
            sys.path.insert(0, forensic_dir)
        
        # Import and run the web interface
        from web_interface import app
        # Use 'stat' reloader instead of 'watchdog' to prevent restarts during file uploads
        # 'stat' is less sensitive to file changes in upload directories
        app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=True, reloader_type='stat')
    except KeyboardInterrupt:
        print("\n👋 Enhanced web interface stopped")
    except Exception as e:
        print(f"❌ Error starting enhanced web interface: {e}")
        import traceback
        traceback.print_exc()
        print("Please check that all required files are present and dependencies are installed.")

def main():
    """Main function."""
    print("Enhanced UFDR Forensic Command Engine - Web Interface")
    print("=" * 70)
    
    # Get FORENSIC directory (parent of scripts)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    forensic_dir = os.path.dirname(script_dir)
    
    # Change to FORENSIC directory and add to Python path
    os.chdir(forensic_dir)
    if forensic_dir not in sys.path:
        sys.path.insert(0, forensic_dir)
    
    # Check if we're in the right directory
    if not os.path.exists("web_interface.py"):
        print("❌ Error: web_interface.py not found")
        print(f"Current directory: {os.getcwd()}")
        print(f"Looking for: {os.path.join(forensic_dir, 'web_interface.py')}")
        print("Please ensure the project structure is correct")
        return
    
    # Check enhanced components
    missing_files = check_enhanced_components()
    if missing_files:
        print("❌ Missing required files:")
        for file_path in missing_files:
            print(f"   - {file_path}")
        print("Please ensure all enhanced components are available")
        return
    
    # Check requirements
    missing_packages = check_requirements()
    if missing_packages:
        print(f"\n📦 Missing packages: {', '.join(missing_packages)}")
        print("Installing missing packages...")
        if not install_requirements():
            print("❌ Failed to install requirements. Please install manually:")
            for package in missing_packages:
                print(f"   pip install {package}")
            return
    
    print("✅ All enhanced components and requirements found!")
    print()
    
    # Start the enhanced web interface
    start_enhanced_web_interface()

if __name__ == "__main__":
    main()
