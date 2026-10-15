#!/usr/bin/env python3
"""
Minimal Setup Script for UFDR Forensic Analysis System
Installs only the essential packages needed for full functionality
"""

import subprocess
import sys
import os

def install_package(package):
    """Install a package using pip"""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"✅ {package} installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install {package}: {e}")
        return False

def check_package(package):
    """Check if a package is already installed"""
    try:
        # Handle special cases for package names vs import names
        import_map = {
            "flask": "flask",
            "pandas": "pandas",
            "rapidfuzz": "rapidfuzz",
            "orjson": "orjson"
        }
        import_name = import_map.get(package, package)
        __import__(import_name)
        print(f"✅ {package} is already installed")
        return True
    except ImportError:
        print(f"❌ {package} is not installed")
        return False

def main():
    """Install minimal required packages"""
    print("🔧 UFDR Forensic Analysis System - Minimal Setup")
    print("=" * 60)
    print("Installing only essential packages for full functionality...")
    print()
    
    # Required packages for full functionality
    required_packages = [
        ("flask", "Flask>=2.0.0"),
        ("pandas", "pandas>=1.3.0"),
        ("rapidfuzz", "rapidfuzz>=2.0.0"),
        ("orjson", "orjson>=3.6.0")
    ]
    
    print("Checking required packages...")
    print("-" * 40)
    
    missing_packages = []
    for package_name, package_spec in required_packages:
        if not check_package(package_name):
            missing_packages.append(package_spec)
    
    if missing_packages:
        print(f"\nInstalling {len(missing_packages)} missing packages...")
        print("-" * 40)
        
        for package in missing_packages:
            install_package(package)
    else:
        print("\n✅ All required packages are already installed!")
    
    print("\n" + "=" * 60)
    print("🎉 Setup complete! You can now run the UFDR system without warnings.")
    print("=" * 60)
    print("\nTo start the web interface:")
    print("  python start_enhanced_web_interface.py")
    print("\nTo start with batch file:")
    print("  start_web.bat")
    print("\nTo test the system:")
    print("  python test_keyword_recognition.py")

if __name__ == "__main__":
    main()

