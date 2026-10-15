#!/usr/bin/env python3
"""
Complete Setup Script for UFDR Forensic Analysis System
Installs all required packages including LM Studio setup instructions
"""

import subprocess
import sys
import os
import requests

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
        import_map = {
            "flask": "flask",
            "pandas": "pandas",
            "rapidfuzz": "rapidfuzz",
            "orjson": "orjson",
            "requests": "requests"
        }
        import_name = import_map.get(package, package)
        __import__(import_name)
        print(f"✅ {package} is already installed")
        return True
    except ImportError:
        print(f"❌ {package} is not installed")
        return False

def check_lm_studio():
    """Check if LM Studio server is running"""
    try:
        response = requests.get("http://localhost:1234/v1/models", timeout=5)
        if response.ok:
            models = response.json().get('data', [])
            print(f"✅ LM Studio server is running with {len(models)} model(s) loaded")
            if models:
                print("   Loaded models:")
                for model in models:
                    print(f"   - {model.get('id', 'Unknown')}")
            return True
        else:
            print("⚠️  LM Studio server is not responding properly")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ LM Studio server is not running")
        return False
    except Exception as e:
        print(f"⚠️  Error checking LM Studio: {e}")
        return False

def main():
    """Install all required packages and check LM Studio"""
    print("🔧 EVI - Complete Setup (Including AI Chat)")
    print("=" * 70)
    print("This will install all required packages for full functionality")
    print("including AI Chat Assistant (requires LM Studio)")
    print()
    
    # Required packages for full functionality
    required_packages = [
        ("flask", "Flask>=2.0.0"),
        ("pandas", "pandas>=1.3.0"),
        ("rapidfuzz", "rapidfuzz>=2.0.0"),
        ("orjson", "orjson>=3.6.0"),
        ("requests", "requests>=2.25.0")
    ]
    
    print("Step 1: Checking Python packages...")
    print("-" * 70)
    
    missing_packages = []
    for package_name, package_spec in required_packages:
        if not check_package(package_name):
            missing_packages.append(package_spec)
    
    if missing_packages:
        print(f"\nInstalling {len(missing_packages)} missing packages...")
        print("-" * 70)
        
        for package in missing_packages:
            install_package(package)
    else:
        print("\n✅ All Python packages are installed!")
    
    print("\n" + "=" * 70)
    print("Step 2: Checking LM Studio (Required for AI Chat Assistant)...")
    print("-" * 70)
    
    lm_studio_ok = check_lm_studio()
    
    if not lm_studio_ok:
        print("\n" + "=" * 70)
        print("⚠️  LM STUDIO SETUP REQUIRED")
        print("=" * 70)
        print("\nLM Studio is required for the AI Chat Assistant feature.")
        print("\nTo install LM Studio:")
        print("  1. Download from: https://lmstudio.ai/")
        print("  2. Install the application")
        print("  3. Open LM Studio and download a model:")
        print("     - Go to 'Search' tab")
        print("     - Search for 'Qwen/Qwen2.5-3B-Instruct' (recommended for performance)")
        print("     - Click 'Download'")
        print("  4. Start the server:")
        print("     - Go to 'Local Server' tab")
        print("     - Click 'Start Server'")
        print("\nAfter installing LM Studio, run this setup script again to verify.")
        print("\n" + "=" * 70)
        print("✅ Python packages installed successfully!")
        print("⚠️  Please install LM Studio to enable AI Chat Assistant")
        print("=" * 70)
    else:
        print("\n" + "=" * 70)
        print("🎉 Setup Complete! Everything is ready!")
        print("=" * 70)
        print("\n✅ All Python packages installed")
        print("✅ LM Studio server is running")
        print("✅ AI Chat Assistant is ready")
        print("\nTo start the web interface:")
        print("  python scripts/start_enhanced_web_interface.py")
        print("\nOr use the batch file:")
        print("  scripts/start_web.bat")
        print("=" * 70)

if __name__ == "__main__":
    main()


