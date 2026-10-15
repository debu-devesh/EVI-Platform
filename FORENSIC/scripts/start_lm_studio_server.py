"""
Start LM Studio server programmatically
"""

import requests
import subprocess
import os
import time
import sys

def find_lm_studio():
    """Find LM Studio installation path."""
    possible_paths = [
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs', 'LM Studio', 'LM Studio.exe'),
        os.path.join(os.environ.get('PROGRAMFILES', ''), 'LM Studio', 'LM Studio.exe'),
        os.path.join(os.environ.get('PROGRAMFILES(X86)', ''), 'LM Studio', 'LM Studio.exe'),
        os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local', 'Programs', 'LM Studio', 'LM Studio.exe'),
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    return None

def is_server_running():
    """Check if LM Studio server is already running."""
    try:
        response = requests.get("http://localhost:1234/v1/models", timeout=2)
        return response.ok
    except:
        return False

def start_lm_studio_server():
    """Attempt to start LM Studio server."""
    print("="*60)
    print("🚀 Starting LM Studio Server")
    print("="*60)
    
    # Check if already running
    if is_server_running():
        print("\n✅ LM Studio server is already running!")
        return True
    
    # Find LM Studio
    print("\n🔍 Looking for LM Studio installation...")
    lm_studio_path = find_lm_studio()
    
    if not lm_studio_path:
        print("❌ Could not find LM Studio installation")
        print("\nPlease install LM Studio from: https://lmstudio.ai/")
        print("Or manually start LM Studio and click 'Start Server'")
        return False
    
    print(f"✅ Found LM Studio at: {lm_studio_path}")
    
    # Try to start LM Studio
    print("\n🚀 Attempting to start LM Studio server...")
    print("   (This may open the LM Studio window)")
    
    try:
        # Start LM Studio (it may auto-start server or need manual start)
        subprocess.Popen([lm_studio_path], shell=True)
        
        # Wait for server to potentially start
        print("\n⏳ Waiting for server to start...")
        for i in range(10):
            time.sleep(2)
            if is_server_running():
                print(f"\n✅ LM Studio server started successfully!")
                print("   Server is running on http://localhost:1234")
                return True
            print(f"   Checking... ({i+1}/10)")
        
        print("\n⚠️  Server did not start automatically")
        print("\nYou may need to:")
        print("1. Open LM Studio (it should be open now)")
        print("2. Go to 'Local Server' tab")
        print("3. Click 'Start Server'")
        print("\nOr check if LM Studio has auto-start enabled in settings.")
        return False
        
    except Exception as e:
        print(f"\n❌ Error starting LM Studio: {e}")
        return False

if __name__ == "__main__":
    success = start_lm_studio_server()
    sys.exit(0 if success else 1)


