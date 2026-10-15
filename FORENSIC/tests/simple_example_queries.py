#!/usr/bin/env python3
"""
Simple Example Queries for UFDR Forensic Analysis System
"""

import json
import sys
import os
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engines.simplified_nl_query_engine import SimplifiedNLQueryEngine

def load_ufdr_from_zip(zip_path: str):
    """Load UFDR data from ZIP file"""
    import zipfile
    ufdr_data = {
        "contacts": [],
        "messages": [],
        "calls": []
    }
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            # Load contacts
            try:
                contacts_data = json.loads(z.read('Artifacts/Contacts/contacts.json'))
                if isinstance(contacts_data, list):
                    ufdr_data["contacts"] = contacts_data
            except:
                pass
            
            # Load SMS
            try:
                sms_data = json.loads(z.read('Artifacts/SMS/sms.json'))
                if isinstance(sms_data, list):
                    ufdr_data["messages"].extend(sms_data)
            except:
                pass
            
            # Load WhatsApp
            try:
                whatsapp_data = json.loads(z.read('Artifacts/WhatsApp/whatsapp.json'))
                if isinstance(whatsapp_data, list):
                    ufdr_data["messages"].extend(whatsapp_data)
            except:
                pass
            
            # Load calls
            try:
                calls_data = json.loads(z.read('Artifacts/Calls/calls.json'))
                if isinstance(calls_data, list):
                    ufdr_data["calls"] = calls_data
            except:
                pass
    except Exception as e:
        print(f"Error loading ZIP: {e}")
    
    return ufdr_data

def demonstrate_queries():
    """Demonstrate example queries"""
    print("UFDR Forensic Analysis System - Example Queries")
    print("=" * 60)
    print()
    
    engine = SimplifiedNLQueryEngine()
    
    # Test with a ZIP UFDR file
    file_path = "../data/UFDR's(new)/case 1 Kidnapping Conspiracy.zip"
    
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        print("Please ensure ZIP UFDR files are available in data/UFDR's(new)/")
        return
    
    try:
        # Load data from ZIP
        data = load_ufdr_from_zip(file_path)
        engine.ufdr_data = {"test_case": data}
        
        total_records = len(data.get("messages", [])) + len(data.get("contacts", [])) + len(data.get("calls", []))
        print(f"Loaded {total_records} records from {file_path}")
        print()
        
        # Example queries
        example_queries = [
            "show all contacts",
            "find messages about money",
            "show calls from last week",
            "find suspicious activities",
            "show device information"
        ]
        
        print("EXAMPLE QUERIES:")
        print("-" * 40)
        
        for i, query in enumerate(example_queries, 1):
            print(f"{i}. Query: '{query}'")
            
            try:
                result = engine.process_query(query)
                if result and result.matches:
                    print(f"   Results: {len(result.matches)} records found")
                    print(f"   Confidence: {result.confidence}%")
                    if result.summary:
                        print(f"   Summary: {result.summary[:100]}...")
                else:
                    print(f"   No results found")
                
                print()
                
            except Exception as e:
                print(f"   Error: {e}")
                print()
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

def show_web_interface_queries():
    """Show web interface query examples"""
    print("\nWEB INTERFACE EXAMPLE QUERIES")
    print("=" * 50)
    print()
    print("To use these queries in the web interface:")
    print("1. Start the web interface: scripts/QUICK_START.bat")
    print("2. Open browser to: http://localhost:5000")
    print("3. Upload a ZIP UFDR file")
    print("4. Use these example queries:")
    print()
    
    # Example queries for different case types
    case_queries = {
        "General Queries": [
            "show all contacts",
            "find messages about money",
            "show calls from last week",
            "find suspicious activities",
            "show device information"
        ],
        "Communication Analysis": [
            "show deleted messages",
            "find encrypted communications",
            "show relationship networks",
            "find frequent contacts",
            "show communication timeline"
        ],
        "Evidence Queries": [
            "find financial transactions",
            "show media files",
            "find location data",
            "show threat indicators",
            "find deleted items"
        ]
    }
    
    for category, queries in case_queries.items():
        print(f"{category.upper()}:")
        print("-" * 30)
        for i, query in enumerate(queries, 1):
            print(f"{i}. {query}")
        print()

def main():
    """Run example query demonstrations"""
    print("UFDR Forensic Analysis System - Example Queries")
    print("=" * 60)
    print()
    
    # Check if ZIP files exist
    test_file = "../data/UFDR's(new)/case 1 Kidnapping Conspiracy.zip"
    
    if not os.path.exists(test_file):
        print(f"Test file not found: {test_file}")
        print("Please ensure ZIP UFDR files are available in data/UFDR's(new)/")
        print("Skipping query demonstration, showing example queries only...")
        print()
        show_web_interface_queries()
        return
    
    # Run demonstrations
    demonstrate_queries()
    show_web_interface_queries()
    
    print("=" * 60)
    print("EXAMPLE QUERIES DEMONSTRATION COMPLETED")
    print("=" * 60)
    print()
    print("TO START THE SYSTEM:")
    print("1. Run: scripts/QUICK_START.bat")
    print("2. Open: http://localhost:5000")
    print("3. Upload a ZIP UFDR file")
    print("4. Use the example queries above!")

if __name__ == "__main__":
    main()

