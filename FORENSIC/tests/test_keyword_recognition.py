#!/usr/bin/env python3
"""
Keyword Recognition Test for UFDR ZIP Files
Tests keyword recognition using ZIP UFDR files
"""

import json
import sys
import os
import zipfile
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engines.enhanced_nl_query_engine import EnhancedNaturalLanguageUFDR

def load_ufdr_from_zip(zip_path: str):
    """Load UFDR data from ZIP file"""
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

def test_keyword_recognition():
    """Test keyword recognition with ZIP UFDR files"""
    print("=" * 80)
    print("KEYWORD RECOGNITION TEST")
    print("=" * 80)
    
    engine = EnhancedNaturalLanguageUFDR()
    
    # Test with available ZIP files
    test_files = [
        ("../data/UFDR's(new)/case 1 Kidnapping Conspiracy.zip", "Kidnapping Conspiracy"),
        ("../data/UFDR's(new)/case 2 Human Trafficking.zip", "Human Trafficking"),
        ("../data/UFDR's(new)/case 3 Cyber Fraud  Phishing.zip", "Cyber Fraud Phishing")
    ]
    
    for file_path, case_type in test_files:
        if not os.path.exists(file_path):
            print(f"Skipping {file_path} - file not found")
            continue
            
        print(f"\n{'='*60}")
        print(f"TESTING: {file_path}")
        print(f"Case Type: {case_type}")
        print(f"{'='*60}")
        
        try:
            # Load data from ZIP
            data = load_ufdr_from_zip(file_path)
            engine.ufdr_data = {"test_case": data}
            
            # Test queries
            test_queries = [
                "show all contacts",
                "find messages about money",
                "show calls from last week"
            ]
            
            for query in test_queries:
                print(f"\nQuery: '{query}'")
                result = engine.process_query(query)
                if result and result.matches:
                    print(f"  Found {len(result.matches)} matches")
                    print(f"  Confidence: {result.confidence}%")
                else:
                    print(f"  No matches found")
            
            print(f"\n✓ Test completed for {case_type}")
            
        except Exception as e:
            print(f"✗ Error analyzing {file_path}: {e}")
            import traceback
            traceback.print_exc()

def main():
    """Run keyword recognition tests"""
    print("UFDR Keyword Recognition Test Suite")
    print("Testing with ZIP UFDR files")
    print()
    
    test_keyword_recognition()
    
    print(f"\n{'='*80}")
    print("KEYWORD RECOGNITION TESTING COMPLETED")
    print(f"{'='*80}")

if __name__ == "__main__":
    main()
