#!/usr/bin/env python3
"""
UFDR File Structure Analyzer

Analyzes .ufdr files to understand their structure and help with integration.
Supports both ZIP-based and other UFDR formats.
"""

import os
import sys
import zipfile
import json
from pathlib import Path
from collections import defaultdict

def format_size(size_bytes):
    """Format file size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

def analyze_ufdr_file(file_path):
    """Analyze a UFDR file to understand its structure."""
    
    print("=" * 80)
    print(f"🔍 UFDR FILE STRUCTURE ANALYZER")
    print("=" * 80)
    print(f"\n📄 File: {os.path.basename(file_path)}")
    print(f"📂 Path: {os.path.dirname(os.path.abspath(file_path))}")
    
    # Check if file exists
    if not os.path.exists(file_path):
        print(f"\n❌ Error: File not found!")
        return False
    
    # Check file size
    file_size = os.path.getsize(file_path)
    print(f"💾 File Size: {format_size(file_size)}")
    
    # Check if it's a ZIP file (most UFDR files are ZIP archives)
    is_zip = False
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            is_zip = True
            print(f"\n✅ File Format: ZIP Archive")
            
            # Get file list
            file_list = zip_ref.namelist()
            print(f"📁 Total files in archive: {len(file_list):,}")
            
            # Analyze structure
            structure = {
                'artifacts': [],
                'metadata': [],
                'media_images': [],
                'media_videos': [],
                'reports': [],
                'other': []
            }
            
            # Categorize files
            for file_path_in_zip in file_list:
                path_lower = file_path_in_zip.lower().replace('\\', '/')
                
                if 'artifacts' in path_lower:
                    structure['artifacts'].append(file_path_in_zip)
                elif 'metadata' in path_lower or '__metadata__' in path_lower:
                    structure['metadata'].append(file_path_in_zip)
                elif 'media' in path_lower:
                    if any(ext in path_lower for ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']):
                        structure['media_images'].append(file_path_in_zip)
                    elif any(ext in path_lower for ext in ['.mp4', '.avi', '.mov', '.mkv', '.webm']):
                        structure['media_videos'].append(file_path_in_zip)
                elif 'reports' in path_lower or 'report' in path_lower:
                    structure['reports'].append(file_path_in_zip)
                else:
                    structure['other'].append(file_path_in_zip)
            
            # Print structure summary
            print(f"\n📂 Directory Structure:")
            print(f"  📦 Artifacts/: {len(structure['artifacts']):,} files")
            print(f"  📋 Metadata/: {len(structure['metadata']):,} files")
            print(f"  🖼️  Media/Images: {len(structure['media_images']):,} files")
            print(f"  🎥 Media/Videos: {len(structure['media_videos']):,} files")
            print(f"  📊 Reports/: {len(structure['reports']):,} files")
            print(f"  📄 Other: {len(structure['other']):,} files")
            
            # Analyze Artifacts folder structure
            if structure['artifacts']:
                print(f"\n🔍 Artifacts Analysis:")
                artifact_types = defaultdict(list)
                
                for artifact in structure['artifacts']:
                    # Extract artifact type (e.g., "Calls", "Contacts", "SMS")
                    parts = artifact.replace('\\', '/').split('/')
                    if len(parts) >= 2:
                        artifact_type = parts[1]  # Second part is usually the type
                        artifact_types[artifact_type].append(artifact)
                
                for artifact_type, files in sorted(artifact_types.items()):
                    print(f"  - {artifact_type}: {len(files):,} files")
                    # Show first few files
                    for file in files[:3]:
                        print(f"    • {file}")
                    if len(files) > 3:
                        print(f"    ... and {len(files) - 3:,} more")
            
            # Analyze Metadata files
            if structure['metadata']:
                print(f"\n📋 Metadata Files:")
                for meta_file in structure['metadata'][:10]:
                    print(f"  - {meta_file}")
                if len(structure['metadata']) > 10:
                    print(f"  ... and {len(structure['metadata']) - 10:,} more")
            
            # Analyze Reports
            if structure['reports']:
                print(f"\n📊 Report Files:")
                for report_file in structure['reports'][:10]:
                    print(f"  - {report_file}")
                if len(structure['reports']) > 10:
                    print(f"  ... and {len(structure['reports']) - 10:,} more")
            
            # Try to read sample JSON files to understand data structure
            print(f"\n🔬 Data Structure Analysis:")
            json_files = [f for f in file_list if f.lower().endswith('.json')]
            print(f"  Found {len(json_files):,} JSON files")
            
            # Analyze sample JSON files from different categories
            samples_analyzed = 0
            max_samples = 5
            
            for json_file in json_files:
                if samples_analyzed >= max_samples:
                    break
                
                try:
                    with zip_ref.open(json_file) as f:
                        sample_data = json.load(f)
                        samples_analyzed += 1
                        
                        print(f"\n  📄 Sample: {json_file}")
                        if isinstance(sample_data, dict):
                            keys = list(sample_data.keys())
                            print(f"    Type: Dictionary")
                            print(f"    Keys ({len(keys)}): {', '.join(keys[:10])}")
                            if len(keys) > 10:
                                print(f"    ... and {len(keys) - 10} more keys")
                            
                            # Check if it's a wrapper with lists
                            for key, value in list(sample_data.items())[:3]:
                                if isinstance(value, list):
                                    print(f"    '{key}': List with {len(value):,} items")
                                    if len(value) > 0 and isinstance(value[0], dict):
                                        print(f"      First item keys: {', '.join(list(value[0].keys())[:10])}")
                                        
                        elif isinstance(sample_data, list):
                            print(f"    Type: List")
                            print(f"    Length: {len(sample_data):,} items")
                            if len(sample_data) > 0:
                                if isinstance(sample_data[0], dict):
                                    print(f"    First item keys: {', '.join(list(sample_data[0].keys())[:10])}")
                                    # Show sample first item (truncated)
                                    sample_item = sample_data[0]
                                    sample_str = json.dumps(sample_item, indent=2)
                                    if len(sample_str) > 500:
                                        sample_str = sample_str[:500] + "..."
                                    print(f"    Sample item:\n      {sample_str}")
                                    
                except Exception as e:
                    print(f"    ⚠️  Could not read {json_file}: {e}")
                    continue
            
            # Detailed Image and Video Analysis
            print(f"\n🖼️  IMAGE ANALYSIS:")
            image_files = []
            image_formats = defaultdict(int)
            image_sizes = []
            image_locations = defaultdict(list)
            
            video_files = []
            video_formats = defaultdict(int)
            video_sizes = []
            video_locations = defaultdict(list)
            
            for file_info in zip_ref.infolist():
                filename = file_info.filename
                filename_lower = filename.lower()
                file_size = file_info.file_size
                
                # Check for images
                image_exts = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.heic', '.tiff', '.tif']
                if any(filename_lower.endswith(ext) for ext in image_exts):
                    ext = os.path.splitext(filename)[1].lower()
                    image_formats[ext] += 1
                    image_sizes.append(file_size)
                    image_files.append({
                        'name': os.path.basename(filename),
                        'path': filename,
                        'size': file_size,
                        'format': ext
                    })
                    # Categorize by location
                    path_lower = filename.replace('\\', '/').lower()
                    if 'media' in path_lower or 'image' in path_lower:
                        if 'chat' in path_lower or 'attachment' in path_lower:
                            image_locations['Chat Attachments'].append(filename)
                        else:
                            image_locations['Media/Images'].append(filename)
                    elif 'chat' in path_lower or 'attachment' in path_lower:
                        image_locations['Chat Attachments'].append(filename)
                    elif 'artifact' in path_lower:
                        image_locations['Artifacts'].append(filename)
                    else:
                        image_locations['Other'].append(filename)
                
                # Check for videos
                video_exts = ['.mp4', '.avi', '.mov', '.mkv', '.webm', '.flv', '.wmv', '.m4v', '.3gp']
                if any(filename_lower.endswith(ext) for ext in video_exts):
                    ext = os.path.splitext(filename)[1].lower()
                    video_formats[ext] += 1
                    video_sizes.append(file_size)
                    video_files.append({
                        'name': os.path.basename(filename),
                        'path': filename,
                        'size': file_size,
                        'format': ext
                    })
                    # Categorize by location
                    path_lower = filename.replace('\\', '/').lower()
                    if 'media' in path_lower or 'video' in path_lower:
                        if 'chat' in path_lower or 'attachment' in path_lower:
                            video_locations['Chat Attachments'].append(filename)
                        else:
                            video_locations['Media/Videos'].append(filename)
                    elif 'chat' in path_lower or 'attachment' in path_lower:
                        video_locations['Chat Attachments'].append(filename)
                    elif 'artifact' in path_lower:
                        video_locations['Artifacts'].append(filename)
                    else:
                        video_locations['Other'].append(filename)
            
            # Image Statistics
            if image_files:
                total_image_size = sum(image_sizes)
                avg_image_size = total_image_size / len(image_files) if image_files else 0
                largest_image = max(image_files, key=lambda x: x['size'])
                smallest_image = min(image_files, key=lambda x: x['size'])
                
                print(f"  📊 Total Images: {len(image_files):,}")
                print(f"  💾 Total Size: {format_size(total_image_size)}")
                print(f"  📏 Average Size: {format_size(avg_image_size)}")
                print(f"  📈 Largest: {largest_image['name']} ({format_size(largest_image['size'])})")
                print(f"  📉 Smallest: {smallest_image['name']} ({format_size(smallest_image['size'])})")
                
                print(f"\n  📁 Image Formats:")
                for fmt, count in sorted(image_formats.items(), key=lambda x: x[1], reverse=True):
                    fmt_size = sum(img['size'] for img in image_files if img['format'] == fmt)
                    print(f"    {fmt.upper()}: {count:,} files ({format_size(fmt_size)})")
                
                print(f"\n  📂 Image Locations:")
                for location, files in sorted(image_locations.items(), key=lambda x: len(x[1]), reverse=True):
                    loc_size = sum(img['size'] for img in image_files if any(f in img['path'] for f in files))
                    print(f"    {location}: {len(files):,} files ({format_size(loc_size)})")
                    # Show sample files
                    for sample in files[:3]:
                        print(f"      • {os.path.basename(sample)}")
                    if len(files) > 3:
                        print(f"      ... and {len(files) - 3:,} more")
            else:
                print(f"  ❌ No image files found")
            
            # Video Statistics
            if video_files:
                total_video_size = sum(video_sizes)
                avg_video_size = total_video_size / len(video_files) if video_files else 0
                largest_video = max(video_files, key=lambda x: x['size'])
                smallest_video = min(video_files, key=lambda x: x['size'])
                
                print(f"\n🎥 VIDEO ANALYSIS:")
                print(f"  📊 Total Videos: {len(video_files):,}")
                print(f"  💾 Total Size: {format_size(total_video_size)}")
                print(f"  📏 Average Size: {format_size(avg_video_size)}")
                print(f"  📈 Largest: {largest_video['name']} ({format_size(largest_video['size'])})")
                print(f"  📉 Smallest: {smallest_video['name']} ({format_size(smallest_video['size'])})")
                
                print(f"\n  📁 Video Formats:")
                for fmt, count in sorted(video_formats.items(), key=lambda x: x[1], reverse=True):
                    fmt_size = sum(vid['size'] for vid in video_files if vid['format'] == fmt)
                    print(f"    {fmt.upper()}: {count:,} files ({format_size(fmt_size)})")
                
                print(f"\n  📂 Video Locations:")
                for location, files in sorted(video_locations.items(), key=lambda x: len(x[1]), reverse=True):
                    loc_size = sum(vid['size'] for vid in video_files if any(f in vid['path'] for f in files))
                    print(f"    {location}: {len(files):,} files ({format_size(loc_size)})")
                    # Show sample files
                    for sample in files[:3]:
                        print(f"      • {os.path.basename(sample)}")
                    if len(files) > 3:
                        print(f"      ... and {len(files) - 3:,} more")
            else:
                print(f"\n🎥 VIDEO ANALYSIS:")
                print(f"  ❌ No video files found")
            
            # Calculate overall size breakdown
            print(f"\n💾 OVERALL SIZE BREAKDOWN:")
            total_size = 0
            json_size = 0
            image_size = sum(image_sizes) if image_sizes else 0
            video_size = sum(video_sizes) if video_sizes else 0
            other_size = 0
            
            for file_info in zip_ref.infolist():
                file_size = file_info.file_size
                total_size += file_size
                filename_lower = file_info.filename.lower()
                
                if filename_lower.endswith('.json'):
                    json_size += file_size
                elif not any(filename_lower.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.heic', '.mp4', '.avi', '.mov', '.mkv', '.webm']):
                    other_size += file_size
            
            print(f"  Total uncompressed: {format_size(total_size)}")
            print(f"  JSON files: {format_size(json_size)} ({json_size/total_size*100:.1f}%)")
            print(f"  Images: {format_size(image_size)} ({image_size/total_size*100:.1f}%)")
            print(f"  Videos: {format_size(video_size)} ({video_size/total_size*100:.1f}%)")
            print(f"  Other: {format_size(other_size)} ({other_size/total_size*100:.1f}%)")
            
            # Check compression ratio
            compression_ratio = (1 - file_size / total_size) * 100 if total_size > 0 else 0
            print(f"\n📊 Compression: {compression_ratio:.1f}% (compressed {format_size(file_size)} → uncompressed {format_size(total_size)})")
            
            # Check for standard UFDR structure
            print(f"\n✅ UFDR Format Compatibility Check:")
            has_artifacts = len(structure['artifacts']) > 0
            has_metadata = len(structure['metadata']) > 0
            has_contacts = any('contact' in f.lower() for f in structure['artifacts'])
            has_messages = any(any(x in f.lower() for x in ['sms', 'whatsapp', 'message']) for f in structure['artifacts'])
            has_calls = any('call' in f.lower() for f in structure['artifacts'])
            
            print(f"  Artifacts folder: {'✅' if has_artifacts else '❌'}")
            print(f"  Metadata folder: {'✅' if has_metadata else '❌'}")
            print(f"  Contacts data: {'✅' if has_contacts else '❌'}")
            print(f"  Messages data: {'✅' if has_messages else '❌'}")
            print(f"  Calls data: {'✅' if has_calls else '❌'}")
            
            if has_artifacts and (has_contacts or has_messages or has_calls):
                print(f"\n  ✅ This file appears to be compatible with EVI!")
                print(f"  💡 Recommendation: Rename to .zip and upload through web interface")
            else:
                print(f"\n  ⚠️  This file may need special handling")
            
            # Show top-level directory structure
            print(f"\n📁 Top-Level Directory Structure:")
            top_level_dirs = defaultdict(int)
            for file_path_in_zip in file_list:
                parts = file_path_in_zip.replace('\\', '/').split('/')
                if len(parts) > 0:
                    first_dir = parts[0]
                    if first_dir and not '.' in first_dir.split('/')[0]:
                        top_level_dirs[first_dir] += 1
            
            for dir_name, file_count in sorted(top_level_dirs.items(), key=lambda x: x[1], reverse=True):
                print(f"  {dir_name}/ ({file_count:,} files)")
            
            # Analyze Cellebrite lightweight format (SQLite databases)
            db_files = [f for f in file_list if f.endswith('.db')]
            if db_files and len(db_files) > 100:
                print(f"\n🔍 Cellebrite Lightweight Format Detected:")
                print(f"  This appears to be a Cellebrite 'lightweight' UFDR format")
                print(f"  Uses SQLite databases ({len(db_files):,} .db files) instead of JSON")
                print(f"  ⚠️  This format is NOT directly supported by EVI")
                print(f"  💡 Recommendation: Export from Cellebrite in 'Full' or 'JSON' format")
                
                # Analyze database file names to understand what data they contain
                print(f"\n  📊 Database File Analysis:")
                db_categories = defaultdict(list)
                for db_file in db_files:
                    db_name = os.path.basename(db_file).lower()
                    if 'sms' in db_name or 'message' in db_name:
                        db_categories['SMS/Messages'].append(db_file)
                    elif 'contact' in db_name or 'phonebook' in db_name:
                        db_categories['Contacts'].append(db_file)
                    elif 'call' in db_name:
                        db_categories['Calls'].append(db_file)
                    elif 'whatsapp' in db_name:
                        db_categories['WhatsApp'].append(db_file)
                    elif 'chat' in db_name:
                        db_categories['Chat'].append(db_file)
                    elif 'location' in db_name or 'gps' in db_name:
                        db_categories['Location'].append(db_file)
                    else:
                        db_categories['Other'].append(db_file)
                
                for category, files in sorted(db_categories.items()):
                    if files:
                        print(f"    - {category}: {len(files):,} databases")
                        # Show sample files
                        for sample in files[:3]:
                            print(f"      • {os.path.basename(sample)}")
                        if len(files) > 3:
                            print(f"      ... and {len(files) - 3:,} more")
            
            # Check for report.xml
            xml_files = [f for f in file_list if f.endswith('.xml')]
            if xml_files:
                print(f"\n📄 XML Report Files: {len(xml_files)}")
                for xml_file in xml_files[:5]:
                    print(f"  - {xml_file}")
                    # Try to read report.xml to get device info
                    if 'report.xml' in xml_file.lower():
                        try:
                            with zip_ref.open(xml_file) as f:
                                xml_content = f.read(5000).decode('utf-8', errors='ignore')
                                if 'device' in xml_content.lower() or 'model' in xml_content.lower():
                                    print(f"    (Contains device information)")
                        except:
                            pass
            
    except zipfile.BadZipFile:
        print(f"\n❌ File is NOT a ZIP archive")
        print(f"   This might be a binary UFDR format that needs special handling")
        print(f"   Current EVI only supports ZIP and JSON formats")
        
        # Check if it might be JSON
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Try to read first 1000 bytes
                sample = f.read(1000)
                if sample.strip().startswith('{') or sample.strip().startswith('['):
                    print(f"\n   ✅ File appears to be JSON format")
                    print(f"   💡 Recommendation: Rename to .json and upload")
                    print(f"   First 200 chars: {sample[:200]}")
                else:
                    print(f"\n   ❌ File appears to be binary or unknown format")
                    print(f"   First 100 bytes (hex): {sample[:100].encode().hex()}")
                    print(f"   ⚠️  This format is not currently supported by EVI")
        except UnicodeDecodeError:
            print(f"\n   ❌ File is binary (not text/JSON)")
            print(f"   ⚠️  This format is not currently supported by EVI")
            print(f"   💡 You may need to export from Cellebrite in ZIP format")
        except Exception as e:
            print(f"   ❌ Could not read file: {e}")
    
    except Exception as e:
        print(f"\n❌ Error analyzing file: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n" + "=" * 80)
    print("✅ Analysis Complete")
    print("=" * 80)
    return True

def main():
    """Main function."""
    # Default file path (use your own UFDR under Testing(UFDR)/UFDR/ — not committed)
    default_file = os.path.join("Testing(UFDR)", "UFDR", "report.ufdr")
    
    # Get file path from command line or use default
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = default_file
    
    # Check if file exists
    if not os.path.exists(file_path):
        print(f"❌ Error: File not found: {file_path}")
        print(f"\nUsage: python analyze_ufdr_file.py [path_to_ufdr_file]")
        print(f"\nLooking for files in Testing(UFDR)/UFDR/:")
        
        ufdr_dir = r"Testing(UFDR)\UFDR"
        if os.path.exists(ufdr_dir):
            for file in os.listdir(ufdr_dir):
                if file.endswith('.ufdr'):
                    print(f"  - {os.path.join(ufdr_dir, file)}")
        sys.exit(1)
    
    # Analyze the file
    success = analyze_ufdr_file(file_path)
    
    if success:
        print(f"\n💡 Next Steps:")
        print(f"  1. If file is ZIP format: Rename to .zip and upload via web interface")
        print(f"  2. If file is JSON format: Rename to .json and upload via web interface")
        print(f"  3. If file is binary: Export from Cellebrite in ZIP format")
        print(f"  4. Upload through: http://localhost:5000 (Case Manager → Upload UFDR File)")

if __name__ == "__main__":
    main()

