#!/usr/bin/env python3
"""
UFDR File Structure Analyzer Module

Analyzes .ufdr files to understand their structure and help with integration.
Supports both ZIP-based and other UFDR formats.
Returns structured data instead of printing.
"""

import os
import zipfile
import json
from collections import defaultdict
from typing import Dict, List, Any, Optional


def format_size(size_bytes: float) -> str:
    """Format file size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def analyze_ufdr_file(file_path: str) -> Dict[str, Any]:
    """
    Analyze a UFDR file to understand its structure.
    
    Args:
        file_path: Path to the UFDR file to analyze
        
    Returns:
        Dictionary with analysis results
    """
    result = {
        'success': False,
        'error': None,
        'file_info': {},
        'structure': {},
        'images': {},
        'videos': {},
        'compatibility': {},
        'recommendations': []
    }
    
    # Check if file exists
    if not os.path.exists(file_path):
        result['error'] = "File not found"
        return result
    
    # File basic info
    file_size = os.path.getsize(file_path)
    result['file_info'] = {
        'filename': os.path.basename(file_path),
        'path': os.path.dirname(os.path.abspath(file_path)),
        'size': file_size,
        'size_formatted': format_size(file_size),
        'format': None
    }
    
    # Check if it's a ZIP file
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            result['file_info']['format'] = 'ZIP Archive'
            
            # Get file list
            file_list = zip_ref.namelist()
            result['file_info']['total_files'] = len(file_list)
            
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
            
            result['structure'] = {
                'artifacts_count': len(structure['artifacts']),
                'metadata_count': len(structure['metadata']),
                'media_images_count': len(structure['media_images']),
                'media_videos_count': len(structure['media_videos']),
                'reports_count': len(structure['reports']),
                'other_count': len(structure['other']),
                'artifacts': structure['artifacts'][:10],  # Sample
                'metadata': structure['metadata'][:10],
                'reports': structure['reports'][:10]
            }
            
            # Analyze Artifacts folder structure
            if structure['artifacts']:
                artifact_types = defaultdict(list)
                for artifact in structure['artifacts']:
                    parts = artifact.replace('\\', '/').split('/')
                    if len(parts) >= 2:
                        artifact_type = parts[1]
                        artifact_types[artifact_type].append(artifact)
                
                result['structure']['artifact_types'] = {
                    k: {'count': len(v), 'samples': v[:3]} 
                    for k, v in sorted(artifact_types.items(), key=lambda x: len(x[1]), reverse=True)
                }
            
            # Analyze images
            image_files = []
            image_formats = defaultdict(int)
            image_sizes = []
            image_locations = defaultdict(list)
            
            for file_info in zip_ref.infolist():
                filename = file_info.filename
                filename_lower = filename.lower()
                file_size = file_info.file_size
                
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
            
            if image_files:
                total_image_size = sum(image_sizes)
                avg_image_size = total_image_size / len(image_files) if image_files else 0
                largest_image = max(image_files, key=lambda x: x['size'])
                smallest_image = min(image_files, key=lambda x: x['size'])
                
                result['images'] = {
                    'total': len(image_files),
                    'total_size': total_image_size,
                    'total_size_formatted': format_size(total_image_size),
                    'average_size': format_size(avg_image_size),
                    'largest': {
                        'name': largest_image['name'],
                        'size': format_size(largest_image['size'])
                    },
                    'smallest': {
                        'name': smallest_image['name'],
                        'size': format_size(smallest_image['size'])
                    },
                    'formats': {
                        fmt: {
                            'count': count,
                            'size': format_size(sum(img['size'] for img in image_files if img['format'] == fmt))
                        }
                        for fmt, count in sorted(image_formats.items(), key=lambda x: x[1], reverse=True)
                    },
                    'locations': {
                        loc: {
                            'count': len(files),
                            'size': format_size(sum(img['size'] for img in image_files if any(f in img['path'] for f in files))),
                            'samples': [os.path.basename(f) for f in files[:3]]
                        }
                        for loc, files in sorted(image_locations.items(), key=lambda x: len(x[1]), reverse=True)
                    }
                }
            
            # Analyze videos
            video_files = []
            video_formats = defaultdict(int)
            video_sizes = []
            video_locations = defaultdict(list)
            
            for file_info in zip_ref.infolist():
                filename = file_info.filename
                filename_lower = filename.lower()
                file_size = file_info.file_size
                
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
            
            if video_files:
                total_video_size = sum(video_sizes)
                avg_video_size = total_video_size / len(video_files) if video_files else 0
                largest_video = max(video_files, key=lambda x: x['size'])
                smallest_video = min(video_files, key=lambda x: x['size'])
                
                result['videos'] = {
                    'total': len(video_files),
                    'total_size': total_video_size,
                    'total_size_formatted': format_size(total_video_size),
                    'average_size': format_size(avg_video_size),
                    'largest': {
                        'name': largest_video['name'],
                        'size': format_size(largest_video['size'])
                    },
                    'smallest': {
                        'name': smallest_video['name'],
                        'size': format_size(smallest_video['size'])
                    },
                    'formats': {
                        fmt: {
                            'count': count,
                            'size': format_size(sum(vid['size'] for vid in video_files if vid['format'] == fmt))
                        }
                        for fmt, count in sorted(video_formats.items(), key=lambda x: x[1], reverse=True)
                    },
                    'locations': {
                        loc: {
                            'count': len(files),
                            'size': format_size(sum(vid['size'] for vid in video_files if any(f in vid['path'] for f in files))),
                            'samples': [os.path.basename(f) for f in files[:3]]
                        }
                        for loc, files in sorted(video_locations.items(), key=lambda x: len(x[1]), reverse=True)
                    }
                }
            
            # Calculate size breakdown
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
            
            result['size_breakdown'] = {
                'total': total_size,
                'total_formatted': format_size(total_size),
                'json': {'size': json_size, 'size_formatted': format_size(json_size), 'percentage': json_size/total_size*100 if total_size > 0 else 0},
                'images': {'size': image_size, 'size_formatted': format_size(image_size), 'percentage': image_size/total_size*100 if total_size > 0 else 0},
                'videos': {'size': video_size, 'size_formatted': format_size(video_size), 'percentage': video_size/total_size*100 if total_size > 0 else 0},
                'other': {'size': other_size, 'size_formatted': format_size(other_size), 'percentage': other_size/total_size*100 if total_size > 0 else 0}
            }
            
            # Compression ratio
            compression_ratio = (1 - file_size / total_size) * 100 if total_size > 0 else 0
            result['compression'] = {
                'ratio': compression_ratio,
                'compressed_size': format_size(file_size),
                'uncompressed_size': format_size(total_size)
            }
            
            # Compatibility check
            has_artifacts = len(structure['artifacts']) > 0
            has_metadata = len(structure['metadata']) > 0
            has_contacts = any('contact' in f.lower() for f in structure['artifacts'])
            has_messages = any(any(x in f.lower() for x in ['sms', 'whatsapp', 'message']) for f in structure['artifacts'])
            has_calls = any('call' in f.lower() for f in structure['artifacts'])
            
            result['compatibility'] = {
                'has_artifacts': has_artifacts,
                'has_metadata': has_metadata,
                'has_contacts': has_contacts,
                'has_messages': has_messages,
                'has_calls': has_calls,
                'is_compatible': has_artifacts and (has_contacts or has_messages or has_calls)
            }
            
            # Top-level directory structure
            top_level_dirs = defaultdict(int)
            for file_path_in_zip in file_list:
                parts = file_path_in_zip.replace('\\', '/').split('/')
                if len(parts) > 0:
                    first_dir = parts[0]
                    if first_dir and not '.' in first_dir.split('/')[0]:
                        top_level_dirs[first_dir] += 1
            
            result['directory_structure'] = {
                dir_name: file_count
                for dir_name, file_count in sorted(top_level_dirs.items(), key=lambda x: x[1], reverse=True)
            }
            
            # Check for Cellebrite lightweight format
            db_files = [f for f in file_list if f.endswith('.db')]
            if db_files and len(db_files) > 100:
                result['cellebrite_format'] = {
                    'detected': True,
                    'db_count': len(db_files),
                    'format_type': 'lightweight',
                    'supported': True  # Now supported!
                }
                
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
                
                result['cellebrite_format']['database_categories'] = {
                    k: {'count': len(v), 'samples': [os.path.basename(f) for f in v[:3]]}
                    for k, v in sorted(db_categories.items())
                }
                
                result['recommendations'].append("Cellebrite lightweight format is now supported! You can upload this file directly.")
            else:
                result['cellebrite_format'] = {'detected': False}
            
            # JSON files analysis
            json_files = [f for f in file_list if f.lower().endswith('.json')]
            result['json_files'] = {
                'count': len(json_files),
                'samples': json_files[:5]
            }
            
            # XML files
            xml_files = [f for f in file_list if f.endswith('.xml')]
            result['xml_files'] = {
                'count': len(xml_files),
                'samples': xml_files[:5]
            }
            
            result['success'] = True
            
    except zipfile.BadZipFile:
        result['file_info']['format'] = 'Not a ZIP archive'
        result['error'] = "File is not a ZIP archive"
        
        # Check if it might be JSON
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                sample = f.read(1000)
                if sample.strip().startswith('{') or sample.strip().startswith('['):
                    result['file_info']['format'] = 'JSON'
                    result['recommendations'].append("Rename to .json and upload")
                else:
                    result['error'] = "File is binary or unknown format"
                    result['recommendations'].append("Export from Cellebrite in ZIP format")
        except UnicodeDecodeError:
            result['error'] = "File is binary (not text/JSON)"
            result['recommendations'].append("Export from Cellebrite in ZIP format")
        except Exception as e:
            result['error'] = f"Could not read file: {str(e)}"
    
    except Exception as e:
        result['error'] = f"Error analyzing file: {str(e)}"
        result['success'] = False
    
    # Add recommendations based on compatibility
    if result.get('compatibility', {}).get('is_compatible'):
        result['recommendations'].append("File appears compatible with EVI - ready to upload")
    elif result.get('file_info', {}).get('format') == 'ZIP Archive':
        result['recommendations'].append("Rename to .zip and upload through web interface")
    
    return result

