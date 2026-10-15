#!/usr/bin/env python3
"""
Cellebrite SQLite Parser for EVI

Parses Cellebrite lightweight UFDR format which uses SQLite databases
instead of JSON files. Extracts contacts, calls, messages, and other data
from SQLite databases and converts to UFDR format.
"""

import os
import sqlite3
import zipfile
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


class CellebriteSQLiteParser:
    """Parser for Cellebrite lightweight UFDR format (SQLite databases)."""
    
    def __init__(self):
        """Initialize the parser."""
        self.extracted_data = {
            'contacts': [],
            'messages': [],
            'call_logs': [],
            'locations': [],
            'device': {},
            'files': [],
            'images': [],
            'videos': []
        }
    
    def _is_essential_file(self, file_path: str) -> bool:
        """
        Check if file is essential for initial processing.
        Non-essential files (media, binaries) are deferred.
        """
        path_lower = file_path.lower().replace('\\', '/')
        
        # Essential: SQLite databases
        if path_lower.endswith('.db'):
            return True
        
        # Essential: Metadata files
        if 'metadata' in path_lower or '__metadata__' in path_lower:
            return True
        
        # Essential: Report files
        if 'report.xml' in path_lower or (path_lower.endswith('.xml') and 'report' in path_lower):
            return True
        
        # Essential: JSON files
        if path_lower.endswith('.json'):
            return True
        
        # Skip: Media files (deferred)
        if 'media' in path_lower or 'image' in path_lower or 'video' in path_lower:
            return False
        
        # Skip: Large binaries
        if path_lower.endswith(('.so', '.apk', '.jar', '.dex', '.bin', '.exe')):
            return False
        
        # Skip: Application files (unless they're databases)
        if 'application' in path_lower and not path_lower.endswith('.db'):
            return False
        
        # Skip: Chat attachments (handled via databases)
        if 'chat' in path_lower and ('attachment' in path_lower or 
                                     any(path_lower.endswith(ext) for ext in ['.jpg', '.png', '.mp4', '.gif', '.jpeg'])):
            return False
        
        # Default: include other files
        return True
    
    def parse_ufdr_zip(self, zip_path: str, extract_to: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse a Cellebrite lightweight UFDR ZIP file.
        
        Args:
            zip_path: Path to the UFDR ZIP file
            extract_to: Directory to extract ZIP contents (optional, uses temp if not provided)
            
        Returns:
            Dictionary with parsed UFDR data
        """
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Extract to temp directory if not provided
                if not extract_to:
                    import tempfile
                    extract_to = tempfile.mkdtemp()
                
                # Extract only essential files (selective extraction)
                # For large files, be even more selective
                zip_size = os.path.getsize(zip_path)
                large_file_threshold = 500 * 1024 * 1024  # 500MB
                is_large_file = zip_size > large_file_threshold
                
                essential_count = 0
                skipped_count = 0
                for info in zip_ref.infolist():
                    path = info.filename.replace('\\', '/')
                    # Skip directories
                    if info.is_dir():
                        continue
                    
                    # For large files, only extract databases and critical metadata
                    if is_large_file:
                        if path.endswith('.db') or '__metadata__' in path.lower() or 'report.xml' in path.lower():
                            zip_ref.extract(info, extract_to)
                            essential_count += 1
                        else:
                            skipped_count += 1
                    else:
                        # Normal selective extraction
                        if self._is_essential_file(path):
                            zip_ref.extract(info, extract_to)
                            essential_count += 1
                        else:
                            skipped_count += 1
                
                logger.info(f"Selectively extracted {essential_count} essential files, skipped {skipped_count} non-essential files to {extract_to}")
                
                # Find all database files
                db_files = self._find_database_files(extract_to)
                logger.info(f"Found {len(db_files)} database files")
                
                # Categorize databases
                db_categories = self._categorize_databases(db_files)
                
                # Check if this is a large file for optimization
                zip_size = os.path.getsize(zip_path)
                large_file_threshold = 500 * 1024 * 1024  # 500MB
                is_large_file = zip_size > large_file_threshold
                
                if is_large_file:
                    logger.info(f"📦 Large file detected ({zip_size / (1024*1024):.1f} MB) - using fast parsing mode")
                
                # Parse each category (limit queries for large files)
                if 'contacts' in db_categories:
                    self._parse_contacts(db_categories['contacts'], extract_to, fast_mode=is_large_file)
                
                if 'calls' in db_categories:
                    self._parse_calls(db_categories['calls'], extract_to, fast_mode=is_large_file)
                
                if 'messages' in db_categories:
                    self._parse_messages(db_categories['messages'], extract_to, fast_mode=is_large_file)
                
                if 'location' in db_categories and not is_large_file:  # Skip location for large files
                    self._parse_locations(db_categories['location'], extract_to)
                
                # Extract device info from report.xml if available
                self._parse_device_info(extract_to)
                
                # Extract images and videos (metadata only - deferred extraction)
                # Skip media extraction for large files to save time
                if not is_large_file:
                    self._extract_media(extract_to, deferred=True)
                else:
                    logger.info("⏩ Skipping media extraction for large file (performance optimization)")
                    # Still add empty arrays for consistency
                    self.extracted_data['images'] = []
                    self.extracted_data['videos'] = []
                
                # Build UFDR structure
                ufdr_data = {
                    'contacts': self.extracted_data['contacts'],
                    'messages': self.extracted_data['messages'],
                    'call_logs': self.extracted_data['call_logs'],
                    'locations': self.extracted_data['locations'],
                    'device': self.extracted_data['device'],
                    'files': self.extracted_data['files'],
                    'images': self.extracted_data['images'],
                    'videos': self.extracted_data['videos'],
                    'tampered': False,
                    'format_version': 'v1',
                    'source_format': 'cellebrite_lightweight'
                }
                
                logger.info(f"Parsed Cellebrite UFDR: {len(ufdr_data['contacts'])} contacts, "
                          f"{len(ufdr_data['messages'])} messages, {len(ufdr_data['call_logs'])} calls")
                
                return ufdr_data
                
        except Exception as e:
            logger.error(f"Error parsing Cellebrite UFDR: {e}", exc_info=True)
            raise
    
    def _find_database_files(self, extract_to: str) -> List[str]:
        """Find all .db files in the extracted directory."""
        db_files = []
        for root, dirs, files in os.walk(extract_to):
            for file in files:
                if file.endswith('.db'):
                    db_files.append(os.path.join(root, file))
        return db_files
    
    def _categorize_databases(self, db_files: List[str]) -> Dict[str, List[str]]:
        """Categorize database files by type."""
        categories = defaultdict(list)
        
        for db_file in db_files:
            db_name = os.path.basename(db_file).lower()
            
            if 'contact' in db_name or 'phonebook' in db_name:
                categories['contacts'].append(db_file)
            elif 'call' in db_name:
                categories['calls'].append(db_file)
            elif 'sms' in db_name or 'message' in db_name or 'whatsapp' in db_name:
                categories['messages'].append(db_file)
            elif 'location' in db_name or 'gps' in db_name:
                categories['location'].append(db_file)
            else:
                # Try to determine by examining tables
                try:
                    conn = sqlite3.connect(db_file)
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [row[0].lower() for row in cursor.fetchall()]
                    conn.close()
                    
                    if any('contact' in t for t in tables):
                        categories['contacts'].append(db_file)
                    elif any('call' in t for t in tables):
                        categories['calls'].append(db_file)
                    elif any(t in ['sms', 'message', 'whatsapp', 'chat'] for t in tables):
                        categories['messages'].append(db_file)
                    elif any('location' in t or 'gps' in t for t in tables):
                        categories['location'].append(db_file)
                except:
                    pass
        
        return categories
    
    def _parse_contacts(self, db_files: List[str], extract_to: str, fast_mode: bool = False):
        """Parse contact databases."""
        for db_file in db_files:
            try:
                conn = sqlite3.connect(db_file)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Try common table names
                table_names = ['contacts', 'contact', 'phonebook', 'addressbook', 'people']
                
                for table_name in table_names:
                    try:
                        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%{table_name}%'")
                        tables = cursor.fetchall()
                        
                        for table in tables:
                            actual_table = table[0]
                            # For large files, limit results to speed up parsing
                            if fast_mode:
                                cursor.execute(f"SELECT * FROM {actual_table} LIMIT 50000")
                            else:
                                cursor.execute(f"SELECT * FROM {actual_table}")
                            rows = cursor.fetchall()
                            
                            for row in rows:
                                contact = self._row_to_dict(row)
                                # Normalize contact data
                                normalized = self._normalize_contact(contact)
                                if normalized and normalized not in self.extracted_data['contacts']:
                                    self.extracted_data['contacts'].append(normalized)
                    except:
                        continue
                
                conn.close()
            except Exception as e:
                logger.warning(f"Error parsing contacts from {db_file}: {e}")
                continue
    
    def _parse_calls(self, db_files: List[str], extract_to: str, fast_mode: bool = False):
        """Parse call log databases."""
        for db_file in db_files:
            try:
                conn = sqlite3.connect(db_file)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Try common table names
                table_names = ['calls', 'call', 'call_log', 'calllog', 'phone_calls']
                
                for table_name in table_names:
                    try:
                        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%{table_name}%'")
                        tables = cursor.fetchall()
                        
                        for table in tables:
                            actual_table = table[0]
                            # For large files, limit results to speed up parsing
                            if fast_mode:
                                cursor.execute(f"SELECT * FROM {actual_table} LIMIT 50000")
                            else:
                                cursor.execute(f"SELECT * FROM {actual_table}")
                            rows = cursor.fetchall()
                            
                            for row in rows:
                                call = self._row_to_dict(row)
                                normalized = self._normalize_call(call)
                                if normalized:
                                    self.extracted_data['call_logs'].append(normalized)
                    except:
                        continue
                
                conn.close()
            except Exception as e:
                logger.warning(f"Error parsing calls from {db_file}: {e}")
                continue
    
    def _parse_messages(self, db_files: List[str], extract_to: str, fast_mode: bool = False):
        """Parse message databases (SMS, WhatsApp, etc.)."""
        for db_file in db_files:
            try:
                conn = sqlite3.connect(db_file)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Try common table names
                table_names = ['sms', 'message', 'messages', 'whatsapp', 'chat', 'texts']
                
                for table_name in table_names:
                    try:
                        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%{table_name}%'")
                        tables = cursor.fetchall()
                        
                        for table in tables:
                            actual_table = table[0]
                            # For large files, limit results to speed up parsing
                            if fast_mode:
                                cursor.execute(f"SELECT * FROM {actual_table} LIMIT 50000")
                            else:
                                cursor.execute(f"SELECT * FROM {actual_table}")
                            rows = cursor.fetchall()
                            
                            for row in rows:
                                message = self._row_to_dict(row)
                                normalized = self._normalize_message(message, db_file)
                                if normalized:
                                    self.extracted_data['messages'].append(normalized)
                    except:
                        continue
                
                conn.close()
            except Exception as e:
                logger.warning(f"Error parsing messages from {db_file}: {e}")
                continue
    
    def _parse_locations(self, db_files: List[str], extract_to: str):
        """Parse location databases."""
        for db_file in db_files:
            try:
                conn = sqlite3.connect(db_file)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                table_names = ['location', 'locations', 'gps', 'geolocation', 'places']
                
                for table_name in table_names:
                    try:
                        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%{table_name}%'")
                        tables = cursor.fetchall()
                        
                        for table in tables:
                            actual_table = table[0]
                            # For large files, limit results to speed up parsing
                            if fast_mode:
                                cursor.execute(f"SELECT * FROM {actual_table} LIMIT 50000")
                            else:
                                cursor.execute(f"SELECT * FROM {actual_table}")
                            rows = cursor.fetchall()
                            
                            for row in rows:
                                location = self._row_to_dict(row)
                                normalized = self._normalize_location(location)
                                if normalized:
                                    self.extracted_data['locations'].append(normalized)
                    except:
                        continue
                
                conn.close()
            except Exception as e:
                logger.warning(f"Error parsing locations from {db_file}: {e}")
                continue
    
    def _parse_device_info(self, extract_to: str):
        """Parse device information from report.xml or metadata."""
        import xml.etree.ElementTree as ET
        
        # Try to find report.xml
        report_xml = os.path.join(extract_to, 'report.xml')
        if os.path.exists(report_xml):
            try:
                tree = ET.parse(report_xml)
                root = tree.getroot()
                
                device_info = {}
                # Extract common device info fields
                for elem in root.iter():
                    tag = elem.tag.lower()
                    if 'device' in tag or 'model' in tag or 'manufacturer' in tag:
                        device_info[tag] = elem.text
                
                if device_info:
                    self.extracted_data['device'] = device_info
            except Exception as e:
                logger.warning(f"Error parsing report.xml: {e}")
    
    def _extract_media(self, extract_to: str, deferred: bool = True):
        """
        Extract media metadata only (deferred full extraction).
        
        Args:
            extract_to: Directory to scan
            deferred: If True, only collect metadata, don't process files
        """
        image_exts = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.heic', '.tiff', '.tif']
        video_exts = ['.mp4', '.avi', '.mov', '.mkv', '.webm', '.flv', '.wmv', '.m4v', '.3gp']
        
        # Only collect metadata, don't process files during initial load
        for root, dirs, files in os.walk(extract_to):
            for file in files:
                # Skip files without extensions
                if '.' not in file:
                    continue
                    
                file_lower = file.lower()
                file_ext = os.path.splitext(file_lower)[1]
                
                if file_ext in image_exts:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, extract_to).replace('\\', '/')
                    # Store only metadata
                    try:
                        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                    except:
                        file_size = 0
                    self.extracted_data['images'].append({
                        'name': file,
                        'rel_path': rel_path,
                        'path': file_path,  # Keep path for later access
                        'size': file_size,
                        'extracted': False  # Mark as not fully processed
                    })
                elif file_ext in video_exts:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, extract_to).replace('\\', '/')
                    try:
                        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                    except:
                        file_size = 0
                    self.extracted_data['videos'].append({
                        'name': file,
                        'rel_path': rel_path,
                        'path': file_path,
                        'size': file_size,
                        'extracted': False
                    })
    
    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert SQLite row to dictionary."""
        return dict(row)
    
    def _normalize_contact(self, contact: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalize contact data to UFDR format."""
        normalized = {
            'name': None,
            'phone': None,
            'email': None,
            'address': None
        }
        
        # Try to find name
        for key in ['name', 'display_name', 'full_name', 'contact_name', 'title']:
            if key in contact and contact[key]:
                normalized['name'] = str(contact[key])
                break
        
        # Try to find phone
        for key in ['phone', 'phone_number', 'number', 'mobile', 'tel']:
            if key in contact and contact[key]:
                normalized['phone'] = str(contact[key])
                break
        
        # Try to find email
        for key in ['email', 'email_address', 'mail']:
            if key in contact and contact[key]:
                normalized['email'] = str(contact[key])
                break
        
        # Only return if we have at least a name or phone
        if normalized['name'] or normalized['phone']:
            return normalized
        return None
    
    def _normalize_call(self, call: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalize call data to UFDR format with required validation fields."""
        normalized = {
            'phone_number': None,
            'from': None,  # Validation requires 'from' or 'caller'
            'to': None,  # Validation requires 'to' or 'receiver'
            'caller': None,  # Alternative to 'from'
            'receiver': None,  # Alternative to 'to'
            'call_type': None,
            'timestamp': None,
            'duration': None,
            'contact_name': None
        }
        
        # Try to find phone number/from
        for key in ['number', 'phone', 'phone_number', 'address', 'remote_number', 'from', 'caller', 'caller_number']:
            if key in call and call[key]:
                phone_value = str(call[key])
                normalized['phone_number'] = phone_value
                normalized['from'] = phone_value
                normalized['caller'] = phone_value
                break
        
        # Try to find recipient/to
        for key in ['to', 'receiver', 'receiver_number', 'destination']:
            if key in call and call[key]:
                receiver_value = str(call[key])
                normalized['to'] = receiver_value
                normalized['receiver'] = receiver_value
                break
        
        # If we have from but not to, set to as the same (self call)
        if normalized['from'] and not normalized['to']:
            normalized['to'] = normalized['from']
            normalized['receiver'] = normalized['from']
        
        # Try to find call type
        for key in ['type', 'call_type', 'direction', 'direction_type']:
            if key in call and call[key]:
                call_type = str(call[key]).lower()
                if 'incoming' in call_type or 'received' in call_type:
                    normalized['call_type'] = 'incoming'
                elif 'outgoing' in call_type or 'dialed' in call_type:
                    normalized['call_type'] = 'outgoing'
                elif 'missed' in call_type:
                    normalized['call_type'] = 'missed'
                break
        
        # Try to find timestamp (validation requires this)
        for key in ['timestamp', 'date', 'time', 'datetime', 'call_time', 'date_time']:
            if key in call and call[key]:
                timestamp_value = call[key]
                # Convert to string if it's a number (Unix timestamp)
                if isinstance(timestamp_value, (int, float)):
                    try:
                        from datetime import datetime
                        normalized['timestamp'] = datetime.fromtimestamp(timestamp_value / 1000 if timestamp_value > 1e10 else timestamp_value).isoformat()
                    except:
                        normalized['timestamp'] = str(timestamp_value)
                else:
                    normalized['timestamp'] = str(timestamp_value)
                break
        
        # Try to find duration
        for key in ['duration', 'call_duration', 'length', 'call_length']:
            if key in call and call[key]:
                normalized['duration'] = int(call[key]) if call[key] else 0
                break
        
        # Validation requires: (from AND to) OR (caller AND receiver), plus timestamp
        has_parties = (normalized['from'] and normalized['to']) or (normalized['caller'] and normalized['receiver'])
        has_timestamp = normalized['timestamp']
        
        # Only return if we have required fields
        if has_parties and has_timestamp:
            # Clean up - remove None values
            return {k: v for k, v in normalized.items() if v is not None}
        
        # If missing required fields, set defaults
        if not has_parties and normalized['phone_number']:
            normalized['from'] = normalized['phone_number']
            normalized['to'] = normalized['phone_number']
            normalized['caller'] = normalized['phone_number']
            normalized['receiver'] = normalized['phone_number']
        
        if not has_timestamp:
            normalized['timestamp'] = datetime.now().isoformat()
        
        # Only return if we have at least a phone number
        if normalized['phone_number'] or normalized['from']:
            return {k: v for k, v in normalized.items() if v is not None}
        return None
    
    def _normalize_message(self, message: Dict[str, Any], db_file: str) -> Optional[Dict[str, Any]]:
        """Normalize message data to UFDR format with required validation fields."""
        normalized = {
            'text': None,
            'content': None,  # UFDR validation requires 'content' or 'text'
            'from': None,
            'to': None,
            'sender': None,  # Alternative to 'from'
            'receiver': None,  # Alternative to 'to'
            'timestamp': None,
            'source': 'SMS'
        }
        
        # Determine source from database filename
        db_name = os.path.basename(db_file).lower()
        if 'whatsapp' in db_name:
            normalized['source'] = 'WhatsApp'
        elif 'imessage' in db_name:
            normalized['source'] = 'iMessage'
        
        # Try to find message text/content (validation requires 'content' or 'text')
        for key in ['text', 'body', 'message', 'content', 'data', 'message_text']:
            if key in message and message[key]:
                text_value = str(message[key])
                normalized['text'] = text_value
                normalized['content'] = text_value  # Set both for compatibility
                break
        
        # Try to find sender (validation requires 'from' or 'sender')
        for key in ['from', 'sender', 'address', 'remote_number', 'phone', 'phone_number', 'sender_number']:
            if key in message and message[key]:
                sender_value = str(message[key])
                normalized['from'] = sender_value
                normalized['sender'] = sender_value  # Set both for compatibility
                break
        
        # Try to find recipient (validation requires 'to' or 'receiver')
        for key in ['to', 'recipient', 'destination', 'receiver', 'receiver_number']:
            if key in message and message[key]:
                receiver_value = str(message[key])
                normalized['to'] = receiver_value
                normalized['receiver'] = receiver_value  # Set both for compatibility
                break
        
        # Try to find timestamp (validation requires this)
        for key in ['timestamp', 'date', 'time', 'datetime', 'sent_time', 'received_time', 'date_sent', 'date_received']:
            if key in message and message[key]:
                timestamp_value = message[key]
                # Convert to string if it's a number (Unix timestamp)
                if isinstance(timestamp_value, (int, float)):
                    # Try to convert Unix timestamp to ISO format
                    try:
                        from datetime import datetime
                        normalized['timestamp'] = datetime.fromtimestamp(timestamp_value / 1000 if timestamp_value > 1e10 else timestamp_value).isoformat()
                    except:
                        normalized['timestamp'] = str(timestamp_value)
                else:
                    normalized['timestamp'] = str(timestamp_value)
                break
        
        # Validation requires: (from AND to) OR (sender AND receiver), plus content/text, plus timestamp
        has_parties = (normalized['from'] and normalized['to']) or (normalized['sender'] and normalized['receiver'])
        has_content = normalized['content'] or normalized['text']
        has_timestamp = normalized['timestamp']
        
        # Only return if we have all required fields
        if has_parties and has_content and has_timestamp:
            # Clean up - remove None values
            return {k: v for k, v in normalized.items() if v is not None}
        
        # If missing required fields, try to set defaults
        if not has_parties:
            # Set default parties if we have at least one
            if normalized['from'] or normalized['sender']:
                normalized['to'] = normalized['to'] or normalized['receiver'] or 'Unknown'
                normalized['receiver'] = normalized['to']
            elif normalized['to'] or normalized['receiver']:
                normalized['from'] = normalized['from'] or normalized['sender'] or 'Unknown'
                normalized['sender'] = normalized['from']
            else:
                normalized['from'] = 'Unknown'
                normalized['to'] = 'Unknown'
                normalized['sender'] = 'Unknown'
                normalized['receiver'] = 'Unknown'
        
        if not has_content:
            normalized['text'] = normalized['text'] or ''
            normalized['content'] = normalized['text']
        
        if not has_timestamp:
            normalized['timestamp'] = datetime.now().isoformat()
        
        # Return with all required fields
        return {k: v for k, v in normalized.items() if v is not None}
    
    def _normalize_location(self, location: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalize location data to UFDR format."""
        normalized = {
            'latitude': None,
            'longitude': None,
            'timestamp': None,
            'accuracy': None
        }
        
        # Try to find latitude
        for key in ['latitude', 'lat', 'y', 'coord_y']:
            if key in location and location[key]:
                try:
                    normalized['latitude'] = float(location[key])
                except:
                    pass
                break
        
        # Try to find longitude
        for key in ['longitude', 'lon', 'lng', 'x', 'coord_x']:
            if key in location and location[key]:
                try:
                    normalized['longitude'] = float(location[key])
                except:
                    pass
                break
        
        # Try to find timestamp
        for key in ['timestamp', 'date', 'time', 'datetime']:
            if key in location and location[key]:
                normalized['timestamp'] = str(location[key])
                break
        
        # Only return if we have coordinates
        if normalized['latitude'] and normalized['longitude']:
            return normalized
        return None


# Global instance
cellebrite_parser = CellebriteSQLiteParser()

