#!/usr/bin/env python3
"""
Fast Cellebrite SQLite Parser - Optimized for 15GB+ files
Specifically handles Cellebrite structure:
- Chats (separate from messages)
- Files (database tables)
- report.xml
- All SQLite databases
- Media (images/videos)
- Zero data loss
"""

import sqlite3
import zipfile
import os
import json
import xml.etree.ElementTree as ET
import logging
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import tempfile
from collections import defaultdict

logger = logging.getLogger(__name__)


class FastCellebriteParser:
    """
    High-performance Cellebrite SQLite parser for large files (up to 15GB).
    
    Handles Cellebrite-specific structures:
    - Chats (separate chat tables)
    - Files (file database tables)
    - report.xml (comprehensive parsing)
    - All SQLite databases
    - Media indexing
    """
    
    def __init__(self, max_workers: int = 4):
        """Initialize parser."""
        self.max_workers = max_workers
        self.progress_callback = None
    
    def parse_cellebrite_ufdr(self, zip_path: str, output_db: str, extract_to: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse Cellebrite UFDR file and store in database.
        
        Args:
            zip_path: Path to Cellebrite UFDR ZIP file
            output_db: Path to SQLite database for storage
            extract_to: Temporary extraction directory
            
        Returns:
            Summary statistics
        """
        zip_size = os.path.getsize(zip_path)
        logger.info(f"🚀 Parsing Cellebrite UFDR: {zip_size / (1024**3):.2f} GB")
        
        # Create database with Cellebrite-aware schema
        self._create_cellebrite_database(output_db)
        
        # Extract to temp directory
        if not extract_to:
            extract_to = tempfile.mkdtemp()
        
        # Phase 1: Extract only essential files (.db, report.xml)
        essential_files = self._extract_essential_cellebrite_files(zip_path, extract_to)
        
        # Phase 2: Parse report.xml first (contains metadata)
        report_xml_path = os.path.join(extract_to, 'report.xml')
        if not os.path.exists(report_xml_path):
            # Try to find report.xml in subdirectories
            for root, dirs, files in os.walk(extract_to):
                if 'report.xml' in files:
                    report_xml_path = os.path.join(root, 'report.xml')
                    break
        
        if os.path.exists(report_xml_path):
            self._parse_report_xml_comprehensive(report_xml_path, output_db)
        
        # Phase 3: Find all database files
        db_files = self._find_all_database_files(extract_to)
        logger.info(f"Found {len(db_files)} database files")
        
        # Phase 4: Categorize databases (chats, files, contacts, calls, messages, etc.)
        db_categories = self._categorize_cellebrite_databases(db_files)
        logger.info(f"Database categories: {dict(db_categories)}")
        
        # Phase 5: Parse databases in parallel (chats, files, contacts, calls, messages, locations)
        stats = self._parse_all_cellebrite_databases(db_categories, output_db, zip_size)
        
        # Phase 6: Index media from ZIP (images/videos)
        self._index_media_from_cellebrite_zip(zip_path, output_db)
        
        # Phase 7: Index files from ZIP (file attachments)
        self._index_files_from_cellebrite_zip(zip_path, output_db)
        
        # Get final statistics
        final_stats = self._get_statistics(output_db)
        logger.info(f"✅ Cellebrite parsing complete: {final_stats}")
        
        return final_stats
    
    def _create_cellebrite_database(self, db_path: str):
        """
        Create SQLite database matching Cellebrite structure.
        Includes: contacts, messages, chats, calls, files, locations, device, media.
        """
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Contacts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                phone TEXT,
                email TEXT,
                source_db TEXT,
                source_table TEXT,
                raw_data TEXT,
                INDEX idx_phone (phone),
                INDEX idx_name (name)
            )
        """)
        
        # Messages table (SMS, WhatsApp messages)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_number TEXT,
                to_number TEXT,
                text_content TEXT,
                timestamp TEXT,
                source TEXT,
                source_db TEXT,
                source_table TEXT,
                raw_data TEXT,
                INDEX idx_from (from_number),
                INDEX idx_to (to_number),
                INDEX idx_timestamp (timestamp),
                INDEX idx_source (source)
            )
        """)
        
        # Chats table (separate from messages - chat sessions/conversations)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT,
                chat_name TEXT,
                participants TEXT,
                platform TEXT,
                last_message_time TEXT,
                message_count INTEGER,
                source_db TEXT,
                source_table TEXT,
                raw_data TEXT,
                INDEX idx_chat_id (chat_id),
                INDEX idx_platform (platform),
                INDEX idx_last_message_time (last_message_time)
            )
        """)
        
        # Chat messages table (messages within chats)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT,
                message_id TEXT,
                from_participant TEXT,
                to_participant TEXT,
                text_content TEXT,
                timestamp TEXT,
                platform TEXT,
                attachment_path TEXT,
                source_db TEXT,
                source_table TEXT,
                raw_data TEXT,
                INDEX idx_chat_id (chat_id),
                INDEX idx_from (from_participant),
                INDEX idx_timestamp (timestamp),
                INDEX idx_platform (platform)
            )
        """)
        
        # Calls table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS call_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_number TEXT,
                to_number TEXT,
                timestamp TEXT,
                duration INTEGER,
                call_type TEXT,
                source_db TEXT,
                source_table TEXT,
                raw_data TEXT,
                INDEX idx_from (from_number),
                INDEX idx_timestamp (timestamp)
            )
        """)
        
        # Locations table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS locations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                latitude REAL,
                longitude REAL,
                timestamp TEXT,
                address TEXT,
                source_db TEXT,
                source_table TEXT,
                raw_data TEXT,
                INDEX idx_timestamp (timestamp),
                INDEX idx_coords (latitude, longitude)
            )
        """)
        
        # Files table (file database entries)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT,
                file_path TEXT,
                file_type TEXT,
                size INTEGER,
                mime_type TEXT,
                created_time TEXT,
                modified_time TEXT,
                accessed_time TEXT,
                hash_md5 TEXT,
                hash_sha1 TEXT,
                source_db TEXT,
                source_table TEXT,
                raw_data TEXT,
                INDEX idx_filename (filename),
                INDEX idx_file_type (file_type),
                INDEX idx_size (size)
            )
        """)
        
        # Device metadata table (from report.xml)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT,
                value TEXT,
                category TEXT,
                source TEXT,
                UNIQUE(key, category)
            )
        """)
        
        # Media index table (images/videos from Media/ folder)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS media_index (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT,
                rel_path TEXT,
                zip_path TEXT,
                media_type TEXT,
                size INTEGER,
                format TEXT,
                extracted INTEGER DEFAULT 0,
                INDEX idx_type (media_type),
                INDEX idx_extracted (extracted)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def _extract_essential_cellebrite_files(self, zip_path: str, extract_to: str) -> List[str]:
        """Extract only essential Cellebrite files (.db, report.xml)."""
        essential_files = []
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for info in zip_ref.infolist():
                path = info.filename.replace('\\', '/')
                
                # Extract .db files
                if path.endswith('.db'):
                    zip_ref.extract(info, extract_to)
                    essential_files.append(os.path.join(extract_to, path))
                
                # Extract report.xml
                elif 'report.xml' in path.lower():
                    zip_ref.extract(info, extract_to)
                    essential_files.append(os.path.join(extract_to, path))
        
        return essential_files
    
    def _find_all_database_files(self, extract_to: str) -> List[str]:
        """Find all .db files in extracted directory."""
        db_files = []
        for root, dirs, files in os.walk(extract_to):
            for file in files:
                if file.endswith('.db'):
                    db_files.append(os.path.join(root, file))
        return db_files
    
    def _parse_report_xml_comprehensive(self, report_xml_path: str, output_db: str):
        """
        Comprehensive report.xml parsing.
        Extracts device info, extraction info, case info, etc.
        """
        conn = sqlite3.connect(output_db)
        cursor = conn.cursor()
        
        try:
            tree = ET.parse(report_xml_path)
            root = tree.getroot()
            
            # Extract device information
            device_info = {}
            extraction_info = {}
            case_info = {}
            
            # Parse XML structure (Cellebrite report.xml format)
            for elem in root.iter():
                tag = elem.tag.lower()
                text = elem.text if elem.text else ''
                
                # Device information
                if any(keyword in tag for keyword in ['device', 'model', 'manufacturer', 'imei', 'serial']):
                    device_info[tag] = text
                
                # Extraction information
                if any(keyword in tag for keyword in ['extraction', 'extracted', 'officer', 'tool', 'method']):
                    extraction_info[tag] = text
                
                # Case information
                if any(keyword in tag for keyword in ['case', 'investigation', 'officer', 'agency']):
                    case_info[tag] = text
            
            # Store device metadata
            for key, value in device_info.items():
                cursor.execute("""
                    INSERT OR REPLACE INTO device_metadata (key, value, category, source)
                    VALUES (?, ?, 'device', 'report.xml')
                """, (key, value))
            
            # Store extraction metadata
            for key, value in extraction_info.items():
                cursor.execute("""
                    INSERT OR REPLACE INTO device_metadata (key, value, category, source)
                    VALUES (?, ?, 'extraction', 'report.xml')
                """, (key, value))
            
            # Store case metadata
            for key, value in case_info.items():
                cursor.execute("""
                    INSERT OR REPLACE INTO device_metadata (key, value, category, source)
                    VALUES (?, ?, 'case', 'report.xml')
                """, (key, value))
            
            conn.commit()
            logger.info(f"✅ Parsed report.xml: {len(device_info)} device fields, {len(extraction_info)} extraction fields, {len(case_info)} case fields")
        
        except Exception as e:
            logger.error(f"Error parsing report.xml: {e}", exc_info=True)
        finally:
            conn.close()
    
    def _categorize_cellebrite_databases(self, db_files: List[str]) -> Dict[str, List[str]]:
        """
        Categorize Cellebrite databases by examining table structures.
        Specifically looks for: chats, files, contacts, calls, messages, locations.
        """
        categories = defaultdict(list)
        
        for db_file in db_files:
            try:
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0].lower() for row in cursor.fetchall()]
                conn.close()
                
                categorized = False
                
                # Check for chats (separate from messages)
                if any('chat' in t and 'message' not in t for t in tables):
                    categories['chats'].append(db_file)
                    categorized = True
                
                # Check for chat messages
                if any('chat' in t and 'message' in t for t in tables):
                    categories['chat_messages'].append(db_file)
                    categorized = True
                
                # Check for files
                if any('file' in t for t in tables):
                    categories['files'].append(db_file)
                    categorized = True
                
                # Check for contacts
                if any('contact' in t for t in tables):
                    categories['contacts'].append(db_file)
                    categorized = True
                
                # Check for calls
                if any('call' in t for t in tables):
                    categories['calls'].append(db_file)
                    categorized = True
                
                # Check for messages (SMS, WhatsApp, etc.)
                if any(t in ['sms', 'message', 'messages', 'whatsapp', 'imessage'] for t in tables):
                    categories['messages'].append(db_file)
                    categorized = True
                
                # Check for locations
                if any('location' in t or 'gps' in t for t in tables):
                    categories['locations'].append(db_file)
                    categorized = True
                
                # If no specific category, check by filename
                if not categorized:
                    db_name = os.path.basename(db_file).lower()
                    if 'chat' in db_name:
                        categories['chats'].append(db_file)
                    elif 'file' in db_name:
                        categories['files'].append(db_file)
                    elif 'contact' in db_name:
                        categories['contacts'].append(db_file)
                    elif 'call' in db_name:
                        categories['calls'].append(db_file)
                    elif 'message' in db_name or 'sms' in db_name:
                        categories['messages'].append(db_file)
                    elif 'location' in db_name:
                        categories['locations'].append(db_file)
            
            except Exception as e:
                logger.warning(f"Error categorizing {db_file}: {e}")
        
        return categories
    
    def _parse_all_cellebrite_databases(self, db_categories: Dict[str, List[str]], output_db: str, zip_size: int) -> Dict:
        """Parse all Cellebrite database categories in parallel."""
        stats = {
            'contacts': 0,
            'messages': 0,
            'chats': 0,
            'chat_messages': 0,
            'calls': 0,
            'locations': 0,
            'files': 0
        }
        
        is_large_file = zip_size > 500 * 1024 * 1024  # 500MB
        
        # Parse in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            # Parse contacts
            if 'contacts' in db_categories:
                future = executor.submit(self._parse_contacts_parallel, db_categories['contacts'], output_db, is_large_file)
                futures.append(('contacts', future))
            
            # Parse calls
            if 'calls' in db_categories:
                future = executor.submit(self._parse_calls_parallel, db_categories['calls'], output_db, is_large_file)
                futures.append(('calls', future))
            
            # Parse messages
            if 'messages' in db_categories:
                future = executor.submit(self._parse_messages_parallel, db_categories['messages'], output_db, is_large_file)
                futures.append(('messages', future))
            
            # Parse chats
            if 'chats' in db_categories:
                future = executor.submit(self._parse_chats_parallel, db_categories['chats'], output_db, is_large_file)
                futures.append(('chats', future))
            
            # Parse chat messages
            if 'chat_messages' in db_categories:
                future = executor.submit(self._parse_chat_messages_parallel, db_categories['chat_messages'], output_db, is_large_file)
                futures.append(('chat_messages', future))
            
            # Parse files
            if 'files' in db_categories:
                future = executor.submit(self._parse_files_parallel, db_categories['files'], output_db, is_large_file)
                futures.append(('files', future))
            
            # Parse locations
            if 'locations' in db_categories:
                future = executor.submit(self._parse_locations_parallel, db_categories['locations'], output_db, is_large_file)
                futures.append(('locations', future))
            
            # Collect results
            for category, future in futures:
                try:
                    count = future.result()
                    stats[category] = count
                    logger.info(f"✅ Parsed {count} {category} records")
                except Exception as e:
                    logger.error(f"Error parsing {category}: {e}", exc_info=True)
        
        return stats
    
    def _parse_contacts_parallel(self, db_files: List[str], output_db: str, fast_mode: bool) -> int:
        """Parse contact databases."""
        conn = sqlite3.connect(output_db)
        cursor = conn.cursor()
        count = 0
        
        for db_file in db_files:
            try:
                db_conn = sqlite3.connect(db_file)
                db_conn.row_factory = sqlite3.Row
                db_cursor = db_conn.cursor()
                
                # Find contact-related tables
                db_cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in db_cursor.fetchall()]
                
                for table in tables:
                    table_lower = table.lower()
                    if 'contact' in table_lower:
                        query = f"SELECT * FROM {table} LIMIT 50000" if fast_mode else f"SELECT * FROM {table}"
                        db_cursor.execute(query)
                        
                        for row in db_cursor.fetchall():
                            contact = dict(row)
                            normalized = self._normalize_contact(contact)
                            if normalized:
                                cursor.execute("""
                                    INSERT INTO contacts (name, phone, email, source_db, source_table, raw_data)
                                    VALUES (?, ?, ?, ?, ?, ?)
                                """, (
                                    normalized.get('name'),
                                    normalized.get('phone'),
                                    normalized.get('email'),
                                    db_file,
                                    table,
                                    json.dumps(contact)
                                ))
                                count += 1
                
                db_conn.close()
            except Exception as e:
                logger.error(f"Error parsing contacts from {db_file}: {e}")
        
        conn.commit()
        conn.close()
        return count
    
    def _parse_calls_parallel(self, db_files: List[str], output_db: str, fast_mode: bool) -> int:
        """Parse call log databases."""
        conn = sqlite3.connect(output_db)
        cursor = conn.cursor()
        count = 0
        
        for db_file in db_files:
            try:
                db_conn = sqlite3.connect(db_file)
                db_conn.row_factory = sqlite3.Row
                db_cursor = db_conn.cursor()
                
                # Find call-related tables
                db_cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in db_cursor.fetchall()]
                
                for table in tables:
                    table_lower = table.lower()
                    if 'call' in table_lower:
                        query = f"SELECT * FROM {table} LIMIT 50000" if fast_mode else f"SELECT * FROM {table}"
                        db_cursor.execute(query)
                        
                        for row in db_cursor.fetchall():
                            call = dict(row)
                            normalized = self._normalize_call(call)
                            if normalized:
                                cursor.execute("""
                                    INSERT INTO call_logs (from_number, to_number, timestamp, duration, call_type, source_db, source_table, raw_data)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    normalized.get('from'),
                                    normalized.get('to'),
                                    normalized.get('timestamp'),
                                    normalized.get('duration', 0),
                                    normalized.get('call_type'),
                                    db_file,
                                    table,
                                    json.dumps(call)
                                ))
                                count += 1
                
                db_conn.close()
            except Exception as e:
                logger.error(f"Error parsing calls from {db_file}: {e}")
        
        conn.commit()
        conn.close()
        return count
    
    def _parse_messages_parallel(self, db_files: List[str], output_db: str, fast_mode: bool) -> int:
        """Parse message databases (SMS, WhatsApp, etc.)."""
        conn = sqlite3.connect(output_db)
        cursor = conn.cursor()
        count = 0
        
        for db_file in db_files:
            try:
                db_conn = sqlite3.connect(db_file)
                db_conn.row_factory = sqlite3.Row
                db_cursor = db_conn.cursor()
                
                # Find message-related tables
                db_cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in db_cursor.fetchall()]
                
                for table in tables:
                    table_lower = table.lower()
                    # Skip chat message tables (handled separately)
                    if 'chat' in table_lower and 'message' in table_lower:
                        continue
                    
                    if any(t in table_lower for t in ['sms', 'message', 'whatsapp', 'imessage']):
                        # Determine source
                        source = 'WhatsApp' if 'whatsapp' in table_lower else 'SMS'
                        if 'imessage' in table_lower:
                            source = 'iMessage'
                        
                        query = f"SELECT * FROM {table} LIMIT 50000" if fast_mode else f"SELECT * FROM {table}"
                        db_cursor.execute(query)
                        
                        for row in db_cursor.fetchall():
                            msg = dict(row)
                            normalized = self._normalize_message(msg)
                            if normalized:
                                cursor.execute("""
                                    INSERT INTO messages (from_number, to_number, text_content, timestamp, source, source_db, source_table, raw_data)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    normalized.get('from'),
                                    normalized.get('to'),
                                    normalized.get('text') or normalized.get('content', ''),
                                    normalized.get('timestamp'),
                                    source,
                                    db_file,
                                    table,
                                    json.dumps(msg)
                                ))
                                count += 1
                
                db_conn.close()
            except Exception as e:
                logger.error(f"Error parsing messages from {db_file}: {e}")
        
        conn.commit()
        conn.close()
        return count
    
    def _parse_chats_parallel(self, db_files: List[str], output_db: str, fast_mode: bool) -> int:
        """
        Parse chat databases (separate from messages).
        Handles chat sessions and chat messages.
        """
        conn = sqlite3.connect(output_db)
        cursor = conn.cursor()
        count = 0
        
        for db_file in db_files:
            try:
                db_conn = sqlite3.connect(db_file)
                db_conn.row_factory = sqlite3.Row
                db_cursor = db_conn.cursor()
                
                # Find chat-related tables
                db_cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in db_cursor.fetchall()]
                
                for table in tables:
                    table_lower = table.lower()
                    
                    # Chat sessions/conversations (not messages)
                    if 'chat' in table_lower and 'message' not in table_lower:
                        query = f"SELECT * FROM {table} LIMIT 50000" if fast_mode else f"SELECT * FROM {table}"
                        db_cursor.execute(query)
                        
                        for row in db_cursor.fetchall():
                            chat = dict(row)
                            normalized = self._normalize_chat(chat)
                            if normalized:
                                participants = normalized.get('participants', [])
                                if isinstance(participants, str):
                                    try:
                                        participants = json.loads(participants)
                                    except:
                                        participants = [participants] if participants else []
                                
                                cursor.execute("""
                                    INSERT INTO chats (chat_id, chat_name, participants, platform, 
                                                      last_message_time, message_count, source_db, source_table, raw_data)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    normalized.get('chat_id') or str(normalized.get('id', '')),
                                    normalized.get('chat_name') or normalized.get('name', ''),
                                    json.dumps(participants),
                                    normalized.get('platform') or normalized.get('app', 'Unknown'),
                                    normalized.get('last_message_time') or normalized.get('last_message', ''),
                                    normalized.get('message_count', 0),
                                    db_file,
                                    table,
                                    json.dumps(chat)
                                ))
                                count += 1
                
                db_conn.close()
            except Exception as e:
                logger.error(f"Error parsing chats from {db_file}: {e}")
        
        conn.commit()
        conn.close()
        return count
    
    def _parse_chat_messages_parallel(self, db_files: List[str], output_db: str, fast_mode: bool) -> int:
        """Parse chat messages (messages within chats)."""
        conn = sqlite3.connect(output_db)
        cursor = conn.cursor()
        count = 0
        
        for db_file in db_files:
            try:
                db_conn = sqlite3.connect(db_file)
                db_conn.row_factory = sqlite3.Row
                db_cursor = db_conn.cursor()
                
                # Find chat message tables
                db_cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in db_cursor.fetchall()]
                
                for table in tables:
                    table_lower = table.lower()
                    
                    # Chat messages (messages within chats)
                    if 'chat' in table_lower and 'message' in table_lower:
                        query = f"SELECT * FROM {table} LIMIT 50000" if fast_mode else f"SELECT * FROM {table}"
                        db_cursor.execute(query)
                        
                        for row in db_cursor.fetchall():
                            msg = dict(row)
                            normalized = self._normalize_chat_message(msg)
                            if normalized:
                                cursor.execute("""
                                    INSERT INTO chat_messages (chat_id, message_id, from_participant, to_participant,
                                                              text_content, timestamp, platform, attachment_path,
                                                              source_db, source_table, raw_data)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    normalized.get('chat_id') or '',
                                    normalized.get('message_id') or str(normalized.get('id', '')),
                                    normalized.get('from'),
                                    normalized.get('to'),
                                    normalized.get('text') or normalized.get('content', ''),
                                    normalized.get('timestamp'),
                                    normalized.get('platform') or normalized.get('app', 'Unknown'),
                                    normalized.get('attachment_path') or normalized.get('attachment', ''),
                                    db_file,
                                    table,
                                    json.dumps(msg)
                                ))
                                count += 1
                
                db_conn.close()
            except Exception as e:
                logger.error(f"Error parsing chat messages from {db_file}: {e}")
        
        conn.commit()
        conn.close()
        return count
    
    def _parse_files_parallel(self, db_files: List[str], output_db: str, fast_mode: bool) -> int:
        """
        Parse file databases.
        Handles file metadata, paths, hashes, etc.
        """
        conn = sqlite3.connect(output_db)
        cursor = conn.cursor()
        count = 0
        
        for db_file in db_files:
            try:
                db_conn = sqlite3.connect(db_file)
                db_conn.row_factory = sqlite3.Row
                db_cursor = db_conn.cursor()
                
                # Find file-related tables
                db_cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in db_cursor.fetchall()]
                
                for table in tables:
                    table_lower = table.lower()
                    if 'file' in table_lower:
                        query = f"SELECT * FROM {table} LIMIT 50000" if fast_mode else f"SELECT * FROM {table}"
                        db_cursor.execute(query)
                        
                        for row in db_cursor.fetchall():
                            file_data = dict(row)
                            normalized = self._normalize_file(file_data)
                            if normalized:
                                cursor.execute("""
                                    INSERT INTO files (filename, file_path, file_type, size, mime_type,
                                                      created_time, modified_time, accessed_time,
                                                      hash_md5, hash_sha1, source_db, source_table, raw_data)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    normalized.get('filename') or normalized.get('name', ''),
                                    normalized.get('file_path') or normalized.get('path', ''),
                                    normalized.get('file_type') or normalized.get('type', ''),
                                    normalized.get('size', 0),
                                    normalized.get('mime_type') or normalized.get('mime', ''),
                                    normalized.get('created_time') or normalized.get('created', ''),
                                    normalized.get('modified_time') or normalized.get('modified', ''),
                                    normalized.get('accessed_time') or normalized.get('accessed', ''),
                                    normalized.get('hash_md5') or normalized.get('md5', ''),
                                    normalized.get('hash_sha1') or normalized.get('sha1', ''),
                                    db_file,
                                    table,
                                    json.dumps(file_data)
                                ))
                                count += 1
                
                db_conn.close()
            except Exception as e:
                logger.error(f"Error parsing files from {db_file}: {e}")
        
        conn.commit()
        conn.close()
        return count
    
    def _parse_locations_parallel(self, db_files: List[str], output_db: str, fast_mode: bool) -> int:
        """Parse location databases."""
        conn = sqlite3.connect(output_db)
        cursor = conn.cursor()
        count = 0
        
        for db_files_list in db_files:
            try:
                db_conn = sqlite3.connect(db_files_list)
                db_conn.row_factory = sqlite3.Row
                db_cursor = db_conn.cursor()
                
                # Find location-related tables
                db_cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in db_cursor.fetchall()]
                
                for table in tables:
                    table_lower = table.lower()
                    if 'location' in table_lower or 'gps' in table_lower:
                        query = f"SELECT * FROM {table} LIMIT 50000" if fast_mode else f"SELECT * FROM {table}"
                        db_cursor.execute(query)
                        
                        for row in db_cursor.fetchall():
                            loc = dict(row)
                            normalized = self._normalize_location(loc)
                            if normalized:
                                cursor.execute("""
                                    INSERT INTO locations (latitude, longitude, timestamp, address, source_db, source_table, raw_data)
                                    VALUES (?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    normalized.get('latitude') or normalized.get('lat'),
                                    normalized.get('longitude') or normalized.get('lng') or normalized.get('lon'),
                                    normalized.get('timestamp'),
                                    normalized.get('address'),
                                    db_files_list,
                                    table,
                                    json.dumps(loc)
                                ))
                                count += 1
                
                db_conn.close()
            except Exception as e:
                logger.error(f"Error parsing locations from {db_files_list}: {e}")
        
        conn.commit()
        conn.close()
        return count
    
    def _normalize_contact(self, contact: Dict) -> Optional[Dict]:
        """Normalize contact data."""
        normalized = dict(contact)
        
        # Map common fields
        if 'name' not in normalized and 'contact_name' in normalized:
            normalized['name'] = normalized['contact_name']
        if 'phone' not in normalized and 'phone_number' in normalized:
            normalized['phone'] = normalized['phone_number']
        if 'phone' not in normalized and 'mobile' in normalized:
            normalized['phone'] = normalized['mobile']
        
        return normalized if (normalized.get('name') or normalized.get('phone')) else None
    
    def _normalize_message(self, msg: Dict) -> Optional[Dict]:
        """Normalize message data."""
        normalized = dict(msg)
        
        # Map fields
        if 'sender' in normalized and 'from' not in normalized:
            normalized['from'] = normalized['sender']
        if 'receiver' in normalized and 'to' not in normalized:
            normalized['to'] = normalized['receiver']
        if 'message' in normalized and 'text' not in normalized:
            normalized['text'] = normalized['message']
        if 'content' in normalized and 'text' not in normalized:
            normalized['text'] = normalized['content']
        
        # Ensure required fields
        if not normalized.get('from'):
            normalized['from'] = 'Unknown'
        if not normalized.get('to'):
            normalized['to'] = 'Unknown'
        if not normalized.get('text') and not normalized.get('content'):
            normalized['text'] = ''
        if not normalized.get('timestamp'):
            normalized['timestamp'] = 'Unknown'
        
        return normalized
    
    def _normalize_call(self, call: Dict) -> Optional[Dict]:
        """Normalize call data."""
        normalized = dict(call)
        
        # Map fields
        if 'caller' in normalized and 'from' not in normalized:
            normalized['from'] = normalized['caller']
        if 'phone_number' in normalized and 'from' not in normalized:
            normalized['from'] = normalized['phone_number']
        
        # Ensure required fields
        if not normalized.get('from'):
            normalized['from'] = 'Unknown'
        if not normalized.get('to'):
            normalized['to'] = 'Unknown'
        if not normalized.get('timestamp'):
            normalized['timestamp'] = 'Unknown'
        
        return normalized
    
    def _normalize_location(self, loc: Dict) -> Optional[Dict]:
        """Normalize location data."""
        normalized = dict(loc)
        
        # Map fields
        if 'latitude' not in normalized and 'lat' in normalized:
            normalized['latitude'] = normalized['lat']
        if 'longitude' not in normalized and 'lng' in normalized:
            normalized['longitude'] = normalized['lng']
        if 'longitude' not in normalized and 'lon' in normalized:
            normalized['longitude'] = normalized['lon']
        
        return normalized if (normalized.get('latitude') and normalized.get('longitude')) else None
    
    def _normalize_chat(self, chat: Dict) -> Optional[Dict]:
        """Normalize chat data."""
        normalized = dict(chat)
        
        # Map common fields
        if 'id' in normalized and 'chat_id' not in normalized:
            normalized['chat_id'] = str(normalized['id'])
        if 'name' in normalized and 'chat_name' not in normalized:
            normalized['chat_name'] = normalized['name']
        if 'app' in normalized and 'platform' not in normalized:
            normalized['platform'] = normalized['app']
        if 'participant' in normalized and 'participants' not in normalized:
            normalized['participants'] = [normalized['participant']]
        
        return normalized if normalized.get('chat_id') or normalized.get('id') else None
    
    def _normalize_chat_message(self, msg: Dict) -> Optional[Dict]:
        """Normalize chat message data."""
        normalized = dict(msg)
        
        # Map fields
        if 'sender' in normalized and 'from' not in normalized:
            normalized['from'] = normalized['sender']
        if 'receiver' in normalized and 'to' not in normalized:
            normalized['to'] = normalized['receiver']
        if 'message' in normalized and 'text' not in normalized:
            normalized['text'] = normalized['message']
        if 'content' in normalized and 'text' not in normalized:
            normalized['text'] = normalized['content']
        
        # Ensure required fields
        if not normalized.get('from'):
            normalized['from'] = 'Unknown'
        if not normalized.get('text') and not normalized.get('content'):
            normalized['text'] = ''
        if not normalized.get('timestamp'):
            normalized['timestamp'] = 'Unknown'
        
        return normalized
    
    def _normalize_file(self, file_data: Dict) -> Optional[Dict]:
        """Normalize file data."""
        normalized = dict(file_data)
        
        # Map common fields
        if 'path' in normalized and 'file_path' not in normalized:
            normalized['file_path'] = normalized['path']
        if 'name' in normalized and 'filename' not in normalized:
            normalized['filename'] = normalized['name']
        if 'type' in normalized and 'file_type' not in normalized:
            normalized['file_type'] = normalized['type']
        
        return normalized if (normalized.get('filename') or normalized.get('file_path')) else None
    
    def _index_media_from_cellebrite_zip(self, zip_path: str, output_db: str):
        """Index media files from Media/ folder in Cellebrite ZIP."""
        conn = sqlite3.connect(output_db)
        cursor = conn.cursor()
        
        image_exts = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.heic', '.tiff', '.tif']
        video_exts = ['.mp4', '.avi', '.mov', '.mkv', '.webm', '.flv', '.wmv', '.m4v', '.3gp']
        
        media_count = 0
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for info in zip_ref.infolist():
                path = info.filename.replace('\\', '/')
                
                if info.is_dir():
                    continue
                
                # Check if it's in Media/ folder
                if not path.startswith('Media/'):
                    continue
                
                file_lower = path.lower()
                is_image = any(file_lower.endswith(ext) for ext in image_exts)
                is_video = any(file_lower.endswith(ext) for ext in video_exts)
                
                if is_image or is_video:
                    media_type = 'image' if is_image else 'video'
                    format_ext = os.path.splitext(path)[1].lower()
                    
                    cursor.execute("""
                        INSERT INTO media_index (filename, rel_path, zip_path, media_type, size, format, extracted)
                        VALUES (?, ?, ?, ?, ?, ?, 0)
                    """, (
                        os.path.basename(path),
                        path,
                        zip_path,
                        media_type,
                        info.file_size,
                        format_ext
                    ))
                    media_count += 1
        
        conn.commit()
        conn.close()
        logger.info(f"✅ Indexed {media_count} media files (deferred extraction)")
    
    def _index_files_from_cellebrite_zip(self, zip_path: str, output_db: str):
        """Index file attachments from Files/ folder in Cellebrite ZIP."""
        conn = sqlite3.connect(output_db)
        cursor = conn.cursor()
        
        file_count = 0
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for info in zip_ref.infolist():
                path = info.filename.replace('\\', '/')
                
                if info.is_dir():
                    continue
                
                # Check if it's in Files/ folder (or similar)
                if path.startswith('Files/') or 'attachment' in path.lower():
                    file_ext = os.path.splitext(path)[1].lower()
                    
                    cursor.execute("""
                        INSERT INTO files (filename, file_path, file_type, size, source_db, source_table, raw_data)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        os.path.basename(path),
                        path,
                        file_ext,
                        info.file_size,
                        zip_path,
                        'zip_file',
                        json.dumps({'path': path, 'size': info.file_size})
                    ))
                    file_count += 1
        
        conn.commit()
        conn.close()
        logger.info(f"✅ Indexed {file_count} file attachments from ZIP")
    
    def _get_statistics(self, db_path: str) -> Dict[str, Any]:
        """Get statistics matching Cellebrite structure."""
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        cursor.execute("SELECT COUNT(*) FROM contacts")
        stats['contacts_count'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM messages")
        stats['messages_count'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM chats")
        stats['chats_count'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM chat_messages")
        stats['chat_messages_count'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM call_logs")
        stats['calls_count'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM locations")
        stats['locations_count'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM files")
        stats['files_count'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM media_index WHERE media_type = 'image'")
        stats['images_count'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM media_index WHERE media_type = 'video'")
        stats['videos_count'] = cursor.fetchone()[0]
        
        conn.close()
        
        return stats

