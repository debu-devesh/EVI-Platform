#!/usr/bin/env python3
"""
XML Cellebrite Report Parser - Experimental
Parses standalone Cellebrite report XML files (like report.xml from Cellebrite exports)
and stores data in SQLite database for querying via CellebriteDataAccessLayer.

This is an experimental feature that works alongside FastCellebriteParser.
"""

import sqlite3
import xml.etree.ElementTree as ET
import os
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import re

logger = logging.getLogger(__name__)

# Extensions commonly found in Cellebrite taggedFiles paths (standalone XML reports).
_IMAGE_EXTS = frozenset({
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.heic', '.heif', '.tif', '.tiff',
    '.dng', '.raw', '.cr2', '.nef', '.orf', '.rw2', '.pef', '.srw', '.arw',
    '.ico', '.jfif', '.pjpeg', '.pjp', '.avif',
})
_VIDEO_EXTS = frozenset({
    '.mp4', '.mov', '.avi', '.mkv', '.webm', '.3gp', '.3g2', '.m4v', '.wmv',
    '.flv', '.mpg', '.mpeg', '.m2ts', '.mts', '.ts', '.asf', '.divx',
})

# UFDR Reader "Media" tree for this report type ≈ all tagged files except these binary
# / package / library extensions (empirically matches ~21.5k vs full ~23.8k tagged files).
_READER_EXCLUDED_EXTENSIONS = frozenset({
    '.so', '.db', '.apk', '.dex', '.odex', '.cnt', '.jar', '.asset', '.file',
})

# UFDR Reader "Devices & Networks" aggregate (decoded artifacts, not tagged file paths).
_DEVICE_NETWORKING_MODEL_TYPES = frozenset({
    'NetworkUsage',
    'DeviceConnectivity',
    'DeviceEvent',
    'RecognizedDevice',
})


class XMLCellebriteParser:
    """
    Parser for standalone Cellebrite report XML files.
    
    Uses streaming XML parsing (iterparse) for memory efficiency with large files.
    Extracts all forensic data types and stores in SQLite database using same schema
    as FastCellebriteParser for compatibility with CellebriteDataAccessLayer.
    """
    
    def __init__(self):
        """Initialize XML parser."""
        self.namespace = {'ns': 'http://pa.cellebrite.com/report/2.0'}
    
    def parse_xml_report(self, xml_path: str, output_db: str) -> Dict[str, Any]:
        """
        Parse Cellebrite report XML file and store in database.
        
        Args:
            xml_path: Path to XML report file
            output_db: Path to SQLite database for storage
            
        Returns:
            Summary statistics
        """
        xml_size = os.path.getsize(xml_path)
        logger.info(f"🔍 Parsing Cellebrite XML report: {xml_size / (1024**2):.2f} MB")
        
        # Create database with same schema as FastCellebriteParser
        self._create_database(output_db)
        
        # Parse XML using streaming for memory efficiency
        stats = self._parse_xml_streaming(xml_path, output_db)
        
        logger.info(f"✅ XML parsing complete: {stats}")
        return stats
    
    def _create_database(self, db_path: str):
        """Create SQLite database with same schema as FastCellebriteParser."""
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
                raw_data TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_phone ON contacts(phone)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_name ON contacts(name)")
        
        # Messages table
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
                raw_data TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_from ON messages(from_number)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_to ON messages(to_number)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON messages(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_source ON messages(source)")
        
        # Chats table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT,
                chat_name TEXT,
                participants TEXT,
                platform TEXT,
                last_message_time TEXT,
                message_count INTEGER,
                is_deleted INTEGER DEFAULT 0,
                source_db TEXT,
                source_table TEXT,
                raw_data TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_chat_name ON chats(chat_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_chat_id ON chats(chat_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_chat_id ON chats(chat_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_platform ON chats(platform)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_last_message_time ON chats(last_message_time)")
        
        # Chat messages table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT,
                chat_name TEXT,
                message_id TEXT,
                from_participant TEXT,
                to_participant TEXT,
                from_identifier TEXT,
                to_identifier TEXT,
                text_content TEXT,
                timestamp TEXT,
                platform TEXT,
                attachment_path TEXT,
                attachments TEXT,
                message_type TEXT,
                is_deleted INTEGER DEFAULT 0,
                source_db TEXT,
                source_table TEXT,
                raw_data TEXT
            )
        """)
        
        # Add new columns if they don't exist (for existing databases)
        for column in ['chat_name', 'from_identifier', 'to_identifier', 'attachments', 'message_type']:
            try:
                cursor.execute(f"ALTER TABLE chat_messages ADD COLUMN {column} TEXT")
            except sqlite3.OperationalError:
                pass  # Column already exists
        
        # Add is_deleted column (INTEGER type)
        try:
            cursor.execute("ALTER TABLE chat_messages ADD COLUMN is_deleted INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        # Add is_deleted column to chats table
        try:
            cursor.execute("ALTER TABLE chats ADD COLUMN is_deleted INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # Column already exists
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_chat_id_msg ON chat_messages(chat_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_from_msg ON chat_messages(from_participant)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp_msg ON chat_messages(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_platform_msg ON chat_messages(platform)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_message_type ON chat_messages(message_type)")
        
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
                raw_data TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_from_call ON call_logs(from_number)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp_call ON call_logs(timestamp)")
        
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
                raw_data TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp_loc ON locations(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_coords ON locations(latitude, longitude)")
        
        # Files table
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
                raw_data TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_filename ON files(filename)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_type ON files(file_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_size ON files(size)")
        
        # Device metadata table
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
        
        # Media index table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS media_index (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT,
                rel_path TEXT,
                zip_path TEXT,
                media_type TEXT,
                size INTEGER,
                format TEXT,
                extracted INTEGER DEFAULT 0
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_type_media ON media_index(media_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_extracted ON media_index(extracted)")
        
        conn.commit()
        conn.close()

    def _classify_tagged_file_media_row(self, file_path: str) -> Optional[str]:
        """
        None = excluded from UFDR Reader-style "Media" totals.
        Otherwise 'image', 'video', or 'other' (DBs, odd extensions, etc.).
        """
        if not file_path or not isinstance(file_path, str):
            return None
        pl_norm = file_path.replace('\\', '/')
        base = os.path.basename(pl_norm).lower()
        ext = os.path.splitext(base)[1]
        if ext in _READER_EXCLUDED_EXTENSIONS:
            return None

        if ext in _IMAGE_EXTS:
            return 'image'
        if ext in _VIDEO_EXTS:
            return 'video'
        low = pl_norm.lower()
        if ext in ('.exo',):
            return 'video'
        if ext in ('.thumb',):
            return 'image'
        if ext in ('.0', '.1', '.2'):
            if any(
                x in low
                for x in (
                    'image_manager_disk_cache',
                    'imgcache',
                    'pic_cache',
                    'thumb_cache',
                    'disk_cache',
                    'glide',
                    'fresco',
                    'coil',
                    'picasso',
                    'recently/',
                    'screenshot',
                    'file_manager',
                    'snapchat',
                )
            ):
                return 'image'
            if any(
                x in low
                for x in (
                    'video_cache',
                    'exoplayer',
                    'exo_cache',
                    'whatsapp video',
                    'screenrecord',
                )
            ):
                return 'video'
            if '/movies/' in low:
                return 'video'
            return 'other'
        if ext == '.ktx':
            return 'image'
        if '/whatsapp images/' in low or '/whatsapp image/' in low:
            return 'image'
        if '/whatsapp video/' in low or '/whatsapp videos/' in low:
            return 'video'
        if '/telegram/images/' in low or '/telegram/image/' in low:
            return 'image'
        if '/telegram/video/' in low or '/telegram/videos/' in low:
            return 'video'
        return 'other'

    def _classify_tagged_file_path_as_media(self, file_path: str) -> Optional[str]:
        """Image/video only (callers that skip generic 'other' rows)."""
        t = self._classify_tagged_file_media_row(file_path)
        if t == 'other':
            return None
        return t

    def _sync_media_index_from_files(self, conn, stats: Dict[str, Any]) -> None:
        """
        Fill media_index from `files` rows (taggedFiles). Standalone XML reports do not
        populate media_index during streaming parse; stats/API expect it for image/video counts.

        IMPORTANT: Use a dedicated cursor for INSERTs. Calling executemany() on the same
        cursor that is iterating a SELECT stops iteration after the first batch in SQLite
        (e.g. exactly 8000 rows when batch_size=8000).
        """
        meta = conn.cursor()
        meta.execute('SELECT COUNT(*) FROM files')
        stats['files'] = int(meta.fetchone()[0] or 0)

        ins = conn.cursor()
        ins.execute("DELETE FROM media_index WHERE zip_path = ?", ('xml_report',))

        sel = conn.cursor()
        sel.execute(
            'SELECT filename, file_path, COALESCE(size, 0) FROM files WHERE file_path IS NOT NULL AND file_path != ""'
        )

        batch: List[Tuple[Any, ...]] = []
        images = 0
        videos = 0
        other_media = 0
        batch_size = 8000
        insert_sql = """
                INSERT INTO media_index (filename, rel_path, zip_path, media_type, size, format, extracted)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """
        for filename, file_path, size in sel:
            mtype = self._classify_tagged_file_media_row(file_path)
            if not mtype:
                continue
            fn = filename or os.path.basename(file_path) or ''
            fmt = os.path.splitext(fn)[1].lstrip('.').lower() or None
            batch.append((fn, file_path, 'xml_report', mtype, int(size or 0), fmt, 0))
            if mtype == 'image':
                images += 1
            elif mtype == 'video':
                videos += 1
            else:
                other_media += 1
            if len(batch) >= batch_size:
                ins.executemany(insert_sql, batch)
                batch.clear()

        if batch:
            ins.executemany(insert_sql, batch)

        stats['images'] = images
        stats['videos'] = videos
        stats['other_media'] = other_media
        stats['total_media'] = images + videos + other_media
        logger.info(
            "✅ media_index synced from files: %s image, %s video, %s other (total reader-style %s) from %s tagged files",
            images,
            videos,
            other_media,
            stats['total_media'],
            stats['files'],
        )
    
    def _parse_xml_streaming(self, xml_path: str, output_db: str) -> Dict[str, Any]:
        """Parse XML file using streaming for memory efficiency."""
        conn = sqlite3.connect(output_db)
        cursor = conn.cursor()
        
        stats = {
            'contacts': 0,
            'calls': 0,
            'messages': 0,
            'chats': 0,
            'locations': 0,
            'files': 0,
            'device_metadata': 0,
            'device_networking': 0,
        }
        
        try:
            # Parse device metadata first (from metadata section)
            self._parse_device_metadata(xml_path, output_db)

            # Parse taggedFiles section
            self._parse_tagged_files(xml_path, output_db)

            # Parse decodedData/modelType incrementally using true streaming parse.
            # We process on end(modelType) so the entire subtree is available, then clear it.
            def _local_name(tag: str) -> str:
                return tag.split('}', 1)[1] if isinstance(tag, str) and tag.startswith('{') else tag

            context = ET.iterparse(xml_path, events=('start', 'end'))
            context = iter(context)
            _, root = next(context)  # Root start event
            logger.info("Processing decodedData/modelType sections with iterparse")

            model_type_count = 0
            processed_per_type = defaultdict(int)

            for event, elem in context:
                if event != 'end':
                    continue

                # Process each completed modelType subtree
                if _local_name(elem.tag) == 'modelType':
                    model_type = elem.get('type', '')
                    if model_type:
                        model_type_count += 1
                        logger.info(f"Parsing modelType: {model_type}")

                        # Process direct child <model> elements only
                        direct_models = [child for child in list(elem) if _local_name(child.tag) == 'model']
                        logger.info(f"  Found {len(direct_models)} models of type {model_type}")

                        # Reader "Devices & Networks" scope: count decoded models without full insert
                        if model_type in _DEVICE_NETWORKING_MODEL_TYPES:
                            n_dn = len(direct_models)
                            stats['device_networking'] = stats.get('device_networking', 0) + n_dn
                            processed_per_type[model_type] = n_dn
                            conn.commit()
                            logger.info(
                                f"  ✅ Device & networking +{n_dn} ({model_type}), total {stats['device_networking']}"
                            )
                            elem.clear()
                            root.clear()
                            continue

                        for idx, model_elem in enumerate(direct_models):
                            try:
                                model_data = self._extract_model_data(model_elem)

                                if model_type == 'Contact':
                                    self._process_contact_xml(model_elem, model_data, cursor, stats)
                                elif model_type == 'Call':
                                    self._process_call_xml(model_elem, model_data, cursor, stats)
                                elif model_type == 'InstantMessage':
                                    self._process_message_xml(model_elem, model_data, cursor, stats)
                                elif model_type == 'Chat':
                                    self._process_chat_xml(model_elem, model_data, cursor, stats)
                                elif model_type == 'Location':
                                    self._process_location_xml(model_elem, model_data, cursor, stats)

                                processed_per_type[model_type] += 1

                                # Commit periodically for large files (every 1000 items)
                                if (idx + 1) % 1000 == 0:
                                    conn.commit()
                                    logger.debug(f"Committed {idx + 1} {model_type} models")
                            except Exception as e:
                                logger.error(f"Error processing {model_type} model: {e}", exc_info=True)
                                continue

                        # Final commit for this model type subtree
                        conn.commit()
                        logger.info(
                            f"✅ Completed {model_type}: {processed_per_type.get(model_type, 0)} processed in stream"
                        )

                    # Critical for memory usage on very large files
                    elem.clear()
                    root.clear()
                # IMPORTANT: Do not clear every element here.
                # Clearing child <model> elements before parent <modelType> end
                # causes empty modelType sections (regression: 0 contacts/platforms).

            if model_type_count == 0:
                logger.warning("No modelType sections found in XML")

            # Persist Reader-style Device & networking total for /api/stats
            dn_total = int(stats.get('device_networking', 0) or 0)
            try:
                cursor.execute(
                    "DELETE FROM device_metadata WHERE key = ? AND category = ?",
                    ('device_networking_total', 'stats'),
                )
                cursor.execute(
                    """
                    INSERT INTO device_metadata (key, value, category, source)
                    VALUES (?, ?, 'stats', 'xml_report')
                    """,
                    ('device_networking_total', str(dn_total)),
                )
            except Exception as e:
                logger.warning(f"Could not persist device_networking_total: {e}")

            # taggedFiles → files table; mirror image/video into media_index for stats & gallery metadata
            self._sync_media_index_from_files(conn, stats)
            conn.commit()

        except Exception as e:
            logger.error(f"Error parsing XML: {e}", exc_info=True)
            conn.rollback()
            raise
        finally:
            conn.close()
        
        return stats
    
    def _extract_model_data(self, model_elem) -> Dict[str, Any]:
        """Extract all field data from a model element."""
        data = {}
        
        # Extract simple fields (handle both with and without namespace)
        fields = model_elem.findall('.//{http://pa.cellebrite.com/report/2.0}field')
        if not fields:
            fields = model_elem.findall('.//field')
        
        for field in fields:
            field_name = field.get('name', '')
            if not field_name:
                continue
                
            # Try with namespace first
            value_elem = field.find('.//{http://pa.cellebrite.com/report/2.0}value')
            if value_elem is None:
                value_elem = field.find('.//value')
            
            if value_elem is not None:
                if value_elem.text:
                    data[field_name] = value_elem.text.strip()
                # Also check formattedTimestamp attribute
                if value_elem.get('formattedTimestamp'):
                    data[f'{field_name}_formatted'] = value_elem.get('formattedTimestamp')
        
        return data
    
    def _extract_parties(self, model_elem) -> Dict[str, str]:
        """Extract parties (From/To) from model element."""
        parties = {'From': None, 'To': None}
        
        # Method 1: Find multiModelField with name="Parties" (handle both with and without namespace)
        parties_field = model_elem.find('.//{http://pa.cellebrite.com/report/2.0}multiModelField[@name="Parties"]')
        if parties_field is None:
            parties_field = model_elem.find('.//multiModelField[@name="Parties"]')
        
        if parties_field is not None:
            party_models = parties_field.findall('.//{http://pa.cellebrite.com/report/2.0}model[@type="Party"]')
            if not party_models:
                party_models = parties_field.findall('.//model[@type="Party"]')
            
            for party_model in party_models:
                # Extract Role
                role_elem = party_model.find('.//{http://pa.cellebrite.com/report/2.0}field[@name="Role"]/{http://pa.cellebrite.com/report/2.0}value')
                if role_elem is None:
                    role_elem = party_model.find('.//field[@name="Role"]/value')
                
                # Extract Name
                name_elem = party_model.find('.//{http://pa.cellebrite.com/report/2.0}field[@name="Name"]/{http://pa.cellebrite.com/report/2.0}value')
                if name_elem is None:
                    name_elem = party_model.find('.//field[@name="Name"]/value')
                
                # Extract Identifier
                identifier_elem = party_model.find('.//{http://pa.cellebrite.com/report/2.0}field[@name="Identifier"]/{http://pa.cellebrite.com/report/2.0}value')
                if identifier_elem is None:
                    identifier_elem = party_model.find('.//field[@name="Identifier"]/value')
                
                role = role_elem.text.strip() if role_elem is not None and role_elem.text else ''
                name = name_elem.text.strip() if name_elem is not None and name_elem.text else ''
                identifier = identifier_elem.text.strip() if identifier_elem is not None and identifier_elem.text else ''
                
                if role in ['From', 'To']:
                    parties[role] = name or identifier
        
        # Method 2: Check for modelField[@name="From"] (WhatsApp, Facebook Messenger)
        # This structure is used when parties are stored as separate modelField elements
        if parties['From'] is None:
            from_field = model_elem.find('.//{http://pa.cellebrite.com/report/2.0}modelField[@name="From"]')
            if from_field is None:
                from_field = model_elem.find('.//modelField[@name="From"]')
            
            if from_field is not None:
                party_model = from_field.find('.//{http://pa.cellebrite.com/report/2.0}model[@type="Party"]')
                if party_model is None:
                    party_model = from_field.find('.//model[@type="Party"]')
                
                if party_model is not None:
                    # Extract Name
                    name_elem = party_model.find('.//{http://pa.cellebrite.com/report/2.0}field[@name="Name"]/{http://pa.cellebrite.com/report/2.0}value')
                    if name_elem is None:
                        name_elem = party_model.find('.//field[@name="Name"]/value')
                    
                    # Extract Identifier
                    identifier_elem = party_model.find('.//{http://pa.cellebrite.com/report/2.0}field[@name="Identifier"]/{http://pa.cellebrite.com/report/2.0}value')
                    if identifier_elem is None:
                        identifier_elem = party_model.find('.//field[@name="Identifier"]/value')
                    
                    name = name_elem.text.strip() if name_elem is not None and name_elem.text else ''
                    identifier = identifier_elem.text.strip() if identifier_elem is not None and identifier_elem.text else ''
                    parties['From'] = name or identifier
        
        # Method 3: Check for modelField[@name="To"] or multiModelField[@name="To"]
        if parties['To'] is None:
            to_field = model_elem.find('.//{http://pa.cellebrite.com/report/2.0}modelField[@name="To"]')
            if to_field is None:
                to_field = model_elem.find('.//modelField[@name="To"]')
            
            if to_field is None:
                to_field = model_elem.find('.//{http://pa.cellebrite.com/report/2.0}multiModelField[@name="To"]')
                if to_field is None:
                    to_field = model_elem.find('.//multiModelField[@name="To"]')
            
            if to_field is not None:
                party_models = to_field.findall('.//{http://pa.cellebrite.com/report/2.0}model[@type="Party"]')
                if not party_models:
                    party_models = to_field.findall('.//model[@type="Party"]')
                
                if party_models:
                    # Use first To party
                    party_model = party_models[0]
                    name_elem = party_model.find('.//{http://pa.cellebrite.com/report/2.0}field[@name="Name"]/{http://pa.cellebrite.com/report/2.0}value')
                    if name_elem is None:
                        name_elem = party_model.find('.//field[@name="Name"]/value')
                    
                    identifier_elem = party_model.find('.//{http://pa.cellebrite.com/report/2.0}field[@name="Identifier"]/{http://pa.cellebrite.com/report/2.0}value')
                    if identifier_elem is None:
                        identifier_elem = party_model.find('.//field[@name="Identifier"]/value')
                    
                    name = name_elem.text.strip() if name_elem is not None and name_elem.text else ''
                    identifier = identifier_elem.text.strip() if identifier_elem is not None and identifier_elem.text else ''
                    parties['To'] = name or identifier
        
        return parties
    
    def _extract_parties_detailed(self, model_elem) -> Dict[str, Dict]:
        """Extract detailed party information including IDs, names, and roles."""
        parties = {'From': {}, 'To': {}}
        
        # Method 1: Find multiModelField with name="Parties"
        parties_field = model_elem.find('.//{http://pa.cellebrite.com/report/2.0}multiModelField[@name="Parties"]')
        if parties_field is None:
            parties_field = model_elem.find('.//multiModelField[@name="Parties"]')
        
        if parties_field is not None:
            party_models = parties_field.findall('.//{http://pa.cellebrite.com/report/2.0}model[@type="Party"]')
            if not party_models:
                party_models = parties_field.findall('.//model[@type="Party"]')
            
            for party_model in party_models:
                party_data = self._extract_model_data(party_model)
                role = party_data.get('Role', '')
                name = party_data.get('Name', '')
                identifier = party_data.get('Identifier', '')
                is_phone_owner = party_data.get('IsPhoneOwner', 'False') == 'True'
                
                if role in ['From', 'To']:
                    parties[role] = {
                        'name': name,
                        'identifier': identifier,
                        'is_phone_owner': is_phone_owner
                    }
        
        # Method 2: Check for modelField[@name="From"] (WhatsApp, Facebook Messenger)
        if not parties['From']:
            from_field = model_elem.find('.//{http://pa.cellebrite.com/report/2.0}modelField[@name="From"]')
            if from_field is None:
                from_field = model_elem.find('.//modelField[@name="From"]')
            
            if from_field is not None:
                party_model = from_field.find('.//{http://pa.cellebrite.com/report/2.0}model[@type="Party"]')
                if party_model is None:
                    party_model = from_field.find('.//model[@type="Party"]')
                
                if party_model is not None:
                    party_data = self._extract_model_data(party_model)
                    name = party_data.get('Name', '')
                    identifier = party_data.get('Identifier', '')
                    is_phone_owner = party_data.get('IsPhoneOwner', 'False') == 'True'
                    parties['From'] = {
                        'name': name,
                        'identifier': identifier,
                        'is_phone_owner': is_phone_owner
                    }
        
        # Method 3: Check for modelField[@name="To"] or multiModelField[@name="To"]
        if not parties['To']:
            to_field = model_elem.find('.//{http://pa.cellebrite.com/report/2.0}modelField[@name="To"]')
            if to_field is None:
                to_field = model_elem.find('.//modelField[@name="To"]')
            
            if to_field is None:
                to_field = model_elem.find('.//{http://pa.cellebrite.com/report/2.0}multiModelField[@name="To"]')
                if to_field is None:
                    to_field = model_elem.find('.//multiModelField[@name="To"]')
            
            if to_field is not None:
                party_models = to_field.findall('.//{http://pa.cellebrite.com/report/2.0}model[@type="Party"]')
                if not party_models:
                    party_models = to_field.findall('.//model[@type="Party"]')
                
                if party_models:
                    # Use first To party
                    party_model = party_models[0]
                    party_data = self._extract_model_data(party_model)
                    name = party_data.get('Name', '')
                    identifier = party_data.get('Identifier', '')
                    is_phone_owner = party_data.get('IsPhoneOwner', 'False') == 'True'
                    parties['To'] = {
                        'name': name,
                        'identifier': identifier,
                        'is_phone_owner': is_phone_owner
                    }
        
        return parties
    
    def _extract_attachments(self, model_elem) -> List[Dict]:
        """Extract attachment information from message element."""
        attachments = []
        
        # Check for Attachment field (single)
        attachment_field = model_elem.find('.//{http://pa.cellebrite.com/report/2.0}modelField[@name="Attachment"]')
        if attachment_field is None:
            attachment_field = model_elem.find('.//modelField[@name="Attachment"]')
        
        # Check for Attachments field (multiple)
        attachments_field = model_elem.find('.//{http://pa.cellebrite.com/report/2.0}multiModelField[@name="Attachments"]')
        if attachments_field is None:
            attachments_field = model_elem.find('.//multiModelField[@name="Attachments"]')
        
        # Extract from multiModelField (multiple attachments)
        if attachments_field is not None:
            attachment_models = attachments_field.findall('.//{http://pa.cellebrite.com/report/2.0}model[@type="Attachment"]')
            if not attachment_models:
                attachment_models = attachments_field.findall('.//model[@type="Attachment"]')
            
            for att_model in attachment_models:
                att_data = self._extract_model_data(att_model)
                attachment = {
                    'filename': att_data.get('Filename', ''),
                    'url': att_data.get('URL', ''),
                    'content_type': att_data.get('ContentType', ''),
                    'size': att_data.get('Size', '')
                }
                if attachment['filename'] or attachment['url']:
                    attachments.append(attachment)
        
        # Extract from single Attachment field
        elif attachment_field is not None:
            att_model = attachment_field.find('.//{http://pa.cellebrite.com/report/2.0}model[@type="Attachment"]')
            if att_model is None:
                att_model = attachment_field.find('.//model[@type="Attachment"]')
            
            if att_model is not None:
                att_data = self._extract_model_data(att_model)
                attachment = {
                    'filename': att_data.get('Filename', ''),
                    'url': att_data.get('URL', ''),
                    'content_type': att_data.get('ContentType', ''),
                    'size': att_data.get('Size', '')
                }
                if attachment['filename'] or attachment['url']:
                    attachments.append(attachment)
        
        return attachments
    
    def _classify_message_type(self, data: Dict, model_elem, attachments: List[Dict]) -> str:
        """
        Classify message type: text, media, location, or system.
        
        Args:
            data: Extracted message data dictionary
            model_elem: XML element for the message
            attachments: List of attachment dictionaries
            
        Returns:
            str: Message type ('text', 'media', 'location', 'system')
        """
        text = data.get('Body', '') or data.get('Text', '') or ''
        text_lower = text.lower() if text else ''
        
        # Check for location sharing
        is_location_sharing = data.get('IsLocationSharing', False)
        if isinstance(is_location_sharing, str):
            is_location_sharing = is_location_sharing.lower() in ['true', '1', 'yes']
        
        # Check if text contains location indicators (addresses, coordinates)
        location_indicators = [
            'grand hill', 'holly springs', 'nc ', 'usa', 'street', 'pl ', 'ave', 'rd', 'blvd',
            'latitude', 'longitude', 'gps', 'coordinates', 'location', 'address'
        ]
        has_location_text = any(indicator in text_lower for indicator in location_indicators) if text else False
        
        # Check for system messages (call notifications, etc.)
        system_patterns = [
            'outgoing call', 'incoming call', 'video call', 'call ended', 'call started',
            'missed call', 'you called', 'called you', 'system message'
        ]
        is_system = any(pattern in text_lower for pattern in system_patterns) if text else False
        
        # Check for media attachments
        has_attachments = attachments and len(attachments) > 0
        
        # Classify based on priority
        if is_location_sharing or has_location_text:
            return 'location'
        elif is_system:
            return 'system'
        elif has_attachments and not text:
            return 'media'
        elif has_attachments and text:
            return 'media'  # Media with caption
        elif text and text.strip():
            return 'text'
        else:
            return 'unknown'
    
    def _extract_contact_entries(self, model_elem) -> Dict[str, str]:
        """Extract contact entries (phone/email) from Contact model."""
        entries = {'phone': None, 'email': None}
        
        # Find multiModelField with name="Entries" (handle both with and without namespace)
        entries_field = model_elem.find('.//{http://pa.cellebrite.com/report/2.0}multiModelField[@name="Entries"]')
        if entries_field is None:
            entries_field = model_elem.find('.//multiModelField[@name="Entries"]')
        
        if entries_field is not None:
            entry_models = entries_field.findall('.//{http://pa.cellebrite.com/report/2.0}model')
            if not entry_models:
                entry_models = entries_field.findall('.//model')
            
            for entry_model in entry_models:
                entry_type = entry_model.get('type', '')
                
                # Extract Value
                value_elem = entry_model.find('.//{http://pa.cellebrite.com/report/2.0}field[@name="Value"]/{http://pa.cellebrite.com/report/2.0}value')
                if value_elem is None:
                    value_elem = entry_model.find('.//field[@name="Value"]/value')
                
                # Extract Domain
                domain_elem = entry_model.find('.//{http://pa.cellebrite.com/report/2.0}field[@name="Domain"]/{http://pa.cellebrite.com/report/2.0}value')
                if domain_elem is None:
                    domain_elem = entry_model.find('.//field[@name="Domain"]/value')
                
                if value_elem is not None and value_elem.text:
                    value = value_elem.text.strip()
                    domain = domain_elem.text.strip() if domain_elem is not None and domain_elem.text else ''
                    
                    if entry_type == 'EmailAddress' or 'email' in domain.lower():
                        entries['email'] = value
                    elif entry_type == 'PhoneNumber' or ('phone' in domain.lower() or 'user id' in domain.lower()):
                        if re.match(r'[\d\+\-\(\)\s]+', value):
                            entries['phone'] = value
                    elif entry_type == 'UserID':
                        # UserID might be phone number
                        if re.match(r'[\d\+\-\(\)\s]+', value) and len(value) >= 10:
                            entries['phone'] = value
        
        return entries
    
    def _parse_device_metadata(self, xml_path: str, output_db: str):
        """Parse device metadata from metadata section."""
        conn = sqlite3.connect(output_db)
        cursor = conn.cursor()
        
        try:
            context = ET.iterparse(xml_path, events=('start', 'end'))
            context = iter(context)
            event, root = next(context)
            
            in_metadata = False
            current_item = {}
            
            for event, elem in context:
                if event == 'start':
                    if elem.tag.endswith('metadata'):
                        section = elem.get('section', '')
                        if section == 'Device Info':
                            in_metadata = True
                    elif in_metadata and elem.tag.endswith('item'):
                        name = elem.get('name', '')
                        if name:
                            current_item = {'name': name, 'value': None}
                
                elif event == 'end':
                    if in_metadata and elem.tag.endswith('item') and current_item:
                        value_text = elem.text.strip() if elem.text else ''
                        if value_text:
                            cursor.execute("""
                                INSERT OR REPLACE INTO device_metadata (key, value, category, source)
                                VALUES (?, ?, 'device', 'xml_report')
                            """, (current_item['name'], value_text))
                        current_item = {}
                    elif elem.tag.endswith('metadata'):
                        in_metadata = False
                    
                    elem.clear()
                    root.clear()
            
            conn.commit()
            logger.info("✅ Parsed device metadata")
        
        except Exception as e:
            logger.error(f"Error parsing device metadata: {e}", exc_info=True)
        finally:
            conn.close()
    
    def _parse_tagged_files(self, xml_path: str, output_db: str):
        """Parse taggedFiles section for file metadata."""
        conn = sqlite3.connect(output_db)
        cursor = conn.cursor()
        
        try:
            context = ET.iterparse(xml_path, events=('start', 'end'))
            context = iter(context)
            event, root = next(context)
            
            in_tagged_files = False
            current_file = {}
            
            for event, elem in context:
                if event == 'start':
                    if elem.tag.endswith('taggedFiles'):
                        in_tagged_files = True
                    elif in_tagged_files and elem.tag.endswith('file'):
                        current_file = {
                            'id': elem.get('id', ''),
                            'path': elem.get('path', ''),
                            'size': elem.get('size', '0'),
                            'deleted': elem.get('deleted', 'Intact') == 'Deleted'
                        }
                
                elif event == 'end':
                    if in_tagged_files and elem.tag.endswith('file') and current_file:
                        # Extract filename from path
                        filename = os.path.basename(current_file.get('path', ''))
                        
                        # Extract MD5 hash if available
                        md5_hash = None
                        for item in elem.findall('.//item'):
                            if item.get('name') == 'MD5':
                                md5_elem = item.find('.//value')
                                if md5_elem is not None and md5_elem.text:
                                    md5_hash = md5_elem.text.strip()
                        
                        # Extract timestamps
                        modify_time = None
                        for timestamp in elem.findall('.//timestamp'):
                            if timestamp.get('name') == 'ModifyTime':
                                modify_time = timestamp.text.strip() if timestamp.text else None
                        
                        cursor.execute("""
                            INSERT INTO files (filename, file_path, size, modified_time, hash_md5, source_db, source_table)
                            VALUES (?, ?, ?, ?, ?, 'xml_report', 'taggedFiles')
                        """, (filename, current_file.get('path', ''), int(current_file.get('size', 0)), modify_time, md5_hash))
                        
                        current_file = {}
                    elif elem.tag.endswith('taggedFiles'):
                        in_tagged_files = False
                    
                    elem.clear()
                    root.clear()
            
            conn.commit()
            logger.info("✅ Parsed tagged files")
        
        except Exception as e:
            logger.error(f"Error parsing tagged files: {e}", exc_info=True)
        finally:
            conn.close()
    
    def _process_contact_xml(self, model_elem, data: Dict, cursor, stats: Dict):
        """Process a Contact model from XML element."""
        name = data.get('Name', '')
        source = data.get('Source', '')
        
        if not name:
            return
        
        # Extract phone/email from Entries
        entries = self._extract_contact_entries(model_elem)
        phone = entries.get('phone', '')
        email = entries.get('email', '')
        
        cursor.execute("""
            INSERT INTO contacts (name, phone, email, source_db, source_table, raw_data)
            VALUES (?, ?, ?, 'xml_report', 'Contact', ?)
        """, (name, phone, email, json.dumps(data)))
        
        stats['contacts'] += 1
    
    def _process_call_xml(self, model_elem, data: Dict, cursor, stats: Dict):
        """Process a Call model from XML element."""
        # Extract parties
        parties = self._extract_parties(model_elem)
        from_party = parties.get('From', '')
        to_party = parties.get('To', '')
        
        # Extract timestamp - try multiple field names
        timestamp = (data.get('TimeStamp', '') or 
                    data.get('TimeStamp_formatted', '') or
                    data.get('DateTime', '') or
                    data.get('DateTime_formatted', '') or
                    data.get('Date', '') or
                    data.get('Date_formatted', '') or
                    data.get('Time', '') or
                    data.get('Time_formatted', '') or
                    data.get('Timestamp', '') or
                    data.get('Timestamp_formatted', ''))
        
        # Extract duration
        duration_str = data.get('Duration', '')
        duration_seconds = self._parse_duration(duration_str) if duration_str else 0
        
        # Extract call type
        call_type = data.get('Type', '') or data.get('Direction', '')
        source = data.get('Source', '')
        
        cursor.execute("""
            INSERT INTO call_logs (from_number, to_number, timestamp, duration, call_type, source_db, source_table, raw_data)
            VALUES (?, ?, ?, ?, ?, 'xml_report', 'Call', ?)
        """, (from_party, to_party, timestamp, duration_seconds, call_type, json.dumps(data)))
        
        stats['calls'] += 1
    
    def _process_message_xml(self, model_elem, data: Dict, cursor, stats: Dict):
        """Process an InstantMessage model from XML element."""
        # Extract deleted state from model element attribute
        deleted_state = model_elem.get('deleted_state', 'Intact')
        is_deleted = 1 if deleted_state == 'Deleted' else 0
        
        # Chat messages use 'Body' field, standalone messages use 'Text' field
        # Try multiple field names to ensure we capture text content
        text = (data.get('Body', '') or 
                data.get('Text', '') or 
                data.get('Message', '') or 
                data.get('Content', '') or 
                data.get('MessageText', '') or 
                data.get('BodyText', ''))
        
        # Normalize empty strings to None for database storage
        if text and text.strip():
            text = text.strip()
        else:
            text = None  # Use None instead of empty string to distinguish from missing field
        
        # Try multiple timestamp field names (XML might use different names)
        timestamp = (data.get('TimeStamp', '') or 
                    data.get('TimeStamp_formatted', '') or
                    data.get('DateTime', '') or
                    data.get('DateTime_formatted', '') or
                    data.get('Date', '') or
                    data.get('Date_formatted', '') or
                    data.get('Time', '') or
                    data.get('Time_formatted', '') or
                    data.get('Timestamp', '') or
                    data.get('Timestamp_formatted', ''))
        
        # Log if timestamp is missing (for debugging)
        if not timestamp and stats.get('messages', 0) < 5:  # Only log first 5 missing timestamps
            logger.debug(f"⚠️ Message missing timestamp. Available fields: {list(data.keys())}")
        
        source = data.get('Source', '')
        
        # Extract parties
        parties = self._extract_parties(model_elem)
        from_party = parties.get('From', '')
        to_party = parties.get('To', '')
        
        # If no parties, use Direction
        if not from_party and not to_party:
            direction = data.get('Direction', '')
            if direction == 'Incoming':
                to_party = 'Device Owner'
            elif direction == 'Outgoing':
                from_party = 'Device Owner'
        
        # Try to find associated chat ID
        chat_id = data.get('ChatID', '') or data.get('Chat', '') or data.get('ThreadID', '') or data.get('ConversationID', '')
        
        # Get message ID if available
        message_id = data.get('ID', '') or data.get('MessageID', '')
        
        # Store in messages table (for general message queries)
        cursor.execute("""
            INSERT INTO messages (from_number, to_number, text_content, timestamp, source, source_db, source_table, raw_data)
            VALUES (?, ?, ?, ?, ?, 'xml_report', 'InstantMessage', ?)
        """, (from_party, to_party, text, timestamp, source, json.dumps(data)))
        
        stats['messages'] = stats.get('messages', 0) + 1
        
        # ALSO store in chat_messages table if we have a chat_id or can infer it from source/parties
        if chat_id or source:
            # If no explicit chat_id, try to find or create chat based on participants
            if not chat_id:
                # Try to find existing chat with these participants
                cursor.execute("""
                    SELECT chat_id FROM chats 
                    WHERE platform = ? AND (chat_name = ? OR chat_name = ? OR chat_name = ?)
                    LIMIT 1
                """, (source, from_party, to_party, f"{from_party} - {to_party}"))
                result = cursor.fetchone()
                if result:
                    chat_id = result[0]
                else:
                    # Create a chat_id from participants
                    chat_id = f"{from_party}_{to_party}" if from_party and to_party else (from_party or to_party or 'Unknown')
            
            # Insert into chat_messages table
            # Try to get chat name from existing chat or use chat_id
            chat_name = chat_id
            cursor.execute("SELECT chat_name FROM chats WHERE chat_id = ? LIMIT 1", (chat_id,))
            result = cursor.fetchone()
            if result:
                chat_name = result[0]
            
            # Extract attachments and detailed party info for standalone messages too
            attachments = self._extract_attachments(model_elem)
            attachments_json = json.dumps(attachments) if attachments else None
            parties_detailed = self._extract_parties_detailed(model_elem)
            from_identifier = parties_detailed.get('From', {}).get('identifier', '')
            to_identifier = parties_detailed.get('To', {}).get('identifier', '')
            
            # Classify message type
            message_type = self._classify_message_type(data, model_elem, attachments)
            
            cursor.execute("""
                INSERT INTO chat_messages (chat_id, chat_name, message_id, from_participant, to_participant, 
                                         from_identifier, to_identifier, text_content, timestamp, platform, 
                                         attachments, message_type, is_deleted, source_db, source_table, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'xml_report', 'InstantMessage', ?)
            """, (chat_id, chat_name, message_id, from_party, to_party, from_identifier, to_identifier, 
                  text, timestamp, source, attachments_json, message_type, is_deleted, json.dumps(data)))
            
            if 'chat_messages' not in stats:
                stats['chat_messages'] = 0
            stats['chat_messages'] += 1
    
    def _process_contact(self, model: Dict, cursor, stats: Dict):
        """Process a Contact model (legacy method - kept for compatibility)."""
        self._process_contact_xml(None, model.get('data', {}), cursor, stats)
    
    def _process_call(self, model: Dict, cursor, stats: Dict):
        """Process a Call model (legacy method - kept for compatibility)."""
        self._process_call_xml(None, model.get('data', {}), cursor, stats)
    
    def _process_message(self, model: Dict, cursor, stats: Dict):
        """Process an InstantMessage model (legacy method - kept for compatibility)."""
        self._process_message_xml(None, model.get('data', {}), cursor, stats)
    
    def _process_chat_xml(self, model_elem, data: Dict, cursor, stats: Dict):
        """Process a Chat model from XML element."""
        # Extract deleted state from model element attribute
        deleted_state = model_elem.get('deleted_state', 'Intact')
        is_deleted = 1 if deleted_state == 'Deleted' else 0
        
        chat_name = data.get('Name', '')
        platform = data.get('Source', '')
        original_chat_id = data.get('ID', '') or data.get('ChatID', '') or chat_name
        
        # Extract participants if available
        participants = []
        participants_field = model_elem.find('.//{http://pa.cellebrite.com/report/2.0}multiModelField[@name="Participants"]')
        if participants_field is None:
            participants_field = model_elem.find('.//multiModelField[@name="Participants"]')
        
        if participants_field is not None:
            participant_models = participants_field.findall('.//{http://pa.cellebrite.com/report/2.0}model')
            if not participant_models:
                participant_models = participants_field.findall('.//model')
            
            for part_model in participant_models:
                part_data = self._extract_model_data(part_model)
                part_name = part_data.get('Name', '') or part_data.get('Phone', '') or part_data.get('Value', '')
                if part_name:
                    participants.append(part_name)
        
        # Generate unique chat_id for this chat
        # Always create a unique chat_id to ensure all chats are stored
        # The platform-level DISTINCT message counting will prevent double-counting
        if not original_chat_id or original_chat_id.strip() == '':
            # Generate unique chat_id using stats counter
            chat_id = f"chat_{platform}_{stats['chats']}"
        else:
            # Use original chat_id, but check if it already exists
            cursor.execute("SELECT id FROM chats WHERE chat_id = ? AND platform = ?", (original_chat_id, platform))
            existing_id = cursor.fetchone()
            if existing_id:
                # Chat_id already exists, generate unique one using counter
                chat_id = f"{original_chat_id}_{platform}_{stats['chats']}"
            else:
                chat_id = original_chat_id
        
        # Always insert chat metadata (don't skip duplicates - let counting logic handle it)
        cursor.execute("""
            INSERT INTO chats (chat_id, chat_name, participants, platform, is_deleted, source_db, source_table, raw_data)
            VALUES (?, ?, ?, ?, ?, 'xml_report', 'Chat', ?)
        """, (chat_id, chat_name, json.dumps(participants) if participants else '[]', platform, is_deleted, json.dumps(data)))
        
        stats['chats'] += 1
        message_chat_id = chat_id
        message_chat_name = chat_name
        
        # Extract messages from this chat
        # IMPORTANT: Only count direct InstantMessage children of Chat models (matching XML structure)
        # Do NOT use Messages field as it may contain duplicates or references
        # Use direct children only to match the XML verification counts
        messages = []
        
        # Look for direct InstantMessage children (not all descendants)
        # First try direct children
        for child in model_elem:
            if child.tag.endswith('}model') or child.tag == 'model':
                model_type = child.get('type', '')
                if model_type == 'InstantMessage':
                    messages.append(child)
        
        # If no direct children found, fall back to finding nested InstantMessage models
        # But this should match the XML structure where messages are nested in Chat
        if not messages:
            messages = model_elem.findall('.//{http://pa.cellebrite.com/report/2.0}model[@type="InstantMessage"]')
            if not messages:
                messages = model_elem.findall('.//model[@type="InstantMessage"]')
        
        # DO NOT extend with Messages field - it may contain duplicates
        # The XML verification shows correct counts when only counting direct InstantMessage children
        
        # Process each message found in this chat
        for msg_elem in messages:
            try:
                msg_data = self._extract_model_data(msg_elem)
                # Chat messages use 'Body' field, standalone messages use 'Text' field
                # Try multiple field names to ensure we capture text content
                text = (msg_data.get('Body', '') or 
                        msg_data.get('Text', '') or 
                        msg_data.get('Message', '') or 
                        msg_data.get('Content', '') or 
                        msg_data.get('MessageText', '') or 
                        msg_data.get('BodyText', ''))
                
                # Normalize empty strings to None for database storage
                if text and text.strip():
                    text = text.strip()
                else:
                    text = None  # Use None instead of empty string to distinguish from missing field
                
                # Extract timestamp
                timestamp = (msg_data.get('TimeStamp', '') or 
                            msg_data.get('TimeStamp_formatted', '') or
                            msg_data.get('DateTime', '') or
                            msg_data.get('DateTime_formatted', '') or
                            msg_data.get('Date', '') or
                            msg_data.get('Date_formatted', '') or
                            msg_data.get('Time', '') or
                            msg_data.get('Time_formatted', '') or
                            msg_data.get('Timestamp', '') or
                            msg_data.get('Timestamp_formatted', ''))
                
                # Extract parties
                parties = self._extract_parties(msg_elem)
                from_party = parties.get('From', '')
                to_party = parties.get('To', '')
                
                # If no parties, use Direction
                if not from_party and not to_party:
                    direction = msg_data.get('Direction', '')
                    if direction == 'Incoming':
                        to_party = 'Device Owner'
                    elif direction == 'Outgoing':
                        from_party = 'Device Owner'

                # Fallback inference for one-to-one chats when UFDR omits explicit "To"
                # (common in some Facebook Messenger exports).
                if from_party and not to_party:
                    # If chat has exactly two participants, infer the counterparty.
                    if participants and len(participants) == 2:
                        from_norm = from_party.strip().lower()
                        inferred_to = None
                        for participant in participants:
                            if participant and participant.strip().lower() != from_norm:
                                inferred_to = participant
                                break
                        if inferred_to:
                            to_party = inferred_to

                    # If still missing, provide a deterministic fallback instead of NULL.
                    if not to_party:
                        to_party = 'Device Owner' if from_party != 'Device Owner' else (chat_name or 'Unknown')
                
                # Get message ID if available
                message_id = msg_data.get('ID', '') or msg_data.get('MessageID', '')
                
                # Extract attachments
                attachments = self._extract_attachments(msg_elem)
                attachments_json = json.dumps(attachments) if attachments else None
                
                # Extract detailed party information
                parties_detailed = self._extract_parties_detailed(msg_elem)
                from_identifier = parties_detailed.get('From', {}).get('identifier', '')
                to_identifier = parties_detailed.get('To', {}).get('identifier', '')
                
                # Classify message type
                message_type = self._classify_message_type(msg_data, msg_elem, attachments)
                
                # Extract deleted state from message element
                msg_deleted_state = msg_elem.get('deleted_state', 'Intact')
                msg_is_deleted = 1 if msg_deleted_state == 'Deleted' else 0
                
                # Insert into chat_messages table with enhanced fields
                cursor.execute("""
                    INSERT INTO chat_messages (chat_id, chat_name, message_id, from_participant, to_participant, 
                                             from_identifier, to_identifier, text_content, timestamp, platform, 
                                             attachments, message_type, is_deleted, source_db, source_table, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'xml_report', 'Chat', ?)
                """, (message_chat_id, message_chat_name, message_id, from_party, to_party, from_identifier, to_identifier, 
                      text, timestamp, platform, attachments_json, message_type, msg_is_deleted, json.dumps(msg_data)))
                
                if 'chat_messages' not in stats:
                    stats['chat_messages'] = 0
                stats['chat_messages'] += 1
            except Exception as e:
                logger.error(f"Error processing message in chat {chat_name}: {e}", exc_info=True)
                continue
    
    def _process_location_xml(self, model_elem, data: Dict, cursor, stats: Dict):
        """Process a Location model from XML element."""
        latitude = None
        longitude = None
        
        # Try multiple timestamp field names
        timestamp = (data.get('TimeStamp', '') or 
                    data.get('TimeStamp_formatted', '') or
                    data.get('DateTime', '') or
                    data.get('DateTime_formatted', '') or
                    data.get('Date', '') or
                    data.get('Date_formatted', '') or
                    data.get('Time', '') or
                    data.get('Time_formatted', '') or
                    data.get('Timestamp', '') or
                    data.get('Timestamp_formatted', ''))
        address = data.get('Address', '')
        
        # Extract coordinates
        lat_str = data.get('Latitude', '')
        lon_str = data.get('Longitude', '')
        
        try:
            if lat_str:
                latitude = float(lat_str)
            if lon_str:
                longitude = float(lon_str)
        except:
            pass
        
        cursor.execute("""
            INSERT INTO locations (latitude, longitude, timestamp, address, source_db, source_table, raw_data)
            VALUES (?, ?, ?, ?, 'xml_report', 'Location', ?)
        """, (latitude, longitude, timestamp, address, json.dumps(data)))
        
        stats['locations'] += 1
    
    def _process_chat(self, model: Dict, cursor, stats: Dict):
        """Process a Chat model (legacy method - kept for compatibility)."""
        self._process_chat_xml(None, model.get('data', {}), cursor, stats)
    
    def _process_location(self, model: Dict, cursor, stats: Dict):
        """Process a Location model (legacy method - kept for compatibility)."""
        self._process_location_xml(None, model.get('data', {}), cursor, stats)
    
    def _parse_duration(self, duration_str: str) -> int:
        """Parse duration string (HH:MM:SS) to seconds."""
        try:
            parts = duration_str.split(':')
            if len(parts) == 3:
                hours, minutes, seconds = map(int, parts)
                return hours * 3600 + minutes * 60 + seconds
        except:
            pass
        return 0

