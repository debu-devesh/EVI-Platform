#!/usr/bin/env python3
"""
Cellebrite Data Access Layer
- Fast querying from Cellebrite database
- Query-aware extraction
- Media on-demand loading
- LLM-ready formatting
- Handles: chats, files, messages, contacts, calls, locations
"""

import sqlite3
import zipfile
import os
import json
import logging
import re
from typing import Dict, List, Any, Optional, Tuple

from datetime import datetime

from core.evidence_scope import EvidenceScope, compute_evidence_scope
from core.query_intent_parser import PLATFORM_ALIASES, extract_platforms_ordered, parse_query_intent

logger = logging.getLogger(__name__)


def _normalize_person_key(name: str) -> str:
    """Lowercase key for deduping; strip image extensions and extra spaces."""
    if not name or not isinstance(name, str):
        return ""
    n = name.strip()
    if not n:
        return ""
    for ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"):
        if n.lower().endswith(ext):
            n = n[: -len(ext)]
            break
    return " ".join(n.split()).lower()


def _clean_display_name(name: str) -> str:
    """Remove common filename artifacts for display."""
    if not name or not isinstance(name, str):
        return ""
    n = name.strip()
    for ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"):
        if n.lower().endswith(ext):
            n = n[: -len(ext)].strip()
            break
    return " ".join(n.split()) or name.strip()


def _dedupe_person_names(names: List[str]) -> List[str]:
    """Merge duplicate identities like 'Josh Hickman' vs 'Josh Hickman.jpg' (one section per person)."""
    by_key: Dict[str, str] = {}
    for name in names:
        key = _normalize_person_key(name)
        if not key:
            continue
        candidate = _clean_display_name(name)
        if key not in by_key:
            by_key[key] = candidate
        else:
            prev = by_key[key]
            if len(candidate) < len(prev) or (".jpg" in prev.lower() and ".jpg" not in candidate.lower()):
                by_key[key] = candidate
    return list(by_key.values())


def _extract_years_from_query(query: str) -> List[int]:
    """Years (e.g. 2020) in the query — used to filter generic timeline slices."""
    if not query:
        return []
    found = set()
    for m in re.finditer(r"\b((?:19|20)\d{2})\b", query):
        y = int(m.group(1))
        if 1970 <= y <= 2100:
            found.add(y)
    return sorted(found)


def _data_availability_breakdown_lines(cursor: sqlite3.Cursor) -> List[str]:
    """
    Platform/source histograms for 'what data is available' style queries.
    Uses chats.platform / chat_messages.platform and json_extract(raw_data, '$.Source') where present.
    """
    lines: List[str] = []

    try:
        cursor.execute(
            """
            SELECT COALESCE(NULLIF(TRIM(platform), ''), '(unspecified)'), COUNT(*)
            FROM chats
            GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 15
            """
        )
        rows = cursor.fetchall()
        if rows:
            lines.append(
                "Chat threads by app/source: "
                + "; ".join(f"{label} ({count})" for label, count in rows)
            )
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute(
            """
            SELECT COALESCE(NULLIF(TRIM(platform), ''), '(unspecified)'), COUNT(*)
            FROM chat_messages
            GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 15
            """
        )
        rows = cursor.fetchall()
        if rows:
            lines.append(
                "Chat messages by app/source: "
                + "; ".join(f"{label} ({count})" for label, count in rows)
            )
    except sqlite3.OperationalError:
        pass

    for table, title in (
        ("call_logs", "Call logs by app/source (PA Call.Source)"),
        ("contacts", "Contacts by app/source (PA Contact.Source)"),
        ("locations", "Locations by app/source (PA Location.Source)"),
    ):
        try:
            cursor.execute(
                f"""
                SELECT COALESCE(NULLIF(TRIM(json_extract(raw_data, '$.Source')), ''), '(unspecified)'), COUNT(*)
                FROM {table}
                WHERE raw_data IS NOT NULL AND TRIM(raw_data) != ''
                GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 12
                """
            )
            rows = cursor.fetchall()
            if rows:
                lines.append(
                    title + ": " + "; ".join(f"{label} ({count})" for label, count in rows)
                )
        except sqlite3.OperationalError:
            pass

    return lines


def _timeline_timestamp_in_years(ts: str, years: List[int]) -> bool:
    if not ts or not years:
        return True
    s = str(ts)
    return any(s.startswith(str(y)) for y in years)


def _platform_rows_in_chat_messages_table(platforms: List[str]) -> bool:
    """
    True when the user's platform pin refers to app-layer chat_messages, not the SMS/MMS `messages` table.
    Compound queries like 'whatsappmessages' still extract platform=whatsapp but miss 'whatsapp message' phrases.
    """
    if not platforms:
        return False
    p0 = str(platforms[0]).strip().lower()
    if "native" in p0:
        return False
    if p0 in ("sms", "mms", "text message", "text messages"):
        return False
    return True


# ISO calendar days (YYYY-MM-DD) in user text; used for deterministic same-day slices.
_ISO_DAY_RE = re.compile(r"\b(20\d{2})-(\d{2})-(\d{2})\b")


def _extract_iso_days_from_query(query: str) -> List[str]:
    if not query:
        return []
    out: List[str] = []
    seen = set()
    for m in _ISO_DAY_RE.finditer(query):
        try:
            mo, d = int(m.group(2)), int(m.group(3))
        except (TypeError, ValueError):
            continue
        if not (1 <= mo <= 12 and 1 <= d <= 31):
            continue
        day = f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
        if day not in seen:
            seen.add(day)
            out.append(day)
    return out


class CellebriteDataAccessLayer:
    """
    Intermediate layer between parsed Cellebrite data and LLM.
    Provides fast, query-aware data access.
    """
    
    def __init__(self, db_path: str, zip_path: Optional[str] = None):
        """
        Initialize data access layer.
        
        Args:
            db_path: Path to SQLite database
            zip_path: Path to original ZIP (for media access)
        """
        self.db_path = db_path
        self.zip_path = zip_path
        # Don't cache connection - SQLite connections can't be shared across threads
        # Each request will create a new connection
    
    def get_connection(self):
        """Get database connection (creates new connection each time for thread safety)."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _execute_query(self, query_func):
        """Helper to execute a query function and ensure connection is closed."""
        conn = self.get_connection()
        try:
            return query_func(conn)
        finally:
            conn.close()
    
    def query_contacts(self, query: str, limit: int = 100) -> List[Dict]:
        """Query contacts based on search terms."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            # Check if query is asking for all contacts
            query_lower = query.lower()
            if any(word in query_lower for word in ['list', 'all', 'every', 'entire', 'complete']) and 'contact' in query_lower:
                # Return all contacts
                cursor.execute("SELECT * FROM contacts ORDER BY name LIMIT ?", (limit,))
                return [dict(row) for row in cursor.fetchall()]
            
            # Check for phone number in query
            phone_pattern = r'\+?\d{10,15}'
            phone_numbers = re.findall(phone_pattern, query)
            
            # Build search query
            search_terms = query.lower().split()
            conditions = []
            params = []
            
            # Filter out common query words
            filtered_terms = [term for term in search_terms if term not in ['list', 'all', 'every', 'entire', 'complete', 'contact', 'contacts', 'show', 'get', 'find', 'info', 'about', 'specific', 'this']]
            
            # Add phone number search if found
            if phone_numbers:
                for phone in phone_numbers:
                    conditions.append("(phone LIKE ? OR name LIKE ?)")
                    params.extend([f"%{phone}%", f"%{phone}%"])
            
            if filtered_terms:
                for term in filtered_terms:
                    # Skip if it's a phone number (already handled)
                    if not re.match(r'^\+?\d+$', term):
                        conditions.append("(name LIKE ? OR phone LIKE ? OR email LIKE ?)")
                        params.extend([f"%{term}%", f"%{term}%", f"%{term}%"])
            
            if conditions:
                where_clause = " OR ".join(conditions)
            else:
                # No search terms, return all
                where_clause = "1=1"
                params = []
            
            cursor.execute(f"""
                SELECT * FROM contacts 
                WHERE {where_clause}
                ORDER BY name
                LIMIT ?
            """, params + [limit])
            
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
    
    def query_messages(self, query: str, limit: int = 100) -> List[Dict]:
        """Query messages based on search terms."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            # Detect query intent
            query_lower = query.lower()
            
            # Message keywords that trigger extraction
            message_keywords = ['message', 'messages', 'text', 'texts', 'sms', 'mms', 
                              'whatsapp', 'imessage', 'telegram', 'messenger', 'communication']
            
            # Check if query contains message keywords
            has_message_keywords = any(kw in query_lower for kw in message_keywords)
            
            # Extract search terms (filter out common query words)
            search_terms = [t for t in query_lower.split() 
                           if t not in ['list', 'all', 'show', 'get', 'find', 'any', 'are', 'there', 
                                       'message', 'messages', 'text', 'texts', 'sms', 'mms',
                                       'whatsapp', 'imessage', 'telegram', 'messenger', 'communication',
                                       'from', 'to', 'who', 'contact', 'person', 'said', 'content', 'what']]
            
            # If query contains message keywords but no specific search terms, return all messages
            if has_message_keywords and not search_terms:
                cursor.execute("""
                    SELECT * FROM messages 
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))
                return [dict(row) for row in cursor.fetchall()]
            
            # Build search conditions
            is_person_query = any(word in query_lower for word in ['who', 'from', 'to', 'contact', 'person'])
            is_content_query = any(word in query_lower for word in ['said', 'text', 'message', 'content'])
            
            conditions = []
            params = []
            
            if is_person_query and search_terms:
                # Search by sender/receiver
                for term in search_terms:
                    conditions.append("(from_number LIKE ? OR to_number LIKE ?)")
                    params.extend([f"%{term}%", f"%{term}%"])
            
            if is_content_query and search_terms:
                # Search by message content
                for term in search_terms:
                    conditions.append("text_content LIKE ?")
                    params.append(f"%{term}%")
            
            # If no conditions but has search terms, search all fields
            if not conditions and search_terms:
                for term in search_terms:
                    conditions.append("(from_number LIKE ? OR to_number LIKE ? OR text_content LIKE ? OR source LIKE ?)")
                    params.extend([f"%{term}%", f"%{term}%", f"%{term}%", f"%{term}%"])
            
            where_clause = " OR ".join(conditions) if conditions else "1=1"
            
            cursor.execute(f"""
                SELECT * FROM messages 
                WHERE {where_clause}
                ORDER BY timestamp DESC
                LIMIT ?
            """, params + [limit] if params else [limit])
            
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
    
    def query_chats(self, query: str, limit: int = 100) -> List[Dict]:
        """Query chats based on search terms."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            query_lower = query.lower()
            conditions = []
            params = []
            
            # Check if user wants ALL chats (list all, show all, etc.)
            wants_all_chats = any(phrase in query_lower for phrase in ['list all', 'show all', 'all chats', 'all chat', 
                                                                       'every chat', 'get all', 'show me all'])
            
            # Search by chat name, platform, or participants
            # Filter out common query words
            filtered_terms = [term for term in query_lower.split() 
                            if term not in ['chat', 'chats', 'conversation', 'group', 'thread', 'list', 'all', 'show', 'get', 'find', 'with', 'from']]
            
            if filtered_terms:
                # First, try to match the full phrase (e.g., "josh hickman")
                full_phrase = ' '.join(filtered_terms)
                # Search in participants JSON (case-insensitive)
                conditions.append("(chat_name LIKE ? OR platform LIKE ? OR participants LIKE ? OR LOWER(participants) LIKE ?)")
                params.extend([f"%{full_phrase}%", f"%{full_phrase}%", f"%{full_phrase}%", f"%{full_phrase.lower()}%"])
                
                # Also try without spaces (e.g., "joshhickman")
                no_space_phrase = ''.join(filtered_terms)
                if no_space_phrase != full_phrase:
                    conditions.append("(chat_name LIKE ? OR platform LIKE ? OR participants LIKE ? OR LOWER(participants) LIKE ?)")
                    params.extend([f"%{no_space_phrase}%", f"%{no_space_phrase}%", f"%{no_space_phrase}%", f"%{no_space_phrase.lower()}%"])
                
                # Then search individual terms
                for term in filtered_terms:
                    if len(term) > 2:  # Only search meaningful terms
                        conditions.append("(chat_name LIKE ? OR platform LIKE ? OR participants LIKE ? OR LOWER(participants) LIKE ?)")
                        params.extend([f"%{term}%", f"%{term}%", f"%{term}%", f"%{term.lower()}%"])
            
            # If wants all chats OR no specific search terms, return all chats
            if wants_all_chats or not conditions:
                where_clause = "1=1"
            elif conditions:
                where_clause = " OR ".join(conditions)
            else:
                where_clause = "1=1"
            
            cursor.execute(f"""
                SELECT * FROM chats 
                WHERE {where_clause}
                ORDER BY last_message_time DESC
                LIMIT ?
            """, params + [limit])
            
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
    
    def _get_chat_metadata(self, chat_id: str, chat_name: str, platform: str) -> Dict:
        """Get comprehensive metadata for a chat.
        
        Returns:
            Dict with keys: participant_count, attachment_count, has_location_data, 
            start_time, last_activity, total_messages
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            metadata = {
                'participant_count': 0,
                'attachment_count': 0,
                'has_location_data': False,
                'start_time': None,
                'last_activity': None,
                'total_messages': 0
            }
            
            # Get all messages for this chat to calculate metadata
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_messages,
                    MIN(timestamp) as start_time,
                    MAX(timestamp) as last_activity,
                    SUM(CASE WHEN message_type = 'location' THEN 1 ELSE 0 END) as location_count,
                    attachments
                FROM chat_messages
                WHERE (
                    (chat_id = ? AND chat_id IS NOT NULL AND chat_id != '')
                    OR 
                    (chat_name = ? AND chat_name IS NOT NULL AND chat_name != '')
                ) AND platform = ?
            """, (chat_id, chat_name, platform))
            
            result = cursor.fetchone()
            if result:
                metadata['total_messages'] = result['total_messages'] or 0
                metadata['start_time'] = result['start_time']
                metadata['last_activity'] = result['last_activity']
                metadata['has_location_data'] = (result['location_count'] or 0) > 0
                
                # Count attachments across all messages
                cursor.execute("""
                    SELECT attachments
                    FROM chat_messages
                    WHERE (
                        (chat_id = ? AND chat_id IS NOT NULL AND chat_id != '')
                        OR 
                        (chat_name = ? AND chat_name IS NOT NULL AND chat_name != '')
                    ) AND platform = ?
                    AND attachments IS NOT NULL
                    AND attachments != ''
                    AND attachments != 'null'
                    AND attachments != '[]'
                """, (chat_id, chat_name, platform))
                
                attachment_count = 0
                for row in cursor.fetchall():
                    att_str = row['attachments']
                    if att_str:
                        try:
                            att_data = json.loads(att_str) if isinstance(att_str, str) else att_str
                            if isinstance(att_data, list):
                                attachment_count += len(att_data)
                            elif isinstance(att_data, dict):
                                attachment_count += 1
                        except:
                            pass
                
                metadata['attachment_count'] = attachment_count
            
            return metadata
        finally:
            conn.close()
    
    def get_chat_data_for_display(self, platform: str = None, chat_id: str = None, limit: int = 100) -> Dict:
        """
        Returns structured chat data ready for frontend display.
        Includes all metadata and messages in chronological order.
        
        Args:
            platform: Optional platform name to filter by
            chat_id: Optional specific chat ID to retrieve
            limit: Maximum number of messages per chat
            
        Returns:
            {
                'platform': 'Native Messages',
                'chats': [
                    {
                        'chat_id': '...',
                        'chat_name': '...',
                        'participants': [...],
                        'participant_count': 2,
                        'start_time': '...',
                        'last_activity': '...',
                        'attachment_count': 4,
                        'has_location_data': True,
                        'location_count': 2,
                        'total_messages': 17,
                        'messages': [
                            {
                                'message_id': '...',
                                'from_participant': '...',
                                'to_participant': '...',
                                'text_content': '...',
                                'timestamp': '...',
                                'message_type': 'text|media|location|system',
                                'is_deleted': False,
                                'attachments': [...]
                            }
                        ]
                    }
                ]
            }
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            result = {
                'platform': platform,
                'chats': []
            }
            
            # Get chats
            if chat_id:
                cursor.execute("""
                    SELECT * FROM chats
                    WHERE chat_id = ? AND platform = ?
                    ORDER BY last_message_time DESC
                """, (chat_id, platform or ''))
            elif platform:
                # Handle platform matching (case-insensitive, partial)
                platform_lower = platform.lower()
                if 'native' in platform_lower:
                    cursor.execute("""
                        SELECT * FROM chats
                        WHERE LOWER(platform) LIKE ?
                        ORDER BY last_message_time DESC
                    """, ('%native%',))
                else:
                    # Case-insensitive platform matching with fallback
                    cursor.execute("""
                        SELECT * FROM chats
                        WHERE platform = ? OR LOWER(platform) = ? OR LOWER(platform) LIKE ?
                        ORDER BY last_message_time DESC
                    """, (platform, platform_lower, f'%{platform_lower}%'))
            else:
                cursor.execute("""
                    SELECT * FROM chats
                    ORDER BY last_message_time DESC
                    LIMIT 50
                """)
            
            chats = [dict(row) for row in cursor.fetchall()]
            
            for chat in chats:
                raw_chat_id = (chat.get('chat_id') or '').strip()
                chat_name = (chat.get('chat_name') or 'Unknown').strip()
                # Stable key for metadata lookups (prefer real chat_id; else name)
                chat_id_val = raw_chat_id or chat_name
                platform_val = chat.get('platform', platform or 'Unknown')
                
                # Get chat metadata
                chat_metadata = self._get_chat_metadata(chat_id_val, chat_name, platform_val)
                
                # Get participants
                participants = []
                try:
                    participants = json.loads(chat.get('participants', '[]'))
                except:
                    participants = [chat.get('participants', '')] if chat.get('participants') else []
                
                # Get messages for this chat — use EXACT chat_id OR EXACT chat_name only.
                # Broad OR + LIKE previously caused the same DB row to match multiple chats/branches → duplicate lines.
                if raw_chat_id:
                    cursor.execute("""
                        SELECT * FROM chat_messages
                        WHERE chat_id = ?
                          AND (platform = ? OR LOWER(platform) = LOWER(?))
                        ORDER BY timestamp ASC
                        LIMIT ?
                    """, (raw_chat_id, platform_val, platform_val, limit))
                elif chat_name and chat_name != 'Unknown':
                    cursor.execute("""
                        SELECT * FROM chat_messages
                        WHERE chat_name = ?
                          AND chat_name IS NOT NULL AND chat_name != ''
                          AND (platform = ? OR LOWER(platform) = LOWER(?))
                        ORDER BY timestamp ASC
                        LIMIT ?
                    """, (chat_name, platform_val, platform_val, limit))
                else:
                    cursor.execute("SELECT * FROM chat_messages WHERE 0")
                
                messages = []
                message_count = 0
                for msg_row in cursor.fetchall():
                    msg = dict(msg_row)
                    message_count += 1
                    
                    # Parse attachments
                    attachments = []
                    att_str = msg.get('attachments')
                    if att_str and att_str != 'null' and att_str != '[]':
                        try:
                            att_data = json.loads(att_str) if isinstance(att_str, str) else att_str
                            if isinstance(att_data, list):
                                attachments = att_data
                            elif isinstance(att_data, dict):
                                attachments = [att_data]
                        except:
                            pass
                    
                    messages.append({
                        'message_id': msg.get('message_id', ''),
                        'from_participant': msg.get('from_participant', 'Unknown'),
                        'to_participant': msg.get('to_participant', 'Unknown'),
                        'from_identifier': msg.get('from_identifier', ''),
                        'to_identifier': msg.get('to_identifier', ''),
                        'text_content': msg.get('text_content', '') or '',
                        'timestamp': msg.get('timestamp', ''),
                        'message_type': msg.get('message_type', 'unknown'),
                        'is_deleted': bool(msg.get('is_deleted', 0) == 1),
                        'attachments': attachments
                    })
                
                # Log message retrieval for debugging
                if message_count == 0:
                    logger.warning(f"⚠️ No messages found for chat: chat_id='{chat_id_val}', chat_name='{chat_name}', platform='{platform_val}'")
                    # Try a more lenient search to see if messages exist at all for this platform
                    cursor.execute("""
                        SELECT COUNT(*) as total FROM chat_messages
                        WHERE (platform = ? OR LOWER(platform) = LOWER(?))
                    """, (platform_val, platform_val))
                    platform_total = cursor.fetchone()['total']
                    if platform_total > 0:
                        logger.warning(f"⚠️ Platform '{platform_val}' has {platform_total} total messages, but none matched chat_id='{chat_id_val}' or chat_name='{chat_name}'")
                else:
                    logger.info(f"✅ Retrieved {message_count} messages for chat: {chat_name} (platform: {platform_val})")
                
                # Get location count
                location_count = 0
                if chat_metadata.get('has_location_data'):
                    if raw_chat_id:
                        cursor.execute("""
                            SELECT COUNT(*) as loc_count
                            FROM chat_messages
                            WHERE chat_id = ?
                              AND (platform = ? OR LOWER(platform) = LOWER(?))
                              AND message_type = 'location'
                        """, (raw_chat_id, platform_val, platform_val))
                    elif chat_name and chat_name != 'Unknown':
                        cursor.execute("""
                            SELECT COUNT(*) as loc_count
                            FROM chat_messages
                            WHERE chat_name = ?
                              AND (platform = ? OR LOWER(platform) = LOWER(?))
                              AND message_type = 'location'
                        """, (chat_name, platform_val, platform_val))
                    else:
                        cursor.execute("SELECT 0 as loc_count", ())
                    loc_result = cursor.fetchone()
                    location_count = loc_result['loc_count'] if loc_result else 0
                
                result['chats'].append({
                    'chat_id': chat_id_val,
                    'chat_name': chat_name,
                    'platform': platform_val,
                    'participants': participants,
                    'participant_count': len(participants) if participants else 0,
                    'start_time': chat_metadata.get('start_time') or chat.get('last_message_time'),
                    'last_activity': chat_metadata.get('last_activity') or chat.get('last_message_time'),
                    'attachment_count': chat_metadata.get('attachment_count', 0),
                    'has_location_data': chat_metadata.get('has_location_data', False),
                    'location_count': location_count,
                    'total_messages': chat_metadata.get('total_messages', len(messages)),
                    'messages': messages
                })
            
            return result
        finally:
            conn.close()
    
    def get_chat_insights(self, chat_data: Dict, query: str = "") -> Dict:
        """
        Returns LLM-generated insights for chat data.
        Called separately from data extraction.
        
        Args:
            chat_data: Chat data dictionary from get_chat_data_for_display()
            query: Optional specific query for insights
            
        Returns:
            {
                'insights': {
                    'participants': '...',
                    'conversation_summary': '...',
                    'timeline_analysis': '...',
                    'suspicious_activity': '...',
                    'key_findings': [...]
                }
            }
        """
        # This method will be called by the LLM analysis endpoint
        # For now, return structured format that LLM can populate
        return {
            'insights': {
                'participants': '',
                'conversation_summary': '',
                'timeline_analysis': '',
                'suspicious_activity': '',
                'key_findings': []
            },
            'chat_data_summary': {
                'total_chats': len(chat_data.get('chats', [])),
                'total_messages': sum(c.get('total_messages', 0) for c in chat_data.get('chats', [])),
                'platform': chat_data.get('platform', 'Unknown')
            }
        }
    
    def query_chat_messages(self, query: str, limit: int = 100, platform_filter: str = None) -> List[Dict]:
        """Query chat messages based on search terms.
        
        Args:
            query: Search query string
            limit: Maximum number of results
            platform_filter: Optional platform name to filter by (e.g., 'Twitter', 'WhatsApp')
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            query_lower = query.lower()
            conditions = []
            params = []
            
            # Detect if this is a platform-only query (user wants all messages from platform, not content search)
            is_platform_only_query = False
            if platform_filter:
                platform_query_patterns = [
                    'pull.*from', 'get.*from', 'show.*from', 'messages.*from',
                    'pull.*messages', 'get.*messages', 'show.*messages',
                    'list.*messages', 'all.*messages'
                ]
                is_platform_only_query = any(
                    re.search(pattern, query_lower) for pattern in platform_query_patterns
                ) or query_lower.strip() in ['', 'list all', 'all messages', 'all']
                # "analyze whatsapp messages" must not apply content LIKE filters on words "analyze"/platform name —
                # that drops normal chat lines (e.g. "Here I am!") and shrinks the LLM packet vs "show … messages".
                if platform_filter and not is_platform_only_query:
                    if re.search(
                        r"\b(analyze|analysis|insights?|summarize|summarise|examine|review|interpret|explain|analzye|nalzye|anaylze|analize|anlyze|analsis)\b",
                        query_lower,
                    ) and re.search(r"\b(messages?|chats?|conversations?)\b", query_lower):
                        is_platform_only_query = True
            
            # Add platform filter if specified
            if platform_filter:
                platform_filter_lower = platform_filter.lower()
                # Handle special cases for multi-word platforms (case-insensitive, partial match)
                if platform_filter_lower == 'native messages' or platform_filter_lower == 'native':
                    conditions.append("(LOWER(platform) LIKE ?)")
                    params.append('%native%')
                elif platform_filter_lower == 'textnow' or platform_filter_lower == 'text now':
                    conditions.append("(LOWER(REPLACE(platform, ' ', '')) LIKE ?)")
                    params.append('%textnow%')
                elif platform_filter_lower == 'tiktok' or platform_filter_lower == 'tik tok':
                    conditions.append("(LOWER(REPLACE(platform, ' ', '')) LIKE ?)")
                    params.append('%tiktok%')
                elif platform_filter_lower == 'wickr' or platform_filter_lower == 'wickr pro':
                    conditions.append("(LOWER(platform) LIKE ?)")
                    params.append('%wickr%')
                elif platform_filter_lower == 'kik':
                    # Match "Kik Messenger" specifically
                    conditions.append("(LOWER(platform) LIKE ?)")
                    params.append('%kik%')
                elif platform_filter_lower == 'messenger' or 'facebook messenger' in platform_filter_lower:
                    # Match "Facebook Messenger" specifically (not "Kik Messenger")
                    conditions.append("(LOWER(platform) LIKE ? AND LOWER(platform) LIKE ?)")
                    params.extend(['%messenger%', '%facebook%'])
                else:
                    conditions.append("(platform = ? OR LOWER(platform) = ?)")
                    params.extend([platform_filter, platform_filter_lower])
            
            # If platform-only query, skip content matching
            if is_platform_only_query:
                search_terms = []
            else:
                # Check if query is about a specific chat/contact name
                # If so, search by chat name/ID first
                chat_keywords = ['chat', 'message', 'messages', 'group', 'thread', 'associated', 'with', 'info', 'about', 'the', 'this', 'is', 'dfir']
                search_terms = [term for term in query_lower.split() if term not in chat_keywords]
            
            # Handle multi-word names (e.g., "this is dfir 2" should search for "thisisdfir" or "dfir")
            # Also handle case-insensitive partial matches
            if search_terms:
                # Try to match multi-word phrases
                full_search_phrase = ' '.join(search_terms)
                # Remove spaces for matching (e.g., "this is dfir 2" -> "thisisdfir2")
                no_space_phrase = ''.join(search_terms)
                
                # Search with both spaced and non-spaced versions (case-insensitive)
                # NOTE: chat_messages table does NOT have a 'participants' column - only chats table has it
                conditions.append("""(from_participant LIKE ? OR LOWER(from_participant) LIKE ?
                    OR to_participant LIKE ? OR LOWER(to_participant) LIKE ?
                    OR text_content LIKE ? OR LOWER(text_content) LIKE ?
                    OR chat_id LIKE ? OR LOWER(chat_id) LIKE ?
                    OR chat_name LIKE ? OR LOWER(chat_name) LIKE ?)""")
                params.extend([f"%{full_search_phrase}%", f"%{full_search_phrase.lower()}%",
                              f"%{full_search_phrase}%", f"%{full_search_phrase.lower()}%",
                              f"%{full_search_phrase}%", f"%{full_search_phrase.lower()}%",
                              f"%{full_search_phrase}%", f"%{full_search_phrase.lower()}%",
                              f"%{full_search_phrase}%", f"%{full_search_phrase.lower()}%"])
                
                conditions.append("""(from_participant LIKE ? OR LOWER(from_participant) LIKE ?
                    OR to_participant LIKE ? OR LOWER(to_participant) LIKE ?
                    OR text_content LIKE ? OR LOWER(text_content) LIKE ?
                    OR chat_id LIKE ? OR LOWER(chat_id) LIKE ?
                    OR chat_name LIKE ? OR LOWER(chat_name) LIKE ?)""")
                params.extend([f"%{no_space_phrase}%", f"%{no_space_phrase.lower()}%",
                              f"%{no_space_phrase}%", f"%{no_space_phrase.lower()}%",
                              f"%{no_space_phrase}%", f"%{no_space_phrase.lower()}%",
                              f"%{no_space_phrase}%", f"%{no_space_phrase.lower()}%",
                              f"%{no_space_phrase}%", f"%{no_space_phrase.lower()}%"])
                
                # Also search individual terms (case-insensitive)
                for term in search_terms:
                    if len(term) > 2:  # Skip very short words
                        conditions.append("""(from_participant LIKE ? OR LOWER(from_participant) LIKE ?
                            OR to_participant LIKE ? OR LOWER(to_participant) LIKE ?
                            OR text_content LIKE ? OR LOWER(text_content) LIKE ?
                            OR chat_id LIKE ? OR LOWER(chat_id) LIKE ?
                            OR chat_name LIKE ? OR LOWER(chat_name) LIKE ?)""")
                        params.extend([f"%{term}%", f"%{term.lower()}%",
                                      f"%{term}%", f"%{term.lower()}%",
                                      f"%{term}%", f"%{term.lower()}%",
                                      f"%{term}%", f"%{term.lower()}%",
                                      f"%{term}%", f"%{term.lower()}%"])
            
            # Build WHERE clause
            # If platform filter exists, it should be AND with other conditions
            # Otherwise, use OR for search terms
            if not conditions:
                where_clause = "1=1"
            elif platform_filter and len(conditions) > 1:
                # Platform filter should be AND, search terms should be OR
                platform_condition = conditions[0]  # First condition is platform
                search_conditions = conditions[1:]  # Rest are search terms
                where_clause = f"{platform_condition} AND ({' OR '.join(search_conditions)})"
            else:
                where_clause = " OR ".join(conditions)
            
            cursor.execute(f"""
                SELECT * FROM chat_messages 
                WHERE {where_clause}
                ORDER BY timestamp DESC
                LIMIT ?
            """, params + [limit] if params else [limit])
            
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
    
    def query_files(self, query: str, limit: int = 100) -> List[Dict]:
        """Query files based on search terms."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            query_lower = query.lower()
            conditions = []
            params = []
            
            # Search by filename, file type, or path
            for term in query_lower.split():
                if term not in ['file', 'files', 'document', 'attachment', 'download']:
                    conditions.append("(filename LIKE ? OR file_type LIKE ? OR file_path LIKE ?)")
                    params.extend([f"%{term}%", f"%{term}%", f"%{term}%"])
            
            where_clause = " OR ".join(conditions) if conditions else "1=1"
            
            cursor.execute(f"""
                SELECT * FROM files 
                WHERE {where_clause}
                ORDER BY size DESC
                LIMIT ?
            """, params + [limit])
            
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
    
    def query_calls(self, query: str, limit: int = 100) -> List[Dict]:
        """Query calls based on search terms."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            query_lower = query.lower()
            
            # Check if user wants ALL calls FIRST (before filtering)
            # Check for phrases that indicate "all" intent
            wants_all_calls = any(phrase in query_lower for phrase in ['list all', 'show all', 'all calls', 'all call logs', 
                                                                      'every call', 'entire', 'complete', 'full list', 
                                                                      'list all call', 'show all call', 'get all call'])
            
            # Check if query is about calls in general (not searching for specific numbers)
            call_keywords = ['call', 'called', 'calls', 'phone', 'dial', 'dialed', 'ring', 'rang', 'spoke', 'spoken', 
                           'suspicious', 'log', 'logs', 'call log', 'call logs', 'call history', 'call record', 
                           'call records', 'incoming call', 'outgoing call', 'missed call', 'missed calls']
            is_general_call_query = any(keyword in query_lower for keyword in call_keywords)
            
            # Extract potential phone numbers or names from query
            conditions = []
            params = []
            
            # Filter out call-related keywords and common query words
            filtered_terms = [t for t in query_lower.split() 
                            if t not in call_keywords + ['list', 'all', 'show', 'get', 'find', 'every', 'entire', 'complete', 'full']]
            
            # Search by phone number or name (skip call-related keywords)
            for term in filtered_terms:
                # Check if term looks like a phone number or name
                if term.replace('+', '').replace('-', '').replace('(', '').replace(')', '').replace(' ', '').isdigit():
                    # Looks like a phone number
                    conditions.append("(from_number LIKE ? OR to_number LIKE ?)")
                    params.extend([f"%{term}%", f"%{term}%"])
                elif len(term) > 2:  # Potential name or other search term
                    conditions.append("(from_number LIKE ? OR to_number LIKE ? OR call_type LIKE ?)")
                    params.extend([f"%{term}%", f"%{term}%", f"%{term}%"])
            
            # If it's a general call query and wants all calls OR no specific search terms, return all calls
            if (is_general_call_query and wants_all_calls) or (is_general_call_query and not conditions):
                where_clause = "1=1"
            elif conditions:
                where_clause = " OR ".join(conditions)
            else:
                # No call keywords and no search terms - return empty
                return []
            
            cursor.execute(f"""
                SELECT * FROM call_logs 
                WHERE {where_clause}
                ORDER BY timestamp DESC
                LIMIT ?
            """, params + [limit] if params else [limit])
            
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
    
    def _analyze_query_intent(self, query: str) -> Dict[str, Any]:
        """
        Comprehensive query intent analysis - bulletproof detection of all query types.
        Returns a dictionary with detected intents, entities, and query characteristics.
        """
        query_lower = query.lower()
        query_original = query
        
        intent = {
            'query': query,
            'query_lower': query_lower,
            'question_type': None,  # what, who, when, where, how, why, which
            'data_types': [],  # contacts, messages, calls, chats, files, locations, device
            'entities': {
                'person_names': [],
                'phone_numbers': [],
                'platforms': [],
                'dates': [],
                'numbers': []
            },
            'modifiers': {
                'temporal': None,  # recent, last week, between dates, etc.
                'count': None,  # "5 chats", "10 messages"
                'comparison': None,  # most, top, least, etc.
                'negation': False,  # not, except, excluding
                'boolean': None  # and, or
            },
            'intent_type': None,  # list, search, analyze, compare, relationship, statistical
            'is_pattern_analysis': False,
            'is_comprehensive': False  # "all", "everything", "complete analysis"
        }
        
        # Question word detection
        question_words = {
            'what': ['what', 'which'],
            'who': ['who', 'whom', 'whose'],
            'when': ['when', 'what time', 'what date'],
            'where': ['where', 'location', 'place'],
            'how': ['how', 'how many', 'how much', 'how often'],
            'why': ['why', 'reason', 'because']
        }
        for qtype, words in question_words.items():
            if any(word in query_lower for word in words):
                intent['question_type'] = qtype
                break
        
        # Extract phone numbers
        phone_pattern = r'\+?\d{10,15}|\d{3}[-.\s]?\d{3}[-.\s]?\d{4}'
        phones = re.findall(phone_pattern, query)
        intent['entities']['phone_numbers'] = [re.sub(r'[-.\s]', '', p) for p in phones]
        
        # Extract numbers (for limits like "5 chats")
        number_pattern = r'\b(\d+)\s+(?:chat|chats|message|messages|contact|contacts|call|calls|file|files|item|items)\b'
        number_match = re.search(number_pattern, query_lower)
        if number_match:
            intent['modifiers']['count'] = int(number_match.group(1))
        
        # Extract person names (capitalized words, excluding common words)
        common_words = {
            'chat', 'chats', 'conversation', 'group', 'thread', 'list', 'all', 'show', 'get', 'find', 
            'with', 'from', 'about', 'info', 'the', 'this', 'is', 'dfir', 'two', 'one', 'three',
            'message', 'messages', 'call', 'calls', 'contact', 'contacts', 'phone', 'whatsapp',
            'telegram', 'messenger', 'twitter', 'facebook', 'instagram', 'snapchat', 'line', 'viber',
            'sms', 'mms', 'imessage', 'signal', 'wechat', 'kik', 'skype', 'discord', 'slack'
        }
        # Do not treat "Correlate WhatsApp", "Compare Telegram", etc. as person names.
        _not_name_leaders = frozenset({
            'correlate', 'correlation', 'compare', 'comparison', 'overlap', 'cross-reference',
            'crossreference', 'cross', 'analyze', 'analysis', 'summarize', 'summarise', 'explain', 'list',
            'show', 'find', 'search', 'get', 'display', 'pull', 'match', 'reconstruct', 'rebuild',
        })
        words = query.split()
        potential_names = []
        for i, word in enumerate(words):
            # Skip if it's a common word or too short
            if word.lower() in common_words or len(word) < 3:
                continue
            wlow = word.lower().strip('.,;:')
            if wlow in _not_name_leaders:
                continue
            # Check if it's capitalized (likely a name)
            if word[0].isupper() and word.isalpha():
                # Check if next word is also capitalized (multi-word name)
                if i + 1 < len(words) and words[i + 1][0].isupper() and words[i + 1].isalpha():
                    potential_names.append(f"{word} {words[i + 1]}")
                elif i == 0 or (i > 0 and words[i - 1][0].isupper()):
                    # Part of multi-word name
                    continue
                else:
                    potential_names.append(word)
        # Drop false positives e.g. "Correlate WhatsApp" if any slipped through
        potential_names = [
            n
            for n in potential_names
            if n
            and not n.lower().startswith(
                ("correlate ", "correlation ", "compare ", "comparison ", "overlap ")
            )
        ]
        intent['entities']['person_names'] = list(set(potential_names))
        
        # Platform detection — must match query_intent_parser boundaries (e.g. "ig" in "insights" is NOT Instagram).
        intent['entities']['platforms'] = extract_platforms_ordered(query_original)
        
        # Data type detection (comprehensive)
        # Guard against platform-name collisions:
        # - "snapchat" should not trigger chats via "chat"
        # - "google photos" should not trigger files via "photo(s)"
        q_for_domain = query_lower
        try:
            alias_pool = sorted(
                {a.lower() for aliases in PLATFORM_ALIASES.values() for a in aliases},
                key=len,
                reverse=True,
            )
            for alias in alias_pool:
                if not alias:
                    continue
                q_for_domain = re.sub(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", " ", q_for_domain)
        except Exception:
            # Fallback safely to raw query if alias map access ever changes.
            q_for_domain = query_lower

        def _kw_match(txt: str, kw: str) -> bool:
            k = (kw or "").strip().lower()
            if not k:
                return False
            return bool(re.search(rf"(?<![a-z0-9]){re.escape(k)}(?![a-z0-9])", txt))

        data_type_keywords = {
            'contacts': ['contact', 'contacts', 'name', 'names', 'phone', 'phones', 'phone number', 'phone numbers',
                        'people', 'person', 'persons', 'address book', 'contact list', 'directory', 'phonebook',
                        'who', 'whom', 'whose', 'international', 'international number', 'international numbers',
                        'international no', 'international nos', 'international phone', 'international phones'],
            'messages': ['message', 'messages', 'text', 'texts', 'text message', 'text messages', 'sms', 'mms',
                        'said', 'sent', 'received', 'communication', 'communications'],
            'calls': ['call', 'calls', 'called', 'dial', 'dialed', 'phone call', 'phone calls', 'ring', 'rang',
                     'spoke', 'spoken', 'log', 'logs', 'call log', 'call logs', 'call history', 'call record',
                     'incoming call', 'outgoing call', 'missed call', 'missed calls'],
            'chats': ['chat', 'chats', 'conversation', 'conversations', 'group', 'groups', 'thread', 'threads',
                     'group chat', 'group message', 'group messages', 'thread message', 'thread messages'],
            'files': ['file', 'files', 'document', 'documents', 'attachment', 'attachments', 'download', 'downloads',
                     'media', 'photo', 'photos', 'image', 'images', 'video', 'videos', 'picture', 'pictures',
                     'screenshot', 'screenshots', 'audio', 'recording', 'recordings', 'stored', 'saved'],
            'locations': ['location', 'locations', 'gps', 'coordinates', 'coordinate', 'where', 'place', 'places',
                         'address', 'addresses', 'map', 'maps', 'visited', 'visit', 'geolocation', 'geolocations',
                         'latitude', 'longitude', 'position', 'positions', 'tracking', 'tracked', 'movement', 'movements'],
            'device': ['device', 'model', 'manufacturer', 'imei', 'serial', 'phone model', 'device model', 'hardware']
        }
        for data_type, keywords in data_type_keywords.items():
            if any(_kw_match(q_for_domain, kw) for kw in keywords):
                intent['data_types'].append(data_type)
        
        # Intent type detection
        if any(word in query_lower for word in ['list', 'show', 'get', 'give', 'display', 'view']):
            intent['intent_type'] = 'list'
        elif any(word in query_lower for word in ['find', 'search', 'look', 'locate']):
            intent['intent_type'] = 'search'
        elif any(word in query_lower for word in ['analyze', 'analysis', 'examine', 'investigate', 'study']):
            intent['intent_type'] = 'analyze'
        elif any(word in query_lower for word in ['compare', 'comparison', 'difference', 'versus', 'vs']):
            intent['intent_type'] = 'compare'
        elif any(word in query_lower for word in ['relationship', 'connection', 'link', 'related', 'associated']):
            intent['intent_type'] = 'relationship'
        elif any(word in query_lower for word in ['statistics', 'stats', 'count', 'how many', 'frequency', 'most', 'top', 'least']):
            intent['intent_type'] = 'statistical'
        elif any(word in query_lower for word in ['timeline', 'chronological', 'sequence', 'order', 'when', 'history']):
            intent['intent_type'] = 'temporal'
        
        # Pattern analysis detection
        intent['is_pattern_analysis'] = any(phrase in query_lower for phrase in [
            'pattern', 'patterns', 'suspicious pattern', 'suspicous pattern',
            'communication pattern', 'communication patterns',
            'analyze pattern', 'find pattern', 'detect pattern', 'identify pattern',
            'suspicious communication', 'suspicous communication',
            'suspicious activity', 'suspicious behavior',
            'suspicous activity', 'suspicous behavior'
        ]) or ('suspic' in query_lower and ('pattern' in query_lower or 'communication' in query_lower))
        
        # Comprehensive query detection
        intent['is_comprehensive'] = any(phrase in query_lower for phrase in [
            'all', 'every', 'entire', 'complete', 'full', 'everything', 'comprehensive',
            'list all', 'show all', 'get all', 'all of', 'all the'
        ])
        
        # Temporal modifiers
        if any(word in query_lower for word in ['recent', 'latest', 'newest', 'last']):
            intent['modifiers']['temporal'] = 'recent'
        elif any(word in query_lower for word in ['oldest', 'first', 'earliest']):
            intent['modifiers']['temporal'] = 'oldest'
        elif any(phrase in query_lower for phrase in ['last week', 'past week', 'this week']):
            intent['modifiers']['temporal'] = 'last_week'
        elif any(phrase in query_lower for phrase in ['last month', 'past month', 'this month']):
            intent['modifiers']['temporal'] = 'last_month'
        elif any(phrase in query_lower for phrase in ['between', 'from', 'to']):
            intent['modifiers']['temporal'] = 'range'
        
        # Comparison modifiers
        if any(word in query_lower for word in ['most', 'top', 'highest', 'maximum', 'max']):
            intent['modifiers']['comparison'] = 'most'
        elif any(word in query_lower for word in ['least', 'lowest', 'minimum', 'min']):
            intent['modifiers']['comparison'] = 'least'
        
        # Negation detection
        intent['modifiers']['negation'] = any(word in query_lower for word in ['not', 'except', 'excluding', 'without', 'no'])
        
        # Boolean operators
        if ' and ' in query_lower or ' & ' in query_lower:
            intent['modifiers']['boolean'] = 'and'
        elif ' or ' in query_lower or ' | ' in query_lower:
            intent['modifiers']['boolean'] = 'or'
        
        return intent

    @staticmethod
    def _sqlite_table_exists(conn: sqlite3.Connection, name: str) -> bool:
        cur = conn.cursor()
        cur.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
            (name,),
        )
        return cur.fetchone() is not None

    def _try_cross_domain_day_bundle(
        self, query: str, evidence_scope: EvidenceScope, max_items: int
    ) -> Tuple[str, bool]:
        """
        Deterministic calendar-day slice for cross-domain questions (e.g. suspicious comms on YYYY-MM-DD).
        Injected early so the LLM sees real app chats / calls / locations / SMS for that day, not device-only noise.
        """
        if evidence_scope.mode != "cross_domain_scoped":
            return "", False
        days = _extract_iso_days_from_query(query)
        if not days:
            return "", False
        days = days[:3]
        per_table = min(80, max(20, max_items))
        ph = ",".join("?" * len(days))
        parts: List[str] = []
        parts.append("=== CROSS-DOMAIN DAY BUNDLE (deterministic calendar-day slice) ===")
        parts.append(f"calendar_days={','.join(days)}")
        has_chat_rows = False
        conn = self.get_connection()
        try:
            cur = conn.cursor()

            if self._sqlite_table_exists(conn, "chat_messages"):
                try:
                    cur.execute(
                        f"""
                        SELECT * FROM chat_messages
                        WHERE timestamp IS NOT NULL
                          AND substr(
                                replace(replace(COALESCE(timestamp,''),'[',''),']',''),
                                1, 10
                              ) IN ({ph})
                        ORDER BY timestamp DESC
                        LIMIT ?
                        """,
                        (*days, per_table),
                    )
                    cm_rows = cur.fetchall()
                except sqlite3.Error as e:
                    logger.warning("cross_domain_day_bundle chat_messages: %s", e)
                    cm_rows = []
                parts.append(f"--- chat_messages rows={len(cm_rows)} (cap {per_table}) ---")
                for r in cm_rows:
                    has_chat_rows = True
                    d = dict(r)
                    ts = d.get("timestamp") or "N/A"
                    plat = d.get("platform") or "?"
                    body = (d.get("text_content") or "")[:240].replace("\n", " ")
                    frm = d.get("from_participant") or "?"
                    to = d.get("to_participant") or "?"
                    parts.append(f"[{ts}] {plat} | {frm} -> {to} | {body}")
            else:
                parts.append("--- chat_messages: table not present ---")

            if self._sqlite_table_exists(conn, "call_logs"):
                try:
                    cur.execute(
                        f"""
                        SELECT * FROM call_logs
                        WHERE timestamp IS NOT NULL
                          AND substr(
                                replace(replace(COALESCE(timestamp,''),'[',''),']',''),
                                1, 10
                              ) IN ({ph})
                        ORDER BY timestamp DESC
                        LIMIT ?
                        """,
                        (*days, per_table),
                    )
                    cl_rows = cur.fetchall()
                except sqlite3.Error as e:
                    logger.warning("cross_domain_day_bundle call_logs: %s", e)
                    cl_rows = []
                parts.append(f"--- call_logs rows={len(cl_rows)} (cap {per_table}) ---")
                for r in cl_rows:
                    d = dict(r)
                    ts = d.get("timestamp") or "N/A"
                    dur = d.get("duration")
                    ctype = d.get("call_type") or ""
                    src = d.get("source_table") or ""
                    parts.append(
                        f"[{ts}] {d.get('from_number')} -> {d.get('to_number')} "
                        f"({dur}s {ctype}) src={src}"
                    )

            if self._sqlite_table_exists(conn, "locations"):
                try:
                    cur.execute(
                        f"""
                        SELECT * FROM locations
                        WHERE timestamp IS NOT NULL
                          AND substr(
                                replace(replace(COALESCE(timestamp,''),'[',''),']',''),
                                1, 10
                              ) IN ({ph})
                        ORDER BY timestamp DESC
                        LIMIT ?
                        """,
                        (*days, per_table),
                    )
                    loc_rows = cur.fetchall()
                except sqlite3.Error as e:
                    logger.warning("cross_domain_day_bundle locations: %s", e)
                    loc_rows = []
                parts.append(f"--- locations rows={len(loc_rows)} (cap {per_table}) ---")
                for r in loc_rows:
                    d = dict(r)
                    ts = d.get("timestamp") or "N/A"
                    lat = d.get("latitude")
                    lon = d.get("longitude")
                    src = d.get("source_table") or ""
                    parts.append(f"[{ts}] ({lat}, {lon}) src={src}")

            if self._sqlite_table_exists(conn, "messages"):
                try:
                    cur.execute(
                        f"""
                        SELECT * FROM messages
                        WHERE timestamp IS NOT NULL
                          AND substr(
                                replace(replace(COALESCE(timestamp,''),'[',''),']',''),
                                1, 10
                              ) IN ({ph})
                        ORDER BY timestamp DESC
                        LIMIT ?
                        """,
                        (*days, per_table),
                    )
                    msg_rows = cur.fetchall()
                except sqlite3.Error as e:
                    logger.warning("cross_domain_day_bundle messages: %s", e)
                    msg_rows = []
                parts.append(f"--- messages (SMS/native table) rows={len(msg_rows)} (cap {per_table}) ---")
                for r in msg_rows:
                    d = dict(r)
                    ts = d.get("timestamp") or "N/A"
                    body = (d.get("text_content") or "")[:240].replace("\n", " ")
                    src = d.get("source") or ""
                    parts.append(
                        f"[{ts}] {d.get('from_number')} -> {d.get('to_number')} "
                        f"source={src} | {body}"
                    )
        finally:
            conn.close()

        return "\n".join(parts), has_chat_rows
    
    def get_relevant_data_for_llm(
        self,
        query: str,
        max_items: int = 50,
        *,
        evidence_scope: Optional[EvidenceScope] = None,
    ) -> str:
        """
        Extract query-relevant data and format for LLM.
        This is the main interface for LLM integration.
        Handles: chats, files, messages, contacts, calls, locations, device info.

        When evidence_scope is None, it is derived from parse_query_intent (single resolver).
        """
        # Comprehensive query intent analysis
        intent = self._analyze_query_intent(query)
        if evidence_scope is None:
            evidence_scope = compute_evidence_scope(query, parse_query_intent(query), None)
        query_lower = intent['query_lower']
        phone_numbers_in_query = intent['entities']['phone_numbers']

        merged_platforms = list(intent["entities"].get("platforms") or [])
        if not merged_platforms and evidence_scope.platforms:
            merged_platforms = list(evidence_scope.platforms)
        # Keep EVIDENCE_SCOPE and SQL filter aligned when the packet is platform-isolated.
        if evidence_scope.mode == "platform_isolated" and len(evidence_scope.platforms) == 1:
            merged_platforms = [evidence_scope.platforms[0]]
        if merged_platforms:
            intent["entities"]["platforms"] = merged_platforms
        
        # Extract numbers from query (e.g., "5 chats", "10 messages", "3 contacts")
        if intent['modifiers']['count']:
            requested_limit = intent['modifiers']['count']
            logger.info(f"🔢 Extracted number from query: {requested_limit} (from '{query}')")
            # Override max_items with the requested number (but cap at reasonable maximum)
            max_items = min(requested_limit, max_items * 2)
        
        # Determine what data to extract
        context_parts = []
        # True if chat_messages (third-party apps) were already included — avoids contradicting the SMS `messages` table section
        context_includes_chat_app_messages = False
        day_bundle, day_bundle_has_chats = self._try_cross_domain_day_bundle(
            query, evidence_scope, max_items
        )
        if day_bundle:
            context_parts.append(day_bundle)
            if day_bundle_has_chats:
                context_includes_chat_app_messages = True
        
        # Use intent analysis for pattern detection
        is_pattern_analysis = intent['is_pattern_analysis']
        
        # Detect pattern analysis queries - these need actual data for comprehensive analysis
        # Handle common typos and variations
        is_pattern_analysis = any(phrase in query_lower for phrase in [
            'pattern', 'patterns', 'suspicious pattern', 'suspicous pattern',  # Handle typo
            'communication pattern', 'communication patterns',
            'analyze pattern', 'find pattern', 'detect pattern', 'identify pattern',
            'suspicious communication', 'suspicous communication',  # Handle typo
            'suspicious activity', 'suspicious behavior',
            'suspicous activity', 'suspicous behavior'  # Handle typo
        ]) or ('suspic' in query_lower and ('pattern' in query_lower or 'communication' in query_lower))
        
        # Device information (model, manufacturer, IMEI, etc.)
        if 'device' in intent['data_types'] and evidence_scope.allows_domain("device"):
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM device_metadata WHERE category = 'device'")
            device_metadata = {row['key']: row['value'] for row in cursor.fetchall()}
            
            if device_metadata:
                context_parts.append("\n=== DEVICE INFORMATION ===")
                for key, value in device_metadata.items():
                    if value:  # Only show non-empty values
                        context_parts.append(f"{key}: {value}")
            
            # Also check if device info is in the UFDR format data
            ufdr_data = self.get_ufdr_format_data()
            device_info = ufdr_data.get('device', {})
            if device_info and not device_metadata:
                context_parts.append("\n=== DEVICE INFORMATION ===")
                for key, value in device_info.items():
                    if value and key not in ['id', 'source']:  # Skip internal fields
                        context_parts.append(f"{key}: {value}")
        
        # International phone number query detection (must be early)
        is_international_phone_query = any(phrase in query_lower for phrase in [
            'international number', 'international numbers', 'international no', 'international nos',
            'international phone', 'international phones', 'list international', 'show international',
            'international contact', 'international contacts'
        ])
        
        # Platform classification query detection - expanded to catch more queries
        is_platform_classification_query = any(phrase in query_lower for phrase in [
            'classify', 'classification', 'platform classification', 'classify chats',
            'classify platforms', 'platform breakdown', 'platform distribution',
            'what platforms', 'which platforms', 'list platforms', 'show platforms',
            'how many chats', 'chat breakdown', 'platforms used', 'messaging apps',
            'what apps', 'which apps', 'chat apps', 'messaging platforms'
        ])
        
        # Whole-case platform stats — only for case_overview (avoid contaminating slice queries)
        if evidence_scope.include_global_preamble:
            platform_classification = self.get_platform_classification()
            context_parts.insert(0, platform_classification)
            if is_platform_classification_query:
                context_parts.insert(
                    0,
                    "=== IMPORTANT: Use the platform classification below for accurate counts. "
                    "Do not estimate or guess. ===",
                )
        
        # Chats - use intent analysis
        is_chat_query = 'chats' in intent['data_types'] or any(word in query_lower for word in [
            'conversation', 'conversations', 'group', 'groups', 'thread', 'threads',
            'group chat', 'group message', 'group messages', 'whatsapp group', 'telegram group',
            'messenger group', 'pull any chats', 'have access to chats', 'chats available',
            'can you pull', 'do you have access to chats', 'analyze chat', 'analyze chats',
            'chat analysis', 'analyze the chats', 'chat conversation', 'chat conversations'
        ]) or (intent['entities']['platforms'] and not intent['data_types'])
        
        # Use extracted person names from intent analysis
        potential_names = intent['entities']['person_names']
        
        _scope_msgs = evidence_scope.allows_domain("messages") or evidence_scope.allows_domain("chats")
        if is_chat_query and _scope_msgs:
            # Use intent analysis for chat limits
            if intent['modifiers']['count'] and ('chat' in query_lower or 'chats' in query_lower):
                requested_chat_limit = intent['modifiers']['count']
                logger.info(f"🔢 User requested {requested_chat_limit} chat(s)")
                chat_limit = min(requested_chat_limit, max_items * 2)
                chat_number_match = True  # Flag for later use
            else:
                chat_number_match = False
                # For "list all" or pattern analysis queries, increase limit significantly
                wants_all_chats = intent['is_comprehensive'] or intent['intent_type'] == 'list'
                # For pattern analysis, get ALL chats and messages for comprehensive analysis
                chat_limit = max_items * 10 if (wants_all_chats or is_pattern_analysis) else max_items
            
            # Platform-specific filtering (support multi-platform cross-app queries)
            platform_filters = list(intent['entities'].get('platforms') or [])
            if not platform_filters and evidence_scope.platforms:
                platform_filters = list(evidence_scope.platforms)
            platform_filter = platform_filters[0] if platform_filters else None
            if platform_filters:
                logger.info(f"🔍 Platform filters for chats: {platform_filters}")

            def _chat_matches_any_platform(chat_row: Dict[str, Any], requested_platforms: List[str]) -> bool:
                if not requested_platforms:
                    return True
                p = (chat_row.get('platform', '') or '').lower()
                p_no_space = p.replace(' ', '')
                for pf in requested_platforms:
                    pf_lower = (pf or '').lower()
                    if not pf_lower:
                        continue
                    if pf_lower in ('native messages', 'native'):
                        if 'native' in p:
                            return True
                    elif pf_lower in ('textnow', 'text now'):
                        if 'textnow' in p_no_space:
                            return True
                    elif pf_lower in ('tiktok', 'tik tok'):
                        if 'tiktok' in p_no_space:
                            return True
                    elif pf_lower in ('wickr', 'wickr pro'):
                        if 'wickr' in p:
                            return True
                    elif pf_lower == 'kik':
                        if 'kik' in p:
                            return True
                    elif pf_lower == 'messenger' or 'facebook messenger' in pf_lower:
                        if 'messenger' in p and 'facebook' in p:
                            return True
                    elif pf_lower in p:
                        return True
                return False
            
            # For pattern analysis or "analyze" queries, get ALL chats without filtering
            is_analyze_query = any(k in query_lower for k in (
                'analyze', 'analysis', 'analzye', 'nalzye', 'anaylze', 'analize', 'anlyze', 'analsis'
            ))
            if is_pattern_analysis or is_analyze_query:
                chats = self.query_chats("list all chats", limit=min(50, chat_limit))
                # Also get chat messages for analysis
                chat_messages = self.query_chat_messages("", limit=min(200, max_items * 5))
            else:
                # First try the query as-is
                chats = self.query_chats(query, limit=chat_limit)
            
            # Apply platform filters if specified
            if platform_filters and chats:
                original_count = len(chats)
                chats = [c for c in chats if _chat_matches_any_platform(c, platform_filters)]
                if len(chats) < original_count:
                    logger.info(f"✅ Filtered to {len(chats)} chat(s) on platforms: {platform_filters}")
            
            # If no chats found but query mentions a person name, try searching more broadly
            if not chats and potential_names:
                # Try searching with just the person name
                name_query = ' '.join(potential_names)
                logger.info(f"🔍 No chats found with full query, trying person name only: '{name_query}'")
                chats = self.query_chats(name_query, limit=chat_limit)
                # Re-apply platform filter if needed
                if platform_filters and chats:
                    chats = [c for c in chats if _chat_matches_any_platform(c, platform_filters)]
            
            # If still no chats, try searching in participants JSON field directly
            if not chats and potential_names:
                conn = self.get_connection()
                try:
                    cursor = conn.cursor()
                    # Search in participants JSON field (stored as JSON string)
                    name_pattern = '%' + ' '.join(potential_names) + '%'
                    # Build query with platform filter if specified
                    if platform_filter:
                        cursor.execute("""
                            SELECT * FROM chats 
                            WHERE (participants LIKE ? OR chat_name LIKE ? OR LOWER(participants) LIKE ? OR LOWER(chat_name) LIKE ?)
                            AND (platform LIKE ? OR LOWER(platform) LIKE ?)
                            ORDER BY last_message_time DESC
                            LIMIT ?
                        """, (name_pattern, name_pattern, name_pattern.lower(), name_pattern.lower(), 
                              f"%{platform_filter}%", f"%{platform_filter.lower()}%", chat_limit))
                    else:
                        cursor.execute("""
                            SELECT * FROM chats 
                            WHERE participants LIKE ? OR chat_name LIKE ? OR platform LIKE ?
                            OR LOWER(participants) LIKE ? OR LOWER(chat_name) LIKE ? OR LOWER(platform) LIKE ?
                            ORDER BY last_message_time DESC
                            LIMIT ?
                        """, (name_pattern, name_pattern, name_pattern, name_pattern.lower(), 
                              name_pattern.lower(), name_pattern.lower(), chat_limit))
                    chats = [dict(row) for row in cursor.fetchall()]
                    if platform_filters and chats:
                        chats = [c for c in chats if _chat_matches_any_platform(c, platform_filters)]
                    if chats:
                        logger.info(f"✅ Found {len(chats)} chat(s) by searching participants JSON field")
                finally:
                    conn.close()
            
            # Limit to requested number if specified
            if chats and chat_number_match and intent['modifiers']['count']:
                requested_chat_limit = intent['modifiers']['count']
                chats = chats[:requested_chat_limit]
                logger.info(f"✅ Limited to {len(chats)} chat(s) as requested")
            
            if chats:
                # De-duplicate chat rows to avoid repeated platform/chat blocks.
                seen_chat_keys = set()
                deduped_chats = []
                for c in chats:
                    ck = (
                        (c.get('platform', '') or '').strip().lower(),
                        (c.get('chat_id', '') or '').strip().lower(),
                        (c.get('chat_name', '') or '').strip().lower(),
                    )
                    if ck in seen_chat_keys:
                        continue
                    seen_chat_keys.add(ck)
                    deduped_chats.append(c)
                chats = deduped_chats

                # Group chats by platform for hierarchical display
                chats_by_platform = {}
                for chat in chats:
                    platform = chat.get('platform', 'Unknown')
                    if platform not in chats_by_platform:
                        chats_by_platform[platform] = []
                    chats_by_platform[platform].append(chat)
                
                # Display in hierarchical format: Platform > Chat > Messages
                for platform, platform_chats in chats_by_platform.items():
                    # Platform-level summary
                    conn_summary = self.get_connection()
                    try:
                        cursor_summary = conn_summary.cursor()
                        cursor_summary.execute("""
                            SELECT COUNT(DISTINCT cm.id) as total_messages
                            FROM chat_messages cm
                            WHERE cm.platform = ?
                            AND cm.source_table = 'Chat'
                        """, (platform,))
                        result = cursor_summary.fetchone()
                        total_platform_messages = result['total_messages'] if result else 0
                        
                        context_parts.append(f"\n=== PLATFORM: {platform} ===")
                        context_parts.append(f"Total Chats: {len(platform_chats)} | Total Messages: {total_platform_messages}")
                    finally:
                        conn_summary.close()
                    
                    # Chat-level details
                    for chat_idx, chat in enumerate(platform_chats, 1):
                        participants = []
                        try:
                            participants = json.loads(chat.get('participants', '[]'))
                        except:
                            participants = [chat.get('participants', '')] if chat.get('participants') else []
                        
                        chat_id = chat.get('chat_id', '') or chat.get('chat_name', '')
                        chat_name = chat.get('chat_name', 'Unknown')
                        
                        # Get comprehensive chat metadata
                        chat_metadata = self._get_chat_metadata(chat_id, chat_name, platform)
                        participant_count = len(participants) if participants else chat_metadata.get('participant_count', 0)
                        
                        # Format chat header with all metadata
                        context_parts.append(f"\n--- Chat {chat_idx}: {chat_name} ---")
                        context_parts.append(f"Participants: {', '.join(participants) if participants else 'Unknown'} ({participant_count} participant{'s' if participant_count != 1 else ''})")
                        
                        if chat_metadata.get('start_time'):
                            context_parts.append(f"Start Time: {chat_metadata['start_time']}")
                        elif chat.get('last_message_time'):
                            context_parts.append(f"Start Time: {chat.get('last_message_time')}")  # Fallback
                        
                        if chat_metadata.get('last_activity'):
                            context_parts.append(f"Last Activity: {chat_metadata['last_activity']}")
                        elif chat.get('last_message_time'):
                            context_parts.append(f"Last Activity: {chat.get('last_message_time')}")
                        
                        context_parts.append(f"Attachments: {chat_metadata.get('attachment_count', 0)}")
                        
                        if chat_metadata.get('has_location_data'):
                            # Count location messages
                            conn_loc = self.get_connection()
                            try:
                                cursor_loc = conn_loc.cursor()
                                cursor_loc.execute("""
                                    SELECT COUNT(*) as loc_count
                                    FROM chat_messages
                                    WHERE (
                                        (chat_id = ? AND chat_id IS NOT NULL AND chat_id != '')
                                        OR 
                                        (chat_name = ? AND chat_name IS NOT NULL AND chat_name != '')
                                    ) AND platform = ?
                                    AND message_type = 'location'
                                """, (chat_id, chat_name, platform))
                                loc_result = cursor_loc.fetchone()
                                loc_count = loc_result['loc_count'] if loc_result else 0
                                context_parts.append(f"Location Data: Yes ({loc_count} location share{'s' if loc_count != 1 else ''})")
                            finally:
                                conn_loc.close()
                        else:
                            context_parts.append("Location Data: No")
                        
                        context_parts.append(f"Messages: {chat_metadata.get('total_messages', chat.get('message_count', 0))}")
                        
                        # Auto-include chat messages for this chat
                        if chat_id:
                            conn_msg = self.get_connection()
                            try:
                                cursor_msg = conn_msg.cursor()
                                # Configurable message limits based on query type
                                is_platform_only_query = platform_filters and any(phrase in query_lower for phrase in [
                                    'pull messages from', 'get messages from', 'show messages from',
                                    'messages from', 'pull from', 'get from'
                                ])
                                
                                if chat_number_match:
                                    msg_limit_per_chat = 2  # Only 2 messages per chat when specific number requested
                                    msg_display_limit = 2
                                elif is_pattern_analysis:
                                    msg_limit_per_chat = 100
                                    msg_display_limit = 50
                                elif is_platform_only_query:
                                    msg_limit_per_chat = 50  # Show more messages for platform-only queries
                                    msg_display_limit = 50
                                else:
                                    msg_limit_per_chat = min(20, max_items)
                                    msg_display_limit = 10
                                
                                cursor_msg.execute("""
                                    SELECT * FROM chat_messages 
                                    WHERE (
                                        (chat_id = ? AND chat_id IS NOT NULL AND chat_id != '')
                                        OR 
                                        (chat_name = ? AND chat_name IS NOT NULL AND chat_name != '')
                                    )
                                    AND (platform = ? OR LOWER(platform) = LOWER(?))
                                    ORDER BY timestamp DESC
                                    LIMIT ?
                                """, (chat_id, chat_name, platform, platform, msg_limit_per_chat))
                                chat_msgs = [dict(row) for row in cursor_msg.fetchall()]
                                
                                if chat_msgs:
                                    context_parts.append(f"\n  Messages in '{chat_name}' ({len(chat_msgs)} shown, {chat_metadata.get('total_messages', len(chat_msgs))} total):")
                                    
                                    # Sort messages by timestamp (oldest first for chronological display)
                                    chat_msgs_sorted = sorted(chat_msgs, key=lambda m: m.get('timestamp', '') or '')
                                    
                                    for msg_idx, msg in enumerate(chat_msgs_sorted[:msg_display_limit], 1):
                                        timestamp = msg.get('timestamp', '') or msg.get('timestamp_formatted', '') or 'N/A'
                                        if timestamp and timestamp != 'N/A' and '[YYYY' not in timestamp:
                                            time_str = timestamp
                                        else:
                                            time_str = "Time: Not available"
                                        
                                        # Don't truncate content for platform-only or analysis queries
                                        is_analyze_query_chat = any(k in query_lower for k in (
                                            'analyze', 'analysis', 'analzye', 'nalzye', 'anaylze', 'analize', 'anlyze', 'analsis'
                                        ))
                                        is_platform_only_msg = is_platform_only_query
                                        content_limit = 50 if chat_number_match else (500 if (is_analyze_query_chat or is_platform_only_msg) else 200)
                                        
                                        text_content = msg.get('text_content', '') or ''
                                        message_type = msg.get('message_type', 'unknown') or 'unknown'
                                        is_deleted = msg.get('is_deleted', 0) == 1
                                        
                                        # Format message based on type
                                        from_participant = msg.get('from_participant', 'Unknown')
                                        deleted_indicator = " [DELETED]" if is_deleted else ""
                                        
                                        if message_type == 'text':
                                            if text_content and text_content.strip():
                                                context_parts.append(
                                                    f"    Message {msg_idx} [{time_str}]{deleted_indicator} {from_participant}: {text_content[:content_limit]}{'...' if len(text_content) > content_limit else ''}"
                                                )
                                            else:
                                                context_parts.append(
                                                    f"    Message {msg_idx} [{time_str}]{deleted_indicator} {from_participant}: [Text message - no content]"
                                                )
                                        elif message_type == 'location':
                                            if text_content:
                                                context_parts.append(
                                                    f"    Message {msg_idx} [{time_str}]{deleted_indicator} {from_participant}: [Location Share] {text_content[:content_limit]}{'...' if len(text_content) > content_limit else ''}"
                                                )
                                            else:
                                                context_parts.append(
                                                    f"    Message {msg_idx} [{time_str}]{deleted_indicator} {from_participant}: [Location Share]"
                                                )
                                        elif message_type == 'media':
                                            attachments = msg.get('attachments')
                                            has_attachments = attachments and attachments != 'null' and attachments != '[]'
                                            
                                            if has_attachments:
                                                try:
                                                    att_data = json.loads(attachments) if isinstance(attachments, str) else attachments
                                                    if att_data and len(att_data) > 0:
                                                        # List each attachment with details
                                                        att_list = []
                                                        for a in att_data:
                                                            if isinstance(a, dict):
                                                                content_type = a.get('content_type', '')
                                                                filename = a.get('filename', '')
                                                                if content_type:
                                                                    att_list.append(content_type)
                                                                elif filename:
                                                                    att_list.append(filename)
                                                                else:
                                                                    att_list.append('attachment')
                                                        att_str = ', '.join(att_list[:5])  # Show up to 5 attachments
                                                        if len(att_data) > 5:
                                                            att_str += f" (+{len(att_data) - 5} more)"
                                                        media_label = f"[Media: {att_str}]"
                                                    else:
                                                        media_label = "[Media]"
                                                except:
                                                    media_label = "[Media]"
                                            else:
                                                media_label = "[Media]"
                                            
                                            # Show attachments as separate lines
                                            context_parts.append(
                                                f"    Message {msg_idx} [{time_str}]{deleted_indicator} {from_participant}: {media_label}"
                                            )
                                            
                                            if has_attachments:
                                                try:
                                                    att_data = json.loads(attachments) if isinstance(attachments, str) else attachments
                                                    if att_data and isinstance(att_data, list):
                                                        for att in att_data[:10]:  # Show up to 10 attachments
                                                            if isinstance(att, dict):
                                                                content_type = att.get('content_type', '')
                                                                filename = att.get('filename', '')
                                                                if content_type:
                                                                    context_parts.append(f"      - Attachment: {content_type}")
                                                                elif filename:
                                                                    context_parts.append(f"      - Attachment: {filename}")
                                                                else:
                                                                    context_parts.append(f"      - Attachment: [Unknown]")
                                                except:
                                                    pass
                                            
                                            if text_content:
                                                context_parts.append(f"      Text: {text_content[:content_limit]}{'...' if len(text_content) > content_limit else ''}")
                                    
                                        elif message_type == 'system':
                                            if text_content:
                                                context_parts.append(
                                                    f"    Message {msg_idx} [{time_str}]{deleted_indicator} [System Notification]: {text_content[:content_limit]}{'...' if len(text_content) > content_limit else ''}"
                                                )
                                            else:
                                                context_parts.append(
                                                    f"    Message {msg_idx} [{time_str}]{deleted_indicator} [System Notification]: [System notification]"
                                                )
                                        else:
                                            # Unknown type - fallback
                                            if text_content and text_content.strip():
                                                context_parts.append(
                                                    f"    Message {msg_idx} [{time_str}]{deleted_indicator} {from_participant}: [{message_type.title()}] {text_content[:content_limit]}{'...' if len(text_content) > content_limit else ''}"
                                                )
                                            else:
                                                context_parts.append(
                                                    f"    Message {msg_idx} [{time_str}]{deleted_indicator} {from_participant}: [{message_type.title()} message]"
                                                )
                                    
                                    if len(chat_msgs) > msg_display_limit:
                                        context_parts.append(f"    ... and {len(chat_msgs) - msg_display_limit} more messages")
                            finally:
                                conn_msg.close()

                # Show explicit no-data blocks for requested platforms that returned no chat rows.
                if platform_filters:
                    present_platforms = {str(p).strip().lower() for p in chats_by_platform.keys()}
                    for requested in platform_filters:
                        req_l = str(requested or '').strip().lower()
                        if req_l and req_l not in present_platforms:
                            context_parts.append(f"\n=== PLATFORM: {requested} ===")
                            context_parts.append("Total Chats: 0 | Total Messages: 0")
                            context_parts.append("No chats found for this platform in the current scope.")
            else:
                # Check if chats exist in database
                conn = self.get_connection()
                try:
                    cursor = conn.cursor()
                    
                    # Apply platform filter if specified
                    if platform_filter:
                        cursor.execute("""
                            SELECT COUNT(*) FROM chats 
                            WHERE platform LIKE ? OR LOWER(platform) LIKE ?
                        """, (f"%{platform_filter}%", f"%{platform_filter.lower()}%"))
                        total_chats = cursor.fetchone()[0]
                        if total_chats > 0:
                            context_parts.append(f"\n=== CHATS ===")
                            context_parts.append(f"Total {platform_filter} chats in database: {total_chats}")
                            context_parts.append(f"No chats matched the search query. Use 'list all chats' to see all {total_chats} {platform_filter} chats.")
                        else:
                            context_parts.append(f"\n=== CHATS ===")
                            context_parts.append(f"No {platform_filter} chats found in database.")
                    else:
                        cursor.execute("SELECT COUNT(*) FROM chats")
                        total_chats = cursor.fetchone()[0]
                        if total_chats > 0:
                            context_parts.append(f"\n=== CHATS ===")
                            context_parts.append(f"Total chats in database: {total_chats}")
                            context_parts.append(f"No chats matched the search query. Use 'list all chats' to see all {total_chats} chats.")
                        else:
                            context_parts.append(f"\n=== CHATS ===")
                            context_parts.append("No chats found in database.")
                finally:
                    conn.close()
        
        # Chat Messages - use intent analysis (app-layer chat_messages table)
        _plat_chat_apps = _platform_rows_in_chat_messages_table(
            intent["entities"].get("platforms") or []
        )
        is_chat_message_query = ('messages' in intent['data_types'] and 'chats' in intent['data_types']) or \
                               any(phrase in query_lower for phrase in [
                                   'chat message', 'chat messages', 'group message', 'group messages',
                                   'thread message', 'thread messages', 'conversation message',
                                   'whatsapp message', 'telegram message', 'messenger message',
                                   'group chat message', 'group chat messages', 'associated with',
                                   'pull', 'show', 'get', 'text messages', 'text message'
                               ]) or \
                               any(phrase in query_lower for phrase in [
                                   'messages from', 'messages to', 'chats with', 'chat with',
                                   'messages associated', 'chats associated'
                               ]) or (
                                   'messages' in intent['data_types'] and _plat_chat_apps
                               )
        
        if is_chat_message_query and _scope_msgs:
            # Multi-platform aware message extraction.
            platform_filters = list(intent['entities'].get('platforms') or [])
            if not platform_filters and evidence_scope.platforms:
                platform_filters = list(evidence_scope.platforms)
            if platform_filters:
                logger.info(f"🔍 Platform filters for messages: {platform_filters}")

            # Detect if this is a platform-only query
            is_platform_only = bool(platform_filters) and any(phrase in query_lower for phrase in [
                'pull messages from', 'get messages from', 'show messages from',
                'messages from', 'pull from', 'get from'
            ])
            if platform_filters and not is_platform_only:
                if re.search(
                    r"\b(analyze|analysis|insights?|summarize|summarise|examine|review|interpret|explain|analzye|nalzye|anaylze|analize|anlyze|analsis)\b",
                    query_lower,
                ) and re.search(r"\b(messages?|chats?|conversations?)\b", query_lower):
                    is_platform_only = True

            chat_messages = []
            if platform_filters:
                per_platform_limit = max_items
                if is_pattern_analysis:
                    per_platform_limit = max_items * 10
                elif is_platform_only:
                    per_platform_limit = max_items * 5
                for pf in platform_filters:
                    rows = self.query_chat_messages(
                        "list all" if is_pattern_analysis else query,
                        limit=per_platform_limit,
                        platform_filter=pf,
                    )
                    chat_messages.extend(rows or [])
            else:
                if is_pattern_analysis:
                    chat_messages = self.query_chat_messages("list all", limit=max_items * 10, platform_filter=None)
                elif is_platform_only:
                    chat_messages = self.query_chat_messages(query, limit=max_items * 5, platform_filter=None)
                else:
                    chat_messages = self.query_chat_messages(query, limit=max_items, platform_filter=None)
            if chat_messages:
                # De-duplicate by row id / stable content key.
                seen_msg_keys = set()
                deduped_msgs = []
                for m in chat_messages:
                    mk = (
                        m.get('id'),
                        m.get('platform'),
                        m.get('chat_id'),
                        m.get('chat_name'),
                        m.get('timestamp'),
                        m.get('from_participant'),
                        m.get('to_participant'),
                        m.get('text_content'),
                    )
                    if mk in seen_msg_keys:
                        continue
                    seen_msg_keys.add(mk)
                    deduped_msgs.append(m)
                chat_messages = deduped_msgs

                # Group messages by chat for better organization
                messages_by_chat = {}
                for msg in chat_messages:
                    chat_id = msg.get('chat_id', '') or msg.get('chat_name', 'Unknown')
                    chat_name = msg.get('chat_name', '') or chat_id
                    platform = msg.get('platform', 'Unknown')
                    chat_key = f"{platform}::{chat_name}"
                    
                    if chat_key not in messages_by_chat:
                        messages_by_chat[chat_key] = {
                            'chat_name': chat_name,
                            'platform': platform,
                            'messages': []
                        }
                    messages_by_chat[chat_key]['messages'].append(msg)
                
                context_parts.append(f"\n=== CHAT MESSAGES (Showing {len(chat_messages)} message(s)) ===")
                
                for chat_key, chat_data in messages_by_chat.items():
                    chat_name = chat_data['chat_name']
                    platform = chat_data['platform']
                    msgs = chat_data['messages']
                    
                    context_parts.append(f"\n--- Chat: {chat_name} (Platform: {platform}) ---")
                    
                    # Sort messages chronologically
                    msgs_sorted = sorted(msgs, key=lambda m: m.get('timestamp', '') or '')
                    
                    for msg_idx, msg in enumerate(msgs_sorted, 1):
                        timestamp = msg.get('timestamp', '') or msg.get('timestamp_formatted', '') or 'N/A'
                        if timestamp and timestamp != 'N/A' and '[YYYY' not in timestamp:
                            time_str = timestamp
                        else:
                            time_str = "Time: Not available"
                        
                        text_content = msg.get('text_content', '') or ''
                        message_type = msg.get('message_type', 'unknown') or 'unknown'
                        is_deleted = msg.get('is_deleted', 0) == 1
                        from_participant = msg.get('from_participant', 'Unknown')
                        to_participant = msg.get('to_participant', 'Unknown')
                        deleted_indicator = " [DELETED]" if is_deleted else ""
                        
                        # Format based on message type
                        if message_type == 'text':
                            if text_content:
                                context_parts.append(
                                    f"  Message {msg_idx} [{time_str}]{deleted_indicator} From: {from_participant} | To: {to_participant} | Content: {text_content[:300]}{'...' if len(text_content) > 300 else ''}"
                                )
                            else:
                                context_parts.append(
                                    f"  Message {msg_idx} [{time_str}]{deleted_indicator} From: {from_participant} | To: {to_participant} | [Text message - no content]"
                                )
                        elif message_type == 'location':
                            location_text = (text_content[:200] if text_content else '') or ''
                            context_parts.append(
                                f"  Message {msg_idx} [{time_str}]{deleted_indicator} From: {from_participant} | To: {to_participant} | [Location Share] {location_text}"
                            )
                        elif message_type == 'media':
                            attachments = msg.get('attachments')
                            has_attachments = attachments and attachments != 'null' and attachments != '[]'
                            if has_attachments:
                                try:
                                    att_data = json.loads(attachments) if isinstance(attachments, str) else attachments
                                    if att_data and len(att_data) > 0:
                                        att_list = []
                                        for a in att_data[:3]:
                                            if isinstance(a, dict):
                                                content_type = a.get('content_type', '')
                                                filename = a.get('filename', '')
                                                if content_type:
                                                    att_list.append(content_type)
                                                elif filename:
                                                    att_list.append(filename)
                                        att_str = ', '.join(att_list) if att_list else 'media'
                                        context_parts.append(
                                            f"  Message {msg_idx} [{time_str}]{deleted_indicator} From: {from_participant} | To: {to_participant} | [Media: {att_str}]"
                                        )
                                    else:
                                        context_parts.append(
                                            f"  Message {msg_idx} [{time_str}]{deleted_indicator} From: {from_participant} | To: {to_participant} | [Media]"
                                        )
                                except:
                                    context_parts.append(
                                        f"  Message {msg_idx} [{time_str}]{deleted_indicator} From: {from_participant} | To: {to_participant} | [Media]"
                                    )
                            else:
                                context_parts.append(
                                    f"  Message {msg_idx} [{time_str}]{deleted_indicator} From: {from_participant} | To: {to_participant} | [Media]"
                                )
                            if text_content:
                                text_preview = text_content[:200] if text_content else ''
                                context_parts.append(f"    Text: {text_preview}{'...' if len(text_content) > 200 else ''}")
                        elif message_type == 'system':
                            context_parts.append(
                                f"  Message {msg_idx} [{time_str}]{deleted_indicator} [System Notification]: {text_content[:300] if text_content else '[System notification]'}"
                            )
                        else:
                            other_text = (text_content[:200] if text_content else '') or ''
                            context_parts.append(
                                f"  Message {msg_idx} [{time_str}]{deleted_indicator} From: {from_participant} | To: {to_participant} | [{message_type.title()}] {other_text}"
                            )
            else:
                # Check if chat messages exist in database
                conn = self.get_connection()
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM chat_messages")
                    total_messages = cursor.fetchone()[0]
                    if total_messages > 0:
                        context_parts.append(f"\n=== CHAT MESSAGES ===")
                        context_parts.append(f"Total chat messages in database: {total_messages}")
                        context_parts.append(f"No chat messages matched the search query. Try searching by contact name or chat name.")
                    else:
                        context_parts.append(f"\n=== CHAT MESSAGES ===")
                        context_parts.append("No chat messages found in database.")
                finally:
                    conn.close()
        
        # Files - use intent analysis
        explicit_file_pull = any(kw in query_lower for kw in (
            'file', 'files', 'list files', 'show files', 'get files', 'pull files',
            'media file', 'attachment file', 'attachments'
        ))
        suppress_noisy_files = (
            evidence_scope.mode == "cross_domain_scoped"
            and intent.get('intent_type') in ('analyze', 'relationship', 'compare', 'statistical')
            and (
                'chats' in (intent.get('data_types') or [])
                or 'locations' in (intent.get('data_types') or [])
                or 'locations' in (evidence_scope.effective_domains() or evidence_scope.domains)
            )
            and not explicit_file_pull
        )
        if suppress_noisy_files:
            context_parts.append(
                "\n=== FILES ===\n"
                "Skipped broad file dump in analysis scope to avoid irrelevant system artifacts. "
                "Ask explicitly for files/attachments to include media file listings."
            )
        elif 'files' in intent['data_types'] and evidence_scope.allows_domain("media"):
            files = self.query_files(query, limit=max_items)
            if files:
                context_parts.append(f"\n=== FILES (Showing {len(files)} file(s)) ===")
                for file in files:
                    context_parts.append(
                        f"File: {file.get('filename', 'Unknown')} | "
                        f"Type: {file.get('file_type', 'Unknown')} | "
                        f"Size: {file.get('size', 0)} bytes | "
                        f"Path: {file.get('file_path', 'N/A')} | "
                        f"Created: {file.get('created_time', 'N/A')}"
                    )
            else:
                # Check if files exist in database
                conn = self.get_connection()
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM files")
                    total_files = cursor.fetchone()[0]
                    if total_files > 0:
                        context_parts.append(f"\n=== FILES ===")
                        context_parts.append(f"Total files in database: {total_files}")
                        context_parts.append(f"No files matched the search query. Use 'list all files' to see all {total_files} files.")
                    else:
                        context_parts.append(f"\n=== FILES ===")
                        context_parts.append("No files found in database.")
                finally:
                    conn.close()
        
        # International phone number query detection (must be before contacts)
        if is_international_phone_query and evidence_scope.allows_domain("contacts"):
            conn = self.get_connection()
            try:
                cursor = conn.cursor()
                
                # Extract international phone numbers from contacts (those starting with +)
                cursor.execute("""
                    SELECT DISTINCT phone, name 
                    FROM contacts 
                    WHERE phone LIKE '+%' AND phone IS NOT NULL AND phone != ''
                    ORDER BY phone
                """)
                international_contacts = cursor.fetchall()
                
                # Extract international phone numbers from call logs
                cursor.execute("""
                    SELECT DISTINCT from_number as phone, 'Call Log (From)' as name
                    FROM call_logs 
                    WHERE from_number LIKE '+%' AND from_number IS NOT NULL AND from_number != ''
                    UNION
                    SELECT DISTINCT to_number as phone, 'Call Log (To)' as name
                    FROM call_logs 
                    WHERE to_number LIKE '+%' AND to_number IS NOT NULL AND to_number != ''
                    ORDER BY phone
                """)
                international_calls = cursor.fetchall()
                
                # Combine and deduplicate
                all_international = {}
                for phone, name in international_contacts + international_calls:
                    phone_clean = phone.strip() if phone else ''
                    if phone_clean and phone_clean.startswith('+'):
                        if phone_clean not in all_international:
                            all_international[phone_clean] = name if name else 'Unknown'
                
                if all_international:
                    context_parts.append(f"\n=== INTERNATIONAL PHONE NUMBERS (Found {len(all_international)} unique number(s)) ===")
                    for i, (phone, name) in enumerate(sorted(all_international.items()), 1):
                        context_parts.append(f"{i}. {phone} - {name}")
                else:
                    context_parts.append("\n=== INTERNATIONAL PHONE NUMBERS ===")
                    context_parts.append("No international phone numbers found in the data.")
                    context_parts.append("(International numbers are those starting with '+' country code)")
            finally:
                conn.close()
        
        # Contacts - use intent analysis
        is_communication_query = 'messages' in intent['data_types'] or 'chats' in intent['data_types'] or \
                                any(word in query_lower for word in ['communication', 'communications', 'pattern', 'patterns', 
                                                                     'suspicious', 'activity', 'interaction'])
        
        is_contact_query = ('contacts' in intent['data_types'] or 
                           intent['question_type'] == 'who' or
                           phone_numbers_in_query or 
                           intent['entities']['person_names']) and not is_communication_query and not is_international_phone_query
        
        if is_contact_query and evidence_scope.allows_domain("contacts"):
            # Check if user wants ALL contacts (not a search)
            wants_all_contacts = any(word in query_lower for word in ['list', 'all', 'every', 'entire', 'complete', 'full', '72', '144'])
            
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Get total count first
            cursor.execute("SELECT COUNT(*) FROM contacts")
            total_count = cursor.fetchone()[0]
            
            if wants_all_contacts or total_count <= 200:  # If asking for list or reasonable number, get all
                # Get ALL contacts (no limit for reasonable sizes, or up to 500 for large datasets)
                limit = min(total_count, 500) if total_count > 200 else total_count
                cursor.execute("SELECT * FROM contacts ORDER BY name LIMIT ?", (limit,))
                contacts = [dict(row) for row in cursor.fetchall()]
            else:
                # Search-based query
                contacts = self.query_contacts(query, limit=max_items)
            
            if contacts:
                context_parts.append(f"\n=== CONTACTS (Showing {len(contacts)} of {total_count} total) ===")
                for i, contact in enumerate(contacts, 1):
                    name = contact.get('name', 'Unknown')
                    phone = contact.get('phone', 'N/A')
                    email = contact.get('email', '')
                    contact_str = f"{i}. {name}: {phone}"
                    if email:
                        contact_str += f" ({email})"
                    context_parts.append(contact_str)
                
                if len(contacts) < total_count:
                    context_parts.append(f"\n... and {total_count - len(contacts)} more contacts (total: {total_count})")
                
                # CROSS-TABLE SEARCH: If a specific person is found, also search their communications
                # Extract person names from found contacts
                person_names = [c.get('name', '') for c in contacts if c.get('name')]
                
                # Also check if query contains phone numbers that might be contacts
                if phone_numbers_in_query:
                    # Search for contacts with these phone numbers
                    for phone in phone_numbers_in_query:
                        phone_contacts = [c for c in contacts if phone in str(c.get('phone', ''))]
                        if phone_contacts:
                            person_names.extend([c.get('name', '') for c in phone_contacts if c.get('name')])
                
                # Check if this is an analysis query (most active, statistics, etc.)
                is_analysis_query = any(phrase in query_lower for phrase in [
                    'most active', 'most calls', 'most contacted', 'most contact', 'top contact', 'top contacts',
                    'which contacts', 'statistics', 'analyze', 'analysis', 'frequency', 'count', 'how many',
                    'who are', 'who is', 'active contacts', 'frequent', 'often', 'regularly',
                    'device owner', 'owner', 'who owns', 'belongs to', 'device user', 'primary user'
                ])
                
                # For analysis queries, get all calls and messages to analyze (whole-case stats — overview only)
                if is_analysis_query and evidence_scope.mode == "case_overview":
                    # Get all calls for analysis
                    all_calls = self.query_calls("", limit=500)
                    if all_calls:
                        # Count calls per contact
                        call_counts = {}
                        for call in all_calls:
                            from_num = call.get('from_number', '')
                            to_num = call.get('to_number', '')
                            if from_num:
                                call_counts[from_num] = call_counts.get(from_num, 0) + 1
                            if to_num:
                                call_counts[to_num] = call_counts.get(to_num, 0) + 1
                        
                        # Get all messages for analysis
                        all_messages = self.query_messages("", limit=500)
                        message_counts = {}
                        for msg in all_messages:
                            from_num = msg.get('from_number', '')
                            to_num = msg.get('to_number', '')
                            if from_num:
                                message_counts[from_num] = message_counts.get(from_num, 0) + 1
                            if to_num:
                                message_counts[to_num] = message_counts.get(to_num, 0) + 1
                        
                        # Also get chat messages for more comprehensive analysis
                        all_chat_messages = self.query_chat_messages("", limit=1000)
                        chat_message_counts = {}
                        for msg in all_chat_messages:
                            from_part = msg.get('from_participant', '')
                            to_part = msg.get('to_participant', '')
                            if from_part:
                                chat_message_counts[from_part] = chat_message_counts.get(from_part, 0) + 1
                            if to_part:
                                chat_message_counts[to_part] = chat_message_counts.get(to_part, 0) + 1
                        
                        # Combine and rank contacts by activity (including chat messages)
                        activity_scores = {}
                        for contact in contacts:
                            phone = str(contact.get('phone', ''))
                            name = contact.get('name', 'Unknown')
                            call_count = call_counts.get(phone, 0)
                            msg_count = message_counts.get(phone, 0)
                            chat_count = chat_message_counts.get(name, 0)
                            total_activity = call_count + msg_count + chat_count
                            if total_activity > 0:
                                activity_scores[name] = {
                                    'calls': call_count,
                                    'messages': msg_count,
                                    'chat_messages': chat_count,
                                    'total': total_activity,
                                    'phone': phone
                                }
                        
                        # Also include chat participants that aren't in contacts
                        for name, chat_count in chat_message_counts.items():
                            if name not in activity_scores and chat_count > 0:
                                # Check if this name matches any contact
                                matching_contact = next((c for c in contacts if c.get('name', '').lower() == name.lower()), None)
                                phone = matching_contact.get('phone', '') if matching_contact else 'N/A'
                                activity_scores[name] = {
                                    'calls': call_counts.get(phone, 0),
                                    'messages': message_counts.get(phone, 0),
                                    'chat_messages': chat_count,
                                    'total': chat_count,
                                    'phone': phone
                                }
                        
                        if activity_scores:
                            context_parts.append(f"\n=== MOST ACTIVE CONTACTS (by communication frequency) ===")
                            sorted_contacts = sorted(activity_scores.items(), key=lambda x: x[1]['total'], reverse=True)
                            
                            # Extract "top N" from query if specified
                            top_n = 20  # Default
                            if 'top' in query_lower:
                                top_match = re.search(r'top\s+(\d+)', query_lower)
                                if top_match:
                                    top_n = int(top_match.group(1))
                            
                            for i, (name, stats) in enumerate(sorted_contacts[:top_n], 1):
                                phone_str = f" ({stats['phone']})" if stats['phone'] != 'N/A' and stats['phone'] else ""
                                context_parts.append(
                                    f"{i}. {name}{phone_str}: {stats['total']} total interactions "
                                    f"({stats['calls']} calls, {stats['messages']} SMS/MMS, {stats.get('chat_messages', 0)} chat messages)"
                                )
                
                # Check if query mentions a specific person name OR phone number
                for person_name in person_names:
                    if person_name.lower() in query_lower or any(word in person_name.lower() for word in query_lower.split() if len(word) > 3):
                        # Search messages involving this person
                        person_messages = (
                            self.query_messages(person_name, limit=20)
                            if evidence_scope.allows_domain("messages")
                            else []
                        )
                        if person_messages:
                            context_parts.append(f"\n=== MESSAGES INVOLVING {person_name} (Showing {len(person_messages)} message(s)) ===")
                            for msg in person_messages[:10]:  # Limit to 10 for display
                                timestamp = msg.get('timestamp', '') or msg.get('timestamp_formatted', '') or 'N/A'
                                if timestamp and timestamp != 'N/A' and '[YYYY' not in timestamp:
                                    time_str = f"Time: {timestamp}"
                                else:
                                    time_str = "Time: Not available"
                                context_parts.append(
                                    f"From: {msg.get('from_number', 'Unknown')} | "
                                    f"To: {msg.get('to_number', 'Unknown')} | "
                                    f"{time_str} | "
                                    f"Source: {msg.get('source', 'Unknown')}\n"
                                    f"Content: {(msg.get('text_content') or 'N/A')[:150] if msg.get('text_content') else 'N/A'}"
                                )
                        
                        # Search calls involving this person
                        person_calls = (
                            self.query_calls(person_name, limit=20)
                            if evidence_scope.allows_domain("calls")
                            else []
                        )
                        if person_calls:
                            context_parts.append(f"\n=== CALLS INVOLVING {person_name} (Showing {len(person_calls)} call(s)) ===")
                            for call in person_calls[:10]:  # Limit to 10 for display
                                timestamp = call.get('timestamp', '') or call.get('timestamp_formatted', '') or 'N/A'
                                if timestamp and timestamp != 'N/A' and '[YYYY' not in timestamp:
                                    time_str = f"Time: {timestamp}"
                                else:
                                    time_str = "Time: Not available"
                                context_parts.append(
                                    f"From: {call.get('from_number', 'Unknown')} | "
                                    f"To: {call.get('to_number', 'Unknown')} | "
                                    f"{time_str} | "
                                    f"Duration: {call.get('duration', 0)}s | "
                                    f"Type: {call.get('call_type', 'Unknown')}"
                                )
                        
                        # Search chats involving this person (third-party chat layer)
                        person_chats = (
                            self.query_chats(person_name, limit=50)
                            if evidence_scope.allows_domain("chats")
                            else []
                        )
                        if person_chats:
                            context_parts.append(f"\n=== CHATS INVOLVING {person_name} (Showing {len(person_chats)} chat(s)) ===")
                            for chat in person_chats[:20]:  # Show more chats
                                chat_name = chat.get('chat_name', 'Unknown')
                                platform = chat.get('platform', 'Unknown')
                                participants = chat.get('participants', [])
                                if isinstance(participants, str):
                                    try:
                                        participants = json.loads(participants)
                                    except:
                                        participants = []
                                participants_str = ', '.join(participants) if participants else 'N/A'
                                
                                # Get message count for this chat
                                conn = self.get_connection()
                                cursor = conn.cursor()
                                cursor.execute("""
                                    SELECT COUNT(*) FROM chat_messages 
                                    WHERE (
                                        (chat_id = ? AND chat_id IS NOT NULL AND chat_id != '')
                                        OR 
                                        (chat_name = ? AND chat_name IS NOT NULL AND chat_name != '')
                                    )
                                """, (chat.get('chat_id', ''), chat_name))
                                msg_count = cursor.fetchone()[0]
                                conn.close()
                                
                                context_parts.append(
                                    f"Chat: {chat_name} | Platform: {platform} | "
                                    f"Participants: {participants_str} | Messages: {msg_count}"
                                )
                            
                            # Also get chat messages for platform analysis
                            person_chat_messages = (
                                self.query_chat_messages(person_name, limit=500)
                                if evidence_scope.allows_domain("messages")
                                else []
                            )
                            if person_chat_messages:
                                context_includes_chat_app_messages = True
                                # Analyze platform usage
                                platform_counts = {}
                                for msg in person_chat_messages:
                                    platform = msg.get('platform', 'Unknown')
                                    platform_counts[platform] = platform_counts.get(platform, 0) + 1
                                
                                if platform_counts:
                                    context_parts.append(f"\n=== PLATFORM USAGE FOR {person_name} ===")
                                    sorted_platforms = sorted(platform_counts.items(), key=lambda x: x[1], reverse=True)
                                    for platform, count in sorted_platforms:
                                        context_parts.append(f"  • {platform}: {count} messages")
                                
                                # Show sample messages
                                context_parts.append(f"\n=== SAMPLE CHAT MESSAGES INVOLVING {person_name} (Showing {min(10, len(person_chat_messages))} of {len(person_chat_messages)} total) ===")
                                for msg in person_chat_messages[:10]:
                                    timestamp = msg.get('timestamp', '') or 'N/A'
                                    from_part = msg.get('from_participant', 'Unknown')
                                    text = (msg.get('text_content', '') or '')[:100]
                                    platform = msg.get('platform', 'Unknown')
                                    context_parts.append(
                                        f"[{timestamp}] {from_part} ({platform}): {text}..."
                                    )
                        break  # Only process first matching person
            else:
                # Still show contact count even if no matches
                if total_count > 0:
                    context_parts.append(f"\n=== CONTACTS ===")
                    context_parts.append(f"Total contacts in database: {total_count}")
                    
                    # CROSS-TABLE SEARCH: If query contains phone number, search communications even if contact not found
                    if phone_numbers_in_query:
                        for phone in phone_numbers_in_query:
                            # Search messages with this phone number
                            phone_messages = self.query_messages(phone, limit=20)
                            if phone_messages:
                                context_parts.append(f"\n=== MESSAGES INVOLVING {phone} (Showing {len(phone_messages)} message(s)) ===")
                                for msg in phone_messages[:10]:
                                    timestamp = msg.get('timestamp', '') or msg.get('timestamp_formatted', '') or 'N/A'
                                    if timestamp and timestamp != 'N/A' and '[YYYY' not in timestamp:
                                        time_str = f"Time: {timestamp}"
                                    else:
                                        time_str = "Time: Not available"
                                    context_parts.append(
                                        f"From: {msg.get('from_number', 'Unknown')} | "
                                        f"To: {msg.get('to_number', 'Unknown')} | "
                                        f"{time_str} | "
                                        f"Source: {msg.get('source', 'Unknown')}\n"
                                        f"Content: {msg.get('text_content', 'N/A')[:150]}"
                                    )
                            
                            # Search calls with this phone number
                            phone_calls = self.query_calls(phone, limit=20)
                            if phone_calls:
                                context_parts.append(f"\n=== CALLS INVOLVING {phone} (Showing {len(phone_calls)} call(s)) ===")
                                for call in phone_calls[:10]:
                                    timestamp = call.get('timestamp', '') or call.get('timestamp_formatted', '') or 'N/A'
                                    if timestamp and timestamp != 'N/A' and '[YYYY' not in timestamp:
                                        time_str = f"Time: {timestamp}"
                                    else:
                                        time_str = "Time: Not available"
                                    context_parts.append(
                                        f"From: {call.get('from_number', 'Unknown')} | "
                                        f"To: {call.get('to_number', 'Unknown')} | "
                                        f"{time_str} | "
                                        f"Duration: {call.get('duration', 0)}s | "
                                        f"Type: {call.get('call_type', 'Unknown')}"
                                    )
                    
                    context_parts.append(f"No contacts matched the search query. Use 'list all contacts' to see all {total_count} contacts.")
                else:
                    context_parts.append(f"\n=== CONTACTS ===")
                    context_parts.append("No contacts found in database.")
            
            conn.close()
        
        # Handle communication queries with person names (FIX: "what communications involve Josh Hickman")
        # This handles queries like "what communications involve [Person Name]" that are classified as communication queries
        # but need person-specific search
        if is_communication_query and intent['entities']['person_names']:
            person_names_from_query = intent['entities']['person_names']
            logger.info(f"🔍 Communication query with person names detected: {person_names_from_query}")
            
            conn = self.get_connection()
            try:
                cursor = conn.cursor()
                found_contacts = []
                for person_name in person_names_from_query:
                    # Search for contacts matching the person name
                    cursor.execute("""
                        SELECT * FROM contacts 
                        WHERE name LIKE ? OR LOWER(name) LIKE ? OR name = ?
                        LIMIT 10
                    """, (f"%{person_name}%", f"%{person_name.lower()}%", person_name))
                    found_contacts.extend([dict(row) for row in cursor.fetchall()])
                
                # Use found contacts or query person names directly
                person_names_to_search = list(set([c.get('name', '') for c in found_contacts if c.get('name')]))
                if not person_names_to_search:
                    person_names_to_search = person_names_from_query
                
                # One logical person → one block (avoid duplicate "Name" vs "Name.jpg" sections)
                person_names_to_search = _dedupe_person_names(person_names_to_search)
                
                logger.info(f"🔍 Searching communications for: {person_names_to_search}")
                
                # Search communications for each person
                for person_name in person_names_to_search:
                    if not person_name:
                        continue
                    
                    person_name_lower = person_name.lower()
                    found_any = False
                    
                    # Search messages involving this person
                    person_messages = self.query_messages(person_name, limit=50)
                    if person_messages:
                        found_any = True
                        context_parts.append(f"\n=== MESSAGES INVOLVING {person_name} (Showing {len(person_messages)} message(s)) ===")
                        for msg in person_messages[:20]:
                            timestamp = msg.get('timestamp', '') or msg.get('timestamp_formatted', '') or 'N/A'
                            if timestamp and timestamp != 'N/A' and '[YYYY' not in timestamp:
                                time_str = f"Time: {timestamp}"
                            else:
                                time_str = "Time: Not available"
                            text_content = msg.get('text_content', '') or ''
                            context_parts.append(
                                f"From: {msg.get('from_number', 'Unknown')} | "
                                f"To: {msg.get('to_number', 'Unknown')} | "
                                f"Source: {msg.get('source', 'Unknown')} | "
                                f"{time_str}\n"
                                f"Content: {text_content[:200]}"
                            )
                    
                    # Search calls involving this person
                    person_calls = self.query_calls(person_name, limit=50)
                    if person_calls:
                        found_any = True
                        context_parts.append(f"\n=== CALLS INVOLVING {person_name} (Showing {len(person_calls)} call(s)) ===")
                        for call in person_calls[:20]:
                            timestamp = call.get('timestamp', '') or call.get('timestamp_formatted', '') or 'N/A'
                            if timestamp and timestamp != 'N/A' and '[YYYY' not in timestamp:
                                time_str = f"Time: {timestamp}"
                            else:
                                time_str = "Time: Not available"
                            context_parts.append(
                                f"From: {call.get('from_number', 'Unknown')} | "
                                f"To: {call.get('to_number', 'Unknown')} | "
                                f"{time_str} | "
                                f"Duration: {call.get('duration', 0)}s | "
                                f"Type: {call.get('call_type', 'Unknown')}"
                            )
                    
                    # Search chats involving this person
                    person_chats = self.query_chats(person_name, limit=50)
                    if person_chats:
                        found_any = True
                        context_parts.append(f"\n=== CHATS INVOLVING {person_name} (Showing {len(person_chats)} chat(s)) ===")
                        for chat in person_chats[:20]:
                            chat_name = chat.get('chat_name', 'Unknown')
                            platform = chat.get('platform', 'Unknown')
                            participants = chat.get('participants', [])
                            if isinstance(participants, str):
                                try:
                                    participants = json.loads(participants)
                                except:
                                    participants = []
                            participants_str = ', '.join(participants) if participants else 'N/A'
                            context_parts.append(
                                f"Chat: {chat_name} | Platform: {platform} | Participants: {participants_str}"
                            )
                    
                    # Search chat messages involving this person
                    person_chat_messages = self.query_chat_messages(person_name, limit=500)
                    if person_chat_messages:
                        found_any = True
                        context_includes_chat_app_messages = True
                        # Analyze platform usage
                        platform_counts = {}
                        for msg in person_chat_messages:
                            platform = msg.get('platform', 'Unknown')
                            platform_counts[platform] = platform_counts.get(platform, 0) + 1
                        
                        if platform_counts:
                            context_parts.append(f"\n=== PLATFORM USAGE FOR {person_name} ===")
                            sorted_platforms = sorted(platform_counts.items(), key=lambda x: x[1], reverse=True)
                            for platform, count in sorted_platforms:
                                context_parts.append(f"  • {platform}: {count} messages")
                        
                        # Show sample messages
                        context_parts.append(f"\n=== SAMPLE CHAT MESSAGES INVOLVING {person_name} (Showing {min(20, len(person_chat_messages))} of {len(person_chat_messages)} total) ===")
                        for msg in person_chat_messages[:20]:
                            timestamp = msg.get('timestamp', '') or 'N/A'
                            from_part = msg.get('from_participant', 'Unknown')
                            to_part = msg.get('to_participant', 'Unknown')
                            text_content = msg.get('text_content', '') or ''
                            platform = msg.get('platform', 'Unknown')
                            msg_type = msg.get('message_type', 'text')
                            context_parts.append(
                                f"[{timestamp}] {from_part} → {to_part} ({platform}, {msg_type}): {text_content[:200]}"
                            )
                    
                    if not found_any:
                        logger.warning(f"⚠️ No communications found for person: {person_name}")
            finally:
                conn.close()
        
        # Messages - native/SMS `messages` table only (not WhatsApp/Telegram/etc.)
        is_message_query = (
            (
                'messages' in intent['data_types']
                or (
                    intent['entities']['platforms']
                    and 'chats' not in intent['data_types']
                )
            )
            and not _platform_rows_in_chat_messages_table(intent['entities'].get('platforms') or [])
        )
        
        if is_message_query and evidence_scope.allows_domain("messages"):
            # For "list" queries or pattern analysis, increase limit significantly
            wants_all_messages = any(word in query_lower for word in ['list', 'all', 'every', 'entire', 'complete', 'full', 'pattern', 'patterns', 'analysis'])
            # For pattern analysis, get ALL messages (much higher limit)
            message_limit = max_items * 10 if (wants_all_messages or is_pattern_analysis) else max_items
            
            # For pattern analysis, get ALL messages without filtering
            if is_pattern_analysis:
                messages = self.query_messages("list all messages", limit=message_limit)
            else:
                messages = self.query_messages(query, limit=message_limit)
            if messages:
                context_parts.append(f"\n=== MESSAGES (Showing {len(messages)} message(s)) ===")
                for msg in messages:
                    timestamp = msg.get('timestamp', '') or msg.get('timestamp_formatted', '') or 'N/A'
                    # Ensure timestamp is not empty or placeholder
                    if timestamp and timestamp != 'N/A' and '[YYYY' not in timestamp:
                        time_str = f"Time: {timestamp}"
                    else:
                        time_str = "Time: Not available"
                    
                    text_content = msg.get('text_content') or ''
                    text_preview = text_content[:200] if text_content else 'N/A'
                    context_parts.append(
                        f"From: {msg.get('from_number', 'Unknown')} | "
                        f"To: {msg.get('to_number', 'Unknown')} | "
                        f"Source: {msg.get('source', 'Unknown')} | "
                        f"{time_str}\n"
                        f"Content: {text_preview}"
                    )
            else:
                # Native/SMS `messages` table — NOT chat_messages (WhatsApp/Telegram/etc. appear under SAMPLE CHAT MESSAGES above)
                conn = self.get_connection()
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM messages")
                    total_messages = cursor.fetchone()[0]
                    if total_messages > 0:
                        context_parts.append(f"\n=== SMS / NATIVE MESSAGES TABLE (not chat apps) ===")
                        context_parts.append(f"Rows in native/SMS `messages` table: {total_messages}")
                        if context_includes_chat_app_messages:
                            context_parts.append(
                                "No SMS/native rows matched this query text. Third-party chat evidence is already listed above "
                                "under 'SAMPLE CHAT MESSAGES INVOLVING …' / chat sections — do not treat this as 'no communications'."
                            )
                        else:
                            context_parts.append(
                                f"No native/SMS rows matched the search query. Use 'list all messages' to see all {total_messages} SMS rows."
                            )
                    else:
                        context_parts.append(f"\n=== SMS / NATIVE MESSAGES TABLE ===")
                        context_parts.append("No SMS/native messages in database.")
                finally:
                    conn.close()
        
        # Calls - use intent analysis
        is_call_query = 'calls' in intent['data_types']
        
        # Check if this is an analysis query (needs all calls)
        is_analysis_query = intent['intent_type'] in ['analyze', 'statistical'] or \
                           intent['modifiers']['comparison'] == 'most' or \
                           intent['question_type'] == 'how'
        
        # Check if user wants ALL calls
        wants_all_calls = intent['is_comprehensive'] or (intent['intent_type'] == 'list' and is_call_query)
        
        if is_call_query and evidence_scope.allows_domain("calls"):
            # For analysis queries, pattern analysis, or "list all", get all calls (much higher limit)
            call_limit = max_items * 10 if (is_analysis_query or wants_all_calls or is_pattern_analysis) else max_items
            calls = self.query_calls(query, limit=call_limit)
            if calls:
                context_parts.append(f"\n=== CALLS (Showing {len(calls)} call(s)) ===")
                for call in calls:
                    timestamp = call.get('timestamp', '') or call.get('timestamp_formatted', '') or 'N/A'
                    # Ensure timestamp is not empty or placeholder
                    if timestamp and timestamp != 'N/A' and '[YYYY' not in timestamp:
                        time_str = f"Time: {timestamp}"
                    else:
                        time_str = "Time: Not available"
                    
                    context_parts.append(
                        f"From: {call.get('from_number', 'Unknown')} | "
                        f"To: {call.get('to_number', 'Unknown')} | "
                        f"{time_str} | "
                        f"Duration: {call.get('duration', 0)}s | "
                        f"Type: {call.get('call_type', 'Unknown')}"
                    )
            else:
                # Check if calls exist in database at all
                conn = self.get_connection()
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM call_logs")
                    total_calls = cursor.fetchone()[0]
                    if total_calls > 0:
                        context_parts.append(f"\n=== CALLS ===")
                        context_parts.append(f"Total calls in database: {total_calls}")
                        if is_analysis_query or wants_all_calls:
                            # For analysis queries or "list all", return all calls even if search didn't match
                            cursor.execute("SELECT * FROM call_logs ORDER BY timestamp DESC LIMIT ?", (call_limit,))
                            all_calls = [dict(row) for row in cursor.fetchall()]
                            if all_calls:
                                context_parts.append(f"\n=== ALL CALLS (Showing {len(all_calls)} of {total_calls} total) ===")
                                for call in all_calls[:100]:  # Show more for analysis
                                    timestamp = call.get('timestamp', '') or call.get('timestamp_formatted', '') or 'N/A'
                                    if timestamp and timestamp != 'N/A' and '[YYYY' not in timestamp:
                                        time_str = f"Time: {timestamp}"
                                    else:
                                        time_str = "Time: Not available"
                                    context_parts.append(
                                        f"From: {call.get('from_number', 'Unknown')} | "
                                        f"To: {call.get('to_number', 'Unknown')} | "
                                        f"{time_str} | "
                                        f"Duration: {call.get('duration', 0)}s | "
                                        f"Type: {call.get('call_type', 'Unknown')}"
                                    )
                                if len(all_calls) < total_calls:
                                    context_parts.append(f"\n... and {total_calls - len(all_calls)} more calls (total: {total_calls})")
                        else:
                            context_parts.append(f"No calls matched the search query. Use 'list all call logs' to see all {total_calls} calls.")
                    else:
                        context_parts.append(f"\n=== CALLS ===")
                        context_parts.append("No call logs found in database.")
                finally:
                    conn.close()
        
        # Locations - use intent analysis
        if (
            ('locations' in intent['data_types'] or intent['question_type'] == 'where')
            and evidence_scope.allows_domain("locations")
        ):
            conn = self.get_connection()
            try:
                cursor = conn.cursor()
                scoped_platforms = list(intent['entities'].get('platforms') or [])
                if not scoped_platforms and evidence_scope.platforms:
                    scoped_platforms = list(evidence_scope.platforms)

                # For app-layer platforms (WhatsApp/Telegram/etc.), constrain location rows to
                # timestamps seen in chat_messages location events for that same platform.
                # Without this, cross-domain packets (messages+locations) can leak whole-device
                # GPS history unrelated to the requested platform.
                scoped_chat_platforms = [
                    p for p in scoped_platforms
                    if _platform_rows_in_chat_messages_table([p])
                ]
                use_platform_location_projection = bool(scoped_chat_platforms)

                def _location_row_matches_scoped_platforms(loc_row: Dict[str, Any], plats: List[str]) -> bool:
                    if not plats:
                        return True
                    blob = " ".join([
                        str(loc_row.get('source_db', '') or ''),
                        str(loc_row.get('source_table', '') or ''),
                        str(loc_row.get('raw_data', '') or ''),
                    ]).lower()
                    for p in plats:
                        pl = (p or '').strip().lower()
                        if not pl:
                            continue
                        if pl in ('google photos', 'google photo'):
                            if 'google photos' in blob or 'photos' in blob:
                                return True
                        elif pl in ('google maps', 'google map'):
                            if 'google maps' in blob or 'maps' in blob:
                                return True
                        elif pl == 'native messages':
                            if 'native' in blob:
                                return True
                        else:
                            # Generic fallback for app names like snapchat/telegram/whatsapp/line etc.
                            if pl in blob:
                                return True
                    return False

                projected_locations = None
                projected_location_share_events = []
                if use_platform_location_projection:
                    chat_loc_ts = []
                    per_platform_scan = max(max_items * 20, 500)
                    for p in scoped_chat_platforms:
                        cursor.execute(
                            """
                            SELECT timestamp
                            FROM chat_messages
                            WHERE (platform = ? OR LOWER(platform) = LOWER(?))
                              AND LOWER(COALESCE(message_type, '')) = 'location'
                              AND COALESCE(timestamp, '') != ''
                            ORDER BY timestamp DESC
                            LIMIT ?
                            """,
                            (p, p, per_platform_scan),
                        )
                        chat_loc_ts.extend([row[0] for row in cursor.fetchall() if row and row[0]])
                        # Keep chat-level location-share evidence for fallback when coordinate rows are unavailable.
                        cursor.execute(
                            """
                            SELECT timestamp, from_participant, to_participant, text_content, platform
                            FROM chat_messages
                            WHERE (platform = ? OR LOWER(platform) = LOWER(?))
                              AND LOWER(COALESCE(message_type, '')) = 'location'
                              AND COALESCE(timestamp, '') != ''
                            ORDER BY timestamp DESC
                            LIMIT ?
                            """,
                            (p, p, min(max_items * 5, 200)),
                        )
                        for ev in cursor.fetchall():
                            projected_location_share_events.append(dict(ev))

                    def _norm_ts_key(ts: str) -> str:
                        # Normalize to second precision and ignore surrounding [] + TZ suffix
                        # so chat_message and locations formats can be aligned.
                        if not ts:
                            return ""
                        s = str(ts).replace("[", "").replace("]", "").strip()
                        return s[:19] if len(s) >= 19 else s

                    ts_keys = { _norm_ts_key(ts) for ts in chat_loc_ts if _norm_ts_key(ts) }

                    if ts_keys:
                        cursor.execute(
                            """
                            SELECT * FROM locations
                            ORDER BY timestamp DESC
                            LIMIT ?
                            """,
                            (max(max_items * 100, 5000),),
                        )
                        loc_candidates = [dict(row) for row in cursor.fetchall()]
                        projected_locations = [
                            loc
                            for loc in loc_candidates
                            if _norm_ts_key(loc.get('timestamp', '')) in ts_keys
                        ]
                    else:
                        projected_locations = []

                # Also include rows whose source metadata matches explicitly requested platforms.
                # This is essential for non-chat location sources (e.g., Google Photos / Google Maps)
                # and mixed queries that include both chat and non-chat apps.
                source_scoped_locations = None
                if scoped_platforms:
                    cursor.execute(
                        """
                        SELECT * FROM locations
                        ORDER BY timestamp DESC
                        LIMIT ?
                        """,
                        (max(max_items * 100, 5000),),
                    )
                    _all_loc_candidates = [dict(row) for row in cursor.fetchall()]
                    source_scoped_locations = [
                        loc for loc in _all_loc_candidates
                        if _location_row_matches_scoped_platforms(loc, scoped_platforms)
                    ]

                if projected_locations is not None or source_scoped_locations is not None:
                    merged = []
                    seen = set()
                    for bucket in (projected_locations or [], source_scoped_locations or []):
                        for loc in bucket:
                            lk = (
                                loc.get('id'),
                                loc.get('timestamp'),
                                loc.get('latitude'),
                                loc.get('longitude'),
                                loc.get('source_db'),
                                loc.get('source_table'),
                            )
                            if lk in seen:
                                continue
                            seen.add(lk)
                            merged.append(loc)
                    total_locations = len(merged)
                    locations = merged[:max_items]
                else:
                    cursor.execute("SELECT COUNT(*) FROM locations")
                    total_locations = cursor.fetchone()[0]
                
                if total_locations > 0:
                    if projected_locations is None:
                        cursor.execute("""
                            SELECT * FROM locations 
                            ORDER BY timestamp DESC
                            LIMIT ?
                        """, (max_items,))
                        locations = [dict(row) for row in cursor.fetchall()]
                    
                    if locations:
                        context_parts.append(f"\n=== LOCATIONS (Showing {len(locations)} of {total_locations} total) ===")
                        for loc in locations:
                            timestamp = loc.get('timestamp', '') or loc.get('timestamp_formatted', '') or 'N/A'
                            # Ensure timestamp is not empty or placeholder
                            if timestamp and timestamp != 'N/A' and '[YYYY' not in timestamp:
                                time_str = f"Time: {timestamp}"
                            else:
                                time_str = "Time: Not available"
                            
                            context_parts.append(
                                f"Coordinates: ({loc.get('latitude', 'N/A')}, {loc.get('longitude', 'N/A')}) | "
                                f"Address: {loc.get('address', 'N/A')} | "
                                f"{time_str}"
                            )
                        
                        if len(locations) < total_locations:
                            context_parts.append(f"\n... and {total_locations - len(locations)} more locations (total: {total_locations})")
                    else:
                        context_parts.append(f"\n=== LOCATIONS ===")
                        context_parts.append(f"Total locations in database: {total_locations}")
                        context_parts.append(f"No locations matched the search query. Use 'list all locations' to see all {total_locations} locations.")
                else:
                    context_parts.append(f"\n=== LOCATIONS ===")
                    context_parts.append("No coordinate rows matched the current scoped platforms.")
                    # Fallback: show chat-level location share events so analysis does not report
                    # \"no location data\" when location shares exist but coordinates are absent.
                    if projected_location_share_events:
                        context_parts.append(
                            f"\n=== CHAT LOCATION SHARES (no coordinates) (Showing {min(len(projected_location_share_events), max_items)} of {len(projected_location_share_events)}) ==="
                        )
                        for ev in projected_location_share_events[:max_items]:
                            ts = ev.get('timestamp', 'N/A')
                            frm = ev.get('from_participant', 'Unknown')
                            to = ev.get('to_participant', 'Unknown')
                            txt = (ev.get('text_content', '') or '').strip()
                            plat = ev.get('platform', 'Unknown')
                            if txt:
                                context_parts.append(
                                    f"[{ts}] {plat} | {frm} -> {to} | [Location Share] {txt[:200]}"
                                )
                            else:
                                context_parts.append(
                                    f"[{ts}] {plat} | {frm} -> {to} | [Location Share]"
                                )
                    else:
                        context_parts.append("No locations found in database.")
            finally:
                conn.close()
        
        # Device owner identification queries
        is_owner_query = any(phrase in query_lower for phrase in [
            'device owner', 'owner', 'who owns', 'belongs to', 'device user', 'primary user',
            'who do you think', 'who is the owner', 'identify owner', 'determine owner'
        ])
        
        if is_owner_query and evidence_scope.allows_domain("device"):
            conn = self.get_connection()
            try:
                cursor = conn.cursor()
                
                # Get device metadata
                cursor.execute("SELECT key, value FROM device_metadata")
                device_metadata = cursor.fetchall()
                
                # PRIORITY 1: Check for explicit owner indicators in system messages
                # Look for messages that explicitly state ownership (e.g., "owner" in system messages)
                cursor.execute("""
                    SELECT from_participant, from_identifier, text_content
                    FROM chat_messages 
                    WHERE (text_content LIKE '%owner%' OR text_content LIKE '%Owner%')
                    AND message_type = 'system'
                    LIMIT 10
                """)
                owner_system_messages = cursor.fetchall()
                
                # PRIORITY 2: Check chat participants table for IsPhoneOwner flag (if available)
                # Since is_phone_owner is not in database, we'll check raw_data or use alternative method
                # Check for participants with phone number matching device MSISDN
                device_phone = None
                for key, value in device_metadata:
                    if key in ['MSISDN', 'Phone Number', 'phone_number'] and value:
                        device_phone = value
                        break
                
                # PRIORITY 3: Analyze outgoing communications to identify owner
                cursor.execute("""
                    SELECT from_number, COUNT(*) as count 
                    FROM call_logs 
                    WHERE from_number IS NOT NULL AND from_number != ''
                    GROUP BY from_number
                    ORDER BY count DESC
                    LIMIT 1
                """)
                most_outgoing_calls = cursor.fetchone()
                
                cursor.execute("""
                    SELECT from_number, COUNT(*) as count 
                    FROM messages 
                    WHERE from_number IS NOT NULL AND from_number != ''
                    GROUP BY from_number
                    ORDER BY count DESC
                    LIMIT 1
                """)
                most_outgoing_messages = cursor.fetchone()
                
                cursor.execute("""
                    SELECT from_participant, COUNT(*) as count 
                    FROM chat_messages 
                    WHERE from_participant IS NOT NULL AND from_participant != ''
                    AND from_participant != 'System Message'
                    GROUP BY from_participant
                    ORDER BY count DESC
                    LIMIT 5
                """)
                most_active_chats = cursor.fetchall()
                
                context_parts.append("\n=== DEVICE OWNER ANALYSIS ===")
                
                if device_metadata:
                    context_parts.append("\nDevice Metadata:")
                    for key, value in device_metadata:
                        if value:
                            context_parts.append(f"  • {key}: {value}")
                
                # Check system messages for explicit owner statements
                owner_from_system = None
                if owner_system_messages:
                    context_parts.append("\nSystem Message Analysis (Explicit Owner Indicators):")
                    for msg in owner_system_messages:
                        text = msg[2] or ''
                        from_part = msg[0] or ''
                        from_id = msg[1] or ''
                        # Look for patterns like "owner" or "19195794674@s.whatsapp.net owner"
                        if 'owner' in text.lower():
                            # Extract name/identifier from system message
                            # Pattern: "Outgoing call from This Is DFIR (19195794674@s.whatsapp.net owner)"
                            owner_match = re.search(r'from\s+([^(]+)\s*\([^)]*owner\)', text, re.IGNORECASE)
                            if owner_match:
                                owner_from_system = owner_match.group(1).strip()
                                context_parts.append(f"  • EXPLICIT OWNER INDICATOR: {owner_from_system} (from system message: '{text[:100]}...')")
                                break
                            # Alternative pattern: check if from_identifier matches device phone
                            if device_phone and from_id and device_phone in from_id:
                                owner_from_system = from_part
                                context_parts.append(f"  • EXPLICIT OWNER INDICATOR: {owner_from_system} (identifier matches device phone)")
                                break
                
                context_parts.append("\nCommunication Pattern Analysis:")
                
                if most_outgoing_calls:
                    cursor.execute("SELECT name FROM contacts WHERE phone = ? LIMIT 1", (most_outgoing_calls[0],))
                    name_result = cursor.fetchone()
                    name = name_result[0] if name_result else most_outgoing_calls[0]
                    context_parts.append(f"  • Most Outgoing Calls: {name} ({most_outgoing_calls[0]}) - {most_outgoing_calls[1]} calls")
                
                if most_outgoing_messages:
                    cursor.execute("SELECT name FROM contacts WHERE phone = ? LIMIT 1", (most_outgoing_messages[0],))
                    name_result = cursor.fetchone()
                    name = name_result[0] if name_result else most_outgoing_messages[0]
                    context_parts.append(f"  • Most Outgoing Messages: {name} ({most_outgoing_messages[0]}) - {most_outgoing_messages[1]} messages")
                
                if most_active_chats:
                    context_parts.append("  • Most Active Chat Participants:")
                    for chat in most_active_chats[:3]:
                        context_parts.append(f"    - {chat[0]}: {chat[1]} messages")
                
                # Determine likely owner - PRIORITIZE explicit indicators
                likely_owner = None
                owner_rationale = ""
                
                # PRIORITY 1: Use explicit owner from system messages
                if owner_from_system:
                    likely_owner = owner_from_system
                    owner_rationale = "Explicit owner indicator found in system messages (IsPhoneOwner=True in XML data)"
                # PRIORITY 2: Check if device phone matches any participant identifier
                elif device_phone:
                    # Check if device phone matches any from_identifier in chat_messages
                    cursor.execute("""
                        SELECT DISTINCT from_participant, from_identifier
                        FROM chat_messages
                        WHERE from_identifier LIKE ? OR from_identifier LIKE ?
                        LIMIT 1
                    """, (f'%{device_phone}%', f'%{device_phone.replace("+", "")}%'))
                    phone_match = cursor.fetchone()
                    if phone_match:
                        likely_owner = phone_match[0]
                        owner_rationale = f"Participant identifier matches device phone number ({device_phone})"
                # PRIORITY 3: Use communication patterns (fallback)
                elif most_outgoing_calls and most_outgoing_messages:
                    if most_outgoing_calls[0] == most_outgoing_messages[0]:
                        cursor.execute("SELECT name FROM contacts WHERE phone = ? LIMIT 1", (most_outgoing_calls[0],))
                        name_result = cursor.fetchone()
                        likely_owner = name_result[0] if name_result else most_outgoing_calls[0]
                        owner_rationale = "Consistent pattern of outgoing calls and messages"
                    else:
                        cursor.execute("SELECT name FROM contacts WHERE phone = ? LIMIT 1", (most_outgoing_calls[0],))
                        name_result = cursor.fetchone()
                        likely_owner = name_result[0] if name_result else most_outgoing_calls[0]
                        owner_rationale = "Most outgoing calls pattern"
                elif most_outgoing_calls:
                    cursor.execute("SELECT name FROM contacts WHERE phone = ? LIMIT 1", (most_outgoing_calls[0],))
                    name_result = cursor.fetchone()
                    likely_owner = name_result[0] if name_result else most_outgoing_calls[0]
                    owner_rationale = "Most outgoing calls pattern"
                elif most_active_chats:
                    likely_owner = most_active_chats[0][0]
                    owner_rationale = "Most active chat participant"
                
                if likely_owner:
                    context_parts.append(f"\n→ LIKELY DEVICE OWNER: {likely_owner}")
                    context_parts.append(f"  Rationale: {owner_rationale}")
            finally:
                conn.close()
        
        # Check for queries asking about data availability (e.g., "do you have access to chats, call logs and contacts")
        if evidence_scope.include_global_preamble and any(
            phrase in query_lower
            for phrase in [
                "do you have access",
                "have access to",
                "can you pull",
                "can you access",
                "available",
                "is available",
                "what data",
                "what information",
            ]
        ):
            conn = self.get_connection()
            try:
                cursor = conn.cursor()
                
                # Get counts for all data types
                cursor.execute("SELECT COUNT(*) FROM contacts")
                contact_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM messages")
                message_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM call_logs")
                call_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM chats")
                chat_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM chat_messages")
                chat_message_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM locations")
                location_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM files")
                file_count = cursor.fetchone()[0]
                
                context_parts.append("\n=== DATA AVAILABILITY ===")
                context_parts.append(
                    "Record counts (indexed SQLite tables from this extraction):"
                )
                context_parts.append(f"✅ Contacts: {contact_count}")
                context_parts.append(
                    f"✅ Root-level instant messages (`messages` table — top-level InstantMessage artifacts; "
                    f"often sparse when most IMs are nested under Chat): {message_count}"
                )
                context_parts.append(
                    f"✅ Chat / app messages (`chat_messages` — thread messages + linked app IMs; "
                    f"use this for WhatsApp, Messenger, LINE, etc.): {chat_message_count}"
                )
                context_parts.append(f"✅ Chat threads (`chats`): {chat_count}")
                context_parts.append(f"✅ Call logs (`call_logs`, includes cellular and app VoIP where decoded): {call_count}")
                context_parts.append(f"✅ Locations (`locations`): {location_count}")
                context_parts.append(
                    f"✅ Files / tagged artifacts (`files` — paths, hashes, media index from report): {file_count}"
                )
                breakdown = _data_availability_breakdown_lines(cursor)
                if breakdown:
                    context_parts.append("\nPlatform / source breakdown (from stored PA Source or platform fields):")
                    context_parts.extend(f"  • {line}" for line in breakdown)
                context_parts.append(
                    "\nLLM NOTE: Do not call `messages` 'standalone SMS' unless source rows indicate SMS/MMS. "
                    "Do not claim platform detail is missing when the breakdown lines above list sources."
                )
                context_parts.append(
                    "Next queries (examples): 'list all contacts', 'show call logs', "
                    "'list all chats', 'summarize chat messages by platform', "
                    "'timeline for February 2020'."
                )
            finally:
                conn.close()
        
        # If no specific data type was matched, try to extract general data for very broad queries
        if evidence_scope.mode == "case_overview" and not context_parts and not is_international_phone_query:
            # Check for very general queries that might need all data types
            general_keywords = ['all', 'everything', 'show', 'list', 'get', 'find', 'search', 'analyze', 'what', 
                               'data', 'information', 'forensic', 'evidence', 'suspicious', 'pattern', 'activity']
            if any(word in query_lower for word in general_keywords):
                # Try to get counts of all data types
                conn = self.get_connection()
                try:
                    cursor = conn.cursor()
                    
                    # Get counts for all data types
                    cursor.execute("SELECT COUNT(*) FROM contacts")
                    contact_count = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT COUNT(*) FROM messages")
                    message_count = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT COUNT(*) FROM call_logs")
                    call_count = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT COUNT(*) FROM chats")
                    chat_count = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT COUNT(*) FROM chat_messages")
                    chat_message_count = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT COUNT(*) FROM locations")
                    location_count = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT COUNT(*) FROM files")
                    file_count = cursor.fetchone()[0]
                    
                    if (
                        contact_count + message_count + call_count + chat_count + chat_message_count + location_count + file_count
                        > 0
                    ):
                        context_parts.append("\n=== AVAILABLE DATA ===")
                        context_parts.append(f"Contacts: {contact_count}")
                        context_parts.append(
                            f"Root-level instant messages (messages table): {message_count}"
                        )
                        context_parts.append(
                            f"Chat / app messages (chat_messages): {chat_message_count}"
                        )
                        context_parts.append(f"Chat threads (chats): {chat_count}")
                        context_parts.append(f"Call logs: {call_count}")
                        context_parts.append(f"Locations: {location_count}")
                        context_parts.append(f"Files: {file_count}")
                        breakdown = _data_availability_breakdown_lines(cursor)
                        for line in breakdown:
                            context_parts.append(f"  • {line}")
                        context_parts.append(
                            "\nPlease specify which data type you'd like to query "
                            "(e.g., 'show contacts', 'list all chats', 'show call logs', "
                            "'find messages in WhatsApp')."
                        )
                finally:
                    conn.close()
        
        # Timeline/Chronological queries (native tables — gated by evidence scope)
        if any(
            word in query_lower
            for word in ["timeline", "events", "chronological", "sequence", "order", "when", "history"]
        ) and (
            evidence_scope.allows_domain("calls")
            or evidence_scope.allows_domain("locations")
            or evidence_scope.allows_domain("messages")
        ):
            conn = self.get_connection()
            try:
                cursor = conn.cursor()
                calls = []
                locations = []
                messages = []
                if evidence_scope.allows_domain("calls"):
                    cursor.execute(
                        """
                    SELECT * FROM call_logs 
                    WHERE timestamp IS NOT NULL AND timestamp != ''
                    ORDER BY timestamp DESC
                    LIMIT ?
                """,
                        (max_items,),
                    )
                    calls = [dict(row) for row in cursor.fetchall()]
                if evidence_scope.allows_domain("locations"):
                    cursor.execute(
                        """
                    SELECT * FROM locations 
                    WHERE timestamp IS NOT NULL AND timestamp != ''
                    ORDER BY timestamp DESC
                    LIMIT ?
                """,
                        (max_items,),
                    )
                    locations = [dict(row) for row in cursor.fetchall()]
                if evidence_scope.allows_domain("messages"):
                    cursor.execute(
                        """
                    SELECT * FROM messages 
                    WHERE timestamp IS NOT NULL AND timestamp != ''
                    ORDER BY timestamp DESC
                    LIMIT ?
                """,
                        (max_items,),
                    )
                    messages = [dict(row) for row in cursor.fetchall()]
                
                # Combine and sort by timestamp
                timeline_items = []
                for call in calls:
                    timestamp = call.get('timestamp', '') or call.get('timestamp_formatted', '')
                    if timestamp:
                        timeline_items.append({
                            'type': 'Call',
                            'timestamp': timestamp,
                            'data': call
                        })
                
                for loc in locations:
                    timestamp = loc.get('timestamp', '') or loc.get('timestamp_formatted', '')
                    if timestamp:
                        timeline_items.append({
                            'type': 'Location',
                            'timestamp': timestamp,
                            'data': loc
                        })
                
                for msg in messages:
                    timestamp = msg.get('timestamp', '') or msg.get('timestamp_formatted', '')
                    if timestamp:
                        timeline_items.append({
                            'type': 'Message',
                            'timestamp': timestamp,
                            'data': msg
                        })
                
                # Sort by timestamp (newest first)
                timeline_items.sort(key=lambda x: x['timestamp'], reverse=True)

                # If the user asked for a specific year (e.g. "timeline ... in 2020"), filter this slice
                _years_in_q = _extract_years_from_query(query)
                _timeline_note = ""
                _year_filter_empty = False
                if _years_in_q and len(_years_in_q) <= 3:
                    _filtered = [t for t in timeline_items if _timeline_timestamp_in_years(t.get('timestamp') or '', _years_in_q)]
                    if _filtered:
                        timeline_items = _filtered
                        _timeline_note = (
                            f" — filtered to year(s) {', '.join(str(y) for y in _years_in_q)} "
                            f"(native SMS/calls/locations only; app chats appear in sections above)"
                        )
                    elif timeline_items:
                        # Do not dump unrelated years when the user asked for a specific year
                        _year_filter_empty = True
                        timeline_items = []
                
                if _year_filter_empty:
                    context_parts.append(
                        f"\n=== TIMELINE OF EVENTS (native SMS / calls / locations) ===\n"
                        f"No events in year(s) {', '.join(str(y) for y in _years_in_q)} in this database slice. "
                        f"Third-party chat timelines for the subject may appear under SAMPLE CHAT MESSAGES / CALLS INVOLVING above."
                    )
                elif timeline_items:
                    context_parts.append(
                        f"\n=== TIMELINE OF EVENTS (Showing {len(timeline_items)} item(s)){_timeline_note} ==="
                    )
                    for item in timeline_items[:50]:  # Limit to 50 items
                        if item['type'] == 'Call':
                            call = item['data']
                            context_parts.append(
                                f"[{item['timestamp']}] CALL: "
                                f"From {call.get('from_number', 'Unknown')} to {call.get('to_number', 'Unknown')} | "
                                f"Duration: {call.get('duration', 0)}s"
                            )
                        elif item['type'] == 'Location':
                            loc = item['data']
                            context_parts.append(
                                f"[{item['timestamp']}] LOCATION: "
                                f"Coordinates: ({loc.get('latitude', 'N/A')}, {loc.get('longitude', 'N/A')})"
                            )
                        elif item['type'] == 'Message':
                            msg = item['data']
                            text_content = msg.get('text_content') or ''
                            text_preview = text_content[:100] if text_content else 'N/A'
                            context_parts.append(
                                f"[{item['timestamp']}] MESSAGE: "
                                f"From {msg.get('from_number', 'Unknown')} to {msg.get('to_number', 'Unknown')} | "
                                f"Content: {text_preview}"
                            )
            finally:
                conn.close()
        
        # If no data found, check if we should provide helpful feedback
        if not context_parts:
            # Log comprehensive query analysis for debugging
            logger.warning(f"⚠️ No data found for query: '{query}'")
            logger.warning(f"   Query intent analysis:")
            logger.warning(f"   - Question type: {intent['question_type']}")
            logger.warning(f"   - Data types detected: {intent['data_types']}")
            logger.warning(f"   - Intent type: {intent['intent_type']}")
            logger.warning(f"   - Person names: {intent['entities']['person_names']}")
            logger.warning(f"   - Phone numbers: {phone_numbers_in_query}")
            logger.warning(f"   - Platforms: {intent['entities']['platforms']}")
            logger.warning(f"   - Is comprehensive: {intent['is_comprehensive']}")
            logger.warning(f"   - Is pattern analysis: {is_pattern_analysis}")
            
            # Try fallback searches based on intent
            fallback_success = False
            
            # If person names detected but no data found, try broader search
            if intent['entities']['person_names'] and not fallback_success:
                logger.info(f"🔄 Fallback: Trying broader search for person names: {intent['entities']['person_names']}")
                for person_name in intent['entities']['person_names']:
                    # Try searching all data types for this person
                    person_messages = self.query_messages(person_name, limit=10)
                    person_calls = self.query_calls(person_name, limit=10)
                    person_chats = self.query_chats(person_name, limit=10)
                    person_contacts = self.query_contacts(person_name, limit=10)
                    
                    if person_messages or person_calls or person_chats or person_contacts:
                        context_parts.append(f"\n=== DATA FOUND FOR '{person_name}' (Fallback Search) ===")
                        if person_contacts:
                            context_parts.append(f"Contacts: {len(person_contacts)} found")
                        if person_messages:
                            context_parts.append(f"Messages: {len(person_messages)} found")
                        if person_calls:
                            context_parts.append(f"Calls: {len(person_calls)} found")
                        if person_chats:
                            context_parts.append(f"Chats: {len(person_chats)} found")
                        fallback_success = True
                        break
            
            # If phone numbers detected but no data found, try cross-table search
            if phone_numbers_in_query and not fallback_success:
                logger.info(f"🔄 Fallback: Trying cross-table search for phone numbers: {phone_numbers_in_query}")
                for phone in phone_numbers_in_query:
                    phone_messages = self.query_messages(phone, limit=10)
                    phone_calls = self.query_calls(phone, limit=10)
                    phone_contacts = self.query_contacts(phone, limit=10)
                    
                    if phone_messages or phone_calls or phone_contacts:
                        context_parts.append(f"\n=== DATA FOUND FOR PHONE '{phone}' (Fallback Search) ===")
                        if phone_contacts:
                            context_parts.append(f"Contacts: {len(phone_contacts)} found")
                        if phone_messages:
                            context_parts.append(f"Messages: {len(phone_messages)} found")
                        if phone_calls:
                            context_parts.append(f"Calls: {len(phone_calls)} found")
                        fallback_success = True
                        break
            
            # If still no data, provide helpful feedback
            if not context_parts:
                conn = self.get_connection()
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM contacts")
                    contact_count = cursor.fetchone()[0]
                    cursor.execute("SELECT COUNT(*) FROM messages")
                    message_count = cursor.fetchone()[0]
                    cursor.execute("SELECT COUNT(*) FROM call_logs")
                    call_count = cursor.fetchone()[0]
                    cursor.execute("SELECT COUNT(*) FROM chats")
                    chat_count = cursor.fetchone()[0]
                    cursor.execute("SELECT COUNT(*) FROM chat_messages")
                    chat_message_count = cursor.fetchone()[0]
                    cursor.execute("SELECT COUNT(*) FROM locations")
                    location_count = cursor.fetchone()[0]
                    cursor.execute("SELECT COUNT(*) FROM files")
                    file_count = cursor.fetchone()[0]
                    
                    if contact_count + message_count + call_count + chat_count + chat_message_count + location_count + file_count > 0:
                        suggestions = []
                        if intent['data_types']:
                            data_type = intent['data_types'][0]
                            suggestions.append(f"Try: 'list all {data_type}' to see all {data_type}")
                        if intent['entities']['person_names']:
                            person_name = intent['entities']['person_names'][0]
                            suggestions.append(f"Try: 'show all communications with {person_name}'")
                        if phone_numbers_in_query:
                            phone = phone_numbers_in_query[0]
                            suggestions.append(f"Try: 'find all data for {phone}'")
                        if not suggestions:
                            suggestions = [
                                "Try: 'list all contacts' to see all contacts",
                                "Try: 'list all chats' to see all chats",
                                "Try: 'show call logs' to see call history",
                                "Try: 'find messages' to search messages"
                            ]
                        
                        return f"""EMPTY_EVIDENCE_SLICE: No row-level records matched the interpreted filters for '{query}'.

**PRE-COMPUTED TABLE COUNTS** (whole extraction, SQLite COUNT(*) — authoritative for what is indexed in this case):
- {contact_count} contacts
- {message_count} root-level instant messages (messages table — sparse when IMs are under Chat)
- {chat_message_count} chat / app messages (chat_messages — primary app conversation store)
- {call_count} call logs
- {chat_count} chat threads
- {location_count} locations
- {file_count} files / tagged artifacts

Suggestions:
{chr(10).join('- ' + s for s in suggestions)}

You can also try:
- Search by phone number: "find data for [phone number]"
- Search by person name: "show chats with [name]"
- List all data: "list all [data type]"
- Pattern analysis: "list suspicious communication patterns\""""
                    else:
                        return "NO_DATA_FOUND: Database appears to be empty. No contacts, messages, calls, or chats found."
                finally:
                    conn.close()
        
        return "\n".join(context_parts)
    
    def get_all_communications_for_person(self, person_name: str, limit: int = 1000) -> Dict[str, Any]:
        """
        Get ALL communications related to a specific person - comprehensive analysis.
        Returns detailed results similar to manual forensic analysis.
        
        Args:
            person_name: Name of the person to search for
            limit: Maximum number of results per category
            
        Returns:
            Dictionary with comprehensive communication data:
            - contact_info: Contact details
            - chats: All chat threads
            - messages: All messages (chronological)
            - calls: All call records
            - summary: Statistics and timeline
        """
        conn = self.get_connection()
        try:
            results = {
                'person_name': person_name,
                'contact_info': {},
                'chats': [],
                'messages': [],
                'calls': [],
                'summary': {
                    'total_chats': 0,
                    'total_messages': 0,
                    'total_calls': 0,
                    'date_range': {'earliest': None, 'latest': None},
                    'platforms': set()
                }
            }
            
            cursor = conn.cursor()
            
            # 1. Find contact information
            cursor.execute("""
                SELECT * FROM contacts 
                WHERE name LIKE ? OR phone LIKE ? OR email LIKE ?
                LIMIT 10
            """, (f"%{person_name}%", f"%{person_name}%", f"%{person_name}%"))
            
            contacts = [dict(row) for row in cursor.fetchall()]
            if contacts:
                # Use the first matching contact
                contact = contacts[0]
                results['contact_info'] = {
                    'name': contact.get('name', ''),
                    'phone': contact.get('phone', ''),
                    'email': contact.get('email', ''),
                    'contact_id': contact.get('id')
                }
            
            # 2. Find all chats involving this person
            # Search by participant name, chat name, or participant identifiers (case-insensitive)
            person_name_lower = person_name.lower()
            
            # DIAGNOSTIC: Log search parameters
            logger.info(f"🔍 Searching chats for: '{person_name}' (lower: '{person_name_lower}')")
            
            cursor.execute("""
                SELECT * FROM chats 
                WHERE chat_name LIKE ? OR LOWER(chat_name) LIKE ? 
                   OR participants LIKE ? OR LOWER(participants) LIKE ?
                   OR platform LIKE ? OR LOWER(platform) LIKE ?
                ORDER BY last_message_time DESC
                LIMIT ?
            """, (f"%{person_name}%", f"%{person_name_lower}%", 
                  f"%{person_name}%", f"%{person_name_lower}%",
                  f"%{person_name}%", f"%{person_name_lower}%", limit))
            
            chats = [dict(row) for row in cursor.fetchall()]
            
            # DIAGNOSTIC: Log results
            logger.info(f"📊 Found {len(chats)} chat(s) matching '{person_name}'")
            if chats:
                for i, chat in enumerate(chats[:3]):  # Log first 3
                    logger.info(f"   Chat {i+1}: {chat.get('chat_name', 'N/A')} | Participants: {chat.get('participants', 'N/A')[:100]}")
            else:
                # Try to see what chats exist
                cursor.execute("SELECT chat_name, participants FROM chats LIMIT 5")
                sample_chats = cursor.fetchall()
                logger.info(f"⚠️ No chats found. Sample chats in DB: {sample_chats}")
            
            results['chats'] = chats
            results['summary']['total_chats'] = len(chats)
            
            # Extract chat IDs for message lookup
            chat_ids = [chat.get('chat_id', '') for chat in chats if chat.get('chat_id')]
            chat_names = [chat.get('chat_name', '') for chat in chats if chat.get('chat_name')]
            
            # 3. Find all messages involving this person
            # Search in chat messages and regular messages (case-insensitive)
            message_conditions = []
            message_params = []
            person_name_lower = person_name.lower()
            
            if chat_ids:
                placeholders = ','.join(['?'] * len(chat_ids))
                message_conditions.append(f"chat_id IN ({placeholders})")
                message_params.extend(chat_ids)
            
            if chat_names:
                placeholders = ','.join(['?'] * len(chat_names))
                message_conditions.append(f"chat_name IN ({placeholders})")
                message_params.extend(chat_names)
            
            # Also search by participant name or identifier (case-insensitive)
            message_conditions.append("""(from_participant LIKE ? OR LOWER(from_participant) LIKE ? 
                OR to_participant LIKE ? OR LOWER(to_participant) LIKE ?
                OR from_identifier LIKE ? OR LOWER(from_identifier) LIKE ?
                OR to_identifier LIKE ? OR LOWER(to_identifier) LIKE ?
                OR text_content LIKE ? OR LOWER(text_content) LIKE ?)""")
            message_params.extend([
                f"%{person_name}%", f"%{person_name_lower}%",
                f"%{person_name}%", f"%{person_name_lower}%",
                f"%{person_name}%", f"%{person_name_lower}%",
                f"%{person_name}%", f"%{person_name_lower}%",
                f"%{person_name}%", f"%{person_name_lower}%"
            ])
            
            where_clause = " OR ".join(message_conditions) if message_conditions else "1=1"
            
            cursor.execute(f"""
                SELECT * FROM chat_messages 
                WHERE {where_clause}
                ORDER BY timestamp ASC
                LIMIT ?
            """, message_params + [limit])
            
            messages = [dict(row) for row in cursor.fetchall()]
            
            # Also search regular messages table (case-insensitive)
            person_name_lower = person_name.lower()
            cursor.execute("""
                SELECT * FROM messages 
                WHERE from_number LIKE ? OR LOWER(from_number) LIKE ?
                   OR to_number LIKE ? OR LOWER(to_number) LIKE ?
                   OR text_content LIKE ? OR LOWER(text_content) LIKE ?
                ORDER BY timestamp ASC
                LIMIT ?
            """, (f"%{person_name}%", f"%{person_name_lower}%",
                  f"%{person_name}%", f"%{person_name_lower}%",
                  f"%{person_name}%", f"%{person_name_lower}%", limit))
            
            regular_messages = [dict(row) for row in cursor.fetchall()]
            messages.extend(regular_messages)
            
            # Sort all messages chronologically
            messages.sort(key=lambda x: x.get('timestamp', '') or '')
            results['messages'] = messages
            results['summary']['total_messages'] = len(messages)
            
            # 4. Find all calls involving this person (case-insensitive)
            person_name_lower = person_name.lower()
            cursor.execute("""
                SELECT * FROM call_logs 
                WHERE from_number LIKE ? OR LOWER(from_number) LIKE ?
                   OR to_number LIKE ? OR LOWER(to_number) LIKE ?
                   OR call_type LIKE ? OR LOWER(call_type) LIKE ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (f"%{person_name}%", f"%{person_name_lower}%",
                  f"%{person_name}%", f"%{person_name_lower}%",
                  f"%{person_name}%", f"%{person_name_lower}%", limit))
            
            calls = [dict(row) for row in cursor.fetchall()]
            results['calls'] = calls
            results['summary']['total_calls'] = len(calls)
            
            # 5. Calculate summary statistics
            all_timestamps = []
            for msg in messages:
                ts = msg.get('timestamp', '')
                if ts:
                    all_timestamps.append(ts)
                platform = msg.get('platform', '') or msg.get('source', '')
                if platform:
                    results['summary']['platforms'].add(platform)
            
            for call in calls:
                ts = call.get('timestamp', '')
                if ts:
                    all_timestamps.append(ts)
            
            if all_timestamps:
                all_timestamps.sort()
                results['summary']['date_range']['earliest'] = all_timestamps[0]
                results['summary']['date_range']['latest'] = all_timestamps[-1]
            
            results['summary']['platforms'] = list(results['summary']['platforms'])
            
            return results
            
        finally:
            conn.close()
    
    def format_comprehensive_analysis(self, person_name: str, communications: Dict[str, Any]) -> str:
        """
        Format comprehensive communication analysis in detailed forensic style.
        Similar to the detailed analysis format I demonstrated.
        
        Args:
            person_name: Name of the person
            communications: Result from get_all_communications_for_person()
            
        Returns:
            Formatted string with comprehensive analysis
        """
        parts = []
        
        # Header
        parts.append(f"## 📋 COMPREHENSIVE COMMUNICATION ANALYSIS")
        parts.append(f"### Person: {person_name}")
        parts.append("")
        
        # Contact Information
        contact_info = communications.get('contact_info', {})
        if contact_info:
            parts.append("### 👤 Contact Information")
            if contact_info.get('name'):
                parts.append(f"- **Name**: {contact_info['name']}")
            if contact_info.get('phone'):
                parts.append(f"- **Phone**: {contact_info['phone']}")
            if contact_info.get('email'):
                parts.append(f"- **Email**: {contact_info['email']}")
            parts.append("")
        
        # Summary Statistics
        summary = communications.get('summary', {})
        parts.append("### 📊 Summary Statistics")
        parts.append(f"- **Total Chats**: {summary.get('total_chats', 0)}")
        parts.append(f"- **Total Messages**: {summary.get('total_messages', 0)}")
        parts.append(f"- **Total Calls**: {summary.get('total_calls', 0)}")
        
        date_range = summary.get('date_range', {})
        if date_range.get('earliest'):
            parts.append(f"- **Earliest Activity**: {date_range['earliest']}")
        if date_range.get('latest'):
            parts.append(f"- **Latest Activity**: {date_range['latest']}")
        
        platforms = summary.get('platforms', [])
        if platforms:
            parts.append(f"- **Platforms**: {', '.join(platforms)}")
        parts.append("")
        
        # Chat Threads
        chats = communications.get('chats', [])
        if chats:
            parts.append("### 💬 Chat Threads")
            for idx, chat in enumerate(chats[:20], 1):  # Limit to 20 chats
                participants = []
                try:
                    participants = json.loads(chat.get('participants', '[]'))
                except:
                    if chat.get('participants'):
                        participants = [chat.get('participants')]
                
                parts.append(f"\n**Chat #{idx}**: {chat.get('chat_name', 'Unknown')}")
                parts.append(f"- **Platform**: {chat.get('platform', 'Unknown')}")
                parts.append(f"- **Participants**: {', '.join(participants) if participants else 'Unknown'}")
                parts.append(f"- **Chat ID**: {chat.get('chat_id', 'N/A')}")
                parts.append(f"- **Last Activity**: {chat.get('last_message_time', 'N/A')}")
                parts.append(f"- **Message Count**: {chat.get('message_count', 0)}")
            if len(chats) > 20:
                parts.append(f"\n... and {len(chats) - 20} more chat(s)")
            parts.append("")
        
        # Messages (Chronological)
        messages = communications.get('messages', [])
        if messages:
            parts.append("### 📨 Message History (Chronological)")
            parts.append("")
            for idx, msg in enumerate(messages[:50], 1):  # Limit to 50 messages
                timestamp = msg.get('timestamp', '') or msg.get('timestamp_formatted', '') or 'N/A'
                from_party = msg.get('from_participant', '') or msg.get('from_number', 'Unknown')
                to_party = msg.get('to_participant', '') or msg.get('to_number', 'Unknown')
                text = msg.get('text_content', '') or msg.get('text', '')
                platform = msg.get('platform', '') or msg.get('source', 'Unknown')
                
                parts.append(f"**Message #{idx}** - {timestamp}")
                parts.append(f"- **From**: {from_party}")
                parts.append(f"- **To**: {to_party}")
                parts.append(f"- **Platform**: {platform}")
                parts.append(f"- **Content**: {text[:200]}{'...' if len(text) > 200 else ''}")
                
                # Check for attachments
                attachments = msg.get('attachments')
                if attachments:
                    try:
                        att_list = json.loads(attachments) if isinstance(attachments, str) else attachments
                        if att_list:
                            parts.append(f"- **Attachments**: {len(att_list)} file(s)")
                            for att in att_list[:3]:  # Show first 3 attachments
                                if att.get('url'):
                                    parts.append(f"  - {att.get('filename', 'File')}: {att['url'][:80]}...")
                    except:
                        pass
                
                parts.append("")
            
            if len(messages) > 50:
                parts.append(f"... and {len(messages) - 50} more message(s)")
            parts.append("")
        
        # Call Records
        calls = communications.get('calls', [])
        if calls:
            parts.append("### 📞 Call Records")
            parts.append("")
            for idx, call in enumerate(calls[:30], 1):  # Limit to 30 calls
                timestamp = call.get('timestamp', 'N/A')
                from_num = call.get('from_number', 'Unknown')
                to_num = call.get('to_number', 'Unknown')
                duration = call.get('duration', 0)
                call_type = call.get('call_type', 'Unknown')
                source = call.get('source_db', '') or call.get('source', 'Unknown')
                
                parts.append(f"**Call #{idx}** - {timestamp}")
                parts.append(f"- **From**: {from_num}")
                parts.append(f"- **To**: {to_num}")
                parts.append(f"- **Duration**: {duration} seconds")
                parts.append(f"- **Type**: {call_type}")
                parts.append(f"- **Source**: {source}")
                parts.append("")
            
            if len(calls) > 30:
                parts.append(f"... and {len(calls) - 30} more call(s)")
            parts.append("")
        
        return "\n".join(parts)
    
    def get_media_metadata(self, media_type: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Get media metadata (images/videos)."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if media_type:
            cursor.execute("""
                SELECT * FROM media_index 
                WHERE media_type = ?
                LIMIT ?
            """, (media_type, limit))
        else:
            cursor.execute("""
                SELECT * FROM media_index 
                LIMIT ?
            """, (limit,))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def extract_media_on_demand(self, rel_path: str, extract_to: str) -> Optional[str]:
        """Extract media file on-demand from ZIP."""
        if not self.zip_path or not os.path.exists(self.zip_path):
            return None
        
        try:
            with zipfile.ZipFile(self.zip_path, 'r') as zip_ref:
                # Extract to specified directory
                zip_ref.extract(rel_path, extract_to)
                extracted_path = os.path.join(extract_to, rel_path)
                
                # Mark as extracted in database
                conn = self.get_connection()
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE media_index 
                    SET extracted = 1 
                    WHERE rel_path = ?
                """, (rel_path,))
                conn.commit()
                
                return extracted_path
        except Exception as e:
            logger.error(f"Error extracting media {rel_path}: {e}")
            return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about stored data."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        stats = {}
        
        # Count records
        for table in ['contacts', 'messages', 'chats', 'chat_messages', 'call_logs', 'locations', 'files']:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            stats[f"{table}_count"] = cursor.fetchone()[0]
        
        # Count media
        cursor.execute("SELECT COUNT(*) FROM media_index WHERE media_type = 'image'")
        stats['images_count'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM media_index WHERE media_type = 'video'")
        stats['videos_count'] = cursor.fetchone()[0]
        
        return stats
    
    def get_platform_classification(self) -> str:
        """
        Get dynamic platform classification with message type breakdowns.
        Returns a formatted string showing all platforms and their message type distributions.
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        result_parts = []
        result_parts.append("=== PLATFORM CLASSIFICATION ===")
        
        # Get total chat count
        cursor.execute("SELECT COUNT(*) FROM chats")
        total_chats = cursor.fetchone()[0]
        
        # Get platform distribution with message counts (matching XML structure)
        cursor.execute("""
            SELECT platform, COUNT(DISTINCT chat_id) as chat_count
            FROM chats
            WHERE platform IS NOT NULL AND platform != ''
            GROUP BY platform
            ORDER BY chat_count DESC
        """)
        platforms = cursor.fetchall()
        
        if not platforms:
            conn.close()
            return "No chats found in database."
        
        result_parts.append(f"\nTotal Chats: {total_chats}\n")
        
        total_messages = 0
        for row in platforms:
            platform = row['platform']
            chat_count = row['chat_count']
            
            # Count messages for this platform
            # Count DISTINCT messages at platform level to avoid double-counting when duplicate chats exist
            cursor.execute("""
                SELECT COUNT(DISTINCT cm.id) as total_msgs
                FROM chat_messages cm
                WHERE cm.platform = ?
                AND cm.source_table = 'Chat'
            """, (platform,))
            result = cursor.fetchone()
            platform_msg_count = result['total_msgs'] if result else 0
            
            # Also get per-chat counts for display (but don't sum them - use platform-level count)
            cursor.execute("""
                SELECT 
                    c.chat_id,
                    COUNT(DISTINCT cm.id) as msg_count_per_chat
                FROM chats c
                LEFT JOIN chat_messages cm ON (
                    (
                        (cm.chat_id = c.chat_id AND cm.chat_id IS NOT NULL AND cm.chat_id != '')
                        OR 
                        (cm.chat_name = c.chat_name AND cm.chat_name IS NOT NULL AND cm.chat_name != '')
                    )
                    AND cm.platform = c.platform
                    AND cm.source_table = 'Chat'
                )
                WHERE c.platform = ?
                GROUP BY c.chat_id
            """, (platform,))
            chat_msg_counts = cursor.fetchall()
            total_messages += platform_msg_count
            
            # Get message type breakdown (for display)
            cursor.execute("""
                SELECT 
                    COALESCE(cm.message_type, 'unknown') as message_type,
                    COUNT(DISTINCT cm.id) as msg_count
                FROM chat_messages cm
                INNER JOIN chats c ON (
                    (
                        (cm.chat_id = c.chat_id AND cm.chat_id IS NOT NULL AND cm.chat_id != '')
                        OR 
                        (cm.chat_name = c.chat_name AND cm.chat_name IS NOT NULL AND cm.chat_name != '')
                    )
                    AND cm.platform = c.platform
                    AND cm.source_table = 'Chat'
                )
                WHERE c.platform = ?
                GROUP BY cm.message_type
            """, (platform,))
            type_counts = cursor.fetchall()
            
            # Format message type breakdown
            type_parts = []
            for type_row in type_counts:
                msg_type = type_row['message_type'] or 'unknown'
                msg_count = type_row['msg_count']
                if msg_count > 0:
                    type_parts.append(f"{msg_type}: {msg_count}")
            
            type_summary = f" ({', '.join(type_parts)})" if type_parts else ""
            
            result_parts.append(f"{platform}: {chat_count} chats, {platform_msg_count} messages{type_summary}")
        
        result_parts.append(f"\nTotal Messages: {total_messages}")
        
        conn.close()
        return "\n".join(result_parts)
    
    def get_pattern_analysis_summary(self) -> str:
        """
        Generate a compact statistical summary for pattern analysis queries.
        Returns key statistics and patterns instead of raw data to fit within context limits.
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        summary_parts = []
        
        # Overall statistics
        cursor.execute("SELECT COUNT(*) FROM contacts")
        contact_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM messages")
        message_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM chats")
        chat_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM chat_messages")
        chat_message_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM call_logs")
        call_count = cursor.fetchone()[0]
        
        summary_parts.append("=== DATABASE OVERVIEW ===")
        summary_parts.append(f"Total Contacts: {contact_count}")
        summary_parts.append(f"Total Messages: {message_count}")
        summary_parts.append(f"Total Chats: {chat_count}")
        summary_parts.append(f"Total Chat Messages: {chat_message_count}")
        summary_parts.append(f"Total Calls: {call_count}")
        
        # Most active contacts (by message count)
        if chat_message_count > 0:
            cursor.execute("""
                SELECT from_participant, COUNT(*) as msg_count
                FROM chat_messages
                WHERE from_participant IS NOT NULL AND from_participant != ''
                GROUP BY from_participant
                ORDER BY msg_count DESC
                LIMIT 10
            """)
            top_senders = cursor.fetchall()
            if top_senders:
                summary_parts.append("\n=== TOP 10 MOST ACTIVE MESSAGE SENDERS ===")
                for row in top_senders:
                    summary_parts.append(f"{row['from_participant']}: {row['msg_count']} messages")
        
        # Platform distribution with message type breakdown
        cursor.execute("""
            SELECT platform, COUNT(*) as count
            FROM chats
            WHERE platform IS NOT NULL AND platform != ''
            GROUP BY platform
            ORDER BY count DESC
        """)
        platforms = cursor.fetchall()
        if platforms:
            summary_parts.append("\n=== CHAT PLATFORMS ===")
            for row in platforms:
                platform = row['platform']
                chat_count = row['count']
                
                # Get message type breakdown for this platform
                cursor.execute("""
                    SELECT message_type, COUNT(*) as msg_count
                    FROM chat_messages
                    WHERE platform = ?
                    GROUP BY message_type
                """, (platform,))
                type_counts = cursor.fetchall()
                
                type_summary = []
                total_msgs = 0
                for type_row in type_counts:
                    msg_type = type_row['message_type'] or 'unknown'
                    msg_count = type_row['msg_count']
                    total_msgs += msg_count
                    type_summary.append(f"{msg_type}:{msg_count}")
                
                summary_parts.append(f"{platform}: {chat_count} chats ({total_msgs} messages)")
                if type_summary:
                    summary_parts.append(f"  Message types: {', '.join(type_summary)}")
        
        # Call patterns
        if call_count > 0:
            cursor.execute("""
                SELECT call_type, COUNT(*) as count
                FROM call_logs
                WHERE call_type IS NOT NULL AND call_type != ''
                GROUP BY call_type
            """)
            call_types = cursor.fetchall()
            if call_types:
                summary_parts.append("\n=== CALL TYPES ===")
                for row in call_types:
                    summary_parts.append(f"{row['call_type']}: {row['count']} calls")
            
            # Average call duration
            cursor.execute("""
                SELECT AVG(CAST(duration AS REAL)) as avg_duration
                FROM call_logs
                WHERE duration IS NOT NULL AND duration != '' AND CAST(duration AS REAL) > 0
            """)
            avg_duration = cursor.fetchone()[0]
            if avg_duration:
                summary_parts.append(f"Average Call Duration: {avg_duration:.1f} seconds")
        
        # Time-based patterns (sample of recent activity)
        cursor.execute("""
            SELECT DATE(timestamp) as date, COUNT(*) as count
            FROM chat_messages
            WHERE timestamp IS NOT NULL AND timestamp != ''
            GROUP BY DATE(timestamp)
            ORDER BY timestamp DESC
            LIMIT 10
        """)
        daily_activity = cursor.fetchall()
        if daily_activity:
            summary_parts.append("\n=== RECENT ACTIVITY (Last 10 Days) ===")
            for row in daily_activity:
                date_str = row['date'] if row['date'] else (row['timestamp'][:10] if 'timestamp' in row and row['timestamp'] else 'Unknown')
                summary_parts.append(f"{date_str}: {row['count']} messages")
        
        # Suspicious indicators
        suspicious_indicators = []
        
        # Check for unusual patterns
        if chat_message_count > 0:
            # Messages with very short content (possible codes)
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM chat_messages
                WHERE LENGTH(text_content) <= 5 AND text_content != ''
            """)
            short_msg_count = cursor.fetchone()[0]
            if short_msg_count > 0:
                suspicious_indicators.append(f"{short_msg_count} very short messages (≤5 chars) - possible codes")
            
            # Messages with repeated content
            cursor.execute("""
                SELECT text_content, COUNT(*) as count
                FROM chat_messages
                WHERE text_content IS NOT NULL AND text_content != ''
                GROUP BY text_content
                HAVING count > 5
                ORDER BY count DESC
                LIMIT 5
            """)
            repeated = cursor.fetchall()
            if repeated:
                suspicious_indicators.append(f"{len(repeated)} messages with repeated content patterns")
        
        # Late night activity (potential suspicious timing)
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM chat_messages
            WHERE timestamp IS NOT NULL 
            AND CAST(strftime('%H', timestamp) AS INTEGER) BETWEEN 0 AND 5
        """)
        late_night = cursor.fetchone()[0]
        if late_night > 0:
            suspicious_indicators.append(f"{late_night} messages sent between midnight and 5 AM")
        
        if suspicious_indicators:
            summary_parts.append("\n=== POTENTIAL SUSPICIOUS PATTERNS ===")
            for indicator in suspicious_indicators:
                summary_parts.append(f"- {indicator}")
        
        # Sample of chat names (for context)
        cursor.execute("""
            SELECT chat_name, platform, message_count
            FROM chats
            WHERE chat_name IS NOT NULL AND chat_name != ''
            ORDER BY last_message_time DESC
            LIMIT 15
        """)
        recent_chats = cursor.fetchall()
        if recent_chats:
            summary_parts.append("\n=== RECENT CHATS (Sample) ===")
            for row in recent_chats:
                summary_parts.append(f"{row['chat_name']} ({row['platform']}) - {row['message_count'] or 0} messages")
        
        conn.close()
        return "\n".join(summary_parts)
    
    def get_ufdr_format_data(self) -> Dict[str, Any]:
        """
        Get data in UFDR format for compatibility with existing system.
        Converts database records to UFDR structure.
        """
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        ufdr_data = {
            'contacts': [],
            'messages': [],
            'call_logs': [],
            'locations': [],
            'device': {},
            'files': [],
            'images': [],
            'videos': [],
            'chats': [],  # Additional Cellebrite-specific
            'chat_messages': [],  # Additional Cellebrite-specific
            'tampered': False,
            'format_version': 'v1',
            'source_format': 'cellebrite_lightweight'
        }
        
        # Load contacts
        cursor.execute("SELECT * FROM contacts")
        for row in cursor.fetchall():
            ufdr_data['contacts'].append(dict(row))
        
        # Load messages
        cursor.execute("SELECT * FROM messages")
        for row in cursor.fetchall():
            ufdr_data['messages'].append(dict(row))
        
        # Load calls
        cursor.execute("SELECT * FROM call_logs")
        for row in cursor.fetchall():
            ufdr_data['call_logs'].append(dict(row))
        
        # Load locations
        cursor.execute("SELECT * FROM locations")
        for row in cursor.fetchall():
            ufdr_data['locations'].append(dict(row))
        
        # Load chats
        cursor.execute("SELECT * FROM chats")
        for row in cursor.fetchall():
            ufdr_data['chats'].append(dict(row))
        
        # Load chat messages
        cursor.execute("SELECT * FROM chat_messages")
        for row in cursor.fetchall():
            ufdr_data['chat_messages'].append(dict(row))
        
        # Load device metadata
        cursor.execute("SELECT key, value FROM device_metadata WHERE category = 'device'")
        for row in cursor.fetchall():
            ufdr_data['device'][row['key']] = row['value']
        
        # Load files
        cursor.execute("SELECT * FROM files")
        for row in cursor.fetchall():
            ufdr_data['files'].append(dict(row))
        
        # Load media metadata
        cursor.execute("SELECT * FROM media_index WHERE media_type = 'image'")
        for row in cursor.fetchall():
            ufdr_data['images'].append({
                'name': row['filename'],
                'rel_path': row['rel_path'],
                'size': row['size'],
                'extracted': bool(row['extracted'])
            })
        
        cursor.execute("SELECT * FROM media_index WHERE media_type = 'video'")
        for row in cursor.fetchall():
            ufdr_data['videos'].append({
                'name': row['filename'],
                'rel_path': row['rel_path'],
                'size': row['size'],
                'extracted': bool(row['extracted'])
            })
        
        return ufdr_data

