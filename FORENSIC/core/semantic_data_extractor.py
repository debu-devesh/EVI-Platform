#!/usr/bin/env python3
"""
Semantic Data Extractor - Magnet AXIOM Style

Uses semantic search to extract ALL relevant data chunks based on query.
No arbitrary limits - extracts everything relevant to the query.

Key Features:
- Semantic search using embeddings (FAISS)
- Query-aware extraction
- Complete chunks (no truncation)
- All relevant data, not just top 8
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


class SemanticDataExtractor:
    """
    Semantic-aware data extractor that uses embeddings to find ALL relevant data.
    
    Philosophy: Extract everything relevant to the query, not just a sample.
    """
    
    def __init__(self, rag_engine=None, similarity_threshold: float = 0.3):
        """
        Initialize semantic extractor.
        
        Args:
            rag_engine: UFDRRAGEngine instance (optional, will create if needed)
            similarity_threshold: Minimum similarity score (0.0-1.0) to include chunk
        """
        self.rag_engine = rag_engine
        self.similarity_threshold = similarity_threshold
        self._data_index = {}  # Index of all data for fast lookup
    
    def extract_relevant_data(self, ufdr_data: Dict[str, Any], query: str) -> str:
        """
        Extract ALL relevant data using semantic search.
        
        Args:
            ufdr_data: Full UFDR data
            query: User query
            
        Returns:
            Formatted context with ALL relevant chunks
        """
        if not query or not isinstance(query, str):
            query = ""
        
        query_lower = query.lower()
        context_parts = []
        
        # Build data index if not exists
        self._build_data_index(ufdr_data)
        
        # Check if query is about a specific person/entity
        entity_info = self._extract_entity_info(query, ufdr_data)
        if entity_info:
            context_parts.append("\n=== ENTITY-SPECIFIC INFORMATION ===")
            context_parts.append(entity_info)
            logger.info(f"✅ Entity-specific information extracted for query: {query[:50]}...")
        
        # Check if query is about device metadata
        is_device_query = any(word in query_lower for word in [
            'device', 'imei', 'phone model', 'device model', 'metadata', 'device info',
            'owner', 'manufacturer', 'android version', 'extraction', 'serial number',
            'storage', 'battery', 'root', 'encryption', 'phone number'
        ])
        
        # Use intelligent analyzer for automatic analysis
        from core.intelligent_analyzer import intelligent_analyzer
        try:
            analysis = intelligent_analyzer.generate_analysis(ufdr_data, query)
            intent = analysis.get('intent', {})
            
            # If analysis is needed (ranking, statistics, patterns, relationships), include it
            if (intent.get('needs_ranking') or intent.get('needs_statistics') or 
                intent.get('needs_patterns') or intent.get('needs_relationships')):
                formatted_analysis = intelligent_analyzer.format_analysis_for_llm(analysis, query)
                context_parts.append(formatted_analysis)
                logger.info(f"✅ Intelligent analysis generated: {intent.get('analysis_type', 'general')}")
        except Exception as e:
            logger.warning(f"Error in intelligent analysis: {e}", exc_info=True)
        
        # If device query, extract device metadata first
        if is_device_query:
            device_metadata = self._extract_device_metadata(ufdr_data)
            if device_metadata:
                context_parts.append("\n=== DEVICE METADATA ===")
                context_parts.append(device_metadata)
                logger.info("✅ Device metadata extracted")
        
        # Use semantic search if RAG engine is available
        if self.rag_engine and self.rag_engine.is_ready():
            logger.info(f"🔍 Using semantic search for query: {query[:50]}...")
            relevant_chunks = self._semantic_search(query, ufdr_data)
            
            if relevant_chunks:
                context_parts.append(f"\n=== SEMANTICALLY RELEVANT DATA ({len(relevant_chunks)} chunks) ===")
                context_parts.extend(self._format_chunks(relevant_chunks))
                logger.info(f"✅ Found {len(relevant_chunks)} relevant chunks via semantic search")
        else:
            # Diagnose why RAG is not available
            if not self.rag_engine:
                logger.warning("⚠️ RAG engine not initialized, falling back to keyword-based extraction")
            elif not self.rag_engine.available:
                logger.warning("⚠️ RAG engine dependencies missing (numpy, faiss, or sentence-transformers), falling back to keyword-based extraction")
                logger.warning("⚠️ Install with: pip install numpy faiss-cpu sentence-transformers")
            elif not self.rag_engine.is_ready():
                logger.warning("⚠️ RAG index not built yet (no data or index build failed), falling back to keyword-based extraction")
            else:
                logger.warning("⚠️ RAG engine not available, falling back to keyword-based extraction")
            
            # Fallback to keyword-based extraction (but without limits)
            relevant_chunks = self._keyword_based_extraction(query, ufdr_data)
            context_parts.extend(self._format_chunks(relevant_chunks))
        
        # Add summary
        summary = self._generate_summary(ufdr_data, len(relevant_chunks) if relevant_chunks else 0)
        context_parts.insert(0, summary)
        
        return "\n".join(context_parts)
    
    def _build_data_index(self, ufdr_data: Dict[str, Any]):
        """Build index of all data for fast lookup."""
        # Always rebuild to ensure fresh data (don't cache across uploads)
        # Reset index to force fresh build
        self._data_index = {
            'contacts': [],
            'messages': [],
            'calls': [],
            'locations': [],
            'files': [],
            'device_info': []
        }
        
        self._data_index = {
            'contacts': [],
            'messages': [],
            'calls': [],
            'locations': [],
            'files': [],
            'device_info': []  # NEW: Index device metadata
        }
        
        # Extract devices data
        devices = []
        if 'devices' in ufdr_data and isinstance(ufdr_data.get('devices'), list):
            devices = ufdr_data['devices']
        elif any(key in ufdr_data for key in ['contacts', 'messages', 'call_logs', 'locations']):
            devices = [ufdr_data]
        
        for device in devices:
            if not isinstance(device, dict):
                continue
            
            # Extract and index device metadata
            device_info = device.get('device', {})
            if not device_info:
                # Try to extract from root level
                device_info = {
                    'owner_name': device.get('owner_name', device.get('owner', 'Unknown')),
                    'device_make': device.get('device_make', device.get('device_model', device.get('model', 'Unknown'))),
                    'imei': device.get('imei', 'N/A'),
                    'phone_number': device.get('phone_number', device.get('phone', 'N/A')),
                    'device_model': device.get('device_model', device.get('model', 'Unknown')),
                    'manufacturer': device.get('manufacturer', 'Unknown'),
                    'android_version': device.get('android_version', 'N/A'),
                    'extraction_method': device.get('extraction_method', 'N/A'),
                    'extraction_tool': device.get('extraction_tool', 'N/A'),
                    'extraction_time': device.get('extraction_time', 'N/A'),
                    'extraction_officer': device.get('extraction_officer', 'N/A'),
                    'device_serial': device.get('device_serial', 'N/A'),
                    'storage_total': device.get('storage_total', 'N/A'),
                    'storage_used': device.get('storage_used', 'N/A'),
                    'battery_level': device.get('battery_level', 'N/A'),
                    'root_status': device.get('root_status', 'N/A'),
                    'encryption_status': device.get('encryption_status', 'N/A')
                }
            
            # Only add if we have meaningful device info
            if device_info.get('owner_name') != 'Unknown' or device_info.get('device_make') != 'Unknown':
                self._data_index['device_info'].append(device_info)
            
            # Index all contacts
            contacts = device.get('contacts', [])
            if isinstance(contacts, list):
                self._data_index['contacts'].extend(contacts)
            
            # Index all messages
            messages = device.get('messages', [])
            if isinstance(messages, list):
                self._data_index['messages'].extend(messages)
            
            # Index all calls
            calls = device.get('call_logs', device.get('calls', []))
            if isinstance(calls, list):
                self._data_index['calls'].extend(calls)
            
            # Index all locations
            locations = device.get('locations', [])
            if isinstance(locations, list):
                self._data_index['locations'].extend(locations)
            
            # Index all files
            files = device.get('files', [])
            if isinstance(files, list):
                self._data_index['files'].extend(files)
        
        # Also check root level
        if 'contacts' in ufdr_data:
            self._data_index['contacts'].extend(ufdr_data.get('contacts', []))
        if 'messages' in ufdr_data:
            self._data_index['messages'].extend(ufdr_data.get('messages', []))
        if 'call_logs' in ufdr_data:
            self._data_index['calls'].extend(ufdr_data.get('call_logs', []))
        if 'locations' in ufdr_data:
            self._data_index['locations'].extend(ufdr_data.get('locations', []))
        
        # Check root level for device info
        if 'device' in ufdr_data and isinstance(ufdr_data.get('device'), dict):
            self._data_index['device_info'].append(ufdr_data['device'])
    
    def _semantic_search(self, query: str, ufdr_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Use RAG engine to find semantically relevant chunks.
        Returns ALL chunks above similarity threshold.
        """
        if not self.rag_engine or not self.rag_engine.is_ready():
            return []
        
        # Query RAG engine with limited k for forensic reliability
        # Hard limit: 50 records max to prevent hallucination
        k = min(50, len(self.rag_engine.chunks))  # Hard limit: 50 most relevant
        rag_results = self.rag_engine.query(query, k=k)
        
        if not rag_results.get('matches'):
            return []
        
        # Filter by similarity threshold and get full data
        relevant_chunks = []
        for match in rag_results['matches']:
            score = match.get('score', 0.0)
            if score >= self.similarity_threshold:
                # Get full data from index (not truncated)
                full_chunk = self._get_full_chunk(match, ufdr_data)
                if full_chunk:
                    full_chunk['similarity_score'] = score
                    relevant_chunks.append(full_chunk)
        
        # Sort by similarity score (highest first)
        relevant_chunks.sort(key=lambda x: x.get('similarity_score', 0), reverse=True)
        
        # CRITICAL: Hard limit to 50 chunks for forensic reliability
        if len(relevant_chunks) > 50:
            logger.info(f"⚠️ Limiting extracted chunks from {len(relevant_chunks)} to 50 (forensic reliability)")
            relevant_chunks = relevant_chunks[:50]
        
        return relevant_chunks
    
    def _get_full_chunk(self, match: Dict[str, Any], ufdr_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get full, untruncated chunk data from the match."""
        chunk_type = match.get('type', '')
        source_file = match.get('source_file', '')
        
        # Get data from the file
        file_data = ufdr_data.get(source_file, {})
        if not file_data:
            # Try to find in devices
            devices = ufdr_data.get('devices', [])
            if devices and isinstance(devices, list) and len(devices) > 0:
                file_data = devices[0]
        
        # Also check root level data
        if not file_data or (isinstance(file_data, dict) and not file_data.get('messages') and not file_data.get('contacts')):
            # Try root level
            if 'contacts' in ufdr_data or 'messages' in ufdr_data:
                file_data = ufdr_data
        
        if chunk_type == 'message':
            # Find the full message
            messages = file_data.get('messages', [])
            from_num = match.get('from')
            timestamp = match.get('timestamp')
            text_preview = match.get('text', '')[:50]  # First 50 chars for matching
            
            for msg in messages:
                if (msg.get('from') == from_num and 
                    msg.get('timestamp') == timestamp and
                    (msg.get('text', '') or msg.get('content', '')).startswith(text_preview)):
                    return {
                        'type': 'message',
                        'data': msg,
                        'source_file': source_file
                    }
        
        elif chunk_type == 'contact':
            # Find the full contact
            contacts = file_data.get('contacts', [])
            name = match.get('name')
            phone = match.get('phone')
            
            for contact in contacts:
                if (contact.get('name') == name and 
                    contact.get('phone') == phone):
                    return {
                        'type': 'contact',
                        'data': contact,
                        'source_file': source_file
                    }
        
        elif chunk_type == 'call':
            # Find the full call
            calls = file_data.get('call_logs', file_data.get('calls', []))
            from_num = match.get('from')
            timestamp = match.get('timestamp')
            
            for call in calls:
                if (call.get('from') == from_num and 
                    call.get('timestamp') == timestamp):
                    return {
                        'type': 'call',
                        'data': call,
                        'source_file': source_file
                    }
        
        elif chunk_type == 'location':
            # Find the full location
            locations = file_data.get('locations', [])
            timestamp = match.get('timestamp')
            lat = match.get('latitude')
            
            for location in locations:
                if (location.get('timestamp') == timestamp and
                    location.get('latitude') == lat):
                    return {
                        'type': 'location',
                        'data': location,
                        'source_file': source_file
                    }
        
        # Fallback: return match as-is (might be truncated but better than nothing)
        return {
            'type': chunk_type,
            'data': match,
            'source_file': source_file
        }
    
    def _keyword_based_extraction(self, query: str, ufdr_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Fallback: Keyword-based extraction without limits.
        Extracts ALL items that match query keywords.
        """
        query_lower = query.lower()
        query_words = set(query_lower.split())
        relevant_chunks = []
        
        # Extract all matching contacts
        for contact in self._data_index.get('contacts', []):
            score = self._calculate_keyword_score(contact, query_words, 'contact')
            if score > 0:
                relevant_chunks.append({
                    'type': 'contact',
                    'data': contact,
                    'score': score
                })
        
        # Extract all matching messages
        for message in self._data_index.get('messages', []):
            score = self._calculate_keyword_score(message, query_words, 'message')
            if score > 0:
                relevant_chunks.append({
                    'type': 'message',
                    'data': message,
                    'score': score
                })
        
        # Extract all matching calls
        for call in self._data_index.get('calls', []):
            score = self._calculate_keyword_score(call, query_words, 'call')
            if score > 0:
                relevant_chunks.append({
                    'type': 'call',
                    'data': call,
                    'score': score
                })
        
        # Extract all matching locations
        for location in self._data_index.get('locations', []):
            score = self._calculate_keyword_score(location, query_words, 'location')
            if score > 0:
                relevant_chunks.append({
                    'type': 'location',
                    'data': location,
                    'score': score
                })
        
        # Sort by score
        relevant_chunks.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        # CRITICAL: Hard limit to 50 chunks for forensic reliability
        if len(relevant_chunks) > 50:
            logger.info(f"⚠️ Limiting keyword-based chunks from {len(relevant_chunks)} to 50 (forensic reliability)")
            relevant_chunks = relevant_chunks[:50]
        
        return relevant_chunks
    
    def _calculate_keyword_score(self, item: Dict[str, Any], query_words: set, item_type: str) -> float:
        """Calculate keyword match score for an item."""
        if not isinstance(item, dict):
            return 0.0
        
        score = 0.0
        item_text = ""
        
        if item_type == 'contact':
            item_text = f"{item.get('name', '')} {item.get('phone', '')} {item.get('email', '')}".lower()
        elif item_type == 'message':
            item_text = f"{item.get('text', '')} {item.get('from', '')} {item.get('to', '')}".lower()
        elif item_type == 'call':
            item_text = f"{item.get('from', '')} {item.get('to', '')} {item.get('call_type', '')}".lower()
        elif item_type == 'location':
            item_text = f"{item.get('address', '')} {item.get('location_name', '')}".lower()
        
        # Count matching words
        item_words = set(item_text.split())
        matches = query_words.intersection(item_words)
        score = len(matches) * 2.0
        
        # Boost for exact phrase matches
        query_phrase = ' '.join(query_words)
        if query_phrase in item_text:
            score += 10.0
        
        return score
    
    def _build_contact_map(self) -> Dict[str, str]:
        """Build phone-to-name mapping from contacts index."""
        contact_map = {}  # phone -> name
        
        # Build from data index contacts
        for contact in self._data_index.get('contacts', []):
            if not isinstance(contact, dict):
                continue
            
            phone = contact.get('phone', '') or contact.get('phone_number', '') or contact.get('mobile', '')
            name = contact.get('name', '') or contact.get('contact_name', '')
            
            if phone and name and name != 'Unknown' and name.strip():
                # Store phone → name
                contact_map[phone] = name
                # Also store normalized version (remove spaces, dashes, etc.)
                normalized = self._normalize_phone(phone)
                if normalized and normalized != phone:
                    contact_map[normalized] = name
        
        return contact_map
    
    def _normalize_phone(self, phone: str) -> str:
        """Normalize phone number for matching (remove spaces, dashes, etc.)."""
        if not phone:
            return ''
        # Remove common formatting
        import re
        normalized = re.sub(r'[\s\-\(\)]', '', str(phone))
        return normalized
    
    def _resolve_phone_to_name(self, phone: str, contact_map: Dict[str, str]) -> str:
        """Resolve phone number to contact name."""
        if not phone or phone == 'Unknown':
            return phone
        
        # Try exact match
        if phone in contact_map:
            return contact_map[phone]
        
        # Try normalized match
        normalized = self._normalize_phone(phone)
        if normalized in contact_map:
            return contact_map[normalized]
        
        # Try reverse lookup (in case phone is stored differently)
        for stored_phone, name in contact_map.items():
            if self._normalize_phone(stored_phone) == normalized:
                return name
        
        # Return phone if no match found
        return phone
    
    def _format_chunks(self, chunks: List[Dict[str, Any]]) -> List[str]:
        """Format chunks for LLM consumption (complete, untruncated)."""
        formatted = []
        
        # Build contact map for phone-to-name resolution
        contact_map = self._build_contact_map()
        
        # Group by type
        by_type = defaultdict(list)
        for chunk in chunks:
            chunk_type = chunk.get('type', 'unknown')
            by_type[chunk_type].append(chunk)
        
        # Format each type
        for chunk_type, type_chunks in by_type.items():
            if chunk_type == 'message':
                formatted.append(f"\n📨 MESSAGES ({len(type_chunks)} relevant):")
                for chunk in type_chunks:
                    msg = chunk.get('data', {})
                    timestamp = msg.get('timestamp', 'Unknown')
                    from_num = msg.get('from', 'Unknown')
                    to_num = msg.get('to', 'Unknown')
                    text = msg.get('text', msg.get('content', ''))
                    source = msg.get('source', 'Unknown')
                    score = chunk.get('similarity_score', chunk.get('score', 0))
                    
                    # Resolve phone numbers to names
                    from_name = self._resolve_phone_to_name(from_num, contact_map)
                    to_name = self._resolve_phone_to_name(to_num, contact_map)
                    
                    # Format: Show name if resolved, otherwise show phone
                    from_display = from_name if from_name != from_num else from_num
                    to_display = to_name if to_name != to_num else to_num
                    
                    # NO TRUNCATION - full message text (complete, untruncated)
                    formatted.append(f"  - [{timestamp}] {from_display} → {to_display} ({source}): {text}")
                    if score > 0:
                        formatted.append(f"    [Relevance Score: {score:.3f}]")
            
            elif chunk_type == 'contact':
                formatted.append(f"\n👤 CONTACTS ({len(type_chunks)} relevant):")
                for chunk in type_chunks:
                    contact = chunk.get('data', {})
                    name = contact.get('name', 'Unknown')
                    phone = contact.get('phone', 'N/A')
                    email = contact.get('email', '')
                    score = chunk.get('similarity_score', chunk.get('score', 0))
                    
                    contact_info = f"  - {name} - {phone}"
                    if email:
                        contact_info += f" ({email})"
                    formatted.append(contact_info)
                    if score > 0:
                        formatted.append(f"    [Relevance: {score:.2f}]")
            
            elif chunk_type == 'call':
                formatted.append(f"\n📞 CALLS ({len(type_chunks)} relevant):")
                for chunk in type_chunks:
                    call = chunk.get('data', {})
                    timestamp = call.get('timestamp', 'Unknown')
                    from_num = call.get('from', 'Unknown')
                    to_num = call.get('to', 'Unknown')
                    duration = call.get('duration', 'N/A')
                    call_type = call.get('call_type', 'unknown')
                    score = chunk.get('similarity_score', chunk.get('score', 0))
                    
                    # Resolve phone numbers to names
                    from_name = self._resolve_phone_to_name(from_num, contact_map)
                    to_name = self._resolve_phone_to_name(to_num, contact_map)
                    
                    # Format: Show name if resolved, otherwise show phone
                    from_display = from_name if from_name != from_num else from_num
                    to_display = to_name if to_name != to_num else to_num
                    
                    formatted.append(f"  - [{timestamp}] {from_display} → {to_display} ({call_type}, {duration}s)")
                    if score > 0:
                        formatted.append(f"    [Relevance: {score:.2f}]")
            
            elif chunk_type == 'location':
                formatted.append(f"\n📍 LOCATIONS ({len(type_chunks)} relevant):")
                for chunk in type_chunks:
                    location = chunk.get('data', {})
                    timestamp = location.get('timestamp', 'Unknown')
                    address = location.get('address', 'Unknown')
                    lat = location.get('latitude', 'N/A')
                    lon = location.get('longitude', 'N/A')
                    location_name = location.get('location_name', '')
                    score = chunk.get('similarity_score', chunk.get('score', 0))
                    
                    loc_info = f"  - [{timestamp}] {location_name or 'Unknown Location'}"
                    if address:
                        loc_info += f" - {address}"
                    loc_info += f" (GPS: {lat}, {lon})"
                    formatted.append(loc_info)
                    if score > 0:
                        formatted.append(f"    [Relevance: {score:.2f}]")
        
        return formatted
    
    def _extract_entity_info(self, query: str, ufdr_data: Dict[str, Any]) -> Optional[str]:
        """
        Extract all information about a specific person/entity mentioned in query.
        
        Detects queries like "about sahil", "who is arjun", "tell me about priya", 
        "Sahil's involvement", "context of Sahil", "investigating Sahil", etc.
        """
        query_lower = query.lower()
        
        # Build contact map first to extract names
        contact_map = self._build_contact_map()
        all_contact_names = [name.lower() for name in contact_map.values() if name and name != 'Unknown']
        
        # Detect entity queries (expanded patterns)
        entity_keywords = ['about', 'who is', 'tell me about', 'information about', 'details about', 
                          'what about', 'regarding', 'concerning', 'involvement', 'context of',
                          'investigating', 'investigate', 'analysis of', 'analyze']
        
        # Check if query mentions any contact name (even without explicit keywords)
        entity_name = None
        for contact_name in all_contact_names:
            # Check for possessive form (X's) or direct mention
            if contact_name in query_lower or f"{contact_name}'s" in query_lower:
                # Find the full name from contact map
                for phone, name in contact_map.items():
                    if name.lower() == contact_name:
                        entity_name = name
                        break
                if entity_name:
                    break
        
        # If no name found, try keyword-based extraction
        if not entity_name:
            is_entity_query = any(keyword in query_lower for keyword in entity_keywords)
            if not is_entity_query:
                return None
            
            # Extract potential entity name from query
            for keyword in entity_keywords:
                if keyword in query_lower:
                    # Extract text after keyword
                    parts = query_lower.split(keyword, 1)
                    if len(parts) > 1:
                        potential_name = parts[1].strip()
                        # Remove common words and possessive markers
                        stop_words = ['the', 'a', 'an', 'is', 'are', 'was', 'were', 'his', 'her', 'their', 
                                     'in', 'these', 'this', 'that', 'those', 'involvement', 'context', 
                                     'discussions', 'conversations']
                        words = [w.rstrip("'s").rstrip("'") for w in potential_name.split() if w.lower() not in stop_words]
                        if words:
                            potential_entity = ' '.join(words[:3])  # Take first 1-3 words as name
                            # Check if this matches any contact name
                            for contact_name in all_contact_names:
                                if potential_entity.lower() in contact_name or contact_name in potential_entity.lower():
                                    # Find full name
                                    for phone, name in contact_map.items():
                                        if name.lower() == contact_name:
                                            entity_name = name
                                            break
                                    if entity_name:
                                        break
                            if not entity_name:
                                entity_name = potential_entity
                            break
        
        if not entity_name or len(entity_name) < 2:
            return None
        
        # Build contact map
        contact_map = self._build_contact_map()
        name_to_phone_map = {name.lower(): phone for phone, name in contact_map.items()}
        
        # Find matching contact (case-insensitive, partial match)
        matching_contact = None
        matching_phone = None
        
        for contact in self._data_index.get('contacts', []):
            if not isinstance(contact, dict):
                continue
            
            name = contact.get('name', '') or contact.get('contact_name', '')
            phone = contact.get('phone', '') or contact.get('phone_number', '') or contact.get('mobile', '')
            
            if name and entity_name.lower() in name.lower():
                matching_contact = contact
                matching_phone = phone
                entity_name = name  # Use full name from contact
                break
        
        # If no exact match, try finding by phone if entity_name looks like a phone
        if not matching_contact and self._is_phone_number(entity_name):
            matching_phone = entity_name
            matching_contact = contact_map.get(matching_phone)
            if matching_contact:
                # Find full contact info
                for contact in self._data_index.get('contacts', []):
                    if contact.get('phone', '') == matching_phone:
                        matching_contact = contact
                        entity_name = contact.get('name', matching_phone)
                        break
        
        if not matching_contact and not matching_phone:
            return None
        
        # Extract all information about this entity
        entity_parts = []
        
        # Contact information
        if matching_contact:
            entity_parts.append(f"\n👤 CONTACT INFORMATION:")
            name = matching_contact.get('name', 'Unknown')
            phone = matching_contact.get('phone', 'N/A')
            email = matching_contact.get('email', '')
            relationship = matching_contact.get('relationship', '')
            notes = matching_contact.get('notes', '')
            
            entity_parts.append(f"  Name: {name}")
            entity_parts.append(f"  Phone: {phone}")
            if email:
                entity_parts.append(f"  Email: {email}")
            if relationship:
                entity_parts.append(f"  Relationship: {relationship}")
            if notes:
                entity_parts.append(f"  Notes: {notes}")
        elif matching_phone:
            entity_parts.append(f"\n👤 CONTACT INFORMATION:")
            entity_parts.append(f"  Phone: {matching_phone}")
            if matching_phone in contact_map:
                entity_parts.append(f"  Name: {contact_map[matching_phone]}")
        
        # Find all messages involving this entity
        entity_phone = matching_phone or (matching_contact.get('phone', '') if matching_contact else '')
        if entity_phone:
            messages_involving = []
            messages_mentioning = []
            
            for msg in self._data_index.get('messages', []):
                if not isinstance(msg, dict):
                    continue
                
                from_num = msg.get('from', '')
                to_num = msg.get('to', '')
                text = (msg.get('text', '') or msg.get('content', '')).lower()
                
                # Check if message involves this entity
                if from_num == entity_phone or to_num == entity_phone:
                    messages_involving.append(msg)
                # Check if message mentions entity name
                elif entity_name.lower() in text:
                    messages_mentioning.append(msg)
            
            if messages_involving:
                entity_parts.append(f"\n📨 MESSAGES INVOLVING THIS ENTITY ({len(messages_involving)} total):")
                # Show first 10 most recent
                for msg in sorted(messages_involving, key=lambda x: x.get('timestamp', ''), reverse=True)[:10]:
                    timestamp = msg.get('timestamp', 'Unknown')
                    from_num = msg.get('from', 'Unknown')
                    to_num = msg.get('to', 'Unknown')
                    text = msg.get('text', msg.get('content', ''))
                    source = msg.get('source', 'Unknown')
                    
                    # Resolve names
                    contact_map_local = self._build_contact_map()
                    from_name = self._resolve_phone_to_name(from_num, contact_map_local)
                    to_name = self._resolve_phone_to_name(to_num, contact_map_local)
                    
                    from_display = from_name if from_name != from_num else from_num
                    to_display = to_name if to_name != to_num else to_num
                    
                    entity_parts.append(f"  - [{timestamp}] {from_display} → {to_display} ({source}): {text[:100]}...")
            
            if messages_mentioning:
                entity_parts.append(f"\n📨 MESSAGES MENTIONING '{entity_name}' ({len(messages_mentioning)} total):")
                # Show first 5 most recent
                for msg in sorted(messages_mentioning, key=lambda x: x.get('timestamp', ''), reverse=True)[:5]:
                    timestamp = msg.get('timestamp', 'Unknown')
                    from_num = msg.get('from', 'Unknown')
                    to_num = msg.get('to', 'Unknown')
                    text = msg.get('text', msg.get('content', ''))
                    source = msg.get('source', 'Unknown')
                    
                    # Resolve names
                    contact_map_local = self._build_contact_map()
                    from_name = self._resolve_phone_to_name(from_num, contact_map_local)
                    to_name = self._resolve_phone_to_name(to_num, contact_map_local)
                    
                    from_display = from_name if from_name != from_num else from_num
                    to_display = to_name if to_name != to_num else to_num
                    
                    entity_parts.append(f"  - [{timestamp}] {from_display} → {to_display} ({source}): {text[:100]}...")
            
            # Find all calls involving this entity
            calls_involving = []
            for call in self._data_index.get('calls', []):
                if not isinstance(call, dict):
                    continue
                
                from_num = call.get('from', '')
                to_num = call.get('to', '')
                
                if from_num == entity_phone or to_num == entity_phone:
                    calls_involving.append(call)
            
            if calls_involving:
                entity_parts.append(f"\n📞 CALLS INVOLVING THIS ENTITY ({len(calls_involving)} total):")
                # Show first 10 most recent
                for call in sorted(calls_involving, key=lambda x: x.get('timestamp', ''), reverse=True)[:10]:
                    timestamp = call.get('timestamp', 'Unknown')
                    from_num = call.get('from', 'Unknown')
                    to_num = call.get('to', 'Unknown')
                    duration = call.get('duration', 'N/A')
                    call_type = call.get('call_type', 'unknown')
                    
                    # Resolve names
                    contact_map_local = self._build_contact_map()
                    from_name = self._resolve_phone_to_name(from_num, contact_map_local)
                    to_name = self._resolve_phone_to_name(to_num, contact_map_local)
                    
                    from_display = from_name if from_name != from_num else from_num
                    to_display = to_name if to_name != to_num else to_num
                    
                    entity_parts.append(f"  - [{timestamp}] {from_display} → {to_display} ({call_type}, {duration}s)")
            
            # Build relationship network
            if messages_involving or calls_involving:
                connected_phones = set()
                for msg in messages_involving:
                    from_num = msg.get('from', '')
                    to_num = msg.get('to', '')
                    if from_num == entity_phone:
                        connected_phones.add(to_num)
                    elif to_num == entity_phone:
                        connected_phones.add(from_num)
                
                for call in calls_involving:
                    from_num = call.get('from', '')
                    to_num = call.get('to', '')
                    if from_num == entity_phone:
                        connected_phones.add(to_num)
                    elif to_num == entity_phone:
                        connected_phones.add(from_num)
                
                if connected_phones:
                    entity_parts.append(f"\n🔗 DIRECT CONNECTIONS ({len(connected_phones)} contacts):")
                    contact_map_local = self._build_contact_map()
                    for phone in sorted(connected_phones)[:20]:  # Show first 20
                        name = self._resolve_phone_to_name(phone, contact_map_local)
                        entity_parts.append(f"  - {name}")
        
        if entity_parts:
            return '\n'.join(entity_parts)
        
        return None
    
    def _is_phone_number(self, value: str) -> bool:
        """Check if a string looks like a phone number."""
        if not value:
            return False
        # Remove common formatting
        digits = ''.join(c for c in value if c.isdigit())
        return len(digits) >= 7  # At least 7 digits
    
    def _generate_summary(self, ufdr_data: Dict[str, Any], relevant_count: int) -> str:
        """Generate summary of available data."""
        total_contacts = len(self._data_index.get('contacts', []))
        total_messages = len(self._data_index.get('messages', []))
        total_calls = len(self._data_index.get('calls', []))
        total_locations = len(self._data_index.get('locations', []))
        
        summary = f"FORENSIC DATA SUMMARY: {total_contacts} contacts, {total_messages} messages, {total_calls} calls, {total_locations} locations"
        if relevant_count > 0:
            summary += f"\n✅ SEMANTIC SEARCH: Found {relevant_count} relevant chunks (showing ALL, no limits)"
        else:
            summary += f"\n⚠️ Using keyword-based extraction (RAG engine not available)"
        
        return summary


# Global instance (will be initialized with RAG engine in web_interface)
semantic_extractor = None

