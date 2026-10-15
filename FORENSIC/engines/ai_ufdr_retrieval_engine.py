#!/usr/bin/env python3
"""
AI-Powered UFDR Data Retrieval Engine

An intelligent system that can understand natural language queries and retrieve
relevant information from UFDR files by analyzing device metadata, contacts,
messages, files, and other forensic data with semantic understanding.
"""

import json
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class RetrievalResult:
    """Structured result from AI-powered data retrieval."""
    query: str
    matches: List[Dict[str, Any]]
    confidence: float
    data_sources: List[str]
    semantic_mappings: Dict[str, str]
    summary: str
    recommendations: List[str]

class SemanticMapper:
    """Maps natural language queries to UFDR data fields."""
    
    def __init__(self):
        """Initialize semantic mappings for common forensic queries."""
        self.field_mappings = {
            # Owner and device information
            'owner': ['device.owner_name', 'device.registered_user', 'device.primary_user'],
            'owner name': ['device.owner_name', 'device.registered_user', 'device.primary_user'],
            'device owner': ['device.owner_name', 'device.registered_user'],
            'registered user': ['device.registered_user', 'device.owner_name'],
            'account holder': ['device.owner_name', 'device.account_holder', 'device.subscriber'],
            'subscriber': ['device.subscriber', 'device.owner_name'],
            
            # Device information
            'device': ['device.device_make', 'device.device_model', 'device.device_id'],
            'phone number': ['device.phone_number', 'device.primary_number'],
            'device id': ['device.device_id', 'device.serial_number'],
            'imei': ['device.imei', 'device.device_id'],
            
            # Contact information
            'contact': ['contacts.name', 'contacts.phone', 'contacts.email'],
            'contact name': ['contacts.name', 'contacts.display_name'],
            'phone': ['contacts.phone', 'device.phone_number'],
            'email': ['contacts.email', 'device.email'],
            
            # Communication data
            'message': ['messages.text', 'messages.content', 'messages.body'],
            'call': ['call_logs.direction', 'call_logs.duration', 'call_logs.number'],
            'conversation': ['messages.text', 'messages.conversation_id'],
            
            # File and media
            'file': ['files.filename', 'files.path', 'files.content'],
            'document': ['files.filename', 'files.content', 'files.type'],
            'photo': ['files.filename', 'files.type', 'media.filename'],
            'image': ['files.filename', 'files.type', 'media.filename'],
            
            # Temporal information
            'time': ['messages.timestamp', 'call_logs.timestamp', 'files.created_time'],
            'date': ['messages.timestamp', 'call_logs.timestamp', 'files.created_time'],
            'recent': ['messages.timestamp', 'call_logs.timestamp'],
            
            # Location information
            'location': ['location.latitude', 'location.longitude', 'location.address'],
            'address': ['location.address', 'contacts.address'],
            'gps': ['location.latitude', 'location.longitude'],
        }
        
        # Synonyms and variations
        self.synonyms = {
            'name': ['owner', 'user', 'holder', 'subscriber'],
            'phone': ['number', 'mobile', 'cell', 'telephone'],
            'message': ['text', 'sms', 'chat', 'communication'],
            'file': ['document', 'attachment', 'media'],
            'contact': ['person', 'individual', 'entity'],
        }

    def map_query_to_fields(self, query: str) -> Dict[str, List[str]]:
        """Map a natural language query to UFDR data fields."""
        query_lower = query.lower().strip()
        mapped_fields = {}
        
        # Direct mapping
        for term, fields in self.field_mappings.items():
            if term in query_lower:
                mapped_fields[term] = fields
        
        # Synonym mapping
        for word in query_lower.split():
            for base_term, synonyms in self.synonyms.items():
                if word in synonyms and base_term in self.field_mappings:
                    mapped_fields[word] = self.field_mappings[base_term]
        
        return mapped_fields

class AIUFDRRetrievalEngine:
    """AI-powered engine for intelligent UFDR data retrieval."""
    
    def __init__(self, ufdr_data: Dict[str, Any]):
        """Initialize the AI retrieval engine with UFDR data."""
        self.ufdr_data = ufdr_data
        self.semantic_mapper = SemanticMapper()
        self.data_index = self._build_comprehensive_index()
        
    def _build_comprehensive_index(self) -> Dict[str, Any]:
        """Build a comprehensive searchable index of all UFDR data."""
        index = {
            'devices': [],
            'contacts': [],
            'messages': [],
            'calls': [],
            'files': [],
            'locations': [],
            'metadata': []
        }
        
        for file_key, file_data in self.ufdr_data.items():
            if not isinstance(file_data, dict):
                continue

            # v2 format: devices array
            if 'devices' in file_data and isinstance(file_data['devices'], list):
                for device in file_data['devices']:
                    if not isinstance(device, dict):
                        continue

                    # Device info
                    if 'device' in device and isinstance(device['device'], dict):
                        device_info = device['device'].copy()
                        device_info['source_file'] = file_key
                        index['devices'].append(device_info)
                    owner_name = device.get('device', {}).get('owner_name', 'Unknown')

                    # Contacts
                    for contact in device.get('contacts', []) or []:
                        if isinstance(contact, dict):
                            contact_info = contact.copy()
                            contact_info['source_file'] = file_key
                            contact_info['device_owner'] = owner_name
                            index['contacts'].append(contact_info)

                    # Messages
                    for message in device.get('messages', []) or []:
                        if isinstance(message, dict):
                            message_info = message.copy()
                            message_info['source_file'] = file_key
                            message_info['device_owner'] = owner_name
                            index['messages'].append(message_info)

                    # Calls
                    for call in device.get('call_logs', []) or []:
                        if isinstance(call, dict):
                            call_info = call.copy()
                            call_info['source_file'] = file_key
                            call_info['device_owner'] = owner_name
                            index['calls'].append(call_info)

                    # Files
                    for file_item in device.get('files', []) or []:
                        if isinstance(file_item, dict):
                            file_info = file_item.copy()
                            file_info['source_file'] = file_key
                            file_info['device_owner'] = owner_name
                            index['files'].append(file_info)
            else:
                # v1 flat format: contacts, messages, call_logs, files, device
                owner_name = (file_data.get('device') or {}).get('owner_name', 'Unknown')

                if isinstance(file_data.get('device'), dict):
                    dev_info = file_data['device'].copy()
                    dev_info['source_file'] = file_key
                    index['devices'].append(dev_info)

                for contact in file_data.get('contacts', []) or []:
                    if isinstance(contact, dict):
                        c = contact.copy()
                        c['source_file'] = file_key
                        c['device_owner'] = owner_name
                        index['contacts'].append(c)

                for message in file_data.get('messages', []) or []:
                    if isinstance(message, dict):
                        m = message.copy()
                        m['source_file'] = file_key
                        m['device_owner'] = owner_name
                        index['messages'].append(m)

                for call in file_data.get('call_logs', []) or []:
                    if isinstance(call, dict):
                        cinfo = call.copy()
                        cinfo['source_file'] = file_key
                        cinfo['device_owner'] = owner_name
                        index['calls'].append(cinfo)

                for file_item in file_data.get('files', []) or []:
                    if isinstance(file_item, dict):
                        finfo = file_item.copy()
                        finfo['source_file'] = file_key
                        finfo['device_owner'] = owner_name
                        index['files'].append(finfo)
        
        return index
    
    def intelligent_search(self, query: str, limit: int = 50) -> RetrievalResult:
        """Perform intelligent search using AI-powered understanding."""
        logger.info(f"AI Retrieval: Processing query '{query}'")
        
        # Map query to data fields
        field_mappings = self.semantic_mapper.map_query_to_fields(query)
        
        matches = []
        data_sources = set()
        confidence = 0.0
        
        # Search based on semantic mappings
        if field_mappings:
            matches, data_sources, confidence = self._search_by_mappings(query, field_mappings, limit)
        else:
            # Fallback to general search
            matches, data_sources, confidence = self._general_intelligent_search(query, limit)
        
        # Generate summary and recommendations
        summary = self._generate_summary(query, matches, field_mappings)
        recommendations = self._generate_recommendations(query, matches, field_mappings)
        
        return RetrievalResult(
            query=query,
            matches=matches,
            confidence=confidence,
            data_sources=list(data_sources),
            semantic_mappings=field_mappings,
            summary=summary,
            recommendations=recommendations
        )
    
    def _search_by_mappings(self, query: str, field_mappings: Dict[str, List[str]], limit: int) -> Tuple[List[Dict], set, float]:
        """Search using semantic field mappings."""
        matches = []
        data_sources = set()
        confidence = 0.8  # High confidence for mapped searches
        
        query_terms = query.lower().split()
        
        for mapped_term, field_paths in field_mappings.items():
            for field_path in field_paths:
                category, field = field_path.split('.', 1) if '.' in field_path else (field_path, None)
                
                if category in self.data_index:
                    for item in self.data_index[category]:
                        match_found = False
                        match_details = {
                            'source': category,
                            'data': item,
                            'matched_field': field_path,
                            'matched_term': mapped_term,
                            'relevance_score': 0.0
                        }
                        
                        if field and field in item:
                            # Direct field match
                            field_value = str(item[field]).lower()
                            if any(term in field_value for term in query_terms):
                                match_details['relevance_score'] = 0.9
                                match_found = True
                        elif not field:
                            # Search all fields in the item
                            for key, value in item.items():
                                if isinstance(value, (str, int, float)):
                                    value_str = str(value).lower()
                                    if any(term in value_str for term in query_terms):
                                        match_details['relevance_score'] = 0.7
                                        match_details['matched_field'] = f"{category}.{key}"
                                        match_found = True
                                        break
                        
                        if match_found:
                            matches.append(match_details)
                            data_sources.add(item.get('source_file', 'unknown'))
                            
                            if len(matches) >= limit:
                                break
                
                if len(matches) >= limit:
                    break
        
        return matches[:limit], data_sources, confidence
    
    def _general_intelligent_search(self, query: str, limit: int) -> Tuple[List[Dict], set, float]:
        """Perform general intelligent search across all data."""
        matches = []
        data_sources = set()
        confidence = 0.5  # Lower confidence for general search
        
        query_terms = [term.lower() for term in query.split()]
        
        # Search across all indexed data
        for category, items in self.data_index.items():
            for item in items:
                relevance_score = self._calculate_relevance(item, query_terms)
                
                if relevance_score > 0.3:  # Threshold for relevance
                    matches.append({
                        'source': category,
                        'data': item,
                        'matched_field': 'general_search',
                        'matched_term': query,
                        'relevance_score': relevance_score
                    })
                    data_sources.add(item.get('source_file', 'unknown'))
        
        # Sort by relevance score
        matches.sort(key=lambda x: x['relevance_score'], reverse=True)
        
        return matches[:limit], data_sources, confidence
    
    def _calculate_relevance(self, item: Dict[str, Any], query_terms: List[str]) -> float:
        """Calculate relevance score for an item against query terms."""
        score = 0.0
        total_fields = 0
        
        for key, value in item.items():
            if isinstance(value, (str, int, float)):
                total_fields += 1
                value_str = str(value).lower()
                
                # Exact matches get higher scores
                for term in query_terms:
                    if term == value_str:
                        score += 1.0
                    elif term in value_str:
                        score += 0.5
                    elif any(word in value_str for word in term.split()):
                        score += 0.3
        
        # Normalize score
        return score / max(total_fields, 1) if total_fields > 0 else 0.0
    
    def _generate_summary(self, query: str, matches: List[Dict], field_mappings: Dict[str, List[str]]) -> str:
        """Generate an intelligent summary of search results."""
        if not matches:
            return f"No results found for '{query}'. The AI system searched across device metadata, contacts, messages, calls, and files but found no relevant information."
        
        # Analyze match distribution
        source_counts = defaultdict(int)
        for match in matches:
            source_counts[match['source']] += 1
        
        summary_parts = [
            f"Found {len(matches)} relevant results for '{query}'."
        ]
        
        # Add source distribution
        if source_counts:
            source_info = []
            for source, count in source_counts.items():
                source_info.append(f"{count} from {source}")
            summary_parts.append(f"Results include: {', '.join(source_info)}.")
        
        # Add semantic mapping info
        if field_mappings:
            mapped_fields = []
            for term, fields in field_mappings.items():
                mapped_fields.extend(fields)
            summary_parts.append(f"AI mapped your query to data fields: {', '.join(set(mapped_fields))}.")
        
        return " ".join(summary_parts)
    
    def _generate_recommendations(self, query: str, matches: List[Dict], field_mappings: Dict[str, List[str]]) -> List[str]:
        """Generate intelligent recommendations for further investigation."""
        recommendations = []
        
        if not matches:
            recommendations.extend([
                "Try searching for related terms (e.g., 'user', 'subscriber', 'account holder' instead of 'owner')",
                "Check if the data contains device registration information",
                "Search for contact names or phone numbers associated with the device",
                "Try broader terms like 'device information' or 'account details'"
            ])
        else:
            # Analyze what was found to suggest related searches
            found_sources = set(match['source'] for match in matches)
            
            if 'devices' in found_sources:
                recommendations.append("Search for related device information like 'phone number', 'device ID', or 'registration details'")
            
            if 'contacts' in found_sources:
                recommendations.append("Explore contact relationships and communication patterns")
            
            if 'messages' in found_sources:
                recommendations.append("Analyze message content for additional context and relationships")
            
            # Suggest expanding the search
            if len(matches) == 1:
                recommendations.append("Try related queries to find more information about this entity")
            elif len(matches) > 20:
                recommendations.append("Consider refining your search with more specific terms")
        
        return recommendations

    def get_owner_information(self) -> List[Dict[str, Any]]:
        """Get all device owner information from the UFDR data."""
        owners = []
        
        for device_info in self.data_index['devices']:
            if 'owner_name' in device_info:
                owners.append({
                    'owner_name': device_info['owner_name'],
                    'device_id': device_info.get('device_id', 'Unknown'),
                    'phone_number': device_info.get('phone_number', 'Unknown'),
                    'device_make': device_info.get('device_make', 'Unknown'),
                    'source_file': device_info.get('source_file', 'Unknown')
                })
        
        return owners

    def search_device_metadata(self, query: str) -> List[Dict[str, Any]]:
        """Specifically search device metadata for owner and registration information."""
        results = []
        query_lower = query.lower()
        
        for device_info in self.data_index['devices']:
            match_score = 0
            matched_fields = []
            
            # Check all device fields
            for key, value in device_info.items():
                if isinstance(value, (str, int, float)):
                    value_str = str(value).lower()
                    if query_lower in value_str:
                        match_score += 1
                        matched_fields.append(key)
            
            if match_score > 0:
                results.append({
                    'device_info': device_info,
                    'match_score': match_score,
                    'matched_fields': matched_fields
                })
        
        # Sort by match score
        results.sort(key=lambda x: x['match_score'], reverse=True)
        return results