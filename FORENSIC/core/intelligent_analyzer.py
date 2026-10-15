#!/usr/bin/env python3
"""
Intelligent Analyzer - General-purpose analysis framework

Automatically detects query intent and provides structured analysis data
for ranking, statistics, patterns, and relationships - without hardcoding
specific query patterns.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter, defaultdict
import re

logger = logging.getLogger(__name__)


class IntelligentAnalyzer:
    """
    General-purpose analyzer that automatically provides structured analysis
    for queries requiring ranking, statistics, patterns, or relationships.
    """
    
    def __init__(self):
        self.analysis_cache = {}
    
    def analyze_query_intent(self, query: str) -> Dict[str, Any]:
        """
        Analyze query to determine what type of analysis is needed.
        
        Returns:
            {
                'needs_ranking': bool,
                'needs_statistics': bool,
                'needs_patterns': bool,
                'needs_relationships': bool,
                'target_entity': str,  # 'contacts', 'messages', 'calls', 'locations', 'all'
                'analysis_type': str   # 'ranking', 'statistics', 'pattern', 'relationship', 'general'
            }
        """
        query_lower = query.lower()
        
        # Detect ranking queries (top, most, key, main, important, frequent, etc.)
        ranking_keywords = [
            'top', 'most', 'key', 'main', 'important', 'frequent', 'primary',
            'best', 'highest', 'leading', 'major', 'significant', 'critical',
            'rank', 'ranking', 'prioritize', 'order by'
        ]
        needs_ranking = any(kw in query_lower for kw in ranking_keywords)
        
        # Detect statistics queries (count, total, average, how many, etc.)
        statistics_keywords = [
            'count', 'total', 'number of', 'how many', 'statistics', 'stats',
            'average', 'mean', 'sum', 'percentage', 'ratio', 'frequency'
        ]
        needs_statistics = any(kw in query_lower for kw in statistics_keywords)
        
        # Detect pattern queries (pattern, trend, behavior, anomaly, etc.)
        pattern_keywords = [
            'pattern', 'trend', 'behavior', 'anomaly', 'unusual', 'suspicious',
            'regular', 'routine', 'timing', 'frequency pattern', 'communication pattern'
        ]
        needs_patterns = any(kw in query_lower for kw in pattern_keywords)
        
        # Detect relationship queries (relationship, connection, network, between, etc.)
        relationship_keywords = [
            'relationship', 'connection', 'network', 'between', 'link', 'associate',
            'interaction', 'communication', 'contact with', 'related to'
        ]
        needs_relationships = any(kw in query_lower for kw in relationship_keywords)
        
        # Detect target entity
        target_entity = 'all'
        if any(word in query_lower for word in ['contact', 'person', 'people', 'character', 'individual']):
            target_entity = 'contacts'
        elif any(word in query_lower for word in ['message', 'text', 'sms', 'chat', 'whatsapp']):
            target_entity = 'messages'
        elif any(word in query_lower for word in ['call', 'phone call', 'dial']):
            target_entity = 'calls'
        elif any(word in query_lower for word in ['location', 'gps', 'place', 'where']):
            target_entity = 'locations'
        
        # Determine primary analysis type
        if needs_ranking:
            analysis_type = 'ranking'
        elif needs_statistics:
            analysis_type = 'statistics'
        elif needs_patterns:
            analysis_type = 'pattern'
        elif needs_relationships:
            analysis_type = 'relationship'
        else:
            analysis_type = 'general'
        
        return {
            'needs_ranking': needs_ranking,
            'needs_statistics': needs_statistics,
            'needs_patterns': needs_patterns,
            'needs_relationships': needs_relationships,
            'target_entity': target_entity,
            'analysis_type': analysis_type
        }
    
    def generate_analysis(self, ufdr_data: Dict[str, Any], query: str) -> Dict[str, Any]:
        """
        Generate comprehensive analysis based on query intent.
        
        Returns structured analysis data that the LLM can use directly.
        """
        intent = self.analyze_query_intent(query)
        
        analysis = {
            'intent': intent,
            'ranking': {},
            'statistics': {},
            'patterns': {},
            'relationships': {}
        }
        
        # Extract devices data
        devices = []
        if 'devices' in ufdr_data and isinstance(ufdr_data.get('devices'), list):
            devices = ufdr_data['devices']
        elif any(key in ufdr_data for key in ['contacts', 'messages', 'call_logs', 'locations']):
            devices = [ufdr_data]
        
        # Generate ranking if needed
        if intent['needs_ranking']:
            analysis['ranking'] = self._generate_ranking(devices, intent['target_entity'])
        
        # Generate statistics if needed
        if intent['needs_statistics']:
            analysis['statistics'] = self._generate_statistics(devices, intent['target_entity'])
        
        # Generate patterns if needed
        if intent['needs_patterns']:
            analysis['patterns'] = self._generate_patterns(devices)
        
        # Generate relationships if needed
        if intent['needs_relationships']:
            analysis['relationships'] = self._generate_relationships(devices)
        
        return analysis
    
    def _normalize_phone(self, phone: str) -> str:
        """Normalize phone number for matching (remove spaces, dashes, etc.)."""
        if not phone:
            return ''
        # Remove common formatting
        normalized = re.sub(r'[\s\-\(\)]', '', str(phone))
        # Remove leading + if present for comparison
        if normalized.startswith('+'):
            normalized = normalized[1:]
        return normalized
    
    def _find_contact_name(self, phone: str, contact_map: Dict[str, str]) -> str:
        """Find contact name by phone, trying multiple formats."""
        if not phone:
            return 'Unknown'
        
        # Try exact match
        if phone in contact_map:
            return contact_map[phone]
        
        # Try normalized match
        normalized = self._normalize_phone(phone)
        for contact_phone, name in contact_map.items():
            if self._normalize_phone(contact_phone) == normalized:
                return name
        
        # If no match found, return phone number as identifier
        return phone if phone else 'Unknown'
    
    def _find_contact_phone(self, name: str, name_to_phone_map: Dict[str, str]) -> str:
        """Find contact phone by name (for handling messages with names instead of phones)."""
        if not name or name == 'Unknown':
            return ''
        
        # Try exact match
        if name in name_to_phone_map:
            return name_to_phone_map[name]
        
        # Try case-insensitive match
        name_lower = name.lower().strip()
        for contact_name, phone in name_to_phone_map.items():
            if contact_name.lower().strip() == name_lower:
                return phone
        
        return ''
    
    def _is_phone_number(self, value: str) -> bool:
        """Check if a value looks like a phone number (not a name)."""
        if not value:
            return False
        # Remove common formatting
        cleaned = re.sub(r'[\s\-\(\)\+]', '', str(value))
        # Check if it's mostly digits (at least 7 digits for a phone)
        digit_count = sum(1 for c in cleaned if c.isdigit())
        return digit_count >= 7
    
    def _generate_ranking(self, devices: List[Dict], target_entity: str) -> Dict[str, Any]:
        """Generate rankings for contacts, messages, calls, etc."""
        rankings = {
            'contacts_by_interactions': [],
            'contacts_by_messages': [],
            'contacts_by_calls': [],
            'messages_by_frequency': [],
            'calls_by_duration': []
        }
        
        contact_stats = defaultdict(lambda: {
            'name': 'Unknown',
            'phone': '',
            'message_count': 0,
            'call_count': 0,
            'total_interactions': 0,
            'total_call_duration': 0,
            'last_contact': None
        })
        
        message_frequency = Counter()
        call_durations = defaultdict(int)
        
        # Build comprehensive contact maps across all devices first
        # phone → name mapping
        global_contact_map = {}
        # name → phone mapping (for handling messages with names instead of phones)
        name_to_phone_map = {}
        
        for device in devices:
            if not isinstance(device, dict):
                continue
            contacts = device.get('contacts', [])
            for contact in contacts:
                if isinstance(contact, dict):
                    phone = contact.get('phone', '') or contact.get('phone_number', '') or contact.get('mobile', '')
                    name = contact.get('name', '') or contact.get('contact_name', '')
                    if phone and name and name != 'Unknown' and name.strip():
                        # Store phone → name
                        global_contact_map[phone] = name
                        # Also store normalized version
                        normalized = self._normalize_phone(phone)
                        if normalized and normalized != phone:
                            global_contact_map[normalized] = name
                        # Store name → phone (for reverse lookup)
                        name_to_phone_map[name] = phone
                        name_to_phone_map[name.lower().strip()] = phone  # Case-insensitive
                        # Initialize contact stats with phone
                        if phone not in contact_stats:
                            contact_stats[phone]['phone'] = phone
                            contact_stats[phone]['name'] = name
        
        for device in devices:
            if not isinstance(device, dict):
                continue
            
            # Also check root-level contacts (already done above, but ensure we have them)
            contacts = device.get('contacts', [])
            for contact in contacts:
                if isinstance(contact, dict):
                    phone = contact.get('phone', '') or contact.get('phone_number', '') or contact.get('mobile', '')
                    name = contact.get('name', '') or contact.get('contact_name', '')
                    if phone:
                        # Initialize with name if available
                        contact_stats[phone]['phone'] = phone
                        if name and name != 'Unknown' and name.strip():
                            contact_stats[phone]['name'] = name
                            global_contact_map[phone] = name
                            # Also store normalized version
                            normalized = self._normalize_phone(phone)
                            if normalized and normalized != phone:
                                global_contact_map[normalized] = name
            
            # Analyze messages
            messages = device.get('messages', [])
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                
                # Handle multiple field formats (from/to, sender/receiver, chat_contact/chat_phone)
                from_val = msg.get('from', '') or msg.get('sender', '')
                to_val = msg.get('to', '') or msg.get('receiver', '')
                chat_contact = msg.get('chat_contact', '')
                chat_phone = msg.get('chat_phone', '')
                
                text = (msg.get('text', '') or msg.get('content', '')).lower()
                
                # Resolve from/sender - check if it's a name or phone
                from_num = from_val
                from_name = ''
                if from_val:
                    if self._is_phone_number(from_val):
                        # It's a phone number - find the name
                        from_name = self._find_contact_name(from_val, global_contact_map)
                    else:
                        # It's likely a name - find the phone
                        from_name = from_val
                        from_num = self._find_contact_phone(from_val, name_to_phone_map)
                        # If we couldn't find phone, try chat_phone as fallback
                        if not from_num and chat_phone and self._is_phone_number(chat_phone):
                            from_num = chat_phone
                        # If still no phone, use the name as identifier (for stats)
                        if not from_num:
                            from_num = from_val
                
                # Resolve to/receiver - check if it's a name or phone
                to_num = to_val
                to_name = ''
                if to_val:
                    if self._is_phone_number(to_val):
                        # It's a phone number - find the name
                        to_name = self._find_contact_name(to_val, global_contact_map)
                    else:
                        # It's likely a name - find the phone
                        to_name = to_val
                        to_num = self._find_contact_phone(to_val, name_to_phone_map)
                        # If we couldn't find phone, try chat_phone as fallback
                        if not to_num and chat_phone and self._is_phone_number(chat_phone):
                            to_num = chat_phone
                        # If still no phone, use the name as identifier (for stats)
                        if not to_num:
                            to_num = to_val
                
                # Also check chat_contact if we still don't have proper resolution
                if chat_contact and not from_name and not to_name:
                    if self._is_phone_number(chat_contact):
                        # chat_contact is a phone
                        if not from_num:
                            from_num = chat_contact
                            from_name = self._find_contact_name(chat_contact, global_contact_map)
                    else:
                        # chat_contact is a name
                        resolved_phone = self._find_contact_phone(chat_contact, name_to_phone_map)
                        if resolved_phone:
                            if not from_num:
                                from_num = resolved_phone
                                from_name = chat_contact
                
                # Update stats for from/sender
                if from_num:
                    contact_stats[from_num]['message_count'] += 1
                    contact_stats[from_num]['total_interactions'] += 1
                    contact_stats[from_num]['phone'] = from_num
                    if from_name and from_name != 'Unknown':
                        contact_stats[from_num]['name'] = from_name
                    elif not contact_stats[from_num]['name'] or contact_stats[from_num]['name'] == 'Unknown':
                        # Try to find name if we don't have it
                        name = self._find_contact_name(from_num, global_contact_map)
                        if name != 'Unknown':
                            contact_stats[from_num]['name'] = name
                
                # Update stats for to/receiver
                if to_num:
                    contact_stats[to_num]['message_count'] += 1
                    contact_stats[to_num]['total_interactions'] += 1
                    contact_stats[to_num]['phone'] = to_num
                    if to_name and to_name != 'Unknown':
                        contact_stats[to_num]['name'] = to_name
                    elif not contact_stats[to_num]['name'] or contact_stats[to_num]['name'] == 'Unknown':
                        # Try to find name if we don't have it
                        name = self._find_contact_name(to_num, global_contact_map)
                        if name != 'Unknown':
                            contact_stats[to_num]['name'] = name
                
                # Track message frequency patterns
                if text:
                    words = re.findall(r'\b\w{4,}\b', text)  # Words 4+ chars
                    for word in words[:5]:  # Top 5 words per message
                        message_frequency[word] += 1
            
            # Analyze calls
            calls = device.get('call_logs', device.get('calls', []))
            for call in calls:
                if not isinstance(call, dict):
                    continue
                
                from_val = call.get('from', '') or call.get('caller', '')
                to_val = call.get('to', '') or call.get('receiver', '')
                duration = int(call.get('duration', 0) or call.get('call_duration', 0) or 0)
                timestamp = call.get('timestamp', '')
                
                # Resolve from/caller - check if it's a name or phone
                from_num = from_val
                from_name = ''
                if from_val:
                    if self._is_phone_number(from_val):
                        # It's a phone number - find the name
                        from_name = self._find_contact_name(from_val, global_contact_map)
                    else:
                        # It's likely a name - find the phone
                        from_name = from_val
                        from_num = self._find_contact_phone(from_val, name_to_phone_map)
                        # If still no phone, use the name as identifier (for stats)
                        if not from_num:
                            from_num = from_val
                
                # Resolve to/receiver - check if it's a name or phone
                to_num = to_val
                to_name = ''
                if to_val:
                    if self._is_phone_number(to_val):
                        # It's a phone number - find the name
                        to_name = self._find_contact_name(to_val, global_contact_map)
                    else:
                        # It's likely a name - find the phone
                        to_name = to_val
                        to_num = self._find_contact_phone(to_val, name_to_phone_map)
                        # If still no phone, use the name as identifier (for stats)
                        if not to_num:
                            to_num = to_val
                
                # Update stats for from/caller
                if from_num:
                    contact_stats[from_num]['call_count'] += 1
                    contact_stats[from_num]['total_interactions'] += 1
                    contact_stats[from_num]['total_call_duration'] += duration
                    contact_stats[from_num]['phone'] = from_num
                    if timestamp and (not contact_stats[from_num]['last_contact'] or timestamp > contact_stats[from_num]['last_contact']):
                        contact_stats[from_num]['last_contact'] = timestamp
                    if from_name and from_name != 'Unknown':
                        contact_stats[from_num]['name'] = from_name
                    elif not contact_stats[from_num]['name'] or contact_stats[from_num]['name'] == 'Unknown':
                        # Try to find name if we don't have it
                        name = self._find_contact_name(from_num, global_contact_map)
                        if name != 'Unknown':
                            contact_stats[from_num]['name'] = name
                
                # Update stats for to/receiver
                if to_num:
                    contact_stats[to_num]['call_count'] += 1
                    contact_stats[to_num]['total_interactions'] += 1
                    contact_stats[to_num]['total_call_duration'] += duration
                    contact_stats[to_num]['phone'] = to_num
                    if timestamp and (not contact_stats[to_num]['last_contact'] or timestamp > contact_stats[to_num]['last_contact']):
                        contact_stats[to_num]['last_contact'] = timestamp
                    if to_name and to_name != 'Unknown':
                        contact_stats[to_num]['name'] = to_name
                    elif not contact_stats[to_num]['name'] or contact_stats[to_num]['name'] == 'Unknown':
                        # Try to find name if we don't have it
                        name = self._find_contact_name(to_num, global_contact_map)
                        if name != 'Unknown':
                            contact_stats[to_num]['name'] = name
                
                # Track call durations
                if duration > 0:
                    call_durations[from_num] += duration
                    call_durations[to_num] += duration
        
        # Rank contacts by total interactions
        ranked_by_interactions = sorted(
            contact_stats.items(),
            key=lambda x: x[1]['total_interactions'],
            reverse=True
        )[:20]
        
        rankings['contacts_by_interactions'] = [
            {
                'name': stats['name'] if stats['name'] != 'Unknown' else (stats['phone'] if stats['phone'] else 'Unknown Contact'),
                'phone': stats['phone'] if stats['phone'] else phone,
                'total_interactions': stats['total_interactions'],
                'message_count': stats['message_count'],
                'call_count': stats['call_count'],
                'last_contact': stats['last_contact']
            }
            for phone, stats in ranked_by_interactions
            if stats['total_interactions'] > 0
        ]
        
        # Rank contacts by messages
        ranked_by_messages = sorted(
            contact_stats.items(),
            key=lambda x: x[1]['message_count'],
            reverse=True
        )[:20]
        
        rankings['contacts_by_messages'] = [
            {
                'name': stats['name'] if stats['name'] != 'Unknown' else (stats['phone'] if stats['phone'] else 'Unknown Contact'),
                'phone': stats['phone'] if stats['phone'] else phone,
                'message_count': stats['message_count']
            }
            for phone, stats in ranked_by_messages
            if stats['message_count'] > 0
        ]
        
        # Rank contacts by calls
        ranked_by_calls = sorted(
            contact_stats.items(),
            key=lambda x: x[1]['call_count'],
            reverse=True
        )[:20]
        
        rankings['contacts_by_calls'] = [
            {
                'name': stats['name'] if stats['name'] != 'Unknown' else (stats['phone'] if stats['phone'] else 'Unknown Contact'),
                'phone': stats['phone'] if stats['phone'] else phone,
                'call_count': stats['call_count'],
                'total_duration': stats['total_call_duration']
            }
            for phone, stats in ranked_by_calls
            if stats['call_count'] > 0
        ]
        
        # Top message keywords
        rankings['messages_by_frequency'] = [
            {'word': word, 'frequency': count}
            for word, count in message_frequency.most_common(20)
        ]
        
        return rankings
    
    def _generate_statistics(self, devices: List[Dict], target_entity: str) -> Dict[str, Any]:
        """Generate statistics for the data."""
        stats = {
            'total_contacts': 0,
            'total_messages': 0,
            'total_calls': 0,
            'total_locations': 0,
            'unique_contacts': set(),
            'date_range': {'earliest': None, 'latest': None}
        }
        
        for device in devices:
            if not isinstance(device, dict):
                continue
            
            stats['total_contacts'] += len(device.get('contacts', []))
            stats['total_messages'] += len(device.get('messages', []))
            stats['total_calls'] += len(device.get('call_logs', device.get('calls', [])))
            stats['total_locations'] += len(device.get('locations', []))
            
            # Track unique contacts
            for contact in device.get('contacts', []):
                if isinstance(contact, dict):
                    phone = contact.get('phone', '')
                    if phone:
                        stats['unique_contacts'].add(phone)
            
            # Track date range
            all_timestamps = []
            for msg in device.get('messages', []):
                if isinstance(msg, dict) and msg.get('timestamp'):
                    all_timestamps.append(msg['timestamp'])
            for call in device.get('call_logs', device.get('calls', [])):
                if isinstance(call, dict) and call.get('timestamp'):
                    all_timestamps.append(call['timestamp'])
            
            if all_timestamps:
                if not stats['date_range']['earliest'] or min(all_timestamps) < stats['date_range']['earliest']:
                    stats['date_range']['earliest'] = min(all_timestamps)
                if not stats['date_range']['latest'] or max(all_timestamps) > stats['date_range']['latest']:
                    stats['date_range']['latest'] = max(all_timestamps)
        
        stats['unique_contacts'] = len(stats['unique_contacts'])
        
        return stats
    
    def _generate_patterns(self, devices: List[Dict]) -> Dict[str, Any]:
        """Generate communication patterns."""
        patterns = {
            'time_patterns': defaultdict(int),
            'day_patterns': defaultdict(int),
            'communication_frequency': defaultdict(int)
        }
        
        for device in devices:
            if not isinstance(device, dict):
                continue
            
            for msg in device.get('messages', []):
                if isinstance(msg, dict) and msg.get('timestamp'):
                    timestamp = msg['timestamp']
                    # Extract hour
                    if 'T' in timestamp:
                        try:
                            hour = int(timestamp.split('T')[1].split(':')[0])
                            patterns['time_patterns'][hour] += 1
                        except:
                            pass
            
            # Analyze communication frequency per contact
            contact_freq = Counter()
            for msg in device.get('messages', []):
                if isinstance(msg, dict):
                    from_num = msg.get('from', '')
                    to_num = msg.get('to', '')
                    if from_num:
                        contact_freq[from_num] += 1
                    if to_num:
                        contact_freq[to_num] += 1
            
            patterns['communication_frequency'] = dict(contact_freq.most_common(20))
        
        return patterns
    
    def _generate_relationships(self, devices: List[Dict]) -> Dict[str, Any]:
        """Generate relationship network."""
        relationships = {
            'network': defaultdict(set),
            'strong_relationships': []
        }
        
        for device in devices:
            if not isinstance(device, dict):
                continue
            
            device_owner = None
            device_info = device.get('device', {})
            if device_info:
                device_owner = device_info.get('owner_name', device_info.get('owner'))
            
            # Build relationship network
            for msg in device.get('messages', []):
                if isinstance(msg, dict):
                    from_num = msg.get('from', '')
                    to_num = msg.get('to', '')
                    if from_num and to_num:
                        relationships['network'][from_num].add(to_num)
                        relationships['network'][to_num].add(from_num)
                        if device_owner:
                            relationships['network'][device_owner].add(from_num)
                            relationships['network'][device_owner].add(to_num)
            
            for call in device.get('call_logs', device.get('calls', [])):
                if isinstance(call, dict):
                    from_num = call.get('from', '')
                    to_num = call.get('to', '')
                    if from_num and to_num:
                        relationships['network'][from_num].add(to_num)
                        relationships['network'][to_num].add(from_num)
                        if device_owner:
                            relationships['network'][device_owner].add(from_num)
                            relationships['network'][device_owner].add(to_num)
        
        # Find strong relationships (contacts with many connections)
        for contact, connections in relationships['network'].items():
            if len(connections) >= 5:  # Threshold for strong relationship
                relationships['strong_relationships'].append({
                    'contact': contact,
                    'connection_count': len(connections)
                })
        
        relationships['strong_relationships'].sort(
            key=lambda x: x['connection_count'],
            reverse=True
        )
        
        return relationships
    
    def format_analysis_for_llm(self, analysis: Dict[str, Any], query: str) -> str:
        """Format analysis results for LLM consumption."""
        intent = analysis['intent']
        formatted = []
        
        formatted.append("=== INTELLIGENT ANALYSIS RESULTS ===")
        formatted.append(f"Query Intent: {intent['analysis_type']}")
        formatted.append(f"Target Entity: {intent['target_entity']}")
        formatted.append("")
        
        # Add ranking data
        if analysis.get('ranking'):
            rankings = analysis['ranking']
            formatted.append("📊 RANKINGS:")
            
            if rankings.get('contacts_by_interactions'):
                formatted.append("\nTop Contacts by Total Interactions:")
                for i, contact in enumerate(rankings['contacts_by_interactions'][:15], 1):
                    # Ensure we have a name - use phone as fallback if name is missing
                    name = contact.get('name', '')
                    if not name or name == 'Unknown' or name == 'Unknown Contact':
                        name = contact.get('phone', 'Unknown Contact')
                    phone = contact.get('phone', 'N/A')
                    formatted.append(
                        f"  {i}. {name} (Phone: {phone}) - "
                        f"{contact['total_interactions']} interactions "
                        f"({contact['message_count']} messages, {contact['call_count']} calls)"
                    )
                formatted.append("")
        
        # Add statistics
        if analysis.get('statistics'):
            stats = analysis['statistics']
            formatted.append("📈 STATISTICS:")
            formatted.append(f"  Total Contacts: {stats['total_contacts']}")
            formatted.append(f"  Unique Contacts: {stats['unique_contacts']}")
            formatted.append(f"  Total Messages: {stats['total_messages']}")
            formatted.append(f"  Total Calls: {stats['total_calls']}")
            formatted.append(f"  Total Locations: {stats['total_locations']}")
            if stats['date_range']['earliest']:
                formatted.append(f"  Date Range: {stats['date_range']['earliest']} to {stats['date_range']['latest']}")
            formatted.append("")
        
        # Add relationships
        if analysis.get('relationships'):
            rels = analysis['relationships']
            if rels.get('strong_relationships'):
                formatted.append("🔗 STRONG RELATIONSHIPS:")
                for rel in rels['strong_relationships'][:10]:
                    formatted.append(f"  {rel['contact']}: {rel['connection_count']} connections")
                formatted.append("")
        
        return "\n".join(formatted)


# Global instance
intelligent_analyzer = IntelligentAnalyzer()

