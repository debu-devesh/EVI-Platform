#!/usr/bin/env python3
"""
Key Characters Analyzer

Identifies and ranks the most important contacts/characters in a forensic investigation
based on communication frequency, relationship strength, and involvement in key events.
"""

import logging
from typing import Dict, List, Any, Tuple
from collections import Counter, defaultdict

logger = logging.getLogger(__name__)


class KeyCharactersAnalyzer:
    """Analyzes UFDR data to identify key characters/contacts."""
    
    def __init__(self):
        self.contact_stats = {}
        self.relationship_network = defaultdict(set)
    
    def analyze_key_characters(self, ufdr_data: Dict[str, Any], top_n: int = 10) -> Dict[str, Any]:
        """
        Analyze and rank key characters based on multiple factors.
        
        Args:
            ufdr_data: UFDR data dictionary
            top_n: Number of top characters to return
            
        Returns:
            Dictionary with ranked characters and analysis
        """
        # Reset stats
        self.contact_stats = {}
        self.relationship_network = defaultdict(set)
        
        # Extract devices data
        devices = []
        if 'devices' in ufdr_data and isinstance(ufdr_data.get('devices'), list):
            devices = ufdr_data['devices']
        elif any(key in ufdr_data for key in ['contacts', 'messages', 'call_logs', 'locations']):
            devices = [ufdr_data]
        
        # Analyze all devices
        for device in devices:
            if not isinstance(device, dict):
                continue
            self._analyze_device(device)
        
        # Also check root level
        if 'contacts' in ufdr_data or 'messages' in ufdr_data:
            self._analyze_device(ufdr_data)
        
        # Rank characters by importance score
        ranked_characters = self._rank_characters(top_n)
        
        return {
            'total_characters': len(self.contact_stats),
            'ranked_characters': ranked_characters,
            'summary': self._generate_summary(ranked_characters)
        }
    
    def _analyze_device(self, device: Dict[str, Any]):
        """Analyze a single device's data."""
        # Get device owner (if available)
        device_owner = None
        device_info = device.get('device', {})
        if device_info:
            device_owner = device_info.get('owner_name', device_info.get('owner'))
        
        # Analyze contacts
        contacts = device.get('contacts', [])
        for contact in contacts:
            if not isinstance(contact, dict):
                continue
            name = contact.get('name', 'Unknown')
            phone = contact.get('phone', '')
            email = contact.get('email', '')
            
            # Initialize contact stats
            contact_key = name if name != 'Unknown' else phone
            if not contact_key:
                continue
            
            if contact_key not in self.contact_stats:
                self.contact_stats[contact_key] = {
                    'name': name,
                    'phone': phone,
                    'email': email,
                    'message_count': 0,
                    'call_count': 0,
                    'total_interactions': 0,
                    'last_contact': None,
                    'first_contact': None,
                    'suspicious_keywords': [],
                    'relationship_strength': 0
                }
        
        # Analyze messages
        messages = device.get('messages', [])
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            
            from_num = msg.get('from', '')
            to_num = msg.get('to', '')
            timestamp = msg.get('timestamp', '')
            text = (msg.get('text', '') or msg.get('content', '')).lower()
            
            # Update stats for sender
            if from_num:
                contact_key = self._find_contact_key(from_num, contacts)
                if contact_key:
                    self.contact_stats[contact_key]['message_count'] += 1
                    self.contact_stats[contact_key]['total_interactions'] += 1
                    self._update_timestamps(contact_key, timestamp)
                    self._check_suspicious_keywords(contact_key, text)
                    if device_owner:
                        self.relationship_network[device_owner].add(contact_key)
                        self.relationship_network[contact_key].add(device_owner)
            
            # Update stats for receiver
            if to_num:
                contact_key = self._find_contact_key(to_num, contacts)
                if contact_key:
                    self.contact_stats[contact_key]['message_count'] += 1
                    self.contact_stats[contact_key]['total_interactions'] += 1
                    self._update_timestamps(contact_key, timestamp)
                    if device_owner:
                        self.relationship_network[device_owner].add(contact_key)
                        self.relationship_network[contact_key].add(device_owner)
        
        # Analyze calls
        calls = device.get('call_logs', device.get('calls', []))
        for call in calls:
            if not isinstance(call, dict):
                continue
            
            from_num = call.get('from', '')
            to_num = call.get('to', '')
            timestamp = call.get('timestamp', '')
            duration = call.get('duration', 0)
            
            # Update stats for caller
            if from_num:
                contact_key = self._find_contact_key(from_num, contacts)
                if contact_key:
                    self.contact_stats[contact_key]['call_count'] += 1
                    self.contact_stats[contact_key]['total_interactions'] += 1
                    self._update_timestamps(contact_key, timestamp)
                    if device_owner:
                        self.relationship_network[device_owner].add(contact_key)
                        self.relationship_network[contact_key].add(device_owner)
            
            # Update stats for receiver
            if to_num:
                contact_key = self._find_contact_key(to_num, contacts)
                if contact_key:
                    self.contact_stats[contact_key]['call_count'] += 1
                    self.contact_stats[contact_key]['total_interactions'] += 1
                    self._update_timestamps(contact_key, timestamp)
                    if device_owner:
                        self.relationship_network[device_owner].add(contact_key)
                        self.relationship_network[contact_key].add(device_owner)
    
    def _find_contact_key(self, phone_or_name: str, contacts: List[Dict]) -> str:
        """Find contact key (name or phone) from phone number or name."""
        if not phone_or_name:
            return None
        
        # First try to find by phone
        for contact in contacts:
            if isinstance(contact, dict):
                if contact.get('phone') == phone_or_name:
                    name = contact.get('name', '')
                    return name if name and name != 'Unknown' else phone_or_name
        
        # Try to find by name
        for contact in contacts:
            if isinstance(contact, dict):
                if contact.get('name') == phone_or_name:
                    return phone_or_name
        
        # If not found, use the phone/name as-is
        return phone_or_name
    
    def _update_timestamps(self, contact_key: str, timestamp: str):
        """Update first and last contact timestamps."""
        if not timestamp:
            return
        
        stats = self.contact_stats[contact_key]
        if not stats['last_contact'] or timestamp > stats['last_contact']:
            stats['last_contact'] = timestamp
        if not stats['first_contact'] or timestamp < stats['first_contact']:
            stats['first_contact'] = timestamp
    
    def _check_suspicious_keywords(self, contact_key: str, text: str):
        """Check for suspicious keywords in messages."""
        if not text:
            return
        
        suspicious_keywords = [
            'weapon', 'gun', 'drug', 'money', 'transfer', 'payment', 'package',
            'meet', 'secret', 'confidential', 'delete', 'hide', 'evidence',
            'police', 'investigation', 'threat', 'kill', 'murder', 'crime'
        ]
        
        text_lower = text.lower()
        for keyword in suspicious_keywords:
            if keyword in text_lower:
                if keyword not in self.contact_stats[contact_key]['suspicious_keywords']:
                    self.contact_stats[contact_key]['suspicious_keywords'].append(keyword)
    
    def _rank_characters(self, top_n: int) -> List[Dict[str, Any]]:
        """Rank characters by importance score."""
        ranked = []
        
        for contact_key, stats in self.contact_stats.items():
            # Calculate importance score
            importance_score = (
                stats['total_interactions'] * 2 +  # Base score from interactions
                stats['message_count'] * 1.5 +     # Messages weighted
                stats['call_count'] * 2.0 +        # Calls weighted more
                len(stats['suspicious_keywords']) * 10 +  # Suspicious activity boost
                len(self.relationship_network.get(contact_key, set())) * 0.5  # Network connections
            )
            
            ranked.append({
                'name': stats['name'],
                'phone': stats['phone'],
                'email': stats['email'],
                'importance_score': round(importance_score, 2),
                'total_interactions': stats['total_interactions'],
                'message_count': stats['message_count'],
                'call_count': stats['call_count'],
                'last_contact': stats['last_contact'],
                'first_contact': stats['first_contact'],
                'suspicious_keywords': stats['suspicious_keywords'],
                'relationship_connections': len(self.relationship_network.get(contact_key, set()))
            })
        
        # Sort by importance score
        ranked.sort(key=lambda x: x['importance_score'], reverse=True)
        
        return ranked[:top_n]
    
    def _generate_summary(self, ranked_characters: List[Dict[str, Any]]) -> str:
        """Generate summary of key characters."""
        if not ranked_characters:
            return "No key characters identified in the data."
        
        summary_parts = []
        for i, char in enumerate(ranked_characters[:5], 1):
            name = char['name'] if char['name'] != 'Unknown' else char['phone']
            summary_parts.append(
                f"{i}. {name}: {char['total_interactions']} total interactions "
                f"({char['message_count']} messages, {char['call_count']} calls)"
            )
        
        return "\n".join(summary_parts)


# Global instance
key_characters_analyzer = KeyCharactersAnalyzer()

