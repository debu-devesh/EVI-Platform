#!/usr/bin/env python3
"""
Query Analyzer - Detects query complexity and intent for adaptive responses
"""

import re
from typing import Dict, List, Tuple, Optional


class QueryAnalyzer:
    """Analyzes user queries to determine complexity and intent."""
    
    # Simple query patterns - direct factual questions
    SIMPLE_PATTERNS = [
        r'\b(how many|count|total|number of|list|show|display|get)\b',
        r'\b(what is|what are|who is|who are)\b',
        r'^\s*(how many|count|list|show)\s+',
        r'\b(all|every|each)\s+(contact|message|call)\b',
    ]
    
    # Complex query patterns - require analysis
    COMPLEX_PATTERNS = [
        r'\b(analyze|analysis|pattern|relationship|network|timeline|sequence)\b',
        r'\b(suspicious|anomaly|unusual|fraud|scam|threat|security)\b',
        r'\b(correlation|connection|link|associate|involve)\b',
        r'\b(recommend|suggest|investigate|examine|evaluate)\b',
        r'\b(trend|frequency|behavior|activity|pattern)\b',
    ]
    
    # Query intent keywords
    INTENT_KEYWORDS = {
        'contact': ['contact', 'name', 'phone', 'who', 'people', 'person', 'caller'],
        'message': ['message', 'text', 'sms', 'chat', 'whatsapp', 'said', 'conversation', 'communication'],
        'call': ['call', 'dial', 'phone', 'ring', 'spoke', 'duration', 'incoming', 'outgoing'],
        'location': ['location', 'gps', 'coordinates', 'latitude', 'longitude', 'where', 'place', 'address', 'map', 'geolocation'],
        'device': ['device', 'imei', 'phone model', 'device model', 'metadata', 'device info', 'owner', 'manufacturer', 'android version', 'extraction', 'serial number', 'storage', 'battery', 'root', 'encryption', 'phone number', 'device metadata', 'device specifications'],
        'timeline': ['when', 'time', 'date', 'timeline', 'sequence', 'chronological', 'order'],
        'relationship': ['relationship', 'connection', 'network', 'associate', 'link', 'between'],
        'pattern': ['pattern', 'frequency', 'trend', 'behavior', 'activity', 'regular'],
        'suspicious': ['suspicious', 'fraud', 'scam', 'threat', 'anomaly', 'unusual', 'illegal'],
        'statistics': ['most', 'least', 'top', 'bottom', 'average', 'total', 'count', 'statistics'],
    }
    
    def __init__(self):
        """Initialize the query analyzer."""
        self.simple_regex = re.compile('|'.join(self.SIMPLE_PATTERNS), re.IGNORECASE)
        self.complex_regex = re.compile('|'.join(self.COMPLEX_PATTERNS), re.IGNORECASE)
    
    def analyze_query(self, query: str) -> Dict[str, any]:
        """
        Analyze a query to determine complexity, intent, and required response style.
        
        Args:
            query: User query string
            
        Returns:
            Dictionary with:
            - complexity: 'simple', 'medium', or 'complex'
            - intent: List of detected intents
            - data_types: List of data types needed (contacts, messages, calls)
            - response_style: Recommended response style
        """
        if not query or not isinstance(query, str):
            query = ""
        
        query_lower = query.lower().strip()
        
        # Detect complexity
        complexity = self._detect_complexity(query_lower)
        
        # Detect intent
        intent = self._detect_intent(query_lower)
        
        # Detect required data types
        data_types = self._detect_data_types(query_lower)
        
        # Determine response style
        response_style = self._determine_response_style(complexity, intent)
        
        return {
            'complexity': complexity,
            'intent': intent,
            'data_types': data_types,
            'response_style': response_style,
            'query_length': len(query),
            'is_statistical': 'statistics' in intent,
            'is_exploratory': complexity == 'complex' and 'pattern' in intent,
        }
    
    def _detect_complexity(self, query: str) -> str:
        """Detect query complexity level."""
        # Check for complex patterns first
        if self.complex_regex.search(query):
            return 'complex'
        
        # Check for simple patterns
        if self.simple_regex.search(query):
            # But if it's a long query with multiple parts, it might be medium
            if len(query.split()) > 8:
                return 'medium'
            return 'simple'
        
        # Default to medium for ambiguous queries
        return 'medium'
    
    def _detect_intent(self, query: str) -> List[str]:
        """Detect what the user is trying to find."""
        detected_intents = []
        
        for intent_type, keywords in self.INTENT_KEYWORDS.items():
            if any(keyword in query for keyword in keywords):
                detected_intents.append(intent_type)
        
        # If no specific intent detected, default to exploratory
        if not detected_intents:
            detected_intents.append('exploratory')
        
        return detected_intents
    
    def _detect_data_types(self, query: str) -> List[str]:
        """Detect which data types are needed for the query."""
        data_types = []
        
        if any(word in query for word in ['contact', 'name', 'phone', 'who', 'people', 'person', 'caller']):
            data_types.append('contacts')
        
        if any(word in query for word in ['message', 'text', 'sms', 'chat', 'whatsapp', 'said', 'conversation']):
            data_types.append('messages')
        
        if any(word in query for word in ['call', 'dial', 'phone', 'ring', 'spoke', 'duration']):
            data_types.append('calls')
        
        if any(word in query for word in ['location', 'gps', 'coordinates', 'latitude', 'longitude', 'where', 'place', 'address', 'map']):
            data_types.append('locations')
        
        # If no specific type mentioned, include all
        if not data_types:
            data_types = ['contacts', 'messages', 'calls', 'locations']
        
        return data_types
    
    def _determine_response_style(self, complexity: str, intent: List[str]) -> str:
        """Determine the appropriate response style."""
        if complexity == 'simple':
            return 'direct'
        elif complexity == 'medium':
            if 'statistics' in intent:
                return 'summary_with_evidence'
            return 'summary_with_evidence'
        else:  # complex
            return 'full_analysis'
    
    def needs_actual_data(self, query: str) -> bool:
        """Determine if query needs actual data extraction vs just counts."""
        # Queries that need actual data
        needs_data_keywords = [
            'show', 'display', 'list', 'find', 'what', 'who', 'when', 'where',
            'message', 'text', 'said', 'content', 'details', 'specific'
        ]
        
        return any(keyword in query.lower() for keyword in needs_data_keywords)
    
    def is_follow_up_question(self, query: str, chat_history: Optional[List] = None) -> bool:
        """Detect if this is a follow-up question."""
        query_lower = query.lower().strip()
        
        # Explicit follow-up indicators
        follow_up_indicators = [
            'also', 'and', 'what about', 'how about', 'tell me more', 'more about',
            'more', 'another', 'other', 'additionally', 'further', 'more details',
            'expand', 'elaborate', 'continue', 'what else', 'anything else',
            'same', 'similar', 'related', 'regarding', 'concerning', 'about that'
        ]
        
        if any(indicator in query_lower for indicator in follow_up_indicators):
            return True
        
        # Check if query is very short and there's history (likely follow-up)
        if chat_history and len(chat_history) > 0:
            if len(query.split()) <= 3:
                return True
            
            # Check for pronouns/references that suggest follow-up
            reference_words = ['it', 'that', 'this', 'them', 'those', 'these', 'he', 'she', 'they']
            if any(word in query_lower.split() for word in reference_words):
                return True
        
        return False
    
    def detect_query_qualifiers(self, query: str) -> Dict[str, bool]:
        """
        Detect qualifiers in the query that indicate response style requirements.
        
        Returns:
            Dictionary with qualifier flags:
            - brief: User wants brief/short answer
            - simple: User wants simple answer
            - just: User wants only what was asked
            - detailed: User wants detailed answer
            - comprehensive: User wants comprehensive answer
        """
        query_lower = query.lower().strip()
        
        qualifiers = {
            'brief': any(word in query_lower for word in ['brief', 'briefly', 'short', 'quick', 'quickly', 'summarize', 'summary']),
            'simple': any(word in query_lower for word in ['simple', 'simply', 'basic', 'basically']),
            'just': any(word in query_lower for word in ['just', 'only', 'solely', 'exactly']),
            'detailed': any(word in query_lower for word in ['detailed', 'detail', 'details', 'full', 'complete', 'comprehensive', 'thorough']),
            'comprehensive': any(word in query_lower for word in ['comprehensive', 'thorough', 'complete', 'full', 'extensive', 'in-depth']),
        }
        
        return qualifiers
    
    def extract_specific_intent(self, query: str) -> Dict[str, any]:
        """
        Extract the specific intent from the query - what exactly is the user asking for.
        
        Returns:
            Dictionary with:
            - primary_intent: Main thing user is asking for
            - scope: What scope of data (all, specific, brief, etc.)
            - qualifiers: Response style qualifiers
            - should_be_comprehensive: Whether to provide comprehensive answer
        """
        query_lower = query.lower().strip()
        qualifiers = self.detect_query_qualifiers(query)
        
        # Detect primary intent
        primary_intent = None
        
        # Device info queries
        if any(phrase in query_lower for phrase in ['device info', 'device information', 'device metadata', 'device details']):
            primary_intent = 'device_info'
        # Contact queries
        elif any(phrase in query_lower for phrase in ['contact', 'contacts', 'who is', 'people']):
            primary_intent = 'contacts'
        # Message queries
        elif any(phrase in query_lower for phrase in ['message', 'messages', 'whatsapp', 'chat', 'conversation']):
            primary_intent = 'messages'
        # Location queries
        elif any(phrase in query_lower for phrase in ['location', 'where', 'gps', 'coordinates', 'last known location']):
            primary_intent = 'location'
        # Owner queries
        elif any(phrase in query_lower for phrase in ['owner', 'who owns', 'device owner', 'likely owner']):
            primary_intent = 'owner'
        # Platform queries
        elif any(phrase in query_lower for phrase in ['platform', 'platforms', 'apps', 'applications']):
            primary_intent = 'platforms'
        # Statistics queries
        elif any(phrase in query_lower for phrase in ['how many', 'count', 'total', 'statistics', 'stats']):
            primary_intent = 'statistics'
        # Default: exploratory
        else:
            primary_intent = 'exploratory'
        
        # Determine if should be comprehensive
        should_be_comprehensive = (
            qualifiers.get('detailed', False) or 
            qualifiers.get('comprehensive', False) or
            any(word in query_lower for word in ['analyze', 'analysis', 'tell me about', 'what can you tell me'])
        ) and not (qualifiers.get('brief', False) or qualifiers.get('simple', False) or qualifiers.get('just', False))
        
        return {
            'primary_intent': primary_intent,
            'qualifiers': qualifiers,
            'should_be_comprehensive': should_be_comprehensive,
            'should_be_brief': qualifiers.get('brief', False) or qualifiers.get('simple', False) or qualifiers.get('just', False)
        }


# Global instance
query_analyzer = QueryAnalyzer()

