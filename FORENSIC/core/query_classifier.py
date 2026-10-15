#!/usr/bin/env python3
"""
Query Classifier for EVI

Distinguishes between:
- Simple Extraction Queries: Direct data retrieval (no LLM needed)
- Analysis Queries: Require LLM for insights and interpretation
- Hybrid Queries: Need both data extraction and LLM analysis
"""

import re
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Short platform tokens where naive `keyword in query` false-matches (e.g. "line" inside "timeline").
_PLATFORM_SUBSTRING_RISK = frozenset(
    {"line", "kik", "sms", "native", "viber", "skype", "gmail", "tiktok"}
)


def _platform_keyword_matches(query_lower: str, keyword: str) -> bool:
    """Match platform alias with word boundaries for risky short tokens."""
    kw = (keyword or "").strip().lower()
    if not kw:
        return False
    if " " in kw:
        return kw in query_lower
    if kw in _PLATFORM_SUBSTRING_RISK or len(kw) <= 4:
        return re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", query_lower) is not None
    return kw in query_lower


def is_confirmation_response(query: str) -> bool:
    """
    Check if the user's query is a confirmation response (yes, confirm, proceed, etc.)
    
    Args:
        query: User's query string
        
    Returns:
        True if the query appears to be a confirmation
    """
    query_lower = query.lower().strip()
    
    confirmation_patterns = [
        r'^yes$',
        r'^y$',
        r'^confirm$',
        r'^proceed$',
        r'^go ahead$',
        r'^pull$',
        r'^show$',
        r'^display$',
        r'^get$',
        r'^retrieve$',
        r'^fetch$',
        r'^ok$',
        r'^okay$',
        r'^sure$',
        r'^do it$',
        r'^please$',
        r'^yes please$',
        r'^yes,? proceed$',
        r'^yes,? go ahead$',
        r'^yes,? pull$',
        r'^yes,? show$',
        r'^yes,? display$',
    ]
    
    return any(re.search(pattern, query_lower) for pattern in confirmation_patterns)


def classify_query(query: str) -> Dict:
    """
    Classify a user query to determine if it needs LLM processing or direct data extraction.
    
    Args:
        query: User's query string
        
    Returns:
        {
            'type': 'extraction' | 'analysis' | 'hybrid',
            'platform': 'Native Messages' | None,
            'chat_id': 'chat_123' | None,
            'needs_llm': bool,
            'needs_direct_data': bool,
            'extraction_keywords': list,
            'analysis_keywords': list
        }
    """
    query_lower = query.lower().strip()
    
    # Platform detection patterns
    platforms = {
        'native messages': ['native messages', 'native message', 'native', 'native sms', 'sms'],
        'whatsapp': ['whatsapp', 'whats app'],
        'telegram': ['telegram'],
        'facebook messenger': ['facebook messenger', 'fb messenger', 'messenger'],
        'twitter': ['twitter'],
        'instagram': ['instagram'],
        'snapchat': ['snapchat'],
        'line': ['line'],
        'skype': ['skype'],
        'viber': ['viber'],
        'kik': ['kik', 'kik messenger'],
        'textnow': ['textnow', 'text now'],
        'tiktok': ['tiktok', 'tik tok'],
        'wickr pro': ['wickr', 'wickr pro', 'wickrpro']
    }
    
    detected_platform = None
    for platform_name, keywords in platforms.items():
        for keyword in keywords:
            if _platform_keyword_matches(query_lower, keyword):
                detected_platform = platform_name
                break
        if detected_platform:
            break
    
    # Extraction query patterns (direct data retrieval)
    extraction_patterns = [
        r'pull\s+(messages|chats|conversations)',
        r'show\s+(me\s+)?(messages|chats|conversations)',
        r'get\s+(messages|chats|conversations)',
        r'display\s+(messages|chats|conversations)',
        r'list\s+(messages|chats|conversations)',
        r'fetch\s+(messages|chats|conversations)',
        r'retrieve\s+(messages|chats|conversations)',
        r'view\s+(messages|chats|conversations)',
        r'open\s+(messages|chats|conversations)',
        r'load\s+(messages|chats|conversations)',
        r'find\s+(all\s+)?(the\s+)?(messages|chats|conversations)',
        r'(messages|chats|conversations)\s+from',
        r'(messages|chats|conversations)\s+in',
    ]
    
    # Analysis query patterns (require LLM)
    analysis_patterns = [
        r'analyze',
        r'analysis',
        r'insight',
        r'what\s+(can\s+you\s+)?tell\s+me',
        r'what\s+do\s+you\s+think',
        r'what\s+is\s+your\s+opinion',
        r'explain',
        r'interpret',
        r'meaning',
        r'significance',
        r'pattern',
        r'suspicious',
        r'unusual',
        r'interesting',
        r'notable',
        r'summarize',
        r'summary',
        r'overview',
        r'conclusion',
        r'findings',
        r'what\s+(does|do)\s+(this|these|it)',
        r'why\s+(did|does|is|are)',
        r'how\s+(did|does|is|are)',
        r'when\s+(did|does|was|were)',
        r'who\s+(did|does|is|are|was|were)',
        r'participants?',
        r'start\s+time',
        r'last\s+activity',
        r'conversation\s+flow',
        r'timeline',
        r'chronology',
    ]
    
    # Hybrid patterns (both extraction and analysis)
    hybrid_patterns = [
        r'show\s+(me\s+)?(messages|chats)\s+and\s+analyze',
        r'display\s+(messages|chats)\s+and\s+(tell|explain|analyze)',
        r'pull\s+(messages|chats)\s+and\s+(analyze|insight|summary)',
        r'get\s+(messages|chats)\s+and\s+(analyze|insight|summary)',
    ]
    
    # Check for hybrid patterns first
    is_hybrid = any(re.search(pattern, query_lower) for pattern in hybrid_patterns)
    
    # Check for extraction patterns
    extraction_matches = [pattern for pattern in extraction_patterns if re.search(pattern, query_lower)]
    is_extraction = len(extraction_matches) > 0
    
    # Check for analysis patterns
    analysis_matches = [pattern for pattern in analysis_patterns if re.search(pattern, query_lower)]
    is_analysis = len(analysis_matches) > 0
    
    # Determine query type
    # NEW FLOW: Extraction queries go through LLM first for confirmation
    if is_hybrid:
        query_type = 'hybrid'
        needs_llm = True
        needs_direct_data = True
    elif is_extraction and not is_analysis:
        # Extraction queries now go through LLM for confirmation prompt
        query_type = 'extraction'
        needs_llm = True  # Changed: LLM asks for confirmation first
        needs_direct_data = True  # After confirmation, fetch data
    elif is_analysis and not is_extraction:
        query_type = 'analysis'
        needs_llm = True
        needs_direct_data = False  # Analysis might work on already-loaded data
    elif is_extraction and is_analysis:
        # Both patterns found but not hybrid - treat as hybrid
        query_type = 'hybrid'
        needs_llm = True
        needs_direct_data = True
    else:
        # Default: if platform detected, treat as extraction; otherwise analysis
        if detected_platform:
            query_type = 'extraction'
            needs_llm = True  # Changed: LLM asks for confirmation first
            needs_direct_data = True
        else:
            query_type = 'analysis'
            needs_llm = True
            needs_direct_data = False
    
    # Extract chat_id if mentioned (e.g., "chat_123", "chat id 456")
    chat_id = None
    chat_id_patterns = [
        r'chat[_\s]?id[:\s]+([a-zA-Z0-9_\-]+)',
        r'chat[:\s]+([a-zA-Z0-9_\-]+)',
    ]
    for pattern in chat_id_patterns:
        match = re.search(pattern, query_lower)
        if match:
            chat_id = match.group(1)
            break
    
    result = {
        'type': query_type,
        'platform': detected_platform,
        'chat_id': chat_id,
        'needs_llm': needs_llm,
        'needs_direct_data': needs_direct_data,
        'extraction_keywords': extraction_matches,
        'analysis_keywords': analysis_matches
    }
    
    logger.info(f"🔍 Query classified: {result}")
    return result

