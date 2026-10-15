#!/usr/bin/env python3
"""
Response Validator - Anti-Hallucination Tool
Validates LLM responses against actual forensic data to detect fabrication.
"""

import re
import logging
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


def extract_claimed_facts(response: str) -> Dict[str, List[str]]:
    """
    Extract claimed facts from LLM response.
    Returns dict with: timestamps, phone_numbers, message_contents, etc.
    """
    facts = {
        'timestamps': [],
        'phone_numbers': [],
        'message_contents': [],
        'contact_names': [],
        'call_durations': []
    }
    
    # Extract timestamps (various formats)
    timestamp_patterns = [
        r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}',  # ISO format
        r'\d{4}-\d{2}-\d{2}',  # Date only
        r'\d{2}/\d{2}/\d{4}',  # US format
        r'\d{2}:\d{2}:\d{2}',  # Time only
    ]
    for pattern in timestamp_patterns:
        matches = re.findall(pattern, response)
        facts['timestamps'].extend(matches)
    
    # Extract phone numbers
    phone_patterns = [
        r'\+?\d{10,15}',  # Standard phone numbers
        r'\d{3}-\d{3}-\d{4}',  # US format
    ]
    for pattern in phone_patterns:
        matches = re.findall(pattern, response)
        facts['phone_numbers'].extend(matches)
    
    # Extract message content (quoted text)
    message_patterns = [
        r'Content:\s*"([^"]+)"',
        r'Message:\s*"([^"]+)"',
        r'"([^"]{20,})"',  # Quoted text longer than 20 chars
    ]
    for pattern in message_patterns:
        matches = re.findall(pattern, response, re.IGNORECASE)
        facts['message_contents'].extend(matches)
    
    # Extract contact names (capitalized words that might be names)
    # This is less reliable, so we'll be lenient
    name_pattern = r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b'
    matches = re.findall(name_pattern, response)
    facts['contact_names'].extend(matches)
    
    # Extract call durations
    duration_patterns = [
        r'Duration:\s*(\d+)s',
        r'(\d+)\s*seconds',
        r'(\d+)\s*minutes',
    ]
    for pattern in duration_patterns:
        matches = re.findall(pattern, response, re.IGNORECASE)
        facts['call_durations'].extend(matches)
    
    return facts


def validate_response(response: str, data_context: str) -> Tuple[bool, List[str]]:
    """
    Validate LLM response against actual data context.
    
    Returns:
        (is_valid, warnings) - is_valid is True if no fabrication detected
    """
    warnings = []
    
    # If data context says no data found, check if response claims data exists
    if "NO_DATA_FOUND" in data_context or not data_context or len(data_context.strip()) == 0:
        # Check if response contains specific data claims
        claimed_facts = extract_claimed_facts(response)
        
        # If response claims specific timestamps, phone numbers, or messages, it's likely fabricated
        if claimed_facts['timestamps']:
            warnings.append(f"⚠️ Response claims {len(claimed_facts['timestamps'])} timestamp(s) but no data was provided")
        if claimed_facts['phone_numbers']:
            warnings.append(f"⚠️ Response claims {len(claimed_facts['phone_numbers'])} phone number(s) but no data was provided")
        if claimed_facts['message_contents']:
            warnings.append(f"⚠️ Response claims {len(claimed_facts['message_contents'])} message(s) but no data was provided")
        
        # Check for phrases that suggest data exists when it doesn't
        fabrication_phrases = [
            "based on the provided data",
            "the following messages",
            "call logs show",
            "messages indicate",
            "the data shows",
        ]
        response_lower = response.lower()
        for phrase in fabrication_phrases:
            if phrase in response_lower and "no data" not in response_lower[:200]:
                warnings.append(f"⚠️ Response uses phrase '{phrase}' but no data was provided - possible fabrication")
        
        return len(warnings) == 0, warnings
    
    # If data exists, check if claimed facts match actual data
    claimed_facts = extract_claimed_facts(response)
    
    # Check timestamps
    for timestamp in claimed_facts['timestamps']:
        if timestamp not in data_context:
            warnings.append(f"⚠️ Timestamp '{timestamp}' claimed in response but not found in data context")
    
    # Check phone numbers (be lenient - might be formatted differently)
    for phone in claimed_facts['phone_numbers']:
        # Normalize phone number for comparison
        normalized_phone = phone.replace('+', '').replace('-', '').replace(' ', '')
        if normalized_phone not in data_context.replace('+', '').replace('-', '').replace(' ', ''):
            warnings.append(f"⚠️ Phone number '{phone}' claimed in response but not found in data context")
    
    # Check message contents (exact match required)
    for msg_content in claimed_facts['message_contents']:
        if msg_content.lower() not in data_context.lower():
            warnings.append(f"⚠️ Message content '{msg_content[:50]}...' claimed but not found in data context")
    
    return len(warnings) == 0, warnings


def log_validation_results(response: str, data_context: str, is_valid: bool, warnings: List[str]):
    """Log validation results for monitoring."""
    if not is_valid:
        logger.warning(f"🚨 RESPONSE VALIDATION FAILED:")
        logger.warning(f"   Response length: {len(response)} chars")
        logger.warning(f"   Data context length: {len(data_context)} chars")
        logger.warning(f"   Warnings: {len(warnings)}")
        for warning in warnings:
            logger.warning(f"   - {warning}")
        logger.warning(f"   Response preview: {response[:200]}...")
    else:
        logger.debug(f"✅ Response validation passed")













