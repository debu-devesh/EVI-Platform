#!/usr/bin/env python3
"""
Enhanced UFDR Data Extractor

Extracts specific UFDR details for LLM display while respecting token limits.
Shows actual names, messages, call details instead of just counts.
"""

import json
import re
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict


class EnhancedDataExtractor:
    """
    Extracts specific UFDR data with actual details for LLM consumption.
    """
    
    def __init__(self, max_items_per_type: int = 50, max_text_length: int = 10000):
        """
        Initialize the enhanced extractor.
        
        Args:
            max_items_per_type: Maximum items to show per data type (hard limit: 50 for forensic reliability)
            max_text_length: Maximum text length per item (increased from 120 to 10000)
        """
        self.max_items_per_type = max_items_per_type  # Hard limit: 50 records max for forensic reliability
        self.max_text_length = max_text_length  # No truncation for most messages
    
    def extract_relevant_data(self, ufdr_data: Dict[str, Any], query: str) -> str:
        """
        Extract relevant UFDR data based on query and format for LLM.
        
        Args:
            ufdr_data: Full UFDR data
            query: User query
            
        Returns:
            Formatted context string with specific details
        """
        # Safety check: ensure query is a string
        if not query or query is None:
            query = ""
        if not isinstance(query, str):
            query = str(query) if query else ""
        
        query_lower = query.lower() if query else ""
        context_parts = []
        
        # Extract devices data - handle multiple formats
        devices = []
        total_contacts = 0
        total_messages = 0
        total_calls = 0
        root_locations = []  # Store root-level locations for flat structures
        
        # Check for v2 format (devices array)
        if 'devices' in ufdr_data and isinstance(ufdr_data.get('devices'), list):
            devices = ufdr_data['devices']
            # Also check for root-level locations in v2 format
            if 'locations' in ufdr_data and isinstance(ufdr_data.get('locations'), list):
                root_locations = ufdr_data['locations']
        # Check for flat structure (contacts, messages, call_logs at root)
        elif any(key in ufdr_data for key in ['contacts', 'messages', 'call_logs', 'locations']):
            # Create a single device from flat structure
            devices = [ufdr_data]
            # Extract root-level locations if they exist
            if 'locations' in ufdr_data and isinstance(ufdr_data.get('locations'), list):
                root_locations = ufdr_data['locations']
        # Check if data itself is a device structure
        elif isinstance(ufdr_data, dict) and ('contacts' in ufdr_data or 'messages' in ufdr_data or 'call_logs' in ufdr_data or 'locations' in ufdr_data):
            devices = [ufdr_data]
            # Extract root-level locations if they exist
            if 'locations' in ufdr_data and isinstance(ufdr_data.get('locations'), list):
                root_locations = ufdr_data['locations']
        else:
            # Last resort: treat entire data as a device
            devices = [ufdr_data]
            if 'locations' in ufdr_data and isinstance(ufdr_data.get('locations'), list):
                root_locations = ufdr_data['locations']
        
        # Determine what data to extract based on query
        show_contacts = any(word in query_lower for word in ['contact', 'name', 'phone', 'who', 'people'])
        show_messages = any(word in query_lower for word in ['message', 'text', 'sms', 'chat', 'said', 'conversation'])
        show_calls = any(word in query_lower for word in ['call', 'dial', 'phone', 'ring', 'spoke'])
        show_files = any(word in query_lower for word in ['file', 'document', 'photo', 'attachment'])
        show_locations = any(word in query_lower for word in ['location', 'gps', 'coordinates', 'latitude', 'longitude', 'where', 'place', 'address', 'map', 'geolocation'])
        
        # Special case: "analyze all" or "analyze" queries should show everything including locations
        if 'analyze' in query_lower and ('all' in query_lower or 'location' in query_lower):
            show_locations = True
        
        # If no specific intent, show a mix of everything
        if not any([show_contacts, show_messages, show_calls, show_files, show_locations]):
            show_contacts = show_messages = show_calls = show_locations = True
        
        for device_idx, device in enumerate(devices):
            if not isinstance(device, dict):
                continue
            
            # Get device info - handle both nested and flat structures
            device_info = device.get('device', {})
            if not device_info and 'device' not in device:
                # Try to extract device info from root level
                device_info = {
                    'owner_name': device.get('owner_name', device.get('owner', f'Device {device_idx + 1}')),
                    'device_make': device.get('device_make', device.get('model', 'Unknown Model'))
                }
            
            device_name = device_info.get('owner_name', device.get('owner_name', device.get('owner', f'Device {device_idx + 1}')))
            device_model = device_info.get('device_make', device.get('device_make', device.get('model', 'Unknown Model')))
            
            context_parts.append(f"\n=== {device_name}'s {device_model} ===")
            
            # Extract contacts with details - check multiple possible locations
            if show_contacts:
                contacts = device.get('contacts', [])
                if not contacts and 'contact' in device:
                    contacts = device['contact'] if isinstance(device['contact'], list) else [device['contact']]
                
                total_contacts += len(contacts) if isinstance(contacts, list) else 0
                if contacts and isinstance(contacts, list) and len(contacts) > 0:
                    contact_details = self._extract_contact_details(contacts, query_lower)
                    if contact_details:
                        context_parts.append(f"\nCONTACTS ({len(contacts)} total):")
                        context_parts.extend(contact_details)
            
            # Extract messages with content - check multiple possible locations
            if show_messages:
                messages = device.get('messages', [])
                if not messages and 'message' in device:
                    messages = device['message'] if isinstance(device['message'], list) else [device['message']]
                
                total_messages += len(messages) if isinstance(messages, list) else 0
                if messages and isinstance(messages, list) and len(messages) > 0:
                    message_details = self._extract_message_details(messages, query_lower)
                    if message_details:
                        context_parts.append(f"\nMESSAGES ({len(messages)} total):")
                        context_parts.extend(message_details)
            
            # Extract calls with details - check multiple possible locations
            if show_calls:
                calls = device.get('call_logs', device.get('calls', []))
                if not calls and 'call' in device:
                    calls = device['call'] if isinstance(device['call'], list) else [device['call']]
                
                total_calls += len(calls) if isinstance(calls, list) else 0
                if calls and isinstance(calls, list) and len(calls) > 0:
                    call_details = self._extract_call_details(calls, query_lower)
                    if call_details:
                        context_parts.append(f"\nCALL LOGS ({len(calls)} total):")
                        context_parts.extend(call_details)
            
            # Extract files if requested
            if show_files:
                file_details = self._extract_file_details(device, query_lower)
                if file_details:
                    context_parts.append(f"\nFILES:")
                    context_parts.extend(file_details)
            
            # Extract location data if requested
            if show_locations:
                locations = device.get('locations', [])
                if not locations and 'location' in device:
                    locations = device['location'] if isinstance(device['location'], list) else [device['location']]
                
                total_locations = len(locations) if isinstance(locations, list) else 0
                if locations and isinstance(locations, list) and len(locations) > 0:
                    location_details = self._extract_location_details(locations, query_lower)
                    if location_details:
                        context_parts.append(f"\nLOCATIONS ({len(locations)} total):")
                        context_parts.extend(location_details)
        
        # Handle root-level locations (for flat structures where locations are at root, not in device)
        # This is critical for normalized UFDR data where locations are at root level
        if show_locations:
            # First check root-level locations (most common in normalized data)
            if root_locations and len(root_locations) > 0:
                location_details = self._extract_location_details(root_locations, query_lower)
                if location_details:
                    context_parts.append(f"\nLOCATIONS ({len(root_locations)} total - Root Level):")
                    context_parts.extend(location_details)
            # Also check if locations exist in the root data structure directly
            elif 'locations' in ufdr_data and isinstance(ufdr_data.get('locations'), list):
                root_locs = ufdr_data['locations']
                if len(root_locs) > 0:
                    location_details = self._extract_location_details(root_locs, query_lower)
                    if location_details:
                        context_parts.append(f"\nLOCATIONS ({len(root_locs)} total - Root Level):")
                        context_parts.extend(location_details)
        
        # Add summary at the top
        # Calculate total locations from both device-level and root-level
        device_locations_count = sum(len(device.get('locations', [])) if isinstance(device.get('locations'), list) else 0 for device in devices)
        total_locations = device_locations_count + len(root_locations)
        summary = f"FORENSIC DATA SUMMARY: {len(devices)} device(s), {total_contacts} contacts, {total_messages} messages, {total_calls} calls, {total_locations} locations"
        context_parts.insert(0, summary)
        
        # Always provide diagnostic information about data structure
        # Check what keys are actually in the data
        top_level_keys = list(ufdr_data.keys()) if isinstance(ufdr_data, dict) else []
        diagnostic = f"\nDATA STRUCTURE ANALYSIS:"
        diagnostic += f"\n- Top-level keys: {top_level_keys}"
        
        if 'devices' in ufdr_data:
            devices_list = ufdr_data.get('devices', [])
            diagnostic += f"\n- Devices array length: {len(devices_list)}"
            if devices_list and isinstance(devices_list[0], dict):
                first_device_keys = list(devices_list[0].keys())
                diagnostic += f"\n- First device keys: {first_device_keys}"
                # Check each device for data
                for i, device in enumerate(devices_list):
                    if isinstance(device, dict):
                        device_contacts = len(device.get('contacts', []))
                        device_messages = len(device.get('messages', []))
                        device_calls = len(device.get('call_logs', []))
                        device_locations = len(device.get('locations', []))
                        diagnostic += f"\n- Device {i+1}: {device_contacts} contacts, {device_messages} messages, {device_calls} calls, {device_locations} locations"
        else:
            # Flat structure
            diagnostic += f"\n- Flat structure detected (no 'devices' key)"
            diagnostic += f"\n- Direct contacts: {len(ufdr_data.get('contacts', []))}"
            diagnostic += f"\n- Direct messages: {len(ufdr_data.get('messages', []))}"
            diagnostic += f"\n- Direct call_logs: {len(ufdr_data.get('call_logs', []))}"
            diagnostic += f"\n- Direct locations: {len(ufdr_data.get('locations', []))}"
            if 'locations' in ufdr_data:
                locs = ufdr_data.get('locations', [])
                if isinstance(locs, list) and len(locs) > 0:
                    diagnostic += f"\n- Location data found at root level: {len(locs)} location records"
                    # Show sample location
                    sample_loc = locs[0] if locs else {}
                    diagnostic += f"\n- Sample location: {sample_loc.get('address', 'N/A')} at ({sample_loc.get('latitude', 'N/A')}, {sample_loc.get('longitude', 'N/A')})"
        
        # If no data found, emphasize this in the diagnostic
        if total_contacts == 0 and total_messages == 0 and total_calls == 0 and total_locations == 0:
            diagnostic += f"\n⚠️ WARNING: No contacts, messages, calls, or locations were extracted from the data."
            diagnostic += f"\nThis could mean:"
            diagnostic += f"\n  1. The UFDR file is empty or contains no communication data"
            diagnostic += f"\n  2. The data structure doesn't match expected format"
            diagnostic += f"\n  3. The data is stored in a different location than expected"
        else:
            diagnostic += f"\n✅ Data extraction successful: {total_contacts} contacts, {total_messages} messages, {total_calls} calls, {total_locations} locations found"
        
        context_parts.append(diagnostic)
        
        return self._format_structured_output(context_parts, query)
    
    def _format_structured_output(self, context_parts: List[str], query: str) -> str:
        """
        Format the extracted data in a more structured, readable format.
        """
        if not context_parts:
            return "No relevant forensic data found."
        
        # Reorganize the data for better structure
        structured_parts = []
        current_device = ""
        device_sections = {}
        
        i = 0
        while i < len(context_parts):
            part = context_parts[i].strip()
            
            # Skip empty lines and summary
            if not part or part.startswith("FORENSIC DATA SUMMARY:"):
                i += 1
                continue
            
            # Detect device headers
            if part.startswith("=== ") and part.endswith(" ==="):
                current_device = part.strip("= ")
                device_sections[current_device] = {"contacts": [], "messages": [], "calls": [], "files": []}
                i += 1
                continue
            
            # Categorize content by type
            if part.startswith("CONTACTS (") and current_device:
                i += 1
                while i < len(context_parts) and context_parts[i].strip().startswith("- "):
                    device_sections[current_device]["contacts"].append(context_parts[i].strip().lstrip("- "))
                    i += 1
                continue
            
            elif part.startswith("MESSAGES (") and current_device:
                i += 1
                while i < len(context_parts) and context_parts[i].strip().startswith("- "):
                    device_sections[current_device]["messages"].append(context_parts[i].strip().lstrip("- "))
                    i += 1
                continue
            
            elif part.startswith("CALL LOGS (") and current_device:
                i += 1
                while i < len(context_parts) and context_parts[i].strip().startswith("- "):
                    device_sections[current_device]["calls"].append(context_parts[i].strip().lstrip("- "))
                    i += 1
                continue
            
            elif part.startswith("FILES:") and current_device:
                i += 1
                while i < len(context_parts) and context_parts[i].strip().startswith("- "):
                    device_sections[current_device]["files"].append(context_parts[i].strip().lstrip("- "))
                    i += 1
                continue
            
            i += 1
        
        # Build structured output
        structured_parts.append("FORENSIC INVESTIGATION REPORT")
        structured_parts.append("=" * 40)
        
        # Add summary from first line
        summary_line = next((part for part in context_parts if part.startswith("FORENSIC DATA SUMMARY:")), None)
        if summary_line:
            structured_parts.append(f"Overview: {summary_line.replace('FORENSIC DATA SUMMARY: ', '')}")
            structured_parts.append("")
        
        # Process each device in a structured way
        for device_name, sections in device_sections.items():
            structured_parts.append(f"DEVICE: {device_name}")
            structured_parts.append("-" * len(f"DEVICE: {device_name}"))
            
            # Contacts section
            if sections["contacts"]:
                structured_parts.append("Contacts:")
                # Group contacts by type
                external_contacts = [c for c in sections["contacts"] if c and isinstance(c, str) and ("external" in c.lower() or "partner" in c.lower())]
                internal_contacts = [c for c in sections["contacts"] if c not in external_contacts]
                
                if external_contacts:
                    structured_parts.append("  External/Partners:")
                    for contact in external_contacts[:4]:
                        structured_parts.append(f"    - {contact}")
                
                if internal_contacts:
                    structured_parts.append("  Internal/Staff:")
                    for contact in internal_contacts[:4]:
                        structured_parts.append(f"    - {contact}")
                structured_parts.append("")
            
            # Messages section
            if sections["messages"]:
                structured_parts.append("Communications:")
                # Separate suspicious from normal messages
                suspicious_msgs = []
                normal_msgs = []
                
                for msg in sections["messages"]:
                    if not msg or not isinstance(msg, str):
                        continue
                    msg_lower = msg.lower()
                    if any(keyword in msg_lower for keyword in ['password', 'confidential', 'secret', 'metadata', 'personal drive', 'official email']):
                        suspicious_msgs.append(msg)
                    else:
                        normal_msgs.append(msg)
                
                if suspicious_msgs:
                    structured_parts.append("  Suspicious Messages:")
                    for msg in suspicious_msgs[:3]:
                        structured_parts.append(f"    [!] {msg}")
                
                if normal_msgs and len(suspicious_msgs) < 3:
                    structured_parts.append("  Recent Messages:")
                    for msg in normal_msgs[:2]:
                        structured_parts.append(f"    - {msg}")
                structured_parts.append("")
            
            # Calls section
            if sections["calls"]:
                structured_parts.append("Call Activity:")
                # Separate by duration
                long_calls = [c for c in sections["calls"] if "m" in c and not c.endswith("0s)")]
                short_calls = [c for c in sections["calls"] if c not in long_calls]
                
                if long_calls:
                    structured_parts.append("  Extended Calls:")
                    for call in long_calls[:3]:
                        structured_parts.append(f"    - {call}")
                
                if short_calls and len(long_calls) < 3:
                    structured_parts.append("  Brief Calls:")
                    for call in short_calls[:2]:
                        structured_parts.append(f"    - {call}")
                structured_parts.append("")
            
            # Files section
            if sections["files"]:
                structured_parts.append("File Transfers:")
                for file_info in sections["files"][:3]:
                    structured_parts.append(f"    - {file_info}")
                structured_parts.append("")
            
            structured_parts.append("")  # Space between devices
        
        return '\n'.join(structured_parts)
    
    def _extract_contact_details(self, contacts: List[Dict], query_lower: str) -> List[str]:
        """Extract specific contact details."""
        details = []
        
        # Score and sort contacts by relevance
        scored_contacts = []
        for contact in contacts:
            score = 0
            # Safe extraction with None handling
            name = (contact.get('name') or '').lower() if contact.get('name') else ''
            phone = contact.get('phone') or ''
            email = (contact.get('email') or '').lower() if contact.get('email') else ''
            
            # Boost score for query matches
            if any(word in name for word in query_lower.split()):
                score += 10
            if any(digit in phone for digit in re.findall(r'\d+', query_lower)):
                score += 8
            if email and any(word in email for word in query_lower.split()):
                score += 6
            
            # Boost suspicious contacts
            if any(keyword in name for keyword in ['external', 'unknown', 'temp', 'suspicious']):
                score += 5
            
            scored_contacts.append((score, contact))
        
        # Sort by score and take top items
        scored_contacts.sort(key=lambda x: x[0], reverse=True)
        
        for i, (score, contact) in enumerate(scored_contacts[:self.max_items_per_type]):
            # Safe extraction with None handling
            name = contact.get('name') or 'Unknown'
            phone = contact.get('phone') or 'N/A'
            email = contact.get('email') or ''
            last_seen = contact.get('last_seen') or ''
            
            # Format contact info
            contact_info = f"  - {name} - {phone}"
            if email:
                contact_info += f" ({email})"
            if last_seen:
                # Show just date part
                date_part = last_seen.split('T')[0] if 'T' in last_seen else last_seen[:10]
                contact_info += f" [Last: {date_part}]"
            
            details.append(contact_info)
        
        return details
    
    def _extract_message_details(self, messages: List[Dict], query_lower: str) -> List[str]:
        """Extract specific message details."""
        details = []
        
        # Score and sort messages by relevance
        scored_messages = []
        for message in messages:
            score = 0
            # Safe extraction with None handling
            text = (message.get('text') or '').lower() if message.get('text') else ''
            msg_type = message.get('type') or ''
            
            # Boost score for query matches
            text_words = set(text.split())
            query_words = set(query_lower.split())
            common_words = query_words.intersection(text_words)
            score += len(common_words) * 3
            
            # Boost for suspicious keywords
            if any(keyword in text for keyword in ['password', 'otp', 'code', 'confidential', 'secret', 'leak', 'transfer']):
                score += 8
            
            # Boost recent messages
            timestamp = message.get('timestamp', '')
            if timestamp and '2025-09' in timestamp:
                score += 2
            
            scored_messages.append((score, message))
        
        # Sort by score and timestamp (recent first for same score)
        scored_messages.sort(key=lambda x: (x[0], x[1].get('timestamp', '')), reverse=True)
        
        for i, (score, message) in enumerate(scored_messages[:self.max_items_per_type]):
            timestamp = message.get('timestamp', '')
            from_num = message.get('from', '')
            to_num = message.get('to', '')
            text = message.get('text', '')
            msg_type = message.get('type', 'text')
            
            # Format timestamp
            time_str = ''
            if timestamp:
                if 'T' in timestamp:
                    date_part, time_part = timestamp.split('T')
                    time_str = f"{date_part} {time_part[:5]}"
                else:
                    time_str = timestamp[:16]
            
            # Format phone numbers (show last 4 digits)
            from_display = from_num[-4:] if len(from_num) > 4 else from_num
            to_display = to_num[-4:] if len(to_num) > 4 else to_num
            
            # Truncate long text
            if len(text) > self.max_text_length:
                text = text[:self.max_text_length] + '...'
            
            # Format message
            msg_info = f"  - [{time_str}] {from_display}->{to_display}: {text}"
            if msg_type != 'text':
                msg_info += f" [{msg_type}]"
            
            details.append(msg_info)
        
        return details
    
    def _extract_call_details(self, calls: List[Dict], query_lower: str) -> List[str]:
        """Extract specific call details."""
        details = []
        
        # Score and sort calls by relevance
        scored_calls = []
        for call in calls:
            score = 0
            # Safe extraction with None handling
            phone = call.get('phone_number') or ''
            call_type = (call.get('type') or '').lower() if call.get('type') else ''
            duration = call.get('duration') or 0
            
            # Boost score for query matches
            if any(digit in phone for digit in re.findall(r'\d+', query_lower)):
                score += 10
            if call_type in query_lower:
                score += 5
            
            # Boost long calls (potentially important)
            if duration > 300:  # 5+ minutes
                score += 4
            elif duration > 60:  # 1+ minute
                score += 2
            
            # Boost recent calls
            timestamp = call.get('timestamp', '')
            if timestamp and '2025-09' in timestamp:
                score += 2
            
            scored_calls.append((score, call))
        
        # Sort by score and timestamp
        scored_calls.sort(key=lambda x: (x[0], x[1].get('timestamp', '')), reverse=True)
        
        for i, (score, call) in enumerate(scored_calls[:self.max_items_per_type]):
            timestamp = call.get('timestamp', '')
            phone = call.get('phone_number', '')
            call_type = call.get('type', 'unknown')
            duration = call.get('duration', 0)
            
            # Format timestamp
            time_str = ''
            if timestamp:
                if 'T' in timestamp:
                    date_part, time_part = timestamp.split('T')
                    time_str = f"{date_part} {time_part[:5]}"
                else:
                    time_str = timestamp[:16]
            
            # Format phone number
            phone_display = phone[-4:] if len(phone) > 4 else phone
            
            # Format duration
            if duration >= 60:
                minutes = duration // 60
                seconds = duration % 60
                duration_str = f"{minutes}m{seconds}s"
            else:
                duration_str = f"{duration}s"
            
            # Format call info
            call_info = f"  - [{time_str}] {call_type.upper()} call - {phone_display} ({duration_str})"
            
            details.append(call_info)
        
        return details
    
    def _extract_file_details(self, device: Dict, query_lower: str) -> List[str]:
        """Extract file details from messages and other sources."""
        details = []
        file_count = 0
        
        # Extract files from message attachments
        messages = device.get('messages', [])
        for message in messages[:20]:  # Limit processing
            attachments = message.get('attachments', [])
            for attachment in attachments:
                if isinstance(attachment, dict):
                    filename = attachment.get('filename', 'unknown')
                    file_type = attachment.get('type', 'unknown')
                    size = attachment.get('size', 0)
                    
                    # Format file size
                    if size > 1024 * 1024:
                        size_str = f"{size / (1024 * 1024):.1f}MB"
                    elif size > 1024:
                        size_str = f"{size / 1024:.1f}KB"
                    else:
                        size_str = f"{size}B"
                    
                    # Truncate long filenames
                    if len(filename) > 30:
                        filename = filename[:27] + '...'
                    
                    file_info = f"  - {filename} ({file_type}, {size_str})"
                    details.append(file_info)
                    file_count += 1
                    
                    if file_count >= self.max_items_per_type:
                        break
            
            if file_count >= self.max_items_per_type:
                break
        
        return details
    
    def _extract_location_details(self, locations: List[Dict], query_lower: str) -> List[str]:
        """Extract specific location details."""
        details = []
        
        # Score and sort locations by relevance
        scored_locations = []
        for location in locations:
            score = 0
            # Safe extraction with None handling
            address = (location.get('address') or '').lower() if location.get('address') else ''
            location_name = (location.get('location_name') or '').lower() if location.get('location_name') else ''
            description = (location.get('description') or '').lower() if location.get('description') else ''
            
            # Boost score for query matches
            if any(word in address for word in query_lower.split()):
                score += 10
            if any(word in location_name for word in query_lower.split()):
                score += 8
            if description and any(word in description for word in query_lower.split()):
                score += 6
            
            # Boost suspicious locations (crime scenes, weapon pickups, etc.)
            suspicious_keywords = ['crime', 'scene', 'weapon', 'warehouse', 'abandoned', 'pickup']
            if any(keyword in address or keyword in location_name for keyword in suspicious_keywords):
                score += 5
            
            # Boost recent locations
            timestamp = location.get('timestamp', '')
            if timestamp and '2025-11' in timestamp:
                score += 2
            
            scored_locations.append((score, location))
        
        # Sort by score and timestamp (recent first for same score)
        scored_locations.sort(key=lambda x: (x[0], x[1].get('timestamp', '')), reverse=True)
        
        for i, (score, location) in enumerate(scored_locations[:self.max_items_per_type]):
            timestamp = location.get('timestamp', '')
            latitude = location.get('latitude', '')
            longitude = location.get('longitude', '')
            address = location.get('address', '')
            location_name = location.get('location_name', '')
            source = location.get('source', 'GPS')
            
            # Format timestamp
            time_str = ''
            if timestamp:
                if 'T' in timestamp:
                    date_part, time_part = timestamp.split('T')
                    time_str = f"{date_part} {time_part[:5]}"
                else:
                    time_str = timestamp[:16]
            
            # Format location info
            loc_info = f"  - [{time_str}] {location_name or 'Unknown Location'}"
            if address:
                loc_info += f" - {address}"
            if latitude and longitude:
                loc_info += f" (GPS: {latitude:.4f}, {longitude:.4f})"
            if source:
                loc_info += f" [{source}]"
            
            details.append(loc_info)
        
        return details


# Global instance
enhanced_extractor = EnhancedDataExtractor()
