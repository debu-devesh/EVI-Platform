#!/usr/bin/env python3
"""
UFDR Parser for Forensic AI Chat Assistant

Parses UFDR JSON files into searchable chunks for FAISS indexing.
Handles both flat and nested UFDR structures.
"""

import json
import re
from typing import Dict, List, Any, Tuple
from datetime import datetime


class UFDRParser:
    """Parse UFDR JSON files into searchable chunks."""
    
    def __init__(self):
        self.chunks = []
        self.metadata = {}
    
    def parse_ufdr_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse a UFDR JSON file into searchable chunks.
        
        Args:
            file_path: Path to UFDR JSON file
            
        Returns:
            List of searchable chunks with metadata
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            return self.parse_ufdr_data(data, file_path)
            
        except Exception as e:
            print(f"Error parsing UFDR file {file_path}: {e}")
            return []
    
    def parse_ufdr_data(self, data: Dict[str, Any], source_file: str = "unknown") -> List[Dict[str, Any]]:
        """
        Parse UFDR data dictionary into searchable chunks.
        
        Args:
            data: UFDR data dictionary
            source_file: Source file name
            
        Returns:
            List of searchable chunks
        """
        chunks = []
        
        # Extract metadata
        metadata = self._extract_metadata(data, source_file)
        
        # Handle nested structure with devices
        devices = data.get("devices", [])
        if not devices:
            # Handle direct structure (fallback)
            devices = [data]
        
        for device_idx, device in enumerate(devices):
            if isinstance(device, dict):
                device_chunks = self._parse_device(device, device_idx, metadata)
                chunks.extend(device_chunks)
        
        return chunks
    
    def _extract_metadata(self, data: Dict[str, Any], source_file: str) -> Dict[str, Any]:
        """Extract metadata from UFDR data."""
        metadata = {
            "source_file": source_file,
            "parsed_at": datetime.now().isoformat(),
            "total_devices": len(data.get("devices", [])),
            "file_type": "ufdr"
        }
        
        # Extract meta information if available
        if "meta" in data:
            meta = data["meta"]
            metadata.update({
                "generated_by": meta.get("generated_by", "Unknown"),
                "scenario": meta.get("scenario", "Unknown"),
                "generated_at": meta.get("generated_at", "Unknown")
            })
        
        return metadata
    
    def _parse_device(self, device: Dict[str, Any], device_idx: int, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse a single device into chunks."""
        chunks = []
        
        # Device info chunk
        device_info = device.get("device", {})
        if device_info:
            chunk = {
                "type": "device_info",
                "content": f"Device: {device_info.get('device_make', 'Unknown')} - {device_info.get('owner_name', 'Unknown')} ({device_info.get('phone_number', 'Unknown')})",
                "metadata": {
                    **metadata,
                    "device_idx": device_idx,
                    "owner_name": device_info.get('owner_name', 'Unknown'),
                    "phone_number": device_info.get('phone_number', 'Unknown'),
                    "device_make": device_info.get('device_make', 'Unknown')
                },
                "searchable_text": f"device owner {device_info.get('owner_name', '')} phone {device_info.get('phone_number', '')} {device_info.get('device_make', '')}"
            }
            chunks.append(chunk)
        
        # Contacts chunks
        contacts = device.get("contacts", [])
        for contact in contacts:
            if isinstance(contact, dict):
                chunk = self._create_contact_chunk(contact, device_idx, metadata)
                chunks.append(chunk)
        
        # Messages chunks
        messages = device.get("messages", [])
        for message in messages:
            if isinstance(message, dict):
                chunk = self._create_message_chunk(message, device_idx, metadata)
                chunks.append(chunk)
        
        # Call logs chunks
        call_logs = device.get("call_logs", [])
        for call in call_logs:
            if isinstance(call, dict):
                chunk = self._create_call_chunk(call, device_idx, metadata)
                chunks.append(chunk)
        
        # Files chunks
        files = device.get("files", [])
        for file_item in files:
            if isinstance(file_item, dict):
                chunk = self._create_file_chunk(file_item, device_idx, metadata)
                chunks.append(chunk)
        
        return chunks
    
    def _create_contact_chunk(self, contact: Dict[str, Any], device_idx: int, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Create a contact chunk."""
        name = contact.get('name', 'Unknown')
        phone = contact.get('phone', 'Unknown')
        email = contact.get('email', '')
        
        content = f"Contact: {name}"
        if phone != 'Unknown':
            content += f" ({phone})"
        if email:
            content += f" - {email}"
        
        return {
            "type": "contact",
            "content": content,
            "metadata": {
                **metadata,
                "device_idx": device_idx,
                "contact_name": name,
                "contact_phone": phone,
                "contact_email": email,
                "contact_id": contact.get('contact_id', '')
            },
            "searchable_text": f"contact {name} phone {phone} email {email}"
        }
    
    def _create_message_chunk(self, message: Dict[str, Any], device_idx: int, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Create a message chunk."""
        text = message.get('text', '') or message.get('content', '')
        from_user = message.get('from', 'Unknown')
        to_user = message.get('to', 'Unknown')
        timestamp = message.get('timestamp', '')
        
        # Clean and truncate text for display
        clean_text = self._clean_text(text)
        display_text = clean_text[:100] + "..." if len(clean_text) > 100 else clean_text
        
        content = f"Message from {from_user} to {to_user}: \"{display_text}\""
        if timestamp:
            content += f" ({timestamp})"
        
        return {
            "type": "message",
            "content": content,
            "metadata": {
                **metadata,
                "device_idx": device_idx,
                "message_from": from_user,
                "message_to": to_user,
                "message_text": text,
                "message_timestamp": timestamp,
                "message_length": len(text)
            },
            "searchable_text": f"message {from_user} {to_user} {clean_text}"
        }
    
    def _create_call_chunk(self, call: Dict[str, Any], device_idx: int, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Create a call chunk."""
        from_user = call.get('from', 'Unknown')
        to_user = call.get('to', 'Unknown')
        # Support both 'duration' and 'duration_seconds' field names
        duration = call.get('duration_seconds', call.get('duration', 0))
        direction = call.get('direction', 'unknown')
        timestamp = call.get('timestamp', '')
        
        content = f"Call: {from_user} → {to_user} ({duration}s, {direction})"
        if timestamp:
            content += f" at {timestamp}"
        
        return {
            "type": "call",
            "content": content,
            "metadata": {
                **metadata,
                "device_idx": device_idx,
                "call_from": from_user,
                "call_to": to_user,
                "call_duration": duration,
                "call_direction": direction,
                "call_timestamp": timestamp
            },
            "searchable_text": f"call {from_user} {to_user} duration {duration} {direction}"
        }
    
    def _create_file_chunk(self, file_item: Dict[str, Any], device_idx: int, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Create a file chunk."""
        filename = file_item.get('filename', 'Unknown')
        size_bytes = file_item.get('size_bytes', 0)
        file_type = filename.split('.')[-1].lower() if '.' in filename else 'unknown'
        
        size_mb = size_bytes / (1024 * 1024) if size_bytes > 0 else 0
        
        content = f"File: {filename} ({size_mb:.2f} MB, {file_type})"
        
        return {
            "type": "file",
            "content": content,
            "metadata": {
                **metadata,
                "device_idx": device_idx,
                "filename": filename,
                "file_size_bytes": size_bytes,
                "file_size_mb": size_mb,
                "file_type": file_type
            },
            "searchable_text": f"file {filename} {file_type} size {size_mb}"
        }
    
    def _clean_text(self, text: str) -> str:
        """Clean text for display and search."""
        if not text:
            return ""
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text.strip())
        
        # Remove special characters that might interfere with search
        text = re.sub(r'[^\w\s@.,!?]', '', text)
        
        return text
    
    def get_chunk_summary(self, chunks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get summary statistics of parsed chunks."""
        summary = {
            "total_chunks": len(chunks),
            "by_type": {},
            "total_contacts": 0,
            "total_messages": 0,
            "total_calls": 0,
            "total_files": 0
        }
        
        for chunk in chunks:
            chunk_type = chunk.get("type", "unknown")
            summary["by_type"][chunk_type] = summary["by_type"].get(chunk_type, 0) + 1
            
            if chunk_type == "contact":
                summary["total_contacts"] += 1
            elif chunk_type == "message":
                summary["total_messages"] += 1
            elif chunk_type == "call":
                summary["total_calls"] += 1
            elif chunk_type == "file":
                summary["total_files"] += 1
        
        return summary


# Global instance
ufdr_parser = UFDRParser()
