#!/usr/bin/env python3
"""
Image Citation System for EVI

Detects image-related queries and extracts relevant image references from UFDR data.
Since Qwen 2.5 3B Instruct doesn't support vision, we use text-based matching to find relevant images.
"""

import re
from typing import Dict, List, Any, Set, Optional
from pathlib import Path


class ImageCitationExtractor:
    """Extracts relevant image citations from UFDR data based on queries."""
    
    # Keywords that indicate image-related queries
    IMAGE_QUERY_KEYWORDS = [
        'photo', 'photos', 'picture', 'pictures', 'image', 'images', 
        'show me', 'display', 'view', 'see', 'visual', 'media',
        'attachment', 'attachments', 'file', 'files', 'evidence',
        'screenshot', 'screenshots', 'camera', 'gallery'
    ]
    
    def __init__(self, media_base_path: Optional[str] = None):
        """
        Initialize the image citation extractor.
        
        Args:
            media_base_path: Base path to media folder (e.g., "Media/images")
        """
        self.media_base_path = media_base_path or "Media/images"
    
    def is_image_query(self, query: str) -> bool:
        """
        Detect if the query is asking for images.
        
        Args:
            query: User query
            
        Returns:
            True if query is image-related
        """
        if not query or query is None:
            return False
        try:
            query_lower = query.lower()
            return any(keyword in query_lower for keyword in self.IMAGE_QUERY_KEYWORDS)
        except AttributeError:
            # Handle case where query is not a string
            return False
    
    def extract_image_citations(self, ufdr_data: Dict[str, Any], query: str) -> List[Dict[str, Any]]:
        """
        Extract relevant image citations from UFDR data based on query.
        
        Args:
            ufdr_data: Full UFDR data
            query: User query
            
        Returns:
            List of image citation dictionaries with filename, path, and context
        """
        citations = []
        if not query or query is None:
            return citations
        try:
            query_lower = query.lower()
        except AttributeError:
            # Handle case where query is not a string
            return citations
        
        # Extract devices
        devices = ufdr_data.get('devices', [])
        if not devices:
            devices = [ufdr_data]
        
        # Collect all image files from files section
        all_files = {}
        for device in devices:
            if isinstance(device, dict):
                files = device.get('files', [])
                for file_item in files:
                    if isinstance(file_item, dict):
                        filename = file_item.get('filename', '')
                        if self._is_image_file(filename):
                            all_files[filename] = {
                                'filename': filename,
                                'file_id': file_item.get('file_id', ''),
                                'size_bytes': file_item.get('size_bytes', 0),
                                'hash': file_item.get('hash', ''),
                                'context': 'files_section'
                            }
        
        # Find images mentioned in messages with attachments
        message_images = {}
        for device in devices:
            if isinstance(device, dict):
                messages = device.get('messages', [])
                for msg in messages:
                    if isinstance(msg, dict):
                        attachments = msg.get('attachments', [])
                        text = msg.get('text', '').lower()
                        timestamp = msg.get('timestamp', '')
                        from_user = msg.get('from', '')
                        
                        for attachment in attachments:
                            if self._is_image_file(attachment):
                                if attachment not in message_images:
                                    message_images[attachment] = {
                                        'filename': attachment,
                                        'context': 'message_attachment',
                                        'mentioned_in': []
                                    }
                                message_images[attachment]['mentioned_in'].append({
                                    'text': msg.get('text', ''),
                                    'timestamp': timestamp,
                                    'from': from_user,
                                    'msg_id': msg.get('msg_id', '')
                                })
        
        # Merge file and message references
        all_images = {}
        for filename, info in all_files.items():
            all_images[filename] = info
        
        for filename, info in message_images.items():
            if filename in all_images:
                all_images[filename]['context'] = 'both'
                all_images[filename]['mentioned_in'] = info.get('mentioned_in', [])
            else:
                all_images[filename] = info
        
        # Filter images based on query relevance
        if self.is_image_query(query):
            # If it's a general image query, return all images
            if any(word in query_lower for word in ['all', 'every', 'list', 'show']):
                citations = list(all_images.values())
            else:
                # Find images relevant to query keywords
                citations = self._filter_relevant_images(all_images, query_lower)
        else:
            # Even for non-image queries, check if any images are mentioned in context
            citations = self._filter_relevant_images(all_images, query_lower)
        
        # Build full paths and add metadata
        for citation in citations:
            citation['path'] = self._build_image_path(citation['filename'])
            citation['relative_path'] = f"{self.media_base_path}/{citation['filename']}"
        
        return citations[:20]  # Limit to top 20 most relevant
    
    def _is_image_file(self, filename: str) -> bool:
        """Check if file is an image based on extension."""
        if not filename:
            return False
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        return ext in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'heic']
    
    def _filter_relevant_images(self, all_images: Dict[str, Any], query_lower: str) -> List[Dict[str, Any]]:
        """
        Filter images based on query relevance.
        
        Args:
            all_images: Dictionary of all images
            query_lower: Lowercase query
            
        Returns:
            List of relevant images sorted by relevance
        """
        relevant = []
        
        # Extract keywords from query
        query_words = set(re.findall(r'\b\w+\b', query_lower))
        query_words.discard('the')
        query_words.discard('a')
        query_words.discard('an')
        query_words.discard('is')
        query_words.discard('are')
        query_words.discard('show')
        query_words.discard('me')
        
        for filename, info in all_images.items():
            relevance_score = 0
            
            # Check filename for keywords
            filename_lower = filename.lower()
            for word in query_words:
                if word in filename_lower:
                    relevance_score += 2
            
            # Check message context if available
            if 'mentioned_in' in info:
                for mention in info['mentioned_in']:
                    text_lower = mention.get('text', '').lower()
                    for word in query_words:
                        if word in text_lower:
                            relevance_score += 3  # Higher weight for message context
            
            # Boost score if image is in message attachments (more relevant)
            if info.get('context') in ['message_attachment', 'both']:
                relevance_score += 1
            
            if relevance_score > 0 or len(query_words) == 0:
                info['relevance_score'] = relevance_score
                relevant.append(info)
        
        # Sort by relevance score
        relevant.sort(key=lambda x: x.get('relevance_score', 0), reverse=True)
        return relevant
    
    def _build_image_path(self, filename: str) -> str:
        """Build full path to image file."""
        return f"{self.media_base_path}/{filename}"
    
    def format_image_citations(self, citations: List[Dict[str, Any]]) -> str:
        """
        Format image citations for display in response.
        
        Args:
            citations: List of image citation dictionaries
            
        Returns:
            Formatted string with image references
        """
        if not citations:
            return ""
        
        formatted = f"\n\n📷 RELEVANT IMAGES FOUND ({len(citations)}):\n"
        for i, citation in enumerate(citations[:10], 1):  # Show top 10
            filename = citation.get('filename', 'Unknown')
            context = citation.get('context', '')
            path = citation.get('relative_path', filename)
            
            formatted += f"{i}. {filename}"
            if context == 'message_attachment':
                formatted += " (attached in message)"
            elif context == 'both':
                formatted += " (in files & messages)"
            formatted += f"\n   Path: {path}\n"
            
            # Add message context if available
            if 'mentioned_in' in citation and citation['mentioned_in']:
                mention = citation['mentioned_in'][0]
                text = mention.get('text', '')[:50]
                if text:
                    formatted += f"   Context: \"{text}...\"\n"
        
        if len(citations) > 10:
            formatted += f"\n... and {len(citations) - 10} more images\n"
        
        return formatted


# Global instance
image_citation_extractor = ImageCitationExtractor()



