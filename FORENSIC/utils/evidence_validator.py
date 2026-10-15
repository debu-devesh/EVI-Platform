"""
Evidence Validation Module - Phase 1 Implementation
Validates LLM responses against actual forensic data to prevent hallucination.
"""

import re
import logging
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


def clean_hallucinated_citations(text: str, available_filenames: Set[str]) -> str:
    """
    Remove hallucinated file citations from LLM response.
    
    Args:
        text: The LLM-generated response text
        available_filenames: Set of actual filenames from uploaded data
        
    Returns:
        Cleaned text with hallucinated citations removed or replaced
    """
    if not text:
        return text
    
    cleaned_text = text
    
    # Generic filenames to remove/replace (more aggressive patterns)
    generic_filenames = [
        r'\bfile\.json\b',
        r'\bdata\.json\b',
        r'\bmessages\.json\b',
        r'\bcontacts\.json\b',
        r'\bcalls\.json\b',
        r'\bufdr\.json\b',
        r'\bevidence\.json\b',
        r'\breport\.json\b',
        r'UFDR_FILE\.format\.zip[^\s\)\]\n]*',  # UFDR_FILE.format.zip (exact match)
        r'UFDR_FILE[^\s\)\]\n]*',  # UFDR_FILE.format.zip.encrypted patterns (more aggressive)
        r'\[UFDR_FILE[^\]]*\]',  # [UFDR_FILE.format.zip]
        r'`UFDR_FILE[^`]*`',  # `UFDR_FILE.format.zip` (code blocks)
    ]
    
    # Remove generic file citations (more aggressive)
    for pattern in generic_filenames:
        # Pattern: "Source: file.json" or "(Source: file.json)" or "[Source: file.json]"
        citation_patterns = [
            rf'Source:\s*{pattern}[^\n]*',
            rf'\(Source:\s*{pattern}[^\)]*\)',
            rf'\[Source:\s*{pattern}[^\]]*\]',
            rf'\[{pattern}[^\]]*\]',  # Just [file.json] or [UFDR_FILE...]
            rf'from\s+{pattern}[^\n]*',
            rf'in\s+{pattern}[^\n]*',
            rf'Evidence:\s*\[{pattern}[^\]]*\]',  # Evidence: [file.json]
        ]
        for cit_pattern in citation_patterns:
            cleaned_text = re.sub(cit_pattern, '', cleaned_text, flags=re.IGNORECASE | re.MULTILINE)
    
    # Remove Evidence IDs
    evidence_id_patterns = [
        r'Evidence\s+ID:\s*[A-Z0-9\-]+',
        r'EVI[DENCE]?[-_]?\d+',
        r'EVD[-_]?\d+',
        r'ARTIFACT[-_]?\d+',
    ]
    for pattern in evidence_id_patterns:
        cleaned_text = re.sub(pattern, '', cleaned_text, flags=re.IGNORECASE)
    
    # Remove generic file paths
    generic_path_patterns = [
        r'/data/ufdr/[^\s\)\]\n]+',
        r'/forensic/[^\s\)\]\n]+',
        r'C:\\[^\s\)\]\n]+ufdr[^\s\)\]\n]+',
        r'[A-Z]:\\[^\s\)\]\n]+\.json',
    ]
    for pattern in generic_path_patterns:
        cleaned_text = re.sub(pattern, '', cleaned_text, flags=re.IGNORECASE)
    
    # Remove standalone "[file.json]" or "[UFDR_FILE...]" patterns
    cleaned_text = re.sub(r'\[file\.json\]', '', cleaned_text, flags=re.IGNORECASE)
    cleaned_text = re.sub(r'\[UFDR_FILE[^\]]*\]', '', cleaned_text, flags=re.IGNORECASE)
    
    # Remove template/placeholder patterns (brackets with placeholders like [Specific timestamp], [Message content])
    template_patterns = [
        r'\[Specific timestamp\]',
        r'\[Message content\]',
        r'\[Contact name\]',
        r'\[Another contact involved\]',
        r'\[Chronological sequence[^\]]*\]',
        r'\[Key contacts[^\]]*\]',
        r'\[Suspicious activities[^\]]*\]',
        r'\[Specific contact names[^\]]*\]',
        r'\[Message content themes[^\]]*\]',
        r'\[Timestamps of suspicious[^\]]*\]',
        r'\[Specific artifact names[^\]]*\]',
        r'\[Timestamp/Date[^\]]*\]',
        r'\[Source Message[^\]]*\]',
        r'\[EVIDENCE[^\]]*\]',
        r'\[TIMELINE[^\]]*\]',
        r'\[RELATIONSHIP[^\]]*\]',
        r'\[SECURITY[^\]]*\]',
        r'\[COMMUNICATION[^\]]*\]',
    ]
    for pattern in template_patterns:
        cleaned_text = re.sub(pattern, '', cleaned_text, flags=re.IGNORECASE)
    
    # Remove entire paragraphs/sentences that contain template phrases (more aggressive)
    template_phrases = [
        r'Since I cannot directly access[^.]*\.',
        r'cannot directly access or examine files[^.]*\.',
        r'I will outline how you should[^.]*\.',
        r'outline how you should structure[^.]*\.',
        r'provide the specific data or evidence[^.]*\.',
        r'files not uploaded here[^.]*\.',
        r'using the available data[^.]*\.',
    ]
    for phrase_pattern in template_phrases:
        # Remove entire sentences containing these phrases
        cleaned_text = re.sub(phrase_pattern, '', cleaned_text, flags=re.IGNORECASE | re.DOTALL)
        # Also remove multi-sentence blocks starting with these phrases
        cleaned_text = re.sub(rf'{phrase_pattern}[^.]*\.', '', cleaned_text, flags=re.IGNORECASE | re.DOTALL)
    
    # Remove sentences that reference "UFDR_FILE.format.zip" file
    cleaned_text = re.sub(r'[^.]*\bUFDR_FILE\.format\.zip[^.]*\.', '', cleaned_text, flags=re.IGNORECASE)
    cleaned_text = re.sub(r'[^.]*\bwithin the `UFDR_FILE[^`]*` file[^.]*\.', '', cleaned_text, flags=re.IGNORECASE)
    cleaned_text = re.sub(r'[^.]*\bfrom `UFDR_FILE[^`]*`[^.]*\.', '', cleaned_text, flags=re.IGNORECASE)
    cleaned_text = re.sub(r'[^.]*\bdata within the `UFDR_FILE[^`]*` file[^.]*\.', '', cleaned_text, flags=re.IGNORECASE)
    cleaned_text = re.sub(r'[^.]*\bexamine files not uploaded[^.]*\.', '', cleaned_text, flags=re.IGNORECASE)
    
    # Remove entire paragraphs that start with template phrases
    if 'since i cannot directly access' in cleaned_text.lower() or 'outline how you should' in cleaned_text.lower():
        # Remove the entire first paragraph if it contains template language
        cleaned_text = re.sub(r'^[^.]*[Ss]ince I cannot[^.]*\.\s*', '', cleaned_text, flags=re.IGNORECASE | re.MULTILINE)
        cleaned_text = re.sub(r'^[^.]*[Ii] will outline[^.]*\.\s*', '', cleaned_text, flags=re.IGNORECASE | re.MULTILINE)
        # Remove multi-paragraph template blocks
        cleaned_text = re.sub(r'Since I cannot[^.]*outline how you should[^.]*available data[^.]*\.', '', cleaned_text, flags=re.IGNORECASE | re.DOTALL)
    
    # Clean up multiple spaces and empty lines
    cleaned_text = re.sub(r'\n\s*\n\s*\n+', '\n\n', cleaned_text)  # Multiple newlines
    cleaned_text = re.sub(r'[ \t]+', ' ', cleaned_text)  # Multiple spaces/tabs
    cleaned_text = re.sub(r'^\s+', '', cleaned_text, flags=re.MULTILINE)  # Leading spaces on lines
    cleaned_text = cleaned_text.strip()
    
    return cleaned_text


class EvidenceValidator:
    """
    Validates evidence citations in LLM responses against actual forensic data.
    Prevents hallucination by checking if cited evidence actually exists.
    """
    
    def __init__(self, data_src: Dict):
        """
        Initialize validator with actual forensic data.
        
        Args:
            data_src: Dictionary of filename -> data mappings from uploaded UFDR files
        """
        self.data_src = data_src
        self.available_filenames = set(data_src.keys())
        # Remove metadata keys
        self.available_filenames = {f for f in self.available_filenames if not f.startswith('_')}
        
        # Build indexes for fast lookup
        self._build_indexes()
    
    def _build_indexes(self):
        """Build indexes of actual data for fast validation."""
        self.contact_names = set()
        self.phone_numbers = set()
        self.message_texts = set()
        self.timestamps = set()
        
        for filename, data in self.data_src.items():
            if filename.startswith('_'):
                continue
            
            if isinstance(data, dict):
                # Index contacts
                for contact in data.get('contacts', []):
                    name = contact.get('name', '').strip()
                    if name:
                        self.contact_names.add(name.lower())
                    phone = contact.get('phone', '').strip()
                    if phone:
                        self.phone_numbers.add(phone)
                
                # Index messages
                for msg in data.get('messages', []):
                    text = msg.get('text') or msg.get('content', '')
                    if text:
                        # Store first 100 chars for matching
                        self.message_texts.add(text[:100].lower())
                    timestamp = msg.get('timestamp', '')
                    if timestamp:
                        self.timestamps.add(str(timestamp))
                
                # Index call logs
                for call in data.get('call_logs', []):
                    timestamp = call.get('timestamp', '')
                    if timestamp:
                        self.timestamps.add(str(timestamp))
    
    def validate_response(self, llm_response: str) -> Dict:
        """
        Validate an LLM response against actual forensic data.
        
        Args:
            llm_response: The LLM-generated response text
            
        Returns:
            Dictionary with validation results:
            - is_validated: bool - Whether evidence was successfully validated
            - validation_score: float - Score from 0.0 to 1.0
            - issues: List[str] - List of validation issues found
            - verified_evidence: List[Dict] - List of verified evidence items
            - unverified_citations: List[str] - List of citations that couldn't be verified
        """
        issues = []
        verified_evidence = []
        unverified_citations = []
        
        # Extract evidence citations from response
        citations = self._extract_citations(llm_response)
        
        # Check for fabricated Evidence IDs
        evidence_ids = self._extract_evidence_ids(llm_response)
        if evidence_ids:
            issues.append(f"Found {len(evidence_ids)} fabricated Evidence ID(s): {', '.join(evidence_ids[:3])}")
            unverified_citations.extend([f"Evidence ID: {eid}" for eid in evidence_ids])
        
        # Check for file path citations
        file_citations = self._extract_file_citations(llm_response)
        verified_files = 0
        for file_citation in file_citations:
            # Check if file exists in actual data
            if file_citation in self.available_filenames:
                verified_evidence.append({
                    'type': 'file',
                    'citation': file_citation,
                    'status': 'verified'
                })
                verified_files += 1
            else:
                # Check if it's a partial match (e.g., "contacts.json" vs "contacts_2024.json")
                partial_match = any(f.startswith(file_citation.split('.')[0]) for f in self.available_filenames)
                if partial_match:
                    verified_evidence.append({
                        'type': 'file',
                        'citation': file_citation,
                        'status': 'partial_match'
                    })
                    verified_files += 1
                else:
                    issues.append(f"Cited file not found in data: {file_citation}")
                    unverified_citations.append(f"File: {file_citation}")
        
        # Check for contact name citations
        contact_citations = self._extract_contact_citations(llm_response)
        verified_contacts = 0
        for contact in contact_citations:
            if contact.lower() in self.contact_names:
                verified_evidence.append({
                    'type': 'contact',
                    'citation': contact,
                    'status': 'verified'
                })
                verified_contacts += 1
            else:
                # Check for partial matches
                partial_match = any(c.lower().startswith(contact.lower()) or contact.lower() in c.lower() 
                                   for c in self.contact_names)
                if partial_match:
                    verified_evidence.append({
                        'type': 'contact',
                        'citation': contact,
                        'status': 'partial_match'
                    })
                    verified_contacts += 1
                else:
                    unverified_citations.append(f"Contact: {contact}")
        
        # Check for generic file paths (hallucinated paths)
        generic_paths = self._extract_generic_paths(llm_response)
        if generic_paths:
            issues.append(f"Found {len(generic_paths)} generic/hallucinated file path(s)")
            unverified_citations.extend([f"Generic path: {path}" for path in generic_paths[:5]])
        
        # Calculate validation score (improved logic)
        total_citations = len(citations) + len(evidence_ids) + len(file_citations) + len(contact_citations)
        verified_count = verified_files + verified_contacts
        validation_score = 0.0
        
        if total_citations > 0:
            # Base score: verified citations / total citations
            base_score = verified_count / total_citations if total_citations > 0 else 0.0
            
            # Penalty for hallucinated files/evidence IDs
            if evidence_ids or (file_citations and verified_files == 0):
                # Heavy penalty for fabricated evidence IDs or all files being fake
                penalty = 0.4
                base_score = max(0.0, base_score - penalty)
            
            validation_score = base_score
        elif len(issues) == 0 and len(citations) == 0:
            # No citations found - might be a general response without file citations
            # If contacts are mentioned and verified, give partial credit
            if verified_contacts > 0:
                validation_score = 0.6  # Partial verification for contact mentions
            else:
                validation_score = 0.5  # Neutral score for general responses
        
        # Determine if response is validated
        # More lenient: Allow partial validation if contacts are verified even with minor issues
        is_validated = (validation_score >= 0.7 and len(issues) == 0) or \
                      (validation_score >= 0.6 and verified_contacts > 0 and len(evidence_ids) == 0)
        
        return {
            'is_validated': is_validated,
            'validation_score': round(validation_score, 2),
            'issues': issues,
            'verified_evidence': verified_evidence,
            'unverified_citations': unverified_citations,
            'total_citations': total_citations,
            'verified_count': verified_count
        }
    
    def _extract_citations(self, text: str) -> List[str]:
        """Extract evidence citations from text."""
        citations = []
        
        # Pattern: "Source: filename.json" or "Source: message/call/contact"
        source_pattern = r'Source:\s*([^\s\n,]+)'
        citations.extend(re.findall(source_pattern, text, re.IGNORECASE))
        
        # Pattern: "Evidence ID: XXX" or "Evidence #XXX"
        evidence_pattern = r'Evidence\s*(?:ID|#)?\s*:?\s*([A-Z0-9\-]+)'
        citations.extend(re.findall(evidence_pattern, text, re.IGNORECASE))
        
        return citations
    
    def _extract_evidence_ids(self, text: str) -> List[str]:
        """Extract fabricated Evidence IDs (e.g., EVI-001, EVD-123)."""
        # Pattern for Evidence IDs: EVI-XXX, EVD-XXX, EVIDENCE-XXX, etc.
        patterns = [
            r'EVI[DENCE]?[-_]?\d+',
            r'Evidence\s*ID\s*:?\s*[A-Z0-9\-]+',
            r'EVD[-_]?\d+',
            r'ARTIFACT[-_]?\d+'
        ]
        
        evidence_ids = []
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            evidence_ids.extend(matches)
        
        return list(set(evidence_ids))  # Remove duplicates
    
    def _extract_file_citations(self, text: str) -> List[str]:
        """Extract file path citations from text."""
        file_citations = []
        
        # Pattern: "filename.json", "path/to/file.json", etc.
        # Match common file extensions
        file_pattern = r'([a-zA-Z0-9_\-/\\]+\.(?:json|txt|csv|xml|db|sqlite))'
        matches = re.findall(file_pattern, text)
        file_citations.extend(matches)
        
        # Also look for "from contacts.json" or "in messages.json"
        context_pattern = r'(?:from|in|source|file)\s+([a-zA-Z0-9_\-]+\.(?:json|txt|csv))'
        matches = re.findall(context_pattern, text, re.IGNORECASE)
        file_citations.extend(matches)
        
        # Remove generic/hallucinated filenames
        generic_names = ['file.json', 'data.json', 'messages.json', 'contacts.json', 
                        'calls.json', 'ufdr.json', 'evidence.json', 'report.json']
        file_citations = [f for f in file_citations if f.lower() not in generic_names]
        
        return list(set(file_citations))  # Remove duplicates
    
    def _extract_contact_citations(self, text: str) -> List[str]:
        """Extract contact name citations from text."""
        # This is a simplified extraction - in practice, you'd want more sophisticated NLP
        # For now, we'll look for capitalized names that appear in quotes or after "contact:"
        contact_pattern = r'(?:Contact|Name|Person):\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)'
        contacts = re.findall(contact_pattern, text)
        
        # Also look for names in quotes after timestamps or in evidence sections
        quoted_names = re.findall(r'"([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)"', text)
        contacts.extend(quoted_names)
        
        return list(set(contacts))  # Remove duplicates
    
    def _extract_generic_paths(self, text: str) -> List[str]:
        """Extract generic/hallucinated file paths (e.g., /data/ufdr/contacts.json)."""
        generic_patterns = [
            r'/data/ufdr/[^\s]+',
            r'/forensic/[^\s]+',
            r'C:\\[^\s]+ufdr[^\s]+',
            r'[A-Z]:\\[^\s]+\.json',
            r'/home/[^\s]+\.json',
            r'/var/[^\s]+\.json',
            r'UFDR_FILE[^\s]*',  # Catch "UFDR_FILE.format.zip.encrypted" patterns
            r'file\.json',  # Generic "file.json"
            r'data\.json',  # Generic "data.json"
        ]
        
        generic_paths = []
        for pattern in generic_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            generic_paths.extend(matches)
        
        return list(set(generic_paths))  # Remove duplicates
    
    def get_quality_indicator(self, validation_result: Dict) -> Dict:
        """
        Generate quality indicator metadata for UI display.
        
        Args:
            validation_result: Result from validate_response()
            
        Returns:
            Dictionary with quality indicator data:
            - badge: str - Badge text (e.g., "Verified", "Unverified")
            - badge_class: str - CSS class for badge styling
            - confidence_level: str - "High", "Medium", "Low"
            - data_backed: bool - Whether response is backed by actual data
            - warning_message: Optional[str] - Warning message if issues found
        """
        score = validation_result['validation_score']
        issues = validation_result['issues']
        is_validated = validation_result['is_validated']
        
        # Determine badge
        if is_validated and score >= 0.9:
            badge = "✓ Verified"
            badge_class = "quality-badge-verified"
            confidence_level = "High"
        elif is_validated and score >= 0.7:
            badge = "✓ Mostly Verified"
            badge_class = "quality-badge-partial"
            confidence_level = "Medium"
        elif score >= 0.5:
            badge = "⚠ Partially Verified"
            badge_class = "quality-badge-warning"
            confidence_level = "Medium"
        else:
            badge = "⚠ Unverified"
            badge_class = "quality-badge-unverified"
            confidence_level = "Low"
        
        # Determine if data-backed
        data_backed = validation_result['verified_count'] > 0
        
        # Generate warning message
        warning_message = None
        if issues:
            if len(issues) <= 2:
                warning_message = "; ".join(issues)
            else:
                warning_message = f"{issues[0]}; and {len(issues) - 1} more issue(s)"
        
        return {
            'badge': badge,
            'badge_class': badge_class,
            'confidence_level': confidence_level,
            'data_backed': data_backed,
            'warning_message': warning_message,
            'validation_score': score
        }


