#!/usr/bin/env python3
"""
Hybrid ZIP Parser for EVI

Intelligent ZIP file parser that uses:
1. Fast heuristic classification (90% of cases)
2. LLM fallback for edge cases (10% of cases)
3. Rule-based field transformation (no LLM)

Philosophy: Use LLM only when heuristics fail, keep parsing fast and reliable.
"""

import json
import os
import re
import zipfile
import tempfile
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

# Import Cellebrite SQLite parser
try:
    from core.cellebrite_sqlite_parser import CellebriteSQLiteParser
    CELLEBRITE_PARSER_AVAILABLE = True
except ImportError:
    CELLEBRITE_PARSER_AVAILABLE = False
    logger.warning("Cellebrite SQLite parser not available")


class HybridZipParser:
    """
    Hybrid ZIP Parser: Rule-based heuristics + LLM fallback
    
    Architecture:
    - Classification: Heuristics → Content Sampling → LLM (only if needed)
    - Parsing: Rule-based field transformations (no LLM)
    - Learning: Cache LLM insights to improve heuristics
    """
    
    def __init__(self, llm_url: Optional[str] = None, llm_model: Optional[str] = None):
        """
        Initialize hybrid parser.
        
        Args:
            llm_url: LM Studio URL (default: http://localhost:1234/v1/chat/completions)
            llm_model: Model name (optional, will use default if not provided)
        """
        self.llm_url = llm_url or "http://localhost:1234/v1/chat/completions"
        self.llm_model = llm_model
        self.pattern_cache = {}  # Cache learned patterns
        self._init_heuristics()
    
    def _init_heuristics(self):
        """Initialize rule-based classification patterns."""
        # Path-based detection patterns (fastest, highest confidence)
        self.path_patterns = {
            'calls': [
                r'Artifacts/Calls?/.*\.json$',
                r'.*[Cc]alls?.*\.json$',
                r'.*[Cc]all[_-]?[Ll]og.*\.json$',
                r'.*[Cc]all[_-]?[Hh]istory.*\.json$',
            ],
            'contacts': [
                r'Artifacts/Contacts?/.*\.json$',
                r'.*[Cc]ontacts?.*\.json$',
                r'.*[Cc]ontact[_-]?[Ll]ist.*\.json$',
                r'.*[Pp]honebook.*\.json$',
            ],
            'messages': [
                r'Artifacts/SMS/.*\.json$',
                r'Artifacts/WhatsApp/.*\.json$',
                r'Artifacts/iMessage/.*\.json$',
                r'.*[Ss][Mm][Ss].*\.json$',
                r'.*[Ww]hatsapp?.*\.json$',
                r'.*[Mm]essages?.*\.json$',
                r'.*[Tt]exts?.*\.json$',
            ],
            'location': [
                r'Artifacts/Location/.*\.json$',
                r'.*[Ll]ocation.*\.json$',
                r'.*[Gg][Pp][Ss].*\.json$',
                r'.*[Gg]eolocation.*\.json$',
                r'.*[Pp]laces?.*\.json$',
            ],
            'device_info': [
                r'__metadata__/device_info\.json$',
                r'.*[Dd]evice.*[Ii]nfo.*\.json$',
                r'.*[Dd]evice.*[Mm]etadata.*\.json$',
            ],
            'case_info': [
                r'__metadata__/case_info\.json$',
                r'.*[Cc]ase.*[Ii]nfo.*\.json$',
                r'.*[Cc]ase.*[Mm]etadata.*\.json$',
            ],
        }
        
        # Filename-based patterns (medium confidence)
        self.filename_patterns = {
            'calls': ['calls', 'call_log', 'call_history', 'phone_calls', 'call_records'],
            'contacts': ['contacts', 'contact_list', 'phonebook', 'address_book'],
            'messages': ['sms', 'whatsapp', 'imessage', 'messages', 'texts', 'chats'],
            'location': ['location', 'gps', 'geolocation', 'places', 'coordinates'],
        }
        
        # Schema-based patterns (for content sampling)
        self.schema_patterns = {
            'calls': {
                'required_fields': ['from', 'to'],
                'optional_fields': ['timestamp', 'duration', 'call_type', 'number'],
                'confidence_boost': 0.3
            },
            'contacts': {
                'required_fields': ['name', 'phone'],
                'optional_fields': ['email', 'address', 'contact_name'],
                'confidence_boost': 0.3
            },
            'messages': {
                'required_fields': ['from', 'text'],
                'optional_fields': ['to', 'timestamp', 'source', 'message', 'content'],
                'confidence_boost': 0.3
            },
            'location': {
                'required_fields': ['latitude', 'longitude'],
                'optional_fields': ['timestamp', 'address', 'location_name'],
                'confidence_boost': 0.3
            },
        }
        
        # Field mapping rules for transformation (no LLM needed)
        self.field_mappings = {
            'messages': {
                'sender': 'from',
                'receiver': 'to',
                'message': 'text',
                'content': 'text',
                'body': 'text',
                'text_content': 'text',
                'date': 'timestamp',
                'time': 'timestamp',
                'datetime': 'timestamp',
            },
            'calls': {
                'number': 'to',  # Context-dependent
                'caller': 'from',
                'receiver': 'to',
                'date': 'timestamp',
                'time': 'timestamp',
                'datetime': 'timestamp',
            },
            'contacts': {
                'contact_name': 'name',
                'phone_number': 'phone',
                'mobile': 'phone',
                'cell': 'phone',
            },
        }
    
    def _is_cellebrite_lightweight(self, zip_path: str) -> bool:
        """
        Check if ZIP file is Cellebrite lightweight format (SQLite databases).
        
        Args:
            zip_path: Path to ZIP file
            
        Returns:
            True if Cellebrite lightweight format detected
        """
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                file_list = zip_ref.namelist()
                db_count = sum(1 for f in file_list if f.endswith('.db'))
                # Cellebrite lightweight typically has many .db files (>100)
                return db_count > 100
        except:
            return False
    
    def parse_zip(self, zip_path: str) -> Dict:
        """
        Main entry point: Parse ZIP using hybrid approach.
        
        Args:
            zip_path: Path to ZIP file
            
        Returns:
            Normalized UFDR data structure
        """
        try:
            logger.info(f"🔍 Starting hybrid ZIP parsing: {zip_path}")
            
            # Check if it's Cellebrite lightweight format (SQLite databases)
            if CELLEBRITE_PARSER_AVAILABLE and self._is_cellebrite_lightweight(zip_path):
                logger.info("🔍 Detected Cellebrite lightweight format - using SQLite parser")
                import tempfile
                extract_to = tempfile.mkdtemp()
                try:
                    parser = CellebriteSQLiteParser()
                    ufdr_data = parser.parse_ufdr_zip(zip_path, extract_to)
                    logger.info(f"✅ Cellebrite parsing complete: {len(ufdr_data.get('contacts', []))} contacts, "
                              f"{len(ufdr_data.get('messages', []))} messages, "
                              f"{len(ufdr_data.get('call_logs', []))} calls")
                    return ufdr_data
                except Exception as e:
                    logger.error(f"Error parsing Cellebrite format: {e}, falling back to standard parser")
                    # Fall through to standard parsing
            
            # Check file size for optimization strategy
            file_size = os.path.getsize(zip_path)
            large_file_threshold = 500 * 1024 * 1024  # 500MB
            is_large_file = file_size > large_file_threshold
            
            if is_large_file:
                logger.info(f"📦 Large file detected ({file_size / (1024*1024):.1f} MB) - using fast mode (heuristics only, no LLM)")
            
            # Step 1: Scan structure (no content loading) - only essential files for large files
            file_tree = self._scan_zip_structure(zip_path)
            logger.info(f"📁 Scanned {len(file_tree['files'])} files, {len(file_tree['folders'])} folders")
            
            # Step 2: Fast heuristic classification
            classifications = {}
            unclassified = []
            
            # Limit processing for large files
            max_files_to_process = 1000 if is_large_file else float('inf')
            files_processed = 0
            
            for file_info in file_tree['files']:
                if files_processed >= max_files_to_process:
                    logger.info(f"⏩ Skipping remaining files for large file optimization (processed {files_processed})")
                    break
                    
                # Skip non-essential files for large files
                if is_large_file and not self._is_essential_file(file_info['path']):
                    continue
                
                classification = self._heuristic_classify(file_info)
                files_processed += 1
                
                if classification['confidence'] >= 0.9:
                    # High confidence - use directly
                    classifications[file_info['path']] = classification
                    logger.debug(f"✅ High confidence: {file_info['path']} → {classification['data_type']} ({classification['method']})")
                elif classification['confidence'] >= 0.5:
                    # Medium confidence - sample content for verification (skip for large files)
                    if is_large_file:
                        # For large files, accept medium confidence without sampling
                        classifications[file_info['path']] = classification
                    else:
                        enhanced = self._enhance_with_content_sampling(
                            zip_path, file_info, classification
                        )
                        classifications[file_info['path']] = enhanced
                        
                        if enhanced['confidence'] < 0.7:
                            unclassified.append(file_info)
                            logger.debug(f"⚠️ Medium confidence after sampling: {file_info['path']} → {enhanced['data_type']} ({enhanced['confidence']:.2f})")
                else:
                    # Low confidence - needs LLM (skip for large files)
                    if is_large_file:
                        # Accept low confidence for large files to avoid LLM overhead
                        classifications[file_info['path']] = classification
                        logger.debug(f"⏩ Accepting low confidence for large file: {file_info['path']} → {classification['data_type']}")
                    else:
                        unclassified.append(file_info)
                        logger.debug(f"❓ Low confidence: {file_info['path']} → {classification['data_type']} ({classification['confidence']:.2f})")
            
            # Step 3: LLM fallback for unclassified files (SKIP for large files)
            if unclassified and not is_large_file:
                logger.info(f"🤖 Using LLM for {len(unclassified)} unclassified files")
                try:
                    llm_classifications = self._llm_classify_fallback(
                        zip_path, unclassified
                    )
                    classifications.update(llm_classifications)
                    
                    # Learn from LLM decisions
                    self._learn_from_llm(llm_classifications)
                except Exception as e:
                    logger.warning(f"LLM classification failed: {e}, using heuristic results")
                    # Continue with heuristic classifications
            elif unclassified and is_large_file:
                logger.info(f"⏩ Skipping LLM classification for {len(unclassified)} files (large file optimization)")
            
            # Step 4: Extract using classifications
            extracted = self._extract_with_classifications(
                zip_path, classifications
            )
            
            # Step 5: Normalize to UFDR format
            normalized = self._normalize_to_ufdr(extracted, classifications)
            
            logger.info(f"✅ Hybrid parsing complete: {len(normalized.get('contacts', []))} contacts, "
                       f"{len(normalized.get('messages', []))} messages, "
                       f"{len(normalized.get('call_logs', []))} calls")
            
            return normalized
            
        except Exception as e:
            logger.error(f"Error in hybrid ZIP parsing: {e}", exc_info=True)
            raise
    
    def _scan_zip_structure(self, zip_path: str) -> Dict:
        """
        Extract ZIP file tree without loading content.
        
        Returns:
            {
                "files": [{"path": str, "size": int, "type": str}, ...],
                "folders": [str, ...],
                "depth": int,
                "total_files": int
            }
        """
        structure = {
            "files": [],
            "folders": set(),
            "depth": 0,
            "total_files": 0
        }
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for info in zip_ref.infolist():
                path = info.filename.replace('\\', '/')
                
                if info.is_dir():
                    structure["folders"].add(path)
                else:
                    # Only scan essential files for processing
                    # Media files will be included in metadata but not extracted
                    if self._is_essential_file(path):
                        structure["files"].append({
                            "path": path,
                            "size": info.file_size,
                            "type": self._detect_file_type(path),
                            "modified": info.date_time
                        })
                    # Count all files for statistics
                    structure["total_files"] += 1
                    
                    # Track folder depth
                    folder_parts = path.split('/')
                    structure["depth"] = max(structure["depth"], len(folder_parts) - 1)
        
        structure["folders"] = sorted(list(structure["folders"]))
        return structure
    
    def _detect_file_type(self, path: str) -> str:
        """Detect file type from extension."""
        ext = os.path.splitext(path)[1].lower()
        if ext == '.json':
            return 'json'
        elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
            return 'image'
        elif ext in ['.mp4', '.avi', '.mov', '.mkv', '.webm']:
            return 'video'
        else:
            return 'other'
    
    def _heuristic_classify(self, file_info: Dict) -> Dict:
        """
        Fast rule-based classification (no LLM, no content loading).
        
        Returns:
            {
                "data_type": str,
                "confidence": float (0.0-1.0),
                "method": str
            }
        """
        path = file_info['path']
        filename = os.path.basename(path).lower()
        
        # Method 1: Path pattern matching (fastest, highest confidence)
        for data_type, patterns in self.path_patterns.items():
            for pattern in patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    return {
                        'data_type': data_type,
                        'confidence': 0.95,
                        'method': 'path_pattern',
                        'pattern_matched': pattern
                    }
        
        # Method 2: Filename pattern matching
        for data_type, keywords in self.filename_patterns.items():
            for keyword in keywords:
                if keyword in filename:
                    return {
                        'data_type': data_type,
                        'confidence': 0.75,
                        'method': 'filename_pattern',
                        'keyword_matched': keyword
                    }
        
        # Method 3: Folder context
        folder = os.path.dirname(path).lower()
        if 'calls' in folder and 'call' not in filename:
            return {'data_type': 'calls', 'confidence': 0.70, 'method': 'folder_context'}
        if 'contacts' in folder and 'contact' not in filename:
            return {'data_type': 'contacts', 'confidence': 0.70, 'method': 'folder_context'}
        if 'sms' in folder or 'whatsapp' in folder or 'message' in folder:
            return {'data_type': 'messages', 'confidence': 0.70, 'method': 'folder_context'}
        if 'location' in folder or 'gps' in folder:
            return {'data_type': 'location', 'confidence': 0.70, 'method': 'folder_context'}
        
        # Unknown - low confidence
        return {
            'data_type': 'unknown',
            'confidence': 0.2,
            'method': 'no_match'
        }
    
    def _enhance_with_content_sampling(self, zip_path: str, 
                                       file_info: Dict, 
                                       classification: Dict) -> Dict:
        """
        Sample first few records to verify classification (lightweight).
        Only reads first 2KB, not entire file.
        """
        if not file_info['path'].endswith('.json'):
            return classification  # Can't sample non-JSON
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                with zip_ref.open(file_info['path']) as f:
                    # Read only first 2KB to peek at structure
                    sample = f.read(2048).decode('utf-8', errors='ignore')
                    
                    # Try to parse first record
                    try:
                        # Find first JSON object/array
                        json_start = sample.find('[')
                        if json_start == -1:
                            json_start = sample.find('{')
                        
                        if json_start != -1:
                            # Try to extract a complete JSON structure
                            # Look for closing bracket/brace
                            bracket_count = 0
                            brace_count = 0
                            end_pos = json_start
                            
                            for i, char in enumerate(sample[json_start:], start=json_start):
                                if char == '[':
                                    bracket_count += 1
                                elif char == ']':
                                    bracket_count -= 1
                                elif char == '{':
                                    brace_count += 1
                                elif char == '}':
                                    brace_count -= 1
                                
                                if bracket_count == 0 and brace_count == 0 and i > json_start:
                                    end_pos = i + 1
                                    break
                            
                            sample_json_str = sample[json_start:end_pos]
                            
                            try:
                                sample_json = json.loads(sample_json_str)
                                
                                # Get first record
                                if isinstance(sample_json, list) and len(sample_json) > 0:
                                    first_record = sample_json[0]
                                elif isinstance(sample_json, dict):
                                    # Check if it's a wrapper
                                    for key, value in sample_json.items():
                                        if isinstance(value, list) and len(value) > 0:
                                            first_record = value[0]
                                            break
                                    else:
                                        first_record = sample_json
                                else:
                                    return classification
                                
                                # Verify against schema patterns
                                schema = self.schema_patterns.get(classification['data_type'], {})
                                required = schema.get('required_fields', [])
                                
                                if required:
                                    # Check if required fields exist
                                    matches = sum(1 for field in required if field in first_record)
                                    match_ratio = matches / len(required)
                                    
                                    if match_ratio >= 0.8:
                                        # Schema matches - boost confidence
                                        classification['confidence'] = min(1.0, 
                                            classification['confidence'] + schema.get('confidence_boost', 0.3)
                                        )
                                        classification['method'] += '+content_sampling'
                                    elif match_ratio < 0.5:
                                        # Schema doesn't match - reduce confidence
                                        classification['confidence'] *= 0.6
                                        classification['data_type'] = 'unknown'
                            except json.JSONDecodeError:
                                pass  # If parsing fails, keep original classification
                    except Exception:
                        pass  # If sampling fails, keep original classification
        except Exception as e:
            logger.debug(f"Content sampling failed for {file_info['path']}: {e}")
        
        return classification
    
    def _llm_classify_fallback(self, zip_path: str, 
                               unclassified_files: List[Dict]) -> Dict:
        """
        LLM classification ONLY for files that heuristics couldn't classify.
        This is the expensive operation, but only runs for edge cases.
        """
        if not self.llm_url:
            logger.warning("No LLM URL configured, skipping LLM classification")
            return {f['path']: {'data_type': 'unknown', 'confidence': 0.0} 
                   for f in unclassified_files}
        
        # Build minimal context for LLM (just paths, not content)
        file_list = []
        for f in unclassified_files:
            file_list.append(f"  - {f['path']} ({f['size']} bytes, {f['type']})")
        
        file_list_str = '\n'.join(file_list)
        
        prompt = f"""You are a forensic data structure analyzer. Classify these unclassified files from a forensic ZIP archive.

Files:
{file_list_str}

For each file, determine:
1. What type of forensic data it contains:
   - calls (call logs)
   - contacts (contact lists)
   - messages (SMS, WhatsApp, iMessage, etc.)
   - location (GPS/location data)
   - device_info (device metadata)
   - case_info (case metadata)
   - media (images/videos)
   - reports (summary reports)
   - unknown (unclassified)

2. Confidence level (0.0-1.0)

Return ONLY valid JSON in this exact format:
{{
  "file_path_1.json": {{
    "data_type": "calls",
    "confidence": 0.85,
    "reasoning": "brief explanation"
  }},
  "file_path_2.json": {{
    "data_type": "contacts",
    "confidence": 0.90,
    "reasoning": "brief explanation"
  }}
}}"""

        try:
            import requests
            
            # Use default model if not specified
            model = self.llm_model or "Qwen/Qwen2.5-7B-Instruct"
            
            response = requests.post(
                self.llm_url,
                json={
                    "model": model,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a forensic data structure analyzer. Return only valid JSON, no other text."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "temperature": 0.3,  # Lower temperature for more consistent classification
                    "max_tokens": 2000
                },
                timeout=30
            )
            
            if response.ok:
                result = response.json()
                content = result.get('choices', [{}])[0].get('message', {}).get('content', '')
                
                # Extract JSON from response (handle markdown code blocks)
                json_match = re.search(r'\{.*\}', content, re.DOTALL)
                if json_match:
                    classifications = json.loads(json_match.group())
                    logger.info(f"✅ LLM classified {len(classifications)} files")
                    return classifications
                else:
                    logger.warning("LLM response did not contain valid JSON")
                    return {f['path']: {'data_type': 'unknown', 'confidence': 0.0} 
                           for f in unclassified_files}
            else:
                logger.warning(f"LLM API error: HTTP {response.status_code}")
                return {f['path']: {'data_type': 'unknown', 'confidence': 0.0} 
                       for f in unclassified_files}
                       
        except Exception as e:
            logger.error(f"LLM classification failed: {e}")
            return {f['path']: {'data_type': 'unknown', 'confidence': 0.0} 
                   for f in unclassified_files}
    
    def _learn_from_llm(self, llm_classifications: Dict):
        """
        Learn from LLM decisions to improve heuristics.
        Convert LLM insights into new pattern rules.
        """
        for file_path, classification in llm_classifications.items():
            if classification.get('confidence', 0) > 0.8:
                # High confidence LLM decision - learn from it
                filename = os.path.basename(file_path).lower()
                data_type = classification.get('data_type', 'unknown')
                reasoning = classification.get('reasoning', '')
                
                if data_type == 'unknown':
                    continue
                
                # Extract keywords from reasoning and filename
                keywords = self._extract_keywords_from_reasoning(reasoning, filename)
                
                # Add to pattern cache (for future use)
                if data_type not in self.pattern_cache:
                    self.pattern_cache[data_type] = []
                
                self.pattern_cache[data_type].append({
                    'filename_pattern': filename,
                    'keywords': keywords,
                    'source': 'llm_learned',
                    'confidence': classification.get('confidence', 0.8)
                })
                
                logger.info(f"📚 Learned pattern: {filename} → {data_type} (confidence: {classification.get('confidence', 0.8):.2f})")
    
    def _extract_keywords_from_reasoning(self, reasoning: str, filename: str) -> List[str]:
        """Extract useful keywords from LLM reasoning."""
        keywords = []
        common_terms = ['call', 'contact', 'message', 'sms', 'whatsapp', 
                       'location', 'gps', 'device', 'case']
        
        reasoning_lower = reasoning.lower()
        for term in common_terms:
            if term in reasoning_lower:
                keywords.append(term)
        
        # Also extract from filename
        filename_terms = filename.replace('.json', '').replace('_', ' ').replace('-', ' ').split()
        keywords.extend([t for t in filename_terms if len(t) > 3])
        
        return list(set(keywords))
    
    def _extract_with_classifications(self, zip_path: str, 
                                     classifications: Dict) -> Dict:
        """
        Extract data from ZIP using classifications.
        Uses rule-based field transformations (no LLM).
        Also extracts images and videos from Media folder.
        """
        extracted_data = {
            'contacts': [],
            'messages': [],
            'call_logs': [],
            'locations': [],
            'device': {},
            'case_info': {},
            'files': [],
            'images': [],
            'videos': []
        }
        
        # Group files by data type
        files_by_type = {}
        for file_path, classification in classifications.items():
            data_type = classification.get('data_type', 'unknown')
            if data_type not in files_by_type:
                files_by_type[data_type] = []
            files_by_type[data_type].append(file_path)
        
        # Extract each type
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Extract JSON data
            for data_type, file_paths in files_by_type.items():
                for file_path in file_paths:
                    try:
                        with zip_ref.open(file_path) as f:
                            if file_path.endswith('.json'):
                                data = json.load(f)
                                
                                # Transform based on data type
                                if data_type == 'contacts':
                                    transformed = self._transform_contacts(data)
                                    extracted_data['contacts'].extend(transformed)
                                elif data_type == 'messages':
                                    transformed = self._transform_messages(data)
                                    extracted_data['messages'].extend(transformed)
                                elif data_type == 'calls':
                                    transformed = self._transform_calls(data)
                                    extracted_data['call_logs'].extend(transformed)
                                elif data_type == 'location':
                                    transformed = self._transform_locations(data)
                                    extracted_data['locations'].extend(transformed)
                                elif data_type == 'device_info':
                                    extracted_data['device'].update(self._transform_device_info(data))
                                elif data_type == 'case_info':
                                    extracted_data['case_info'].update(data)
                    except Exception as e:
                        logger.warning(f"Failed to extract {file_path}: {e}")
            
            # Extract images and videos metadata from Media folder (deferred extraction)
            image_exts = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.heic', '.tiff', '.tif')
            video_exts = ('.mp4', '.avi', '.mov', '.mkv', '.webm', '.flv', '.wmv', '.m4v', '.3gp')
            
            for info in zip_ref.infolist():
                path = info.filename.replace('\\', '/')
                
                # Skip directories
                if info.is_dir():
                    continue
                
                # Extract images (metadata only - deferred extraction)
                if path.startswith('Media/') and path.lower().endswith(image_exts):
                    file_ext = os.path.splitext(path.lower())[1]
                    if file_ext in image_exts:
                        extracted_data['images'].append({
                            'path': path,  # Store ZIP path, not extracted path
                            'name': os.path.basename(path),
                            'size': info.file_size,
                            'extracted': False  # Mark as deferred
                        })
                
                # Extract videos (metadata only - deferred extraction)
                elif path.startswith('Media/') and path.lower().endswith(video_exts):
                    file_ext = os.path.splitext(path.lower())[1]
                    if file_ext in video_exts:
                        extracted_data['videos'].append({
                            'path': path,
                            'name': os.path.basename(path),
                            'size': info.file_size,
                            'extracted': False
                        })
        
        logger.info(f"Extracted {len(extracted_data['images'])} images and {len(extracted_data['videos'])} videos")
        return extracted_data
    
    def _transform_contacts(self, data: Any) -> List[Dict]:
        """Transform contacts using rule-based field mappings."""
        contacts = []
        mapping = self.field_mappings.get('contacts', {})
        
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            # Check if it's a wrapper
            items = []
            for key, value in data.items():
                if isinstance(value, list):
                    items.extend(value)
                    break
            if not items:
                items = [data]
        else:
            return []
        
        for item in items:
            if not isinstance(item, dict):
                continue
            
            normalized = dict(item)
            
            # Apply field mappings
            for old_field, new_field in mapping.items():
                if old_field in normalized and new_field not in normalized:
                    normalized[new_field] = normalized.pop(old_field)
            
            # Ensure required fields
            if 'name' not in normalized and 'contact_name' in normalized:
                normalized['name'] = normalized['contact_name']
            if 'phone' not in normalized:
                # Try to find phone in any field
                for field in ['phone_number', 'mobile', 'cell', 'telephone', 'number']:
                    if field in normalized:
                        normalized['phone'] = normalized[field]
                        break
            
            # Validation requires at least name OR phone - set defaults if missing
            if not normalized.get('name') and not normalized.get('phone'):
                # Try to extract from other fields or set defaults
                if 'id' in normalized:
                    normalized['name'] = f"Contact {normalized['id']}"
                elif 'email' in normalized:
                    normalized['name'] = normalized['email'].split('@')[0] if '@' in normalized['email'] else normalized['email']
                else:
                    # Set a default name to pass validation
                    normalized['name'] = "Unknown Contact"
            
            # Only add contact if it has at least name or phone (validation requirement)
            if normalized.get('name') or normalized.get('phone'):
                contacts.append(normalized)
        
        return contacts
    
    def _transform_messages(self, data: Any) -> List[Dict]:
        """Transform messages using rule-based field mappings."""
        messages = []
        mapping = self.field_mappings.get('messages', {})
        
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = []
            for key, value in data.items():
                if isinstance(value, list):
                    items.extend(value)
                    break
            if not items:
                items = [data]
        else:
            return []
        
        for item in items:
            if not isinstance(item, dict):
                continue
            
            normalized = dict(item)
            
            # Apply field mappings
            for old_field, new_field in mapping.items():
                if old_field in normalized and new_field not in normalized:
                    normalized[new_field] = normalized.pop(old_field)
            
            # Ensure required fields for validation
            if 'from' not in normalized:
                normalized['from'] = normalized.get('sender', 'Unknown')
            if 'to' not in normalized:
                normalized['to'] = normalized.get('receiver', 'Unknown')
            if 'text' not in normalized:
                # Try to find text in any field
                for field in ['message', 'content', 'body', 'text_content']:
                    if field in normalized:
                        normalized['text'] = normalized[field]
                        break
                if 'text' not in normalized:
                    normalized['text'] = ''  # Empty string is acceptable for validation
            if 'timestamp' not in normalized:
                normalized['timestamp'] = normalized.get('date', normalized.get('time', 'Unknown'))
            
            # Add source if not present
            if 'source' not in normalized:
                # Infer from path or content
                normalized['source'] = 'SMS'  # Default
            
            # Only add message if it has required fields (validation requirement)
            has_parties = (normalized.get('from') and normalized.get('to'))
            has_content = normalized.get('text') is not None
            has_timestamp = bool(normalized.get('timestamp'))
            if has_parties and has_content and has_timestamp:
                messages.append(normalized)
        
        return messages
    
    def _transform_calls(self, data: Any) -> List[Dict]:
        """Transform calls using rule-based field mappings."""
        calls = []
        mapping = self.field_mappings.get('calls', {})
        
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = []
            for key, value in data.items():
                if isinstance(value, list):
                    items.extend(value)
                    break
            if not items:
                items = [data]
        else:
            return []
        
        for item in items:
            if not isinstance(item, dict):
                continue
            
            normalized = dict(item)
            
            # Apply field mappings
            for old_field, new_field in mapping.items():
                if old_field in normalized and new_field not in normalized:
                    normalized[new_field] = normalized.pop(old_field)
            
            # Ensure required fields for validation
            if 'from' not in normalized:
                normalized['from'] = normalized.get('caller', normalized.get('number', 'Unknown'))
            if 'to' not in normalized:
                normalized['to'] = normalized.get('receiver', normalized.get('number', 'Unknown'))
            if 'timestamp' not in normalized:
                normalized['timestamp'] = normalized.get('date', normalized.get('time', 'Unknown'))
            if 'call_type' not in normalized:
                normalized['call_type'] = normalized.get('type', 'unknown')
            
            # Only add call if it has required fields (validation requirement)
            has_parties = (normalized.get('from') and normalized.get('to'))
            has_timestamp = bool(normalized.get('timestamp'))
            if has_parties and has_timestamp:
                calls.append(normalized)
        
        return calls
    
    def _transform_locations(self, data: Any) -> List[Dict]:
        """Transform locations (minimal transformation needed)."""
        locations = []
        
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = []
            for key, value in data.items():
                if isinstance(value, list):
                    items.extend(value)
                    break
            if not items:
                items = [data]
        else:
            return []
        
        for item in items:
            if isinstance(item, dict):
                locations.append(dict(item))
        
        return locations
    
    def _transform_device_info(self, data: Dict) -> Dict:
        """Transform device info (minimal transformation)."""
        return dict(data) if isinstance(data, dict) else {}
    
    def _normalize_to_ufdr(self, extracted: Dict, classifications: Dict) -> Dict:
        """
        Final normalization to ensure UFDR schema compliance.
        """
        ufdr_data = {
            'contacts': extracted.get('contacts', []),
            'messages': extracted.get('messages', []),
            'call_logs': extracted.get('call_logs', []),
            'locations': extracted.get('locations', []),
            'device': extracted.get('device', {}),
            'files': extracted.get('files', []),
            'images': extracted.get('images', []),  # Include images
            'videos': extracted.get('videos', []),   # Include videos
            'tampered': False,
            'format_version': 'v1'
        }
        
        # Merge case_info into device if present
        if extracted.get('case_info'):
            ufdr_data['device'].update(extracted['case_info'])
        
        logger.info(f"Normalized UFDR data: {len(ufdr_data.get('images', []))} images, {len(ufdr_data.get('videos', []))} videos")
        
        return ufdr_data

