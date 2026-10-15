#!/usr/bin/env python3
"""
Enhanced Natural Language UFDR Query Engine

Provides robust natural language query handling with advanced keyword detection,
semantic understanding, and comprehensive information retrieval from UFDR data.
Features include:
- Multi-level keyword detection (exact, fuzzy, semantic)
- Context-aware query understanding
- Comprehensive forensic analysis
- Intelligent result ranking and filtering
"""

import os
import re
import json
import difflib
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Set
from collections import defaultdict, Counter
from dataclasses import dataclass
import logging

# Optional dependencies for enhanced functionality
try:
    from transformers import pipeline
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False

try:
    import spacy
    HAS_SPACY = True
except ImportError:
    HAS_SPACY = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class QueryResult:
    """Structured query result with metadata."""
    query: str
    matches: List[Dict[str, Any]]
    summary: str
    confidence: float
    keywords_found: List[str]
    analysis_type: str
    recommendations: List[str]

class EnhancedKeywordDetector:
    """Advanced keyword detection with multiple matching strategies."""
    
    def __init__(self):
        """Initialize the keyword detector with comprehensive keyword sets."""
        
        # Forensic investigation categories
        self.keyword_categories = {
            'financial_fraud': {
                'primary': ['money', 'payment', 'transfer', 'bank', 'account', 'wire', 'deposit', 'withdraw'],
                'secondary': ['fee', 'processing', 'transaction', 'balance', 'credit', 'debit', 'loan', 'investment'],
                'context': ['suspicious', 'urgent', 'immediate', 'secret', 'confidential', 'cash', 'bitcoin', 'crypto']
            },
            'identity_theft': {
                'primary': ['password', 'pin', 'otp', 'credential', 'login', 'username', 'ssn', 'social security'],
                'secondary': ['verification', 'authenticate', 'confirm', 'validate', 'access', 'account'],
                'context': ['steal', 'hack', 'breach', 'compromise', 'phishing', 'fake', 'impersonate']
            },
            'data_breach': {
                'primary': ['data', 'file', 'document', 'database', 'backup', 'download', 'upload', 'share'],
                'secondary': ['confidential', 'classified', 'sensitive', 'private', 'restricted', 'internal'],
                'context': ['leak', 'expose', 'steal', 'copy', 'extract', 'unauthorized', 'illegal']
            },
            'communication_patterns': {
                'primary': ['call', 'message', 'text', 'chat', 'email', 'contact', 'phone'],
                'secondary': ['frequent', 'regular', 'pattern', 'unusual', 'strange', 'odd'],
                'context': ['suspicious', 'encrypted', 'coded', 'hidden', 'secret', 'anonymous']
            },
            'threat_indicators': {
                'primary': ['threat', 'danger', 'harm', 'violence', 'attack', 'bomb', 'weapon'],
                'secondary': ['plan', 'plot', 'scheme', 'target', 'victim', 'revenge'],
                'context': ['kill', 'hurt', 'destroy', 'eliminate', 'remove', 'silence']
            },
            'drug_activity': {
                'primary': ['drug', 'drugs', 'substance', 'pill', 'powder', 'package', 'delivery'],
                'secondary': ['deal', 'sell', 'buy', 'trade', 'exchange', 'supply', 'distribute'],
                'context': ['illegal', 'controlled', 'narcotic', 'cannabis', 'cocaine', 'heroin', 'meth']
            },
            'location_tracking': {
                'primary': ['location', 'address', 'place', 'where', 'gps', 'coordinates', 'map'],
                'secondary': ['meet', 'meeting', 'appointment', 'visit', 'travel', 'trip'],
                'context': ['secret', 'hidden', 'remote', 'isolated', 'abandoned', 'private']
            },
            'time_patterns': {
                'primary': ['time', 'when', 'date', 'schedule', 'timing', 'hour', 'minute'],
                'secondary': ['frequent', 'regular', 'pattern', 'unusual', 'late', 'early'],
                'context': ['suspicious', 'coordinated', 'synchronized', 'planned', 'organized']
            }
        }
        
        # Common forensic query intents
        self.query_intents = {
            'find_suspicious_activity': [
                'suspicious', 'unusual', 'strange', 'odd', 'abnormal', 'irregular', 'anomaly'
            ],
            'analyze_patterns': [
                'pattern', 'trend', 'frequency', 'regular', 'recurring', 'repeated'
            ],
            'search_content': [
                'find', 'search', 'look for', 'containing', 'about', 'regarding'
            ],
            'get_information': [
                'get', 'show', 'display', 'list', 'retrieve', 'extract'
            ],
            'analyze_relationships': [
                'relationship', 'connection', 'link', 'associate', 'network', 'group'
            ],
            'timeline_analysis': [
                'timeline', 'chronology', 'sequence', 'order', 'before', 'after', 'during'
            ]
        }
        
        # Initialize NLP models if available
        self.nlp = None
        self.sentiment_analyzer = None
        
        if HAS_SPACY:
            try:
                self.nlp = spacy.load("en_core_web_sm")
            except OSError:
                logger.warning("spaCy English model not found. Using basic NLP.")
        
        if HAS_TRANSFORMERS:
            skip_hf = os.getenv("EVI_SKIP_HF_MODELS", "").strip().lower() in ("1", "true", "yes")
            enable_hf = os.getenv("EVI_ENABLE_HF_ZERO_SHOT", "").strip().lower() in ("1", "true", "yes")
            if enable_hf and not skip_hf:
                try:
                    local_only = os.getenv("EVI_HF_LOCAL_FILES_ONLY", "1").strip().lower() in (
                        "1", "true", "yes"
                    )
                    self.sentiment_analyzer = pipeline(
                        "sentiment-analysis",
                        model="distilbert-base-uncased-finetuned-sst-2-english",
                        revision="af0f99b",
                        local_files_only=local_only,
                    )
                except Exception:
                    logger.warning("Could not load sentiment analysis model.")
            else:
                logger.info("Skipping Hugging Face sentiment model (optional; rule-based NLP still active).")
    
    def detect_keywords(self, text: str) -> Dict[str, Any]:
        """Detect keywords using multiple strategies."""
        text_lower = text.lower()
        
        # Exact keyword matching
        exact_matches = self._find_exact_matches(text_lower)
        
        # Fuzzy keyword matching
        fuzzy_matches = self._find_fuzzy_matches(text_lower)
        
        # Semantic keyword matching (if NLP available)
        semantic_matches = self._find_semantic_matches(text) if self.nlp else {}
        
        # Intent detection
        detected_intents = self._detect_intents(text_lower)
        
        # Combine results
        return {
            'exact_matches': exact_matches,
            'fuzzy_matches': fuzzy_matches,
            'semantic_matches': semantic_matches,
            'intents': detected_intents,
            'confidence': self._calculate_confidence(exact_matches, fuzzy_matches, semantic_matches)
        }
    
    def _find_exact_matches(self, text: str) -> Dict[str, List[str]]:
        """Find exact keyword matches in text."""
        matches = defaultdict(list)
        
        for category, keywords in self.keyword_categories.items():
            for level, word_list in keywords.items():
                for keyword in word_list:
                    if keyword in text:
                        matches[category].append(keyword)
        
        return dict(matches)
    
    def _find_fuzzy_matches(self, text: str, threshold: float = 0.8) -> Dict[str, List[Tuple[str, float]]]:
        """Find fuzzy keyword matches using string similarity."""
        matches = defaultdict(list)
        words = text.split()
        
        for category, keywords in self.keyword_categories.items():
            for level, word_list in keywords.items():
                for keyword in word_list:
                    for word in words:
                        similarity = difflib.SequenceMatcher(None, keyword, word).ratio()
                        if similarity >= threshold:
                            matches[category].append((keyword, similarity))
        
        return dict(matches)
    
    def _find_semantic_matches(self, text: str) -> Dict[str, List[str]]:
        """Find semantic matches using NLP models."""
        if not self.nlp:
            return {}
        
        doc = self.nlp(text)
        matches = defaultdict(list)
        
        # Extract entities and analyze their context
        for ent in doc.ents:
            if ent.label_ in ['PERSON', 'ORG', 'MONEY', 'DATE', 'TIME', 'GPE']:
                matches['entities'].append(f"{ent.text} ({ent.label_})")
        
        # Analyze sentiment for suspicious content
        if self.sentiment_analyzer:
            try:
                sentiment = self.sentiment_analyzer(text)[0]
                if sentiment['label'] == 'NEGATIVE' and sentiment['score'] > 0.8:
                    matches['sentiment'].append('negative_sentiment')
            except Exception:
                pass
        
        return dict(matches)
    
    def _detect_intents(self, text: str) -> List[str]:
        """Detect query intents from text."""
        detected = []
        
        for intent, keywords in self.query_intents.items():
            if any(keyword in text for keyword in keywords):
                detected.append(intent)
        
        return detected
    
    def _calculate_confidence(self, exact: Dict, fuzzy: Dict, semantic: Dict) -> float:
        """Calculate overall confidence score for keyword detection."""
        score = 0.0
        
        # Exact matches have highest weight
        score += len(sum(exact.values(), [])) * 0.5
        
        # Fuzzy matches have medium weight
        score += len(sum(fuzzy.values(), [])) * 0.3
        
        # Semantic matches have lower weight
        score += len(sum(semantic.values(), [])) * 0.2
        
        return min(score, 1.0)

class EnhancedNaturalLanguageUFDR:
    """Enhanced natural language query engine for UFDR data."""
    
    def __init__(self, ufdr_data: Dict[str, Dict[str, Any]]):
        """Initialize the enhanced query engine."""
        self.ufdr_data = ufdr_data
        self.keyword_detector = EnhancedKeywordDetector()
        
        # Cache for performance
        self.query_cache = {}
        self.analysis_cache = {}
        
        # Initialize data indices for faster searching
        self._build_indices()
    
    def _build_indices(self):
        """Build search indices for faster querying."""
        self.message_index = defaultdict(list)
        self.contact_index = defaultdict(list)
        self.call_index = defaultdict(list)
        self.file_index = defaultdict(list)
        
        for filename, data in self.ufdr_data.items():
            # Index messages
            for msg in data.get('messages', []):
                text = (msg.get('text') or msg.get('content') or '').lower()
                words = re.findall(r'\w+', text)
                for word in words:
                    self.message_index[word].append({**msg, 'source_file': filename})
            
            # Index contacts
            for contact in data.get('contacts', []):
                name = (contact.get('name') or '').lower()
                phone = contact.get('phone') or ''
                if name:
                    self.contact_index[name].append({**contact, 'source_file': filename})
                if phone:
                    self.contact_index[phone].append({**contact, 'source_file': filename})
            
            # Index calls
            for call in data.get('call_logs', []):
                caller = (call.get('from') or call.get('caller') or '').lower()
                receiver = (call.get('to') or call.get('receiver') or '').lower()
                if caller:
                    self.call_index[caller].append({**call, 'source_file': filename})
                if receiver:
                    self.call_index[receiver].append({**call, 'source_file': filename})
            
            # Index files
            for file_obj in data.get('files', []):
                filename_lower = (file_obj.get('filename') or '').lower()
                if filename_lower:
                    self.file_index[filename_lower].append({**file_obj, 'source_file': filename})
    
    def query(self, user_query: str, chat_history: Optional[List[Dict[str, str]]] = None) -> QueryResult:
        """Process a natural language query and return comprehensive results.
        
        Args:
            user_query: The user's query string
            chat_history: Optional list of previous conversation messages in format
                         [{"role": "user|assistant", "content": "..."}, ...]
        
        Returns:
            QueryResult object with query results and metadata
            
        Raises:
            ValueError: If user_query is empty or invalid
            TypeError: If chat_history has invalid format
        """
        try:
            # Validate input
            if not user_query or not isinstance(user_query, str):
                raise ValueError(f"Invalid user_query: expected non-empty string, got {type(user_query)}")
            
            user_query = user_query.strip()
            if not user_query:
                raise ValueError("user_query cannot be empty or whitespace only")
            
            # Validate chat_history format if provided
            if chat_history is not None:
                if not isinstance(chat_history, list):
                    raise TypeError(f"chat_history must be a list, got {type(chat_history)}")
                
                # Validate each message in history
                for i, msg in enumerate(chat_history):
                    if not isinstance(msg, dict):
                        logger.warning(f"Invalid message format at index {i}: expected dict, got {type(msg)}")
                        continue
                    if 'role' not in msg or 'content' not in msg:
                        logger.warning(f"Message at index {i} missing required fields (role/content): {msg}")
            
            # Enhance query with chat history context if available
            try:
                enhanced_query = self._enhance_query_with_context(user_query, chat_history)
            except Exception as e:
                logger.error(f"Error enhancing query with chat history context: {e}", exc_info=True)
                # Fallback to original query if enhancement fails
                enhanced_query = user_query
                logger.info("Falling back to original query without context enhancement")
            
            # Check cache first (use original query for cache key to maintain consistency)
            try:
                cache_key = f"{user_query}:{hash(str(chat_history)) if chat_history else ''}"
                if cache_key in self.query_cache:
                    logger.debug(f"Cache hit for query: {user_query[:50]}...")
                    return self.query_cache[cache_key]
            except Exception as e:
                logger.warning(f"Error checking cache: {e}, proceeding without cache")
                cache_key = user_query
            
            # Detect keywords and intents (use enhanced query for better context awareness)
            try:
                keyword_analysis = self.keyword_detector.detect_keywords(enhanced_query)
            except Exception as e:
                logger.error(f"Error in keyword detection: {e}", exc_info=True)
                # Fallback to basic keyword analysis
                keyword_analysis = {
                    'exact_matches': {},
                    'fuzzy_matches': {},
                    'semantic_matches': {},
                    'intents': [],
                    'confidence': 0.5
                }
                logger.warning("Using fallback keyword analysis due to detection error")
            
            # Determine the best analysis strategy
            try:
                analysis_type = self._determine_analysis_type(keyword_analysis)
            except Exception as e:
                logger.error(f"Error determining analysis type: {e}", exc_info=True)
                analysis_type = 'general_search'
                logger.warning(f"Falling back to general_search analysis type")
            
            # Execute the appropriate analysis
            try:
                matches = self._execute_analysis(enhanced_query, keyword_analysis, analysis_type)
            except Exception as e:
                logger.error(f"Error executing analysis: {e}", exc_info=True)
                matches = []
                logger.warning("Analysis execution failed, returning empty matches")
            
            # Generate insights and recommendations
            try:
                recommendations = self._generate_recommendations(keyword_analysis, matches, analysis_type)
            except Exception as e:
                logger.error(f"Error generating recommendations: {e}", exc_info=True)
                recommendations = []
                logger.warning("Recommendation generation failed, returning empty list")
            
            # Create result
            try:
                result = QueryResult(
                    query=user_query,  # Store original query, not enhanced
                    matches=matches,
                    summary=self._generate_summary(matches, analysis_type),
                    confidence=keyword_analysis.get('confidence', 0.5),
                    keywords_found=self._extract_found_keywords(keyword_analysis),
                    analysis_type=analysis_type,
                    recommendations=recommendations
                )
            except Exception as e:
                logger.error(f"Error creating QueryResult: {e}", exc_info=True)
                # Create minimal result as fallback
                result = QueryResult(
                    query=user_query,
                    matches=matches,
                    summary="Error processing query. Please try again.",
                    confidence=0.0,
                    keywords_found=[],
                    analysis_type=analysis_type,
                    recommendations=[]
                )
            
            # Cache result
            try:
                self.query_cache[cache_key] = result
            except Exception as e:
                logger.warning(f"Error caching result: {e}")
            
            return result
            
        except (ValueError, TypeError) as e:
            logger.error(f"Input validation error in query method: {e}", exc_info=True)
            raise
        except Exception as e:
            logger.error(f"Unexpected error in query method: {e}", exc_info=True)
            # Return minimal error result instead of raising to prevent complete failure
            return QueryResult(
                query=user_query if isinstance(user_query, str) else "",
                matches=[],
                summary=f"Error processing query: {str(e)}",
                confidence=0.0,
                keywords_found=[],
                analysis_type='error',
                recommendations=["Please check the query format and try again."]
            )
    
    def _enhance_query_with_context(self, user_query: str, chat_history: Optional[List[Dict[str, str]]] = None) -> str:
        """Enhance query with context from chat history.
        
        Extracts relevant information from previous conversations such as:
        - Phone numbers, contacts, dates mentioned
        - Previous query topics
        - Referenced entities
        
        Args:
            user_query: The original user query
            chat_history: Optional list of previous conversation messages
        
        Returns:
            Enhanced query string with context, or original query if enhancement fails
        """
        try:
            # Validate inputs
            if not user_query or not isinstance(user_query, str):
                logger.warning(f"Invalid user_query in _enhance_query_with_context: {type(user_query)}")
                return user_query if isinstance(user_query, str) else ""
            
            if not chat_history or len(chat_history) == 0:
                logger.debug("No chat history provided, returning original query")
                return user_query
            
            if not isinstance(chat_history, list):
                logger.warning(f"chat_history is not a list: {type(chat_history)}, returning original query")
                return user_query
            
            # Extract context from recent chat history (last 10 messages)
            try:
                recent_history = chat_history[-10:] if len(chat_history) > 10 else chat_history
                logger.debug(f"Processing {len(recent_history)} messages from chat history")
            except Exception as e:
                logger.error(f"Error slicing chat history: {e}", exc_info=True)
                return user_query
            
            context_entities = []
            context_keywords = []
            
            # Extract phone numbers, dates, and key terms from history
            phone_pattern = r'\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
            date_pattern = r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}\b'
            
            # Process each message in history
            for i, msg in enumerate(recent_history):
                try:
                    if not isinstance(msg, dict):
                        logger.warning(f"Message at index {i} is not a dict: {type(msg)}, skipping")
                        continue
                    
                    content = msg.get('content', '')
                    if not content or not isinstance(content, str):
                        logger.debug(f"Message at index {i} has no content or invalid content type")
                        continue
                    
                    # Extract phone numbers
                    try:
                        phones = re.findall(phone_pattern, content)
                        if phones:
                            context_entities.extend(phones)
                            logger.debug(f"Found {len(phones)} phone numbers in message {i}")
                    except Exception as e:
                        logger.warning(f"Error extracting phone numbers from message {i}: {e}")
                    
                    # Extract dates
                    try:
                        dates = re.findall(date_pattern, content, re.IGNORECASE)
                        if dates:
                            context_entities.extend(dates)
                            logger.debug(f"Found {len(dates)} dates in message {i}")
                    except Exception as e:
                        logger.warning(f"Error extracting dates from message {i}: {e}")
                    
                    # Extract important keywords (capitalized words, quoted strings)
                    try:
                        important_words = re.findall(r'\b[A-Z][a-z]+\b|"[^"]+"', content)
                        if important_words:
                            context_keywords.extend(important_words)
                    except Exception as e:
                        logger.warning(f"Error extracting keywords from message {i}: {e}")
                        
                except Exception as e:
                    logger.error(f"Error processing message at index {i}: {e}", exc_info=True)
                    continue  # Skip this message and continue with others
            
            # Build enhanced query
            enhanced_parts = [user_query]
            
            # Add relevant context if found
            if context_entities:
                try:
                    # Deduplicate while preserving order
                    unique_entities = []
                    seen = set()
                    for entity in context_entities:
                        if not isinstance(entity, str):
                            continue
                        entity_lower = entity.lower()
                        if entity_lower not in seen:
                            unique_entities.append(entity)
                            seen.add(entity_lower)
                    
                    if unique_entities:
                        # Limit to 5 entities to avoid query bloat
                        context_str = f"Context from previous conversation: {', '.join(unique_entities[:5])}"
                        enhanced_parts.append(context_str)
                        logger.info(f"Enhanced query with {len(unique_entities[:5])} context entities")
                except Exception as e:
                    logger.error(f"Error processing context entities: {e}", exc_info=True)
                    # Continue without context entities
            
            # Check if current query is a follow-up (pronouns, "that", "it", "them", etc.)
            try:
                follow_up_indicators = ['it', 'that', 'them', 'this', 'those', 'these', 'he', 'she', 'they', 'him', 'her']
                query_lower = user_query.lower()
                is_follow_up = any(indicator in query_lower.split() for indicator in follow_up_indicators)
                
                if is_follow_up and recent_history:
                    logger.debug("Follow-up query detected, extracting context from previous response")
                    # Get the last assistant response to understand what "it" refers to
                    last_assistant_msg = None
                    for msg in reversed(recent_history):
                        if not isinstance(msg, dict):
                            continue
                        if msg.get('role') == 'assistant':
                            last_assistant_msg = msg.get('content', '')
                            break
                    
                    if last_assistant_msg and isinstance(last_assistant_msg, str):
                        try:
                            # Extract key entities from last response
                            key_terms = re.findall(r'\b(?:contact|phone|number|message|call|date|location|file|device)\b', last_assistant_msg, re.IGNORECASE)
                            if key_terms:
                                unique_terms = list(set(key_terms[:3]))  # Limit to 3 unique terms
                                enhanced_parts.append(f"Referring to: {', '.join(unique_terms)}")
                                logger.info(f"Detected follow-up query, added context: {unique_terms}")
                        except Exception as e:
                            logger.warning(f"Error extracting key terms from assistant message: {e}")
            except Exception as e:
                logger.error(f"Error in follow-up detection: {e}", exc_info=True)
                # Continue without follow-up enhancement
            
            # Join enhanced parts
            try:
                enhanced_query = ' '.join(enhanced_parts)
                
                # Log enhancement if context was added
                if enhanced_query != user_query:
                    logger.info(f"Query enhanced with chat history context (length: {len(enhanced_query)} chars)")
                    logger.debug(f"Original: '{user_query[:100]}...'")
                    logger.debug(f"Enhanced: '{enhanced_query[:100]}...'")
                
                return enhanced_query
            except Exception as e:
                logger.error(f"Error joining enhanced query parts: {e}", exc_info=True)
                return user_query
                
        except Exception as e:
            logger.error(f"Unexpected error in _enhance_query_with_context: {e}", exc_info=True)
            # Always return original query as fallback
            return user_query
    
    def _determine_analysis_type(self, keyword_analysis: Dict[str, Any]) -> str:
        """Determine the best analysis type based on detected keywords and intents."""
        
        exact_matches = keyword_analysis['exact_matches']
        intents = keyword_analysis['intents']
        
        # Priority-based analysis type selection
        if 'financial_fraud' in exact_matches:
            return 'financial_analysis'
        elif 'identity_theft' in exact_matches:
            return 'identity_analysis'
        elif 'data_breach' in exact_matches:
            return 'data_analysis'
        elif 'threat_indicators' in exact_matches:
            return 'threat_analysis'
        elif 'drug_activity' in exact_matches:
            return 'drug_analysis'
        elif 'analyze_patterns' in intents:
            return 'pattern_analysis'
        elif 'analyze_relationships' in intents:
            return 'relationship_analysis'
        elif 'timeline_analysis' in intents:
            return 'timeline_analysis'
        elif 'search_content' in intents:
            return 'content_search'
        else:
            return 'general_search'
    
    def _execute_analysis(self, query: str, keyword_analysis: Dict[str, Any], analysis_type: str) -> List[Dict[str, Any]]:
        """Execute the appropriate analysis based on the determined type."""
        
        if analysis_type == 'financial_analysis':
            return self._analyze_financial_activity(keyword_analysis)
        elif analysis_type == 'identity_analysis':
            return self._analyze_identity_theft(keyword_analysis)
        elif analysis_type == 'data_analysis':
            return self._analyze_data_breach(keyword_analysis)
        elif analysis_type == 'threat_analysis':
            return self._analyze_threats(keyword_analysis)
        elif analysis_type == 'drug_analysis':
            return self._analyze_drug_activity(keyword_analysis)
        elif analysis_type == 'pattern_analysis':
            return self._analyze_patterns(keyword_analysis)
        elif analysis_type == 'relationship_analysis':
            return self._analyze_relationships(keyword_analysis)
        elif analysis_type == 'timeline_analysis':
            return self._analyze_timeline(keyword_analysis)
        elif analysis_type == 'content_search':
            return self._search_content(keyword_analysis)
        else:
            return self._general_search(query, keyword_analysis)
    
    def _analyze_financial_activity(self, keyword_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze financial-related activities and transactions."""
        matches = []
        financial_keywords = keyword_analysis['exact_matches'].get('financial_fraud', [])
        
        for filename, data in self.ufdr_data.items():
            for msg in data.get('messages', []):
                text = (msg.get('text') or msg.get('content') or '').lower()
                
                # Check for financial keywords
                if any(keyword in text for keyword in financial_keywords):
                    # Additional analysis for suspicious patterns
                    suspicion_score = self._calculate_financial_suspicion(text)
                    
                    matches.append({
                        'type': 'financial_message',
                        'msg_id': msg.get('msg_id'),
                        'timestamp': msg.get('timestamp'),
                        'from': msg.get('from') or msg.get('sender'),
                        'to': msg.get('to') or msg.get('receiver'),
                        'text': msg.get('text') or msg.get('content'),
                        'suspicion_score': suspicion_score,
                        'keywords_found': [kw for kw in financial_keywords if kw in text],
                        'source_file': filename
                    })
        
        # Sort by suspicion score
        matches.sort(key=lambda x: x.get('suspicion_score', 0), reverse=True)
        return matches
    
    def _calculate_financial_suspicion(self, text: str) -> float:
        """Calculate suspicion score for financial content."""
        score = 0.0
        
        # High-risk indicators
        high_risk = ['urgent', 'immediate', 'secret', 'confidential', 'cash only', 'no questions']
        score += sum(0.3 for indicator in high_risk if indicator in text)
        
        # Medium-risk indicators
        medium_risk = ['fee', 'processing', 'advance', 'upfront', 'guarantee']
        score += sum(0.2 for indicator in medium_risk if indicator in text)
        
        # Low-risk indicators
        low_risk = ['money', 'payment', 'transfer', 'bank']
        score += sum(0.1 for indicator in low_risk if indicator in text)
        
        return min(score, 1.0)
    
    def _analyze_identity_theft(self, keyword_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze identity theft related activities."""
        matches = []
        identity_keywords = keyword_analysis['exact_matches'].get('identity_theft', [])
        
        for filename, data in self.ufdr_data.items():
            for msg in data.get('messages', []):
                text = (msg.get('text') or msg.get('content') or '').lower()
                
                if any(keyword in text for keyword in identity_keywords):
                    risk_score = self._calculate_identity_risk(text)
                    
                    matches.append({
                        'type': 'identity_threat',
                        'msg_id': msg.get('msg_id'),
                        'timestamp': msg.get('timestamp'),
                        'from': msg.get('from') or msg.get('sender'),
                        'to': msg.get('to') or msg.get('receiver'),
                        'text': msg.get('text') or msg.get('content'),
                        'risk_score': risk_score,
                        'keywords_found': [kw for kw in identity_keywords if kw in text],
                        'source_file': filename
                    })
        
        matches.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        return matches
    
    def _calculate_identity_risk(self, text: str) -> float:
        """Calculate risk score for identity theft content."""
        score = 0.0
        
        # Critical indicators
        critical = ['ssn', 'social security', 'password', 'pin', 'otp']
        score += sum(0.4 for indicator in critical if indicator in text)
        
        # High-risk indicators
        high_risk = ['verify', 'confirm', 'authenticate', 'login', 'account']
        score += sum(0.2 for indicator in high_risk if indicator in text)
        
        return min(score, 1.0)
    
    def _analyze_data_breach(self, keyword_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze data breach related activities."""
        matches = []
        data_keywords = keyword_analysis['exact_matches'].get('data_breach', [])
        
        # Analyze both messages and files
        for filename, data in self.ufdr_data.items():
            # Check messages
            for msg in data.get('messages', []):
                text = (msg.get('text') or msg.get('content') or '').lower()
                if any(keyword in text for keyword in data_keywords):
                    matches.append({
                        'type': 'data_message',
                        'msg_id': msg.get('msg_id'),
                        'timestamp': msg.get('timestamp'),
                        'from': msg.get('from') or msg.get('sender'),
                        'to': msg.get('to') or msg.get('receiver'),
                        'text': msg.get('text') or msg.get('content'),
                        'keywords_found': [kw for kw in data_keywords if kw in text],
                        'source_file': filename
                    })
            
            # Check files
            for file_obj in data.get('files', []):
                file_name = (file_obj.get('filename') or '').lower()
                if any(keyword in file_name for keyword in data_keywords):
                    matches.append({
                        'type': 'suspicious_file',
                        'filename': file_obj.get('filename'),
                        'timestamp': file_obj.get('timestamp'),
                        'size': file_obj.get('size'),
                        'path': file_obj.get('path'),
                        'keywords_found': [kw for kw in data_keywords if kw in file_name],
                        'source_file': filename
                    })
        
        return matches
    
    def _analyze_threats(self, keyword_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze threat indicators and violent content."""
        matches = []
        threat_keywords = keyword_analysis['exact_matches'].get('threat_indicators', [])
        
        for filename, data in self.ufdr_data.items():
            for msg in data.get('messages', []):
                text = (msg.get('text') or msg.get('content') or '').lower()
                
                if any(keyword in text for keyword in threat_keywords):
                    threat_level = self._calculate_threat_level(text)
                    
                    matches.append({
                        'type': 'threat_message',
                        'msg_id': msg.get('msg_id'),
                        'timestamp': msg.get('timestamp'),
                        'from': msg.get('from') or msg.get('sender'),
                        'to': msg.get('to') or msg.get('receiver'),
                        'text': msg.get('text') or msg.get('content'),
                        'threat_level': threat_level,
                        'keywords_found': [kw for kw in threat_keywords if kw in text],
                        'source_file': filename
                    })
        
        matches.sort(key=lambda x: x.get('threat_level', 0), reverse=True)
        return matches
    
    def _calculate_threat_level(self, text: str) -> str:
        """Calculate threat level based on content analysis."""
        critical_words = ['kill', 'bomb', 'weapon', 'attack', 'destroy']
        high_words = ['threat', 'harm', 'violence', 'hurt', 'revenge']
        medium_words = ['plan', 'plot', 'target', 'eliminate']
        
        if any(word in text for word in critical_words):
            return 'CRITICAL'
        elif any(word in text for word in high_words):
            return 'HIGH'
        elif any(word in text for word in medium_words):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _analyze_drug_activity(self, keyword_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze drug-related activities."""
        matches = []
        drug_keywords = keyword_analysis['exact_matches'].get('drug_activity', [])
        
        for filename, data in self.ufdr_data.items():
            for msg in data.get('messages', []):
                text = (msg.get('text') or msg.get('content') or '').lower()
                
                if any(keyword in text for keyword in drug_keywords):
                    matches.append({
                        'type': 'drug_message',
                        'msg_id': msg.get('msg_id'),
                        'timestamp': msg.get('timestamp'),
                        'from': msg.get('from') or msg.get('sender'),
                        'to': msg.get('to') or msg.get('receiver'),
                        'text': msg.get('text') or msg.get('content'),
                        'keywords_found': [kw for kw in drug_keywords if kw in text],
                        'source_file': filename
                    })
        
        return matches
    
    def _analyze_patterns(self, keyword_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze communication patterns and anomalies."""
        patterns = []
        
        # Analyze message frequency patterns
        message_patterns = self._analyze_message_patterns()
        patterns.extend(message_patterns)
        
        # Analyze call patterns
        call_patterns = self._analyze_call_patterns()
        patterns.extend(call_patterns)
        
        # Analyze time patterns
        time_patterns = self._analyze_time_patterns()
        patterns.extend(time_patterns)
        
        return patterns
    
    def _analyze_message_patterns(self) -> List[Dict[str, Any]]:
        """Analyze message frequency and patterns."""
        patterns = []
        contact_message_count = Counter()
        
        for filename, data in self.ufdr_data.items():
            for msg in data.get('messages', []):
                sender = msg.get('from') or msg.get('sender')
                receiver = msg.get('to') or msg.get('receiver')
                
                if sender:
                    contact_message_count[sender] += 1
                if receiver:
                    contact_message_count[receiver] += 1
        
        # Find high-frequency contacts
        for contact, count in contact_message_count.most_common(10):
            if count > 50:  # Threshold for high frequency
                patterns.append({
                    'type': 'high_frequency_contact',
                    'contact': contact,
                    'message_count': count,
                    'pattern': 'frequent_communication'
                })
        
        return patterns
    
    def _analyze_call_patterns(self) -> List[Dict[str, Any]]:
        """Analyze call frequency and duration patterns."""
        patterns = []
        call_data = []
        
        for filename, data in self.ufdr_data.items():
            for call in data.get('call_logs', []):
                call_data.append({
                    'from': call.get('from') or call.get('caller'),
                    'to': call.get('to') or call.get('receiver'),
                    'duration': call.get('duration') or call.get('duration_seconds', 0),
                    'timestamp': call.get('timestamp')
                })
        
        # Analyze unusual call durations
        if call_data:
            durations = [call['duration'] for call in call_data if isinstance(call['duration'], (int, float))]
            if durations:
                avg_duration = sum(durations) / len(durations)
                
                for call in call_data:
                    if isinstance(call['duration'], (int, float)) and call['duration'] > avg_duration * 3:
                        patterns.append({
                            'type': 'unusual_call_duration',
                            'from': call['from'],
                            'to': call['to'],
                            'duration': call['duration'],
                            'average_duration': avg_duration,
                            'pattern': 'long_duration_call'
                        })
        
        return patterns
    
    def _analyze_time_patterns(self) -> List[Dict[str, Any]]:
        """Analyze temporal patterns in communications."""
        patterns = []
        time_data = []
        
        for filename, data in self.ufdr_data.items():
            for msg in data.get('messages', []):
                if msg.get('timestamp'):
                    time_data.append({
                        'timestamp': msg.get('timestamp'),
                        'type': 'message',
                        'from': msg.get('from') or msg.get('sender')
                    })
            
            for call in data.get('call_logs', []):
                if call.get('timestamp'):
                    time_data.append({
                        'timestamp': call.get('timestamp'),
                        'type': 'call',
                        'from': call.get('from') or call.get('caller')
                    })
        
        # Analyze for unusual time patterns (e.g., late night communications)
        for item in time_data:
            try:
                dt = datetime.fromisoformat(item['timestamp'].replace('Z', ''))
                hour = dt.hour
                
                if hour < 6 or hour > 23:  # Late night/early morning
                    patterns.append({
                        'type': 'unusual_time_communication',
                        'timestamp': item['timestamp'],
                        'hour': hour,
                        'communication_type': item['type'],
                        'from': item['from'],
                        'pattern': 'late_night_activity'
                    })
            except Exception:
                continue
        
        return patterns
    
    def _analyze_relationships(self, keyword_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze relationships and connections between contacts."""
        relationships = []
        contact_interactions = defaultdict(lambda: defaultdict(int))
        
        for filename, data in self.ufdr_data.items():
            # Analyze message relationships
            for msg in data.get('messages', []):
                sender = msg.get('from') or msg.get('sender')
                receiver = msg.get('to') or msg.get('receiver')
                
                if sender and receiver:
                    contact_interactions[sender][receiver] += 1
                    contact_interactions[receiver][sender] += 1
            
            # Analyze call relationships
            for call in data.get('call_logs', []):
                caller = call.get('from') or call.get('caller')
                receiver = call.get('to') or call.get('receiver')
                
                if caller and receiver:
                    contact_interactions[caller][receiver] += 1
                    contact_interactions[receiver][caller] += 1
        
        # Find strong relationships (high interaction count)
        for contact1, interactions in contact_interactions.items():
            for contact2, count in interactions.items():
                if count > 20:  # Threshold for strong relationship
                    relationships.append({
                        'type': 'strong_relationship',
                        'contact1': contact1,
                        'contact2': contact2,
                        'interaction_count': count,
                        'relationship_strength': 'high' if count > 50 else 'medium'
                    })
        
        return relationships
    
    def _analyze_timeline(self, keyword_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze timeline of events and activities."""
        timeline = []
        events = []
        
        for filename, data in self.ufdr_data.items():
            # Collect all timestamped events
            for msg in data.get('messages', []):
                if msg.get('timestamp'):
                    events.append({
                        'timestamp': msg.get('timestamp'),
                        'type': 'message',
                        'from': msg.get('from') or msg.get('sender'),
                        'to': msg.get('to') or msg.get('receiver'),
                        'content': msg.get('text') or msg.get('content'),
                        'source_file': filename
                    })
            
            for call in data.get('call_logs', []):
                if call.get('timestamp'):
                    events.append({
                        'timestamp': call.get('timestamp'),
                        'type': 'call',
                        'from': call.get('from') or call.get('caller'),
                        'to': call.get('to') or call.get('receiver'),
                        'duration': call.get('duration'),
                        'source_file': filename
                    })
        
        # Sort events by timestamp
        try:
            events.sort(key=lambda x: datetime.fromisoformat(x['timestamp'].replace('Z', '')))
        except Exception:
            pass
        
        # Analyze for clusters of activity
        if len(events) > 1:
            for i in range(len(events) - 1):
                try:
                    current_time = datetime.fromisoformat(events[i]['timestamp'].replace('Z', ''))
                    next_time = datetime.fromisoformat(events[i + 1]['timestamp'].replace('Z', ''))
                    
                    time_diff = (next_time - current_time).total_seconds()
                    
                    # If events are very close in time (within 5 minutes)
                    if time_diff < 300:
                        timeline.append({
                            'type': 'activity_cluster',
                            'start_time': events[i]['timestamp'],
                            'end_time': events[i + 1]['timestamp'],
                            'time_difference_seconds': time_diff,
                            'events': [events[i], events[i + 1]],
                            'pattern': 'rapid_succession_activity'
                        })
                except Exception:
                    continue
        
        return timeline
    
    def _search_content(self, keyword_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search for specific content based on keywords."""
        matches = []
        all_keywords = []
        
        # Collect all detected keywords
        for category_keywords in keyword_analysis['exact_matches'].values():
            all_keywords.extend(category_keywords)
        
        for filename, data in self.ufdr_data.items():
            for msg in data.get('messages', []):
                text = (msg.get('text') or msg.get('content') or '').lower()
                
                found_keywords = [kw for kw in all_keywords if kw in text]
                if found_keywords:
                    matches.append({
                        'type': 'content_match',
                        'msg_id': msg.get('msg_id'),
                        'timestamp': msg.get('timestamp'),
                        'from': msg.get('from') or msg.get('sender'),
                        'to': msg.get('to') or msg.get('receiver'),
                        'text': msg.get('text') or msg.get('content'),
                        'keywords_found': found_keywords,
                        'source_file': filename
                    })
        
        return matches
    
    def _general_search(self, query: str, keyword_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Perform general search across all data types."""
        matches = []
        query_words = re.findall(r'\w+', query.lower())
        
        for filename, data in self.ufdr_data.items():
            # Search messages
            for msg in data.get('messages', []):
                text = (msg.get('text') or msg.get('content') or '').lower()
                if any(word in text for word in query_words):
                    matches.append({
                        'type': 'message',
                        'msg_id': msg.get('msg_id'),
                        'timestamp': msg.get('timestamp'),
                        'from': msg.get('from') or msg.get('sender'),
                        'to': msg.get('to') or msg.get('receiver'),
                        'text': msg.get('text') or msg.get('content'),
                        'source_file': filename
                    })
            
            # Search contacts
            for contact in data.get('contacts', []):
                name = (contact.get('name') or '').lower()
                if any(word in name for word in query_words):
                    matches.append({
                        'type': 'contact',
                        'name': contact.get('name'),
                        'phone': contact.get('phone'),
                        'source_file': filename
                    })
            
            # Search files
            for file_obj in data.get('files', []):
                filename_lower = (file_obj.get('filename') or '').lower()
                if any(word in filename_lower for word in query_words):
                    matches.append({
                        'type': 'file',
                        'filename': file_obj.get('filename'),
                        'timestamp': file_obj.get('timestamp'),
                        'size': file_obj.get('size'),
                        'source_file': filename
                    })
        
        return matches
    
    def _generate_recommendations(self, keyword_analysis: Dict[str, Any], matches: List[Dict[str, Any]], analysis_type: str) -> List[str]:
        """Generate intelligent recommendations based on analysis results."""
        recommendations = []
        
        if analysis_type == 'financial_analysis':
            recommendations.extend([
                "Review all financial transactions for unusual patterns",
                "Cross-reference with bank records and financial institutions"
            ])
        
        elif analysis_type == 'identity_analysis':
            recommendations.extend([
                "Verify authenticity of identity-related communications",
                "Check for unauthorized access attempts"
            ])
        
        elif analysis_type == 'threat_analysis':
            recommendations.extend([
                "Escalate to appropriate authorities immediately",
                "Document all threat-related communications"
            ])
        
        elif analysis_type == 'pattern_analysis':
            recommendations.extend([
                "Investigate unusual communication patterns",
                "Analyze temporal correlations with external events"
            ])
        
        # Add general recommendations based on match count
        if len(matches) > 50:
            recommendations.append("High volume of matches detected - prioritize review by relevance")
        elif len(matches) == 0:
            recommendations.append("No matches found - consider broadening search criteria")
        
        # Limit to 2 recommendations
        return recommendations[:2]
    
    def _generate_summary(self, matches: List[Dict[str, Any]], analysis_type: str) -> str:
        """Generate a comprehensive summary of analysis results."""
        if not matches:
            return "No relevant evidence found in the UFDR data."
        
        match_count = len(matches)
        match_types = Counter(match.get('type', 'unknown') for match in matches)
        
        summary = f"Found {match_count} relevant items during {analysis_type.replace('_', ' ')}. "
        
        if match_types:
            type_breakdown = ", ".join([f"{count} {type_name}" for type_name, count in match_types.most_common(3)])
            summary += f"Breakdown: {type_breakdown}. "
        
        # Add specific insights based on analysis type
        if analysis_type == 'financial_analysis':
            high_suspicion = sum(1 for match in matches if match.get('suspicion_score', 0) > 0.7)
            if high_suspicion > 0:
                summary += f"{high_suspicion} items flagged as high suspicion. "
        
        elif analysis_type == 'threat_analysis':
            critical_threats = sum(1 for match in matches if match.get('threat_level') == 'CRITICAL')
            if critical_threats > 0:
                summary += f"{critical_threats} CRITICAL threat indicators found. "
        
        return summary.strip()
    
    def _extract_found_keywords(self, keyword_analysis: Dict[str, Any]) -> List[str]:
        """Extract all found keywords from the analysis."""
        found_keywords = []
        
        for category_keywords in keyword_analysis['exact_matches'].values():
            found_keywords.extend(category_keywords)
        
        for category_matches in keyword_analysis['fuzzy_matches'].values():
            found_keywords.extend([match[0] for match in category_matches])
        
        return list(set(found_keywords))
    
    def update_data(self, ufdr_data: Dict[str, Dict[str, Any]]):
        """Update the UFDR data and rebuild indices."""
        self.ufdr_data = ufdr_data
        self.query_cache.clear()
        self.analysis_cache.clear()
        self._build_indices()
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics about the UFDR data."""
        stats = {
            'total_files': len(self.ufdr_data),
            'total_messages': 0,
            'total_contacts': 0,
            'total_calls': 0,
            'total_files': 0,
            'date_range': {'earliest': None, 'latest': None},
            'top_contacts': [],
            'message_types': Counter(),
            'call_directions': Counter()
        }
        
        all_timestamps = []
        contact_frequency = Counter()
        
        for filename, data in self.ufdr_data.items():
            stats['total_messages'] += len(data.get('messages', []))
            stats['total_contacts'] += len(data.get('contacts', []))
            stats['total_calls'] += len(data.get('call_logs', []))
            stats['total_files'] += len(data.get('files', []))
            
            # Collect timestamps
            for msg in data.get('messages', []):
                if msg.get('timestamp'):
                    all_timestamps.append(msg['timestamp'])
                    stats['message_types'][msg.get('type', 'unknown')] += 1
                
                # Count contact frequency
                sender = msg.get('from') or msg.get('sender')
                receiver = msg.get('to') or msg.get('receiver')
                if sender:
                    contact_frequency[sender] += 1
                if receiver:
                    contact_frequency[receiver] += 1
            
            for call in data.get('call_logs', []):
                if call.get('timestamp'):
                    all_timestamps.append(call['timestamp'])
                
                direction = call.get('direction', 'unknown')
                stats['call_directions'][direction] += 1
        
        # Calculate date range
        if all_timestamps:
            try:
                parsed_timestamps = []
                for ts in all_timestamps:
                    try:
                        parsed_timestamps.append(datetime.fromisoformat(ts.replace('Z', '')))
                    except Exception:
                        continue
                
                if parsed_timestamps:
                    stats['date_range']['earliest'] = min(parsed_timestamps).isoformat()
                    stats['date_range']['latest'] = max(parsed_timestamps).isoformat()
            except Exception:
                pass
        
        # Top contacts
        stats['top_contacts'] = [{'contact': contact, 'frequency': freq} 
                                for contact, freq in contact_frequency.most_common(10)]
        
        return stats

# Example usage and testing
if __name__ == "__main__":
    # Example UFDR data for testing
    sample_data = {
        "test_file.json": {
            "messages": [
                {
                    "msg_id": "1",
                    "timestamp": "2024-01-15T10:30:00Z",
                    "from": "+1234567890",
                    "to": "+0987654321",
                    "text": "Can you transfer $5000 to my account urgently? It's confidential.",
                    "type": "text"
                },
                {
                    "msg_id": "2",
                    "timestamp": "2024-01-15T14:20:00Z",
                    "from": "+0987654321",
                    "to": "+1234567890",
                    "text": "Need your password and PIN for verification",
                    "type": "text"
                }
            ],
            "contacts": [
                {"name": "John Doe", "phone": "+1234567890"},
                {"name": "Jane Smith", "phone": "+0987654321"}
            ],
            "call_logs": [
                {
                    "from": "+1234567890",
                    "to": "+0987654321",
                    "timestamp": "2024-01-15T09:00:00Z",
                    "duration": 300
                }
            ]
        }
    }
    
    # Initialize the enhanced query engine
    engine = EnhancedNaturalLanguageUFDR(sample_data)
    
    # Test queries
    test_queries = [
        "Find suspicious money transfers",
        "Show me identity theft attempts",
        "Analyze communication patterns",
        "Look for threats or violence",
        "Find unusual activity patterns"
    ]
    
    print("Enhanced Natural Language UFDR Query Engine - Test Results")
    print("=" * 60)
    
    for query in test_queries:
        print(f"\nQuery: {query}")
        result = engine.query(query)
        print(f"Analysis Type: {result.analysis_type}")
        print(f"Confidence: {result.confidence:.2f}")
        print(f"Matches Found: {len(result.matches)}")
        print(f"Keywords: {', '.join(result.keywords_found)}")
        print(f"Summary: {result.summary}")
        print(f"Recommendations: {len(result.recommendations)} items")
        print("-" * 40)