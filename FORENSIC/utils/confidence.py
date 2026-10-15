#!/usr/bin/env python3
"""
Confidence Scoring System for Forensic AI Chat Assistant

Calculates confidence scores based on:
- Retrieval similarity scores
- Intent detection strength
- Data completeness
- Query complexity
"""

import math
from typing import Dict, List, Any, Tuple


class ConfidenceCalculator:
    """Calculate confidence scores for forensic chat responses."""
    
    def __init__(self):
        self.base_confidence = 0.5
        self.max_confidence = 1.0
        self.min_confidence = 0.0
    
    def calculate_confidence(self, 
                           retrieval_scores: List[float] = None,
                           intent_strength: float = 0.5,
                           data_completeness: float = 1.0,
                           query_complexity: float = 0.5,
                           response_quality: float = 0.8) -> float:
        """
        Calculate overall confidence score.
        
        Args:
            retrieval_scores: List of similarity scores from FAISS
            intent_strength: How well the intent was detected (0-1)
            data_completeness: How complete the data is (0-1)
            query_complexity: How complex the query is (0-1)
            response_quality: Quality of the generated response (0-1)
            
        Returns:
            Confidence score between 0 and 1
        """
        if retrieval_scores is None:
            retrieval_scores = [0.5]
        
        # Calculate average retrieval score
        avg_retrieval = sum(retrieval_scores) / len(retrieval_scores) if retrieval_scores else 0.5
        
        # Weighted confidence calculation
        weights = {
            'retrieval': 0.3,
            'intent': 0.25,
            'data_completeness': 0.2,
            'query_complexity': 0.15,
            'response_quality': 0.1
        }
        
        confidence = (
            weights['retrieval'] * avg_retrieval +
            weights['intent'] * intent_strength +
            weights['data_completeness'] * data_completeness +
            weights['query_complexity'] * (1.0 - query_complexity) +  # Lower complexity = higher confidence
            weights['response_quality'] * response_quality
        )
        
        # Apply sigmoid function for better distribution
        confidence = self._sigmoid(confidence)
        
        # Ensure within bounds
        confidence = max(self.min_confidence, min(self.max_confidence, confidence))
        
        return round(confidence, 3)
    
    def _sigmoid(self, x: float) -> float:
        """Apply sigmoid function for better confidence distribution."""
        return 1 / (1 + math.exp(-6 * (x - 0.5)))
    
    def calculate_intent_strength(self, query: str, detected_intent: str) -> float:
        """
        Calculate intent detection strength based on query analysis.
        
        Args:
            query: User's query
            detected_intent: Detected intent type
            
        Returns:
            Intent strength score (0-1)
        """
        # Safety check: ensure query is a string
        if not query or query is None:
            query = ""
        if not isinstance(query, str):
            query = str(query) if query else ""
        
        query_lower = query.lower() if query else ""
        
        # Direct command patterns (high confidence)
        direct_patterns = [
            'show all', 'find all', 'list all', 'get all',
            'count', 'total', 'how many'
        ]
        
        # Semantic patterns (medium confidence)
        semantic_patterns = [
            'who', 'what', 'when', 'where', 'why', 'how',
            'suspicious', 'unusual', 'frequent', 'recent'
        ]
        
        # Ambiguous patterns (low confidence)
        ambiguous_patterns = [
            'maybe', 'possibly', 'might', 'could', 'perhaps'
        ]
        
        # Special handling for LLM queries
        if detected_intent == "llm_query":
            return 0.95  # High confidence for LLM-generated responses
        
        # Check for direct patterns
        for pattern in direct_patterns:
            if pattern in query_lower:
                return 0.9
        
        # Check for semantic patterns
        for pattern in semantic_patterns:
            if pattern in query_lower:
                return 0.7
        
        # Check for ambiguous patterns
        for pattern in ambiguous_patterns:
            if pattern in query_lower:
                return 0.3
        
        # Default based on query length and specificity
        if len(query.split()) > 5:
            return 0.6  # Longer queries are usually more specific
        else:
            return 0.4  # Shorter queries might be ambiguous
    
    def calculate_data_completeness(self, data_sources: List[Dict]) -> float:
        """
        Calculate data completeness score.
        
        Args:
            data_sources: List of data source information
            
        Returns:
            Data completeness score (0-1)
        """
        if not data_sources:
            return 0.0
        
        total_sources = len(data_sources)
        complete_sources = sum(1 for source in data_sources if source.get('complete', True))
        
        return complete_sources / total_sources if total_sources > 0 else 0.0
    
    def calculate_query_complexity(self, query: str) -> float:
        """
        Calculate query complexity score.
        
        Args:
            query: User's query
            
        Returns:
            Query complexity score (0-1)
        """
        words = query.split()
        word_count = len(words)
        
        # Complex indicators
        complex_indicators = [
            'and', 'or', 'but', 'however', 'although', 'while',
            'compare', 'analyze', 'correlate', 'relationship'
        ]
        
        complex_count = sum(1 for word in words if word.lower() in complex_indicators)
        
        # Calculate complexity based on word count and complex indicators
        word_complexity = min(word_count / 20, 1.0)  # Normalize to 0-1
        indicator_complexity = min(complex_count / 5, 1.0)  # Normalize to 0-1
        
        return (word_complexity + indicator_complexity) / 2
    
    def get_confidence_explanation(self, confidence: float) -> str:
        """
        Get human-readable explanation of confidence level.
        
        Args:
            confidence: Confidence score (0-1)
            
        Returns:
            Explanation string
        """
        if confidence >= 0.9:
            return "Very High - Strong evidence and clear intent"
        elif confidence >= 0.8:
            return "High - Good evidence with clear patterns"
        elif confidence >= 0.7:
            return "Good - Solid evidence with some uncertainty"
        elif confidence >= 0.6:
            return "Moderate - Some evidence but limited data"
        elif confidence >= 0.5:
            return "Low - Weak evidence or incomplete data"
        else:
            return "Very Low - Insufficient evidence or unclear query"


# Global instance
confidence_calculator = ConfidenceCalculator()
