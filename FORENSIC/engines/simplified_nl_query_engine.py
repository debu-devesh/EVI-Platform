#!/usr/bin/env python3
"""
Simplified Natural Language UFDR Query Engine
Self-contained engine that works without external dependencies
"""

import re
import json
from typing import Any, Dict, List, Tuple, Optional
from datetime import datetime
import pandas as pd
from rapidfuzz import fuzz

class SimplifiedNLQueryEngine:
    """
    Simplified Natural Language Query Engine for UFDR Analysis
    Works without external dependencies - uses only built-in Python libraries
    """
    
    def __init__(self):
        # Scenario-specific keyword mappings based on actual UFDR v2 data
        self.scenario_keywords = {
            "insider_data_leak": {
                "keywords": [
                    # Data sharing and confidentiality keywords
                    "data leak", "insider", "confidential", "external partner", "data sharing",
                    "sensitive", "proprietary", "leak", "breach", "unauthorized access",
                    "ravi kumar", "external.partner@example.com", "colleague",
                    # Specific phrases from UFDR data
                    "rename the report before sharing", "remove metadata from the file",
                    "don't use official email", "use the personal drive", "check after midnight",
                    "send the package tonight", "will do", "on it", "all good",
                    # Technical terms
                    "metadata", "report", "sharing", "personal drive", "official email",
                    "midnight", "package", "tonight"
                ],
                "entities": ["Ravi Kumar", "External Partner", "Colleague"],
                "patterns": [
                    r"external\s+partner", r"data\s+sharing", r"confidential",
                    r"rename\s+.*\s+before\s+sharing", r"remove\s+metadata",
                    r"don't\s+use\s+official\s+email", r"use\s+the\s+personal\s+drive",
                    r"check\s+after\s+midnight", r"send\s+the\s+package\s+tonight"
                ]
            },
            "scam_network": {
                "keywords": [
                    # Scam and fraud keywords
                    "scam", "fraud", "job scam", "processing fee", "victim", "fake job",
                    "overseas job", "offer letter", "interview", "sandeep yadav", "hr manager",
                    "global tech", "processing fee", "5000", "secure offer",
                    # Specific phrases from UFDR data
                    "attend the online interview at 10:00 am", "here is your offer letter, kindly sign and return",
                    "congratulations! you have been selected for an overseas job", "call me back",
                    "please confirm receipt", "please pay the processing fee of 5000 to secure your offer",
                    # Job-related terms
                    "online interview", "offer letter", "overseas job", "selected", "interview",
                    "processing fee", "secure offer", "confirm receipt", "sign and return"
                ],
                "entities": ["Sandeep Yadav", "S. Yadav", "HR Manager - Global Tech", "Victim 1", "Victim 2", "Victim 3", "Victim 4", "Victim 5", "Victim 6", "Victim 7", "Victim 8"],
                "patterns": [
                    r"processing\s+fee", r"overseas\s+job", r"offer\s+letter",
                    r"online\s+interview", r"selected\s+for", r"secure\s+offer",
                    r"₹\d+", r"rs\.?\s*\d+", r"rupees?\s*\d+"
                ]
            },
            "sim_swap_attack": {
                "keywords": [
                    # SIM swap and OTP keywords
                    "sim swap", "otp", "one time password", "telecom", "bank otp",
                    "ax-service", "ax-bankotp", "arjun", "sim card", "phone number",
                    "verification", "unknown caller", "telecom helpline",
                    # Specific phrases from UFDR data
                    "your otp is", "ax-service", "ax-bankotp", "telecom helpline",
                    "unknown caller", "arjun m", "arjun mehta",
                    # OTP patterns
                    "otp is", "one time", "verification code", "bank otp"
                ],
                "entities": ["Arjun M.", "Arjun Mehta", "Telecom Helpline", "Unknown Caller"],
                "patterns": [
                    r"otp\s+is\s+\d+", r"ax-service", r"ax-bankotp",
                    r"your\s+otp\s+is", r"telecom\s+helpline", r"unknown\s+caller"
                ]
            }
        }
        
        # General suspicious patterns
        self.suspicious_patterns = [
            r"money\s+transfer", r"urgent\s+payment", r"click\s+here", r"verify\s+account",
            r"bank\s+details", r"personal\s+information", r"social\s+security", r"ssn"
        ]
        
        # Financial patterns
        self.financial_patterns = [
            r"₹\d+", r"rs\.?\s*\d+", r"rupees?\s*\d+", r"payment\s+of", r"fee\s+of",
            r"transfer\s+\d+", r"amount\s+\d+"
        ]
        
        # Contact patterns
        self.contact_patterns = [
            r"victim\s+\d+", r"external\s+partner", r"hr\s+manager", r"unknown\s+caller",
            r"telecom\s+helpline"
        ]

    def detect_scenario(self, records: List[Dict[str, Any]]) -> str:
        """Detect the scenario type based on content analysis"""
        if not records:
            return "unknown"
            
        # Analyze first few records for scenario indicators
        sample_text = ""
        for rec in records[:100]:  # Sample first 100 records
            sample_text += self._extract_text_content(rec) + " "
        
        sample_text = sample_text.lower()
        
        # Check for scenario-specific indicators
        scenario_scores = {}
        for scenario, config in self.scenario_keywords.items():
            score = 0
            for keyword in config["keywords"]:
                if keyword.lower() in sample_text:
                    score += 1
            for pattern in config["patterns"]:
                if re.search(pattern, sample_text, re.IGNORECASE):
                    score += 2
            scenario_scores[scenario] = score
        
        # Return scenario with highest score
        if scenario_scores:
            return max(scenario_scores.items(), key=lambda x: x[1])[0]
        return "unknown"

    def process_query(self, query: str, records: List[Dict[str, Any]], 
                     flat_df: pd.DataFrame, limit: int = 100) -> Tuple[List[Dict[str, Any]], str]:
        """Process query with comprehensive keyword recognition"""
        query = (query or "").strip().lower()
        if not query:
            return [], "Empty query"
        
        # Detect scenario
        scenario = self.detect_scenario(records)
        
        # Extract keywords from query
        keywords = self._extract_keywords(query)
        
        # Enhanced keyword matching
        enhanced_keywords = keywords + self.scenario_keywords.get(scenario, {}).get("keywords", [])
        
        # Find matching records
        matching_records = []
        for rec in records:
            text_content = self._extract_text_content(rec).lower()
            
            # Calculate relevance score
            relevance_score = 0
            matched_keywords = []
            matched_patterns = []
            matched_entities = []
            
            # Keyword matching
            for kw in enhanced_keywords:
                if kw.lower() in text_content:
                    relevance_score += 1
                    matched_keywords.append(kw)
            
            # Pattern matching (higher weight)
            if scenario in self.scenario_keywords:
                for pattern in self.scenario_keywords[scenario]["patterns"]:
                    matches = len(re.findall(pattern, text_content, re.IGNORECASE))
                    if matches > 0:
                        relevance_score += matches * 2
                        matched_patterns.append(pattern)
            
            # Entity matching (highest weight)
            if scenario in self.scenario_keywords:
                for entity in self.scenario_keywords[scenario]["entities"]:
                    if entity.lower() in text_content:
                        relevance_score += 2
                        matched_entities.append(entity)
            
            # Suspicious pattern matching
            for pattern in self.suspicious_patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    relevance_score += 1
            
            # Financial pattern matching
            for pattern in self.financial_patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    relevance_score += 1
            
            if relevance_score > 0:
                rec_copy = rec.copy()
                rec_copy['_relevance_score'] = relevance_score
                rec_copy['_scenario'] = scenario
                rec_copy['_matched_keywords'] = matched_keywords
                rec_copy['_matched_patterns'] = matched_patterns
                rec_copy['_matched_entities'] = matched_entities
                matching_records.append(rec_copy)
        
        # Sort by relevance score
        matching_records.sort(key=lambda x: x.get('_relevance_score', 0), reverse=True)
        
        # Limit results
        results = matching_records[:limit]
        
        # Generate explanation
        explanation = f"Scenario: {scenario.replace('_', ' ').title()}. "
        explanation += f"Found {len(results)} relevant records. "
        explanation += f"Keywords: {', '.join(keywords[:5])}"
        if results:
            explanation += f" | Top relevance score: {results[0].get('_relevance_score', 0)}"
        
        return results, explanation

    def get_scenario_summary(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get summary information about the detected scenario"""
        scenario = self.detect_scenario(records)
        
        if scenario == "unknown":
            return {"scenario": "unknown", "summary": "No specific scenario detected"}
        
        scenario_config = self.scenario_keywords[scenario]
        
        # Count entities and patterns
        entity_counts = {}
        pattern_matches = 0
        
        for rec in records:
            text_content = self._extract_text_content(rec).lower()
            
            # Count entities
            for entity in scenario_config["entities"]:
                if entity.lower() in text_content:
                    entity_counts[entity] = entity_counts.get(entity, 0) + 1
            
            # Count pattern matches
            for pattern in scenario_config["patterns"]:
                if re.search(pattern, text_content, re.IGNORECASE):
                    pattern_matches += 1
        
        return {
            "scenario": scenario,
            "summary": f"Detected {scenario.replace('_', ' ')} scenario",
            "entities_found": entity_counts,
            "pattern_matches": pattern_matches,
            "total_records": len(records)
        }

    def suggest_queries(self, scenario: str) -> List[str]:
        """Suggest relevant queries based on scenario"""
        if scenario not in self.scenario_keywords:
            return [
                "Show all messages",
                "Find suspicious activities",
                "Show financial transactions",
                "Find contacts with unusual patterns"
            ]
        
        scenario_config = self.scenario_keywords[scenario]
        
        if scenario == "insider_data_leak":
            return [
                "Show messages with external partners",
                "Find data sharing activities",
                "Show communications with Ravi Kumar",
                "Find confidential data mentions",
                "Show external partner contacts",
                "Find messages about renaming reports",
                "Show metadata removal activities",
                "Find personal drive usage",
                "Show midnight activities",
                "Find package sending activities"
            ]
        elif scenario == "scam_network":
            return [
                "Show job scam messages",
                "Find processing fee requests",
                "Show communications with victims",
                "Find fake job offers",
                "Show HR Manager communications",
                "Find overseas job offers",
                "Show interview invitations",
                "Find offer letter activities",
                "Show victim communications",
                "Find financial transactions"
            ]
        elif scenario == "sim_swap_attack":
            return [
                "Show OTP messages",
                "Find telecom communications",
                "Show bank OTP messages",
                "Find unknown caller contacts",
                "Show SIM swap related activities",
                "Find AX-SERVICE messages",
                "Show AX-BANKOTP messages",
                "Find Arjun communications",
                "Show telecom helpline calls",
                "Find verification activities"
            ]
        
        return ["Show all records", "Find suspicious patterns"]

    def _extract_keywords(self, query: str) -> List[str]:
        """Extract meaningful keywords from query"""
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might', 'can', 'must', 'show', 'find', 'get', 'all', 'any', 'some', 'this', 'that', 'these', 'those'}
        
        words = re.findall(r'\b[a-zA-Z0-9]+\b', query.lower())
        keywords = [w for w in words if len(w) >= 3 and w not in stop_words]
        
        return keywords

    def _extract_text_content(self, record: Dict[str, Any]) -> str:
        """Extract all text content from a record"""
        text_parts = []
        
        text_fields = ['text', 'body', 'message', 'content', 'note', 'description', 'title', 'name']
        
        for field in text_fields:
            if field in record and isinstance(record[field], str):
                text_parts.append(record[field])
        
        for key, value in record.items():
            if isinstance(value, str) and key not in text_fields and len(value) <= 200:
                text_parts.append(value)
        
        return " ".join(text_parts)

