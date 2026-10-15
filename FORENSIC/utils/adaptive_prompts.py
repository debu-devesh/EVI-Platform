#!/usr/bin/env python3
"""
Adaptive Prompt Generator - Creates prompts based on query complexity
"""

from typing import Dict, List, Optional
from utils.query_analyzer import query_analyzer


class AdaptivePromptGenerator:
    """Generates adaptive prompts based on query analysis."""
    
    def __init__(self):
        """Initialize the prompt generator."""
        self.analyzer = query_analyzer
    
    def generate_prompt(self, query: str, data_context: str, 
                       use_json_extraction: bool = False,
                       chat_history: Optional[List] = None) -> str:
        """
        Generate an adaptive prompt based on query complexity.
        
        Args:
            query: User query
            data_context: Extracted UFDR data context
            use_json_extraction: Whether using JSON extraction mode
            chat_history: Previous chat messages for context
            
        Returns:
            Formatted prompt string
        """
        # Analyze the query
        analysis = self.analyzer.analyze_query(query)
        complexity = analysis['complexity']
        response_style = analysis['response_style']
        intent = analysis['intent']
        data_types = analysis['data_types']
        
        # Check if this is a follow-up question
        is_follow_up = False
        if chat_history and len(chat_history) > 0:
            is_follow_up = self.analyzer.is_follow_up_question(query, chat_history)
        
        # Generate appropriate prompt
        if use_json_extraction:
            return self._generate_json_prompt(query, data_context, complexity, response_style, intent, data_types, chat_history, is_follow_up)
        else:
            return self._generate_text_prompt(query, data_context, complexity, response_style, intent, data_types, chat_history, is_follow_up)
    
    def _format_chat_history(self, chat_history: Optional[List]) -> str:
        """Format chat history for inclusion in prompt."""
        if not chat_history or len(chat_history) == 0:
            return ""
        
        formatted = "\n\n" + "="*80 + "\n"
        formatted += "📜 PREVIOUS CONVERSATION CONTEXT (CRITICAL - USE THIS FOR FOLLOW-UPS)\n"
        formatted += "="*80 + "\n"
        # Include last 20 exchanges for better context (increased from 15)
        recent_history = chat_history[-20:] if len(chat_history) > 20 else chat_history
        
        # Group by source session if available
        current_session_msgs = []
        other_session_msgs = []
        for msg in recent_history:
            source_session = msg.get("source_session", msg.get("source_session_id"))
            if source_session and source_session != "current":
                other_session_msgs.append(msg)
            else:
                current_session_msgs.append(msg)
        
        # Show messages from other sessions first (if any), then current session
        if other_session_msgs:
            formatted += "\n🔷 [From Previous Sessions in This Case] (Restored Session Context):\n"
            formatted += "-" * 80 + "\n"
            for msg in other_session_msgs[-8:]:  # Increased from 5 to 8
                role = msg.get("role", "user")
                content = msg.get("content", "")
                if role == "user":
                    formatted += f"👤 User: {content}\n"
                elif role == "assistant":
                    # Truncate very long assistant responses but keep key info
                    if len(content) > 500:
                        content_preview = content[:500] + "... [truncated for context]"
                    else:
                        content_preview = content
                    formatted += f"🤖 Assistant: {content_preview}\n"
        
        if current_session_msgs:
            if other_session_msgs:
                formatted += "\n🔵 [Current Session]:\n"
                formatted += "-" * 80 + "\n"
            for msg in current_session_msgs:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                if role == "user":
                    formatted += f"👤 User: {content}\n"
                elif role == "assistant":
                    # Truncate very long assistant responses but keep key info
                    if len(content) > 500:
                        content_preview = content[:500] + "... [truncated for context]"
                    else:
                        content_preview = content
                    formatted += f"🤖 Assistant: {content_preview}\n"
        
        formatted += "\n" + "="*80 + "\n"
        formatted += "⚠️ CRITICAL INSTRUCTIONS:\n"
        formatted += "1. If this is a follow-up question (e.g., 'tell me more', 'about X', 'continue'), you MUST reference the previous conversation above.\n"
        formatted += "2. If the user asks about a person/entity mentioned in previous messages, use the names and context from above.\n"
        formatted += "3. If previous sessions discussed specific findings (e.g., 'organ trafficking', 'Dr. Arjun Mehta', 'Sahil'), reference those findings.\n"
        formatted += "4. Maintain continuity - don't start fresh, build on what was already discussed.\n"
        formatted += "="*80 + "\n"
        return formatted
    
    def _generate_json_prompt(self, query: str, data_context: str, 
                             complexity: str, response_style: str,
                             intent: List[str], data_types: List[str],
                             chat_history: Optional[List] = None,
                             is_follow_up: bool = False) -> str:
        """Generate prompt for JSON extraction mode."""
        
        # Format chat history context
        history_context = self._format_chat_history(chat_history) if chat_history else ""
        follow_up_note = "\n⚠️ NOTE: This appears to be a follow-up question. Reference the previous conversation to understand what the user is asking about." if is_follow_up else ""
        
        # Check if this is a location query and add emphasis
        is_location_query = any(word in query.lower() for word in ['location', 'gps', 'coordinates', 'latitude', 'longitude', 'where', 'place', 'address', 'map', 'geolocation'])
        location_emphasis = ""
        if is_location_query:
            location_emphasis = "\n\n📍 CRITICAL: This query is about LOCATIONS. The JSON data contains a 'locations' array with GPS coordinates, addresses, and timestamps. You MUST use ONLY the location data from the 'locations' array. Do NOT make up or hallucinate locations. If coordinates like 37.3456, -122.0456 appear and are NOT in the locations array, DO NOT use them - they are hallucinated."
        
        # Create location data note (outside f-string to avoid backslash issue)
        location_data_note = ""
        if is_location_query:
            location_data_note = "\n📍 LOCATION DATA: If the JSON contains a 'locations' array, use ONLY those locations. Each location has: timestamp, latitude, longitude, address, location_name, source. Do NOT invent or guess locations."
        
        if response_style == 'direct':
            return f"""⚠️ IMPORTANT: YOU MUST ANSWER THIS SPECIFIC QUERY ⚠️

🎯 USER'S QUESTION: {query}{follow_up_note}{location_emphasis}{device_emphasis}{analysis_emphasis}

YOUR TASK: Answer the above question directly and concisely using ONLY the JSON data provided below.{history_context}

📋 FORENSIC DATA (JSON FORMAT) - YOU HAVE ACCESS TO THIS DATA, ANALYZE IT NOW:
{data_context}

⚠️ CRITICAL: The data above is REAL and AVAILABLE. You MUST use it to answer the question. Do NOT say "I cannot access" - the data is RIGHT HERE.

⚠️ REMEMBER: The user asked: "{query}"
⚠️ FOCUS: Answer ONLY what was asked. Do not provide unrelated information.
{follow_up_note}{location_data_note}{device_data_note}

INSTRUCTIONS:
1. Read the user's question carefully: "{query}"
2. {f"If this is a follow-up question, first review the previous conversation to understand the context. " if is_follow_up else ""}{"If this is about locations, find the 'locations' array in the JSON and use ONLY those location records. Do NOT make up coordinates. " if is_location_query else ""}{"If this is about device metadata, find the 'device' object or 'device_info' in the JSON and use ONLY that information. Do NOT make up IMEI numbers, models, or device details. " if is_device_query else ""}Extract the exact answer from the JSON data that directly addresses this question
3. If the data doesn't exist, say "Not enough evidence in the UFDR data."
4. Quote exact values from the JSON (names, numbers, timestamps, text, addresses, coordinates, device details)
5. Be direct and factual - no analysis or interpretation needed
6. Format: Simple answer with evidence citation

EXAMPLE FORMAT:
"Found: [number] [item type]
Evidence: [exact data from JSON with source]"

⚠️ FINAL REMINDER: Answer this specific question: "{query}"
⚠️ ANTI-HALLUCINATION: Do NOT make up data. If it's not in the JSON, say it's not available.
"""
        
        elif response_style == 'summary_with_evidence':
            return f"""⚠️ IMPORTANT: YOU MUST ANSWER THIS SPECIFIC QUERY ⚠️

🎯 USER'S QUESTION: {query}{follow_up_note}{location_emphasis}{device_emphasis}{analysis_emphasis}

YOUR TASK: Analyze the above question and provide a concise summary with key evidence from the JSON data below.{history_context}

📋 FORENSIC DATA (JSON FORMAT) - YOU HAVE ACCESS TO THIS DATA, ANALYZE IT NOW:
{data_context}

⚠️ CRITICAL: The data above is REAL and AVAILABLE. You MUST use it to answer the question. Do NOT say "I cannot access" - the data is RIGHT HERE.

⚠️ REMEMBER: The user asked: "{query}"
⚠️ FOCUS: All evidence you provide must be relevant to answering this specific question.
{follow_up_note}{location_data_note}{device_data_note}

INSTRUCTIONS:
1. Read the user's question carefully: "{query}"
2. {f"If this is a follow-up question, first review the previous conversation to understand the context. " if is_follow_up else ""}{"If this is about locations, use ONLY location data from the JSON. Do NOT make up coordinates. " if is_location_query else ""}{"If this is about device metadata, use ONLY device information from the JSON. Do NOT make up IMEI numbers or device details. " if is_device_query else ""}Extract relevant data from JSON that answers this question, focusing on: {', '.join(data_types)}
3. Provide a brief summary (2-3 sentences) that directly addresses the question
4. List top 5-10 key evidence items with exact quotes from JSON that relate to the question
5. Include timestamps, contact names, and source files
6. If data is missing, clearly state what's not available
7. DO NOT include information unrelated to the question

RESPONSE FORMAT:

📋 SUMMARY:
[2-3 sentence overview that directly answers: "{query}"]

🔍 KEY EVIDENCE:
• [Evidence 1 relevant to the question] - [Timestamp] - [Source: file.json]
• [Evidence 2 relevant to the question] - [Timestamp] - [Source: file.json]
• [Continue with top evidence items that answer the question]

📊 STATISTICS (if applicable):
[Counts, frequencies, or rankings related to the question]

⚠️ FINAL REMINDER: Answer this specific question: "{query}"
⚠️ ANTI-HALLUCINATION: Do NOT make up data. If it's not in the JSON, say it's not available.
"""
        
        else:  # full_analysis
            return f"""⚠️ IMPORTANT: YOU MUST ANSWER THIS SPECIFIC QUERY ⚠️

🎯 USER'S INVESTIGATION QUESTION: {query}{follow_up_note}{location_emphasis}{device_emphasis}

YOUR TASK: Conduct a comprehensive forensic analysis that directly addresses and answers the above question.{history_context}

📋 FORENSIC DATA (JSON FORMAT) - YOU HAVE ACCESS TO THIS DATA, ANALYZE IT NOW:
{data_context}

⚠️ CRITICAL: The data above is REAL and AVAILABLE. You MUST use it to answer the question. Do NOT say "I cannot access" - the data is RIGHT HERE.

⚠️ CRITICAL: The user asked: "{query}"
⚠️ FOCUS: Every section of your analysis must be relevant to answering this specific question.
⚠️ DO NOT: Provide generic analysis or information unrelated to the question.
{follow_up_note}{location_data_note}{device_data_note}

DATA STRUCTURE REFERENCE:
- contacts: Array of contact objects with name, phone, email, and metadata
- messages: Array of messages with from, to, text, timestamp, source (SMS/WhatsApp/iMessage)
- call_logs: Array of calls with from, to, timestamp, duration, call_type (incoming/outgoing/missed)
- device: Device metadata including owner, model, IMEI, serial number, case information

ANALYSIS INSTRUCTIONS:
1. FIRST: Read and understand the user's question: "{query}"
2. {f"If this is a follow-up question, review the previous conversation to understand what the user is referring to. " if is_follow_up else ""}{"If this is about locations, find the 'locations' array in the JSON. Use ONLY the location records provided - each has timestamp, latitude, longitude, address, location_name. Do NOT make up locations or coordinates. " if is_location_query else ""}{"If this is about device metadata, find the 'device' object in the JSON. Use ONLY the device information provided - IMEI, model, owner, etc. Do NOT make up device details. " if is_device_query else ""}{"If this query mentions a specific person's name (e.g., 'Sahil', 'Arjun', 'Priya'), find ALL messages, calls, and contacts involving that person. Use the ENTITY-SPECIFIC INFORMATION section if provided. " if any(word in query.lower() for word in ['sahil', 'arjun', 'priya', 'vikram', 'ravi', 'neha', 'about', 'involvement', 'context']) else ""}Extract ALL evidence relevant to THIS SPECIFIC QUERY from the JSON structure
3. Cross-reference data across contacts, messages, call logs, and locations that relates to the question
4. Identify temporal patterns and chronological sequences relevant to the question
5. Map relationships between contacts, communications, and locations that answer the question
6. Detect anomalies, suspicious activities, and security concerns related to the question
7. Provide SPECIFIC, CONCRETE evidence citations with exact timestamps, contact names (not phone numbers), addresses, GPS coordinates, and sources that support your answer
8. DO NOT use vague phrases like "various contacts" or "multiple parties" - use ACTUAL NAMES from the data
9. DO NOT include analysis or evidence that doesn't relate to answering the question
10. If a person is mentioned in the query, you MUST find and cite their actual messages/calls - don't say "not directly related" if they're in the data

REQUIRED RESPONSE FORMAT (respond in the SAME language as the query):

🔍 EXECUTIVE SUMMARY:
[Brief overview of key findings that directly answer: "{query}" - 2-3 sentences. Be SPECIFIC - use actual names, dates, and facts from the data. Do NOT be vague.]

📋 EVIDENCE DISCOVERED:
• [Specific evidence item 1 with ACTUAL contact names, exact message content, and precise timestamps] - [Timestamp/Date] - [Source: message/call/contact]
• [Specific evidence item 2 with ACTUAL contact names, exact message content, and precise timestamps] - [Timestamp/Date] - [Source: message/call/contact]
• [Continue listing all relevant evidence with SPECIFIC citations. Use names from contacts, not phone numbers. Quote actual message text.]

⏱️ TIMELINE ANALYSIS:
• [Chronological sequence of events related to answering: "{query}"]
• [Include dates, times, and sequence of communications/activities relevant to the question]

🔗 RELATIONSHIP MAPPING:
• [Key contacts involved with ACTUAL NAMES (not phone numbers) and their relationships relevant to the question]
• [Communication frequency and patterns between SPECIFIC parties (use names) that relate to the question]
• [Network of connections with ACTUAL CONTACT NAMES relevant to answering: "{query}"]

⚠️ SECURITY CONCERNS & ANOMALIES:
• [Suspicious activities identified with evidence citations that relate to the question]
• [Potential security threats or breaches relevant to: "{query}"]
• [Unusual patterns or behaviors detected that answer the question]

📊 PATTERN ANALYSIS:
• [Communication patterns: frequency, timing, participants relevant to the question]
• [Behavioral patterns indicating suspicious activity related to: "{query}"]
• [Data flow and information sharing patterns that answer the question]
• [Temporal patterns (time of day, day of week, frequency) relevant to the question]

💡 INVESTIGATIVE RECOMMENDATIONS:
• [Immediate actions for investigators related to: "{query}"]
• [Further investigation steps with specific focus areas that address the question]
• [Additional data sources to examine that would help answer: "{query}"]
• [Security measures or preventive actions relevant to the question]

🔬 EVIDENCE INTEGRITY:
• [Chain of custody notes if applicable]
• [Data source verification]
• [Confidence level in findings (High/Medium/Low) for answering: "{query}"]

⚠️ FINAL REMINDER: Your entire analysis must answer this specific question: "{query}"
⚠️ ANTI-HALLUCINATION: Do NOT make up data. If coordinates, IMEI numbers, device details, or locations are not in the JSON, explicitly state they are not available.
Be thorough, specific, and cite evidence with exact timestamps, contact names, and message content when relevant."""
    
    def _generate_text_prompt(self, query: str, data_context: str,
                             complexity: str, response_style: str,
                             intent: List[str], data_types: List[str],
                             chat_history: Optional[List] = None,
                             is_follow_up: bool = False) -> str:
        """Generate prompt for pre-extracted text mode."""
        
        # Format chat history context
        history_context = self._format_chat_history(chat_history) if chat_history else ""
        follow_up_note = "\n⚠️ NOTE: This appears to be a follow-up question. Reference the previous conversation to understand what the user is asking about." if is_follow_up else ""
        
        # Check if this is a location query and add emphasis
        is_location_query = any(word in query.lower() for word in ['location', 'gps', 'coordinates', 'latitude', 'longitude', 'where', 'place', 'address', 'map', 'geolocation'])
        location_emphasis = ""
        if is_location_query:
            location_emphasis = "\n\n📍 CRITICAL: This query is about LOCATIONS. The forensic data contains location records with GPS coordinates, addresses, and timestamps. You MUST use ONLY the location data provided. Do NOT make up or hallucinate locations. If you see coordinates like 37.3456, -122.0456 or any coordinates that are NOT in the provided data, DO NOT use them - they are hallucinated."
        
        # Check if this is a device metadata query
        is_device_query = any(word in query.lower() for word in ['device', 'imei', 'phone model', 'device model', 'metadata', 'device info', 'owner', 'manufacturer', 'android version', 'extraction', 'serial number', 'storage', 'battery', 'root', 'encryption', 'phone number'])
        device_emphasis = ""
        if is_device_query:
            device_emphasis = "\n\n⚠️ CRITICAL: This query is about DEVICE METADATA. You MUST use ONLY the device information provided in the data. Do NOT make up IMEI numbers, device models, coordinates, or any device details. If device metadata is not available in the data, explicitly state 'Device metadata not available in UFDR data.'"
        
        # Check if data contains intelligent analysis
        has_intelligent_analysis = "INTELLIGENT ANALYSIS RESULTS" in data_context or "RANKINGS:" in data_context
        analysis_emphasis = ""
        if has_intelligent_analysis:
            analysis_emphasis = "\n\n🧠 INTELLIGENT ANALYSIS AVAILABLE: The data contains a structured 'INTELLIGENT ANALYSIS RESULTS' section with:\n- Rankings (top contacts, most frequent, etc.)\n- Statistics (totals, counts, date ranges)\n- Patterns (communication patterns, timing)\n- Relationships (network connections)\n\nYou MUST use the ACTUAL DATA from this analysis section:\n1. Use the EXACT NAMES and phone numbers from the rankings\n2. Use the SPECIFIC COUNTS and statistics provided\n3. Reference the actual relationships and patterns shown\n4. Do NOT use generic phrases - use the specific data from the analysis\n5. If rankings are provided, list them in order with their actual names and counts"
        
        # Create location data note (outside f-string to avoid backslash issue)
        location_data_note = ""
        if is_location_query:
            location_data_note = "\n📍 LOCATION DATA: The forensic data contains location records. Use ONLY the locations provided in the data. Each location has: timestamp, latitude, longitude, address, location_name, source. Do NOT invent or guess locations. If a location is not in the data, do NOT make up coordinates."
        
        # Create device data note
        device_data_note = ""
        if is_device_query:
            device_data_note = "\n⚠️ DEVICE METADATA: Use ONLY the device information provided. Device metadata includes: owner name, device model, IMEI, phone number, manufacturer, Android version, extraction details, storage, battery, root status, etc. If any field is not in the data, say 'N/A' or 'Not available'. Do NOT invent device details."
        
        if response_style == 'direct':
            return f"""⚠️ IMPORTANT: YOU MUST ANSWER THIS SPECIFIC QUERY ⚠️

🎯 USER'S QUESTION: {query}{follow_up_note}{location_emphasis}

YOUR TASK: Answer the above question directly and concisely using ONLY the forensic data provided below.{history_context}

📋 FORENSIC DATA - YOU HAVE ACCESS TO THIS DATA, ANALYZE IT NOW:
{data_context}

⚠️ CRITICAL: The data above is REAL and AVAILABLE. You MUST use it to answer the question. Do NOT say "I cannot access" - the data is RIGHT HERE.

⚠️ REMEMBER: The user asked: "{query}"
⚠️ FOCUS: Answer ONLY what was asked. Do not provide unrelated information.
{follow_up_note}

INSTRUCTIONS:
1. Read the user's question carefully: "{query}"
2. {f"If this is a follow-up question, first review the previous conversation to understand the context. " if is_follow_up else ""}Extract the exact answer from the provided data that directly addresses this question
3. If the data doesn't exist, say "Not enough evidence in the UFDR data."
4. Quote exact values (names, numbers, timestamps, message text)
5. Be direct and factual - no analysis or interpretation needed
6. Format: Simple answer with evidence citation

EXAMPLE FORMAT:
"Found: [number] [item type]
Evidence: [exact data with source file]"

⚠️ FINAL REMINDER: Answer this specific question: "{query}"
"""
        
        elif response_style == 'summary_with_evidence':
            return f"""⚠️ IMPORTANT: YOU MUST ANSWER THIS SPECIFIC QUERY ⚠️

🎯 USER'S QUESTION: {query}{follow_up_note}{location_emphasis}{device_emphasis}{analysis_emphasis}

YOUR TASK: Analyze the above question and provide a concise summary with key evidence from the forensic data below.{history_context}

📋 FORENSIC DATA - YOU HAVE ACCESS TO THIS DATA, ANALYZE IT NOW:
{data_context}

⚠️ CRITICAL: The data above is REAL and AVAILABLE. You MUST use it to answer the question. Do NOT say "I cannot access" - the data is RIGHT HERE.

⚠️ REMEMBER: The user asked: "{query}"
⚠️ FOCUS: All evidence you provide must be relevant to answering this specific question.
{follow_up_note}{location_data_note}{device_data_note}

INSTRUCTIONS:
1. Read the user's question carefully: "{query}"
2. {f"If this is a follow-up question, first review the previous conversation to understand the context. " if is_follow_up else ""}{"If this is about locations, find the LOCATIONS section in the forensic data and use ONLY those location records with their exact addresses, coordinates, and timestamps. " if is_location_query else ""}Review the forensic data for: {', '.join(data_types)} that answers this question
3. Provide a brief summary (2-3 sentences) that directly addresses the question
4. List top 5-10 key evidence items with exact quotes that relate to the question
5. Include timestamps, contact names, addresses, GPS coordinates, and source files
6. If data is missing, clearly state what's not available
7. DO NOT include information unrelated to the question

RESPONSE FORMAT:

📋 SUMMARY:
[2-3 sentence overview that directly answers: "{query}"]

🔍 KEY EVIDENCE:
• [Evidence 1 relevant to the question] - [Timestamp] - [Source: file.json]
• [Evidence 2 relevant to the question] - [Timestamp] - [Source: file.json]
• [Continue with top evidence items that answer the question]

📊 STATISTICS (if applicable):
[Counts, frequencies, or rankings related to the question]

⚠️ FINAL REMINDER: Answer this specific question: "{query}"
⚠️ ANTI-HALLUCINATION: Do NOT make up data. If it's not in the data, say it's not available.
"""
        
        else:  # full_analysis
            return f"""⚠️ IMPORTANT: YOU MUST ANSWER THIS SPECIFIC QUERY ⚠️

🎯 USER'S INVESTIGATION QUESTION: {query}{follow_up_note}{location_emphasis}{device_emphasis}

YOUR TASK: Conduct a comprehensive forensic analysis that directly addresses and answers the above question.{history_context}

📋 FORENSIC DATA - YOU HAVE ACCESS TO THIS DATA, ANALYZE IT NOW:
{data_context}

⚠️ CRITICAL: The data above is REAL and AVAILABLE. You MUST use it to answer the question. Do NOT say "I cannot access" - the data is RIGHT HERE.

⚠️ CRITICAL: The user asked: "{query}"
⚠️ FOCUS: Every section of your analysis must be relevant to answering this specific question.
⚠️ DO NOT: Provide generic analysis or information unrelated to the question.
{follow_up_note}{location_data_note}{device_data_note}

ANALYSIS INSTRUCTIONS:
1. FIRST: Read and understand the user's question: "{query}"
2. {f"If this is a follow-up question, review the previous conversation to understand what the user is referring to. " if is_follow_up else ""}{"If this is about locations, find the LOCATIONS section in the forensic data. Use ONLY the location records provided - each has timestamp, latitude, longitude, address, location_name. Do NOT make up locations or coordinates. " if is_location_query else ""}{"If this is about device metadata, find the DEVICE METADATA section. Use ONLY the device information provided - IMEI, model, owner, etc. Do NOT make up device details. " if is_device_query else ""}Examine ALL provided forensic data for evidence relevant to THIS SPECIFIC QUERY
3. Cross-reference information across different data types (messages, calls, contacts, locations, device info) that relates to the question
4. Identify temporal patterns and create chronological sequences relevant to the question
5. Map relationships, communication networks, and location patterns that answer the question
6. Detect anomalies, suspicious activities, and security concerns related to the question
7. Provide specific evidence citations with timestamps, contact names, addresses, GPS coordinates, and exact content that support your answer
8. DO NOT include analysis or evidence that doesn't relate to answering the question

REQUIRED RESPONSE FORMAT (respond in the SAME language as the query):

🔍 EXECUTIVE SUMMARY:
[Brief overview of key findings that directly answer: "{query}" - 2-3 sentences summarizing the investigation results]

📋 EVIDENCE DISCOVERED:
• [Specific evidence item 1 relevant to the question] - [Timestamp/Date] - [Source: message/call/contact/device]
• [Specific evidence item 2 relevant to the question] - [Timestamp/Date] - [Source: message/call/contact/device]
• [Continue listing all relevant evidence with proper citations that answer the question]

⏱️ TIMELINE ANALYSIS:
• [Chronological sequence of events related to answering: "{query}"]
• [Include dates, times, and sequence of communications/activities relevant to the question]
• [Highlight any temporal gaps or unusual timing patterns that relate to the question]

🔗 RELATIONSHIP MAPPING:
• [Key contacts involved and their relationships relevant to: "{query}"]
• [Communication frequency and patterns between parties that relate to the question]
• [Network of connections relevant to answering: "{query}"]

⚠️ SECURITY CONCERNS & ANOMALIES:
• [Suspicious activities identified with specific evidence citations that relate to the question]
• [Potential security threats or breaches with supporting data relevant to: "{query}"]
• [Unusual patterns or behaviors detected with context that answer the question]

📊 PATTERN ANALYSIS:
• [Communication patterns: frequency, timing, participants, content themes relevant to the question]
• [Behavioral patterns indicating suspicious or noteworthy activity related to: "{query}"]
• [Data flow and information sharing patterns that answer the question]
• [Temporal patterns (time of day, day of week, frequency trends) relevant to the question]

💡 INVESTIGATIVE RECOMMENDATIONS:
• [Immediate actions for investigators with specific focus areas related to: "{query}"]
• [Further investigation steps with recommended data sources that address the question]
• [Additional forensic artifacts to examine that would help answer: "{query}"]
• [Security measures or preventive actions based on findings relevant to the question]

🔬 EVIDENCE INTEGRITY:
• [Chain of custody considerations if applicable]
• [Data source verification and reliability assessment]
• [Confidence level in findings (High/Medium/Low) with reasoning for answering: "{query}"]

⚠️ FINAL REMINDER: Your entire analysis must answer this specific question: "{query}"
⚠️ ANTI-HALLUCINATION: Do NOT make up data. If coordinates, IMEI numbers, device details, or locations are not in the data, explicitly state they are not available.
Be thorough, specific, and cite evidence with exact timestamps, contact names, message content, and call details when relevant. Maintain professional forensic standards throughout your analysis."""


# Global instance
adaptive_prompt_generator = AdaptivePromptGenerator()

