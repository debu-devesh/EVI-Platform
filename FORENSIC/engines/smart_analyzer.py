#!/usr/bin/env python3
"""
Smart UFDR Analyzer

A simple, non-dynamic analyzer that provides comprehensive analysis reports
of UFDR data without interactive features.
"""

import json
from typing import Dict, List, Any
from collections import Counter, defaultdict
from datetime import datetime


class SmartUFDRAnalyzer:
    """Simple UFDR analyzer that provides comprehensive analysis reports."""
    
    def __init__(self):
        """Initialize the analyzer."""
        self.analysis_cache = {}
    
    def analyze_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform dynamic analysis of UFDR data with interactive features.
        Returns comprehensive data for dynamic exploration and filtering.
        
        Args:
            data: UFDR data dictionary
            
        Returns:
            Dictionary containing dynamic analysis results
        """
        try:
            # Get comprehensive analysis
            overview = self._get_data_overview(data)
            patterns = self._detect_patterns(data)
            suspicious = self._detect_suspicious_activity(data)
            communications = self._analyze_communications(data)
            files = self._analyze_files(data)
            timeline = self._analyze_timeline(data)
            
            # Generate dynamic recommendations
            recommendations = self._generate_dynamic_recommendations(overview, suspicious, files)
            
            # Create dynamic analysis data
            analysis_data = {
                "report_type": "Dynamic Analysis Report",
                "generated_at": self._get_current_timestamp(),
                "analysis_complete": True,
                
                # Core analysis data
                "overview": overview,
                "patterns": patterns,
                "suspicious_activity": suspicious,
                "communication_analysis": communications,
                "file_analysis": files,
                "timeline_analysis": timeline,
                "recommendations": recommendations,
                
                # Dynamic exploration data
                "exploration_data": self._prepare_exploration_data(data),
                "filter_options": self._generate_filter_options(data),
                "interactive_insights": self._generate_interactive_insights(data),
                
                # Summary for initial display
                "summary": self._create_dynamic_summary(overview, suspicious),
                "key_findings": self._create_key_findings(patterns, suspicious, communications),
                "security_assessment": self._create_security_assessment(suspicious, files)
            }
            
            return analysis_data
            
        except Exception as e:
            return {
                "report_type": "Error Report",
                "error": f"Analysis failed: {str(e)}",
                "summary": "Unable to analyze data due to processing error",
                "recommendations": ["Check data format and try again"],
                "analysis_complete": False
            }
    
    def _get_data_overview(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Get high-level overview of the data."""
        # Count only actual UFDR files (exclude metadata keys starting with '_')
        ufdr_file_keys = [key for key in data.keys() if not key.startswith('_')]
        total_ufdr_files = len(ufdr_file_keys)
        
        overview = {
            "total_files": total_ufdr_files,
            "total_contacts": 0,
            "total_messages": 0,
            "total_calls": 0,
            "total_files_found": 0,
            "tampered_files": 0
        }
        
        for filename, file_data in data.items():
            # Skip metadata entries (keys starting with '_')
            if filename.startswith('_'):
                continue
                
            if isinstance(file_data, dict):
                # Handle nested structure with devices array
                devices = file_data.get("devices", [])
                if not devices:
                    # Handle direct structure (fallback)
                    devices = [file_data]
                
                for device in devices:
                    if isinstance(device, dict):
                        overview["total_contacts"] += len(device.get("contacts", []))
                        overview["total_messages"] += len(device.get("messages", []))
                        overview["total_calls"] += len(device.get("call_logs", []))
                        overview["total_files_found"] += len(device.get("files", []))
                        
                        if device.get("tampered", False):
                            overview["tampered_files"] += 1
        
        return overview
    
    def _detect_patterns(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect patterns in the data with enhanced intelligence."""
        patterns = {
            "frequent_contacts": [],
            "keyword_frequency": {},
            "file_types": {},
            "communication_times": [],
            "communication_networks": {},
            "time_patterns": {},
            "message_length_patterns": {}
        }
        
        # Analyze contact frequency
        contact_counts = Counter()
        keyword_counts = Counter()
        file_type_counts = Counter()
        communication_network = defaultdict(set)  # Who talks to whom
        hour_activity = Counter()
        day_activity = Counter()
        message_lengths = []
        
        for filename, file_data in data.items():
            if isinstance(file_data, dict):
                # Handle nested structure with devices array
                devices = file_data.get("devices", [])
                if not devices:
                    devices = [file_data]
                
                for device in devices:
                    if isinstance(device, dict):
                        # Count contacts
                        for contact in device.get("contacts", []):
                            if isinstance(contact, dict):
                                name = contact.get("name", "Unknown")
                                phone = contact.get("phone", contact.get("number", ""))
                                contact_key = f"{name} ({phone})" if phone else name
                                contact_counts[contact_key] += 1
                        
                        # Enhanced message analysis
                        for message in device.get("messages", []):
                            if isinstance(message, dict):
                                text = message.get("text", "") or message.get("content", "")
                                from_user = message.get("from", "Unknown")
                                to_user = message.get("to", "Unknown")
                                
                                # Build communication network
                                if from_user and to_user and from_user != to_user:
                                    communication_network[from_user].add(to_user)
                                    communication_network[to_user].add(from_user)
                                
                                # Enhanced keyword extraction (phrases and important words)
                                if text:
                                    text_lower = text.lower()
                                    # Extract meaningful words (longer than 3 chars, not common stop words)
                                    stop_words = {"the", "and", "for", "are", "but", "not", "you", "all", "can", "her", "was", "one", "our", "out", "day", "get", "has", "him", "his", "how", "its", "may", "new", "now", "old", "see", "two", "way", "who", "boy", "did", "its", "let", "put", "say", "she", "too", "use"}
                                    words = [w for w in text_lower.split() if len(w) > 3 and w not in stop_words]
                                    for word in words:
                                        keyword_counts[word] += 1
                                    
                                    # Track message length
                                    message_lengths.append(len(text))
                                
                                # Analyze timestamps for patterns
                                timestamp = message.get("timestamp", "")
                                if timestamp:
                                    try:
                                        dt = datetime.fromisoformat(timestamp.replace("Z", ""))
                                        hour_activity[dt.hour] += 1
                                        day_activity[dt.strftime("%A")] += 1
                                    except:
                                        pass
                        
                        # Count file types with metadata
                        for file_item in device.get("files", []):
                            if isinstance(file_item, dict):
                                filename_ext = file_item.get("filename", "")
                                if "." in filename_ext:
                                    ext = filename_ext.split(".")[-1].lower()
                                    file_type_counts[ext] += 1
        
        patterns["frequent_contacts"] = contact_counts.most_common(15)  # Increased to 15
        patterns["keyword_frequency"] = dict(keyword_counts.most_common(30))  # Increased to 30
        patterns["file_types"] = dict(file_type_counts.most_common(15))  # Increased to 15
        
        # Communication network analysis
        network_stats = {}
        for person, contacts in communication_network.items():
            network_stats[person] = {
                "contact_count": len(contacts),
                "contacts": list(contacts)[:10]  # Top 10 contacts
            }
        patterns["communication_networks"] = dict(sorted(network_stats.items(), 
                                                         key=lambda x: x[1]["contact_count"], 
                                                         reverse=True)[:10])
        
        # Time pattern analysis
        if hour_activity:
            patterns["time_patterns"] = {
                "peak_hours": dict(hour_activity.most_common(5)),
                "activity_distribution": dict(hour_activity)
            }
        if day_activity:
            patterns["time_patterns"]["peak_days"] = dict(day_activity.most_common(7))
        
        # Message length patterns
        if message_lengths:
            patterns["message_length_patterns"] = {
                "average": round(sum(message_lengths) / len(message_lengths), 2),
                "short_messages": len([l for l in message_lengths if l < 50]),
                "medium_messages": len([l for l in message_lengths if 50 <= l < 200]),
                "long_messages": len([l for l in message_lengths if l >= 200]),
                "total_messages": len(message_lengths)
            }
        
        return patterns
    
    def _detect_suspicious_activity(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect potentially suspicious activities with enhanced intelligence."""
        suspicious_activities = []
        
        # Enhanced keyword patterns (phrases and context-aware)
        suspicious_patterns = {
            "financial": [
                "password", "pin", "otp", "bank", "account", "transfer", "payment", 
                "money", "cash", "deposit", "withdraw", "balance", "credit card",
                "atm", "transaction", "refund", "invoice", "receipt"
            ],
            "security": [
                "secret", "confidential", "private", "classified", "encrypted",
                "password", "login", "access", "key", "code", "token"
            ],
            "deletion": [
                "delete", "remove", "erase", "clear", "wipe", "destroy", "hide",
                "disappear", "gone", "lost", "missing"
            ],
            "urgency": [
                "urgent", "immediate", "asap", "now", "quick", "hurry", "emergency",
                "critical", "important", "rush"
            ],
            "fraud": [
                "fraud", "scam", "fake", "illegal", "unauthorized", "suspicious",
                "warning", "alert", "danger", "risk"
            ],
            "coordination": [
                "meet", "location", "address", "place", "time", "when", "where",
                "coordinate", "plan", "arrange"
            ]
        }
        
        # Track message patterns for context
        message_contexts = {}
        
        for filename, file_data in data.items():
            if isinstance(file_data, dict):
                # Handle nested structure with devices array
                devices = file_data.get("devices", [])
                if not devices:
                    devices = [file_data]
                
                for device in devices:
                    if isinstance(device, dict):
                        # Enhanced message analysis
                        for message in device.get("messages", []):
                            if isinstance(message, dict):
                                text = (message.get("text", "") or message.get("content", "")).lower()
                                from_user = message.get("from", "Unknown")
                                to_user = message.get("to", "Unknown")
                                timestamp = message.get("timestamp", "")
                                
                                # Check for suspicious patterns with context
                                detected_patterns = []
                                for category, keywords in suspicious_patterns.items():
                                    for keyword in keywords:
                                        if keyword in text:
                                            detected_patterns.append((category, keyword))
                                
                                # Context-aware detection
                                if detected_patterns:
                                    # Check for multiple suspicious indicators
                                    if len(detected_patterns) >= 2:
                                        suspicious_activities.append({
                                            "type": "high_risk_message",
                                            "severity": "HIGH",
                                            "message": f"Message contains multiple suspicious indicators: {', '.join([p[0] for p in detected_patterns[:3]])}",
                                            "filename": filename,
                                            "timestamp": timestamp,
                                            "from": from_user,
                                            "to": to_user,
                                            "patterns": [p[0] for p in detected_patterns],
                                            "snippet": text[:100] + "..." if len(text) > 100 else text
                                        })
                                    else:
                                        pattern_type, keyword = detected_patterns[0]
                                        suspicious_activities.append({
                                            "type": "suspicious_message",
                                            "severity": "MEDIUM",
                                            "message": f"Message contains {pattern_type} keyword: '{keyword}'",
                                            "filename": filename,
                                            "timestamp": timestamp,
                                            "from": from_user,
                                            "to": to_user,
                                            "pattern_type": pattern_type,
                                            "snippet": text[:100] + "..." if len(text) > 100 else text
                                        })
                                
                                # Detect unusual communication patterns
                                if from_user and to_user:
                                    key = f"{from_user}_{to_user}"
                                    if key not in message_contexts:
                                        message_contexts[key] = []
                                    message_contexts[key].append({
                                        "timestamp": timestamp,
                                        "text_length": len(text),
                                        "has_suspicious": len(detected_patterns) > 0
                                    })
                        
                        # Check for tampered files
                        if device.get("tampered", False):
                            suspicious_activities.append({
                                "type": "tampered_file",
                                "severity": "HIGH",
                                "message": "File has been tampered with",
                                "filename": filename,
                                "reason": device.get("tampered_reason", "Unknown")
                            })
                        
                        # Enhanced file analysis
                        for file_item in device.get("files", []):
                            if isinstance(file_item, dict):
                                filename_ext = file_item.get("filename", "").lower()
                                file_size = file_item.get("size_bytes", 0)
                                
                                # Check for suspicious file names
                                suspicious_file_keywords = ["password", "secret", "confidential", "private", "hidden", "encrypted"]
                                if any(keyword in filename_ext for keyword in suspicious_file_keywords):
                                    suspicious_activities.append({
                                        "type": "suspicious_file",
                                        "severity": "MEDIUM",
                                        "message": f"Suspicious file name detected: {file_item.get('filename', 'Unknown')}",
                                        "filename": filename,
                                        "file_size_mb": round(file_size / (1024 * 1024), 2) if file_size > 0 else 0
                                    })
                                
                                # Detect unusually large files (potential data exfiltration)
                                if file_size > 100 * 1024 * 1024:  # >100MB
                                    suspicious_activities.append({
                                        "type": "large_file",
                                        "severity": "LOW",
                                        "message": f"Unusually large file detected: {file_item.get('filename', 'Unknown')} ({round(file_size / (1024 * 1024), 2)} MB)",
                                        "filename": filename,
                                        "file_size_mb": round(file_size / (1024 * 1024), 2)
                                    })
                        
                        # Detect rapid communication bursts (potential coordination)
                        for key, messages in message_contexts.items():
                            if len(messages) >= 10:  # High message count
                                recent_messages = [m for m in messages if m.get("has_suspicious")]
                                if len(recent_messages) >= 3:
                                    from_user, to_user = key.split("_", 1)
                                    suspicious_activities.append({
                                        "type": "communication_burst",
                                        "severity": "MEDIUM",
                                        "message": f"High-volume suspicious communication between {from_user} and {to_user}",
                                        "filename": filename,
                                        "message_count": len(messages),
                                        "suspicious_count": len(recent_messages)
                                    })
        
        # Sort by severity (HIGH > MEDIUM > LOW) and limit
        severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        suspicious_activities.sort(key=lambda x: severity_order.get(x.get("severity", "LOW"), 0), reverse=True)
        
        return suspicious_activities[:30]  # Increased limit to 30
    
    def _analyze_communications(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze communication patterns."""
        communication_analysis = {
            "top_communicators": [],
            "message_length_distribution": {},
            "communication_frequency": {}
        }
        
        communicator_counts = Counter()
        message_lengths = []
        
        for filename, file_data in data.items():
            if isinstance(file_data, dict):
                for message in file_data.get("messages", []):
                    if isinstance(message, dict):
                        from_user = message.get("from", "Unknown")
                        to_user = message.get("to", "Unknown")
                        
                        communicator_counts[from_user] += 1
                        communicator_counts[to_user] += 1
                        
                        text = message.get("text", "") or message.get("content", "")
                        if text:
                            message_lengths.append(len(text))
        
        communication_analysis["top_communicators"] = communicator_counts.most_common(10)
        
        # Analyze message length distribution
        if message_lengths:
            avg_length = sum(message_lengths) / len(message_lengths)
            communication_analysis["message_length_distribution"] = {
                "average_length": round(avg_length, 2),
                "short_messages": len([l for l in message_lengths if l < 50]),
                "medium_messages": len([l for l in message_lengths if 50 <= l < 200]),
                "long_messages": len([l for l in message_lengths if l >= 200])
            }
        
        return communication_analysis
    
    def _analyze_files(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze file information."""
        file_analysis = {
            "sensitive_files": [],
            "file_types": {},
            "large_files": [],
            "total_files": 0
        }
        
        file_type_counts = Counter()
        large_files = []
        
        for filename, file_data in data.items():
            if isinstance(file_data, dict):
                for file_item in file_data.get("files", []):
                    if isinstance(file_item, dict):
                        file_analysis["total_files"] += 1
                        
                        # Check for sensitive file names
                        file_name = file_item.get("filename", "").lower()
                        if any(keyword in file_name for keyword in ["password", "secret", "confidential", "private"]):
                            file_analysis["sensitive_files"].append({
                                "filename": file_item.get("filename", "Unknown"),
                                "size": file_item.get("size_bytes", 0),
                                "source_file": filename
                            })
                        
                        # Count file types
                        if "." in file_name:
                            ext = file_name.split(".")[-1]
                            file_type_counts[ext] += 1
                        
                        # Check for large files (>10MB)
                        size_bytes = file_item.get("size_bytes", 0)
                        if size_bytes > 10 * 1024 * 1024:  # 10MB
                            large_files.append({
                                "filename": file_item.get("filename", "Unknown"),
                                "size_mb": round(size_bytes / (1024 * 1024), 2),
                                "source_file": filename
                            })
        
        file_analysis["file_types"] = dict(file_type_counts.most_common(10))
        file_analysis["large_files"] = large_files[:10]  # Top 10 largest files
        
        return file_analysis
    
    def _analyze_timeline(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze timeline patterns."""
        timeline_analysis = {
            "activity_by_hour": {},
            "activity_by_day": {},
            "most_active_period": ""
        }
        
        hour_counts = Counter()
        day_counts = Counter()
        
        for filename, file_data in data.items():
            if isinstance(file_data, dict):
                # Analyze message timestamps
                for message in file_data.get("messages", []):
                    if isinstance(message, dict):
                        timestamp = message.get("timestamp", "")
                        if timestamp:
                            try:
                                # Parse timestamp (assuming ISO format)
                                dt = datetime.fromisoformat(timestamp.replace("Z", ""))
                                hour_counts[dt.hour] += 1
                                day_counts[dt.strftime("%A")] += 1
                            except:
                                pass
                
                # Analyze call timestamps
                for call in file_data.get("call_logs", []):
                    if isinstance(call, dict):
                        timestamp = call.get("timestamp", "")
                        if timestamp:
                            try:
                                dt = datetime.fromisoformat(timestamp.replace("Z", ""))
                                hour_counts[dt.hour] += 1
                                day_counts[dt.strftime("%A")] += 1
                            except:
                                pass
        
        timeline_analysis["activity_by_hour"] = dict(hour_counts.most_common())
        timeline_analysis["activity_by_day"] = dict(day_counts.most_common())
        
        if hour_counts:
            most_active_hour = hour_counts.most_common(1)[0][0]
            timeline_analysis["most_active_period"] = f"{most_active_hour}:00-{most_active_hour+1}:00"
        
        return timeline_analysis
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on analysis results."""
        recommendations = []
        
        # Check for suspicious activity
        if analysis.get("suspicious_activity"):
            suspicious_count = len(analysis["suspicious_activity"])
            recommendations.append(f"⚠️ Found {suspicious_count} suspicious activities - immediate investigation recommended")
        
        # Check for tampered files
        overview = analysis.get("overview", {})
        if overview.get("tampered_files", 0) > 0:
            recommendations.append("🔍 Tampered files detected - verify data integrity")
        
        # Check for sensitive files
        file_analysis = analysis.get("file_analysis", {})
        if file_analysis.get("sensitive_files"):
            recommendations.append("📁 Sensitive files found - review for data protection compliance")
        
        # Check communication patterns
        comm_analysis = analysis.get("communication_analysis", {})
        if comm_analysis.get("top_communicators"):
            top_comm = comm_analysis["top_communicators"][0]
            recommendations.append(f"📞 Focus investigation on top communicator: {top_comm[0]} ({top_comm[1]} interactions)")
        
        # Check timeline patterns
        timeline = analysis.get("timeline_analysis", {})
        if timeline.get("most_active_period"):
            recommendations.append(f"⏰ Peak activity period: {timeline['most_active_period']} - consider temporal analysis")
        
        # General recommendations
        if overview.get("total_messages", 0) > 1000:
            recommendations.append("📊 Large message dataset - consider automated keyword filtering")
        
        if overview.get("total_files_found", 0) > 100:
            recommendations.append("💾 Extensive file collection - prioritize by file type and size")
        
        if not recommendations:
            recommendations.append("✅ No immediate concerns detected - proceed with standard analysis")
        
        return recommendations
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp for the report."""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def _create_summary(self, overview: Dict[str, Any], suspicious: List[Dict[str, Any]]) -> str:
        """Create a simple summary of the analysis."""
        total_files = overview.get("total_files", 0)
        total_contacts = overview.get("total_contacts", 0)
        total_messages = overview.get("total_messages", 0)
        suspicious_count = len(suspicious)
        
        summary = f"Analysis of {total_files} UFDR files containing {total_contacts} contacts and {total_messages} messages."
        
        if suspicious_count > 0:
            summary += f" Found {suspicious_count} potentially suspicious activities requiring attention."
        else:
            summary += " No immediate suspicious activities detected."
            
        return summary
    
    def _create_key_findings(self, patterns: Dict[str, Any], suspicious: List[Dict[str, Any]], communications: Dict[str, Any]) -> List[str]:
        """Create key findings from the analysis."""
        findings = []
        
        # Top contacts
        if patterns.get("frequent_contacts"):
            top_contact = patterns["frequent_contacts"][0]
            findings.append(f"Most frequent contact: {top_contact[0]} ({top_contact[1]} interactions)")
        
        # Suspicious activities
        if suspicious:
            findings.append(f"Found {len(suspicious)} suspicious activities")
        
        # Communication patterns
        if communications.get("top_communicators"):
            top_comm = communications["top_communicators"][0]
            findings.append(f"Top communicator: {top_comm[0]} ({top_comm[1]} messages)")
        
        # File types
        if patterns.get("file_types"):
            top_file_type = max(patterns["file_types"].items(), key=lambda x: x[1])
            findings.append(f"Most common file type: .{top_file_type[0]} ({top_file_type[1]} files)")
        
        return findings[:5]  # Limit to top 5 findings
    
    def _create_security_assessment(self, suspicious: List[Dict[str, Any]], files: Dict[str, Any]) -> Dict[str, Any]:
        """Create an enhanced security assessment with severity analysis."""
        assessment = {
            "risk_level": "LOW",
            "suspicious_activities": len(suspicious),
            "high_severity_count": 0,
            "medium_severity_count": 0,
            "low_severity_count": 0,
            "sensitive_files": len(files.get("sensitive_files", [])),
            "assessment": "No immediate security concerns detected",
            "recommendations": []
        }
        
        # Count by severity
        for activity in suspicious:
            severity = activity.get("severity", "LOW")
            if severity == "HIGH":
                assessment["high_severity_count"] += 1
            elif severity == "MEDIUM":
                assessment["medium_severity_count"] += 1
            else:
                assessment["low_severity_count"] += 1
        
        # Enhanced risk assessment
        high_risk_count = assessment["high_severity_count"]
        medium_risk_count = assessment["medium_severity_count"]
        total_suspicious = len(suspicious)
        
        if high_risk_count >= 3 or (high_risk_count >= 1 and total_suspicious > 10):
            assessment["risk_level"] = "HIGH"
            assessment["assessment"] = f"Multiple high-severity suspicious activities detected ({high_risk_count} high, {medium_risk_count} medium) - immediate investigation recommended"
            assessment["recommendations"].append("Prioritize investigation of high-severity activities")
            assessment["recommendations"].append("Review all tampered files and suspicious communications")
        elif high_risk_count >= 1 or total_suspicious > 5:
            assessment["risk_level"] = "MEDIUM"
            assessment["assessment"] = f"Suspicious activities detected ({high_risk_count} high, {medium_risk_count} medium) - review recommended"
            assessment["recommendations"].append("Investigate high-severity activities first")
            assessment["recommendations"].append("Review communication patterns for anomalies")
        elif total_suspicious > 0:
            assessment["risk_level"] = "LOW"
            assessment["assessment"] = f"Minor suspicious activities detected ({total_suspicious} total) - standard review recommended"
            assessment["recommendations"].append("Review flagged activities for context")
        else:
            assessment["assessment"] = "No suspicious activities detected - standard forensic analysis recommended"
            assessment["recommendations"].append("Proceed with standard analysis procedures")
        
        # Add file-related recommendations
        if assessment["sensitive_files"] > 0:
            assessment["recommendations"].append(f"Review {assessment['sensitive_files']} sensitive files for data protection compliance")
        
        return assessment
    
    def _create_communication_summary(self, communications: Dict[str, Any]) -> Dict[str, Any]:
        """Create a simple communication summary."""
        summary = {
            "total_communicators": len(communications.get("top_communicators", [])),
            "message_distribution": communications.get("message_length_distribution", {}),
            "summary": "Communication patterns analyzed"
        }
        
        if communications.get("top_communicators"):
            summary["top_communicator"] = communications["top_communicators"][0][0]
        
        return summary
    
    def _create_file_summary(self, files: Dict[str, Any]) -> Dict[str, Any]:
        """Create a simple file summary."""
        summary = {
            "total_files": files.get("total_files", 0),
            "sensitive_files": len(files.get("sensitive_files", [])),
            "file_types": len(files.get("file_types", {})),
            "large_files": len(files.get("large_files", [])),
            "summary": "File analysis completed"
        }
        
        if files.get("file_types"):
            top_type = max(files["file_types"].items(), key=lambda x: x[1])
            summary["most_common_type"] = f".{top_type[0]}"
        
        return summary
    
    def _create_timeline_summary(self, timeline: Dict[str, Any]) -> Dict[str, Any]:
        """Create a simple timeline summary."""
        summary = {
            "peak_activity": timeline.get("most_active_period", "Unknown"),
            "activity_days": len(timeline.get("activity_by_day", {})),
            "summary": "Timeline analysis completed"
        }
        
        if timeline.get("activity_by_day"):
            most_active_day = max(timeline["activity_by_day"].items(), key=lambda x: x[1])
            summary["most_active_day"] = most_active_day[0]
        
        return summary
    
    def _generate_static_recommendations(self, overview: Dict[str, Any], suspicious: List[Dict[str, Any]], files: Dict[str, Any]) -> List[str]:
        """Generate static recommendations based on analysis."""
        recommendations = []
        
        # Security recommendations
        if len(suspicious) > 0:
            recommendations.append(f"🔍 Investigate {len(suspicious)} suspicious activities found in the data")
        
        if len(files.get("sensitive_files", [])) > 0:
            recommendations.append("📁 Review sensitive files for data protection compliance")
        
        # Data volume recommendations
        if overview.get("total_messages", 0) > 1000:
            recommendations.append("📊 Large message dataset - consider automated filtering for efficiency")
        
        if overview.get("total_files_found", 0) > 100:
            recommendations.append("💾 Extensive file collection - prioritize analysis by file type and size")
        
        # General recommendations
        if overview.get("tampered_files", 0) > 0:
            recommendations.append("⚠️ Tampered files detected - verify data integrity")
        
        # Default recommendation if no issues found
        if not recommendations:
            recommendations.append("✅ No immediate concerns detected - proceed with standard forensic analysis")
        
        return recommendations
    
    def _prepare_exploration_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for dynamic exploration."""
        exploration_data = {
            "contacts": [],
            "messages": [],
            "calls": [],
            "files": [],
            "timeline_events": []
        }
        
        for filename, file_data in data.items():
            if isinstance(file_data, dict):
                # Handle nested structure with devices array
                devices = file_data.get("devices", [])
                if not devices:
                    # Handle direct structure (fallback)
                    devices = [file_data]
                
                for device in devices:
                    if isinstance(device, dict):
                        # Prepare contacts for exploration
                        for contact in device.get("contacts", []):
                            if isinstance(contact, dict):
                                exploration_data["contacts"].append({
                                    "name": contact.get("name", "Unknown"),
                                    "phone": contact.get("phone", ""),
                                    "email": contact.get("email", ""),
                                    "source_file": filename,
                                    "interaction_count": 0  # Will be calculated
                                })
                        
                        # Prepare messages for exploration
                        for message in device.get("messages", []):
                            if isinstance(message, dict):
                                exploration_data["messages"].append({
                                    "text": message.get("text", "") or message.get("content", ""),
                                    "from": message.get("from", "Unknown"),
                                    "to": message.get("to", "Unknown"),
                                    "timestamp": message.get("timestamp", ""),
                                    "source_file": filename,
                                    "length": len(message.get("text", "") or message.get("content", ""))
                                })
                        
                        # Prepare calls for exploration
                        for call in device.get("call_logs", []):
                            if isinstance(call, dict):
                                exploration_data["calls"].append({
                                    "from": call.get("from", "Unknown"),
                                    "to": call.get("to", "Unknown"),
                                    "duration": call.get("duration", 0),
                                    "direction": call.get("direction", "unknown"),
                                    "timestamp": call.get("timestamp", ""),
                                    "source_file": filename
                                })
                        
                        # Prepare files for exploration
                        for file_item in device.get("files", []):
                            if isinstance(file_item, dict):
                                exploration_data["files"].append({
                                    "filename": file_item.get("filename", "Unknown"),
                                    "size_bytes": file_item.get("size_bytes", 0),
                                    "file_type": file_item.get("filename", "").split(".")[-1].lower() if "." in file_item.get("filename", "") else "unknown",
                                    "source_file": filename,
                                    "sensitive": any(keyword in file_item.get("filename", "").lower() for keyword in ["password", "secret", "confidential"])
                                })
        
        return exploration_data
    
    def _generate_filter_options(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate filter options for dynamic filtering."""
        filter_options = {
            "date_ranges": [],
            "contact_names": [],
            "file_types": [],
            "message_keywords": [],
            "call_directions": ["incoming", "outgoing", "missed"],
            "file_sizes": ["small (<1MB)", "medium (1-10MB)", "large (>10MB)"],
            "risk_levels": ["low", "medium", "high"]
        }
        
        # Extract unique values for filtering
        all_contacts = set()
        all_file_types = set()
        all_keywords = set()
        
        for filename, file_data in data.items():
            if isinstance(file_data, dict):
                # Collect contact names
                for contact in file_data.get("contacts", []):
                    if isinstance(contact, dict) and contact.get("name"):
                        all_contacts.add(contact["name"])
                
                # Collect file types
                for file_item in file_data.get("files", []):
                    if isinstance(file_item, dict) and file_item.get("filename"):
                        filename_ext = file_item["filename"]
                        if "." in filename_ext:
                            ext = filename_ext.split(".")[-1].lower()
                            all_file_types.add(ext)
                
                # Collect keywords from messages
                for message in file_data.get("messages", []):
                    if isinstance(message, dict):
                        text = (message.get("text", "") or message.get("content", "")).lower()
                        words = text.split()
                        for word in words:
                            if len(word) > 3:  # Only meaningful words
                                all_keywords.add(word)
        
        filter_options["contact_names"] = sorted(list(all_contacts))[:50]  # Limit to top 50
        filter_options["file_types"] = sorted(list(all_file_types))
        filter_options["message_keywords"] = sorted(list(all_keywords))[:100]  # Limit to top 100
        
        return filter_options
    
    def _generate_interactive_insights(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate interactive insights for dynamic exploration."""
        insights = []
        
        # Communication insights
        total_messages = sum(len(file_data.get("messages", [])) for file_data in data.values() if isinstance(file_data, dict))
        if total_messages > 0:
            insights.append({
                "type": "communication",
                "title": "Message Volume Analysis",
                "description": f"Total of {total_messages} messages analyzed",
                "action": "explore_messages",
                "priority": "high"
            })
        
        # Contact insights
        total_contacts = sum(len(file_data.get("contacts", [])) for file_data in data.values() if isinstance(file_data, dict))
        if total_contacts > 0:
            insights.append({
                "type": "contacts",
                "title": "Contact Network Analysis",
                "description": f"{total_contacts} unique contacts identified",
                "action": "explore_contacts",
                "priority": "medium"
            })
        
        # File insights
        total_files = sum(len(file_data.get("files", [])) for file_data in data.values() if isinstance(file_data, dict))
        if total_files > 0:
            insights.append({
                "type": "files",
                "title": "File Collection Analysis",
                "description": f"{total_files} files found for analysis",
                "action": "explore_files",
                "priority": "medium"
            })
        
        # Security insights
        suspicious_count = len(self._detect_suspicious_activity(data))
        if suspicious_count > 0:
            insights.append({
                "type": "security",
                "title": "Security Alert",
                "description": f"{suspicious_count} suspicious activities detected",
                "action": "explore_suspicious",
                "priority": "critical"
            })
        
        return insights
    
    def _create_dynamic_summary(self, overview: Dict[str, Any], suspicious: List[Dict[str, Any]]) -> str:
        """Create a dynamic summary for interactive analysis."""
        total_files = overview.get("total_files", 0)
        total_contacts = overview.get("total_contacts", 0)
        total_messages = overview.get("total_messages", 0)
        suspicious_count = len(suspicious)
        
        summary = f"Dynamic analysis of {total_files} UFDR files containing {total_contacts} contacts and {total_messages} messages."
        summary += " Use the interactive panels below to explore data, apply filters, and generate real-time insights."
        
        if suspicious_count > 0:
            summary += f" ⚠️ {suspicious_count} suspicious activities require immediate attention."
            
        return summary
    
    def _generate_dynamic_recommendations(self, overview: Dict[str, Any], suspicious: List[Dict[str, Any]], files: Dict[str, Any]) -> List[str]:
        """Generate dynamic recommendations for interactive analysis."""
        recommendations = []
        
        # Interactive exploration recommendations
        recommendations.append("🔍 Use the Exploration Panel to drill down into specific data types")
        recommendations.append("🎯 Apply filters to focus on relevant information")
        recommendations.append("📊 Generate real-time insights for deeper analysis")
        
        # Security recommendations
        if len(suspicious) > 0:
            recommendations.append(f"⚠️ Investigate {len(suspicious)} suspicious activities using the Security Panel")
        
        if len(files.get("sensitive_files", [])) > 0:
            recommendations.append("📁 Review sensitive files in the File Analysis section")
        
        # Data volume recommendations
        if overview.get("total_messages", 0) > 1000:
            recommendations.append("📊 Use keyword filtering to navigate large message datasets")
        
        if overview.get("total_files_found", 0) > 100:
            recommendations.append("💾 Filter files by type and size for efficient analysis")
        
        # Default recommendations
        if not (len(suspicious) > 0 or len(files.get("sensitive_files", [])) > 0):
            recommendations.append("✅ No immediate concerns - proceed with interactive exploration")
        
        return recommendations


# Initialize the smart analyzer
smart_analyzer = SmartUFDRAnalyzer()
