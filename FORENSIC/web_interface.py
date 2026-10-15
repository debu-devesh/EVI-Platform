#!/usr/bin/env python3
"""
EVI - UFDR Forensic Analysis Web Interface

A comprehensive web-based forensic analysis system for analyzing UFDR 
(Unified Forensic Data Records) files with natural language querying, 
scenario detection, and AI-powered insights.

Features:
- Natural Language Query Processing
- AI-Powered Chat Assistant (LM Studio integration)
- Real-time Forensic Analysis
- ZIP UFDR File Support
- Case Management
- Session Persistence
"""

# Standard library imports
import json
import os
import re
import secrets
import unicodedata
import shutil
import sqlite3
import logging
import zipfile
from datetime import datetime
from functools import wraps
from pathlib import Path
from textwrap import dedent
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple, Union

# Third-party imports
import bcrypt
import requests
from flask import (
    Flask, render_template, request, jsonify, session, Response,
    stream_with_context, send_file, redirect, url_for, flash
)
from werkzeug.utils import secure_filename
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.platypus.flowables import HRFlowable
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    # Note: Logger not yet defined, using print instead
    print("Warning: ReportLab not available. PDF export will be disabled. Install with: pip install reportlab")

from engines.nl_query_engine import NaturalLanguageUFDR
from engines.enhanced_nl_query_engine import EnhancedNaturalLanguageUFDR
from engines.ai_ufdr_retrieval_engine import AIUFDRRetrievalEngine
# RAG engine disabled - using keyword-based extraction instead
# from engines.rag_engine import UFDRRAGEngine
from engines.smart_analyzer import smart_analyzer
from utils.confidence import confidence_calculator
from utils.image_citation import image_citation_extractor
from utils.ufdr_analyzer import analyze_ufdr_file
from core.enhanced_data_extractor import enhanced_extractor
from core.hybrid_zip_parser import HybridZipParser
from core.semantic_data_extractor import semantic_extractor
from core.fast_cellebrite_parser import FastCellebriteParser
from core.cellebrite_data_access_layer import CellebriteDataAccessLayer
from core.xml_cellebrite_parser import XMLCellebriteParser
from core.query_classifier import classify_query, is_confirmation_response
from core.query_intent_parser import (
    parse_query_intent,
    to_canonical_query,
    extract_platforms_ordered,
    scrub_platform_aliases_for_domain_parsing,
    scrub_platform_chat_labels_for_domain_parsing,
)
from core.query_planner import build_query_plan
from core.guarantee_class import GUARANTEE_FOLLOWUP_ANALYSIS, GUARANTEE_HYBRID
from core.query_route import decide_query_route
from core.query_route_scores import apply_route_score_bias, compute_route_scores
from core.query_feedback import (
    ALL_FAILURE_TYPES,
    append_feedback_record,
    apply_feedback_to_query_route,
    default_feedback_path,
    invalidate_feedback_cache,
    record_from_api_payload,
)
from core.llm_evidence_packet import (
    EvidencePacket,
    build_llm_evidence_packet,
    EVIDENCE_CONTRACT_TEXT,
    FORENSIC_SPECULATION_RULE,
    MANDATORY_UNCERTAINTY_SECTION_HINT,
    log_llm_packet_debug,
)
from core.llm_response_format import (
    describe_tier_for_logging,
    format_universal_response_instructions,
    select_response_format_tier,
)
from core.correlation_engine import build_v1_correlation_result
from core.events_normalizer import (
    normalize_calls, normalize_chat_messages, normalize_locations, normalize_contacts
)
from utils.query_analyzer import query_analyzer
from utils.response_validator import validate_response, log_validation_results
from utils.investigator_deterministic_format import (
    build_markdown_table,
    format_correlation_report,
    format_timeline_investigator,
    short_time_from_timestamp,
)
from utils.llm_text_repair import repair_llm_mojibake
from utils.chat_response_format import format_structured_response_html
from utils.pdf_chat_html_flowables import ChatPdfStyles, chat_html_fragment_to_flowables

# Configure logging (must be before logger is used)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Forensic payload size sent to the local LLM (lower = faster, fewer context errors on 7B).
# Full tuning (context cap, output tokens) is next to USE_LLM below.
LLM_MAX_FORENSIC_CHARS = int(os.environ.get("LLM_MAX_FORENSIC_CHARS", "12000"))

# Security enhancements
try:
    from security.security_enhancements import (
        encryption, audit_logger, RBAC,
        audit_action, encrypt_sensitive_field, decrypt_sensitive_field
    )
    from security import create_audit_table, sanitize_input
    # require_permission is a method of RBAC class
    require_permission = RBAC.require_permission
    # Stub functions for compatibility (if used elsewhere)
    require_case_access = lambda f: f
    configure_secure_sessions = lambda app: None
    calculate_file_hash = lambda filepath: None
    SECURITY_AVAILABLE = True
    logger.info("Security enhancements module loaded")
except ImportError as e:
    SECURITY_AVAILABLE = False
    logger.warning(f"Security enhancements not available: {e}")
except Exception as e:
    SECURITY_AVAILABLE = False
    logger.warning(f"Security enhancements not available: {e}")

# Session persistence
def persist_chat_message(session_id, role, content, metadata=None):
    """Helper to save chat message to both in-memory and database"""
    # In-memory (for backward compatibility)
    if session_id not in CHAT_HISTORIES:
        CHAT_HISTORIES[session_id] = []
    CHAT_HISTORIES[session_id].append({"role": role, "content": content, "timestamp": datetime.now().isoformat()})
    
    # Database persistence
    if SESSION_DB_AVAILABLE:
        try:
            save_chat_message(session_id, role, content, metadata=metadata)
        except Exception as e:
            logger.warning(f"Failed to persist chat message to database: {e}")

# Session persistence
try:
    import sys
    import os
    # Add database/code to path for session_db import
    _database_code_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'code')
    if _database_code_path not in sys.path:
        sys.path.insert(0, _database_code_path)
    from session_db import (
        init_session_db, create_session, update_session_access, get_session,
        save_chat_message, get_chat_history, get_chat_history_from_related_sessions, clear_chat_history,
        save_preference, get_preferences,
        save_query, get_query_history,
        get_sessions_by_case, get_all_sessions,
        create_case, get_case, get_all_cases, update_case, delete_case,
        save_session_file, get_session_files, delete_session_file, clear_session_files
    )
    SESSION_DB_AVAILABLE = True
    logger.info("Session database module loaded")
    # Initialize database on import
    success, error_msg = init_session_db()
    if success:
        logger.info("Session database initialized successfully")
        # Initialize audit table if security is available
        if SECURITY_AVAILABLE and SESSION_DB_AVAILABLE:
            try:
                create_audit_table()
                logger.info("Audit table initialized")
            except Exception as e:
                logger.warning(f"Could not initialize audit table: {e}")
    else:
        error_message = error_msg or "Unknown error during initialization"
        logger.error(f"Failed to initialize session database: {error_message}")
        SESSION_DB_AVAILABLE = False
except ImportError as e:
    SESSION_DB_AVAILABLE = False
    logger.warning(f"Session database not available: {e}")

app = Flask(__name__)
# Set secret key for session management
_sk = os.environ.get("SECRET_KEY", "")
if not _sk or _sk.startswith("your-secret-key"):
    _sk = secrets.token_hex(32)  # unset or placeholder: random per start
app.secret_key = _sk

# Configure session settings
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Only use Secure cookies in production (HTTPS)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_DOMAIN'] = None  # Allow cookies on any domain/IP
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# Configure secure sessions if security is available (but override Secure flag for HTTP)
if SECURITY_AVAILABLE:
    try:
        # Temporarily disable secure flag for HTTP access
        original_secure = app.config.get('SESSION_COOKIE_SECURE', False)
        configure_secure_sessions(app)
        # Override secure flag if not using HTTPS
        app.config['SESSION_COOKIE_SECURE'] = False  # Allow HTTP access
        app.config['SESSION_COOKIE_DOMAIN'] = None  # Allow cookies on any domain/IP
        logger.info("Secure session configuration applied (HTTP mode)")
    except Exception as e:
        logger.warning(f"Could not apply secure session config: {e}")

# Configure Flask to ignore upload directory in reloader (prevents restarts during file uploads)
# This is a workaround for Flask's auto-reloader being too sensitive to file changes
if app.debug:
    import sys
    # Add upload directory to ignored patterns if using watchdog
    try:
        from werkzeug.serving import is_running_from_reloader
        # This helps prevent reloader from triggering on upload directory changes
        pass
    except:
        pass

# Development Mode — bypasses authentication and Case Manager; opens chat directly.
# Default: on. For production, set environment variable DEV_MODE=false (or edit to force False below).
DEV_MODE = os.environ.get("DEV_MODE", "false").strip().lower() in ("1", "true", "yes")
# For development, set DEV_MODE = True or export DEV_MODE=True
# For production, set DEV_MODE = False or export DEV_MODE=False
# DEV_MODE bypasses: Authentication, Case Manager, and redirects directly to chat interface

if DEV_MODE:
    logger.warning("⚠️  DEVELOPMENT MODE ENABLED - Authentication and Case Manager DISABLED")
    logger.warning("⚠️  You can access EVI chat interface directly without login")
    logger.warning("⚠️  Case Manager and other non-chat features are disabled")
    logger.warning("⚠️  Set DEV_MODE=False for production!")
else:
    logger.info("🔒 PRODUCTION MODE - Authentication is REQUIRED")

# Configure template paths to include Authentication templates and Security templates
from jinja2 import FileSystemLoader, ChoiceLoader
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVI_SCAN_DIR = os.path.dirname(BASE_DIR)
AUTH_TEMPLATES = os.path.join(EVI_SCAN_DIR, 'Authentication', 'templates')
FORENSIC_TEMPLATES = os.path.join(BASE_DIR, 'templates')
SECURITY_TEMPLATES = os.path.join(BASE_DIR, 'security', 'templates')
app.jinja_loader = ChoiceLoader([
    FileSystemLoader(FORENSIC_TEMPLATES),
    FileSystemLoader(AUTH_TEMPLATES),
    FileSystemLoader(SECURITY_TEMPLATES)
])

# Authentication Database Configuration
AUTH_DB_PATH = os.path.join(EVI_SCAN_DIR, 'Authentication', 'evi_scan.db')
captcha_storage = {}

# Configuration
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'data', 'uploaded_ufdrs')
ALLOWED_EXTENSIONS = {'json', 'zip', 'ufdr', 'xml'}

# Configure Flask for large file uploads (after UPLOAD_FOLDER is defined)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 * 1024  # 10GB max file size
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Chat history storage (in-memory, per session)
# Format: {session_id: [{"role": "user|assistant", "content": "...", "timestamp": "..."}, ...]}
CHAT_HISTORIES = {}
# Follow-up base message context selected by the user (per session)
# Format: {session_id: {"message_id": "...", "content": "...", "timestamp": "..."}}
FOLLOWUP_BASE_CONTEXT = {}


def _find_evidence_snapshot_for_followup(session_id: str, base_content: str) -> str:
    """
    Match the user's selected follow-up anchor to a prior assistant message that stored
    `evidence_snapshot` (raw forensic text from that turn). Enables row-level examples
    without re-querying the DB.
    """
    hist = CHAT_HISTORIES.get(session_id) or []
    bc = (base_content or "").strip()
    if len(bc) < 12:
        return ""

    def _head(s: str, n: int = 400) -> str:
        return " ".join((s or "").split())[:n]

    hb = _head(bc)
    for m in reversed(hist):
        if m.get("role") != "assistant":
            continue
        c = (m.get("content") or "").strip()
        if not c:
            continue
        hc = _head(c)
        if hc.startswith(hb) or hb.startswith(hc) or bc[:220] == c[:220]:
            snap = m.get("evidence_snapshot")
            if snap:
                return str(snap)
    return ""


def _iso_dates_in_text(text: str) -> set:
    """Calendar dates YYYY-MM-DD appearing in free text."""
    if not text:
        return set()
    return set(re.findall(r"\d{4}-\d{2}-\d{2}", text))


def _infer_followup_base_domain(base_content: str) -> Optional[str]:
    """
    Rough domain of the selected assistant bubble (for follow-up supplement logic).
    """
    bc = (base_content or "").lower()
    if not bc:
        return None
    if "locations (" in bc or "=== locations" in bc or "location records" in bc:
        return "locations"
    if "calls (" in bc or "=== calls" in bc or "call log" in bc:
        return "calls"
    if "contacts (" in bc or "=== contacts" in bc:
        return "contacts"
    if "media (" in bc or "=== media" in bc:
        return "media"
    if "messages (" in bc or "=== messages" in bc or "chat_messages" in bc:
        return "messages"
    if "chats (" in bc or "conversation" in bc[:120]:
        return "chats"
    return None


def _followup_supplementary_deterministic_block(
    user_query_original: str,
    parsed_intent: Optional[dict],
    base_content: str,
) -> str:
    """
    When follow-up references a *different* forensic domain than the selected base (e.g. base
    is WhatsApp messages but the user asks for locations on a date), run the same deterministic
    retrieval used for direct queries and attach rows to the LLM prompt.

    Covers similar phrasing: find/show/list/get/pull locations|calls|messages|... with dates.
    """
    uq = (user_query_original or "").strip()
    if not uq or any(ord(ch) > 127 for ch in uq):
        return ""
    if not _is_basic_deterministic_intent(uq):
        return ""
    req_domain = _detect_basic_deterministic_domain(uq)
    if not req_domain:
        return ""
    base_domain = _infer_followup_base_domain(base_content or "")
    # Avoid duplicating the same table when the user repeats the same domain+date scope as the base.
    if base_domain and req_domain == base_domain and req_domain not in ("forensic_multibundle", "calls_and_chats"):
        u_dates = _iso_dates_in_text(uq)
        b_dates = _iso_dates_in_text(base_content or "")
        if not u_dates or (u_dates and b_dates and u_dates.issubset(b_dates)):
            return ""

    try:
        filt = None
        if isinstance(parsed_intent, dict):
            filt = parsed_intent.get("filters")
        dr = run_basic_deterministic_retrieval(
            uq,
            platform=None,
            limit=80,
            intent_filters=filt if isinstance(filt, dict) else None,
            user_query_for_dates=uq,
        )
    except Exception as e:
        logger.warning(f"Follow-up supplementary deterministic retrieval failed: {e}")
        return ""
    if not dr or not dr.get("handled"):
        return ""
    text = (dr.get("response") or "").strip()
    if not text:
        return ""
    cap = LLM_MAX_FORENSIC_CHARS
    if len(text) > cap:
        text = text[:cap] + "\n\n[… supplementary deterministic evidence truncated …]"
    logger.info(
        "📎 Follow-up supplementary deterministic: domain=%s base_domain=%s chars=%s",
        req_domain,
        base_domain,
        len(text),
    )
    return (
        "\n\n---\n\n"
        "SUPPLEMENTARY DETERMINISTIC FORENSIC DATA (retrieved from the loaded case for this follow-up question; "
        "use for facts in this domain — the selected base message may be a different artifact type):\n"
        f"{text}"
    )


def _followup_supplementary_has_data_rows(data_context: str) -> bool:
    """
    True when the supplementary block contains real row bullets (not only 'No matching' lines).
    Used to force the LLM not to contradict deterministic rows (recency / attention issue).
    """
    if not data_context or "SUPPLEMENTARY DETERMINISTIC FORENSIC DATA" not in data_context:
        return False
    idx = data_context.find("SUPPLEMENTARY DETERMINISTIC FORENSIC DATA")
    chunk = data_context[idx:]
    return bool(re.search(r"^\s*-\s*\[\d{4}-\d{2}-\d{2}", chunk, re.MULTILINE))


def _format_evidence_summary_found_span(ts: list) -> str:
    """
    Human-readable span for 'Found: N records …' when timestamps were parsed from deterministic text.
    Avoids misleading 'on Sep12–Oct4 between 20:16 to 17:33 UTC' (wall times from different days).
    """
    if not ts:
        return "date/time span unavailable"
    srt = sorted(ts)
    first, last = srt[0], srt[-1]
    d1, d2 = first[:10], last[:10]

    def wall_clock(s: str) -> str:
        if len(s) >= 16:
            return f"{s[:10]} {s[11:16]} UTC"
        if len(s) >= 10:
            return f"{s[:10]} (time not shown) UTC"
        return s

    if len(srt) == 1:
        return f"at {wall_clock(first)}"

    if d1 == d2:
        t1 = first[11:16] if len(first) >= 16 else "?"
        t2 = last[11:16] if len(last) >= 16 else "?"
        return f"on {d1} between {t1} and {t2} UTC"

    return f"from {wall_clock(first)} through {wall_clock(last)}"


def _extract_iso_timestamps_for_summary(text: str) -> list:
    """
    Pull timestamp-like strings from deterministic text blocks.
    Supports full ISO and date-only forms.
    """
    if not text:
        return []
    ts = re.findall(
        r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)?",
        text,
    )
    out = []
    for t in ts:
        v = (t or "").strip()
        if not v:
            continue
        # Normalize date-only to sortable datetime-ish shape.
        if len(v) == 10:
            v = v + "T00:00:00"
        else:
            v = v.replace(" ", "T")
            if len(v) == 16:
                v = v + ":00"
            if v.endswith("Z"):
                v = v[:-1] + "+00:00"
        out.append(v)
    return out


def _build_deterministic_key_observation(query: str, response_text: str, timestamps: list, count: int) -> str:
    """Simple deterministic rule-based observation (no LLM)."""
    q = (query or "").lower()
    has_overlap_terms = any(
        k in q for k in ("correlate", "cross-reference", "cross reference", "overlap", "timeline", "reconstruct")
    )
    if count == 0:
        return "No matching evidence rows were found for the requested constraints."
    if len(timestamps) >= 2:
        srt = sorted(timestamps)
        first = srt[0]
        last = srt[-1]
        same_day = first[:10] == last[:10]
        try:
            d1 = datetime.fromisoformat(first)
            d2 = datetime.fromisoformat(last)
            mins = abs((d2 - d1).total_seconds()) / 60.0
            if same_day and mins <= 10:
                return "Evidence events occur in a short time window, indicating burst-like activity."
            if same_day and has_overlap_terms:
                return "Cross-domain evidence overlaps on the same day, supporting timeline correlation."
        except Exception:
            pass
    if has_overlap_terms:
        return "Deterministic correlation rows were returned for the requested relationship scope."
    if "platform" in q or any(p in q for p in ("whatsapp", "telegram", "line", "sms", "calls", "messages", "location")):
        return "Returned rows match the requested domain/platform filters."
    return "Returned rows provide a deterministic evidence baseline for follow-up analysis."


def _derive_record_count_from_deterministic_text(text: str) -> int:
    """
    Best-effort count extraction for deterministic blocks that do not pass count explicitly
    (notably correlation/timeline formatted text).
    """
    if not text:
        return 0
    total = 0

    # Prefer explicit Count bullets, e.g.:
    # - Chats: 14 message(s), 1 thread(s)
    # - Locations: 5 record(s)
    for m in re.finditer(r"-\s+[A-Za-z ]+:\s*(\d+)\s+(?:message|record|call|contact|chat)", text, re.IGNORECASE):
        try:
            total += int(m.group(1))
        except Exception:
            pass
    if total > 0:
        return total

    # Fallback: summary line, e.g. "— 14 chat message(s), 5 location record(s)"
    for m in re.finditer(r"(\d+)\s+(?:chat\s+message|location\s+record|call|message|record|contact)s?\b", text, re.IGNORECASE):
        try:
            total += int(m.group(1))
        except Exception:
            pass
    if total > 0:
        return total

    # Last fallback: count row bullets like [timestamp] lines
    row_hits = len(re.findall(r"^\s*\[\d{4}-\d{2}-\d{2}", text, flags=re.MULTILINE))
    return row_hits


def _prepend_deterministic_evidence_summary(
    *,
    query: str,
    response_text: str,
    scope_label: str,
    count: int = None,
    platform_hint: str = None,
) -> str:
    """
    Add a fixed 3-line Evidence Summary block above deterministic output.
    Presentation-only: no routing/retrieval changes.
    """
    body = (response_text or "").strip()
    if not body:
        return body
    if body.lower().startswith("evidence summary"):
        return body

    ts = _extract_iso_timestamps_for_summary(body)
    effective_count = count if isinstance(count, int) and count >= 0 else _derive_record_count_from_deterministic_text(body)
    count_text = str(effective_count) if isinstance(effective_count, int) and effective_count >= 0 else "N/A"
    found_span = _format_evidence_summary_found_span(ts)

    scope = scope_label or "requested forensic domain"
    if isinstance(platform_hint, (list, tuple)):
        platform_hint = platform_hint[0] if platform_hint else None
    if platform_hint is not None and not isinstance(platform_hint, str):
        platform_hint = str(platform_hint)
    if platform_hint:
        scope = f"{platform_hint} {scope}"
    observation = _build_deterministic_key_observation(
        query,
        body,
        ts,
        effective_count if isinstance(effective_count, int) else -1,
    )

    summary = (
        "Evidence Summary\n"
        f"Scope: {scope}\n"
        f"Found: {count_text} records — {found_span}\n"
        f"Key observation: {observation}\n"
    )
    return f"{summary}\n{body}"


# Create upload directory
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize NL query engines (answers will be restricted to ACTIVE_DATA)
nl_engine = NaturalLanguageUFDR({})
enhanced_nl_engine = EnhancedNaturalLanguageUFDR({})

# Initialize the AI-powered retrieval engine
ai_retrieval_engine = AIUFDRRetrievalEngine({})

# Initialize simplified engine for comprehensive analysis
from engines.simplified_nl_query_engine import SimplifiedNLQueryEngine
simplified_engine = SimplifiedNLQueryEngine()
# RAG engine disabled - using keyword-based extraction instead
rag_engine = None  # UFDRRAGEngine()

# Initialize semantic extractor without RAG engine (will use keyword-based extraction)
from core.semantic_data_extractor import SemanticDataExtractor
semantic_extractor = SemanticDataExtractor(rag_engine=None)
# LLM Configuration
USE_LLM = True  # Enable LM Studio integration (Required for AI Chat Assistant)
LLM_MODEL = "Qwen/Qwen2.5-7B-Instruct"  # LM Studio model (Qwen 2.5 7B Instruct - optimized for better performance)
LLM_URL = "http://localhost:1234/v1/chat/completions"  # LM Studio API endpoint
LLM_PROVIDER_DEFAULT = (os.environ.get("LLM_PROVIDER_DEFAULT", "local") or "local").strip().lower()
LLM_OPENROUTER_URL = os.environ.get("LLM_OPENROUTER_URL", "https://openrouter.ai/api/v1/chat/completions")
LLM_OPENROUTER_MODEL = os.environ.get("LLM_OPENROUTER_MODEL", "").strip()


def _normalize_openrouter_api_key(raw: Optional[str]) -> str:
    """Strip whitespace and accidental 'Bearer ' prefix (we add Bearer in headers)."""
    key = (raw or "").strip()
    if key.lower().startswith("bearer "):
        key = key[7:].strip()
    return key


OPENROUTER_API_KEY = _normalize_openrouter_api_key(os.environ.get("OPENROUTER_API_KEY", ""))
OPENROUTER_REFERER = os.environ.get("OPENROUTER_REFERER", "").strip()
OPENROUTER_TITLE = os.environ.get("OPENROUTER_TITLE", "EVI").strip()
LLM_LOCAL_MODELS_URL = os.environ.get("LLM_LOCAL_MODELS_URL", "http://localhost:1234/v1/models")

# LLM Context Length Configuration
# Set this to match your model's context length in LM Studio (after "Reload to apply").
# Common values: 2048, 4096, 8192, 32768
LLM_CONTEXT_LENGTH = int(os.environ.get("LLM_CONTEXT_LENGTH", "32768"))
# If LM Studio loaded a smaller n_ctx than LLM_CONTEXT_LENGTH (e.g. forgot reload), set this to the
# actual loaded value so truncation stays safe — e.g. LLM_ASSUMED_CONTEXT_CAP=4096
LLM_ASSUMED_CONTEXT_CAP = int(os.environ.get("LLM_ASSUMED_CONTEXT_CAP", "0") or "0")
# Completion length (lower = faster local inference)
LLM_MAX_OUTPUT_TOKENS = max(256, int(os.environ.get("LLM_MAX_OUTPUT_TOKENS", "1536")))
LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0.35"))
# Reserve for FORENSIC DATA framing, evidence contract, and tokenization slack
LLM_PROMPT_OVERHEAD_TOKENS = int(os.environ.get("LLM_PROMPT_OVERHEAD_TOKENS", "600"))

_VALID_LLM_PROVIDERS = frozenset({"local", "openrouter"})


def normalize_llm_provider(value: Optional[str]) -> str:
    p = (value or "").strip().lower()
    if p not in _VALID_LLM_PROVIDERS:
        return "local"
    return p


def get_session_preferred_llm_provider(session_id: Optional[str]) -> Optional[str]:
    if not session_id or not SESSION_DB_AVAILABLE:
        return None
    try:
        prefs = get_preferences(session_id) or {}
        p = prefs.get("llm_provider")
        if p:
            return normalize_llm_provider(str(p))
    except Exception as e:
        logger.debug(f"Could not load llm_provider preference for session={session_id}: {e}")
    return None


def resolve_effective_llm_provider(
    *,
    session_id: Optional[str] = None,
    request_data: Optional[Dict[str, Any]] = None,
) -> str:
    # Priority:
    # 1) explicit request override, 2) session preference, 3) env default.
    req_provider = None
    if isinstance(request_data, dict):
        req_provider = request_data.get("llm_provider")
    if req_provider:
        return normalize_llm_provider(str(req_provider))
    sess_provider = get_session_preferred_llm_provider(session_id)
    if sess_provider:
        return sess_provider
    return normalize_llm_provider(LLM_PROVIDER_DEFAULT)


def resolve_effective_llm_model(provider: str) -> str:
    p = normalize_llm_provider(provider)
    if p == "openrouter":
        return LLM_OPENROUTER_MODEL or LLM_MODEL
    return LLM_MODEL


def resolve_effective_llm_url(provider: str) -> str:
    p = normalize_llm_provider(provider)
    if p == "openrouter":
        return LLM_OPENROUTER_URL
    return LLM_URL


def _provider_display_name(provider: str) -> str:
    return "OpenRouter" if normalize_llm_provider(provider) == "openrouter" else "LM Studio"


def _provider_request_headers(provider: str) -> Dict[str, str]:
    p = normalize_llm_provider(provider)
    headers = {"Content-Type": "application/json"}
    if p == "openrouter":
        if OPENROUTER_API_KEY:
            headers["Authorization"] = f"Bearer {OPENROUTER_API_KEY}"
        if OPENROUTER_REFERER:
            headers["HTTP-Referer"] = OPENROUTER_REFERER
        if OPENROUTER_TITLE:
            # https://openrouter.ai/docs/api/reference/authentication
            headers["X-OpenRouter-Title"] = OPENROUTER_TITLE
    return headers


def _openrouter_client_error_hint(provider: str, status_code: int, body: str) -> str:
    if normalize_llm_provider(provider) != "openrouter" or status_code != 401:
        return ""
    hint = (
        "\n\n**What to try:** OpenRouter returned 401 — your request reached them but the key was rejected. "
        "Open https://openrouter.ai/keys , create a new secret key, set user env var `OPENROUTER_API_KEY` "
        "to the key string only (do not include `Bearer `). Fully quit and restart EVI so Python reloads the env."
    )
    if (body or "").lower().find("user not found") >= 0:
        hint += (
            ' The text \"User not found\" almost always means the key is wrong, revoked, or not an OpenRouter '
            "`sk-or-...` key (for example a different provider's key by mistake)."
        )
    return hint


def llm_provider_health_check(provider: str, timeout: int = 5) -> Tuple[bool, str]:
    p = normalize_llm_provider(provider)
    if p == "openrouter":
        if not OPENROUTER_API_KEY:
            return False, "OpenRouter API key is not configured."
        try:
            resp = requests.get(
                "https://openrouter.ai/api/v1/models",
                headers=_provider_request_headers("openrouter"),
                timeout=timeout,
            )
            if not resp.ok:
                if resp.status_code == 401:
                    return (
                        False,
                        "OpenRouter health check: HTTP 401 — API key rejected. "
                        "Use a key from https://openrouter.ai/keys (value only, no 'Bearer ' prefix) and restart EVI.",
                    )
                return False, f"OpenRouter health check failed: HTTP {resp.status_code}"
            return True, "OpenRouter health check passed."
        except requests.exceptions.Timeout:
            return False, "OpenRouter health check timed out."
        except requests.exceptions.ConnectionError:
            return False, "Cannot connect to OpenRouter."
        except Exception as e:
            return False, f"OpenRouter health check failed: {e}"
    try:
        resp = requests.get(LLM_LOCAL_MODELS_URL, timeout=timeout)
        if not resp.ok:
            return False, f"LM Studio health check failed: HTTP {resp.status_code}"
        return True, "LM Studio health check passed."
    except requests.exceptions.Timeout:
        return False, "LM Studio health check timed out."
    except requests.exceptions.ConnectionError:
        return False, "Cannot connect to LM Studio."
    except Exception as e:
        return False, f"LM Studio health check failed: {e}"


def llm_request(
    provider: str,
    payload: Dict[str, Any],
    *,
    stream: bool,
    timeout: int = 90,
):
    url = resolve_effective_llm_url(provider)
    resp = requests.post(
        url,
        json=payload,
        headers=_provider_request_headers(provider),
        timeout=timeout,
        stream=stream,
    )
    # Provider may omit charset; requests defaults to ISO-8859-1 and corrupts UTF-8 in .text / iter_lines.
    resp.encoding = "utf-8"
    return resp


def llm_effective_context_tokens() -> int:
    if LLM_ASSUMED_CONTEXT_CAP > 0:
        return min(LLM_CONTEXT_LENGTH, LLM_ASSUMED_CONTEXT_CAP)
    return LLM_CONTEXT_LENGTH


def compute_llm_forensic_char_budget(messages: list, query: str) -> tuple:
    """(max_chars_for_forensic_blob, effective_context_tokens)."""
    effective_ctx = llm_effective_context_tokens()
    system_chars = len(messages[0].get("content", "")) if messages else 0
    system_tokens = int(system_chars / 1.67)
    query_tokens = int(len(query or "") / 1.67)
    response_reserve = LLM_MAX_OUTPUT_TOKENS + 256
    available_tokens = (
        effective_ctx - system_tokens - query_tokens - response_reserve - LLM_PROMPT_OVERHEAD_TOKENS
    )
    available_tokens = int(available_tokens * 0.9)
    available_tokens = max(500, available_tokens)
    available_chars = int(available_tokens * 1.67)
    available_chars = min(available_chars, LLM_MAX_FORENSIC_CHARS)
    return available_chars, effective_ctx


def truncate_forensic_text_to_budget(text: str, max_chars: int) -> str:
    if not text or max_chars <= 0:
        return text or ""
    if len(text) <= max_chars:
        return text
    truncated = text[:max_chars]
    last_nl = truncated.rfind("\n")
    last_period = truncated.rfind(".")
    last_boundary = max(last_nl, last_period)
    if last_boundary > int(max_chars * 0.82):
        truncated = text[: last_boundary + 1]
    return (
        truncated
        + f"\n\n_…truncated to {len(truncated)} / {len(text)} characters for model context._"
    )


def llm_context_overflow_user_message(
    raw_error: str,
    approx_prompt_tokens: int,
    user_content_chars: int,
) -> str:
    """Accurate guidance when LM Studio / llama.cpp rejects the prompt (n_ctx, n_keep, etc.)."""
    n_ctx_hint = None
    m = re.search(r"n_ctx\D*(\d+)", raw_error or "")
    if m:
        try:
            n_ctx_hint = int(m.group(1))
        except ValueError:
            n_ctx_hint = None
    eff = llm_effective_context_tokens()
    parts = [
        "**CONTEXT / PROMPT TOO LARGE FOR THE LOADED MODEL**",
        "",
        f"Server message: `{((raw_error or '')[:500]).strip()}`",
        "",
    ]
    if n_ctx_hint is not None:
        cap_note = (
            f"{LLM_ASSUMED_CONTEXT_CAP}"
            if LLM_ASSUMED_CONTEXT_CAP > 0
            else "off (not set)"
        )
        parts.append(
            f"LM Studio / the backend reports **n_ctx ≈ {n_ctx_hint}**. "
            f"The app budgets prompts using **{eff}** tokens "
            f"(`LLM_CONTEXT_LENGTH`={LLM_CONTEXT_LENGTH}, `LLM_ASSUMED_CONTEXT_CAP`={cap_note})."
        )
        parts.append(
            f"If those numbers differ, either raise Context Length in LM Studio and click **Reload to apply**, "
            f"or set `LLM_ASSUMED_CONTEXT_CAP={n_ctx_hint}` (and optionally `LLM_CONTEXT_LENGTH={n_ctx_hint}`) "
            f"and restart EVI."
        )
    else:
        parts.append(
            f"Approximate prompt size ~**{approx_prompt_tokens}** tokens (rough). "
            f"Effective context used for budgeting: **{eff}** tokens."
        )
        parts.append(
            "Try: reload the model in LM Studio with a larger context, narrow the query, "
            "or lower `LLM_MAX_FORENSIC_CHARS` / `LLM_MAX_OUTPUT_TOKENS`."
        )
    parts.append("")
    parts.append(f"User message size: **{user_content_chars}** characters.")
    return "\n".join(parts)

# Qwen2.5-VL-7B Configuration
USE_QWEN_VL = False  # DISABLED - Enable Qwen2.5-VL-7B for multimodal (images/videos) - Set to True to enable
QWEN_VL_MODEL_NAME = "Qwen/Qwen2.5-VL-7B-Instruct"
QWEN_VL_MODEL = None
QWEN_VL_PROCESSOR = None
QWEN_VL_LOADED = False

# Log LLM configuration at startup
if USE_LLM:
    logger.info(
        "LLM enabled — default_provider=%s, model=%s, local_url=%s, openrouter_url=%s, context=%s (effective=%s), max_forensic_chars=%s, max_output_tokens=%s, temp=%s",
        normalize_llm_provider(LLM_PROVIDER_DEFAULT),
        LLM_MODEL,
        LLM_URL,
        LLM_OPENROUTER_URL,
        LLM_CONTEXT_LENGTH,
        llm_effective_context_tokens(),
        LLM_MAX_FORENSIC_CHARS,
        LLM_MAX_OUTPUT_TOKENS,
        LLM_TEMPERATURE,
    )
else:
    logger.warning("LLM integration disabled - AI Chat Assistant will not be available")

if USE_QWEN_VL:
    logger.info(f"Qwen2.5-VL-7B multimodal support enabled - Model: {QWEN_VL_MODEL_NAME}")
else:
    logger.info("Qwen2.5-VL-7B multimodal support disabled")

# Available LLM models
AVAILABLE_MODELS = ["qwen2.5", "llama3.2", "mistral"]

# Active uploaded UFDR context
ACTIVE_FILENAME = None
ACTIVE_DATA = {}
ACTIVE_DATA_LAYERS = {}  # Store data access layers for fast querying (Cellebrite format)
ACTIVE_DB_PATHS = {}  # Store database paths for Cellebrite files

def get_current_data():
    """Return only actively uploaded UFDR data. No synthetic fallback."""
    global ACTIVE_DATA, ACTIVE_DATA_LAYERS
    try:
        if ACTIVE_DATA:
            return ACTIVE_DATA
    except Exception:
        pass
    
    # Check ACTIVE_DATA_LAYERS (for XML/Cellebrite files)
    # Return a marker dict to indicate XML data is available
    # The actual data will be accessed via ACTIVE_DATA_LAYERS in query handlers
    if ACTIVE_DATA_LAYERS:
        return {'_xml_data_available': True, '_data_layers': list(ACTIVE_DATA_LAYERS.keys())}
    
    return {}

def rebuild_rag_index():
    """Rebuild the RAG index with current data."""
    # RAG is disabled - return early
    if rag_engine is None:
        logger.debug("RAG engine is disabled - skipping index rebuild")
        return False
    
    data_src = get_current_data()
    try:
        # Clear old RAG index first
        rag_engine.chunks = []
        rag_engine.index = None
        rag_engine._embed_cache.clear()
        rag_engine._query_cache.clear()
        
        # Check if RAG engine is available before building
        if not rag_engine.available:
            logger.warning("⚠️ RAG engine dependencies missing - cannot build index")
            logger.warning("⚠️ Install with: pip install numpy faiss-cpu sentence-transformers")
            return False
        
        # Build new index with current data
        success = rag_engine.build_index(data_src)
        
        if success:
            # Update semantic extractor with rebuilt RAG engine
            global semantic_extractor
            if semantic_extractor:
                semantic_extractor.rag_engine = rag_engine
                semantic_extractor._data_index = {}  # Reset data index to force rebuild
                logger.info("✅ Semantic extractor data index reset")
            
            logger.info("✅ RAG index rebuilt with fresh data, semantic extractor updated")
            return True
        else:
            logger.warning("⚠️ RAG index build failed - check logs above for details")
            return False
    except Exception as e:
        logger.error(f"❌ Failed to rebuild RAG index: {e}", exc_info=True)
        return False


def is_query_too_broad(query: str) -> bool:
    """
    Heuristic to detect overly broad queries that are likely to produce
    generic, non-data-grounded answers.
    """
    if not query or not isinstance(query, str):
        return False

    q = query.strip().lower()

    # Very short generic prompts
    if len(q) < 12:
        return True

    generic_phrases = [
        "what can you tell me about the ufdr",
        "what can you tell me about this ufdr",
        "what can you tell me about this file",
        "tell me about the ufdr",
        "tell me about this ufdr",
        "tell me about this case",
        "summarize this file",
        "give me a summary",
        "overall summary",
        "overall analysis",
        "analyse this ufdr",
        "analyze this ufdr",
        "analyze this file",
        "general overview",
    ]

    for phrase in generic_phrases:
        if phrase in q:
            return True

    # If user only says "tell me about this" or similar without any domain terms
    if ("tell me" in q or "what can you tell" in q) and not any(
        kw in q
        for kw in ["message", "messages", "sms", "whatsapp", "call", "calls",
                   "contact", "contacts", "timeline", "date", "time",
                   "money", "transaction", "otp", "location"]
    ):
        return True

    return False


def generate_forensic_overview(data_src: dict) -> dict:
    """
    Generate a pre-summarized forensic overview object instead of dumping raw data.
    This prevents hallucination for summary questions.
    """
    overview = {
        "contacts_count": 0,
        "messages_count": 0,
        "calls_count": 0,
        "locations_count": 0,
        "date_range": None,
        "top_apps": [],
        "most_active_contacts": [],
        "activity_spikes": [],
        "deleted_artifacts": False
    }
    
    all_dates = []
    contact_frequency = {}
    app_types = set()
    
    for filename, data in data_src.items():
        if filename.startswith('_'):
            continue
            
        if isinstance(data, dict):
            # Handle devices array format
            if 'devices' in data:
                devices = data['devices']
                for device in devices:
                    if isinstance(device, dict):
                        overview["contacts_count"] += len(device.get('contacts', []))
                        overview["messages_count"] += len(device.get('messages', []))
                        overview["calls_count"] += len(device.get('call_logs', []))
                        overview["locations_count"] += len(device.get('locations', []))
                        
                        # Extract dates from messages
                        for msg in device.get('messages', []):
                            if msg.get('timestamp'):
                                all_dates.append(msg.get('timestamp'))
                            if msg.get('source'):
                                app_types.add(msg.get('source'))
                        
                        # Count contact activity
                        for msg in device.get('messages', []):
                            contact = msg.get('from') or msg.get('sender')
                            if contact:
                                contact_frequency[contact] = contact_frequency.get(contact, 0) + 1
            else:
                # Flat structure
                overview["contacts_count"] += len(data.get('contacts', []))
                overview["messages_count"] += len(data.get('messages', []))
                overview["calls_count"] += len(data.get('call_logs', []))
                overview["locations_count"] += len(data.get('locations', []))
                
                # Extract dates
                for msg in data.get('messages', []):
                    if msg.get('timestamp'):
                        all_dates.append(msg.get('timestamp'))
                    if msg.get('source'):
                        app_types.add(msg.get('source'))
                
                # Count contact activity
                for msg in data.get('messages', []):
                    contact = msg.get('from') or msg.get('sender')
                    if contact:
                        contact_frequency[contact] = contact_frequency.get(contact, 0) + 1
    
    # Calculate date range
    if all_dates:
        try:
            from datetime import datetime
            valid_dates = [d for d in all_dates if d and isinstance(d, str)]
            if valid_dates:
                # Try to parse dates
                parsed_dates = []
                for d in valid_dates[:100]:  # Sample first 100
                    try:
                        # Try common formats
                        for fmt in ['%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S']:
                            try:
                                parsed_dates.append(datetime.strptime(d[:19], fmt))
                                break
                            except:
                                continue
                    except:
                        continue
                
                if parsed_dates:
                    min_date = min(parsed_dates)
                    max_date = max(parsed_dates)
                    overview["date_range"] = f"{min_date.strftime('%Y-%m-%d')} to {max_date.strftime('%Y-%m-%d')}"
        except Exception as e:
            logger.debug(f"Error calculating date range: {e}")
    
    # Top apps
    overview["top_apps"] = list(app_types)[:5]
    
    # Most active contacts (top 5)
    if contact_frequency:
        sorted_contacts = sorted(contact_frequency.items(), key=lambda x: x[1], reverse=True)
        overview["most_active_contacts"] = [name for name, count in sorted_contacts[:5]]
    
    return overview


def rewrite_vague_query(query: str) -> str:
    """
    Auto-rewrite vague questions to specific forensic queries.
    Prevents hallucination by making intent explicit.
    """
    query_lower = query.lower().strip()
    
    vague_patterns = {
        "what can you tell me about this ufdr file": "Summarize ONLY: dataset size, data types present, date range, notable activity patterns",
        "what can you tell me about this ufdr": "Summarize ONLY: dataset size, data types present, date range, notable activity patterns",
        "what can you tell me about this file": "Summarize ONLY: dataset size, data types present, date range, notable activity patterns",
        "tell me about this ufdr": "Summarize ONLY: dataset size, data types present, date range, notable activity patterns",
        "tell me about this case": "Summarize ONLY: dataset size, data types present, date range, notable activity patterns",
        "analyze this ufdr": "Summarize ONLY: dataset size, data types present, date range, notable activity patterns",
        "analyze this file": "Summarize ONLY: dataset size, data types present, date range, notable activity patterns",
    }
    
    for pattern, rewrite in vague_patterns.items():
        if pattern in query_lower:
            logger.info(f"🔄 Rewriting vague query: '{query}' → '{rewrite}'")
            return rewrite
    
    return query  # Return original if not vague


def _get_active_data_layer():
    """Return the currently active Cellebrite data layer, if any."""
    global ACTIVE_DATA_LAYERS, ACTIVE_FILENAME
    if ACTIVE_FILENAME and ACTIVE_FILENAME in ACTIVE_DATA_LAYERS:
        return ACTIVE_DATA_LAYERS[ACTIVE_FILENAME]
    if ACTIVE_DATA_LAYERS:
        return list(ACTIVE_DATA_LAYERS.values())[0]
    return None


def _keyword_has_phrase(query_lower: str, phrase: str) -> bool:
    """Word-boundary-safe phrase match on already-lowercased query."""
    q = query_lower or ""
    p = re.escape((phrase or "").lower().strip())
    if not p:
        return False
    return re.search(rf"(^|[^a-z0-9]){p}([^a-z0-9]|$)", q) is not None


def _query_lower_for_message_chat_facets(query: str) -> str:
    """Strip platform+chat labels before deciding if the user asked for the messages facet."""
    return scrub_platform_chat_labels_for_domain_parsing(query)


def _collect_forensic_domain_mentions(query: str) -> set:
    """Which forensic facets the user asked for (used for multibundle). 'messages' covers chat/messages wording."""
    q = (query or "").lower()
    q_no_platform = scrub_platform_aliases_for_domain_parsing(query)
    q_msg = _query_lower_for_message_chat_facets(query)
    if not q:
        return set()
    message_kws = ["message", "messages", "sms", "mms", "text", "texts", "संदेश", "मैसेज"]
    chat_kws = ["chat", "chats", "conversation", "conversations", "thread", "threads", "चैट", "बातचीत", "संवाद"]
    call_kws = ["call", "calls", "call log", "call logs", "dialed", "incoming call", "outgoing call", "कॉल", "कॉल लॉग", "फोन कॉल"]
    contact_kws = ["contact", "contacts", "phonebook", "address book", "संपर्क", "कॉन्टैक्ट", "फ़ोनबुक", "फोनबुक"]
    location_kws = [
        "location", "locations", "gps", "coordinate", "coordinates", "map", "address history",
        "where was", "whereabouts", "लोकेशन", "स्थान", "जीपीएस", "मैप",
    ]
    media_kws = ["media", "image", "images", "photo", "photos", "video", "videos", "attachment", "attachments", "मीडिया", "फोटो", "चित्र", "वीडियो", "अटैचमेंट"]
    mentions = set()
    if any(_keyword_has_phrase(q_no_platform, kw) for kw in location_kws):
        mentions.add("locations")
    if any(_keyword_has_phrase(q_no_platform, kw) for kw in call_kws):
        mentions.add("calls")
    if any(_keyword_has_phrase(q_no_platform, kw) for kw in contact_kws):
        mentions.add("contacts")
    if any(_keyword_has_phrase(q_no_platform, kw) for kw in media_kws):
        mentions.add("media")
    if any(_keyword_has_phrase(q_msg, kw) for kw in message_kws):
        mentions.add("messages")
    if any(_keyword_has_phrase(q_msg, kw) for kw in chat_kws):
        mentions.add("messages")
    return mentions


def _query_has_chat_or_message_phrase(query: str) -> bool:
    qm = _query_lower_for_message_chat_facets(query)
    message_kws = ["message", "messages", "sms", "mms", "text", "texts", "संदेश", "मैसेज"]
    chat_kws = ["chat", "chats", "conversation", "conversations", "thread", "threads", "चैट", "बातचीत", "संवाद"]
    return any(_keyword_has_phrase(qm, kw) for kw in chat_kws) or any(_keyword_has_phrase(qm, kw) for kw in message_kws)


def _detect_basic_deterministic_domain(query: str):
    """
    Super-basic deterministic detector for core domains plus coordinated pairs:
    forensic_multibundle, calls_and_chats, locations, calls, contacts, media, messages, chats.
    Returns domain name or None.
    """
    q = (query or "").lower()
    q_no_platform = scrub_platform_aliases_for_domain_parsing(query)
    mentions = _collect_forensic_domain_mentions(query)
    has_calls = "calls" in mentions
    has_chat_or_msg = _query_has_chat_or_message_phrase(query)

    message_kws = ["message", "messages", "sms", "mms", "text", "texts", "संदेश", "मैसेज"]
    chat_kws = ["chat", "chats", "conversation", "conversations", "thread", "threads", "चैट", "बातचीत", "संवाद"]
    call_kws = ["call", "calls", "call log", "call logs", "dialed", "incoming call", "outgoing call", "कॉल", "कॉल लॉग", "फोन कॉल"]
    contact_kws = ["contact", "contacts", "phonebook", "address book", "संपर्क", "कॉन्टैक्ट", "फ़ोनबुक", "फोनबुक"]
    location_kws = [
        "location", "locations", "gps", "coordinate", "coordinates", "map", "address history",
        "where was", "whereabouts", "लोकेशन", "स्थान", "जीपीएस", "मैप",
    ]
    media_kws = ["media", "image", "images", "photo", "photos", "video", "videos", "attachment", "attachments", "मीडिया", "फोटो", "चित्र", "वीडियो", "अटैचमेंट"]

    # "Show calls and chats from WhatsApp on …" — coordinated pair (narrower than full multibundle).
    if has_calls and has_chat_or_msg and _wants_combined_calls_and_chats_query(q):
        return "calls_and_chats"

    # "Locations and chats", "calls and locations and contacts", … — multiple facets in one answer.
    if len(mentions) >= 2 and re.search(r"(\band\b|\bor\b|[,;/]|&|\+)", q):
        return "forensic_multibundle"

    # Single-domain priority (locations before calls, etc.)
    if any(_keyword_has_phrase(q_no_platform, kw) for kw in location_kws):
        return "locations"
    if any(_keyword_has_phrase(q_no_platform, kw) for kw in call_kws):
        return "calls"
    if any(_keyword_has_phrase(q_no_platform, kw) for kw in contact_kws):
        return "contacts"
    if any(_keyword_has_phrase(q_no_platform, kw) for kw in media_kws):
        return "media"
    qm = _query_lower_for_message_chat_facets(query)
    if any(_keyword_has_phrase(qm, kw) for kw in message_kws):
        return "messages"
    if any(_keyword_has_phrase(qm, kw) for kw in chat_kws):
        return "chats"
    return None


def _is_basic_deterministic_intent(query: str) -> bool:
    """Detect clear retrieval/count/filter style intents."""
    q = (query or "").lower()
    # Analysis / interpretation belongs on the LLM path with a forensic packet, not list-only deterministic.
    if re.search(
        r"\b(analyze|analyse|analysis|insights?|summarize|summarise|interpret|explain|analzye|nalzye|anaylze|analize|anlyze|analsis)\b",
        q,
    ):
        return False
    retrieval_terms = [
        "show", "list", "get", "find", "pull", "fetch", "retrieve", "view", "open", "display", "count", "how many",
        "दिखाओ", "दिखाएं", "निकालो", "निकालें", "प्राप्त", "प्राप्त करें", "खोज", "ढूंढ", "ढूँढ", "गिनती", "कितने", "सूची"
    ]
    return any(term in q for term in retrieval_terms)


def _count_rows(data_layer, table_name: str) -> int:
    """Best-effort table row count helper."""
    conn = data_layer.get_connection()
    try:
        cur = conn.cursor()
        cur.execute(f"SELECT COUNT(*) AS c FROM {table_name}")
        row = cur.fetchone()
        return int(row["c"] if row and "c" in row.keys() else 0)
    except Exception:
        return 0
    finally:
        conn.close()


def _normalize_platform_name(name: str) -> str:
    """Normalize platform labels for tolerant matching."""
    if not name:
        return ""
    s = str(name).strip().lower()
    s = s.replace(" ", "").replace("-", "").replace("_", "")
    alias_map = {
        "native": "nativemessages",
        "nativemessage": "nativemessages",
        "textnow": "textnow",
        "tiktok": "tiktok",
        "messenger": "facebookmessenger",
        "facebookmessenger": "facebookmessenger",
        "wickr": "wickrpro",
        "wickrpro": "wickrpro",
        "line": "line",
        "whatsapp": "whatsapp",
        "telegram": "telegram",
        "instagram": "instagram",
        "skype": "skype",
        "viber": "viber",
        "snapchat": "snapchat",
        "twitter": "twitter",
        "gmail": "gmail",
        "googlemaps": "googlemaps",
        "googlephotos": "googlephotos",
    }
    return alias_map.get(s, s)


def _platform_match(candidate: str, requested: str) -> bool:
    """Loose platform matcher for deterministic filtering."""
    c = _normalize_platform_name(candidate)
    r = _normalize_platform_name(requested)
    if not c or not r:
        return False
    return c == r or (r in c) or (c in r)


def _derive_record_platform(record: Dict) -> str:
    """Derive platform/app source from raw_data/source fields for contacts/locations."""
    source = None
    raw = record.get("raw_data")
    if raw:
        try:
            obj = json.loads(raw) if isinstance(raw, str) else raw
            if isinstance(obj, dict):
                source = (
                    obj.get("Source")
                    or obj.get("source")
                    or obj.get("App")
                    or obj.get("Application")
                    or obj.get("Service")
                )
        except Exception:
            source = None
    if not source:
        source = record.get("source_table") or record.get("source_db")
    return str(source).strip() if source else "Unknown"


def _extract_requested_limit(query: str) -> int:
    """
    Extract an explicit limit from user query.
    Examples: "show 10 locations", "top 5 calls", "first 20 messages", "limit 15".
    Returns None when no explicit limit is requested.
    """
    q = (query or "").lower()
    patterns = [
        r'\b(?:top|first|last|limit)\s+(\d{1,5})\b',
        r'\b(?:show|list|get|find|fetch|retrieve|display|pull)\s+(\d{1,5})\b',
    ]
    for p in patterns:
        m = re.search(p, q)
        if m:
            try:
                n = int(m.group(1))
                if n > 0:
                    return n
            except Exception:
                pass
    return None


def _extract_platform_hint(query: str) -> str:
    """
    Extract platform/app hint directly from query text for deterministic routing.
    Uses word-boundary-safe matching (avoids 'line' inside 'timeline').
    """
    pl = extract_platforms_ordered(query or "")
    if pl:
        return pl[0]
    q = (query or "")
    localized_platform_aliases = {
        "स्नैपचैट": "snapchat",
        "व्हाट्सएप": "whatsapp",
        "टेलीग्राम": "telegram",
        "इंस्टाग्राम": "instagram",
        "स्काइप": "skype",
        "वाइबर": "viber",
        "लाइन": "line",
        "ट्विटर": "twitter",
        "जीमेल": "gmail",
        "गूगल फोटो": "google photos",
        "गूगल फ़ोटो": "google photos",
        "गूगल मैप्स": "google maps",
    }
    for local_kw, canonical in localized_platform_aliases.items():
        if local_kw in q:
            return canonical
    return None


def _participant_effectively_unknown(val) -> bool:
    """True when chat direction fields are empty or placeholder (parser/DB noise)."""
    if val is None:
        return True
    s = unicodedata.normalize("NFKC", str(val)).strip().lower()
    if not s:
        return True
    return s in frozenset(
        {
            "unknown",
            "n/a",
            "na",
            "none",
            "null",
            "(unknown)",
            "?",
            "unspecified",
        }
    )


def _message_timestamp_weak(m: dict) -> bool:
    ts = str(m.get("timestamp") or "").strip()
    if not ts:
        return True
    if ts.upper() == "N/A":
        return True
    tl = unicodedata.normalize("NFKC", ts).strip().lower()
    return tl in ("unknown", "none", "null", "n/a")


def _is_deterministic_chat_system_membership_noise(m: dict) -> bool:
    """
    Drop join/leave-style rows (LINE/group system lines, bad party resolution).
    """
    if not isinstance(m, dict):
        return False
    text = (m.get("text_content") or "").strip().lower()
    if not text:
        return False
    needles = (
        "joined the chat",
        "left the chat",
        "was added to the chat",
        "was added to the group",
        "was removed from the group",
        "removed from the chat",
        "removed from the group",
    )
    if not any(n in text for n in needles):
        return False
    if _participant_effectively_unknown(m.get("from_participant")) and _participant_effectively_unknown(
        m.get("to_participant")
    ):
        return True
    if _message_timestamp_weak(m):
        return True
    return False


def _dedupe_chat_message_rows(rows: list) -> list:
    """
    Collapse duplicate chat_messages rows (same logical message stored more than once).
    Prefer message_id when present; otherwise signature from timestamp + parties + text.
    """
    if not rows:
        return []
    seen = set()
    out = []
    for m in rows:
        if not isinstance(m, dict):
            continue
        if _is_deterministic_chat_system_membership_noise(m):
            continue
        mid = (str(m.get("message_id") or "")).strip()
        if mid:
            key = ("id", mid)
        else:
            key = (
                "sig",
                str(m.get("timestamp") or ""),
                str(m.get("from_participant") or ""),
                str(m.get("to_participant") or ""),
                (m.get("text_content") or "")[:500],
            )
        if key in seen:
            continue
        seen.add(key)
        out.append(m)
    return out


# Phrases that indicate the user is asking about a specific person's communications (not generic case questions).
_PERSON_INVESTIGATION_PHRASES = (
    'all chats related to', 'list all chats', 'show all chats', 'chats with', 'show chats with',
    'all communications', 'all messages', 'all calls', 'everything about',
    'complete analysis', 'comprehensive analysis', 'detailed analysis',
    'show chats', 'list chats', 'find chats', 'get chats',
    'know more about', 'tell me about', 'information about', 'learn about',
    'details about', 'communications with', 'communication with',
    'messages with', 'messages from', 'messages to', 'interactions with', 'interaction with',
)


def _is_person_investigation_query(query_lower: str) -> bool:
    if not query_lower:
        return False
    if any(phrase in query_lower for phrase in _PERSON_INVESTIGATION_PHRASES):
        return True
    # "who is josh hickman" — require a multi-word lowercase name (not "who is the suspect")
    if re.search(
        r'\bwho\s+is\s+(?!the\s|a\s|an\s|this\s|that\s)([a-z][a-z\']*(?:\s+[a-z][a-z\']*){1,3})\b',
        query_lower,
    ):
        return True
    return False


# Words that are never part of a person's name when they appear at the end of a naive capture
# (e.g. "interactions with josh hickman in 2020" → must not become "Josh Hickman In").
_PERSON_NAME_TRAILING_STOPWORDS = frozenset({
    'in', 'on', 'at', 'for', 'to', 'from', 'during', 'after', 'before', 'between', 'within',
    'the', 'a', 'an', 'and', 'or', 'vs', 'versus', 'with', 'about', 'into', 'by', 'as', 'of',
    'is', 'are', 'was', 'were', 'be', 'been', 'when', 'where', 'which', 'who', 'what', 'how', 'why',
})


def _trim_trailing_stopwords_from_person_name(name: str) -> Union[str, None]:
    """Remove trailing prepositions / junk tokens from extracted person names."""
    if not name:
        return None
    parts = name.strip().split()
    while len(parts) > 1 and parts[-1].lower() in _PERSON_NAME_TRAILING_STOPWORDS:
        parts.pop()
    out = " ".join(parts).strip()
    if not out or (len(parts) == 1 and parts[0].lower() in _PERSON_NAME_TRAILING_STOPWORDS):
        return None
    return out


def _extract_person_name_from_investigation_query(query: str):
    """
    Extract a person name from investigation-style queries.
    Supports lowercase names (e.g. 'know more about josh hickman') — not only Title Case.
    """
    if not query:
        return None
    ql = query.lower().strip()
    q_orig = query.strip()
    person_name = None

    # 1) Phrase-led capture for lowercase multi-word names
    # Stop before " in/on/at ..." + year or date-ish tail so "in 2020" is not part of the name.
    m = re.search(
        r"(?:know\s+more\s+about|tell\s+me\s+about|information\s+about|everything\s+about|"
        r"learn\s+about|details\s+about|communications?\s+with|messages\s+with|"
        r"messages\s+from|messages\s+to|interactions?\s+with)\s+"
        r"([a-z][a-z']*(?:\s+[a-z][a-z']*){0,3})(?=\s+(?:in|on|at|during|from|to|for|between|after|before)\s|\s+\d{4}\b|\s*$)",
        ql,
    )
    if m:
        raw = m.group(1).strip()
        fw = raw.split()[0].lower()
        stop = {
            'the', 'a', 'an', 'this', 'that', 'my', 'your', 'our', 'case', 'device', 'phone',
            'report', 'evidence', 'data', 'here', 'you', 'someone', 'anyone', 'suspect',
        }
        if fw not in stop and len(raw) >= 2:
            person_name = _trim_trailing_stopwords_from_person_name(raw.title()) or raw.title()

    # 1b) "timeline ... with X ..." / "activity with X" (query may start with timeline, not interaction)
    if not person_name:
        m = re.search(
            r"(?:timeline|history|chronolog|sequence|activity)\s+[^\n]{0,40}?\bwith\s+"
            r"([a-z][a-z']*(?:\s+[a-z][a-z']*){0,3})(?=\s+(?:in|on|at|during|from|to|for)\s|\s+\d{4}\b|\s*$)",
            ql,
        )
        if m:
            raw = m.group(1).strip()
            if raw.split()[0].lower() not in {'the', 'a', 'an', 'this', 'that'}:
                person_name = _trim_trailing_stopwords_from_person_name(raw.title()) or raw.title()

    # 2) "who is josh hickman" — require 2+ lowercase words; avoid "who is responsible" / "who is the ..."
    if not person_name:
        m = re.search(r"who\s+is\s+(?!the\s|a\s|an\s)([a-z][a-z']*(?:\s+[a-z][a-z']*){1,3})", ql)
        if m:
            raw = m.group(1).strip()
            if raw.split()[0].lower() not in {'the', 'this', 'that'}:
                person_name = _trim_trailing_stopwords_from_person_name(raw.title()) or raw.title()

    # 3) Title-case patterns on original query
    if not person_name:
        patterns = [
            r'(?:related to|with|about|from|to|for)\s+([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*)',
            r'([A-Z][a-zA-Z]+\s+[A-Z][a-zA-Z]+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, q_orig)
            if match:
                person_name = _trim_trailing_stopwords_from_person_name(match.group(1)) or match.group(1)
                break

    if not person_name:
        words = q_orig.split()
        common_words_lower = {
            'chat', 'chats', 'conversation', 'group', 'thread', 'list', 'all', 'show', 'get', 'find',
            'with', 'from', 'about', 'info', 'the', 'this', 'is', 'dfir', 'related', 'to', 'and', 'or',
            'want', 'know', 'more', 'i', 'me', 'please', 'tell', 'information', 'details', 'learn',
            'timeline', 'interactions', 'interaction', 'chronological', 'sequence', 'history', 'of',
        }
        capitalized = [w for w in words if w and w[0].isupper() and w.lower() not in common_words_lower and len(w) > 2]
        if capitalized:
            person_name = ' '.join(capitalized[-2:]) if len(capitalized) >= 2 else capitalized[-1]
            person_name = _trim_trailing_stopwords_from_person_name(person_name) or person_name

    if not person_name and 'with' in ql:
        parts = q_orig.split('with', 1)
        if len(parts) > 1:
            after_with = parts[1].strip()
            words_after = after_with.split()
            name_words = [w for w in words_after if w and w[0].isupper() and len(w) > 2]
            if name_words:
                person_name = ' '.join(name_words[:2])
                person_name = _trim_trailing_stopwords_from_person_name(person_name) or person_name

    return person_name.strip() if person_name else None


def _is_standalone_investigative_query(query_lower: str) -> bool:
    """
    True when the user is asking a full-case question, not a deictic chat follow-up
    ('this result', 'explain that message'). These must NOT require selecting
    'Analyze this result' when follow-up mode is off.
    """
    if not query_lower:
        return False
    # Comparison / contrast across entities or platforms
    if re.search(r"\bcompare\b", query_lower):
        return True
    if " vs " in query_lower or " versus " in query_lower:
        return True
    # Entity identity (including names like 'This Is DFIR Two')
    if re.match(r"^who\s+is\s+", query_lower):
        if re.match(r"^who\s+is\s+the\s+(device|owner|phone|user|suspect|account)\b", query_lower):
            return False
        return True
    if re.search(r"\bcorrelate\b|\bcross[-\s]?reference\b", query_lower):
        return True
    if _is_person_investigation_query(query_lower):
        return True
    return False


def _log_pipeline_trace(session_id: str, stage: str, payload: dict):
    """Structured debug log for query routing (see PIPELINE key in logs)."""
    try:
        import json as _json
        safe = {k: v for k, v in payload.items() if v is not None}
        logger.info(f"PIPELINE[{str(session_id)[:8]}] {stage}: {_json.dumps(safe, default=str)[:8000]}")
    except Exception as e:
        logger.warning(f"PIPELINE log failed: {e}")


def _merge_followup_platform_context(parsed_intent: dict, followup_mode: bool, followup_base, user_query_original: str):
    """
    Anchor platform from follow-up base when the user query is deictic or names no platform.
    Clears false LINE match caused by the substring 'timeline'.
    """
    q = (user_query_original or "").lower()
    base_txt = ""
    if isinstance(followup_base, dict):
        base_txt = str(followup_base.get("content") or "")
    query_plats = extract_platforms_ordered(user_query_original or "")
    base_plats = extract_platforms_ordered(base_txt) if base_txt else []

    if parsed_intent.get("platform") == "line" and "timeline" in q.replace(" ", ""):
        parsed_intent["platform"] = None
        po = [p for p in (parsed_intent.get("platforms") or []) if p != "line"]
        parsed_intent["platforms"] = po

    deictic = bool(re.search(r"\b(these|those|this|that|above|here)\b", q))
    xref = parsed_intent.get("action") == "cross_reference"
    if followup_mode and base_txt and base_plats:
        if (not query_plats) and (deictic or xref):
            parsed_intent["platform"] = base_plats[0]
            parsed_intent["platforms"] = list(base_plats)
        elif not parsed_intent.get("platform") and base_plats and (deictic or xref):
            parsed_intent["platform"] = base_plats[0]
            merged = list(dict.fromkeys((parsed_intent.get("platforms") or []) + base_plats))
            parsed_intent["platforms"] = merged


def _normalize_contact_overlap_keys(row: dict):
    keys = set()
    ph = re.sub(r"\D+", "", str(row.get("phone") or ""))
    if len(ph) >= 7:
        keys.add(("phone", ph))
    em = (str(row.get("email") or "").strip().lower())
    if em and "@" in em:
        keys.add(("email", em))
    nm = (str(row.get("name") or "").strip().lower())
    if len(nm) >= 2:
        keys.add(("name", nm))
    return keys


def run_contact_platform_intersection(data_layer, platform_a: str, platform_b: str):
    """Deterministic intersection of contacts appearing on two platforms (normalized keys)."""
    conn = data_layer.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM contacts ORDER BY name")
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

    keys_a = {}
    keys_b = {}
    for r in rows:
        plat = _derive_record_platform(r)
        if _platform_match(plat, platform_a):
            for k in _normalize_contact_overlap_keys(r):
                keys_a.setdefault(k, []).append(r)
        if _platform_match(plat, platform_b):
            for k in _normalize_contact_overlap_keys(r):
                keys_b.setdefault(k, []).append(r)

    common = sorted(set(keys_a.keys()) & set(keys_b.keys()), key=lambda x: (x[0], x[1]))
    lines = [
        f"**Contact overlap** · {platform_a} ∩ {platform_b}",
        f"- Matches: {len(common)}",
        "",
    ]
    if not common:
        lines.append("No overlapping contacts for this pair.")
        return {"handled": True, "response": "\n".join(lines), "domain": "contacts", "count": 0}

    for k in common[:200]:
        kt, kv = k
        ra = keys_a[k][0]
        rb = keys_b[k][0]
        lines.append(
            f"- [{kt}] {kv} | A: {ra.get('name') or 'Unknown'} / {ra.get('phone') or 'N/A'} | "
            f"B: {rb.get('name') or 'Unknown'} / {rb.get('phone') or 'N/A'}"
        )
    if len(common) > 200:
        lines.append(f"... ({len(common) - 200} more keys omitted)")
    return {"handled": True, "response": "\n".join(lines), "domain": "contacts", "count": len(common)}


def run_deterministic_timeline_reconstruction(parsed_intent: dict, data_layer, followup_base, user_query_original: str):
    """Merged chronological chat_messages + locations for one day (optionally platform-scoped)."""
    filt = parsed_intent.get("filters") or {}
    dates = list(filt.get("dates") or [])
    if not dates and isinstance(followup_base, dict):
        dates = _extract_dates_from_text(str(followup_base.get("content") or ""))
    if not dates:
        msg = (
            "**Timeline** — add a date (YYYY-MM-DD) in the query or pick a base message that includes a date."
        )
        return {"handled": True, "response": msg, "domain": "timeline", "count": 0, "fallback_reason": "reconstruct_no_date"}

    day = str(dates[0])[:10]
    platform = parsed_intent.get("platform") or _extract_platform_hint(user_query_original or "")
    if not platform and isinstance(followup_base, dict):
        bp = extract_platforms_ordered(str(followup_base.get("content") or ""))
        platform = bp[0] if bp else None
    if not platform:
        msg = "**Timeline** — name the app (e.g. line, whatsapp) in the query or use a base message that shows the platform."
        return {"handled": True, "response": msg, "domain": "timeline", "count": 0, "fallback_reason": "reconstruct_no_platform"}

    domains = list(parsed_intent.get("domains") or [])
    base_txt = str((followup_base or {}).get("content") or "") if isinstance(followup_base, dict) else ""
    btl = base_txt.lower()
    want_chats = any(d in domains for d in ("chats", "messages"))
    want_locs = "locations" in domains
    if not want_chats and not want_locs:
        if "chat" in btl or "message" in btl:
            want_chats = True
        if "location" in btl:
            want_locs = True
    if not want_chats and not want_locs:
        want_chats = True
        want_locs = True

    conn = data_layer.get_connection()
    events: List[dict] = []
    try:
        cur = conn.cursor()
        if want_chats:
            cur.execute(
                "SELECT * FROM chat_messages WHERE substr(COALESCE(timestamp,''),1,10)=? ORDER BY timestamp ASC",
                (day,),
            )
            for r in cur.fetchall():
                row = dict(r)
                if not _platform_match(_derive_record_platform(row), platform):
                    continue
                ts = str(row.get("timestamp") or "N/A")
                fp = row.get("from_participant") or "Unknown"
                tp = row.get("to_participant") or "Unknown"
                txt = (row.get("text_content") or "")[:200]
                events.append(
                    {
                        "kind": "chat",
                        "timestamp": ts,
                        "from_participant": fp,
                        "to_participant": tp,
                        "text_content": txt,
                    }
                )

        if want_locs:
            cur.execute(
                "SELECT * FROM locations WHERE substr(COALESCE(timestamp,''),1,10)=? ORDER BY timestamp ASC",
                (day,),
            )
            for r in cur.fetchall():
                row = dict(r)
                if not _platform_match(_derive_record_platform(row), platform):
                    continue
                ts = str(row.get("timestamp") or "N/A")
                lat = row.get("latitude")
                lon = row.get("longitude")
                events.append(
                    {
                        "kind": "location",
                        "timestamp": ts,
                        "latitude": lat,
                        "longitude": lon,
                    }
                )
    finally:
        conn.close()

    events.sort(key=lambda x: str(x.get("timestamp") or ""))
    if not events:
        msg = (
            f"**Timeline** · {day} · {platform} — no events match (check date and app name)."
        )
        return {"handled": True, "response": msg, "domain": "timeline", "count": 0, "fallback_reason": "reconstruct_no_rows"}

    # All matching rows are loaded from SQLite (no SQL LIMIT). Optional display cap for huge days.
    _DISPLAY_MAX_LINES = 100000
    shown_events = events[:_DISPLAY_MAX_LINES]
    truncated = len(events) > _DISPLAY_MAX_LINES
    response = format_timeline_investigator(
        day=day,
        platform=platform,
        timeline_events=shown_events,
        total_events=len(events),
        want_chats=want_chats,
        want_locs=want_locs,
        truncated=truncated,
        display_max=_DISPLAY_MAX_LINES,
    )
    return {"handled": True, "response": response, "domain": "timeline", "count": len(events)}


def _normalize_multilingual_query_for_retrieval(query: str) -> str:
    """
    Convert common multilingual forensic command terms into canonical English tokens
    for deterministic/classification/data lookup, while preserving the original user
    query for LLM response language and UI display.
    """
    q = (query or "").strip()
    if not q:
        return q

    replacements = {
        # Hindi command verbs
        "प्राप्त करें": "retrieve",
        "प्राप्त": "retrieve",
        "दिखाएं": "show",
        "दिखाओ": "show",
        "निकालें": "pull",
        "निकालो": "pull",
        "खोजें": "find",
        "खोज": "find",
        "ढूंढें": "find",
        "ढूंढ": "find",
        "ढूँढें": "find",
        "ढूँढ": "find",
        "कितने": "count",
        "गिनती": "count",

        # Hindi forensic nouns/domains
        "लोकेशन": "locations",
        "स्थान": "locations",
        "संदेश": "messages",
        "मैसेज": "messages",
        "चैट": "chat",
        "कॉल लॉग": "call logs",
        "कॉल": "calls",
        "संपर्क": "contacts",
        "फोटो": "photos",
        "चित्र": "images",
        "वीडियो": "videos",
        "मीडिया": "media",

        # Hindi platform names
        "स्नैपचैट": "snapchat",
        "व्हाट्सएप": "whatsapp",
        "टेलीग्राम": "telegram",
        "इंस्टाग्राम": "instagram",
        "स्काइप": "skype",
        "वाइबर": "viber",
        "लाइन": "line",
        "ट्विटर": "twitter",
        "जीमेल": "gmail",
        "गूगल फोटो": "google photos",
        "गूगल फ़ोटो": "google photos",
        "गूगल मैप्स": "google maps",
    }

    q_norm = q
    for src, tgt in replacements.items():
        q_norm = q_norm.replace(src, tgt)

    return q_norm


def _extract_dates_from_text(text: str):
    """Extract ISO-like YYYY-MM-DD dates from free text."""
    if not text:
        return []
    dates = re.findall(r'\b(\d{4}-\d{2}-\d{2})\b', str(text))
    # preserve order, unique
    seen = set()
    out = []
    for d in dates:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _merge_iso_date_filters(intent_filters, *extra_texts: str):
    """
    Merge parser filters['dates'] with any ISO dates found in query strings.
    Order: intent dates first, then first occurrence in extra_texts.
    """
    out = []
    seen = set()
    for d in (intent_filters or {}).get("dates") or []:
        if not d:
            continue
        ds = str(d)[:10]
        if re.match(r"^\d{4}-\d{2}-\d{2}$", ds) and ds not in seen:
            seen.add(ds)
            out.append(ds)
    for t in extra_texts:
        for d in _extract_dates_from_text(t or ""):
            if d not in seen:
                seen.add(d)
                out.append(d)
    return out


def _sanitized_iso_date_filters(date_filters) -> list:
    """Keep only strict YYYY-MM-DD entries (defense in depth for SQL IN clauses)."""
    if not date_filters:
        return []
    out = []
    seen = set()
    for d in date_filters:
        ds = str(d)[:10] if d is not None else ""
        if re.match(r"^\d{4}-\d{2}-\d{2}$", ds) and ds not in seen:
            seen.add(ds)
            out.append(ds)
    return out


def _wants_combined_calls_and_chats_query(q: str) -> bool:
    """
    True when the user explicitly asks for *both* calls and messages/chats in one question.

    Prevents false positives such as "calls in the chat app" or "call log for this chat"
    where both token types appear but the user only wants one domain.
    """
    ql = (q or "").strip().lower()
    if not ql:
        return False
    # Coordinators between the two halves (allow comma, slash, ampersand, conjunctions)
    coord = r"(?:[,;/]|&|\+|\band\b|\bor\b|\bas\s+well\s+as\b|\balong\s+with\b|\bplus\b|\bwith\b)"
    callish = r"(?:calls?|call\s+logs?|phone\s+calls?|incoming\s+calls?|outgoing\s+calls?|dialed)"
    msgish = r"(?:chats?|conversations?|threads?|messages?|sms|mms|texts?)"
    mid = r".{0,240}?"
    flags = re.DOTALL | re.IGNORECASE
    pat_forward = rf"\b{callish}\b{mid}{coord}{mid}\b{msgish}\b"
    pat_reverse = rf"\b{msgish}\b{mid}{coord}{mid}\b{callish}\b"
    return bool(re.search(pat_forward, ql, flags) or re.search(pat_reverse, ql, flags))


def _call_row_matches_date_filters(row: dict, date_filters: list) -> bool:
    if not date_filters:
        return True
    ts = str(row.get("timestamp") or "")
    if len(ts) < 10:
        return False
    return ts[:10] in set(date_filters)


def _query_has_temporal_range_keywords(query: str) -> bool:
    """True if user asked after / before / between (calendar semantics, not just 'on date')."""
    ql = (query or "").lower()
    return bool(re.search(r"\b(after|before|between)\b", ql))


def _temporal_scope_note(query: str, date_filters: list) -> str:
    """Compact date scope suffix for headers."""
    ql = (query or "").lower()
    dates = _sanitized_iso_date_filters(date_filters)
    if not dates:
        return ""
    if re.search(r"\bbetween\b", ql) and len(dates) >= 2:
        lo, hi = sorted(dates)[0], sorted(dates)[-1]
        return f" · {lo}–{hi}"
    if re.search(r"\bafter\b", ql):
        return f" · after {dates[0]}"
    if re.search(r"\bbefore\b", ql):
        return f" · before {dates[-1]}"
    if len(dates) == 1:
        return f" · {dates[0]}"
    return f" · {', '.join(dates)}"


def _temporal_filter_timestamp_rows(query: str, rows: list, date_filters: list) -> list:
    """
    Filter row dicts with ISO-like 'timestamp' using query wording:
    - between: min..max of extracted YYYY-MM-DD inclusive
    - after: calendar day strictly after reference date
    - before: calendar day strictly before reference date
    - else: exact day IN date_filters
    """
    if not rows:
        return rows
    ql = (query or "").lower()
    dates = sorted(_sanitized_iso_date_filters(date_filters)) if date_filters else []

    def dpart(row):
        ts = str(row.get("timestamp") or "")
        return ts[:10] if len(ts) >= 10 else ""

    if re.search(r"\bbetween\b", ql) and len(dates) >= 2:
        lo, hi = dates[0], dates[-1]
        return [r for r in rows if dpart(r) and lo <= dpart(r) <= hi]
    if re.search(r"\bafter\b", ql) and dates:
        ref = dates[0]
        return [r for r in rows if dpart(r) and dpart(r) > ref]
    if re.search(r"\bbefore\b", ql) and dates:
        ref = dates[-1]
        return [r for r in rows if dpart(r) and dpart(r) < ref]
    if dates:
        ds = set(dates)
        return [r for r in rows if dpart(r) in ds]
    return rows


def _filtered_call_log_rows(data_layer, query: str, date_filters: list, platform_hint, display_limit: int):
    """
    Load call_logs rows with optional platform + date scope.
    SQL day-IN for simple calendar-day match; in-memory temporal rules for after/before/between.
    Returns (filtered_rows, table_total).
    """
    table_total = _count_rows(data_layer, "call_logs")
    temporal = bool(date_filters) and _query_has_temporal_range_keywords(query)
    filtered = []
    conn = data_layer.get_connection()
    try:
        cur = conn.cursor()
        if date_filters and not temporal:
            placeholders = ",".join(["?"] * len(date_filters))
            cur.execute(
                f"SELECT * FROM call_logs WHERE substr(COALESCE(timestamp,''),1,10) IN ({placeholders}) "
                f"ORDER BY timestamp DESC",
                tuple(date_filters),
            )
            filtered = [dict(r) for r in cur.fetchall()]
            if platform_hint:
                filtered = [r for r in filtered if _platform_match(_derive_record_platform(r), platform_hint)]
        else:
            if platform_hint:
                cur.execute("SELECT * FROM call_logs ORDER BY timestamp DESC")
                filtered = [dict(r) for r in cur.fetchall()]
                filtered = [r for r in filtered if _platform_match(_derive_record_platform(r), platform_hint)]
            else:
                cur.execute(
                    "SELECT * FROM call_logs ORDER BY timestamp DESC LIMIT ?",
                    (min(max(display_limit * 50, 5000), 100000),),
                )
                filtered = [dict(r) for r in cur.fetchall()]
            if date_filters:
                filtered = _temporal_filter_timestamp_rows(query, filtered, date_filters)
    finally:
        conn.close()
    return filtered, table_total


def _build_location_cross_reference_response(data_layer, base_content: str, limit_dates: int = 12) -> str:
    """
    Deterministically cross-reference location dates from follow-up base content
    with call logs and messages/chat_messages.
    """
    dates = _extract_dates_from_text(base_content or "")
    # Fallback: if base text parsing misses dates (format/encoding differences),
    # derive dates from platform-scoped locations in DB using source hints.
    if not dates:
        platform_hint = _extract_platform_hint(base_content or "")
        if platform_hint:
            conn = data_layer.get_connection()
            try:
                cur = conn.cursor()
                cur.execute("SELECT timestamp, source_db, source_table, raw_data FROM locations")
                all_rows = [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()
            scoped_dates = []
            for r in all_rows:
                if _platform_match(_derive_record_platform(r), platform_hint):
                    ts = str(r.get("timestamp") or "")
                    if len(ts) >= 10:
                        d = ts[:10]
                        if re.match(r'^\d{4}-\d{2}-\d{2}$', d):
                            scoped_dates.append(d)
            # unique preserving order
            seen = set()
            dates = []
            for d in scoped_dates:
                if d not in seen:
                    seen.add(d)
                    dates.append(d)

    if not dates:
        return "**Cross-reference** — no dated locations in the selected base. Pull locations with timestamps first."

    dates = dates[:limit_dates]
    conn = data_layer.get_connection()
    try:
        cur = conn.cursor()
        lines = []
        lines.append("# Cross-reference")
        lines.append(f"- Location dates in base: {len(dates)}")
        lines.append(f"- Date range sampled: {dates[-1]} to {dates[0] if dates else 'N/A'}")

        total_calls = 0
        total_sms = 0
        total_chat_msgs = 0
        matched_days = 0
        day_rows = []
        top_overlap_days = []

        for d in dates:
            cur.execute("SELECT COUNT(*) AS c FROM call_logs WHERE substr(COALESCE(timestamp,''),1,10)=?", (d,))
            calls_c = int(cur.fetchone()["c"] or 0)

            cur.execute("SELECT COUNT(*) AS c FROM messages WHERE substr(COALESCE(timestamp,''),1,10)=?", (d,))
            sms_c = int(cur.fetchone()["c"] or 0)

            cur.execute("SELECT COUNT(*) AS c FROM chat_messages WHERE substr(COALESCE(timestamp,''),1,10)=?", (d,))
            chat_c = int(cur.fetchone()["c"] or 0)

            total_calls += calls_c
            total_sms += sms_c
            total_chat_msgs += chat_c
            day_total = calls_c + sms_c + chat_c
            if (calls_c + sms_c + chat_c) > 0:
                matched_days += 1

            if day_total > 0:
                lines.append(f"- {d}: calls={calls_c}, sms/messages={sms_c}, chat_messages={chat_c}")
                top_overlap_days.append((d, day_total))
            day_rows.append((d, calls_c, sms_c, chat_c, day_total))

        top_overlap_days.sort(key=lambda x: x[1], reverse=True)

        lines.append("")
        lines.append("Evidence Basis:")
        lines.append(f"- Communication overlap detected on {matched_days}/{len(dates)} location date(s).")
        lines.append(f"- Totals on matched date set: calls={total_calls}, sms/messages={total_sms}, chat_messages={total_chat_msgs}.")
        if top_overlap_days:
            lines.append(f"- Highest overlap day: {top_overlap_days[0][0]} ({top_overlap_days[0][1]} total communication events).")

        # Top entities across overlapping days
        overlap_dates = [d for d, _, _, _, t in day_rows if t > 0]
        if overlap_dates:
            placeholders = ",".join(["?"] * len(overlap_dates))
            try:
                cur.execute(
                    f"""
                    SELECT COALESCE(from_number,'Unknown') AS entity, COUNT(*) AS c
                    FROM call_logs
                    WHERE substr(COALESCE(timestamp,''),1,10) IN ({placeholders})
                    GROUP BY COALESCE(from_number,'Unknown')
                    ORDER BY c DESC
                    LIMIT 3
                    """,
                    tuple(overlap_dates),
                )
                top_call_entities = [dict(r) for r in cur.fetchall()]
            except Exception:
                top_call_entities = []

            try:
                cur.execute(
                    f"""
                    SELECT COALESCE(from_participant,'Unknown') AS entity, COUNT(*) AS c
                    FROM chat_messages
                    WHERE substr(COALESCE(timestamp,''),1,10) IN ({placeholders})
                    GROUP BY COALESCE(from_participant,'Unknown')
                    ORDER BY c DESC
                    LIMIT 3
                    """,
                    tuple(overlap_dates),
                )
                top_msg_entities = [dict(r) for r in cur.fetchall()]
            except Exception:
                top_msg_entities = []

            if top_call_entities or top_msg_entities:
                lines.append("- Top communicating entities on overlap days:")
                for r in top_call_entities:
                    lines.append(f"  - Calls: {r.get('entity') or 'Unknown'} ({r.get('c') or 0})")
                for r in top_msg_entities:
                    lines.append(f"  - Messages: {r.get('entity') or 'Unknown'} ({r.get('c') or 0})")

        lines.append("")
        lines.append("Interpretation:")
        if matched_days == 0:
            lines.append("- No same-day communication overlap was found for the sampled location dates.")
        else:
            lines.append("- Same-day overlap between location activity and communications is present, indicating potential temporal coordination windows.")
            if matched_days >= max(2, len(dates) // 2):
                lines.append("- Overlap occurs on multiple location days, suggesting repeated communication around movement events.")
            # Risk-oriented indicators
            lines.append("- Overlap strength is highest on specific days; prioritize those days for timeline reconstruction and sequence analysis.")

        lines.append("")
        lines.append("Priority Checks:")
        if top_overlap_days:
            top_days = [d for d, _ in top_overlap_days[:3]]
            lines.append(f"- Reconstruct event sequence on top overlap day(s): {', '.join(top_days)}.")
        else:
            lines.append("- Pull broader date range locations to increase overlap coverage.")
        lines.append("- Correlate contact identities appearing in calls and chat messages on overlap dates.")
        lines.append("- Verify whether repeated entities coincide with movement clusters (same area + same day).")

        lines.append("")
        lines.append("Suggested Next Query:")
        if top_overlap_days:
            lines.append(f"- show calls and messages on {top_overlap_days[0][0]} to inspect exact sequence around location events")
        else:
            lines.append("- show calls and messages on <specific date> to inspect exact sequence around location events")

        return "\n".join(lines)
    finally:
        conn.close()


def _detect_domains_in_text(text: str):
    """Detect requested forensic domains from free text."""
    t = (text or "").lower()
    domains = []
    if any(k in t for k in ["location", "locations", "gps", "coordinate"]):
        domains.append("locations")
    if any(k in t for k in ["call", "calls", "call log", "voip"]):
        domains.append("calls")
    if any(k in t for k in ["message", "messages", "chat", "chats", "sms"]):
        domains.append("messages")
    if any(k in t for k in ["contact", "contacts", "person", "participant"]):
        domains.append("contacts")
    if any(k in t for k in ["media", "image", "images", "photo", "photos", "video", "videos", "attachment"]):
        domains.append("media")
    # preserve order/unique
    out = []
    seen = set()
    for d in domains:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _is_cross_reference_intent(text: str) -> bool:
    """
    Broad intent detector for cross-domain correlation requests.
    Supports varied phrasing, not just explicit 'cross-reference'.
    """
    t = (text or "").lower()
    if not t:
        return False
    t = t.replace("‑", "-").replace("–", "-").replace("—", "-")

    # Direct correlation phrases
    direct_signals = [
        "cross-reference", "cross reference", "crossref", "correlate", "correlation",
        "relate", "relationship", "link", "linked", "connect", "connected",
        "compare", "match up", "map against", "align with", "tie with",
        "coordination", "coordinated", "associated with", "related to",
        "pattern across", "across domains", "other domain", "other domains"
    ]
    if any(s in t for s in direct_signals):
        return True

    # Implicit phrasing: if user asks for insight plus mention of multiple domains
    analysis_signals = ["analyze", "analysis", "insight", "findings", "suspicious", "unusual", "pattern"]
    mentioned_domains = _detect_domains_in_text(t)
    if len(mentioned_domains) >= 2 and any(s in t for s in analysis_signals):
        return True

    # Handle compact requests like "check with calls/messages"
    if ("with call" in t or "with calls" in t or "with message" in t or "with messages" in t) and (
        "check" in t or "verify" in t or "see if" in t or "look for" in t or "find" in t
    ):
        return True

    return False


def _detect_base_domain_from_content(base_content: str):
    """Best-effort domain detection from selected follow-up base content."""
    domains = _detect_domains_in_text(base_content or "")
    if not domains:
        return None
    # prioritize strongest deterministic domain hints
    for d in ["locations", "calls", "messages", "contacts", "media"]:
        if d in domains:
            return d
    return domains[0]


def _build_cross_reference_response(data_layer, base_content: str, query_text: str) -> str:
    """
    Generic deterministic cross-reference entry point across all core domains.
    Currently strongest implementation is date-based timeline correlation
    and location-led overlap with communications.
    """
    base_domain = _detect_base_domain_from_content(base_content or "")
    requested_domains = _detect_domains_in_text(query_text or "")

    # Location-led cross-reference uses richer deterministic logic.
    if base_domain == "locations":
        return _build_location_cross_reference_response(data_layer, base_content)

    # Generic date-overlap cross-reference for other base domains.
    dates = _extract_dates_from_text(base_content or "")
    if not dates:
        return "**Cross-reference** — pick a base message that includes at least one date (YYYY-MM-DD)."

    dates = dates[:12]
    conn = data_layer.get_connection()
    try:
        cur = conn.cursor()
        lines = []
        lines.append("# Cross-reference")
        lines.append(f"- Base domain: {base_domain or 'unknown'}")
        lines.append(f"- Dates analyzed: {len(dates)}")

        # Always compute communications + movement overlap baseline
        totals = {"calls": 0, "messages": 0, "chat_messages": 0, "locations": 0}
        overlap_days = []
        for d in dates:
            cur.execute("SELECT COUNT(*) AS c FROM call_logs WHERE substr(COALESCE(timestamp,''),1,10)=?", (d,))
            c_calls = int(cur.fetchone()["c"] or 0)
            cur.execute("SELECT COUNT(*) AS c FROM messages WHERE substr(COALESCE(timestamp,''),1,10)=?", (d,))
            c_msg = int(cur.fetchone()["c"] or 0)
            cur.execute("SELECT COUNT(*) AS c FROM chat_messages WHERE substr(COALESCE(timestamp,''),1,10)=?", (d,))
            c_chat = int(cur.fetchone()["c"] or 0)
            cur.execute("SELECT COUNT(*) AS c FROM locations WHERE substr(COALESCE(timestamp,''),1,10)=?", (d,))
            c_loc = int(cur.fetchone()["c"] or 0)

            totals["calls"] += c_calls
            totals["messages"] += c_msg
            totals["chat_messages"] += c_chat
            totals["locations"] += c_loc
            day_total = c_calls + c_msg + c_chat + c_loc
            if day_total > 0:
                overlap_days.append((d, c_calls, c_msg, c_chat, c_loc, day_total))

        overlap_days.sort(key=lambda x: x[5], reverse=True)

        lines.append("")
        lines.append("Evidence Basis:")
        lines.append(f"- Overlap days with activity: {len(overlap_days)}/{len(dates)}.")
        lines.append(
            f"- Aggregate counts on analyzed dates: calls={totals['calls']}, "
            f"sms/messages={totals['messages']}, chat_messages={totals['chat_messages']}, locations={totals['locations']}."
        )
        if overlap_days:
            lines.append(f"- Top overlap day: {overlap_days[0][0]} (events={overlap_days[0][5]}).")
            lines.append("Top overlap day details:")
            d, c_calls, c_msg, c_chat, c_loc, _ = overlap_days[0]
            lines.append(f"- {d}: calls={c_calls}, sms/messages={c_msg}, chat_messages={c_chat}, locations={c_loc}")

        lines.append("")
        lines.append("Interpretation:")
        if not overlap_days:
            lines.append("- No temporal cross-domain overlap was found on the sampled dates.")
        else:
            lines.append("- Multi-domain activity occurs on shared dates, which supports timeline-level coordination analysis.")
            if overlap_days[0][5] >= 5:
                lines.append("- Peak overlap day contains dense mixed activity and should be prioritized for sequence reconstruction.")

        lines.append("")
        lines.append("Priority Checks:")
        if overlap_days:
            lines.append(f"- Reconstruct event sequence on {overlap_days[0][0]} across requested domains.")
        lines.append("- Verify repeated entities/numbers on overlap dates to identify persistent counterparts.")
        lines.append("- Compare day-level patterns (weekday/time windows) for recurring coordination windows.")

        lines.append("")
        lines.append("Suggested Next Query:")
        if overlap_days:
            lines.append(f"- show calls and messages on {overlap_days[0][0]} with exact timestamps")
        else:
            lines.append("- show calls and messages on <specific date> with exact timestamps")

        return "\n".join(lines)
    finally:
        conn.close()


def _correlation_ts_key(ts: Optional[str]) -> str:
    """Normalize timestamps so chat/location/call rows can be paired."""
    if not ts:
        return ""
    m = re.search(
        r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)",
        str(ts).replace("Z", "+00:00"),
    )
    if m:
        return m.group(1).replace(" ", "T")
    return ""


def _build_correlation_evidence_lines(
    events_by_domain: dict,
    domains: list,
    result: dict,
    limit_pairs: int = 30,
) -> dict:
    """
    Only rows that support the correlation: same normalized timestamp across domains
    on overlap calendar days (no unrelated chat/location dumps).
    """
    from collections import defaultdict

    paired: List[str] = []
    evidence = result.get("evidence") or []

    def _overlap_dates(block_type: str) -> set:
        blk = next((b for b in evidence if b.get("type") == block_type), None)
        top = (blk or {}).get("top_dates") or []
        return {str(r.get("date"))[:10] for r in top if r.get("date")}

    # Locations ↔ chats (same instant)
    if "locations" in domains and ("chats" in domains or "messages" in domains):
        days = _overlap_dates("locations_chats_same_date")
        loc_evs = [
            e
            for e in (events_by_domain.get("locations") or [])
            if (e.get("date_key") or "")[:10] in days
        ]
        chat_evs = [
            e
            for e in (events_by_domain.get("chats") or [])
            if (e.get("date_key") or "")[:10] in days
        ]
        by_l = defaultdict(list)
        by_c = defaultdict(list)
        for e in loc_evs:
            k = _correlation_ts_key(e.get("timestamp"))
            if k:
                by_l[k].append(e)
        for e in chat_evs:
            k = _correlation_ts_key(e.get("timestamp"))
            if k:
                by_c[k].append(e)
        for k in sorted(set(by_l.keys()) & set(by_c.keys()))[:limit_pairs]:
            le, ce = by_l[k][0], by_c[k][0]
            ts = le.get("timestamp") or ce.get("timestamp") or ""
            paired.append(
                f"[{ts}] lat={le.get('location_lat')} lon={le.get('location_lon')}"
            )
            body = (ce.get("message_text") or "").strip().replace("\n", " ")[:200]
            paired.append(
                f"[{ts}] {ce.get('contact_label', '?')} → {ce.get('counterparty_label', '?')} | {body or '[no text]'}"
            )

    # Calls ↔ chats (same instant)
    elif "calls" in domains and ("chats" in domains or "messages" in domains):
        days = _overlap_dates("calls_chats_same_date")
        call_evs = [
            e
            for e in (events_by_domain.get("calls") or [])
            if (e.get("date_key") or "")[:10] in days
        ]
        chat_evs = [
            e
            for e in (events_by_domain.get("chats") or [])
            if (e.get("date_key") or "")[:10] in days
        ]
        by_a = defaultdict(list)
        by_b = defaultdict(list)
        for e in call_evs:
            k = _correlation_ts_key(e.get("timestamp"))
            if k:
                by_a[k].append(e)
        for e in chat_evs:
            k = _correlation_ts_key(e.get("timestamp"))
            if k:
                by_b[k].append(e)
        for k in sorted(set(by_a.keys()) & set(by_b.keys()))[:limit_pairs]:
            ce, te = by_a[k][0], by_b[k][0]
            ts = ce.get("timestamp") or te.get("timestamp") or ""
            paired.append(
                f"[{ts}] {ce.get('contact_label', '?')} → {ce.get('counterparty_label', '?')} | call"
            )
            body = (te.get("message_text") or "").strip().replace("\n", " ")[:200]
            paired.append(
                f"[{ts}] {te.get('contact_label', '?')} → {te.get('counterparty_label', '?')} | {body or '[no text]'}"
            )

    # Locations ↔ calls
    elif "locations" in domains and "calls" in domains:
        days = _overlap_dates("locations_calls_same_date")
        loc_evs = [
            e
            for e in (events_by_domain.get("locations") or [])
            if (e.get("date_key") or "")[:10] in days
        ]
        call_evs = [
            e
            for e in (events_by_domain.get("calls") or [])
            if (e.get("date_key") or "")[:10] in days
        ]
        by_l = defaultdict(list)
        by_p = defaultdict(list)
        for e in loc_evs:
            k = _correlation_ts_key(e.get("timestamp"))
            if k:
                by_l[k].append(e)
        for e in call_evs:
            k = _correlation_ts_key(e.get("timestamp"))
            if k:
                by_p[k].append(e)
        for k in sorted(set(by_l.keys()) & set(by_p.keys()))[:limit_pairs]:
            le, ce = by_l[k][0], by_p[k][0]
            ts = le.get("timestamp") or ce.get("timestamp") or ""
            paired.append(
                f"[{ts}] lat={le.get('location_lat')} lon={le.get('location_lon')}"
            )
            paired.append(
                f"[{ts}] {ce.get('contact_label', '?')} → {ce.get('counterparty_label', '?')} | {ce.get('direction', '')}"
            )

    return {"paired_analysis": paired}


def _format_correlation_result_text(result: dict) -> str:
    """Investigator layout via utils.investigator_deterministic_format."""
    return format_correlation_report(result)


def _run_same_domain_cross_platform_correlation(plan: dict, data_layer):
    """
    Deterministic same-domain cross-platform comparison.
    Example: "co-relate WhatsApp messages with LINE messages".
    """
    filters = plan.get("filters") or {}
    domains = list(plan.get("domains") or [])
    platforms = [p for p in (filters.get("platforms") or []) if p]
    if len(domains) != 1 or len(platforms) < 2:
        return None

    domain = domains[0]
    p1, p2 = str(platforms[0]), str(platforms[1])
    date_filter = filters.get("date")
    if not date_filter:
        ds = filters.get("dates") or []
        if ds:
            date_filter = str(ds[0])[:10]

    conn = data_layer.get_connection()
    try:
        cur = conn.cursor()

        def _rows_for_platform(table: str, platform_name: str):
            cur.execute(f"SELECT * FROM {table} ORDER BY timestamp DESC")
            rows = [dict(r) for r in cur.fetchall()]
            rows = [r for r in rows if _platform_match(_derive_record_platform(r), platform_name)]
            if date_filter:
                rows = [r for r in rows if str(r.get("timestamp") or "")[:10] == str(date_filter)[:10]]
            return rows

        if domain in ("messages", "chats"):
            table = "chat_messages"
            r1 = _rows_for_platform(table, p1)
            r2 = _rows_for_platform(table, p2)
            # Deduplicate to avoid inflated same-platform counts.
            r1 = _dedupe_chat_message_rows(r1)
            r2 = _dedupe_chat_message_rows(r2)

            d1 = {str(r.get("timestamp") or "")[:10] for r in r1 if r.get("timestamp")}
            d2 = {str(r.get("timestamp") or "")[:10] for r in r2 if r.get("timestamp")}
            overlap_days = sorted(d1 & d2)

            lines = []
            lines.append("# Correlation")
            scope_note = f" on {date_filter}" if date_filter else ""
            lines.append("")
            lines.append(
                f"Summary. {domain} comparison ({p1} vs {p2}){scope_note} — {len(r1)} record(s) vs {len(r2)} record(s)"
            )
            lines.append("")
            lines.append("Counts")
            lines.append(f"- {p1}: {len(r1)} record(s)")
            lines.append(f"- {p2}: {len(r2)} record(s)")
            if overlap_days:
                lines.append(f"- Same-day overlap: {', '.join(overlap_days[:8])}")
            else:
                lines.append("- Same-day overlap: none")

            lines.append("")
            lines.append(f"Records ({p1} sample)")
            for row in r1[:5]:
                txt = (row.get("text_content") or "").strip()
                if len(txt) > 120:
                    txt = txt[:117] + "..."
                lines.append(
                    f"- [{row.get('timestamp') or 'N/A'}] {row.get('from_participant') or 'Unknown'} -> "
                    f"{row.get('to_participant') or 'Unknown'}: {txt or '[No text]'}"
                )

            lines.append("")
            lines.append(f"Records ({p2} sample)")
            for row in r2[:5]:
                txt = (row.get("text_content") or "").strip()
                if len(txt) > 120:
                    txt = txt[:117] + "..."
                lines.append(
                    f"- [{row.get('timestamp') or 'N/A'}] {row.get('from_participant') or 'Unknown'} -> "
                    f"{row.get('to_participant') or 'Unknown'}: {txt or '[No text]'}"
                )

            return "\n".join(lines)

        return None
    finally:
        conn.close()


def _run_planned_deterministic_correlation(plan: dict, data_layer) -> str:
    """Execute minimal v1 deterministic correlation plan."""
    same_domain_text = _run_same_domain_cross_platform_correlation(plan, data_layer)
    if same_domain_text:
        return same_domain_text

    conn = data_layer.get_connection()
    try:
        cur = conn.cursor()
        domains = plan.get("domains") or []
        filters = plan.get("filters") or {}
        date_filter = filters.get("date")
        if not date_filter:
            ds = filters.get("dates") or []
            if ds:
                date_filter = str(ds[0])[:10]
        platform_filter = filters.get("platform")

        events_by_domain = {}
        platform_filter_applied = False

        if "calls" in domains:
            if platform_filter:
                platform_filter_applied = True
                cur.execute("SELECT * FROM call_logs ORDER BY timestamp DESC")
                rows = [dict(r) for r in cur.fetchall()]
                rows = [r for r in rows if _platform_match(_derive_record_platform(r), platform_filter if isinstance(platform_filter, str) else (platform_filter[0] if platform_filter else ""))]
            else:
                cur.execute("SELECT * FROM call_logs ORDER BY timestamp DESC")
                rows = [dict(r) for r in cur.fetchall()]
            events_by_domain["calls"] = normalize_calls(rows)

        if "chats" in domains or "messages" in domains:
            if platform_filter:
                platform_filter_applied = True
                pf = platform_filter if isinstance(platform_filter, str) else (platform_filter[0] if platform_filter else None)
                if pf:
                    # Do in-memory matching for robust alias/platform variants.
                    cur.execute("SELECT * FROM chat_messages ORDER BY timestamp DESC")
                    rows = [dict(r) for r in cur.fetchall()]
                    rows = [r for r in rows if _platform_match(_derive_record_platform(r), pf)]
                else:
                    cur.execute("SELECT * FROM chat_messages ORDER BY timestamp DESC")
                    rows = [dict(r) for r in cur.fetchall()]
            else:
                cur.execute("SELECT * FROM chat_messages ORDER BY timestamp DESC")
                rows = [dict(r) for r in cur.fetchall()]
            events_by_domain["chats"] = normalize_chat_messages(rows)

        if "locations" in domains:
            cur.execute("SELECT * FROM locations ORDER BY timestamp DESC")
            rows = [dict(r) for r in cur.fetchall()]
            if platform_filter:
                platform_filter_applied = True
                pf = platform_filter if isinstance(platform_filter, str) else (platform_filter[0] if platform_filter else None)
                if pf:
                    rows = [r for r in rows if _platform_match(_derive_record_platform(r), pf)]
            events_by_domain["locations"] = normalize_locations(rows)

        if "contacts" in domains:
            cur.execute("SELECT * FROM contacts ORDER BY name")
            rows = [dict(r) for r in cur.fetchall()]
            if platform_filter:
                platform_filter_applied = True
                pf = platform_filter if isinstance(platform_filter, str) else (platform_filter[0] if platform_filter else None)
                if pf:
                    rows = [r for r in rows if _platform_match(_derive_record_platform(r), pf)]
            events_by_domain["contacts"] = normalize_contacts(rows)

        # Apply optional date filter
        if date_filter:
            for d in list(events_by_domain.keys()):
                events_by_domain[d] = [e for e in events_by_domain[d] if (e.get("date_key") == str(date_filter)[:10])]

        result = build_v1_correlation_result(plan, events_by_domain)
        domain_event_counts = {d: len(evts or []) for d, evts in events_by_domain.items()}
        chat_thread_counts = {}
        if "chats" in events_by_domain:
            conv_ids = set()
            for e in (events_by_domain.get("chats") or []):
                cid = (e.get("conversation_id") or e.get("thread_id") or "").strip()
                if cid:
                    conv_ids.add(cid)
            chat_thread_counts["chats"] = len(conv_ids)
        query_constraint_match = True
        if platform_filter and domain_event_counts:
            # If user requested platform and every requested domain is empty after filters,
            # mark as mismatch so output is explicit/auditable.
            query_constraint_match = any(v > 0 for v in domain_event_counts.values())
        evidence_samples = _build_correlation_evidence_lines(events_by_domain, domains, result)
        result["meta"] = {
            "requested_platform": platform_filter if isinstance(platform_filter, str) else (platform_filter[0] if platform_filter else None),
            "platform_filter_applied": platform_filter_applied,
            "domain_event_counts": domain_event_counts,
            "chat_thread_counts": chat_thread_counts,
            "query_constraint_match": query_constraint_match,
            "effective_date_filter": date_filter,
            "evidence_samples": evidence_samples,
        }
        return _format_correlation_result_text(result)
    finally:
        conn.close()


def run_basic_deterministic_retrieval(
    query: str,
    platform: str = None,
    limit: int = 20,
    intent_filters: dict = None,
    user_query_for_dates: str = None,
):
    """
    Super-basic deterministic retrieval for the 5 core domains.
    Returns dict with response text and metadata, or None if not applicable.

    intent_filters: optional dict from parse_query_intent (e.g. filters.dates).
    user_query_for_dates: original user text so dates survive canonical_query rewriting.
    """
    facet_probe = (user_query_for_dates or "").strip() or (query or "")
    # User preference: multilingual/non-English queries should be handled by LLM only.
    # If query contains non-ASCII text (e.g., Devanagari), skip deterministic routing.
    if any(ord(ch) > 127 for ch in (query or "")):
        return None

    if not _is_basic_deterministic_intent(query):
        return None

    platform_hint = platform or _extract_platform_hint(query)
    # Multi-platform deterministic filter support (e.g., "snapchat and google maps").
    _platforms_from_query = extract_platforms_ordered((user_query_for_dates or query) or "")
    platform_hints = list(dict.fromkeys(([platform_hint] if platform_hint else []) + (_platforms_from_query or [])))
    platform_scope_label = ", ".join(platform_hints) if platform_hints else "any"

    def _filter_rows_by_platforms(rows):
        if not platform_hints:
            return rows
        out = []
        for r in rows or []:
            try:
                rp = _derive_record_platform(r)
            except Exception:
                rp = ""
            if any(_platform_match(rp, pf) for pf in platform_hints):
                out.append(r)
        return out

    def _query_chat_messages_multi(limit: int):
        if not platform_hints:
            return data_layer.query_chat_messages(query, limit=limit, platform_filter=None) or []
        merged = []
        for pf in platform_hints:
            merged.extend(
                data_layer.query_chat_messages("list all messages", limit=limit, platform_filter=pf) or []
            )
        return merged

    # Canonical query joins domains with " and " — use original wording for facet detection
    # (e.g. "locations from line chat" must not become multibundle via "show chats and locations…").
    domain = _detect_basic_deterministic_domain(facet_probe)
    if not domain:
        return None

    data_layer = _get_active_data_layer()
    if not data_layer:
        return {
            "handled": True,
            "response": "No forensic data is currently loaded. Please upload UFDR/XML data first.",
            "domain": domain,
            "count": 0,
        }

    try:
        q = (query or "").lower()
        is_count = ("count" in q) or ("how many" in q) or ("total" in q)
        requested_limit = _extract_requested_limit(query)
        # Default behavior: show all unless user explicitly asks for a limit.
        display_limit = requested_limit if requested_limit is not None else 10000
        date_filters = _sanitized_iso_date_filters(
            _merge_iso_date_filters(intent_filters, query, user_query_for_dates or "")
        )

        if domain == "forensic_multibundle":
            mentioned_set = _collect_forensic_domain_mentions(facet_probe)
            order = ["locations", "calls", "messages", "contacts", "media"]
            mentioned = [x for x in order if x in mentioned_set]
            if not mentioned:
                mentioned = sorted(mentioned_set)
            nfacets = max(1, len(mentioned))
            per_cap = min(400, max(40, display_limit // nfacets))
            tnote = _temporal_scope_note(query, date_filters)

            if is_count:
                count_bits = []
                total_n = 0
                if "locations" in mentioned_set:
                    conn = data_layer.get_connection()
                    try:
                        cur = conn.cursor()
                        if platform_hints:
                            cur.execute("SELECT * FROM locations ORDER BY timestamp DESC")
                            base = [dict(r) for r in cur.fetchall()]
                            loc_f = _filter_rows_by_platforms(base)
                        else:
                            cur.execute("SELECT * FROM locations ORDER BY timestamp DESC LIMIT ?", (25000,))
                            loc_f = [dict(r) for r in cur.fetchall()]
                    finally:
                        conn.close()
                    if date_filters:
                        loc_f = _temporal_filter_timestamp_rows(query, loc_f, date_filters)
                    count_bits.append(f"locations={len(loc_f)}")
                    total_n += len(loc_f)
                if "calls" in mentioned_set:
                    fc, _ = _filtered_call_log_rows(data_layer, query, date_filters, None, display_limit)
                    fc = _filter_rows_by_platforms(fc)
                    count_bits.append(f"calls={len(fc)}")
                    total_n += len(fc)
                if "messages" in mentioned_set:
                    raw = _query_chat_messages_multi(100000 if platform_hints else 50000)
                    mr = _dedupe_chat_message_rows(raw)
                    mr = [m for m in mr if isinstance(m, dict) and not _is_deterministic_chat_system_membership_noise(m)]
                    mr = _filter_rows_by_platforms(mr)
                    if date_filters:
                        mr = _temporal_filter_timestamp_rows(query, mr, date_filters)
                    count_bits.append(f"messages={len(mr)}")
                    total_n += len(mr)
                if "contacts" in mentioned_set:
                    if platform_hints:
                        conn = data_layer.get_connection()
                        try:
                            cur = conn.cursor()
                            cur.execute("SELECT * FROM contacts ORDER BY name")
                            all_c = [dict(r) for r in cur.fetchall()]
                        finally:
                            conn.close()
                        cf = _filter_rows_by_platforms(all_c)
                    else:
                        cf = data_layer.query_contacts(query, limit=100000) or []
                    count_bits.append(f"contacts={len(cf)}")
                    total_n += len(cf)
                if "media" in mentioned_set:
                    mc = _count_rows(data_layer, "media_index")
                    count_bits.append(f"media_table_rows={mc}")
                    total_n += mc
                return {
                    "handled": True,
                    "response": f"**Counts** · multibundle{tnote}\n"
                    + "\n".join(f"- {b}" for b in count_bits),
                    "domain": domain,
                    "count": total_n,
                }

            lines = [
                f"# Multi-source report{tnote}",
                f"_Facets: {', '.join(mentioned)} · App: {platform_scope_label}_",
                "",
            ]
            bundle_total = 0

            if "locations" in mentioned_set:
                lines.append("### Locations")
                conn = data_layer.get_connection()
                try:
                    cur = conn.cursor()
                    if platform_hints:
                        cur.execute("SELECT * FROM locations ORDER BY timestamp DESC")
                        base = [dict(r) for r in cur.fetchall()]
                        loc_f = _filter_rows_by_platforms(base)
                    else:
                        cur.execute(
                            "SELECT * FROM locations ORDER BY timestamp DESC LIMIT ?",
                            (min(per_cap * 20, 25000),),
                        )
                        loc_f = [dict(r) for r in cur.fetchall()]
                finally:
                    conn.close()
                if date_filters:
                    loc_f = _temporal_filter_timestamp_rows(query, loc_f, date_filters)
                loc_show = loc_f[:per_cap]
                bundle_total += len(loc_show)
                if not loc_show:
                    lines.append("- None found.")
                else:
                    for r in loc_show:
                        src = _derive_record_platform(r)
                        lines.append(
                            f"- [{r.get('timestamp') or 'N/A'}] ({r.get('latitude') or 'N/A'}, {r.get('longitude') or 'N/A'}) "
                            f"{r.get('address') or ''} | Source: {src}".strip()
                        )
                lines.append("")

            if "calls" in mentioned_set:
                lines.append("### Calls")
                fc, _tt = _filtered_call_log_rows(data_layer, query, date_filters, None, per_cap)
                fc = _filter_rows_by_platforms(fc)
                cs = fc[:per_cap]
                bundle_total += len(cs)
                if not cs:
                    lines.append("- None found.")
                else:
                    for r in cs:
                        cp = _derive_record_platform(r)
                        lines.append(
                            f"- [{r.get('timestamp') or 'N/A'}] {r.get('from_number') or 'Unknown'} -> {r.get('to_number') or 'Unknown'} "
                            f"({r.get('call_type') or 'Unknown'}, {r.get('duration') or 0}s, platform: {cp or 'Unknown'})"
                        )
                lines.append("")

            if "messages" in mentioned_set:
                lines.append("### Messages")
                raw = _query_chat_messages_multi(100000 if platform_hints else min(25000, per_cap * 50))
                mr = _dedupe_chat_message_rows(raw)
                mr = [m for m in mr if isinstance(m, dict) and not _is_deterministic_chat_system_membership_noise(m)]
                mr = _filter_rows_by_platforms(mr)
                if date_filters:
                    mr = _temporal_filter_timestamp_rows(query, mr, date_filters)
                mr.sort(key=lambda x: str(x.get("timestamp") or ""), reverse=True)
                ms = mr[:per_cap]
                bundle_total += len(ms)
                if not ms:
                    lines.append("- None found.")
                else:
                    for m in ms:
                        if _is_deterministic_chat_system_membership_noise(m):
                            continue
                        text = (m.get("text_content") or "").strip()
                        if len(text) > 120:
                            text = text[:117] + "..."
                        lines.append(
                            f"- [{m.get('timestamp') or 'N/A'}] {m.get('from_participant') or 'Unknown'} -> "
                            f"{m.get('to_participant') or 'Unknown'}: {text or '[No text]'}"
                        )
                lines.append("")

            if "contacts" in mentioned_set:
                lines.append("### Contacts")
                if platform_hints:
                    conn = data_layer.get_connection()
                    try:
                        cur = conn.cursor()
                        cur.execute("SELECT * FROM contacts ORDER BY name")
                        all_c = [dict(r) for r in cur.fetchall()]
                    finally:
                        conn.close()
                    cf = _filter_rows_by_platforms(all_c)
                else:
                    cf = data_layer.query_contacts(query, limit=per_cap * 5) or []
                cf = cf[:per_cap]
                bundle_total += len(cf)
                if not cf:
                    lines.append("- None found.")
                else:
                    for c in cf:
                        lines.append(
                            f"- {c.get('name') or 'Unknown'} | {c.get('phone') or 'N/A'} | {c.get('email') or 'N/A'}"
                        )
                lines.append("")

            if "media" in mentioned_set:
                lines.append("### Media (sample)")
                media_rows = data_layer.get_media_metadata(limit=per_cap) or []
                bundle_total += len(media_rows)
                if not media_rows:
                    lines.append("- None found.")
                else:
                    for r in media_rows:
                        lines.append(
                            f"- {r.get('filename') or 'Unknown file'} | {r.get('media_type') or 'unknown'} | {r.get('source_path') or 'N/A'}"
                        )

            return {
                "handled": True,
                "response": "\n".join(lines),
                "domain": domain,
                "count": bundle_total,
            }

        if domain == "contacts":
            total = _count_rows(data_layer, "contacts")
            # If platform filter requested, derive and filter in-memory from contacts table.
            if platform_hints:
                conn = data_layer.get_connection()
                try:
                    cur = conn.cursor()
                    cur.execute("SELECT * FROM contacts ORDER BY name")
                    all_rows = [dict(r) for r in cur.fetchall()]
                finally:
                    conn.close()
                filtered = _filter_rows_by_platforms(all_rows)
                if is_count:
                    return {
                        "handled": True,
                        "response": f"**Contacts** · {platform_scope_label} — {len(filtered)} found.",
                        "domain": domain,
                        "count": len(filtered),
                    }
                shown = filtered[:display_limit]
                lines = [f"**Contacts** · {platform_scope_label} · {len(shown)} shown · {len(filtered)} matched"]
                for c in shown:
                    lines.append(
                        f"- {c.get('name') or 'Unknown'} | {c.get('phone') or 'N/A'} | {c.get('email') or 'N/A'}"
                    )
                if not shown:
                    lines.append("- No matching contacts found.")
                return {"handled": True, "response": "\n".join(lines), "domain": domain, "count": len(filtered)}
            else:
                if is_count:
                    return {"handled": True, "response": f"**Contacts** — {total} in table.", "domain": domain, "count": total}
                rows = data_layer.query_contacts(query, limit=display_limit)
                lines = [f"**Contacts** · {len(rows)} shown · {total} in table"]
                for c in rows[:display_limit]:
                    lines.append(f"- {c.get('name') or 'Unknown'} | {c.get('phone') or 'N/A'} | {c.get('email') or 'N/A'}")
                if not rows:
                    lines.append("- No matching contacts found.")
                return {"handled": True, "response": "\n".join(lines), "domain": domain, "count": total}

        if domain == "calls_and_chats":
            filtered_calls, table_total = _filtered_call_log_rows(
                data_layer, query, date_filters, None, display_limit
            )
            filtered_calls = _filter_rows_by_platforms(filtered_calls)
            raw_msg = _query_chat_messages_multi(100000 if platform_hints else min(display_limit, 5000))
            msg_rows = _dedupe_chat_message_rows(raw_msg)
            msg_rows = _filter_rows_by_platforms(msg_rows)
            if date_filters:
                msg_rows = _temporal_filter_timestamp_rows(query, msg_rows, date_filters)
            msg_rows.sort(key=lambda x: str(x.get("timestamp") or ""), reverse=True)

            if is_count:
                tnote = _temporal_scope_note(query, date_filters)
                plat_note = f" for platforms '{platform_scope_label}'" if platform_hints else ""
                return {
                    "handled": True,
                    "response": (
                        f"**Calls & messages**{plat_note}{tnote} — "
                        f"{len(filtered_calls)} calls, {len(msg_rows)} messages."
                    ),
                    "domain": domain,
                    "count": len(filtered_calls) + len(msg_rows),
                }

            shown_calls = filtered_calls[:display_limit]
            shown_msg = msg_rows[:display_limit]
            scope_bits = []
            if date_filters:
                scope_bits.append(
                    f"date={date_filters[0]}" if len(date_filters) == 1 else f"dates={','.join(date_filters)}"
                )
            if _query_has_temporal_range_keywords(query):
                scope_bits.append("temporal=after|before|between")
            if platform_hints:
                scope_bits.append(f"platforms={platform_scope_label}")
            scope_txt = f" ({', '.join(scope_bits)})" if scope_bits else ""
            tnote_hdr = _temporal_scope_note(query, date_filters)

            lines = [
                f"# Calls & messages{tnote_hdr}{scope_txt}",
                "",
                f"### Calls · {len(shown_calls)} shown · {len(filtered_calls)} matched",
                "",
            ]
            try:
                platform_map = {}
                for r in filtered_calls:
                    p = _derive_record_platform(r)
                    platform_map[p] = platform_map.get(p, 0) + 1
                platform_counts = [{"platform_name": k, "c": v} for k, v in platform_map.items()]
                platform_counts.sort(key=lambda x: int(x.get("c", 0)), reverse=True)
                if platform_counts:
                    lines.append("_Call platforms:_")
                    for pc in platform_counts:
                        lines.append(f"- {pc.get('platform_name') or 'Unknown'} ({pc.get('c') or 0})")
                    lines.append("")
            except Exception as e:
                logger.warning("Could not build call platform breakdown (calls_and_chats): %s", e)
            call_table_rows: List[List[Any]] = []
            for r in shown_calls:
                call_platform = _derive_record_platform(r)
                dur_raw = r.get("duration")
                try:
                    dur_disp = f"{int(dur_raw)} sec"
                except (TypeError, ValueError):
                    dur_disp = str(dur_raw if dur_raw is not None else "0")
                call_table_rows.append(
                    [
                        short_time_from_timestamp(str(r.get("timestamp") or "N/A")),
                        r.get("call_type") or "Unknown",
                        r.get("from_number") or "Unknown",
                        r.get("to_number") or "Unknown",
                        dur_disp,
                        call_platform or "Unknown",
                    ]
                )
            if call_table_rows:
                lines.append(
                    build_markdown_table(
                        ["Time (UTC)", "Type", "From", "To", "Duration", "Platform"],
                        call_table_rows,
                    )
                )
            else:
                lines.append("- None found.")

            lines.append("")
            lines.append(
                f"### Messages · {len(shown_msg)} shown · {len(msg_rows)} matched{scope_txt}"
            )
            msg_table_rows: List[List[Any]] = []
            for m in shown_msg:
                text = (m.get("text_content") or "").strip()
                if len(text) > 200:
                    text = text[:197] + "..."
                msg_table_rows.append(
                    [
                        str(m.get("timestamp") or "N/A"),
                        m.get("from_participant") or "Unknown",
                        m.get("to_participant") or "Unknown",
                        text or "[No text]",
                    ]
                )
            if msg_table_rows:
                lines.append(
                    build_markdown_table(
                        ["Timestamp (UTC)", "Sender", "Receiver", "Message"],
                        msg_table_rows,
                    )
                )
            else:
                lines.append("- None found.")
            return {
                "handled": True,
                "response": "\n".join(lines),
                "domain": domain,
                "count": len(filtered_calls) + len(msg_rows),
            }

        if domain == "calls":
            if not date_filters and not platform_hints:
                table_total = _count_rows(data_layer, "call_logs")
                if is_count:
                    return {
                        "handled": True,
                        "response": f"**Calls** — {table_total} in call log table.",
                        "domain": domain,
                        "count": table_total,
                    }
                rows = data_layer.query_calls(query, limit=display_limit)
                filtered = [dict(r) for r in rows] if rows else []
            else:
                filtered, table_total = _filtered_call_log_rows(
                    data_layer, query, date_filters, None, display_limit
                )
                filtered = _filter_rows_by_platforms(filtered)

            if date_filters:
                logger.info(
                    f"PIPELINE: deterministic call_logs date_filters={date_filters} matched_rows={len(filtered)}"
                )

            if is_count:
                tnote = _temporal_scope_note(query, date_filters)
                plat_note = f" for platforms '{platform_scope_label}'" if platform_hints else ""
                return {
                    "handled": True,
                    "response": f"**Calls**{plat_note}{tnote} — {len(filtered)} matched.",
                    "domain": domain,
                    "count": len(filtered),
                }

            shown = filtered[:display_limit]
            scope_bits = []
            if date_filters:
                scope_bits.append(
                    f"date={date_filters[0]}" if len(date_filters) == 1 else f"dates={','.join(date_filters)}"
                )
            if _query_has_temporal_range_keywords(query):
                scope_bits.append("temporal=after|before|between")
            if platform_hints:
                scope_bits.append(f"platforms={platform_scope_label}")
            scope_txt = f" ({', '.join(scope_bits)})" if scope_bits else ""
            tnote_hdr = _temporal_scope_note(query, date_filters)
            lines = [
                f"# Calls{tnote_hdr}{scope_txt}",
                "",
                f"**Summary.** {len(shown)} shown · {len(filtered)} matched · {table_total} rows in table",
                "",
            ]
            iter_rows = shown
            total_for_header = len(filtered)

            # Platform breakdown: scoped rows only (consistent with list below)
            try:
                platform_map = {}
                for r in filtered:
                    p = _derive_record_platform(r)
                    platform_map[p] = platform_map.get(p, 0) + 1
                platform_counts = [{"platform_name": k, "c": v} for k, v in platform_map.items()]
                platform_counts.sort(key=lambda x: int(x.get("c", 0)), reverse=True)
                if platform_counts:
                    lines.append("_By platform:_")
                    for pc in platform_counts:
                        lines.append(f"- {pc.get('platform_name') or 'Unknown'} ({pc.get('c') or 0})")
                    lines.append("")
            except Exception as e:
                logger.warning(f"Could not build call platform breakdown: {e}")

            call_only_rows: List[List[Any]] = []
            for r in iter_rows:
                call_platform = _derive_record_platform(r)
                dur_raw = r.get("duration")
                try:
                    dur_disp = f"{int(dur_raw)} sec"
                except (TypeError, ValueError):
                    dur_disp = str(dur_raw if dur_raw is not None else "0")
                call_only_rows.append(
                    [
                        short_time_from_timestamp(str(r.get("timestamp") or "N/A")),
                        r.get("call_type") or "Unknown",
                        r.get("from_number") or "Unknown",
                        r.get("to_number") or "Unknown",
                        dur_disp,
                        call_platform or "Unknown",
                    ]
                )
            if call_only_rows:
                lines.append(
                    build_markdown_table(
                        ["Time (UTC)", "Type", "From", "To", "Duration", "Platform"],
                        call_only_rows,
                    )
                )
            else:
                lines.append("- None found.")
            return {"handled": True, "response": "\n".join(lines), "domain": domain, "count": total_for_header}

        if domain == "chats":
            if platform_hints:
                # Pull broad then filter by requested platforms (supports >1 app).
                chat_data = data_layer.get_chat_data_for_display(platform=None, chat_id=None, limit=max(display_limit * 20, 500))
            else:
                chat_data = data_layer.get_chat_data_for_display(platform=None, chat_id=None, limit=display_limit)
            chats = chat_data.get("chats", []) if isinstance(chat_data, dict) else []
            if platform_hints:
                chats = [c for c in chats if any(_platform_match(c.get("platform"), pf) for pf in platform_hints)]
            total_chats = len(chats)
            total_msgs = sum(int(c.get("total_messages") or len(c.get("messages", []))) for c in chats)
            if is_count:
                if platform_hints:
                    return {
                        "handled": True,
                        "response": f"**Chats** · {platform_scope_label} — {total_chats} threads, {total_msgs} messages.",
                        "domain": domain,
                        "count": total_chats,
                    }
                return {
                    "handled": True,
                    "response": f"**Chats** — {total_chats} threads, {total_msgs} messages.",
                    "domain": domain,
                    "count": total_chats,
                }
            shown_chats = chats[:display_limit]
            if platform_hints:
                header = f"**Chats** · {platform_scope_label} · {len(shown_chats)} shown · {total_chats} threads / {total_msgs} messages"
            else:
                header = f"**Chats** · {len(shown_chats)} shown · {total_chats} threads / {total_msgs} messages"
            lines = [header, ""]
            for c in shown_chats:
                participants = c.get("participants") or []
                if isinstance(participants, list):
                    participants_text = ", ".join([str(p) for p in participants[:3]]) if participants else "N/A"
                else:
                    participants_text = str(participants) if participants else "N/A"
                if isinstance(participants, list) and len(participants) > 3:
                    participants_text += " ..."
                lines.append(
                    f"- Chat: {c.get('chat_name') or c.get('chat_id') or 'Unknown'} | "
                    f"Participants: {participants_text} | "
                    f"Messages: {c.get('total_messages') or len(c.get('messages', []))} | "
                    f"Last Activity: {c.get('last_activity') or 'N/A'}"
                )
            if not shown_chats:
                lines.append("- None found.")
            return {"handled": True, "response": "\n".join(lines), "domain": domain, "count": total_chats}

        if domain == "messages":
            total = _count_rows(data_layer, "chat_messages")
            if is_count:
                if platform_hints:
                    raw = _query_chat_messages_multi(100000)
                    rows_ct = _dedupe_chat_message_rows(raw)
                    rows_ct = _filter_rows_by_platforms(rows_ct)
                    if date_filters:
                        rows_ct = _temporal_filter_timestamp_rows(query, rows_ct, date_filters)
                    n = len(rows_ct)
                    tnote = _temporal_scope_note(query, date_filters)
                    return {
                        "handled": True,
                        "response": f"**Messages** · {platform_scope_label}{tnote} — {n} matched.",
                        "domain": domain,
                        "count": n,
                    }
                return {"handled": True, "response": f"**Messages** — {total} rows in chat_messages.", "domain": domain, "count": total}
            if platform_hints:
                # One SQL row per query row — dedupe in case the DB contains duplicate rows for the same logical message
                # (seen with Native SMS / some parsers). Platform routing uses extract_platforms_ordered (not ambiguous "messenger").
                raw = _query_chat_messages_multi(100000)
                rows = _dedupe_chat_message_rows(raw)
                rows = _filter_rows_by_platforms(rows)
                if date_filters:
                    rows = _temporal_filter_timestamp_rows(query, rows, date_filters)
                rows.sort(key=lambda x: str(x.get("timestamp") or ""), reverse=True)
                platform_total = len(rows)
                shown = rows[:display_limit]
                tnote = _temporal_scope_note(query, date_filters)
                lines = [
                    f"# Messages · {platform_scope_label}{tnote}",
                    "",
                    f"**Summary.** {len(shown)} shown · {platform_total} unique after dedupe",
                    "",
                ]
                plat_msg_rows: List[List[Any]] = []
                for m in shown:
                    text = (m.get("text_content") or "").strip()
                    if len(text) > 200:
                        text = text[:197] + "..."
                    plat_msg_rows.append(
                        [
                            str(m.get("timestamp") or "N/A"),
                            m.get("from_participant") or "Unknown",
                            m.get("to_participant") or "Unknown",
                            text or "[No text]",
                        ]
                    )
                if plat_msg_rows:
                    lines.append(
                        build_markdown_table(
                            ["Timestamp (UTC)", "Sender", "Receiver", "Message"],
                            plat_msg_rows,
                        )
                    )
                else:
                    lines.append("- None found.")
                return {"handled": True, "response": "\n".join(lines), "domain": domain, "count": platform_total}
            else:
                rows = data_layer.query_chat_messages(query, limit=display_limit, platform_filter=None)
                rows = [
                    r
                    for r in rows
                    if isinstance(r, dict) and not _is_deterministic_chat_system_membership_noise(r)
                ]
                lines = [f"# Messages", "", f"**Summary.** {len(rows)} shown · {total} in table", ""]
                gen_msg_rows: List[List[Any]] = []
                for m in rows[:display_limit]:
                    text = (m.get("text_content") or "").strip()
                    if len(text) > 200:
                        text = text[:197] + "..."
                    gen_msg_rows.append(
                        [
                            str(m.get("timestamp") or "N/A"),
                            m.get("from_participant") or "Unknown",
                            m.get("to_participant") or "Unknown",
                            text or "[No text]",
                        ]
                    )
                if gen_msg_rows:
                    lines.append(
                        build_markdown_table(
                            ["Timestamp (UTC)", "Sender", "Receiver", "Message"],
                            gen_msg_rows,
                        )
                    )
                else:
                    lines.append("- None found.")
                return {"handled": True, "response": "\n".join(lines), "domain": domain, "count": total}

        if domain == "locations":
            total = _count_rows(data_layer, "locations")
            tnote = _temporal_scope_note(query, date_filters)
            conn = data_layer.get_connection()
            try:
                cur = conn.cursor()
                if platform_hints:
                    cur.execute("SELECT * FROM locations ORDER BY timestamp DESC")
                    base_rows = [dict(r) for r in cur.fetchall()]
                    filtered = [
                        r for r in base_rows
                        if any(_platform_match(_derive_record_platform(r), pf) for pf in platform_hints)
                    ]
                else:
                    lim = min(display_limit * 25, 50000) if (date_filters or _query_has_temporal_range_keywords(query)) else display_limit
                    cur.execute("SELECT * FROM locations ORDER BY timestamp DESC LIMIT ?", (lim,))
                    filtered = [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()

            if date_filters:
                filtered = _temporal_filter_timestamp_rows(query, filtered, date_filters)

            if is_count and not platform_hints and not date_filters:
                return {"handled": True, "response": f"**Locations** — {total} rows in table.", "domain": domain, "count": total}
            if is_count:
                plat_note = f" for platforms {', '.join(platform_hints)}" if platform_hints else ""
                return {
                    "handled": True,
                    "response": f"**Locations**{plat_note}{tnote} — {len(filtered)} matched.",
                    "domain": domain,
                    "count": len(filtered),
                }

            shown = filtered[:display_limit]
            if platform_hints:
                lines = [
                    f"# Locations · {', '.join(platform_hints)}{tnote}",
                    "",
                    f"**Summary.** {len(shown)} shown · {len(filtered)} matched",
                    "",
                ]
            else:
                lines = [
                    f"# Locations{tnote}",
                    "",
                    f"**Summary.** {len(shown)} shown · {len(filtered)} matched · {total} rows in table",
                    "",
                ]
            loc_rows: List[List[Any]] = []
            for r in shown:
                src = _derive_record_platform(r)
                addr = (r.get("address") or "").strip()
                loc_rows.append(
                    [
                        short_time_from_timestamp(str(r.get("timestamp") or "N/A")),
                        r.get("latitude") or "N/A",
                        r.get("longitude") or "N/A",
                        addr or " ",
                        src or "Unknown",
                    ]
                )
            if loc_rows:
                lines.append(
                    build_markdown_table(
                        ["Time (UTC)", "Latitude", "Longitude", "Address", "Source"],
                        loc_rows,
                    )
                )
            else:
                lines.append("- None found.")
            return {"handled": True, "response": "\n".join(lines), "domain": domain, "count": len(filtered)}

        if domain == "media":
            total = _count_rows(data_layer, "media_index")
            if is_count:
                return {"handled": True, "response": f"**Media** — {total} rows in media index.", "domain": domain, "count": total}
            rows = data_layer.get_media_metadata(limit=display_limit)
            lines = [f"# Media", "", f"**Summary.** {len(rows)} shown · {total} in table", ""]
            for r in rows[:display_limit]:
                lines.append(f"- {r.get('filename') or 'Unknown file'} | {r.get('media_type') or 'unknown'} | {r.get('source_path') or 'N/A'}")
            if not rows:
                lines.append("- No media records found.")
            return {"handled": True, "response": "\n".join(lines), "domain": domain, "count": total}

    except Exception as e:
        logger.error(f"Deterministic retrieval failed: {e}", exc_info=True)
        return {
            "handled": True,
            "response": f"Deterministic retrieval failed for {domain}: {str(e)}",
            "domain": domain,
            "count": 0,
        }

    return None


def get_query_refinement_suggestions(query: str, data_src: dict) -> dict:
    """
    Build user-friendly suggestions to refine an overly broad query,
    optionally using basic stats from ACTIVE_DATA.
    """
    # Basic stats from ACTIVE_DATA if available
    stats = {
        "contacts": 0,
        "messages": 0,
        "calls": 0,
    }

    try:
        if data_src:
            for _, file_data in data_src.items():
                if not isinstance(file_data, dict):
                    continue
                contacts = file_data.get("contacts", [])
                messages = file_data.get("messages", [])
                calls = file_data.get("calls", [])
                if isinstance(contacts, list):
                    stats["contacts"] += len(contacts)
                if isinstance(messages, list):
                    stats["messages"] += len(messages)
                if isinstance(calls, list):
                    stats["calls"] += len(calls)
    except Exception:
        pass

    suggestions = [
        "Show all messages and calls for this UFDR.",
        "Summarize the communication timeline for this device.",
        "List the top contacts by number of messages and calls.",
        "Find messages that mention money, payments, or transactions.",
        "Show suspicious or high-risk conversations in this UFDR.",
    ]

    # Tailor suggestions slightly based on available data
    tailored = []
    if stats["messages"] > 0:
        tailored.append(
            f"Summarize key patterns from the {stats['messages']} messages in this UFDR."
        )
        tailored.append(
            "Find messages that look related to threats, blackmail, or fraud."
        )
    if stats["calls"] > 0:
        tailored.append(
            f"Analyze the {stats['calls']} calls and highlight unusual calling patterns."
        )
    if stats["contacts"] > 0:
        tailored.append(
            f"Show relationships between the {stats['contacts']} contacts and the main suspect."
        )

    if tailored:
        suggestions = tailored + suggestions

    return {
        "status": "BROAD_QUERY",
        "message": "Your question is very broad, so the AI may answer generically without using the uploaded UFDR data effectively.",
        "original_query": query,
        "stats": stats,
        "suggested_queries": suggestions[:8],  # keep list short
    }

def init_qwen_vl_model():
    """Initialize Qwen2.5-VL-7B model for multimodal processing."""
    global QWEN_VL_MODEL, QWEN_VL_PROCESSOR, QWEN_VL_LOADED
    
    if QWEN_VL_LOADED:
        return QWEN_VL_MODEL, QWEN_VL_PROCESSOR
    
    if not USE_QWEN_VL:
        return None, None
    
    try:
        logger.info("Loading Qwen2.5-VL-7B model...")
        from transformers import AutoProcessor, Qwen2VLForConditionalGeneration
        import torch
        
        # Check if CUDA is available
        device = "cuda" if torch.cuda.is_available() else "cpu"
        logger.info(f"Loading model on device: {device}")
        
        # Load model with proper configuration
        # Use trust_remote_code=True for Qwen models and force download if cache is corrupted
        try:
            # First try loading without quantization (more reliable)
            logger.info("Loading Qwen2.5-VL-7B model (full precision)...")
            QWEN_VL_MODEL = Qwen2VLForConditionalGeneration.from_pretrained(
                QWEN_VL_MODEL_NAME,
                torch_dtype=torch.float16 if device == "cuda" else torch.float32,
                trust_remote_code=True,
                low_cpu_mem_usage=True
            )
            # Move to device manually
            QWEN_VL_MODEL = QWEN_VL_MODEL.to(device)
            logger.info(f"Model loaded successfully on {device}")
        except Exception as e:
            # If there's a size mismatch, the cache might be corrupted
            if "size mismatch" in str(e).lower() or "shape" in str(e).lower():
                logger.warning("Model cache appears corrupted. Attempting to force re-download...")
                try:
                    # Force re-download by clearing cache and downloading fresh
                    logger.info("Clearing corrupted cache and re-downloading model...")
                    QWEN_VL_MODEL = Qwen2VLForConditionalGeneration.from_pretrained(
                        QWEN_VL_MODEL_NAME,
                        torch_dtype=torch.float16 if device == "cuda" else torch.float32,
                        trust_remote_code=True,
                        low_cpu_mem_usage=True,
                        force_download=True,  # Force re-download
                        resume_download=False  # Don't resume, start fresh
                    )
                    QWEN_VL_MODEL = QWEN_VL_MODEL.to(device)
                    logger.info(f"Model re-downloaded and loaded on {device}")
                except Exception as e2:
                    logger.error(f"Failed to re-download model: {e2}")
                    logger.error("You may need to manually clear the cache at: ~/.cache/huggingface/hub/")
                    raise e  # Re-raise original error
            else:
                # Other error, re-raise
                raise
        
        QWEN_VL_PROCESSOR = AutoProcessor.from_pretrained(QWEN_VL_MODEL_NAME)
        QWEN_VL_LOADED = True
        logger.info("✅ Qwen2.5-VL-7B model loaded successfully")
        return QWEN_VL_MODEL, QWEN_VL_PROCESSOR
    except ImportError as e:
        logger.error(f"Failed to import transformers for Qwen2.5-VL: {e}")
        logger.error("Install with: pip install transformers torch pillow")
        return None, None
    except Exception as e:
        logger.error(f"Failed to load Qwen2.5-VL-7B model: {e}")
        logger.error("Model may not be downloaded. Download from Hugging Face first.")
        return None, None

def extract_zip_with_hybrid_parser(zip_path, extract_to=None):
    """
    Extract ZIP file using hybrid parser (heuristics + LLM fallback).
    Falls back to standard parser if hybrid parser fails.
    
    Args:
        zip_path: Path to ZIP file
        extract_to: Optional extraction directory
        
    Returns:
        Extracted data structure in UFDR format
    """
    import tempfile
    try:
        logger.info(f"🔍 Attempting hybrid ZIP parsing for: {zip_path}")
        
        # Initialize hybrid parser with LLM settings
        hybrid_parser = HybridZipParser(
            llm_url=LLM_URL if USE_LLM else None,
            llm_model=LLM_MODEL if USE_LLM else None
        )
        
        # Try hybrid parsing
        ufdr_data = hybrid_parser.parse_zip(zip_path)
        
        # Check if we got meaningful data
        if ufdr_data and (ufdr_data.get('contacts') or ufdr_data.get('messages') 
                          or ufdr_data.get('call_logs') or ufdr_data.get('locations')):
            logger.info("✅ Hybrid parser succeeded")
            
            # Extract images and videos - need to extract ZIP first to get full paths
            extracted_images = []
            extracted_videos = []
            
            # Extract ZIP to persistent location (not temp) so images persist across sessions
            if extract_to is None:
                # Try to get session_id from Flask session or request context
                try:
                    from flask import session, request
                    session_id = session.get('session_id') if session else None
                    # Also try request args
                    if not session_id:
                        session_id = request.args.get('session_id') if request else None
                except RuntimeError:
                    # Not in request context
                    session_id = None
                
                if session_id and session_id != 'None' and session_id != '':
                    # Use persistent location: data/extracted_ufdrs/session_id/
                    extract_base = os.path.join('data', 'extracted_ufdrs')
                    os.makedirs(extract_base, exist_ok=True)
                    extract_to = os.path.join(extract_base, session_id)
                    os.makedirs(extract_to, exist_ok=True)
                    logger.info(f"📂 Using persistent extraction path: {extract_to}")
                else:
                    # Fallback to temp if no session_id
                    extract_to = tempfile.mkdtemp()
                    logger.warning(f"⚠️ No session_id available, using temp directory: {extract_to} (images may not persist)")
            
            logger.info(f"Selectively extracting essential files to {extract_to}")
            import zipfile
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Selective extraction - only extract essential files
                essential_count = 0
                skipped_count = 0
                for info in zip_ref.infolist():
                    path = info.filename.replace('\\', '/')
                    # Skip directories
                    if info.is_dir():
                        continue
                    # Extract only essential files (databases, JSON, metadata)
                    # Skip media files - they'll be extracted on-demand
                    if (path.endswith('.db') or 
                        path.endswith('.json') or 
                        'metadata' in path.lower() or 
                        'report.xml' in path.lower() or
                        (path.endswith('.xml') and 'report' in path.lower())):
                        zip_ref.extract(info, extract_to)
                        essential_count += 1
                    else:
                        skipped_count += 1
                logger.info(f"Selectively extracted {essential_count} essential files, skipped {skipped_count} non-essential files")
                
                # Get images and videos metadata from ufdr_data (deferred extraction)
                images = ufdr_data.get('images', [])
                videos = ufdr_data.get('videos', [])
                
                logger.info(f"Found {len(images)} image entries and {len(videos)} video entries (metadata only - deferred extraction)")
                
                # Store only metadata - don't extract files yet (deferred extraction)
                # Images will be extracted on-demand when accessed
                for img_info in images:
                    if isinstance(img_info, dict):
                        rel_path = img_info.get('path', '') or img_info.get('rel_path', '')
                        if rel_path:
                            rel_path_normalized = rel_path.replace('\\', '/')
                            extracted_images.append({
                                'name': img_info.get('name', os.path.basename(rel_path)),
                                'rel_path': rel_path_normalized,
                                'path': None,  # Will be resolved on-demand
                                'size': img_info.get('size', 0),
                                'extracted': False  # Mark as deferred
                            })
                
                # Same for videos - metadata only
                for vid_info in videos:
                    if isinstance(vid_info, dict):
                        rel_path = vid_info.get('path', '') or vid_info.get('rel_path', '')
                        if rel_path:
                            rel_path_normalized = rel_path.replace('\\', '/')
                            extracted_videos.append({
                                'name': vid_info.get('name', os.path.basename(rel_path)),
                                'rel_path': rel_path_normalized,
                                'path': None,  # Will be resolved on-demand
                                'size': vid_info.get('size', 0),
                                'extracted': False  # Mark as deferred
                            })
            
            logger.info(f"Stored metadata for {len(extracted_images)} images and {len(extracted_videos)} videos (deferred extraction)")
            
            # Mark as hybrid parsed and include normalized data
            return {
                'hybrid_parsed': True,
                'ufdr_data': ufdr_data,  # Already normalized
                'json_files': {zip_path: ufdr_data},
                'structure': {
                    'artifacts': {
                        'contacts': ufdr_data.get('contacts', []),
                        'sms': [m for m in ufdr_data.get('messages', []) if m.get('source') == 'SMS'],
                        'whatsapp': [m for m in ufdr_data.get('messages', []) if m.get('source') == 'WhatsApp'],
                        'calls': ufdr_data.get('call_logs', []),
                        'location': ufdr_data.get('locations', [])
                    },
                    'metadata': {
                        'device_info': ufdr_data.get('device', {}),
                        'case_info': ufdr_data.get('case_info', {})
                    }
                },
                'images': extracted_images,
                'videos': extracted_videos,
                'extract_path': extract_to or tempfile.mkdtemp()
            }
        else:
            logger.warning("⚠️ Hybrid parser returned empty data, falling back to standard parser")
            raise Exception("Hybrid parser returned empty data")
            
    except Exception as e:
        logger.warning(f"⚠️ Hybrid parser failed: {e}, falling back to standard parser")
        # Fallback to standard parser
        return extract_zip_file(zip_path, extract_to)

def extract_zip_file(zip_path, extract_to=None):
    """Extract ZIP file and return extracted data structure following UFDR format."""
    import zipfile
    import tempfile
    
    if extract_to is None:
        extract_to = tempfile.mkdtemp()
    
    extracted_files = {
        'json_files': {},
        'images': [],
        'videos': [],
        'other_files': [],
        'extract_path': extract_to,
        'structure': {
            'artifacts': {},
            'metadata': {},
            'media': {},
            'reports': {}
        }
    }
    
    try:
        logger.info(f"Opening ZIP file: {zip_path}")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Skip testzip() for large files - it can be very slow
            # Just try to extract and catch errors if ZIP is invalid
            logger.info(f"Selectively extracting essential files to: {extract_to}")
            # Selective extraction - only extract essential files
            essential_count = 0
            skipped_count = 0
            for info in zip_ref.infolist():
                path = info.filename.replace('\\', '/')
                # Skip directories
                if info.is_dir():
                    continue
                # Extract only essential files (databases, JSON, metadata)
                # Skip media files - they'll be extracted on-demand
                if (path.endswith('.db') or 
                    path.endswith('.json') or 
                    'metadata' in path.lower() or 
                    'report.xml' in path.lower() or
                    (path.endswith('.xml') and 'report' in path.lower()) or
                    'artifacts' in path.lower()):
                    zip_ref.extract(info, extract_to)
                    essential_count += 1
                else:
                    skipped_count += 1
            logger.info(f"Selectively extracted {essential_count} essential files, skipped {skipped_count} non-essential files")
            
            # Scan extracted files and organize by structure
            file_count = 0
            max_files = 50000  # Safety limit to prevent memory issues (increased for large extractions)
            for root, dirs, files in os.walk(extract_to):
                if file_count >= max_files:
                    logger.warning(f"Reached maximum file limit ({max_files}). Stopping scan.")
                    break
                for file in files:
                    file_count += 1
                    if file_count % 100 == 0:
                        logger.info(f"Processing file {file_count}...")
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, extract_to)
                    # Normalize path separators (handle both Windows \ and Unix /)
                    rel_path_normalized = rel_path.replace('\\', '/')
                    
                    # Organize by UFDR structure
                    if rel_path_normalized.startswith('Artifacts/'):
                        # Artifacts folder (Calls, Contacts, SMS, WhatsApp)
                        if file.endswith('.json'):
                            try:
                                # Check file size before loading (skip if too large - >10MB)
                                file_size = os.path.getsize(file_path)
                                if file_size > 10 * 1024 * 1024:  # 10MB limit per JSON file
                                    logger.warning(f"Skipping large JSON file {rel_path} ({file_size} bytes)")
                                    continue
                                
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    # Store with full path as key (use normalized path)
                                    extracted_files['json_files'][rel_path_normalized] = data
                                    # Also store in structure
                                    if 'Calls' in rel_path_normalized:
                                        extracted_files['structure']['artifacts']['calls'] = data
                                    elif 'Contacts' in rel_path_normalized:
                                        extracted_files['structure']['artifacts']['contacts'] = data
                                    elif 'SMS' in rel_path_normalized:
                                        extracted_files['structure']['artifacts']['sms'] = data
                                    elif 'WhatsApp' in rel_path_normalized:
                                        extracted_files['structure']['artifacts']['whatsapp'] = data
                                    elif 'Location' in rel_path_normalized:
                                        extracted_files['structure']['artifacts']['location'] = data
                            except json.JSONDecodeError as e:
                                logger.warning(f"Invalid JSON in file {rel_path}: {e}")
                            except MemoryError as e:
                                logger.error(f"Memory error loading JSON file {rel_path}: {e}")
                                raise  # Re-raise memory errors
                            except Exception as e:
                                logger.warning(f"Failed to load JSON file {rel_path}: {e}")
                    
                    elif rel_path_normalized.startswith('__metadata__/'):
                        # Metadata folder (case_info, device_info, log)
                        if file.endswith('.json'):
                            try:
                                # Check file size before loading
                                file_size = os.path.getsize(file_path)
                                if file_size > 10 * 1024 * 1024:  # 10MB limit
                                    logger.warning(f"Skipping large metadata file {rel_path} ({file_size} bytes)")
                                    continue
                                
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    extracted_files['json_files'][rel_path_normalized] = data
                                    if 'case_info' in rel_path_normalized:
                                        extracted_files['structure']['metadata']['case_info'] = data
                                    elif 'device_info' in rel_path_normalized:
                                        extracted_files['structure']['metadata']['device_info'] = data
                            except json.JSONDecodeError as e:
                                logger.warning(f"Invalid JSON in metadata file {rel_path}: {e}")
                            except MemoryError as e:
                                logger.error(f"Memory error loading metadata file {rel_path}: {e}")
                                raise
                            except Exception as e:
                                logger.warning(f"Failed to load JSON file {rel_path}: {e}")
                    
                    elif rel_path_normalized.startswith('Media/'):
                        # Media folder (Images, Videos)
                        if file.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp')):
                            extracted_files['images'].append({
                                'path': file_path,
                                'rel_path': rel_path_normalized,
                                'name': file
                            })
                            if 'Images' in rel_path_normalized:
                                if 'images' not in extracted_files['structure']['media']:
                                    extracted_files['structure']['media']['images'] = []
                                extracted_files['structure']['media']['images'].append({
                                    'path': file_path,
                                    'rel_path': rel_path_normalized,
                                    'name': file
                                })
                        
                        elif file.lower().endswith(('.mp4', '.avi', '.mov', '.mkv', '.webm')):
                            extracted_files['videos'].append({
                                'path': file_path,
                                'rel_path': rel_path_normalized,
                                'name': file
                            })
                            if 'Videos' in rel_path_normalized or 'Video' in rel_path_normalized:
                                if 'videos' not in extracted_files['structure']['media']:
                                    extracted_files['structure']['media']['videos'] = []
                                extracted_files['structure']['media']['videos'].append({
                                    'path': file_path,
                                    'rel_path': rel_path_normalized,
                                    'name': file
                                })
                    
                    elif rel_path_normalized.startswith('Reports/'):
                        # Reports folder
                        if file.endswith('.json'):
                            try:
                                file_size = os.path.getsize(file_path)
                                if file_size > 10 * 1024 * 1024:  # 10MB limit
                                    logger.warning(f"Skipping large report file {rel_path} ({file_size} bytes)")
                                    continue
                                
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    extracted_files['json_files'][rel_path_normalized] = data
                                    if 'summary' in rel_path_normalized:
                                        extracted_files['structure']['reports']['summary'] = data
                            except json.JSONDecodeError as e:
                                logger.warning(f"Invalid JSON in report file {rel_path}: {e}")
                            except MemoryError as e:
                                logger.error(f"Memory error loading report file {rel_path}: {e}")
                                raise
                            except Exception as e:
                                logger.warning(f"Failed to load JSON file {rel_path}: {e}")
                    
                    else:
                        # Other files
                        if file.endswith('.json'):
                            try:
                                file_size = os.path.getsize(file_path)
                                if file_size > 10 * 1024 * 1024:  # 10MB limit
                                    logger.warning(f"Skipping large JSON file {rel_path_normalized} ({file_size} bytes)")
                                    continue
                                
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    extracted_files['json_files'][rel_path_normalized] = data
                            except json.JSONDecodeError as e:
                                logger.warning(f"Invalid JSON in file {rel_path_normalized}: {e}")
                            except MemoryError as e:
                                logger.error(f"Memory error loading JSON file {rel_path_normalized}: {e}")
                                raise
                            except Exception as e:
                                logger.warning(f"Failed to load JSON file {rel_path_normalized}: {e}")
                        else:
                            extracted_files['other_files'].append({
                                'path': file_path,
                                'rel_path': rel_path_normalized,
                                'name': file
                            })
        
        logger.info(f"Extracted ZIP: {len(extracted_files['json_files'])} JSON, "
                   f"{len(extracted_files['images'])} images, "
                   f"{len(extracted_files['videos'])} videos")
        logger.info(f"Structure: Artifacts={bool(extracted_files['structure']['artifacts'])}, "
                   f"Metadata={bool(extracted_files['structure']['metadata'])}, "
                   f"Media={bool(extracted_files['structure']['media'])}")
        return extracted_files
    except zipfile.BadZipFile as e:
        logger.error(f"Invalid ZIP file format: {e}", exc_info=True)
        raise  # Re-raise to be caught by upload handler
    except MemoryError as e:
        logger.error(f"Memory error extracting ZIP file: {e}", exc_info=True)
        raise  # Re-raise to be caught by upload handler
    except Exception as e:
        logger.error(f"Failed to extract ZIP file: {e}", exc_info=True)
        raise  # Re-raise to be caught by upload handler

def normalize_zip_to_ufdr(extracted_files):
    """Convert extracted ZIP structure to UFDR format."""
    try:
        structure = extracted_files.get('structure', {})
        artifacts = structure.get('artifacts', {})
        metadata = structure.get('metadata', {})
        
        # Initialize UFDR structure
        ufdr_data = {
            'contacts': [],
            'messages': [],
            'call_logs': [],
            'device': {},
            'files': []
        }
    except Exception as e:
        logger.error(f"Error initializing UFDR structure: {e}")
        raise
    
    # Map Contacts
    try:
        if 'contacts' in artifacts:
            contacts = artifacts['contacts']
            if isinstance(contacts, list):
                ufdr_data['contacts'] = contacts
            else:
                ufdr_data['contacts'] = [contacts] if contacts else []
    except Exception as e:
        logger.warning(f"Error processing contacts: {e}")
        ufdr_data['contacts'] = []
    
    # Merge SMS and WhatsApp into messages
    messages = []
    try:
        if 'sms' in artifacts:
            sms_messages = artifacts['sms']
            if isinstance(sms_messages, list):
                for msg in sms_messages:
                    # Normalize message format: sender/message -> from/to/text
                    normalized_msg = dict(msg)
                    normalized_msg['source'] = 'SMS'
                    # Map sender -> from, receiver -> to
                    if 'sender' in normalized_msg and 'from' not in normalized_msg:
                        normalized_msg['from'] = normalized_msg['sender']
                    if 'receiver' in normalized_msg and 'to' not in normalized_msg:
                        normalized_msg['to'] = normalized_msg['receiver']
                    # Map content fields: message -> text, or ensure content exists
                    if 'message' in normalized_msg and 'text' not in normalized_msg:
                        normalized_msg['text'] = normalized_msg['message']
                    if 'content' in normalized_msg and 'text' not in normalized_msg:
                        normalized_msg['text'] = normalized_msg['content']
                    # Ensure at least one content field exists (validation requires text or content)
                    if 'text' not in normalized_msg and 'content' not in normalized_msg:
                        # Try to find any text-like field
                        for field in ['message', 'body', 'content', 'text_content']:
                            if field in normalized_msg and normalized_msg[field]:
                                normalized_msg['text'] = normalized_msg[field]
                                break
                        # If still no content, set empty string (validation checks 'is not None', not truthiness)
                        if 'text' not in normalized_msg:
                            normalized_msg['text'] = ''
                    # If no 'to' field, try to infer or set default
                    if 'to' not in normalized_msg and 'receiver' not in normalized_msg:
                        normalized_msg['to'] = 'Unknown'
                    # Ensure 'from' field exists (validation requires parties)
                    if 'from' not in normalized_msg and 'sender' not in normalized_msg:
                        normalized_msg['from'] = 'Unknown'
                    # Map timestamp fields: date, time, datetime -> timestamp
                    if 'timestamp' not in normalized_msg:
                        if 'date' in normalized_msg:
                            normalized_msg['timestamp'] = normalized_msg['date']
                        elif 'time' in normalized_msg:
                            normalized_msg['timestamp'] = normalized_msg['time']
                        elif 'datetime' in normalized_msg:
                            normalized_msg['timestamp'] = normalized_msg['datetime']
                        else:
                            # Add default timestamp if missing (required for validation)
                            normalized_msg['timestamp'] = 'Unknown'
                    messages.append(normalized_msg)
            elif sms_messages:
                normalized_msg = dict(sms_messages)
                normalized_msg['source'] = 'SMS'
                if 'sender' in normalized_msg and 'from' not in normalized_msg:
                    normalized_msg['from'] = normalized_msg['sender']
                if 'message' in normalized_msg and 'text' not in normalized_msg:
                    normalized_msg['text'] = normalized_msg['message']
                if 'to' not in normalized_msg and 'receiver' not in normalized_msg:
                    normalized_msg['to'] = 'Unknown'
                # Map timestamp fields
                if 'timestamp' not in normalized_msg:
                    if 'date' in normalized_msg:
                        normalized_msg['timestamp'] = normalized_msg['date']
                    elif 'time' in normalized_msg:
                        normalized_msg['timestamp'] = normalized_msg['time']
                    elif 'datetime' in normalized_msg:
                        normalized_msg['timestamp'] = normalized_msg['datetime']
                    else:
                        normalized_msg['timestamp'] = 'Unknown'
                messages.append(normalized_msg)
        
        if 'whatsapp' in artifacts:
            whatsapp_messages = artifacts['whatsapp']
            if isinstance(whatsapp_messages, list):
                for msg in whatsapp_messages:
                    # Normalize message format: sender/message -> from/to/text
                    normalized_msg = dict(msg)
                    normalized_msg['source'] = 'WhatsApp'
                    # Map sender -> from, receiver -> to
                    if 'sender' in normalized_msg and 'from' not in normalized_msg:
                        normalized_msg['from'] = normalized_msg['sender']
                    if 'receiver' in normalized_msg and 'to' not in normalized_msg:
                        normalized_msg['to'] = normalized_msg['receiver']
                    # Map content fields: message -> text, or ensure content exists
                    if 'message' in normalized_msg and 'text' not in normalized_msg:
                        normalized_msg['text'] = normalized_msg['message']
                    if 'content' in normalized_msg and 'text' not in normalized_msg:
                        normalized_msg['text'] = normalized_msg['content']
                    # Ensure at least one content field exists (validation requires text or content)
                    if 'text' not in normalized_msg and 'content' not in normalized_msg:
                        # Try to find any text-like field
                        for field in ['message', 'body', 'content', 'text_content']:
                            if field in normalized_msg and normalized_msg[field]:
                                normalized_msg['text'] = normalized_msg[field]
                                break
                        # If still no content, set empty string (validation checks 'is not None', not truthiness)
                        if 'text' not in normalized_msg:
                            normalized_msg['text'] = ''
                    # If no 'to' field, try to infer or set default
                    if 'to' not in normalized_msg and 'receiver' not in normalized_msg:
                        normalized_msg['to'] = 'Unknown'
                    # Ensure 'from' field exists (validation requires parties)
                    if 'from' not in normalized_msg and 'sender' not in normalized_msg:
                        normalized_msg['from'] = 'Unknown'
                    # Map timestamp fields: date, time, datetime -> timestamp
                    if 'timestamp' not in normalized_msg:
                        if 'date' in normalized_msg:
                            normalized_msg['timestamp'] = normalized_msg['date']
                        elif 'time' in normalized_msg:
                            normalized_msg['timestamp'] = normalized_msg['time']
                        elif 'datetime' in normalized_msg:
                            normalized_msg['timestamp'] = normalized_msg['datetime']
                        else:
                            # Add default timestamp if missing (required for validation)
                            normalized_msg['timestamp'] = 'Unknown'
                    messages.append(normalized_msg)
            elif whatsapp_messages:
                normalized_msg = dict(whatsapp_messages)
                normalized_msg['source'] = 'WhatsApp'
                if 'sender' in normalized_msg and 'from' not in normalized_msg:
                    normalized_msg['from'] = normalized_msg['sender']
                if 'message' in normalized_msg and 'text' not in normalized_msg:
                    normalized_msg['text'] = normalized_msg['message']
                if 'to' not in normalized_msg and 'receiver' not in normalized_msg:
                    normalized_msg['to'] = 'Unknown'
                # Map timestamp fields
                if 'timestamp' not in normalized_msg:
                    if 'date' in normalized_msg:
                        normalized_msg['timestamp'] = normalized_msg['date']
                    elif 'time' in normalized_msg:
                        normalized_msg['timestamp'] = normalized_msg['time']
                    elif 'datetime' in normalized_msg:
                        normalized_msg['timestamp'] = normalized_msg['datetime']
                    else:
                        normalized_msg['timestamp'] = 'Unknown'
                messages.append(normalized_msg)
    except Exception as e:
        logger.warning(f"Error processing messages: {e}")
        # Continue with whatever messages we have
    
    ufdr_data['messages'] = messages
    
    # Map Calls to call_logs and normalize format
    try:
        if 'calls' in artifacts:
            calls = artifacts['calls']
            if isinstance(calls, list):
                normalized_calls = []
                # Get device owner for call normalization
                try:
                    device_owner = metadata.get('device_info', {}).get('owner') or metadata.get('device_info', {}).get('device_owner') or 'Unknown'
                except Exception:
                    device_owner = 'Unknown'
                
                for call in calls:
                    if not isinstance(call, dict):
                        continue
                    
                    normalized_call = dict(call)
                    
                    # Convert ZIP format (number, type) to UFDR format (from, to)
                    if 'number' in call and 'type' in call:
                        call_type = call.get('type', '').lower()
                        number = call.get('number', '')
                        
                        if call_type == 'incoming':
                            # Incoming: from = number, to = device owner
                            normalized_call['from'] = number
                            normalized_call['to'] = device_owner
                        elif call_type == 'outgoing':
                            # Outgoing: from = device owner, to = number
                            normalized_call['from'] = device_owner
                            normalized_call['to'] = number
                        elif call_type == 'missed':
                            # Missed: treat as incoming for structure
                            normalized_call['from'] = number
                            normalized_call['to'] = device_owner
                        else:
                            # Unknown type: default to outgoing
                            normalized_call['from'] = device_owner
                            normalized_call['to'] = number
                        
                        # Keep original fields for reference
                        normalized_call['call_type'] = call_type
                        if 'number' not in normalized_call:
                            normalized_call['number'] = number
                    
                    # Ensure timestamp exists
                    if 'timestamp' not in normalized_call:
                        normalized_call['timestamp'] = call.get('timestamp', '')
                    
                    normalized_calls.append(normalized_call)
                
                ufdr_data['call_logs'] = normalized_calls
            else:
                ufdr_data['call_logs'] = [calls] if calls else []
    except Exception as e:
        logger.warning(f"Error processing calls: {e}")
        ufdr_data['call_logs'] = []
    
    # Combine device_info and case_info into device
    device_info = metadata.get('device_info', {})
    case_info = metadata.get('case_info', {})
    
    ufdr_data['device'] = {
        **device_info,
        **case_info,
        'extraction_time': device_info.get('extraction_time', ''),
        'device_model': device_info.get('device_model', ''),
        'imei': device_info.get('imei', ''),
        'device_owner': device_info.get('device_owner') or device_info.get('owner', ''),
        'case_id': case_info.get('case_id', ''),
        'officer': case_info.get('officer', ''),
        'notes': case_info.get('notes', '')
    }
    
    # Map Location data
    try:
        if 'location' in artifacts:
            locations = artifacts['location']
            if isinstance(locations, list):
                ufdr_data['locations'] = locations
            else:
                ufdr_data['locations'] = [locations] if locations else []
            logger.info(f"✅ Processed {len(ufdr_data['locations'])} location records")
    except Exception as e:
        logger.warning(f"Error processing location data: {e}")
        ufdr_data['locations'] = []
    
    # Also check json_files for location data (in case it wasn't in structure)
    try:
        json_files = extracted_files.get('json_files', {})
        for file_path, data in json_files.items():
            if 'Location' in file_path or 'location.json' in file_path:
                if isinstance(data, list):
                    if 'locations' not in ufdr_data or not ufdr_data['locations']:
                        ufdr_data['locations'] = data
                        logger.info(f"✅ Found location data in json_files: {len(data)} records")
                elif data:
                    if 'locations' not in ufdr_data or not ufdr_data['locations']:
                        ufdr_data['locations'] = [data]
                        logger.info(f"✅ Found location data in json_files: 1 record")
                break
    except Exception as e:
        logger.warning(f"Error checking json_files for location data: {e}")
    
    # Add summary if available
    if 'reports' in structure and 'summary' in structure['reports']:
        ufdr_data['summary'] = structure['reports']['summary']
    
    return ufdr_data

def truncate_for_context(text: str, max_tokens: int = 3000, reserved_tokens: int = 1000) -> str:
    """
    Truncate text to fit within model's context window.
    
    Args:
        text: Text to truncate
        max_tokens: Maximum tokens available (default 3000 leaves room for system message and response)
        reserved_tokens: Tokens to reserve for system message, query, and response
    
    Returns:
        Truncated text that fits within context window
    """
    # Rough estimation: 1 token ≈ 2.2 characters for English text
    # More conservative: use 2.0 to be safe
    chars_per_token = 2.0
    available_chars = int((max_tokens - reserved_tokens) * chars_per_token)
    
    if len(text) <= available_chars:
        return text
    
    # Truncate and add indicator
    truncated = text[:available_chars]
    # Try to truncate at a reasonable boundary (end of line or sentence)
    last_newline = truncated.rfind('\n')
    last_period = truncated.rfind('.')
    last_boundary = max(last_newline, last_period)
    
    if last_boundary > available_chars * 0.8:  # If we can find a good boundary
        truncated = text[:last_boundary + 1]
    
    return truncated + f"\n\n[Note: Data truncated to fit context window. Showing first {len(truncated)} characters of {len(text)} total.]"

def prepare_json_for_llm(ufdr_data, query, max_chars=8000):
    """
    Prepare JSON data for LLM to extract directly.
    
    This function sends JSON to the LLM instead of pre-extracted text,
    allowing the LLM to decide what data is relevant to the query.
    
    Args:
        ufdr_data: UFDR data dictionary
        query: User query (used to determine what data to prioritize)
        max_chars: Maximum characters to send (default 8000 ≈ 3000-4000 tokens)
    
    Returns:
        JSON string formatted for LLM consumption
    """
    import json
    
    # Create a copy to modify
    data_copy = dict(ufdr_data)
    
    # Remove internal metadata that LLM doesn't need
    data_copy.pop('_zip_info', None)
    data_copy.pop('_truncated', None)
    
    # Truncate large arrays based on query intent
    query_lower = query.lower() if query else ""
    
    # Determine query intent
    is_contact_query = any(word in query_lower for word in ['contact', 'name', 'phone', 'who', 'people', 'person'])
    is_message_query = any(word in query_lower for word in ['message', 'text', 'sms', 'chat', 'said', 'conversation', 'whatsapp'])
    is_call_query = any(word in query_lower for word in ['call', 'dial', 'phone', 'ring', 'spoke', 'duration'])
    
    # If no specific intent, use balanced limits
    if not any([is_contact_query, is_message_query, is_call_query]):
        is_contact_query = is_message_query = is_call_query = True
    
    # Apply intelligent truncation based on query intent
    # Limit arrays to reasonable sizes to stay within context window
    max_items_per_type = 100  # Reasonable limit per data type
    
    if 'contacts' in data_copy and isinstance(data_copy['contacts'], list):
        if not is_contact_query and len(data_copy['contacts']) > 20:
            data_copy['contacts'] = data_copy['contacts'][:20]
        elif len(data_copy['contacts']) > max_items_per_type:
            data_copy['contacts'] = data_copy['contacts'][:max_items_per_type]
    
    if 'messages' in data_copy and isinstance(data_copy['messages'], list):
        if not is_message_query and len(data_copy['messages']) > 50:
            data_copy['messages'] = data_copy['messages'][:50]
        elif len(data_copy['messages']) > max_items_per_type:
            data_copy['messages'] = data_copy['messages'][:max_items_per_type]
    
    if 'call_logs' in data_copy and isinstance(data_copy['call_logs'], list):
        if not is_call_query and len(data_copy['call_logs']) > 30:
            data_copy['call_logs'] = data_copy['call_logs'][:30]
        elif len(data_copy['call_logs']) > max_items_per_type:
            data_copy['call_logs'] = data_copy['call_logs'][:max_items_per_type]
    
    # Convert to JSON string with proper formatting
    try:
        json_str = json.dumps(data_copy, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        logger.warning(f"Error serializing JSON for LLM: {e}")
        # Fallback: try without ensure_ascii
        json_str = json.dumps(data_copy, indent=2, default=str)
    
    # Apply final truncation if needed
    original_length = len(json_str)
    if len(json_str) > max_chars:
        json_str = truncate_for_context(json_str, max_tokens=3500, reserved_tokens=1000)
        logger.warning(f"⚠️ JSON truncated from {original_length} to {len(json_str)} characters to fit context window")
    
    logger.info(f"Prepared JSON for LLM: {len(json_str)} characters")
    
    return json_str

def has_images_or_videos(data):
    """Check if data contains images or videos that need Qwen2.5-VL processing."""
    if isinstance(data, dict):
        # Check for ZIP info at top level (ACTIVE_DATA structure)
        if '_zip_info' in data:
            zip_info = data.get('_zip_info', {})
            if zip_info.get('is_zip'):
                if zip_info.get('images') or zip_info.get('videos'):
                    logger.info(f"Found images/videos in ZIP: {len(zip_info.get('images', []))} images, {len(zip_info.get('videos', []))} videos")
                    return True
        
        # Check each file's data (if data is a dict of files)
        for key, value in data.items():
            if key == '_zip_info':
                continue
            if isinstance(value, dict):
                # Check for ZIP info in file data
                if '_zip_info' in value:
                    zip_info = value.get('_zip_info', {})
                    if zip_info.get('is_zip'):
                        if zip_info.get('images') or zip_info.get('videos'):
                            logger.info(f"Found images/videos in file {key}: {len(zip_info.get('images', []))} images")
                            return True
                
                # Check for image references in messages
                for device in value.get('devices', [value]):
                    # Check messages for image attachments
                    for msg in device.get('messages', []):
                        if not isinstance(msg, dict):
                            continue
                        msg_str = str(msg).lower()
                        if 'image' in msg_str or 'photo' in msg_str:
                            return True
                        if 'attachment' in msg:
                            attachment = msg.get('attachment', '')
                            if attachment and any(ext in str(attachment).lower() 
                                                 for ext in ['.jpg', '.png', '.gif', '.mp4', '.avi']):
                                return True
    return False

def process_with_qwen_vl(query, data_src, chat_history=None):
    """Process query with Qwen2.5-VL-7B for multimodal analysis."""
    if not query:
        return None, "No query provided"
    
    model, processor = init_qwen_vl_model()
    
    if model is None or processor is None:
        return None, "Qwen2.5-VL-7B model not available"
    
    try:
        from PIL import Image
        import torch
        
        # Check for images/videos in ZIP
        # data_src can be a dict of files or a single data structure
        zip_info = {}
        images_to_process = []
        
        # Try to get zip_info from data_src directly (if it's a single data structure)
        if isinstance(data_src, dict) and '_zip_info' in data_src:
            zip_info = data_src.get('_zip_info', {})
        else:
            # data_src is a dict of files, check each file's data
            for filename, data in data_src.items():
                if isinstance(data, dict) and '_zip_info' in data:
                    zip_info = data.get('_zip_info', {})
                    break
        
        if zip_info.get('is_zip'):
            # Get images from ZIP
            images_list = zip_info.get('images', [])
            logger.info(f"Found {len(images_list)} images in ZIP file")
            for img_info in images_list[:5]:  # Limit to 5 images
                if not isinstance(img_info, dict):
                    continue
                img_path = img_info.get('path')
                if img_path and os.path.exists(img_path):
                    try:
                        img = Image.open(img_path)
                        images_to_process.append({
                            'image': img,
                            'name': img_info.get('name', 'unknown'),
                            'path': img_path
                        })
                        logger.info(f"Loaded image: {img_info.get('name', 'unknown')}")
                    except Exception as e:
                        logger.warning(f"Failed to load image {img_info.get('name', 'unknown')}: {e}")
                else:
                    logger.warning(f"Image path does not exist: {img_path}")
        
        # If no images found, check query for image-related keywords
        if not images_to_process:
            query_lower = query.lower() if query else ""
            if query_lower and any(word in query_lower for word in ['image', 'photo', 'picture', 'screenshot', 'video']):
                # Try to find images in data
                for filename, data in data_src.items():
                    if filename == '_zip_info':
                        continue
                    # Look for image paths in messages
                    for device in data.get('devices', [data]):
                        for msg in device.get('messages', []):
                            if 'image' in str(msg).lower() or 'photo' in str(msg).lower():
                                # Try to find image file
                                if zip_info.get('is_zip'):
                                    for img_info in zip_info.get('images', []):
                                        if os.path.exists(img_info['path']):
                                            try:
                                                img = Image.open(img_info['path'])
                                                images_to_process.append({
                                                    'image': img,
                                                    'name': img_info['name'],
                                                    'path': img_info['path']
                                                })
                                                break
                                            except:
                                                pass
        
        # Prepare messages for Qwen2.5-VL
        messages = []
        
        if images_to_process:
            # Add images to message - Qwen2.5-VL format
            content = [{"type": "text", "text": query}]
            for img_data in images_to_process:
                content.append({"type": "image", "image": img_data['image']})
            
            messages.append({
                "role": "user",
                "content": content
            })
        else:
            # Text-only query
            messages.append({
                "role": "user",
                "content": query
            })
        
        # Process with Qwen2.5-VL processor
        # Qwen2.5-VL uses messages format with images embedded
        try:
            # Apply chat template (this handles the messages format)
            text = processor.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            
            # Extract images from messages
            image_list = []
            if images_to_process:
                image_list = [img_data['image'] for img_data in images_to_process]
            
            # Prepare inputs - Qwen2.5-VL processor accepts text and images separately
            if image_list:
                inputs = processor(
                    text=[text],
                    images=image_list,
                    padding=True,
                    return_tensors="pt"
                ).to(model.device)
            else:
                # Text-only
                inputs = processor(
                    text=[text],
                    padding=True,
                    return_tensors="pt"
                ).to(model.device)
        except Exception as e:
            logger.error(f"Error preparing inputs for Qwen2.5-VL: {e}")
            raise
        
        # Generate response
        with torch.no_grad():
            outputs = model.generate(**inputs, max_new_tokens=512, do_sample=False)
        
        # Decode response
        response = processor.batch_decode(outputs, skip_special_tokens=True, clean_up_tokenization_spaces=False)[0]
        
        # Extract just the assistant's response
        if "assistant\n" in response:
            response = response.split("assistant\n")[-1].strip()
        
        return response, None
        
    except Exception as e:
        logger.error(f"Error processing with Qwen2.5-VL: {e}")
        return None, str(e)

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_uploaded_files():
    """Load existing uploaded files into ACTIVE_DATA on startup."""
    global ACTIVE_DATA, ACTIVE_FILENAME, enhanced_nl_engine, ai_retrieval_engine, ACTIVE_DATA_LAYERS, ACTIVE_DB_PATHS
    
    loaded_count = 0
    
    # Remove any existing XML files and their .db files on startup
    # DISABLED for Docker persistence: this was deleting XML files on every
    # container restart, breaking session restore (stats stayed at 0 after
    # relaunch because the source XML/db was wiped even though the parsed
    # session record survived). Original cleanup logic preserved below,
    # commented out.

    # if os.path.exists(UPLOAD_FOLDER):
    #     xml_files_removed = []
    #     for filename in os.listdir(UPLOAD_FOLDER):
    #         if filename.endswith('.xml') or filename.endswith('.xml.encrypted'):
    #             try:
    #                 file_path = os.path.join(UPLOAD_FOLDER, filename)
    #                 os.remove(file_path)
    #                 xml_files_removed.append(filename)
    #                 logger.info(f"🗑️ Removed existing XML file: {filename}")
                    
    #                 # Also remove associated .db file
    #                 db_file = filename + '.db'
    #                 db_path = os.path.join(UPLOAD_FOLDER, db_file)
    #                 if os.path.exists(db_path):
    #                     os.remove(db_path)
    #                     logger.info(f"🗑️ Removed associated database file: {db_file}")
    #             except Exception as e:
    #                 logger.warning(f"Failed to remove XML file {filename}: {e}")
        
    #     if xml_files_removed:
    #         logger.info(f"✅ Removed {len(xml_files_removed)} existing XML file(s) on startup")
    
    # Load JSON files only (not XML - XML files use data layers)
    if os.path.exists(UPLOAD_FOLDER):
        for filename in os.listdir(UPLOAD_FOLDER):
            # Skip encrypted files, XML files, and .db files
            if filename.endswith('.encrypted') or filename.endswith('.xml') or filename.endswith('.db'):
                continue
            if filename.endswith('.json'):
                try:
                    file_path = os.path.join(UPLOAD_FOLDER, filename)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        
                        ACTIVE_DATA[filename] = data
                        ACTIVE_FILENAME = filename
                        loaded_count += 1
                        
                        # Update engines with loaded data
                        nl_engine.update_data(ACTIVE_DATA)
                        enhanced_nl_engine = EnhancedNaturalLanguageUFDR(ACTIVE_DATA)
                        ai_retrieval_engine = AIUFDRRetrievalEngine(ACTIVE_DATA)
                        
                except Exception as e:
                    logger.error(f"Error loading {filename}: {e}")
                    continue
    
    return loaded_count

# Authentication helper functions
def ensure_auth_db_schema(conn):
    """
    Ensure the authentication DB has the required schema.
    This prevents runtime errors like: "no such table: users"
    when the web UI creates new accounts.
    """
    if not conn:
        return

    try:
        cur = conn.cursor()

        # Base schema (matches Authentication/app.py)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active INTEGER DEFAULT 1
            )
        """)

        # RBAC expects this column. If it's missing, add it.
        cur.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cur.fetchall()]
        if 'role' not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'investigator'")

        # Create login_logs for completeness (some flows may rely on it).
        cur.execute("""
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id),
                email TEXT,
                login_attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success INTEGER,
                ip_address TEXT
            )
        """)

        conn.commit()
        cur.close()
    except Exception as e:
        logger.warning(f"Auth DB schema initialization failed: {e}")

def get_auth_db_connection():
    """Create and return authentication database connection"""
    try:
        conn = sqlite3.connect(AUTH_DB_PATH)
        conn.row_factory = sqlite3.Row
        ensure_auth_db_schema(conn)
        return conn
    except sqlite3.Error as e:
        logger.error(f"Auth database connection error: {e}")
        return None

def load_user_profile_data(user_id=None):
    """Load user profile data from database and update session
    This ensures profile data persists across server restarts, similar to case restoration
    """
    if not user_id:
        user_id = session.get('user_id')
    
    if not user_id:
        return {}
    
    try:
        conn = sqlite3.connect(AUTH_DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # First, check which columns exist
        cur.execute("PRAGMA table_info(users)")
        columns_info = cur.fetchall()
        available_columns = [col[1] for col in columns_info]
        
        # Build SELECT query with only existing columns
        base_columns = ['first_name', 'last_name', 'email', 'username']
        optional_columns = ['phone', 'location', 'bio', 'profile_picture']
        
        select_columns = base_columns.copy()
        for col in optional_columns:
            if col in available_columns:
                select_columns.append(col)
        
        # Get all profile fields (only columns that exist)
        query = f"SELECT {', '.join(select_columns)} FROM users WHERE id = ?"
        cur.execute(query, (user_id,))
        user = cur.fetchone()
        
        if user:
            # Row objects don't have .get() method, access directly and handle None
            profile_data = {
                'first_name': user['first_name'] if user['first_name'] else '',
                'last_name': user['last_name'] if user['last_name'] else '',
                'email': user['email'] if user['email'] else '',
                'username': user['username'] if user['username'] else '',
            }
            
            # Add optional fields only if they exist in the result
            for col in optional_columns:
                if col in available_columns:
                    try:
                        profile_data[col] = user[col] if user[col] else ''
                    except (KeyError, IndexError):
                        profile_data[col] = ''
                else:
                    profile_data[col] = ''
            
            # Update session with profile data (ensures persistence)
            session['username'] = profile_data['username']
            session['email'] = profile_data['email']
            session['name'] = f"{profile_data['first_name']} {profile_data['last_name']}".strip()
            session['phone'] = profile_data['phone']
            session['location'] = profile_data['location']
            session['bio'] = profile_data['bio']
            session['profile_picture'] = profile_data['profile_picture']
            
            logger.info(f"Loaded profile data for user {user_id}, profile_picture: {profile_data['profile_picture'] or 'None'}")
            
            cur.close()
            conn.close()
            return profile_data
        else:
            cur.close()
            conn.close()
            return {}
    except Exception as e:
        logger.warning(f"Error loading user profile data: {e}")
        return {}

def login_required(f):
    """Decorator to require login for routes (bypassed in DEV_MODE)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip authentication in development mode
        if DEV_MODE:
            # Set default session values for dev mode
            if 'user_id' not in session:
                session['user_id'] = 1
                session['username'] = 'dev_user'
                session['email'] = 'dev@example.com'
                session['name'] = 'Development User'
            return f(*args, **kwargs)
        
        # Normal authentication check
        if 'user_id' not in session:
            logger.warning(f"Access denied to {request.path}: No user_id in session")
            flash('Please log in to access this page.', 'warning')
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def generate_captcha():
    """Generate a simple CAPTCHA"""
    import random
    import string
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    captcha_id = secrets.token_hex(8)
    captcha_storage[captcha_id] = captcha_text
    return captcha_id, captcha_text

def verify_captcha(captcha_id, user_input):
    """Verify CAPTCHA input"""
    if captcha_id not in captcha_storage:
        return False
    stored_captcha = captcha_storage.pop(captcha_id)
    return stored_captcha.upper() == user_input.upper()

@app.route('/auth', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page - redirects to Case Manager in DEV_MODE"""
    # If already logged in, redirect to dashboard (prevent redirect loop)
    if 'user_id' in session and not DEV_MODE:
        logger.info(f"User {session.get('user_id')} already logged in, redirecting to dashboard")
        return redirect('/case-manager')
    elif 'user_id' in session and DEV_MODE:
        # In DEV_MODE, redirect to chat interface
        return redirect(url_for('index'))
    
    # In development mode, skip login and go straight to chat interface
    if DEV_MODE:
        # Set default session values for dev mode
        if 'user_id' not in session:
            session['user_id'] = 1
            session['username'] = 'dev_user'
            session['email'] = 'dev@example.com'
            session['name'] = 'Development User'
        # Redirect to chat interface instead of Case Manager
        return redirect(url_for('index'))  # index() is the /evi-scan route
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        captcha_id = request.form.get('captcha_id', '')
        captcha_input = request.form.get('captcha', '').strip()
        
        if not verify_captcha(captcha_id, captcha_input):
            flash('Invalid CAPTCHA. Please try again.', 'error')
            captcha_id, captcha_text = generate_captcha()
            return render_template('auth.html', captcha_id=captcha_id, captcha_text=captcha_text)
        
        conn = get_auth_db_connection()
        if not conn:
            flash('Database connection error.', 'error')
            captcha_id, captcha_text = generate_captcha()
            return render_template('auth.html', captcha_id=captcha_id, captcha_text=captcha_text)
        
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE email = ? AND is_active = 1", (email,))
            user = cur.fetchone()
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                # Set session variables
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['email'] = user['email']
                session['name'] = f"{user['first_name']} {user['last_name']}"
                session.permanent = True  # Make session persistent
                
                # Load all profile data from database (phone, location, bio, profile_picture)
                # This ensures profile data persists across server restarts
                try:
                    cur.execute("PRAGMA table_info(users)")
                    columns = [row[1] for row in cur.fetchall()]
                    
                    # Load profile fields if they exist (user is a Row object, access by column name)
                    if 'phone' in columns:
                        session['phone'] = user['phone'] if user['phone'] else ''
                    if 'location' in columns:
                        session['location'] = user['location'] if user['location'] else ''
                    if 'bio' in columns:
                        session['bio'] = user['bio'] if user['bio'] else ''
                    if 'profile_picture' in columns:
                        session['profile_picture'] = user['profile_picture'] if user['profile_picture'] else ''
                        logger.info(f"Loaded profile_picture for user {user['id']}: {session.get('profile_picture', 'None')}")
                except Exception as profile_error:
                    logger.warning(f"Error loading profile data: {profile_error}")
                    # Fallback: try to load profile picture directly
                    try:
                        cur.execute("SELECT profile_picture FROM users WHERE id = ?", (user['id'],))
                        pic_row = cur.fetchone()
                        if pic_row and pic_row['profile_picture']:
                            session['profile_picture'] = pic_row['profile_picture']
                            logger.info(f"Loaded profile_picture via fallback: {session.get('profile_picture')}")
                    except Exception as fallback_error:
                        logger.warning(f"Fallback profile picture load failed: {fallback_error}")
                
                # Commit session before redirect
                try:
                    session.modified = True
                except:
                    pass
                
                cur.execute("UPDATE users SET last_login = ? WHERE id = ?", (datetime.now(), user['id']))
                conn.commit()
                
                # Get user role for audit logging
                user_role = 'investigator'  # Default
                if SECURITY_AVAILABLE:
                    try:
                        cur.execute("PRAGMA table_info(users)")
                        columns = [row[1] for row in cur.fetchall()]
                        if 'role' in columns:
                            cur.execute("SELECT role FROM users WHERE id = ?", (user['id'],))
                            role_row = cur.fetchone()
                            if role_row and role_row[0]:
                                user_role = role_row[0]
                    except:
                        pass
                
                cur.close()
                conn.close()
                
                logger.info(f"User {user['email']} (ID: {user['id']}) logged in successfully")
                logger.info(f"Session data: user_id={session.get('user_id')}, username={session.get('username')}")
                
                # Audit logging: Log login event
                if SECURITY_AVAILABLE and audit_logger:
                    audit_logger.log_action('login', resource=f"user_{user['id']}", success=True,
                                          details={
                                              'email': user['email'],
                                              'username': user['username'],
                                              'role': user_role,
                                              'ip_address': request.remote_addr
                                          })
                
                flash('Login successful!', 'success')
                
                # Redirect to Case Manager after login (or chat in DEV_MODE)
                if DEV_MODE:
                    return redirect(url_for('index'))  # Chat interface
                return redirect('/case-manager')
            else:
                # Audit logging: Log failed login attempt
                if SECURITY_AVAILABLE and audit_logger:
                    audit_logger.log_action('login', resource=f"email_{email}", success=False,
                                          details={
                                              'reason': 'invalid_credentials',
                                              'ip_address': request.remote_addr
                                          })
                flash('Invalid email or password.', 'error')
                captcha_id, captcha_text = generate_captcha()
                return render_template('auth.html', captcha_id=captcha_id, captcha_text=captcha_text)
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An error occurred. Please try again.', 'error')
            captcha_id, captcha_text = generate_captcha()
            return render_template('auth.html', captcha_id=captcha_id, captcha_text=captcha_text)
    
    captcha_id, captcha_text = generate_captcha()
    return render_template('auth.html', captcha_id=captcha_id, captcha_text=captcha_text)

def validate_password(password):
    """Validate password requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Signup page with password validation"""
    # If already logged in, redirect to dashboard (or chat in DEV_MODE)
    if 'user_id' in session:
        if DEV_MODE:
            return redirect(url_for('index'))  # Chat interface
        return redirect('/case-manager')
    
    if request.method == 'POST':
        first_name = request.form.get('firstName', '').strip()
        last_name = request.form.get('lastName', '').strip()
        email = request.form.get('email', '').strip().lower()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirmPassword', '')
        terms_accepted = request.form.get('termsCheck') == 'on'
        
        # Validate all fields
        errors = []
        if not first_name:
            errors.append('First name is required')
        if not last_name:
            errors.append('Last name is required')
        if not email or '@' not in email:
            errors.append('Valid email is required')
        if not username or len(username) < 4:
            errors.append('Username must be at least 4 characters')
        if password != confirm_password:
            errors.append('Passwords do not match')
        
        # Validate password requirements
        is_valid, password_error = validate_password(password)
        if not is_valid:
            errors.append(password_error)
        
        if not terms_accepted:
            errors.append('You must accept the terms and conditions')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth.html')
        
        # Check if email or username already exists
        conn = get_auth_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return render_template('auth.html')
        
        try:
            cur = conn.cursor()
            cur.execute("SELECT email FROM users WHERE email = ?", (email,))
            if cur.fetchone():
                flash('Email already registered.', 'error')
                cur.close()
                conn.close()
                return render_template('auth.html')
            
            cur.execute("SELECT username FROM users WHERE username = ?", (username,))
            if cur.fetchone():
                flash('Username already taken.', 'error')
                cur.close()
                conn.close()
                return render_template('auth.html')
            
            # Hash password with bcrypt
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Insert new user - explicitly set role to 'investigator' (default)
            # Check if role column exists
            cur.execute("PRAGMA table_info(users)")
            columns = [row[1] for row in cur.fetchall()]
            has_role_column = 'role' in columns
            
            if has_role_column:
                cur.execute("""
                    INSERT INTO users (first_name, last_name, email, username, password_hash, role)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (first_name, last_name, email, username, password_hash, 'investigator'))
            else:
                # Role column doesn't exist yet, insert without it (will be added by migration)
                cur.execute("""
                    INSERT INTO users (first_name, last_name, email, username, password_hash)
                    VALUES (?, ?, ?, ?, ?)
                """, (first_name, last_name, email, username, password_hash))
            
            user_id = cur.lastrowid
            conn.commit()
            
            # Audit logging: Log user creation
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('user_created', resource=f"user_{user_id}", success=True,
                                      details={
                                          'email': email,
                                          'username': username,
                                          'role': 'investigator',
                                          'created_by': 'signup'
                                      })
            
            cur.close()
            conn.close()
            
            logger.info(f"New user created: {email} (ID: {user_id}) with role: investigator")
            flash('Account created successfully! Please log in.', 'success')
            # Redirect to auth page with login tab active
            return redirect('/auth#login')
            
        except Exception as e:
            logger.error(f"Signup error: {e}")
            conn.rollback()
            cur.close()
            conn.close()
            flash(f'An error occurred: {str(e)}', 'error')
            return render_template('auth.html')
    
    # GET request - show signup form
    return render_template('auth.html')

@app.route('/logout')
@login_required
def logout():
    """Logout user and clear session"""
    # Audit logging: Log logout event before clearing session
    if SECURITY_AVAILABLE and audit_logger and 'user_id' in session:
        user_id = session.get('user_id')
        username = session.get('username', 'unknown')
        email = session.get('email', 'unknown')
        audit_logger.log_action('logout', resource=f"user_{user_id}", success=True,
                              details={
                                  'email': email,
                                  'username': username,
                                  'ip_address': request.remote_addr
                              })
    
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def root():
    """Root route - redirects to case manager (or chat in DEV_MODE)"""
    if DEV_MODE:
        # In DEV_MODE, skip Case Manager and go directly to chat interface
        return redirect(url_for('index'))  # index() is the /evi-scan route
    return redirect(url_for('case_manager'))

@app.route('/case-manager')
@login_required
def case_manager():
    """Case Manager UI - Main landing page after login (disabled in DEV_MODE)"""
    # In DEV_MODE, redirect to chat interface instead
    if DEV_MODE:
        logger.info("DEV_MODE: Case Manager disabled, redirecting to chat interface")
        return redirect(url_for('index'))  # index() is the /evi-scan route
    
    # Debug: Check session
    if 'user_id' not in session:
        logger.warning("No user_id in session when accessing case_manager")
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))
    
    logger.info(f"Case manager accessed by user {session.get('user_id')} ({session.get('email')})")
    
    # Get user role for template
    user_role = 'investigator'  # Default
    can_view_audit_logs = False
    can_manage_users = False
    
    if SECURITY_AVAILABLE:
        try:
            user_role = RBAC.get_user_role()
            can_view_audit_logs = RBAC.has_permission('view_audit_logs')
            can_manage_users = RBAC.has_permission('manage_users')
        except Exception as e:
            logger.warning(f"Error getting user role for template: {e}")
    
    # Get user profile data for settings - load from database to ensure persistence across server restarts
    user_id = session.get('user_id')
    user_profile_data = load_user_profile_data(user_id) if user_id else {}
    
    # Ensure all expected fields exist in user_profile_data for template
    if not user_profile_data:
        user_profile_data = {}
    
    # Fill in missing fields from session or set defaults
    user_profile_data.setdefault('first_name', session.get('name', '').split()[0] if session.get('name') else '')
    user_profile_data.setdefault('last_name', session.get('name', '').split()[-1] if len(session.get('name', '').split()) > 1 else '')
    user_profile_data.setdefault('email', session.get('email', ''))
    user_profile_data.setdefault('username', session.get('username', ''))
    user_profile_data.setdefault('phone', session.get('phone', ''))
    user_profile_data.setdefault('location', session.get('location', ''))
    user_profile_data.setdefault('bio', session.get('bio', ''))
    user_profile_data.setdefault('profile_picture', session.get('profile_picture', ''))
    
    # Ensure profile_picture is loaded from session if not in user_profile_data
    profile_picture = user_profile_data.get('profile_picture', '') or session.get('profile_picture', '')
    if not profile_picture and user_id:
        # Last resort: try to load just the profile_picture column
        try:
            conn = sqlite3.connect(AUTH_DB_PATH)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            # Check if profile_picture column exists
            cur.execute("PRAGMA table_info(users)")
            columns = [row[1] for row in cur.fetchall()]
            if 'profile_picture' in columns:
                cur.execute("SELECT profile_picture FROM users WHERE id = ?", (user_id,))
                pic_row = cur.fetchone()
                if pic_row and pic_row['profile_picture']:
                    profile_picture = pic_row['profile_picture']
                    session['profile_picture'] = profile_picture
                    logger.info(f"Loaded profile_picture directly for user {user_id}: {profile_picture}")
            cur.close()
            conn.close()
        except Exception as e:
            logger.warning(f"Error loading profile_picture directly: {e}")
    
    return render_template('case_manager/case_manager.html',
                         username=session.get('username', 'User'),
                         name=session.get('name', 'Forensic Analyst'),
                         email=session.get('email', ''),
                         first_name=user_profile_data.get('first_name', ''),
                         last_name=user_profile_data.get('last_name', ''),
                         phone=user_profile_data.get('phone', ''),
                         location=user_profile_data.get('location', ''),
                         bio=user_profile_data.get('bio', ''),
                         profile_picture=profile_picture,
                         user_role=user_role,
                         can_view_audit_logs=can_view_audit_logs,
                         can_manage_users=can_manage_users)

@app.route('/evi-scan')
@login_required
def index():
    """Main page with the web interface - requires login (or dev mode)"""
    # Declare global variables at the top of the function
    global ACTIVE_FILENAME, ACTIVE_DATA, enhanced_nl_engine, ai_retrieval_engine, ACTIVE_DATA_LAYERS, ACTIVE_DB_PATHS
    
    # In DEV_MODE, start with no files preloaded - clear everything for fresh start
    if DEV_MODE:
        logger.info("🔧 DEV_MODE: Starting with no files preloaded - clearing all data")
        ACTIVE_DATA = {}
        ACTIVE_FILENAME = None
        ACTIVE_DATA_LAYERS = {}
        ACTIVE_DB_PATHS = {}
        # Clear session_id to prevent any restoration
        if 'session_id' in session:
            del session['session_id']
        if 'case_id' in session:
            del session['case_id']
        # Update engines with empty data
        try:
            nl_engine.update_data(ACTIVE_DATA)
            enhanced_nl_engine = EnhancedNaturalLanguageUFDR(ACTIVE_DATA)
            ai_retrieval_engine = AIUFDRRetrievalEngine(ACTIVE_DATA)
            rebuild_rag_index()
        except Exception as e:
            logger.warning(f"Error clearing engines in DEV_MODE: {e}")
        # Render with empty state
        return render_template('enhanced_index.html',
                             username='dev_user',
                             name='Development User',
                             email='dev@example.com',
                             profile_picture='',
                             session_id=None,
                             case_id=None,
                             case_name=None)
    
    # Check for session_id in URL query params
    session_id_from_url = request.args.get('session_id')
    case_info = None
    
    # Get current user ID for security
    user_id = session.get('user_id')
    
    # Check if this is a brand new session (no chat history) - if so, clear ACTIVE_DATA
    is_new_session = False
    if session_id_from_url and SESSION_DB_AVAILABLE:
        # Restore session from database (filtered by user_id for security)
        sess = get_session(session_id_from_url, user_id=user_id) if user_id else get_session(session_id_from_url)
        if sess:
            # Verify session belongs to current user (skip in DEV_MODE)
            if user_id and sess.get('user_id') != user_id and not DEV_MODE:
                flash('Access denied: This session does not belong to you.', 'error')
                return redirect(url_for('case_manager'))
            # Store in Flask session
            session['session_id'] = session_id_from_url
            case_id = sess.get('case_id')
            if case_id:
                session['case_id'] = case_id
                # Get case information to display in EVI
                case_info = get_case(case_id)
            # Load chat history from current session AND related sessions (same case)
            # This provides context continuity across multiple sessions for the same case
            chat_history = get_chat_history(session_id_from_url)
            related_chat_history = []
            
            if SESSION_DB_AVAILABLE:
                # Get chat history from related sessions (same case) for context
                related_chat_history = get_chat_history_from_related_sessions(
                    session_id_from_url, 
                    include_current=False,  # Don't duplicate current session's history
                    limit_per_session=50  # Limit per session to avoid token bloat
                )
                logger.info(f"📜 Current session: {len(chat_history)} messages, Related sessions: {len(related_chat_history)} messages")
            
            # Merge histories: related sessions first (chronological), then current session
            # This maintains chronological order while prioritizing current session
            all_chat_history = related_chat_history + chat_history
            
            # Check if session has files in database FIRST (files indicate it's not a brand new session)
            session_files = []
            if SESSION_DB_AVAILABLE:
                session_files = get_session_files(session_id_from_url)
                logger.info(f"📁 Checking session {session_id_from_url}: {len(session_files)} file(s) in database, {len(all_chat_history)} total chat message(s) (current: {len(chat_history)}, related: {len(related_chat_history)})")
            
            # If session has files, restore it (it's an existing session)
            # Note: We only restore if there are actual files, not just chat history
            # This ensures "Create New Session" truly starts fresh
            if session_files:
                # Existing session - restore uploaded files into ACTIVE_DATA
                logger.info(f"🔄 Restoring existing session {session_id_from_url} - loading session files into ACTIVE_DATA")
                ACTIVE_DATA = {}
                ACTIVE_FILENAME = None
                
                # Load only files that belong to this session
                if session_files and os.path.exists(UPLOAD_FOLDER):
                    loaded_files = []
                    for file_record in session_files:
                        filename = file_record['filename']
                        
                        # Skip XML files - they use data layers, not ACTIVE_DATA
                        if filename.endswith('.xml') or filename.replace('.encrypted', '').endswith('.xml'):
                            logger.info(f"⏭️ Skipping XML file {filename} during session restoration - XML files use data layers")
                            continue
                        
                        file_path_recorded = file_record.get('file_path', filename)
                        # Use recorded path or fallback to UPLOAD_FOLDER
                        if os.path.isabs(file_path_recorded) and os.path.exists(file_path_recorded):
                            file_path = file_path_recorded
                        else:
                            file_path = os.path.join(UPLOAD_FOLDER, filename)
                        
                        # Check if file exists (try both encrypted and unencrypted versions)
                        is_encrypted = False
                        original_filename = filename  # Keep original for logging
                        if not os.path.exists(file_path):
                            # Try encrypted version
                            encrypted_path = file_path + '.encrypted'
                            if os.path.exists(encrypted_path):
                                file_path = encrypted_path
                                filename = filename + '.encrypted'  # Update filename to include .encrypted
                                is_encrypted = True
                                logger.info(f"🔐 Found encrypted version: {original_filename} → {filename}")
                                # Update database record to reflect encrypted filename (if session_db available)
                                if SESSION_DB_AVAILABLE and session_id_from_url:
                                    try:
                                        # Delete old record and create new one with encrypted filename
                                        delete_session_file(session_id_from_url, original_filename)
                                        save_session_file(session_id_from_url, filename, file_path)
                                        logger.info(f"📝 Updated database record: {original_filename} → {filename}")
                                    except Exception as db_update_error:
                                        logger.warning(f"⚠️ Could not update database record: {db_update_error}")
                            else:
                                logger.warning(f"File {filename} not found at {file_path} or {encrypted_path}, skipping")
                            continue
                        else:
                            # File exists, check if it's encrypted by checking if filename ends with .encrypted
                            is_encrypted = filename.endswith('.encrypted') or file_path.endswith('.encrypted')
                        
                        try:
                            # Ensure is_encrypted flag is set correctly
                            if not is_encrypted:
                                is_encrypted = file_path.endswith('.encrypted') or filename.endswith('.encrypted')
                            temp_decrypted_path = None
                            
                            # If encrypted, decrypt it first
                            if is_encrypted and SECURITY_AVAILABLE and encryption:
                                try:
                                    logger.info(f"🔓 Decrypting encrypted file: {filename}")
                                    # Read encrypted content
                                    with open(file_path, 'rb') as f:
                                        encrypted_content = f.read()
                                    
                                    # Decrypt content
                                    decrypted_content = encryption.cipher.decrypt(encrypted_content)
                                    
                                    # Create temporary decrypted file for processing
                                    temp_decrypted_path = file_path.replace('.encrypted', '')
                                    with open(temp_decrypted_path, 'wb') as f:
                                        f.write(decrypted_content)
                                    
                                    # Use temp decrypted file for processing
                                    file_path = temp_decrypted_path
                                    logger.info(f"✅ File decrypted for restoration: {filename}")
                                except Exception as decrypt_error:
                                    error_type = type(decrypt_error).__name__
                                    if "InvalidSignature" in error_type or "InvalidToken" in error_type:
                                        logger.error(f"❌ CRITICAL: Cannot decrypt file {filename} - Wrong encryption key!")
                                        logger.error(f"   The encryption key used to encrypt this file is different from the current key.")
                                        logger.error(f"   Possible causes:")
                                        logger.error(f"   1. Encryption key changed between server restarts")
                                        logger.error(f"   2. File was encrypted with a different key")
                                        logger.error(f"   3. File data is corrupted")
                                        logger.error(f"   Solution: Ensure ENCRYPTION_KEY environment variable is set, or restore .encryption_key file")
                                    else:
                                        logger.error(f"❌ Error decrypting file {filename} during restore: {decrypt_error}", exc_info=True)
                                    # Skip this file but continue with others
                                    continue
                            
                            # Handle ZIP files (including .ufdr files which are ZIP archives) - use hybrid parser (same as upload) for consistent extraction
                            is_zip_file = filename.endswith('.zip') or filename.endswith('.ufdr') or \
                                         (is_encrypted and (filename.replace('.encrypted', '').endswith('.zip') or 
                                                          filename.replace('.encrypted', '').endswith('.ufdr')))
                            if is_zip_file:
                                try:
                                    logger.info(f"📦 Restoring ZIP file {filename} using hybrid parser...")
                                    
                                    # Check if we have a stored extraction path for this session
                                    stored_extract_path = None
                                    if SESSION_DB_AVAILABLE and session_id_from_url:
                                        try:
                                            sess = get_session(session_id_from_url)
                                            if sess and sess.get('metadata'):
                                                metadata = sess.get('metadata')
                                                if isinstance(metadata, dict):
                                                    stored_extract_path = metadata.get('zip_extraction_path')
                                                    if stored_extract_path and os.path.exists(stored_extract_path):
                                                        logger.info(f"📂 Found stored extraction path: {stored_extract_path}")
                                                    else:
                                                        logger.info(f"⚠️ Stored extraction path does not exist: {stored_extract_path}, will re-extract")
                                        except Exception as meta_error:
                                            logger.debug(f"Could not retrieve stored extraction path: {meta_error}")
                                    
                                    # Use stored path if available and valid, otherwise extract fresh
                                    # Pass session_id to ensure persistent extraction
                                    extracted = extract_zip_with_hybrid_parser(file_path, extract_to=stored_extract_path)
                                    
                                    if extracted:
                                        # Check if hybrid parser already normalized it
                                        if 'hybrid_parsed' in extracted:
                                            # Hybrid parser already normalized, use directly
                                            ufdr_data = extracted['ufdr_data']
                                            logger.info(f"✅ Using hybrid parser normalized data for restore. Contacts: {len(ufdr_data.get('contacts', []))}, Messages: {len(ufdr_data.get('messages', []))}, Calls: {len(ufdr_data.get('call_logs', []))}")
                                        else:
                                            # Standard parser - need normalization
                                            ufdr_data = normalize_zip_to_ufdr(extracted)
                                            logger.info(f"✅ Using standard parser normalized data for restore. Contacts: {len(ufdr_data.get('contacts', []))}, Messages: {len(ufdr_data.get('messages', []))}, Calls: {len(ufdr_data.get('call_logs', []))}")
                                        
                                        if ufdr_data:
                                            # Store ZIP info with images/videos (same structure as upload)
                                            extract_path = extracted.get('extract_path', '')
                                            zip_info = {
                                                'is_zip': True,
                                                'extracted_path': extract_path,
                                                'images': extracted.get('images', []),
                                                'videos': extracted.get('videos', []),
                                                'json_files': list(extracted.get('json_files', {}).keys()) if isinstance(extracted.get('json_files'), dict) else []
                                            }
                                            logger.info(f"📦 ZIP info for restore: {len(zip_info.get('images', []))} images, {len(zip_info.get('videos', []))} videos, extract_path: {extract_path}")
                                            
                                            # Store extraction path in session metadata for future restores
                                            if SESSION_DB_AVAILABLE and extract_path and session_id_from_url:
                                                try:
                                                    sess = get_session(session_id_from_url)
                                                    if sess:
                                                        metadata = sess.get('metadata', {})
                                                        if not isinstance(metadata, dict):
                                                            metadata = {}
                                                        metadata['zip_extraction_path'] = extract_path
                                                        metadata['zip_filename'] = filename
                                                        # Update session metadata
                                                        import json
                                                        from session_db import create_session
                                                        create_session(session_id_from_url, 
                                                                      case_id=sess.get('case_id'),
                                                                      title=sess.get('title'),
                                                                      metadata=metadata,
                                                                      user_id=sess.get('user_id'))
                                                        logger.info(f"💾 Stored extraction path {extract_path} in session metadata")
                                                except Exception as meta_error:
                                                    logger.debug(f"Could not store extraction path: {meta_error}")
                                            
                                            # Use encrypted filename if file was encrypted, otherwise use original
                                            restore_filename = filename
                                            ACTIVE_DATA[restore_filename] = ufdr_data
                                            ACTIVE_DATA['_zip_info'] = zip_info
                                            ACTIVE_FILENAME = restore_filename
                                            loaded_files.append(restore_filename)
                                            logger.info(f"✅ Restored ZIP file {restore_filename} into ACTIVE_DATA with {len(zip_info.get('images', []))} images")
                                except Exception as zip_error:
                                    logger.error(f"❌ Error extracting/normalizing ZIP file {filename} during restore: {zip_error}", exc_info=True)
                                    # Clean up temp decrypted file if it was created
                                    if temp_decrypted_path and os.path.exists(temp_decrypted_path):
                                        try:
                                            os.remove(temp_decrypted_path)
                                        except:
                                            pass
                                    continue
                            else:
                                # Handle JSON files
                                logger.info(f"📂 Loading file: {filename}")
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    # Normalize the data
                                    data = normalize_ufdr_data(data)
                                    # Use encrypted filename if file was encrypted, otherwise use original
                                    # The filename from database should already include .encrypted if it was encrypted
                                    restore_filename = filename  # Use filename as stored in database (includes .encrypted if encrypted)
                                    ACTIVE_DATA[restore_filename] = data
                                    ACTIVE_FILENAME = restore_filename
                                    loaded_files.append(restore_filename)
                                    logger.info(f"✅ Restored JSON file {restore_filename} into ACTIVE_DATA")
                            
                            # Clean up temporary decrypted file if it was created
                            if temp_decrypted_path and os.path.exists(temp_decrypted_path):
                                try:
                                    os.remove(temp_decrypted_path)
                                    logger.info(f"✅ Cleaned up temp decrypted file after restoration: {temp_decrypted_path}")
                                except Exception as cleanup_error:
                                    logger.warning(f"⚠️ Failed to clean up temp decrypted file {temp_decrypted_path}: {cleanup_error}")
                        except Exception as e:
                            logger.error(f"❌ Error loading file {filename} for session restore: {e}", exc_info=True)
                            continue
                    
                    # Restore XML files and their data layers
                    xml_files_restored = []
                    ACTIVE_DATA_LAYERS = {}
                    ACTIVE_DB_PATHS = {}
                    
                    for file_record in session_files:
                        filename = file_record['filename']
                        base_filename = filename.replace('.encrypted', '')
                        
                        # Check if this is an XML file
                        if base_filename.endswith('.xml'):
                            file_path_recorded = file_record.get('file_path', filename)
                            if os.path.isabs(file_path_recorded) and os.path.exists(file_path_recorded):
                                xml_file_path = file_path_recorded
                            else:
                                xml_file_path = os.path.join(UPLOAD_FOLDER, filename)
                            
                            # Check if XML file exists
                            if not os.path.exists(xml_file_path):
                                # Try encrypted version
                                encrypted_path = xml_file_path + '.encrypted'
                                if os.path.exists(encrypted_path):
                                    xml_file_path = encrypted_path
                                else:
                                    logger.warning(f"XML file {filename} not found, skipping")
                                    continue
                            
                            # Check if associated .db file exists
                            db_path = os.path.join(UPLOAD_FOLDER, f"{base_filename}.db")
                            if os.path.exists(db_path):
                                try:
                                    # Restore XML data layer
                                    from FORENSIC.core.cellebrite_data_access_layer import CellebriteDataAccessLayer
                                    data_layer = CellebriteDataAccessLayer(db_path, xml_file_path)
                                    ACTIVE_DATA_LAYERS[filename] = data_layer
                                    ACTIVE_DB_PATHS[filename] = db_path
                                    xml_files_restored.append(filename)
                                    logger.info(f"✅ Restored XML file {filename} with data layer")
                                except Exception as e:
                                    logger.error(f"❌ Error restoring XML data layer for {filename}: {e}", exc_info=True)
                            else:
                                logger.warning(f"Database file not found for XML {filename} at {db_path}, skipping")
                    
                    if xml_files_restored:
                        logger.info(f"✅ Successfully restored {len(xml_files_restored)} XML file(s) with data layers")
                    
                    # Update engines with loaded data
                    if ACTIVE_DATA:
                        try:
                            nl_engine.update_data(ACTIVE_DATA)
                            enhanced_nl_engine = EnhancedNaturalLanguageUFDR(ACTIVE_DATA)
                            ai_retrieval_engine = AIUFDRRetrievalEngine(ACTIVE_DATA)
                            rebuild_rag_index()
                            logger.info(f"✅ Successfully restored {len(loaded_files)} file(s) into ACTIVE_DATA for session {session_id_from_url}")
                            logger.info(f"   ACTIVE_DATA keys: {list(ACTIVE_DATA.keys())}")
                        except Exception as e:
                            logger.error(f"❌ Error updating engines with restored data: {e}", exc_info=True)
                    else:
                        logger.warning(f"⚠️ No files could be loaded for session {session_id_from_url}")
                elif not session_files:
                    logger.info(f"ℹ️ No files found in database or folder for session {session_id_from_url}")
                else:
                    logger.warning(f"⚠️ UPLOAD_FOLDER does not exist: {UPLOAD_FOLDER}")
            else:
                # Truly new session - no files AND no chat history - clear ACTIVE_DATA and XML data layers
                is_new_session = True
                logger.info(f"🆕 Brand new session {session_id_from_url} detected (no files, no chat) - clearing ACTIVE_DATA and XML data layers")
                ACTIVE_FILENAME = None
                ACTIVE_DATA = {}
                ACTIVE_DATA_LAYERS = {}
                ACTIVE_DB_PATHS = {}
                try:
                    nl_engine.update_data(ACTIVE_DATA)
                    enhanced_nl_engine = EnhancedNaturalLanguageUFDR(ACTIVE_DATA)
                    ai_retrieval_engine = AIUFDRRetrievalEngine(ACTIVE_DATA)
                    rebuild_rag_index()
                except Exception as e:
                    logger.error(f"Error clearing ACTIVE_DATA for new session: {e}")
            
            if session_id_from_url not in CHAT_HISTORIES:
                CHAT_HISTORIES[session_id_from_url] = []
            
            # Only load chat history if this is NOT a new session (has files)
            # For new sessions, start with empty chat history
            if session_files and all_chat_history:
                # Load all chat history (from related sessions + current session) into in-memory cache
                # This ensures context continuity across sessions for the same case
                for msg in all_chat_history:
                    CHAT_HISTORIES[session_id_from_url].append({
                        "role": msg['role'],
                        "content": msg['content'],
                        "timestamp": msg.get('timestamp'),
                        "source_session": msg.get('source_session_id', session_id_from_url)  # Track which session it came from
                    })
                
                if related_chat_history:
                    logger.info(f"✅ Loaded chat history from {len(set(msg.get('source_session_id', '') for msg in related_chat_history))} previous session(s) for context continuity")
            else:
                logger.info(f"🆕 Starting with empty chat history for new session {session_id_from_url}")
            update_session_access(session_id_from_url)
            # Also update the case's updated_at timestamp when EVI is accessed
            # This makes "Last Updated" and "Last Opened" synchronized
            if case_id and SESSION_DB_AVAILABLE:
                # update_case already imported at top
                update_case(case_id)  # This will update updated_at to current time
    elif not session_id_from_url:
        # No session_id - this is a fresh start, clear everything
        logger.info("No session_id provided - clearing ACTIVE_DATA for fresh start")
        ACTIVE_FILENAME = None
        ACTIVE_DATA = {}
        ACTIVE_DATA_LAYERS = {}
        ACTIVE_DB_PATHS = {}
        try:
            nl_engine.update_data(ACTIVE_DATA)
            enhanced_nl_engine = EnhancedNaturalLanguageUFDR(ACTIVE_DATA)
            ai_retrieval_engine = AIUFDRRetrievalEngine(ACTIVE_DATA)
            rebuild_rag_index()
        except Exception as e:
            logger.error(f"Error clearing ACTIVE_DATA: {e}")
    
    # Get user profile picture
    profile_picture = session.get('profile_picture', '')
    if not profile_picture and user_id:
        try:
            conn = sqlite3.connect(AUTH_DB_PATH)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT profile_picture FROM users WHERE id = ?", (user_id,))
            user = cur.fetchone()
            if user and user['profile_picture']:
                profile_picture = user['profile_picture']
                session['profile_picture'] = profile_picture
            cur.close()
            conn.close()
        except Exception as e:
            logger.warning(f"Error loading profile picture: {e}")
    
    # In dev mode, show dev user info
    if DEV_MODE:
        return render_template('enhanced_index.html',
                             username='dev_user',
                             name='Development User',
                             email='dev@example.com',
                             profile_picture='',
                             session_id=session_id_from_url or session.get('session_id'),
                             case_id=case_info.get('case_id') if case_info else None,
                             case_name=case_info.get('case_name') if case_info else None)
    return render_template('enhanced_index.html',
                         username=session.get('username', 'User'),
                         name=session.get('name', 'Forensic Analyst'),
                         email=session.get('email', ''),
                         profile_picture=profile_picture,
                         session_id=session_id_from_url or session.get('session_id'),
                         case_id=case_info.get('case_id') if case_info else None,
                         case_name=case_info.get('case_name') if case_info else None)


@app.route('/images')
@login_required
def images_gallery():
    """Images gallery page for viewing images from ZIP UFDR files."""
    # Get user profile picture - load from database to ensure persistence
    user_id = session.get('user_id')
    profile_picture = session.get('profile_picture', '')
    if not profile_picture and user_id:
        # Load profile data from database (ensures persistence across server restarts)
        profile_data = load_user_profile_data(user_id)
        profile_picture = profile_data.get('profile_picture', '') if profile_data else ''
    
    return render_template('images_gallery.html',
                         username=session.get('username', 'User'),
                         name=session.get('name', 'Forensic Analyst'),
                         email=session.get('email', ''),
                         profile_picture=profile_picture)


def validate_ufdr_structure(file_data):
    """
    Comprehensive UFDR file structure validation.
    Supports both v1 (flat structure) and v2 (devices array) formats.
    
    Args:
        file_data: The UFDR file data to validate
        
    Returns:
        Dictionary containing validation results
    """
    # Check if this is v2 format with devices array
    if 'devices' in file_data and isinstance(file_data['devices'], list):
        # V2 format validation
        if len(file_data['devices']) == 0:
            return {'is_valid': False, 'message': 'V2 format: devices array is empty'}
        
        validation_errors = []
        
        for device_idx, device_entry in enumerate(file_data['devices']):
            if not isinstance(device_entry, dict):
                validation_errors.append(f'Device {device_idx} is not a dictionary')
                continue
            
            # Validate contacts within this device
            device_contacts = device_entry.get('contacts', [])
            if device_contacts is not None and not isinstance(device_contacts, list):
                validation_errors.append(f'Device {device_idx}: contacts (not a list)')
                continue
            
            if isinstance(device_contacts, list):
                for i, contact in enumerate(device_contacts):
                    if not isinstance(contact, dict):
                        validation_errors.append(f'Device {device_idx}, Contact {i} is not a dictionary')
                        continue
                    if not (contact.get('name') or contact.get('phone')):
                        validation_errors.append(f'Device {device_idx}, Contact {i} missing name/phone')
            
            # Validate messages within this device
            device_messages = device_entry.get('messages', [])
            if device_messages is not None and not isinstance(device_messages, list):
                validation_errors.append(f'Device {device_idx}: messages (not a list)')
                continue
            
            if isinstance(device_messages, list):
                for i, message in enumerate(device_messages):
                    if not isinstance(message, dict):
                        validation_errors.append(f'Device {device_idx}, Message {i} is not a dictionary')
                        continue
                    
                    has_parties = (message.get('from') and message.get('to')) or (message.get('sender') and message.get('receiver'))
                    has_content = (message.get('text') is not None) or (message.get('content') is not None)
                    has_timestamp = bool(message.get('timestamp'))
                    if not (has_parties and has_content and has_timestamp):
                        validation_errors.append(f'Device {device_idx}, Message {i} missing required fields')
            
            # Validate calls within this device
            device_calls = device_entry.get('call_logs', device_entry.get('calls', []))
            if device_calls is not None and not isinstance(device_calls, list):
                validation_errors.append(f'Device {device_idx}: call_logs/calls (not a list)')
                continue
            
            if isinstance(device_calls, list):
                for i, call in enumerate(device_calls):
                    if not isinstance(call, dict):
                        validation_errors.append(f'Device {device_idx}, Call {i} is not a dictionary')
                        continue
                    
                    has_parties = (call.get('from') and call.get('to')) or (call.get('caller') and call.get('receiver'))
                    has_timestamp = bool(call.get('timestamp'))
                    if not (has_parties and has_timestamp):
                        validation_errors.append(f'Device {device_idx}, Call {i} missing required fields')
        
        if validation_errors:
            return {
                'is_valid': False,
                'message': f'V2 validation errors: {"; ".join(validation_errors[:5])}{"..." if len(validation_errors) > 5 else ""}'
            }
        
        return {
            'is_valid': True,
            'message': f'V2 UFDR file structure is valid ({len(file_data["devices"])} devices)'
        }
    
    # V1 format validation (original logic)
    # Normalize sections: accept keys from multiple schema variants
    contacts = file_data.get('contacts', [])
    messages = file_data.get('messages', [])
    calls = file_data.get('call_logs', file_data.get('calls', []))
    
    # Basic type checks if sections exist
    if contacts is not None and not isinstance(contacts, list):
        return {'is_valid': False, 'message': 'contacts (not a list)'}
    if messages is not None and not isinstance(messages, list):
        return {'is_valid': False, 'message': 'messages (not a list)'}
    if calls is not None and not isinstance(calls, list):
        return {'is_valid': False, 'message': 'calls/call_logs (not a list)'}
    
    # Validate individual data structures
    validation_errors = []
    
    # Validate contacts
    if isinstance(contacts, list):
        for i, contact in enumerate(contacts):
            if not isinstance(contact, dict):
                validation_errors.append(f'Contact {i} is not a dictionary')
                continue
            
            # Accept minimal fields; name or phone preferred
            if not (contact.get('name') or contact.get('phone')):
                validation_errors.append(f'Contact {i} missing name/phone')
    
    # Validate messages
    if isinstance(messages, list):
        for i, message in enumerate(messages):
            if not isinstance(message, dict):
                validation_errors.append(f'Message {i} is not a dictionary')
                continue
            
            # Accept either (from/to/text) or (sender/receiver/content), plus timestamp
            has_parties = (message.get('from') and message.get('to')) or (message.get('sender') and message.get('receiver'))
            has_content = (message.get('text') is not None) or (message.get('content') is not None)
            has_timestamp = bool(message.get('timestamp'))
            if not (has_parties and has_content and has_timestamp):
                validation_errors.append(f'Message {i} missing required fields (parties/content/timestamp)')
    
    # Validate calls (calls or call_logs)
    if isinstance(calls, list):
        for i, call in enumerate(calls):
            if not isinstance(call, dict):
                validation_errors.append(f'Call {i} is not a dictionary')
                continue
            
            has_parties = (call.get('from') and call.get('to')) or (call.get('caller') and call.get('receiver'))
            has_timestamp = bool(call.get('timestamp'))
            if not (has_parties and has_timestamp):
                validation_errors.append(f'Call {i} missing required fields (parties/timestamp)')
    
    if validation_errors:
        return {
            'is_valid': False,
            'message': f'V1 validation errors: {"; ".join(validation_errors[:5])}{"..." if len(validation_errors) > 5 else ""}'
        }
    
    # Consider valid even if sections are missing; caller may warn separately
    return {
        'is_valid': True,
        'message': 'V1 UFDR file structure is valid'
    }

def normalize_ufdr_data(raw: dict) -> dict:
    """Normalize various UFDR schemas into a standard app schema.
    Ensures presence of: contacts, messages, call_logs, files, device.
    Maps common alternate keys to expected ones.
    Supports both v1 (flat structure) and v2 (devices array) formats.
    """
    data = dict(raw) if isinstance(raw, dict) else {}
    if not isinstance(data, dict):
        return {'contacts': [], 'messages': [], 'call_logs': [], 'files': [], 'device': {}}

    # Check if this is v2 format with devices array
    if 'devices' in data and isinstance(data['devices'], list) and len(data['devices']) > 0:
        # V2 format: aggregate data from all devices
        all_contacts = []
        all_messages = []
        all_calls = []
        all_files = []
        all_locations = []
        primary_device = {}
        
        for device_entry in data['devices']:
            if not isinstance(device_entry, dict):
                continue
                
            # Collect contacts
            device_contacts = device_entry.get('contacts', [])
            if isinstance(device_contacts, list):
                all_contacts.extend(device_contacts)
            
            # Collect messages
            device_messages = device_entry.get('messages', [])
            if isinstance(device_messages, list):
                for m in device_messages:
                    if isinstance(m, dict):
                        nm = dict(m)
                        if 'from' not in nm and 'sender' in nm:
                            nm['from'] = nm.get('sender')
                        if 'to' not in nm and 'receiver' in nm:
                            nm['to'] = nm.get('receiver')
                        if 'text' not in nm and 'content' in nm:
                            nm['text'] = nm.get('content')
                        all_messages.append(nm)
            
            # Collect calls
            device_calls = device_entry.get('call_logs', device_entry.get('calls', []))
            if isinstance(device_calls, list):
                for c in device_calls:
                    if isinstance(c, dict):
                        nc = dict(c)
                        if 'from' not in nc and 'caller' in nc:
                            nc['from'] = nc.get('caller')
                        if 'to' not in nc and 'receiver' in nc:
                            nc['to'] = nc.get('receiver')
                        if 'duration' not in nc and 'duration_seconds' in nc:
                            nc['duration'] = nc.get('duration_seconds')
                        all_calls.append(nc)
            
            # Collect files
            device_files = device_entry.get('files', [])
            if isinstance(device_files, list):
                all_files.extend(device_files)
            
            # Collect locations
            device_locations = device_entry.get('locations', [])
            if isinstance(device_locations, list):
                all_locations.extend(device_locations)
            
            # Use first device info as primary
            if not primary_device and 'device' in device_entry:
                primary_device = device_entry['device']
        
        return {
            'contacts': all_contacts,
            'messages': all_messages,
            'call_logs': all_calls,
            'files': all_files,
            'locations': all_locations,
            'device': primary_device,
            'tampered': data.get('tampered', False),
            'tampered_reason': data.get('tampered_reason'),
            'format_version': 'v2',
            'device_count': len(data['devices'])
        }
    
    # V1 format processing (original logic)
    # Contacts
    contacts = data.get('contacts')
    if not isinstance(contacts, list):
        contacts = []

    # Messages normalize
    normalized_messages = []
    src_messages = data.get('messages') if isinstance(data.get('messages'), list) else []
    for m in src_messages:
        if not isinstance(m, dict):
            continue
        nm = dict(m)
        if 'from' not in nm and 'sender' in nm:
            nm['from'] = nm.get('sender')
        if 'to' not in nm and 'receiver' in nm:
            nm['to'] = nm.get('receiver')
        if 'text' not in nm and 'content' in nm:
            nm['text'] = nm.get('content')
        normalized_messages.append(nm)

    # Fallback: collect nested message-like entries
    if not normalized_messages:
        def _collect_messages(node):
            acc = []
            if isinstance(node, list):
                for itm in node:
                    if isinstance(itm, dict):
                        keys = set(itm.keys())
                        if 'timestamp' in keys and (('text' in keys) or ('content' in keys)) and (('from' in keys and 'to' in keys) or ('sender' in keys and 'receiver' in keys)):
                            nm = dict(itm)
                            if 'from' not in nm and 'sender' in nm:
                                nm['from'] = nm.get('sender')
                            if 'to' not in nm and 'receiver' in nm:
                                nm['to'] = nm.get('receiver')
                            if 'text' not in nm and 'content' in nm:
                                nm['text'] = nm.get('content')
                            acc.append(nm)
            elif isinstance(node, dict):
                for v in node.values():
                    acc.extend(_collect_messages(v))
            return acc
        normalized_messages = _collect_messages(data)

    # Calls normalize: prefer call_logs else calls
    src_calls = data.get('call_logs')
    if not isinstance(src_calls, list):
        src_calls = data.get('calls') if isinstance(data.get('calls'), list) else []
    normalized_calls = []
    for c in src_calls:
        if not isinstance(c, dict):
            continue
        nc = dict(c)
        if 'from' not in nc and 'caller' in nc:
            nc['from'] = nc.get('caller')
        if 'to' not in nc and 'receiver' in nc:
            nc['to'] = nc.get('receiver')
        if 'duration' not in nc and 'duration_seconds' in nc:
            nc['duration'] = nc.get('duration_seconds')
        normalized_calls.append(nc)

    # Fallback: collect nested call-like entries
    if not normalized_calls:
        def _collect_calls(node):
            acc = []
            if isinstance(node, list):
                for itm in node:
                    if isinstance(itm, dict):
                        keys = set(itm.keys())
                        if 'timestamp' in keys and (('from' in keys and 'to' in keys) or ('caller' in keys and 'receiver' in keys)):
                            nc = dict(itm)
                            if 'from' not in nc and 'caller' in nc:
                                nc['from'] = nc.get('caller')
                            if 'to' not in nc and 'receiver' in nc:
                                nc['to'] = nc.get('receiver')
                            if 'duration' not in nc and 'duration_seconds' in nc:
                                nc['duration'] = nc.get('duration_seconds')
                            acc.append(nc)
            elif isinstance(node, dict):
                for v in node.values():
                    acc.extend(_collect_calls(v))
            return acc
        normalized_calls = _collect_calls(data)

    # Files
    files = data.get('files') if isinstance(data.get('files'), list) else []

    # Locations
    locations = data.get('locations', [])
    if not isinstance(locations, list):
        locations = []

    # Device
    device = data.get('device') if isinstance(data.get('device'), dict) else {}

    return {
        'contacts': contacts,
        'messages': normalized_messages,
        'call_logs': normalized_calls,
        'files': files,
        'locations': locations,
        'device': device,
        'tampered': data.get('tampered', False),
        'tampered_reason': data.get('tampered_reason'),
        'format_version': 'v1'
    }

@app.route('/api/health', methods=['GET'])
def health_check():
    """Simple health check endpoint."""
    return jsonify({"status": "OK", "message": "Server is running"}), 200

@app.route('/api/upload', methods=['GET', 'POST'])
def upload_file():
    """Upload UFDR JSON files with comprehensive validation."""
    # Declare globals at the top of the function
    global ACTIVE_DATA_LAYERS, ACTIVE_DB_PATHS, ACTIVE_FILENAME, ACTIVE_DATA, enhanced_nl_engine, ai_retrieval_engine
    
    # Handle GET requests with helpful error message
    if request.method == 'GET':
        return jsonify({
            "status": "ERROR",
            "message": "This endpoint only accepts POST requests. Please use the file upload interface on the main page to upload files."
        }), 405
    
    logger.info("=" * 50)
    logger.info("Upload request received")
    try:
        if 'file' not in request.files:
            logger.warning("No file in request")
            return jsonify({"status": "ERROR", "message": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            logger.warning("Empty filename")
            return jsonify({"status": "ERROR", "message": "No file selected"}), 400
        
        logger.info(f"File received: {file.filename}")
        
        # Check file extension
        if not file or not allowed_file(file.filename):
            return jsonify({"status": "ERROR", "message": "Only JSON, ZIP, UFDR, and XML files are allowed"})
        
        # Check file size (limit to 10GB)
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > 10 * 1024 * 1024 * 1024:  # 10GB limit
            return jsonify({"status": "ERROR", "message": "File size exceeds 10GB limit"})
        
        if file_size == 0:
            return jsonify({"status": "ERROR", "message": "File is empty"})
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        encrypted_filepath = filepath + '.encrypted'
        
        # Check if file already exists (both encrypted and unencrypted versions) - allow overwriting
        files_to_remove = []
        if os.path.exists(filepath):
            files_to_remove.append(filepath)
        if os.path.exists(encrypted_filepath):
            files_to_remove.append(encrypted_filepath)
        
        if files_to_remove:
            logger.info(f"File {filename} already exists. Removing old file(s) to allow overwrite.")
            for file_to_remove in files_to_remove:
                try:
                    os.remove(file_to_remove)
                    logger.info(f"Removed existing file: {file_to_remove}")
                except Exception as e:
                    logger.warning(f"Failed to remove existing file {file_to_remove}: {e}")
                    return jsonify({"status": "ERROR", "message": f"File '{filename}' already exists and could not be removed. Please manually delete it first."})
        
        # Save file with error handling
        try:
            file.save(filepath)
            logger.info(f"File saved successfully: {filename} ({file_size} bytes)")
            
            # Encrypt file if security is available
            if SECURITY_AVAILABLE and encryption:
                try:
                    # Read file content
                    with open(filepath, 'rb') as f:
                        file_content = f.read()
                    
                    # Encrypt file content
                    encrypted_content = encryption.cipher.encrypt(file_content)
                    
                    # Save encrypted file (append .encrypted extension)
                    encrypted_filepath = filepath + '.encrypted'
                    with open(encrypted_filepath, 'wb') as f:
                        f.write(encrypted_content)
                    
                    # Remove original unencrypted file
                    os.remove(filepath)
                    
                    # Update filepath to encrypted version
                    filepath = encrypted_filepath
                    logger.info(f"File encrypted successfully: {filename}")
                except Exception as e:
                    logger.warning(f"File encryption failed, keeping unencrypted: {e}")
                    # Continue with unencrypted file if encryption fails
            
            # Calculate file hash for integrity checking
            file_hash = None
            if SECURITY_AVAILABLE:
                try:
                    file_hash = calculate_file_hash(filepath)
                    logger.info(f"File hash calculated: {file_hash[:16]}...")
                except Exception as e:
                    logger.warning(f"Could not calculate file hash: {e}")
            
            # Audit logging for file upload
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('file_upload', resource=filename, success=True,
                                      details={'size': file_size, 'hash': file_hash[:32] if file_hash else None})
        except Exception as e:
            logger.error(f"Error saving file {filename}: {str(e)}", exc_info=True)
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('file_upload', resource=filename, success=False,
                                      details={'error': str(e)})
            return jsonify({
                "status": "ERROR",
                "message": f"Failed to save file: {str(e)}. The file might be too large or there's insufficient disk space."
            }), 500
        
        # Handle encrypted files - decrypt if needed
        is_encrypted = filepath.endswith('.encrypted')
        temp_decrypted_file = None  # Track temp file for cleanup
        original_encrypted_filepath = None  # Keep reference to encrypted file
        
        if is_encrypted and SECURITY_AVAILABLE and encryption:
            try:
                # Store reference to original encrypted file
                original_encrypted_filepath = filepath
                
                # Read encrypted content
                with open(filepath, 'rb') as f:
                    encrypted_content = f.read()
                
                # Decrypt content
                decrypted_content = encryption.cipher.decrypt(encrypted_content)
                
                # Create temporary decrypted file for processing
                temp_filepath = filepath.replace('.encrypted', '')
                with open(temp_filepath, 'wb') as f:
                    f.write(decrypted_content)
                
                temp_decrypted_file = temp_filepath  # Track for cleanup
                filepath = temp_filepath
                logger.info(f"File decrypted for processing: {filename}")
            except Exception as e:
                logger.error(f"Error decrypting file: {e}")
                return jsonify({"status": "ERROR", "message": f"Failed to decrypt file: {str(e)}"}), 500
        
        # Handle XML files (Cellebrite report XML) - EXPERIMENTAL
        is_xml_file = filename.endswith('.xml') or 'Report.xml' in filename or \
                     (is_encrypted and (filename.replace('.encrypted', '').endswith('.xml') or 
                                       'Report.xml' in filename.replace('.encrypted', '')))
        if is_xml_file:
            # In DEV_MODE or when uploading a new XML file, clear all previous XML data layers
            # This ensures only the latest file is active, not merged with previous ones
            if DEV_MODE or True:  # Always clear previous XML files when uploading new one
                logger.info(f"🗑️ Clearing previous XML data layers before loading new file")
                
                # Get base filename (without .encrypted) for database cleanup
                base_filename_for_db = filename.replace('.encrypted', '')
                
                # Remove old .db files from disk (both encrypted and unencrypted versions)
                if os.path.exists(UPLOAD_FOLDER):
                    for existing_file in os.listdir(UPLOAD_FOLDER):
                        if existing_file.endswith('.db'):
                            # Remove database files for any XML files (not just Google_)
                            # Check if this db file corresponds to an XML file
                            db_base = existing_file.replace('.db', '')
                            # If there's a corresponding XML file (encrypted or not), remove the db
                            xml_file_exists = os.path.exists(os.path.join(UPLOAD_FOLDER, db_base)) or \
                                            os.path.exists(os.path.join(UPLOAD_FOLDER, db_base + '.encrypted'))
                            if xml_file_exists and db_base != base_filename_for_db:
                                # This is an old database file for a different XML file
                                db_file_path = os.path.join(UPLOAD_FOLDER, existing_file)
                                try:
                                    os.remove(db_file_path)
                                    logger.info(f"🗑️ Removed old database file: {existing_file}")
                                except Exception as e:
                                    logger.warning(f"Failed to remove old database file {existing_file}: {e}")
                
                # Clear all XML data layers from memory
                cleared_count = len(ACTIVE_DATA_LAYERS)
                ACTIVE_DATA_LAYERS.clear()
                ACTIVE_DB_PATHS.clear()
                logger.info(f"✅ Cleared {cleared_count} previous XML data layer(s) from memory")
            
            logger.info(f"🔍 Processing XML report file: {filename} (size: {file_size / (1024**2):.2f} MB)")
            try:
                # Use XML parser
                # Use base filename (without .encrypted) for database path to avoid confusion
                base_filename_for_db = filename.replace('.encrypted', '')
                db_path = os.path.join(UPLOAD_FOLDER, f"{base_filename_for_db}.db")
                
                # In DEV_MODE, delete existing database file to prevent data accumulation during testing
                # In production mode, preserve existing data (may be shared across sessions)
                if DEV_MODE and os.path.exists(db_path):
                    try:
                        os.remove(db_path)
                        logger.info(f"🗑️ DEV_MODE: Removed existing database file: {os.path.basename(db_path)}")
                    except Exception as e:
                        logger.warning(f"⚠️ Could not remove existing database file {db_path}: {e}")
                elif os.path.exists(db_path):
                    logger.info(f"ℹ️ Database file already exists: {os.path.basename(db_path)} - preserving existing data (production mode)")
                
                parser = XMLCellebriteParser()
                stats = parser.parse_xml_report(filepath, db_path)
                
                # Verify database was created and has data
                if not os.path.exists(db_path):
                    raise Exception(f"Database file was not created at {db_path}")
                
                db_size = os.path.getsize(db_path)
                logger.info(f"📊 Database created: {db_path} ({db_size / 1024:.2f} KB)")
                
                # Verify database has tables and data
                test_conn = sqlite3.connect(db_path)
                test_cursor = test_conn.cursor()
                test_cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in test_cursor.fetchall()]
                logger.info(f"📋 Database tables: {tables}")
                
                # Check counts
                for table in ['contacts', 'messages', 'call_logs', 'chats', 'locations', 'files']:
                    if table in tables:
                        test_cursor.execute(f"SELECT COUNT(*) FROM {table}")
                        count = test_cursor.fetchone()[0]
                        logger.info(f"  {table}: {count} records")
                test_conn.close()
                
                # Create data access layer
                data_layer = CellebriteDataAccessLayer(db_path, filepath)
                
                # Store for later use
                # Store with both encrypted and base filename for easier lookup
                ACTIVE_DATA_LAYERS[filename] = data_layer
                ACTIVE_DB_PATHS[filename] = db_path
                ACTIVE_FILENAME = filename
                
                # Also store with base filename (without .encrypted) for easier lookup
                base_filename = filename.replace('.encrypted', '')
                if base_filename != filename:
                    ACTIVE_DATA_LAYERS[base_filename] = data_layer
                    ACTIVE_DB_PATHS[base_filename] = db_path
                    logger.info(f"📝 Also registered data layer with base filename: {base_filename}")
                
                logger.info(f"✅ XML parsing complete: {stats}")
                logger.info(f"✅ Data layer created and stored in ACTIVE_DATA_LAYERS[{filename}]")
                
                # Get UFDR format data for compatibility
                ufdr_data = data_layer.get_ufdr_format_data()
                
                # Set extracted data structure (similar to fast parser)
                extracted = {
                    'hybrid_parsed': True,
                    'ufdr_data': ufdr_data,
                    'images': ufdr_data.get('images', []),
                    'videos': ufdr_data.get('videos', []),
                    'json_files': {},
                    'structure': {
                        'artifacts': {},
                        'metadata': {}
                    },
                    'xml_parser_used': True,
                    'db_path': db_path
                }
                
                # Don't set ACTIVE_DATA for XML files - they use ACTIVE_DATA_LAYERS only
                # XML files should NOT be added to ACTIVE_DATA - they use data layers for querying
                
                # Prepare quick stats for UI
                _ti = int(stats.get('images', 0) or 0)
                _tv = int(stats.get('videos', 0) or 0)
                _to = int(stats.get('other_media', 0) or 0)
                _tm = int(stats.get('total_media', _ti + _tv + _to) or 0)
                quick_stats = {
                    "total_files": 1,
                    "total_contacts": stats.get('contacts', 0),
                    "total_messages": stats.get('messages', 0),
                    "total_calls": stats.get('calls', 0),
                    "total_chats": stats.get('chats', 0),
                    "total_locations": stats.get('locations', 0),
                    "total_files_count": stats.get('files', 0),
                    "device_networking": stats.get('device_networking'),
                    "total_images": _ti,
                    "total_videos": _tv,
                    "total_other_media": _to,
                    "images_count": _ti,
                    "videos_count": _tv,
                    "total_media": _tm,
                }
                
                # Save XML file to session_files table if we have a session_id
                if SESSION_DB_AVAILABLE:
                    session_id = session.get('session_id') or request.args.get('session_id') or request.form.get('session_id')
                    if session_id and session_id != 'None' and session_id != '':
                        file_path_full = os.path.join(UPLOAD_FOLDER, filename)
                        if save_session_file(session_id, filename, file_path_full):
                            logger.info(f"✅ Saved XML file {filename} to session {session_id} in database")
                            session['session_id'] = session_id
                        else:
                            logger.warning(f"❌ Failed to save XML file {filename} to session {session_id}")
                
                # Clean up temp decrypted file if exists
                if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                    try:
                        os.remove(temp_decrypted_file)
                    except:
                        pass
                
                return jsonify({
                    "status": "SUCCESS",
                    "message": f"XML report parsed successfully",
                    "filename": filename,
                    "stats": stats,
                    "quick_stats": quick_stats,
                    "uploaded_files": [filename],
                    "parser": "xml_cellebrite_parser"
                })
                
            except Exception as e:
                logger.error(f"XML parser failed: {e}", exc_info=True)
                # Clean up temp decrypted file if exists
                if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                    try:
                        os.remove(temp_decrypted_file)
                    except:
                        pass
                return jsonify({
                    "status": "ERROR",
                    "message": f"Failed to parse XML report: {str(e)}"
                }), 500
        
        # Handle ZIP files (including .ufdr files which are ZIP archives)
        is_zip_file = filename.endswith('.zip') or filename.endswith('.ufdr') or \
                     (is_encrypted and (filename.replace('.encrypted', '').endswith('.zip') or 
                                       filename.replace('.encrypted', '').endswith('.ufdr')))
        if is_zip_file:
            logger.info(f"Processing ZIP file: {filename} (size: {file_size} bytes)")
            
            # Check if it's a Cellebrite format and use fast parser
            is_cellebrite = False
            use_fast_parser = False
            extracted = None  # Initialize extracted variable
            
            try:
                with zipfile.ZipFile(filepath, 'r') as zip_ref:
                    db_count = sum(1 for name in zip_ref.namelist() if name.endswith('.db'))
                    # Cellebrite format typically has many .db files
                    is_cellebrite = db_count >= 2
                    # Use fast parser for Cellebrite files (especially large ones)
                    use_fast_parser = is_cellebrite and (file_size > 500 * 1024 * 1024 or True)  # Always use fast parser for Cellebrite
            except Exception:
                pass
            
            if use_fast_parser:
                logger.info(f"🚀 Detected Cellebrite format - using fast parser for {file_size / (1024**3):.2f} GB file")
                try:
                    # Use fast Cellebrite parser
                    import tempfile
                    extract_to = tempfile.mkdtemp()
                    db_path = os.path.join(UPLOAD_FOLDER, f"{filename}.db")
                    
                    parser = FastCellebriteParser(max_workers=4)
                    stats = parser.parse_cellebrite_ufdr(filepath, db_path, extract_to)
                    
                    # Create data access layer
                    data_layer = CellebriteDataAccessLayer(db_path, filepath)
                    
                    # Store for later use
                    ACTIVE_DATA_LAYERS[filename] = data_layer
                    ACTIVE_DB_PATHS[filename] = db_path
                    
                    # Get UFDR format data for compatibility
                    ufdr_data = data_layer.get_ufdr_format_data()
                    
                    logger.info(f"✅ Fast Cellebrite parsing complete: {stats}")
                    
                    # Set extracted data structure
                    extracted = {
                        'hybrid_parsed': True,
                        'ufdr_data': ufdr_data,
                        'images': ufdr_data.get('images', []),
                        'videos': ufdr_data.get('videos', []),
                        'json_files': {},
                        'structure': {
                            'artifacts': {},
                            'metadata': {}
                        },
                        'extract_path': extract_to,
                        'fast_parser_used': True,
                        'db_path': db_path
                    }
                    
                except Exception as e:
                    logger.error(f"Fast Cellebrite parser failed: {e}, falling back to hybrid parser", exc_info=True)
                    # Fall through to hybrid parser
                    use_fast_parser = False
            
            if not use_fast_parser:
                logger.info("Starting ZIP file extraction with hybrid parser...")
                try:
                    # Try hybrid parser (heuristics + LLM fallback)
                    extracted = extract_zip_with_hybrid_parser(filepath)
                    logger.info(f"ZIP extraction complete. JSON files: {len(extracted.get('json_files', {}))}, Images: {len(extracted.get('images', []))}")
                except MemoryError as e:
                    logger.error(f"Memory error extracting ZIP file: {str(e)}", exc_info=True)
                    try:
                        # Remove temp decrypted file if it exists, keep encrypted file
                        if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                            os.remove(temp_decrypted_file)
                        elif not is_encrypted and os.path.exists(filepath):
                            os.remove(filepath)
                    except:
                        pass
                    return jsonify({
                        "status": "ERROR",
                        "message": "ZIP file is too large to process. The server ran out of memory. Please try a smaller file or split the ZIP into smaller parts."
                    }), 500
                except zipfile.BadZipFile as e:
                    logger.error(f"Invalid ZIP file format: {str(e)}", exc_info=True)
                    try:
                        # Remove temp decrypted file if it exists, keep encrypted file
                        if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                            os.remove(temp_decrypted_file)
                        elif not is_encrypted and os.path.exists(filepath):
                            os.remove(filepath)
                    except:
                        pass
                    return jsonify({
                        "status": "ERROR",
                        "message": "Invalid ZIP file format. Please ensure the file is a valid ZIP archive."
                    }), 400
                except Exception as e:
                    logger.error(f"Error extracting ZIP file: {str(e)}", exc_info=True)
                    try:
                        # Remove temp decrypted file if it exists, keep encrypted file
                        if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                            os.remove(temp_decrypted_file)
                        elif not is_encrypted and os.path.exists(filepath):
                            os.remove(filepath)
                    except:
                        pass
                    error_msg = str(e)
                    if "corrupted" in error_msg.lower() or "bad zip" in error_msg.lower():
                        return jsonify({
                            "status": "ERROR",
                            "message": "ZIP file appears to be corrupted or invalid. Please check the file and try again."
                        }), 400
                    return jsonify({
                        "status": "ERROR",
                        "message": f"Failed to extract ZIP file: {error_msg}"
                    }), 500
            
            if not extracted:
                # Remove temp decrypted file if it exists, keep encrypted file
                try:
                    if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                        os.remove(temp_decrypted_file)
                    elif not is_encrypted and os.path.exists(filepath):
                        os.remove(filepath)
                except:
                    pass
                return jsonify({
                    "status": "ERROR",
                    "message": "Failed to extract ZIP file"
                })
            
            # Check if we have the expected UFDR structure
            structure = extracted.get('structure', {})
            has_artifacts = bool(structure.get('artifacts'))
            has_metadata = bool(structure.get('metadata'))
            
            if not has_artifacts and not extracted.get('json_files'):
                # Remove temp decrypted file if it exists, keep encrypted file
                try:
                    if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                        os.remove(temp_decrypted_file)
                    elif not is_encrypted and os.path.exists(filepath):
                        os.remove(filepath)
                except:
                    pass
                # Provide more helpful error message
                structure_info = f"Found: {len(extracted.get('json_files', {}))} JSON files"
                return jsonify({
                    "status": "ERROR",
                    "message": f"ZIP file does not contain valid UFDR structure. Expected 'Artifacts/' folder with Calls, Contacts, SMS, and WhatsApp JSON files. {structure_info}"
                })
            
            # Normalize ZIP structure to UFDR format
            # Check if hybrid parser or fast parser already normalized it
            if 'hybrid_parsed' in extracted or extracted.get('fast_parser_used'):
                # Parser already normalized, use directly
                ufdr_data = extracted['ufdr_data']
                logger.info(f"Using parser normalized data. Contacts: {len(ufdr_data.get('contacts', []))}, Messages: {len(ufdr_data.get('messages', []))}, Calls: {len(ufdr_data.get('call_logs', []))}")
                if extracted.get('fast_parser_used'):
                    logger.info(f"Fast parser used - data stored in database: {extracted.get('db_path')}")
            else:
                # Standard parser - need normalization
                try:
                    logger.info("Starting ZIP normalization...")
                    ufdr_data = normalize_zip_to_ufdr(extracted)
                    logger.info(f"Normalization complete. Contacts: {len(ufdr_data.get('contacts', []))}, Messages: {len(ufdr_data.get('messages', []))}, Calls: {len(ufdr_data.get('call_logs', []))}")
                except Exception as e:
                    logger.error(f"Error normalizing ZIP data: {str(e)}", exc_info=True)
                    # Remove temp decrypted file if it exists, keep encrypted file
                    try:
                        if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                            os.remove(temp_decrypted_file)
                        elif not is_encrypted and os.path.exists(filepath):
                            os.remove(filepath)
                    except:
                        pass
                    return jsonify({
                        "status": "ERROR",
                        "message": f"Error processing ZIP file structure: {str(e)}. Please check the file format."
                    }), 500
            
            if not ufdr_data or (not ufdr_data.get('contacts') and not ufdr_data.get('messages') 
                                and not ufdr_data.get('call_logs')):
                # Remove temp decrypted file if it exists, keep encrypted file
                try:
                    if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                        os.remove(temp_decrypted_file)
                    elif not is_encrypted and os.path.exists(filepath):
                        os.remove(filepath)
                except:
                    pass
                # Provide detailed error message
                found_items = []
                if ufdr_data:
                    if ufdr_data.get('contacts'):
                        found_items.append(f"{len(ufdr_data.get('contacts'))} contacts")
                    if ufdr_data.get('messages'):
                        found_items.append(f"{len(ufdr_data.get('messages'))} messages")
                    if ufdr_data.get('call_logs'):
                        found_items.append(f"{len(ufdr_data.get('call_logs'))} calls")
                
                found_str = f"Found: {', '.join(found_items)}" if found_items else "No data found"
                return jsonify({
                    "status": "ERROR",
                    "message": f"ZIP file does not contain valid UFDR data. Expected Artifacts folder with Calls, Contacts, SMS, and WhatsApp JSON files. {found_str}"
                })
            
            # Use normalized UFDR data
            # If hybrid parser already normalized it, use directly without re-normalizing
            if 'hybrid_parsed' in extracted:
                # Hybrid parser already normalized the data, use it directly
                data = ufdr_data
                logger.info(f"Using hybrid parser normalized data directly (skipping re-normalization)")
            else:
                # Standard parser - need to normalize
                raw = ufdr_data
                data = normalize_ufdr_data(raw)
            
            zip_info = {
                'is_zip': True,
                'extracted_path': extracted.get('extract_path', ''),
                'images': extracted.get('images', []),
                'videos': extracted.get('videos', []),
                'json_files': list(extracted.get('json_files', {}).keys())
            }
            # Log image/video counts for debugging
            # Log image/video counts for debugging
            image_count = len(zip_info.get('images', []))
            video_count = len(zip_info.get('videos', []))
            logger.info(f"ZIP info created: {image_count} images, {video_count} videos")
            if image_count == 0 and video_count == 0:
                logger.warning(f"⚠️ No images/videos found in extracted data. Extracted keys: {list(extracted.keys())}")
                if 'images' in extracted:
                    logger.warning(f"   extracted['images'] type: {type(extracted.get('images'))}, length: {len(extracted.get('images', []))}")
                if 'videos' in extracted:
                    logger.warning(f"   extracted['videos'] type: {type(extracted.get('videos'))}, length: {len(extracted.get('videos', []))}")
        else:
            # Handle JSON files (existing logic)
            zip_info = {'is_zip': False}
            # Validate JSON format and UFDR structure
            try:
                # Read file (already decrypted if encrypted)
                with open(filepath, 'r', encoding='utf-8') as f:
                    raw = json.load(f)
            except json.JSONDecodeError as e:
                # Remove temp decrypted file if it exists, keep encrypted file
                try:
                    if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                        os.remove(temp_decrypted_file)
                    elif not is_encrypted and os.path.exists(filepath):
                        os.remove(filepath)
                except:
                    pass
                return jsonify({"status": "ERROR", "message": f"Invalid JSON format: {str(e)}"})
            
            # Normalize uploaded data to SYNTHETIC UFDR schema (for JSON files)
            try:
                data = normalize_ufdr_data(raw)
            except Exception as e:
                # Remove temp decrypted file if it exists, keep encrypted file
                try:
                    if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                        os.remove(temp_decrypted_file)
                    elif not is_encrypted and os.path.exists(filepath):
                        os.remove(filepath)
                except:
                    pass
                return jsonify({"status": "ERROR", "message": f"Failed to normalize UFDR data: {str(e)}"})
        
        # Basic JSON structure check
        if not isinstance(data, dict):
            # Remove temp decrypted file if it exists, keep encrypted file
            try:
                if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                    os.remove(temp_decrypted_file)
                elif not is_encrypted and os.path.exists(filepath):
                    os.remove(filepath)
            except:
                pass
            return jsonify({"status": "ERROR", "message": "Invalid JSON format: root element must be an object"})
        
        # Comprehensive UFDR validation
        validation_result = validate_ufdr_structure(data)
        
        if not validation_result['is_valid']:
            # Remove temp decrypted file if it exists, keep encrypted file
            try:
                if temp_decrypted_file and os.path.exists(temp_decrypted_file):
                    os.remove(temp_decrypted_file)
                elif not is_encrypted and os.path.exists(filepath):
                    os.remove(filepath)
            except:
                pass
            return jsonify({
                "status": "ERROR", 
                "message": f"Invalid UFDR file structure: {validation_result['message']}"
            })
        
        # Additional checks for data quality
        warnings = []
        
        # Section presence and emptiness warnings (supporting v2 keys)
        if 'contacts' not in data:
            warnings.append("'contacts' section missing")
        elif len(data.get('contacts', [])) == 0:
            warnings.append("'contacts' section is empty")
        
        if 'messages' not in data:
            warnings.append("'messages' section missing")
        elif len(data.get('messages', [])) == 0:
            warnings.append("'messages' section is empty")
        
        if 'call_logs' not in data and 'calls' not in data:
            warnings.append("'call_logs'/'calls' section missing")
        else:
            calls_list = data.get('call_logs', data.get('calls', []))
            if isinstance(calls_list, list) and len(calls_list) == 0:
                warnings.append("'call_logs'/'calls' section is empty")
        
        if 'device' not in data:
            warnings.append("Missing device information")
        
        # Set this file as ACTIVE context only
        # Use encrypted filename if file was encrypted, otherwise use original
        active_filename = original_encrypted_filepath.split(os.sep)[-1] if original_encrypted_filepath else filename
        ACTIVE_FILENAME = active_filename
        ACTIVE_DATA = {active_filename: data}
        # Store ZIP info if it's a ZIP file
        if zip_info.get('is_zip'):
            ACTIVE_DATA['_zip_info'] = zip_info
            
            # Save extraction path to session metadata for persistence
            if SESSION_DB_AVAILABLE:
                session_id = session.get('session_id')
                if session_id and session_id != 'None' and session_id != '':
                    extract_path = zip_info.get('extracted_path', '')
                    if extract_path:
                        # Store extraction path in session metadata
                        try:
                            sess = get_session(session_id)
                            if sess:
                                metadata = sess.get('metadata', {})
                                if not isinstance(metadata, dict):
                                    metadata = {}
                                metadata['zip_extraction_path'] = extract_path
                                metadata['zip_filename'] = active_filename
                                # Update session with metadata
                                import json
                                from session_db import update_session_access
                                # We need to update the session metadata
                                # For now, we'll store it in a way that can be retrieved
                                logger.info(f"💾 Storing extraction path {extract_path} for session {session_id}")
                        except Exception as meta_error:
                            logger.warning(f"Could not store extraction path in metadata: {meta_error}")
        
        # Save file to session_files table if we have a session_id
        # Try multiple sources for session_id
        session_id = None
        if SESSION_DB_AVAILABLE:
            # Try Flask session first
            session_id = session.get('session_id')
            # Try URL params if not in session
            if not session_id or session_id == 'None' or session_id == '':
                session_id = request.args.get('session_id')
            # Try request form data
            if not session_id or session_id == 'None' or session_id == '':
                session_id = request.form.get('session_id')
            # Try JSON body
            if not session_id or session_id == 'None' or session_id == '':
                try:
                    json_data = request.get_json(silent=True)
                    if json_data:
                        session_id = json_data.get('session_id')
                except:
                    pass
            
            if session_id and session_id != 'None' and session_id != '':
                # Use encrypted filename if file was encrypted, otherwise use original
                file_to_save = original_encrypted_filepath.split(os.sep)[-1] if original_encrypted_filepath else filename
                file_path_full = os.path.join(UPLOAD_FOLDER, file_to_save)
                if save_session_file(session_id, file_to_save, file_path_full):
                    logger.info(f"✅ Saved file {file_to_save} to session {session_id} in database")
                    # Also store in Flask session for future use
                    session['session_id'] = session_id
                else:
                    logger.warning(f"❌ Failed to save file {file_to_save} to session {session_id}")
            else:
                logger.warning(f"⚠️ No session_id available when uploading {filename}. File not linked to session.")
        
        # Log data structure for debugging
        logger.info(f"Storing data for {filename}: contacts={len(data.get('contacts', []))}, messages={len(data.get('messages', []))}, calls={len(data.get('call_logs', []))}")
        logger.info(f"ACTIVE_DATA keys: {list(ACTIVE_DATA.keys())}")
        
        # Update engines with new data (synchronously to avoid race conditions)
        try:
            nl_engine.update_data(ACTIVE_DATA)
            logger.info("Updated nl_engine with ACTIVE_DATA")
        except Exception as e:
            logger.error(f"Error updating nl_engine: {e}", exc_info=True)
        
        # Initialize enhanced engine with new data
        try:
            enhanced_nl_engine = EnhancedNaturalLanguageUFDR(ACTIVE_DATA)
            logger.info("Initialized enhanced_nl_engine with ACTIVE_DATA")
        except Exception as e:
            logger.error(f"Error initializing enhanced_nl_engine: {e}", exc_info=True)
        
        # Initialize AI retrieval engine with new data
        try:
            ai_retrieval_engine = AIUFDRRetrievalEngine(ACTIVE_DATA)
            logger.info("Initialized ai_retrieval_engine with ACTIVE_DATA")
        except Exception as e:
            logger.error(f"Error initializing ai_retrieval_engine: {e}", exc_info=True)
        
        # Create metadata-only response function (for faster initial load)
        def create_metadata_response(ufdr_data, zip_info):
            """Create metadata-only response with counts and samples."""
            contacts_list = ufdr_data.get('contacts', [])
            messages_list = ufdr_data.get('messages', [])
            calls_list = ufdr_data.get('call_logs', [])
            images_list = ufdr_data.get('images', [])
            videos_list = ufdr_data.get('videos', [])
            
            return {
                'contacts': {
                    'count': len(contacts_list) if isinstance(contacts_list, list) else 0,
                    'sample': contacts_list[:10] if isinstance(contacts_list, list) and len(contacts_list) > 10 else (contacts_list if isinstance(contacts_list, list) else [])
                },
                'messages': {
                    'count': len(messages_list) if isinstance(messages_list, list) else 0,
                    'sample': messages_list[:10] if isinstance(messages_list, list) and len(messages_list) > 10 else (messages_list if isinstance(messages_list, list) else [])
                },
                'call_logs': {
                    'count': len(calls_list) if isinstance(calls_list, list) else 0,
                    'sample': calls_list[:10] if isinstance(calls_list, list) and len(calls_list) > 10 else (calls_list if isinstance(calls_list, list) else [])
                },
                'images': {
                    'count': len(images_list) if isinstance(images_list, list) else 0,
                    'total_size': sum(img.get('size', 0) for img in images_list if isinstance(img, dict))
                },
                'videos': {
                    'count': len(videos_list) if isinstance(videos_list, list) else 0,
                    'total_size': sum(vid.get('size', 0) for vid in videos_list if isinstance(vid, dict))
                },
                'device': ufdr_data.get('device', {}),
                'full_data_loaded': True  # Full data is in ACTIVE_DATA, metadata is for response
            }
        
        # Prepare quick stats for immediate UI update
        # Ensure we're working with lists and handle both formats
        contacts_list = data.get("contacts", [])
        messages_list = data.get("messages", [])
        calls_list = data.get("call_logs", data.get("calls", []))
        
        # Handle V2 format with devices array
        if not isinstance(contacts_list, list) or len(contacts_list) == 0:
            devices = data.get("devices", [])
            if devices and isinstance(devices, list):
                contacts_list = []
                messages_list = []
                calls_list = []
                for device in devices:
                    if isinstance(device, dict):
                        contacts_list.extend(device.get("contacts", []))
                        messages_list.extend(device.get("messages", []))
                        calls_list.extend(device.get("call_logs", device.get("calls", [])))
        
        quick_stats = {
            "total_files": 1,
            "total_contacts": len(contacts_list) if isinstance(contacts_list, list) else 0,
            "total_messages": len(messages_list) if isinstance(messages_list, list) else 0,
            "total_calls": len(calls_list) if isinstance(calls_list, list) else 0,
            "tampered_files": 1 if data.get("tampered", False) else 0,
            "clean_files": 0 if data.get("tampered", False) else 1
        }
        
        logger.info(f"Quick stats calculated: contacts={quick_stats['total_contacts']}, messages={quick_stats['total_messages']}, calls={quick_stats['total_calls']}")
        
        # Add ZIP info to stats if it's a ZIP file
        if zip_info.get('is_zip'):
            quick_stats['is_zip'] = True
            _zi = len(zip_info.get('images', []))
            _zv = len(zip_info.get('videos', []))
            quick_stats['images_count'] = _zi
            quick_stats['videos_count'] = _zv
            quick_stats['total_media'] = _zi + _zv
            quick_stats['json_files_count'] = len(zip_info.get('json_files', []))
        
        # Create metadata response
        metadata_response = create_metadata_response(data, zip_info)

        # Use encrypted filename in response if file was encrypted
        response_filename = original_encrypted_filepath.split(os.sep)[-1] if original_encrypted_filepath else filename

        response_data = {
            "status": "SUCCESS",
            "message": "File uploaded successfully and set as active.",
            "filename": response_filename,
            "active": True,
            "quick_stats": quick_stats,
            "metadata": metadata_response,  # Include metadata response
            "validation": {
                "is_valid": True,
                "message": validation_result['message']
            }
        }
        
        if warnings:
            response_data["warnings"] = warnings
        
        # Verify data is accessible before returning
        try:
            verify_data = get_current_data()
            if not verify_data or active_filename not in verify_data:
                logger.warning(f"Data verification failed: filename {active_filename} not in ACTIVE_DATA")
            else:
                logger.info(f"Data verification successful: filename {active_filename} found in ACTIVE_DATA with {len(verify_data[active_filename].get('contacts', []))} contacts, {len(verify_data[active_filename].get('messages', []))} messages")
        except Exception as e:
            logger.error(f"Error verifying data: {e}", exc_info=True)
        
        # Reset semantic extractor's data index cache when new file is uploaded
        global semantic_extractor
        if semantic_extractor:
            semantic_extractor._data_index = {}  # Clear cached data index to force rebuild
            logger.info("✅ Cleared semantic extractor data index cache for new upload")
        
        # Rebuild RAG index after successful upload
        try:
            rebuild_rag_index()
            logger.info("✅ RAG index rebuilt successfully with new data")
        except Exception as e:
            logger.warning(f"Error rebuilding RAG index: {e}", exc_info=True)
        
        # Clean up temporary decrypted file if it was created
        if temp_decrypted_file and os.path.exists(temp_decrypted_file):
            try:
                os.remove(temp_decrypted_file)
                logger.info(f"✅ Cleaned up temporary decrypted file: {temp_decrypted_file}")
            except Exception as e:
                logger.warning(f"Failed to clean up temp decrypted file {temp_decrypted_file}: {e}")
        
        return jsonify(response_data)
    
    except Exception as e:
        # Catch any unhandled exceptions
        logger.error(f"Error in upload_file: {str(e)}", exc_info=True)
        # Try to remove file if it was saved
        try:
            if 'filepath' in locals() and os.path.exists(filepath):
                os.remove(filepath)
            # Also clean up temp decrypted file if it exists
            if 'temp_decrypted_file' in locals() and temp_decrypted_file and os.path.exists(temp_decrypted_file):
                os.remove(temp_decrypted_file)
                logger.info(f"✅ Cleaned up temp decrypted file on error: {temp_decrypted_file}")
        except:
            pass
        
        # Provide user-friendly error message
        error_msg = str(e)
        if "timeout" in error_msg.lower():
            return jsonify({
                "status": "ERROR",
                "message": "Upload timeout. The file might be too large or the server is busy. Please try again."
            }), 500
        elif "memory" in error_msg.lower() or "MemoryError" in error_msg:
            return jsonify({
                "status": "ERROR",
                "message": "File is too large to process. Please reduce the file size or split it into smaller files."
            }), 500
        else:
            return jsonify({
                "status": "ERROR",
                "message": f"Error processing file: {error_msg}. Please check the file format and try again."
            }), 500

@app.route('/api/uploaded-files')
def get_uploaded_files():
    """Get list of uploaded files (JSON and ZIP) for current session."""
    try:
        uploaded_files = []
        has_active_forensic_data = bool(ACTIVE_FILENAME or ACTIVE_DATA or ACTIVE_DATA_LAYERS)
        
        # If we have a session_id, get files from session_files table
        if SESSION_DB_AVAILABLE:
            session_id = session.get('session_id') or request.args.get('session_id')
            logger.info(f"📋 Getting uploaded files for session_id: {session_id}")
            
            if session_id and session_id != 'None' and session_id != '':
                session_files = get_session_files(session_id)
                logger.info(f"📁 Found {len(session_files)} file(s) in database for session {session_id}")
                
                for file_record in session_files:
                    filename = file_record['filename']
                    file_path_recorded = file_record.get('file_path', filename)
                    # Use recorded path or fallback to UPLOAD_FOLDER
                    if os.path.isabs(file_path_recorded) and os.path.exists(file_path_recorded):
                        file_path = file_path_recorded
                    else:
                        file_path = os.path.join(UPLOAD_FOLDER, filename)
                    
                    # Check if file exists (try both encrypted and unencrypted versions)
                    if not os.path.exists(file_path):
                        # Try encrypted version
                        encrypted_path = file_path + '.encrypted'
                        if os.path.exists(encrypted_path):
                            file_path = encrypted_path
                        else:
                            logger.warning(f"   ⚠️ File not found: {filename} at {file_path} or {encrypted_path}")
                            continue
                    
                    if os.path.exists(file_path):
                        file_size = os.path.getsize(file_path)
                        # Determine file type (check original filename, not encrypted path)
                        base_filename = filename.replace('.encrypted', '')
                        if base_filename.endswith('.xml'):
                            file_type = 'XML'
                        elif base_filename.endswith('.zip') or base_filename.endswith('.ufdr'):
                            file_type = 'ZIP'
                        elif base_filename.endswith('.db'):
                            # Skip .db files (they're created by XML parser, not user uploads)
                            continue
                        else:
                            file_type = 'JSON'
                        # Check if it's encrypted
                        is_encrypted = file_path.endswith('.encrypted')
                        # Check if this file is active (check both encrypted and base filename)
                        base_filename_check = filename.replace('.encrypted', '')
                        is_active = (filename == ACTIVE_FILENAME or 
                                   base_filename_check == ACTIVE_FILENAME or
                                   filename in ACTIVE_DATA_LAYERS or
                                   base_filename_check in ACTIVE_DATA_LAYERS)
                        uploaded_files.append({
                            "filename": filename,  # Keep original filename from database
                            "size": file_size,
                            "size_mb": round(file_size / (1024 * 1024), 2),
                            "type": file_type,
                            "encrypted": is_encrypted,
                            "active": is_active
                        })
                        logger.info(f"   ✅ Added file: {filename} {'(encrypted)' if is_encrypted else ''}")
                    else:
                        logger.warning(f"   ⚠️ File not found: {filename} at {file_path}")
                
                return jsonify({
                    "uploaded_files": uploaded_files,
                    "count": len(uploaded_files),
                    "session_id": session_id,
                    "has_active_forensic_data": has_active_forensic_data,
                })
            else:
                logger.warning(f"⚠️ No valid session_id provided")
        
        # Fallback: get all files from UPLOAD_FOLDER (for backward compatibility)
        logger.info(f"📂 Falling back to UPLOAD_FOLDER listing")
        if os.path.exists(UPLOAD_FOLDER):
            for file in os.listdir(UPLOAD_FOLDER):
                # Skip .db files (created by parsers)
                if file.endswith('.db'):
                    continue
                
                # Check for encrypted files first
                is_encrypted_file = file.endswith('.encrypted')
                base_filename = file.replace('.encrypted', '') if is_encrypted_file else file
                
                # Include XML files, JSON, ZIP, UFDR
                if base_filename.endswith('.json') or base_filename.endswith('.zip') or base_filename.endswith('.ufdr') or base_filename.endswith('.xml'):
                    file_path = os.path.join(UPLOAD_FOLDER, file)
                    
                    # Skip if file doesn't exist
                    if not os.path.exists(file_path):
                        continue
                    
                    file_size = os.path.getsize(file_path)
                    
                    # Determine file type from base filename
                    if base_filename.endswith('.xml'):
                        file_type = 'XML'
                    elif base_filename.endswith('.zip') or base_filename.endswith('.ufdr'):
                        file_type = 'ZIP'
                    else:
                        file_type = 'JSON'
                    
                    # Check if this file is active (check both encrypted and unencrypted versions)
                    is_active = (file == ACTIVE_FILENAME or 
                               base_filename == ACTIVE_FILENAME or
                               file.replace('.encrypted', '') == ACTIVE_FILENAME or
                               base_filename in ACTIVE_DATA_LAYERS or
                               file in ACTIVE_DATA_LAYERS)
                    
                    uploaded_files.append({
                        "filename": file,  # Use actual filename (may include .encrypted)
                        "size": file_size,
                        "size_mb": round(file_size / (1024 * 1024), 2),
                        "type": file_type,
                        "encrypted": is_encrypted_file,
                        "active": is_active
                    })
                    logger.info(f"   ✅ Added file from folder: {file} ({file_type}, {'encrypted' if is_encrypted_file else 'unencrypted'}, active: {is_active})")
        
        return jsonify({
            "uploaded_files": uploaded_files,
            "count": len(uploaded_files),
            "has_active_forensic_data": has_active_forensic_data,
        })
    except Exception as e:
        logger.error(f"❌ Error getting uploaded files: {e}", exc_info=True)
        return jsonify({"error": str(e)})

@app.route('/api/clear-uploads', methods=['POST'])
def clear_uploads():
    """Clear all uploaded files (including encrypted versions)."""
    try:
        files_removed = []
        if os.path.exists(UPLOAD_FOLDER):
            for file in os.listdir(UPLOAD_FOLDER):
                file_path = os.path.join(UPLOAD_FOLDER, file)
                # Remove all files except .encrypted files (we'll handle those separately)
                # Include XML files, skip .db files (created by parsers)
                if file.endswith('.json') or file.endswith('.zip') or file.endswith('.ufdr') or file.endswith('.xml'):
                    # Skip if this is an encrypted file (we'll remove it when we find the original)
                    if not file.endswith('.encrypted') and not file.endswith('.db'):
                        try:
                            os.remove(file_path)
                            files_removed.append(file)
                        except Exception as e:
                            logger.warning(f"Failed to remove {file}: {e}")
                # Also remove encrypted files
                elif file.endswith('.encrypted'):
                    try:
                        os.remove(file_path)
                        files_removed.append(file)
                    except Exception as e:
                        logger.warning(f"Failed to remove {file}: {e}")
        
        # Clear active context; require upload before answering
        global ACTIVE_FILENAME, ACTIVE_DATA
        ACTIVE_FILENAME = None
        ACTIVE_DATA = {}
        nl_engine.update_data(ACTIVE_DATA)
        
        # Rebuild RAG index after clearing
        try:
            rebuild_rag_index()
        except Exception:
            pass
        return jsonify({
            "status": "SUCCESS",
            "message": "All uploaded files cleared. Using only synthetic data."
        })
    except Exception as e:
        return jsonify({"status": "ERROR", "message": f"Error clearing files: {str(e)}"})

@app.route('/api/analyze-ufdr', methods=['POST'])
def analyze_ufdr():
    """
    Analyze a UFDR file structure before uploading.
    Accepts file upload and returns detailed analysis.
    """
    try:
        if 'file' not in request.files:
            return jsonify({
                "status": "ERROR",
                "message": "No file provided"
            }), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({
                "status": "ERROR",
                "message": "No file selected"
            }), 400
        
        # Save file temporarily for analysis
        import tempfile
        temp_dir = tempfile.mkdtemp()
        temp_filepath = os.path.join(temp_dir, secure_filename(file.filename))
        file.save(temp_filepath)
        
        try:
            # Analyze the file
            analysis_result = analyze_ufdr_file(temp_filepath)
            
            if not analysis_result.get('success'):
                return jsonify({
                    "status": "ERROR",
                    "message": analysis_result.get('error', 'Analysis failed'),
                    "analysis": analysis_result
                }), 400
            
            return jsonify({
                "status": "SUCCESS",
                "message": "File analyzed successfully",
                "analysis": analysis_result
            }), 200
            
        finally:
            # Clean up temp file
            try:
                if os.path.exists(temp_filepath):
                    os.remove(temp_filepath)
                if os.path.exists(temp_dir):
                    os.rmdir(temp_dir)
            except:
                pass
    
    except Exception as e:
        logger.error(f"Error in analyze_ufdr endpoint: {e}", exc_info=True)
        return jsonify({
            "status": "ERROR",
            "message": f"Analysis failed: {str(e)}"
        }), 500

@app.route('/api/remove-upload/<filename>', methods=['DELETE'])
def remove_upload(filename):
    """Remove a specific uploaded file (both encrypted and decrypted versions)."""
    try:
        # Secure the filename
        secure_name = secure_filename(filename)
        file_path = os.path.join(UPLOAD_FOLDER, secure_name)
        
        files_removed = []
        
        # Check if file exists (could be encrypted or unencrypted)
        if os.path.exists(file_path):
            os.remove(file_path)
            files_removed.append(secure_name)
            logger.info(f"Removed file: {secure_name}")
        
        # Also check for encrypted version
        encrypted_file_path = file_path + '.encrypted'
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)
            files_removed.append(secure_name + '.encrypted')
            logger.info(f"Removed encrypted file: {secure_name}.encrypted")
        
        # Also check if the file being deleted IS an encrypted file, remove decrypted version too
        if secure_name.endswith('.encrypted'):
            decrypted_file_path = file_path.replace('.encrypted', '')
            if os.path.exists(decrypted_file_path):
                os.remove(decrypted_file_path)
                files_removed.append(secure_name.replace('.encrypted', ''))
                logger.info(f"Removed decrypted file: {secure_name.replace('.encrypted', '')}")
        
        # If removing XML file, also remove associated .db file
        base_name = secure_name.replace('.encrypted', '')
        if base_name.endswith('.xml'):
            db_file_path = file_path + '.db'
            if os.path.exists(db_file_path):
                try:
                    os.remove(db_file_path)
                    files_removed.append(base_name + '.db')
                    logger.info(f"Removed associated database file: {base_name}.db")
                except Exception as e:
                    logger.warning(f"Failed to remove database file {base_name}.db: {e}")
        
        # Also remove from ACTIVE_DATA_LAYERS if it's a Cellebrite file
        global ACTIVE_DATA_LAYERS, ACTIVE_DB_PATHS
        if base_name in ACTIVE_DATA_LAYERS:
            try:
                # Close database connection
                data_layer = ACTIVE_DATA_LAYERS[base_name]
                if hasattr(data_layer, '_conn') and data_layer._conn:
                    data_layer._conn.close()
                del ACTIVE_DATA_LAYERS[base_name]
                logger.info(f"Removed data layer for {base_name}")
            except Exception as e:
                logger.warning(f"Error removing data layer: {e}")
        
        if base_name in ACTIVE_DB_PATHS:
            del ACTIVE_DB_PATHS[base_name]
        
        if not files_removed:
            return jsonify({
                "status": "ERROR",
                "message": f"File {filename} not found."
            })
        
        # Remove from session_files table if we have a session_id
        if SESSION_DB_AVAILABLE:
            session_id = session.get('session_id')
            if session_id and session_id != 'None' and session_id != '':
                # Remove both encrypted and unencrypted versions from database
                delete_session_file(session_id, secure_name)
                if secure_name.endswith('.encrypted'):
                    delete_session_file(session_id, secure_name.replace('.encrypted', ''))
                else:
                    delete_session_file(session_id, secure_name + '.encrypted')
                logger.info(f"Removed file {secure_name} from session {session_id}")
        
        # If the removed file was active, clear active context
        global ACTIVE_FILENAME, ACTIVE_DATA
        base_name = secure_name.replace('.encrypted', '')
        if base_name == (ACTIVE_FILENAME or "").replace('.encrypted', ''):
            ACTIVE_FILENAME = None
            ACTIVE_DATA = {}
            nl_engine.update_data(ACTIVE_DATA)
        
        return jsonify({
            "status": "SUCCESS",
            "message": f"File {filename} removed successfully. ({len(files_removed)} file(s) deleted)",
            "files_removed": files_removed
        })
    except Exception as e:
        logger.error(f"Error removing file: {e}", exc_info=True)
        return jsonify({"status": "ERROR", "message": f"Error removing file: {str(e)}"})

@app.route('/api/stats')
def get_stats():
    """Get basic statistics about the loaded data."""
    try:
        data_src = get_current_data()
        # Compute AI summary strictly from ACTIVE_DATA if analyzer exists
        ai_summary_out = {"analysis_available": False}
        try:
            if data_src and hasattr(engine, 'ai_analyzer') and engine.ai_analyzer:
                ai_summary = engine.ai_analyzer.analyze_multiple_files(data_src)
                ai_summary_out = {
                    "analysis_available": True,
                    "total_files_analyzed": len(data_src),
                    "risk_distribution": ai_summary.get("comparative_analysis", {}).get("risk_distribution", {}),
                    "average_risk_score": ai_summary.get("comparative_analysis", {}).get("average_risk_score", 0),
                    "overall_assessment": ai_summary.get("summary", {}).get("overall_assessment", "")
                }
        except Exception:
            ai_summary_out = {"analysis_available": False}

        # Calculate stats with proper nested structure handling
        total_contacts = 0
        total_messages = 0
        total_calls = 0
        total_chats = 0
        total_locations = 0
        total_device_files = 0
        total_device_networking = 0
        device_networking_stat_present = False
        total_images = 0
        total_videos = 0
        total_other_media = 0
        is_zip_file = False
        
        # Check for Cellebrite data layers (XML/DB format)
        global ACTIVE_DATA_LAYERS, ACTIVE_DB_PATHS
        
        # If ACTIVE_DATA_LAYERS is empty, try to reload from existing .db files
        if not ACTIVE_DATA_LAYERS and os.path.exists(UPLOAD_FOLDER):
            logger.info("ACTIVE_DATA_LAYERS is empty, checking for existing .db files to reload")
            for file in os.listdir(UPLOAD_FOLDER):
                if file.endswith('.db'):
                    # Find corresponding XML file
                    xml_filename = file.replace('.db', '')
                    xml_path = os.path.join(UPLOAD_FOLDER, xml_filename)
                    db_path = os.path.join(UPLOAD_FOLDER, file)
                    
                    # Check if XML file exists (could be encrypted)
                    if not os.path.exists(xml_path):
                        encrypted_path = xml_path + '.encrypted'
                        if os.path.exists(encrypted_path):
                            xml_path = encrypted_path
                        else:
                            continue
                    
                    try:
                        data_layer = CellebriteDataAccessLayer(db_path, xml_path)
                        ACTIVE_DATA_LAYERS[xml_filename] = data_layer
                        ACTIVE_DB_PATHS[xml_filename] = db_path
                        logger.info(f"✅ Reloaded XML data layer for {xml_filename}")
                    except Exception as e:
                        logger.warning(f"Failed to reload data layer for {xml_filename}: {e}")
        
        logger.info(f"📊 Stats calculation: ACTIVE_DATA_LAYERS has {len(ACTIVE_DATA_LAYERS)} entries: {list(ACTIVE_DATA_LAYERS.keys())}")
        logger.info(f"📊 ACTIVE_DB_PATHS has {len(ACTIVE_DB_PATHS)} entries: {list(ACTIVE_DB_PATHS.keys())}")
        
        # Track which databases have already been counted to avoid double-counting
        # (same database might be registered with both encrypted and base filename)
        counted_databases = set()
        logger.info(f"📊 Starting stats calculation - will track counted databases to prevent duplicates")
        
        if ACTIVE_DATA_LAYERS:
            for filename, data_layer in ACTIVE_DATA_LAYERS.items():
                conn = None
                try:
                    # Get the database path for this data layer to check if we've already counted it
                    db_path = ACTIVE_DB_PATHS.get(filename)
                    if not db_path:
                        # Try to get db_path from base filename if current filename is encrypted
                        base_filename = filename.replace('.encrypted', '')
                        db_path = ACTIVE_DB_PATHS.get(base_filename)
                    
                    # Skip if we've already counted this database (prevents double-counting)
                    if db_path and db_path in counted_databases:
                        logger.info(f"  ⏭️ Skipping {filename} - database already counted: {db_path}")
                        continue
                    
                    if db_path:
                        counted_databases.add(db_path)
                    
                    # Query database for counts (create new connection for thread safety)
                    conn = data_layer.get_connection()
                    cursor = conn.cursor()
                    
                    # Count contacts
                    cursor.execute("SELECT COUNT(*) FROM contacts")
                    contacts_count = cursor.fetchone()[0] or 0
                    total_contacts += contacts_count
                    logger.info(f"  📇 {filename}: {contacts_count} contacts")
                    
                    # Count messages
                    cursor.execute("SELECT COUNT(*) FROM messages")
                    messages_count = cursor.fetchone()[0] or 0
                    total_messages += messages_count
                    logger.info(f"  💬 {filename}: {messages_count} messages")
                    
                    # Count calls
                    cursor.execute("SELECT COUNT(*) FROM call_logs")
                    calls_count = cursor.fetchone()[0] or 0
                    total_calls += calls_count
                    logger.info(f"  📞 {filename}: {calls_count} calls")
                    
                    # Count chats
                    cursor.execute("SELECT COUNT(*) FROM chats")
                    chats_count = cursor.fetchone()[0] or 0
                    total_chats += chats_count
                    logger.info(f"  💭 {filename}: {chats_count} chats")
                    
                    # Count locations
                    cursor.execute("SELECT COUNT(*) FROM locations")
                    locations_count = cursor.fetchone()[0] or 0
                    total_locations += locations_count
                    logger.info(f"  📍 {filename}: {locations_count} locations")
                    
                    # Count files
                    cursor.execute("SELECT COUNT(*) FROM files")
                    files_count = cursor.fetchone()[0] or 0
                    total_device_files += files_count
                    logger.info(f"  📁 {filename}: {files_count} files")

                    # Reader-style "Devices & Networks" (decoded artifacts; XML reports only)
                    try:
                        cursor.execute(
                            "SELECT value FROM device_metadata WHERE key = ? AND category = ?",
                            ('device_networking_total', 'stats'),
                        )
                        row_dn = cursor.fetchone()
                        if row_dn and row_dn[0] is not None and str(row_dn[0]).strip() != '':
                            total_device_networking += int(row_dn[0])
                            device_networking_stat_present = True
                    except Exception as e:
                        logger.debug(f"device_networking_total not available: {e}")
                    
                    # Count images/videos from media_index
                    cursor.execute("SELECT COUNT(*) FROM media_index WHERE media_type = 'image'")
                    images_count = cursor.fetchone()[0] or 0
                    total_images += images_count
                    
                    cursor.execute("SELECT COUNT(*) FROM media_index WHERE media_type = 'video'")
                    videos_count = cursor.fetchone()[0] or 0
                    total_videos += videos_count

                    cursor.execute("SELECT COUNT(*) FROM media_index WHERE media_type = 'other'")
                    other_media_count = cursor.fetchone()[0] or 0
                    total_other_media += other_media_count
                    
                except Exception as e:
                    logger.error(f"❌ Error getting stats from data layer {filename}: {e}", exc_info=True)
                finally:
                    # Always close connection to prevent thread issues
                    if conn:
                        try:
                            conn.close()
                        except:
                            pass
        
        # Check for ZIP info (images/videos from ZIP files)
        if '_zip_info' in data_src:
            zip_info = data_src.get('_zip_info', {})
            if zip_info.get('is_zip'):
                is_zip_file = True
                total_images = len(zip_info.get('images', []))
                total_videos = len(zip_info.get('videos', []))
        
        # Log data source info for debugging
        logger.info(f"Stats calculation: data_src has {len(data_src)} items, keys: {list(data_src.keys())}")
        
        # Also check in file data (if ZIP info is nested in file data)
        for filename, file_data in data_src.items():
            if filename == '_zip_info':
                continue  # Skip ZIP info metadata
                
            if isinstance(file_data, dict):
                # Check for ZIP info in file data
                if '_zip_info' in file_data:
                    zip_info = file_data.get('_zip_info', {})
                    if zip_info.get('is_zip'):
                        is_zip_file = True
                        total_images = len(zip_info.get('images', []))
                        total_videos = len(zip_info.get('videos', []))
                
                # Handle nested structure with devices array (V2 format)
                devices = file_data.get("devices", [])
                if devices and isinstance(devices, list) and len(devices) > 0:
                    # V2 format: data is in devices array
                    for device in devices:
                        if isinstance(device, dict):
                            total_contacts += len(device.get("contacts", []))
                            total_messages += len(device.get("messages", []))
                            total_calls += len(device.get("call_logs", device.get("calls", [])))
                            total_chats += len(device.get("chats", []))
                            total_locations += len(device.get("locations", []))
                            total_device_files += len(device.get("files", []))
                else:
                    # V1 format: flat structure (contacts, messages, call_logs at top level)
                    # This is the format returned by normalize_zip_to_ufdr() and normalize_ufdr_data()
                    file_contacts = file_data.get("contacts", [])
                    file_messages = file_data.get("messages", [])
                    file_calls = file_data.get("call_logs", file_data.get("calls", []))
                    file_chats = file_data.get("chats", [])
                    file_locations = file_data.get("locations", [])
                    
                    # Ensure we're working with lists
                    if isinstance(file_contacts, list):
                        total_contacts += len(file_contacts)
                    if isinstance(file_messages, list):
                        total_messages += len(file_messages)
                    if isinstance(file_calls, list):
                        total_calls += len(file_calls)
                    if isinstance(file_chats, list):
                        total_chats += len(file_chats)
                    if isinstance(file_locations, list):
                        total_locations += len(file_locations)
                    total_device_files += len(file_data.get("files", []))
                    
                    # Log for debugging
                    logger.info(f"Stats for {filename}: contacts={len(file_contacts) if isinstance(file_contacts, list) else 0}, messages={len(file_messages) if isinstance(file_messages, list) else 0}, calls={len(file_calls) if isinstance(file_calls, list) else 0}, chats={len(file_chats) if isinstance(file_chats, list) else 0}, locations={len(file_locations) if isinstance(file_locations, list) else 0}")
                    logger.debug(f"File data keys for {filename}: {list(file_data.keys())[:10]}")  # Log first 10 keys

        # Count actual files (exclude _zip_info which is metadata)
        actual_files = {k: v for k, v in data_src.items() if k != '_zip_info'}
        
        total_media = total_images + total_videos + total_other_media
        stats = {
            "total_files": len(actual_files),
            "tampered_files": sum(1 for data in actual_files.values() if isinstance(data, dict) and data.get("tampered", False)),
            "clean_files": sum(1 for data in actual_files.values() if isinstance(data, dict) and not data.get("tampered", False)),
            "total_contacts": total_contacts,
            "total_messages": total_messages,
            "total_calls": total_calls,
            "total_chats": total_chats,
            "total_locations": total_locations,
            "total_files_count": total_device_files,
            "total_device_files": total_device_files,
            "device_networking": (total_device_networking if device_networking_stat_present else None),
            "total_images": total_images,
            "total_videos": total_videos,
            "total_other_media": total_other_media,
            "total_media": total_media,
            "is_zip": is_zip_file,
            "uploaded_files_count": len([f for f in os.listdir(UPLOAD_FOLDER) if f.endswith('.json')]) if os.path.exists(UPLOAD_FOLDER) else 0,
            "ai_analysis": ai_summary_out
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/stats/platforms', methods=['GET'])
def get_platform_stats():
    """Get platform breakdown for chats with message type distribution."""
    try:
        global ACTIVE_DATA_LAYERS
        
        platforms_data = []
        
        if ACTIVE_DATA_LAYERS:
            for filename, data_layer in ACTIVE_DATA_LAYERS.items():
                try:
                    conn = data_layer.get_connection()
                    cursor = conn.cursor()
                    
                    # Get platform distribution with message type breakdown
                    cursor.execute("""
                        SELECT platform, COUNT(DISTINCT c.chat_id) as chat_count
                        FROM chats c
                        WHERE c.platform IS NOT NULL AND c.platform != ''
                        GROUP BY c.platform
                        ORDER BY chat_count DESC
                    """)
                    platforms = cursor.fetchall()
                    
                    for row in platforms:
                        platform = row['platform']
                        chat_count = row['chat_count']
                        
                        # Count messages for this platform
                        # Count DISTINCT messages at platform level to avoid double-counting when duplicate chats exist
                        # First, get all unique message IDs for this platform
                        cursor.execute("""
                            SELECT COUNT(DISTINCT cm.id) as total_msgs
                            FROM chat_messages cm
                            WHERE cm.platform = ?
                            AND cm.source_table = 'Chat'
                        """, (platform,))
                        result = cursor.fetchone()
                        total_msgs = result['total_msgs'] if result else 0
                        
                        # Count deleted messages for this platform
                        cursor.execute("""
                            SELECT COUNT(DISTINCT cm.id) as deleted_msgs
                            FROM chat_messages cm
                            WHERE cm.platform = ?
                            AND cm.source_table = 'Chat'
                            AND cm.is_deleted = 1
                        """, (platform,))
                        deleted_result = cursor.fetchone()
                        deleted_msgs = deleted_result['deleted_msgs'] if deleted_result else 0
                        
                        # Also get per-chat counts for display (but don't sum them - use platform-level count)
                        cursor.execute("""
                            SELECT 
                                c.chat_id,
                                COUNT(DISTINCT cm.id) as msg_count_per_chat
                            FROM chats c
                            LEFT JOIN chat_messages cm ON (
                                (
                                    (cm.chat_id = c.chat_id AND cm.chat_id IS NOT NULL AND cm.chat_id != '')
                                    OR 
                                    (cm.chat_name = c.chat_name AND cm.chat_name IS NOT NULL AND cm.chat_name != '')
                                )
                                AND cm.platform = c.platform
                                AND cm.source_table = 'Chat'
                            )
                            WHERE c.platform = ?
                            GROUP BY c.chat_id
                        """, (platform,))
                        chat_msg_counts = cursor.fetchall()
                        
                        # Get message type breakdown (for display, but not used in total count)
                        cursor.execute("""
                            SELECT 
                                COALESCE(cm.message_type, 'unknown') as message_type,
                                COUNT(DISTINCT cm.id) as msg_count
                            FROM chat_messages cm
                            INNER JOIN chats c ON (
                                (
                                    (cm.chat_id = c.chat_id AND cm.chat_id IS NOT NULL AND cm.chat_id != '')
                                    OR 
                                    (cm.chat_name = c.chat_name AND cm.chat_name IS NOT NULL AND cm.chat_name != '')
                                )
                                AND cm.platform = c.platform
                                AND cm.source_table = 'Chat'
                            )
                            WHERE c.platform = ?
                            GROUP BY cm.message_type
                        """, (platform,))
                        type_counts = cursor.fetchall()
                        
                        type_breakdown = {}
                        for type_row in type_counts:
                            msg_type = type_row['message_type'] or 'unknown'
                            msg_count = type_row['msg_count']
                            type_breakdown[msg_type] = msg_count
                        
                        platforms_data.append({
                            'platform': platform,
                            'chat_count': chat_count,
                            'message_count': total_msgs,
                            'deleted_message_count': deleted_msgs,
                            'message_types': type_breakdown
                        })
                    
                    conn.close()
                except Exception as e:
                    logger.error(f"Error getting platform stats from {filename}: {e}", exc_info=True)
        
        # Aggregate platforms across all data layers (in case multiple files)
        aggregated = {}
        for platform_data in platforms_data:
            platform = platform_data['platform']
            if platform not in aggregated:
                aggregated[platform] = {
                    'platform': platform,
                    'chat_count': 0,
                    'message_count': 0,
                    'deleted_message_count': 0,
                    'message_types': {}
                }
            aggregated[platform]['chat_count'] += platform_data['chat_count']
            aggregated[platform]['message_count'] += platform_data['message_count']
            aggregated[platform]['deleted_message_count'] += platform_data.get('deleted_message_count', 0)
            for msg_type, count in platform_data['message_types'].items():
                aggregated[platform]['message_types'][msg_type] = aggregated[platform]['message_types'].get(msg_type, 0) + count
        
        # Convert to list and sort by chat count
        result = sorted(aggregated.values(), key=lambda x: x['chat_count'], reverse=True)
        
        return jsonify({
            "platforms": result,
            "total_platforms": len(result)
        })
    except Exception as e:
        logger.error(f"Error getting platform stats: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/stats/call-platforms', methods=['GET'])
def get_call_platform_stats():
    """Get platform breakdown for call logs."""
    try:
        global ACTIVE_DATA_LAYERS

        platform_counts = {}
        total_calls = 0

        if ACTIVE_DATA_LAYERS:
            for _, data_layer in ACTIVE_DATA_LAYERS.items():
                try:
                    conn = data_layer.get_connection()
                    cursor = conn.cursor()

                    # Check if call_logs has platform column (older schema does not)
                    cursor.execute("PRAGMA table_info(call_logs)")
                    call_cols = {str(r["name"]).lower() for r in cursor.fetchall()}
                    rows = []

                    if "platform" in call_cols:
                        cursor.execute("""
                            SELECT COALESCE(platform, 'Unknown') AS platform_name, COUNT(*) AS call_count
                            FROM call_logs
                            GROUP BY COALESCE(platform, 'Unknown')
                        """)
                        rows = cursor.fetchall()
                    else:
                        # Fallback 1: derive platform from call_logs.raw_data Source/App fields
                        # XML parser stores call platform inside raw_data payload even when call_logs has no platform column.
                        cursor.execute("SELECT raw_data FROM call_logs")
                        raw_rows = cursor.fetchall()
                        parsed_counts = {}
                        for rr in raw_rows:
                            raw = rr["raw_data"] if rr and "raw_data" in rr.keys() else None
                            platform_name = None
                            if raw:
                                try:
                                    obj = json.loads(raw) if isinstance(raw, str) else raw
                                    if isinstance(obj, dict):
                                        platform_name = (
                                            obj.get("Source")
                                            or obj.get("source")
                                            or obj.get("App")
                                            or obj.get("Application")
                                            or obj.get("Service")
                                        )
                                except Exception:
                                    platform_name = None
                            if not platform_name:
                                platform_name = "Unknown"
                            platform_name = str(platform_name).strip() or "Unknown"
                            parsed_counts[platform_name] = parsed_counts.get(platform_name, 0) + 1

                        rows = [{"platform_name": k, "call_count": v} for k, v in parsed_counts.items()]

                        # Fallback 2: derive call activity per platform from chat_messages
                        # (works for app call events like WhatsApp/Telegram/Line/etc.)
                        if not rows:
                            cursor.execute("""
                                SELECT COALESCE(platform, 'Unknown') AS platform_name, COUNT(*) AS call_count
                                FROM chat_messages
                                WHERE (
                                    LOWER(COALESCE(message_type, '')) IN ('call', 'voip', 'system')
                                    AND LOWER(COALESCE(text_content, '')) LIKE '%call%'
                                )
                                OR LOWER(COALESCE(text_content, '')) LIKE '%incoming call%'
                                OR LOWER(COALESCE(text_content, '')) LIKE '%outgoing call%'
                                OR LOWER(COALESCE(text_content, '')) LIKE '%video call%'
                                GROUP BY COALESCE(platform, 'Unknown')
                            """)
                            rows = cursor.fetchall()

                        # Fallback 3: if still empty, group by source_db from call_logs
                        if not rows:
                            cursor.execute("""
                                SELECT COALESCE(source_db, 'Unknown') AS platform_name, COUNT(*) AS call_count
                                FROM call_logs
                                GROUP BY COALESCE(source_db, 'Unknown')
                            """)
                            rows = cursor.fetchall()

                    for row in rows:
                        platform_name = row['platform_name'] or 'Unknown'
                        call_count = int(row['call_count'] or 0)
                        if call_count <= 0:
                            continue
                        platform_counts[platform_name] = platform_counts.get(platform_name, 0) + call_count
                        total_calls += call_count
                    conn.close()
                except Exception as e:
                    logger.error(f"Error getting call platform stats: {e}", exc_info=True)

        result = [
            {"platform": name, "call_count": count}
            for name, count in platform_counts.items()
        ]

        # Normalization: in many UFDR exports, telephony call logs do not carry explicit app/source.
        # These show up as "Unknown" in our derived stats but correspond to Native call logs.
        unknown_count = platform_counts.get("Unknown", 0)
        has_native_bucket = any(str(k).strip().lower() == "native" for k in platform_counts.keys())
        if unknown_count > 0 and not has_native_bucket:
            # Move Unknown -> Native to align with Cellebrite call log grouping.
            platform_counts["Native"] = platform_counts.get("Native", 0) + unknown_count
            del platform_counts["Unknown"]
            result = [
                {"platform": name, "call_count": count}
                for name, count in platform_counts.items()
            ]

        result.sort(key=lambda x: x["call_count"], reverse=True)

        return jsonify({
            "platforms": result,
            "total_platforms": len(result),
            "total_calls": total_calls
        })
    except Exception as e:
        logger.error(f"Error getting call platform stats endpoint: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/stats/contact-platforms', methods=['GET'])
def get_contact_platform_stats():
    """Get platform/app breakdown for contacts."""
    try:
        global ACTIVE_DATA_LAYERS

        platform_counts = {}
        total_contacts = 0

        if ACTIVE_DATA_LAYERS:
            for _, data_layer in ACTIVE_DATA_LAYERS.items():
                try:
                    conn = data_layer.get_connection()
                    cursor = conn.cursor()

                    # Contacts table schema does not include explicit platform in many parsers.
                    # Derive source platform from raw_data when possible.
                    cursor.execute("SELECT source_db, source_table, raw_data FROM contacts")
                    rows = cursor.fetchall()
                    for row in rows:
                        total_contacts += 1
                        source_db = row["source_db"] if row and "source_db" in row.keys() else None
                        source_table = row["source_table"] if row and "source_table" in row.keys() else None
                        raw = row["raw_data"] if row and "raw_data" in row.keys() else None

                        platform_name = None
                        if raw:
                            try:
                                obj = json.loads(raw) if isinstance(raw, str) else raw
                                if isinstance(obj, dict):
                                    platform_name = (
                                        obj.get("Source")
                                        or obj.get("source")
                                        or obj.get("App")
                                        or obj.get("Application")
                                        or obj.get("Service")
                                    )
                            except Exception:
                                platform_name = None

                        if not platform_name and source_table:
                            platform_name = str(source_table)
                        if not platform_name and source_db:
                            platform_name = str(source_db)
                        if not platform_name:
                            platform_name = "Unknown"

                        platform_name = str(platform_name).strip() or "Unknown"
                        platform_counts[platform_name] = platform_counts.get(platform_name, 0) + 1

                    conn.close()
                except Exception as e:
                    logger.error(f"Error getting contact platform stats: {e}", exc_info=True)

        result = [
            {"platform": name, "contact_count": count}
            for name, count in platform_counts.items()
        ]
        result.sort(key=lambda x: x["contact_count"], reverse=True)

        return jsonify({
            "platforms": result,
            "total_platforms": len(result),
            "total_contacts": total_contacts
        })
    except Exception as e:
        logger.error(f"Error getting contact platform stats endpoint: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/stats/location-platforms', methods=['GET'])
def get_location_platform_stats():
    """Get platform/app breakdown for locations."""
    try:
        global ACTIVE_DATA_LAYERS

        platform_counts = {}
        total_locations = 0

        if ACTIVE_DATA_LAYERS:
            for _, data_layer in ACTIVE_DATA_LAYERS.items():
                try:
                    conn = data_layer.get_connection()
                    cursor = conn.cursor()

                    # Locations schema usually lacks explicit platform.
                    # Derive it from raw_data first, then source_table/source_db.
                    cursor.execute("SELECT source_db, source_table, raw_data FROM locations")
                    rows = cursor.fetchall()
                    for row in rows:
                        total_locations += 1
                        source_db = row["source_db"] if row and "source_db" in row.keys() else None
                        source_table = row["source_table"] if row and "source_table" in row.keys() else None
                        raw = row["raw_data"] if row and "raw_data" in row.keys() else None

                        platform_name = None
                        if raw:
                            try:
                                obj = json.loads(raw) if isinstance(raw, str) else raw
                                if isinstance(obj, dict):
                                    platform_name = (
                                        obj.get("Source")
                                        or obj.get("source")
                                        or obj.get("App")
                                        or obj.get("Application")
                                        or obj.get("Service")
                                    )
                            except Exception:
                                platform_name = None

                        if not platform_name and source_table:
                            platform_name = str(source_table)
                        if not platform_name and source_db:
                            platform_name = str(source_db)
                        if not platform_name:
                            platform_name = "Unknown"

                        platform_name = str(platform_name).strip() or "Unknown"
                        platform_counts[platform_name] = platform_counts.get(platform_name, 0) + 1

                    conn.close()
                except Exception as e:
                    logger.error(f"Error getting location platform stats: {e}", exc_info=True)

        result = [
            {"platform": name, "location_count": count}
            for name, count in platform_counts.items()
        ]
        result.sort(key=lambda x: x["location_count"], reverse=True)

        return jsonify({
            "platforms": result,
            "total_platforms": len(result),
            "total_locations": total_locations
        })
    except Exception as e:
        logger.error(f"Error getting location platform stats endpoint: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/api/images')
def get_images():
    """Get list of images from ZIP files."""
    try:
        data_src = get_current_data()
        if not data_src:
            return jsonify({"images": [], "count": 0})
        
        images_list = []
        seen_paths = set()  # Track seen paths to avoid duplicates
        
        # Check for ZIP info at top level
        if '_zip_info' in data_src:
            zip_info = data_src.get('_zip_info', {})
            if zip_info.get('is_zip'):
                for img_info in zip_info.get('images', []):
                    rel_path = img_info.get('rel_path', '')
                    if rel_path and rel_path not in seen_paths:
                        seen_paths.add(rel_path)
                        images_list.append({
                            'name': img_info.get('name', 'unknown'),
                            'path': rel_path,
                            'full_path': img_info.get('path', '')
                        })
        
        # Also check in file data
        for filename, file_data in data_src.items():
            if filename == '_zip_info':
                continue
            if isinstance(file_data, dict) and '_zip_info' in file_data:
                zip_info = file_data.get('_zip_info', {})
                if zip_info.get('is_zip'):
                    for img_info in zip_info.get('images', []):
                        rel_path = img_info.get('rel_path', '')
                        if rel_path and rel_path not in seen_paths:
                            seen_paths.add(rel_path)
                            images_list.append({
                                'name': img_info.get('name', 'unknown'),
                                'path': rel_path,
                                'full_path': img_info.get('path', '')
                            })
        
        return jsonify({
            "images": images_list,
            "count": len(images_list)
        })
    except Exception as e:
        logger.error(f"Error getting images: {e}")
        return jsonify({"images": [], "count": 0, "error": str(e)})

@app.route('/api/ai-analysis')
def get_ai_analysis():
    """Get AI analysis results."""
    try:
        if not ACTIVE_DATA:
            return jsonify({"status": "ERROR", "message": "Upload a UFDR JSON file first."})
        if not hasattr(engine, 'ai_analyzer') or not engine.ai_analyzer:
            return jsonify({"status": "ERROR", "message": "AI analyzer unavailable in this build."})
        analysis_result = engine.ai_analyzer.analyze_multiple_files(ACTIVE_DATA)
        return jsonify({
            "status": "SUCCESS",
            "analysis": analysis_result
        })
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/ai-analysis/<filename>')
def get_file_ai_analysis(filename):
    """Get AI analysis for a specific file."""
    try:
        if not hasattr(engine, 'ai_analyzer') or not engine.ai_analyzer:
            return jsonify({"status": "ERROR", "message": "AI analyzer unavailable in this build."})
        if ACTIVE_DATA and filename in ACTIVE_DATA:
            analysis = engine.ai_analyzer.analyze_ufdr_file(filename, ACTIVE_DATA[filename])
            return jsonify({
                "status": "SUCCESS",
                "analysis": analysis
            })
        else:
            return jsonify({
                "status": "NOT_FOUND",
                "message": f"File '{filename}' not found"
            })
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)})


@app.route('/api/nl-query', methods=['POST'])
def nl_query():
    """Enhanced natural language query endpoint with robust keyword detection and chat history context."""
    error_context = {"step": "initialization", "details": ""}
    
    try:
        # Step 1: Parse request data
        error_context["step"] = "request_parsing"
        try:
            data = request.get_json() or {}
            if not isinstance(data, dict):
                logger.error(f"Invalid request data type: {type(data)}")
                return jsonify({"error": "Invalid request format. Expected JSON object."}), 400
        except Exception as e:
            logger.error(f"Error parsing request JSON: {e}", exc_info=True)
            error_context["details"] = f"JSON parsing failed: {str(e)}"
            return jsonify({"error": "Invalid JSON in request body", "details": str(e)}), 400
        
        # Step 2: Extract and validate query
        error_context["step"] = "query_extraction"
        try:
            query = (data.get('query') or '').strip()
            use_enhanced = data.get('enhanced', True)  # Default to enhanced engine
            
            if not query:
                logger.warning("Empty query received")
                return jsonify({"error": "No query provided.", "step": "query_extraction"}), 400
            
            if not isinstance(query, str):
                logger.error(f"Invalid query type: {type(query)}")
                return jsonify({"error": f"Query must be a string, got {type(query).__name__}"}), 400
                
            logger.info(f"Processing NL query: '{query[:100]}...' (enhanced={use_enhanced})")
        except Exception as e:
            logger.error(f"Error extracting query: {e}", exc_info=True)
            error_context["details"] = f"Query extraction failed: {str(e)}"
            return jsonify({"error": "Failed to extract query from request", "details": str(e)}), 400

        # Step 3: Get data source
        error_context["step"] = "data_retrieval"
        try:
            data_src = get_current_data()
            if not data_src:
                logger.warning("No data source available")
                return jsonify({"error": "Upload a UFDR JSON file first.", "step": "data_retrieval"}), 400
            logger.debug(f"Data source retrieved: {len(data_src)} file(s)")
        except Exception as e:
            logger.error(f"Error retrieving data source: {e}", exc_info=True)
            error_context["details"] = f"Data retrieval failed: {str(e)}"
            return jsonify({"error": "Failed to retrieve data source", "details": str(e)}), 500
        
        # Step 4: Get session ID and chat history for context
        error_context["step"] = "session_management"
        session_id = None
        chat_history = []
        
        try:
            # Try to get session_id from Flask session
            if 'session_id' in session:
                session_id = session['session_id']
                logger.debug(f"Session ID from Flask session: {session_id[:8]}...")
            else:
                # Try to get from request data
                session_id = data.get('session_id')
                if session_id:
                    logger.debug(f"Session ID from request data: {session_id[:8]}...")
                    # Initialize session if provided
                    if session_id not in CHAT_HISTORIES:
                        CHAT_HISTORIES[session_id] = []
                        logger.debug(f"Initialized new chat history for session: {session_id[:8]}...")
        except Exception as e:
            logger.warning(f"Error retrieving session ID: {e}, continuing without session")
            session_id = None
        
        # Step 5: Retrieve chat history if session_id is available
        error_context["step"] = "chat_history_retrieval"
        if session_id:
            try:
                # Get from in-memory storage
                if session_id in CHAT_HISTORIES:
                    try:
                        chat_history = CHAT_HISTORIES[session_id]
                        if not isinstance(chat_history, list):
                            logger.warning(f"Invalid chat history format in memory: {type(chat_history)}, resetting")
                            CHAT_HISTORIES[session_id] = []
                            chat_history = []
                        else:
                            logger.debug(f"Retrieved {len(chat_history)} messages from in-memory chat history")
                    except Exception as e:
                        logger.error(f"Error accessing in-memory chat history: {e}", exc_info=True)
                        chat_history = []
                
                # Also try to get from database if available
                if SESSION_DB_AVAILABLE:
                    try:
                        db_history = get_chat_history(session_id, limit=20)  # Last 20 messages
                        if db_history:
                            if not isinstance(db_history, list):
                                logger.warning(f"Database returned invalid chat history format: {type(db_history)}")
                            else:
                                # Merge with in-memory history, avoiding duplicates
                                existing_contents = {msg.get('content', '') for msg in chat_history if isinstance(msg, dict)}
                                for db_msg in db_history:
                                    if not isinstance(db_msg, dict):
                                        logger.warning(f"Invalid message format from database: {type(db_msg)}")
                                        continue
                                    content = db_msg.get('content', '')
                                    if content and content not in existing_contents:
                                        chat_history.append({
                                            "role": db_msg.get('role', 'user'),
                                            "content": content
                                        })
                                        existing_contents.add(content)
                                
                                # Sort by timestamp if available, otherwise keep order
                                try:
                                    chat_history = sorted(chat_history, key=lambda x: x.get('timestamp', ''))[-20:]
                                except Exception as e:
                                    logger.warning(f"Error sorting chat history: {e}, keeping original order")
                                
                                logger.debug(f"Merged chat history: {len(chat_history)} total messages")
                    except Exception as e:
                        logger.warning(f"Could not retrieve chat history from database: {e}", exc_info=True)
                        # Continue without database history
            except Exception as e:
                logger.error(f"Unexpected error retrieving chat history: {e}", exc_info=True)
                chat_history = []  # Continue without chat history
        
        # Step 6: Process query with appropriate engine
        error_context["step"] = "query_processing"
        if use_enhanced:
            try:
                # Update engine with data
                try:
                    enhanced_nl_engine.update_data(data_src)
                    logger.debug("Enhanced NL engine data updated")
                except Exception as e:
                    logger.error(f"Error updating enhanced NL engine data: {e}", exc_info=True)
                    error_context["details"] = f"Engine data update failed: {str(e)}"
                    return jsonify({"error": "Failed to update query engine", "details": str(e)}), 500
                
                # Pass chat history for context-aware querying
                try:
                    logger.debug(f"Calling enhanced_nl_engine.query with chat_history length: {len(chat_history)}")
                    result = enhanced_nl_engine.query(query, chat_history=chat_history if chat_history else None)
                    logger.debug(f"Query processed successfully, analysis_type: {result.analysis_type}")
                except ValueError as e:
                    logger.error(f"Input validation error in query: {e}", exc_info=True)
                    return jsonify({"error": "Invalid query format", "details": str(e)}), 400
                except TypeError as e:
                    logger.error(f"Type error in query: {e}", exc_info=True)
                    return jsonify({"error": "Invalid query type", "details": str(e)}), 400
                except Exception as e:
                    logger.error(f"Error processing query with enhanced engine: {e}", exc_info=True)
                    error_context["details"] = f"Query processing failed: {str(e)}"
                    return jsonify({"error": "Failed to process query", "details": str(e)}), 500
                
                # Step 7: Convert QueryResult to JSON-serializable format
                error_context["step"] = "response_formatting"
                try:
                    response = {
                        "query": result.query,
                        "analysis_type": result.analysis_type,
                        "confidence": result.confidence,
                        "keywords_found": result.keywords_found if hasattr(result, 'keywords_found') else [],
                        "summary": result.summary if hasattr(result, 'summary') else "",
                        "total_matches": len(result.matches) if hasattr(result, 'matches') else 0,
                        "matches": result.matches[:50] if hasattr(result, 'matches') else [],  # Limit to first 50 matches
                        "recommendations": result.recommendations if hasattr(result, 'recommendations') else [],
                        "enhanced": True
                    }
                except Exception as e:
                    logger.error(f"Error formatting response: {e}", exc_info=True)
                    error_context["details"] = f"Response formatting failed: {str(e)}"
                    return jsonify({"error": "Failed to format response", "details": str(e)}), 500
                
                # Step 8: Add statistics if available
                try:
                    stats = enhanced_nl_engine.get_analysis_statistics()
                    if stats:
                        response["statistics"] = stats
                except Exception as e:
                    logger.debug(f"Statistics not available: {e}")
                    # Not critical, continue without statistics
                
                # Step 9: Store query and response in chat history
                error_context["step"] = "chat_history_storage"
                if session_id:
                    try:
                        # Store user query
                        try:
                            persist_chat_message(session_id, "user", query, metadata={
                                "query_type": "nl_query",
                                "analysis_type": result.analysis_type if hasattr(result, 'analysis_type') else "unknown",
                                "confidence": result.confidence if hasattr(result, 'confidence') else 0.0
                            })
                            logger.debug("User query stored in chat history")
                        except Exception as e:
                            logger.warning(f"Error storing user query in chat history: {e}", exc_info=True)
                            # Non-critical, continue
                        
                        # Store assistant response (summary)
                        try:
                            response_text = result.summary if hasattr(result, 'summary') else "No summary available"
                            if hasattr(result, 'recommendations') and result.recommendations:
                                response_text += "\n\nRecommendations:\n" + "\n".join(f"- {rec}" for rec in result.recommendations)
                            
                            persist_chat_message(session_id, "assistant", response_text, metadata={
                                "query_type": "nl_query",
                                "analysis_type": result.analysis_type if hasattr(result, 'analysis_type') else "unknown",
                                "confidence": result.confidence if hasattr(result, 'confidence') else 0.0,
                                "total_matches": len(result.matches) if hasattr(result, 'matches') else 0
                            })
                            logger.debug("Assistant response stored in chat history")
                        except Exception as e:
                            logger.warning(f"Error storing assistant response in chat history: {e}", exc_info=True)
                            # Non-critical, continue
                    except Exception as e:
                        logger.warning(f"Error in chat history storage: {e}", exc_info=True)
                        # Non-critical, continue without storing
                
                # Step 10: Return response
                logger.info(f"NL query processed successfully: {result.analysis_type}, {len(result.matches)} matches")
                return jsonify(response)
                
            except Exception as e:
                logger.error(f"Unexpected error in enhanced query processing: {e}", exc_info=True)
                error_context["details"] = f"Unexpected error: {str(e)}"
                return jsonify({"error": "Unexpected error processing query", "details": str(e), "step": error_context["step"]}), 500
        else:
            # Use original engine for backward compatibility
            try:
                error_context["step"] = "original_engine_processing"
                nl_engine.update_data(data_src)
                result = nl_engine.answer(query)
                if not isinstance(result, dict):
                    logger.error(f"Original engine returned invalid result type: {type(result)}")
                    return jsonify({"error": "Invalid response from query engine"}), 500
                result["enhanced"] = False
                return jsonify(result)
            except Exception as e:
                logger.error(f"Error in original engine: {e}", exc_info=True)
                error_context["details"] = f"Original engine failed: {str(e)}"
                return jsonify({"error": "Failed to process query with original engine", "details": str(e)}), 500
            
    except Exception as e:
        logger.error(f"Critical error in nl_query endpoint: {e}", exc_info=True)
        return jsonify({
            "error": "Internal server error",
            "details": str(e),
            "step": error_context.get("step", "unknown"),
            "context": error_context.get("details", "")
        }), 500

@app.route('/api/enhanced-suggestions')
def get_enhanced_suggestions():
    """Get intelligent query suggestions based on loaded data and forensic categories."""
    try:
        data_src = get_current_data()
        if not data_src:
            return jsonify({"error": "Upload a UFDR JSON file first."})
        
        # Update enhanced engine with current data
        enhanced_nl_engine.update_data(data_src)
        
        # Get data statistics for intelligent suggestions
        stats = enhanced_nl_engine.get_analysis_statistics()
        
        # Generate context-aware suggestions
        suggestions = {
            "Financial Investigation": [
                "Find suspicious money transfers",
                "Show me financial transactions",
                "Analyze payment patterns",
                "Look for money laundering indicators",
                "Find urgent financial requests"
            ],
            "Identity & Security": [
                "Find identity theft attempts",
                "Show password sharing activities", 
                "Look for phishing attempts",
                "Find credential compromise indicators",
                "Analyze authentication patterns"
            ],
            "Data & Privacy": [
                "Find data breach indicators",
                "Show file sharing activities",
                "Look for confidential data leaks",
                "Analyze document access patterns",
                "Find unauthorized data transfers"
            ],
            "Threat Analysis": [
                "Find threat indicators",
                "Look for violent content",
                "Analyze threatening communications",
                "Find planning activities",
                "Show high-risk conversations"
            ],
            "Communication Patterns": [
                "Analyze communication frequency",
                "Find unusual contact patterns",
                "Show relationship networks",
                "Look for coordinated activities",
                "Analyze time-based patterns"
            ],
            "Timeline & Events": [
                "Show timeline of activities",
                "Find activity clusters",
                "Analyze event sequences",
                "Look for synchronized communications",
                "Show chronological patterns"
            ]
        }
        
        # Add data-specific suggestions based on available content
        data_specific = []
        if stats['total_messages'] > 0:
            data_specific.append(f"Analyze {stats['total_messages']} messages for patterns")
        if stats['total_calls'] > 0:
            data_specific.append(f"Investigate {stats['total_calls']} call records")
        if stats['total_contacts'] > 0:
            data_specific.append(f"Review {stats['total_contacts']} contacts for relationships")
        if stats['top_contacts']:
            top_contact = stats['top_contacts'][0]['contact']
            data_specific.append(f"Analyze communications with {top_contact}")
        
        if data_specific:
            suggestions["Data-Specific Analysis"] = data_specific
        
        return jsonify({
            "suggestions": suggestions,
            "statistics": stats,
            "enhanced": True
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to generate suggestions: {str(e)}"})

@app.route('/api/comprehensive-analysis')
def get_comprehensive_analysis():
    """Get comprehensive scenario analysis using the comprehensive query engine."""
    try:
        if not ACTIVE_DATA:
            return jsonify({"error": "No UFDR data loaded"})
        
        # Extract records from active data
        records = []
        if isinstance(ACTIVE_DATA, list):
            records = ACTIVE_DATA
        elif isinstance(ACTIVE_DATA, dict) and 'devices' in ACTIVE_DATA:
            for device in ACTIVE_DATA['devices']:
                if 'messages' in device:
                    records.extend(device['messages'])
                if 'contacts' in device:
                    records.extend(device['contacts'])
                if 'call_logs' in device:
                    records.extend(device['call_logs'])
        
        if not records:
            return jsonify({"error": "No records found in UFDR data"})
        
        # Get comprehensive analysis
        analysis = simplified_engine.get_comprehensive_scenario_analysis(records)
        
        # Get suggested queries
        suggested_queries = simplified_engine.suggest_comprehensive_queries(analysis['scenario'])
        
        return jsonify({
            "analysis": analysis,
            "suggested_queries": suggested_queries,
            "total_records_analyzed": len(records)
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to perform comprehensive analysis: {str(e)}"})

@app.route('/api/simplified-query', methods=['POST'])
def simplified_query():
    """Process simplified natural language query without external dependencies."""
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        limit = data.get('limit', 100)
        
        if not query:
            return jsonify({"error": "No query provided"})
        
        if not ACTIVE_DATA:
            return jsonify({"error": "No UFDR data loaded"})
        
        # Extract records from active data
        records = []
        if isinstance(ACTIVE_DATA, list):
            records = ACTIVE_DATA
        elif isinstance(ACTIVE_DATA, dict) and 'devices' in ACTIVE_DATA:
            for device in ACTIVE_DATA['devices']:
                if 'messages' in device:
                    records.extend(device['messages'])
                if 'contacts' in device:
                    records.extend(device['contacts'])
                if 'call_logs' in device:
                    records.extend(device['call_logs'])
        
        if not records:
            return jsonify({"error": "No records found in UFDR data"})
        
        # Process query with simplified engine
        results, explanation = simplified_engine.process_query(query, records, None, limit)
        
        # Format results for display
        formatted_results = []
        for result in results:
            formatted_result = {
                "content": result.get('text', result.get('message', '')),
                "timestamp": result.get('timestamp', ''),
                "from": result.get('from', ''),
                "to": result.get('to', ''),
                "type": result.get('type', ''),
                "relevance_score": result.get('_relevance_score', 0),
                "matched_keywords": result.get('_matched_keywords', []),
                "matched_patterns": result.get('_matched_patterns', []),
                "matched_entities": result.get('_matched_entities', [])
            }
            formatted_results.append(formatted_result)
        
        return jsonify({
            "results": formatted_results,
            "explanation": explanation,
            "total_found": len(formatted_results)
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to process simplified query: {str(e)}"})

@app.route('/api/simplified-analysis')
def get_simplified_analysis():
    """Get simplified scenario analysis without external dependencies."""
    try:
        if not ACTIVE_DATA:
            return jsonify({"error": "No UFDR data loaded"})
        
        # Extract records from active data
        records = []
        if isinstance(ACTIVE_DATA, list):
            records = ACTIVE_DATA
        elif isinstance(ACTIVE_DATA, dict) and 'devices' in ACTIVE_DATA:
            for device in ACTIVE_DATA['devices']:
                if 'messages' in device:
                    records.extend(device['messages'])
                if 'contacts' in device:
                    records.extend(device['contacts'])
                if 'call_logs' in device:
                    records.extend(device['call_logs'])
        
        if not records:
            return jsonify({"error": "No records found in UFDR data"})
        
        # Get simplified analysis
        analysis = simplified_engine.get_scenario_summary(records)
        
        # Get suggested queries
        suggested_queries = simplified_engine.suggest_queries(analysis['scenario'])
        
        return jsonify({
            "analysis": analysis,
            "suggested_queries": suggested_queries,
            "total_records_analyzed": len(records)
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to perform simplified analysis: {str(e)}"})

@app.route('/api/comprehensive-query', methods=['POST'])
def comprehensive_query():
    """Process comprehensive natural language query."""
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        limit = data.get('limit', 100)
        
        if not query:
            return jsonify({"error": "No query provided"})
        
        if not ACTIVE_DATA:
            return jsonify({"error": "No UFDR data loaded"})
        
        # Extract records from active data
        records = []
        if isinstance(ACTIVE_DATA, list):
            records = ACTIVE_DATA
        elif isinstance(ACTIVE_DATA, dict) and 'devices' in ACTIVE_DATA:
            for device in ACTIVE_DATA['devices']:
                if 'messages' in device:
                    records.extend(device['messages'])
                if 'contacts' in device:
                    records.extend(device['contacts'])
                if 'call_logs' in device:
                    records.extend(device['call_logs'])
        
        if not records:
            return jsonify({"error": "No records found in UFDR data"})
        
        # Process query with comprehensive engine
        results, explanation = simplified_engine.process_query(query, records, None, limit)
        
        # Format results for display
        formatted_results = []
        for result in results:
            formatted_result = {
                "content": result.get('text', result.get('message', '')),
                "timestamp": result.get('timestamp', ''),
                "from": result.get('from', ''),
                "to": result.get('to', ''),
                "type": result.get('type', ''),
                "relevance_score": result.get('_relevance_score', 0),
                "matched_keywords": result.get('_matched_keywords', []),
                "matched_patterns": result.get('_matched_patterns', []),
                "matched_entities": result.get('_matched_entities', [])
            }
            formatted_results.append(formatted_result)
        
        return jsonify({
            "results": formatted_results,
            "explanation": explanation,
            "total_found": len(formatted_results)
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to process comprehensive query: {str(e)}"})

@app.route('/api/ai-retrieval', methods=['POST'])
def ai_retrieval():
    """AI-powered intelligent data retrieval endpoint."""
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        limit = data.get('limit', 50)
        
        if not query:
            return jsonify({
                "status": "ERROR",
                "message": "No query provided"
            })
        
        data_src = get_current_data()
        if not data_src:
            return jsonify({
                "status": "ERROR",
                "message": "Upload a UFDR JSON file first."
            })
        
        # Perform AI-powered retrieval
        # Rebuild retrieval engine with current data
        global ai_retrieval_engine
        ai_retrieval_engine = AIUFDRRetrievalEngine(data_src)
        result = ai_retrieval_engine.intelligent_search(query, limit)
        
        return jsonify({
            "status": "SUCCESS",
            "query": result.query,
            "matches": result.matches,
            "confidence": result.confidence,
            "data_sources": result.data_sources,
            "semantic_mappings": result.semantic_mappings,
            "summary": result.summary,
            "recommendations": result.recommendations,
            "total_matches": len(result.matches)
        })
        
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "message": f"Error in AI retrieval: {str(e)}"
        })

@app.route('/api/owner-info')
def get_owner_info():
    """Get all device owner information from loaded UFDR data."""
    try:
        data_src = get_current_data()
        if not data_src:
            return jsonify({
                "status": "ERROR",
                "message": "Upload a UFDR JSON file first."
            })
        global ai_retrieval_engine
        ai_retrieval_engine = AIUFDRRetrievalEngine(data_src)
        owners = ai_retrieval_engine.get_owner_information()
        
        return jsonify({
            "status": "SUCCESS",
            "owners": owners,
            "total_owners": len(owners)
        })
        
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "message": f"Error retrieving owner information: {str(e)}"
        })

@app.route('/api/llm-models', methods=['GET'])
def get_llm_models():
    """Get available LLM models from LM Studio."""
    try:
        if not USE_LLM:
            return jsonify({"error": "LLM integration is disabled"})
        
        response = requests.get("http://localhost:1234/v1/models", timeout=5)
        if response.ok:
            models_data = response.json()
            models = []
            for model in models_data.get('data', []):
                models.append({
                    'name': model.get('id', 'Unknown'),
                    'size': model.get('size', 'Unknown'),
                    'parameter_size': 'Unknown',
                    'family': 'Unknown'
                })
            return jsonify({
                "status": "success",
                "current_model": LLM_MODEL,
                "models": models
            })
        else:
            return jsonify({"error": "Could not connect to LM Studio"})
    except Exception as e:
        return jsonify({"error": f"Error fetching models: {str(e)}"})

@app.route('/api/llm-switch', methods=['POST'])
def switch_llm_model():
    """Switch the active LLM model."""
    global LLM_MODEL
    try:
        data = request.get_json() or {}
        new_model = data.get('model', '').strip()
        
        if not new_model:
            return jsonify({"error": "No model specified"})
        
        if new_model not in AVAILABLE_MODELS:
            return jsonify({"error": f"Model {new_model} not available"})
        
        # Test the model
        test_response = requests.post(LLM_URL, json={
            "model": new_model, 
            "prompt": "Test", 
            "stream": False
        }, timeout=10)
        test_response.encoding = "utf-8"

        if test_response.ok:
            LLM_MODEL = new_model
            return jsonify({
                "status": "success",
                "message": f"Switched to {new_model}",
                "current_model": LLM_MODEL
            })
        else:
            return jsonify({"error": f"Model {new_model} is not responding"})
            
    except Exception as e:
        return jsonify({"error": f"Error switching model: {str(e)}"})

@app.route('/api/device-metadata', methods=['POST'])
def search_device_metadata():
    """Search specifically in device metadata for owner and registration information."""
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        
        if not query:
            return jsonify({
                "status": "ERROR",
                "message": "No query provided"
            })
        
        data_src = get_current_data()
        if not data_src:
            return jsonify({
                "status": "ERROR",
                "message": "Upload a UFDR JSON file first."
            })
        global ai_retrieval_engine
        ai_retrieval_engine = AIUFDRRetrievalEngine(data_src)
        results = ai_retrieval_engine.search_device_metadata(query)
        
        return jsonify({
            "status": "SUCCESS",
            "query": query,
            "results": results,
            "total_results": len(results)
        })
        
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "message": f"Error searching device metadata: {str(e)}"
        })

# Note: Using LM Studio directly with model name (no model name mapping needed)

@app.route('/api/models', methods=['GET'])
def get_available_models():
    """Get list of available AI models from LM Studio and local models."""
    try:
        models = []
        
        # Add Qwen2.5-VL-7B as a local model (if enabled)
        if USE_QWEN_VL:
            qwen_status = "loaded" if QWEN_VL_LOADED else "available"
            models.append({
                "id": "qwen/qwen2.5-vl-7b",
                "name": "Qwen2.5-VL-7B",
                "description": "Multimodal model for image/video analysis (Local Transformers)",
                "provider": "Local (Transformers)",
                "available": True,
                "status": qwen_status,
                "is_local": True
            })
        
        # Check what models are actually available in LM Studio
        try:
            lm_studio_response = requests.get("http://localhost:1234/v1/models", timeout=5)
            if lm_studio_response.ok:
                lm_studio_models = lm_studio_response.json().get('data', [])
                for model_data in lm_studio_models:
                    model_id = model_data.get('id', 'Unknown')

                    # Skip heavy / non-chat models in this UI (too slow or not suitable for chat)
                    # This hides them from the dropdown but does not affect LM Studio itself.
                    lower_id = model_id.lower()
                    if any(bad in lower_id for bad in ['7b', '8b', 'embed', 'embedding']):
                        continue

                    models.append({
                        "id": model_id,
                        "name": model_id,
                        "description": f"Model loaded in LM Studio",
                        "provider": "LM Studio",
                        "available": True,
                        "is_local": False
                    })
        except Exception as e:
            logger.warning(f"Could not fetch LM Studio models: {e}")
        
        # If no models found, still return SUCCESS but with empty array
        # Frontend will handle displaying appropriate message
        return jsonify({
            "status": "SUCCESS",
            "models": models,
            "current_model": LLM_MODEL if models else None,
            "available_count": len(models),
            "lm_studio_connected": len([m for m in models if not m.get('is_local', False)]) > 0
        })
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "message": f"Error getting models: {str(e)}"
        })

@app.route('/api/models/<path:model_id>', methods=['POST'])
def switch_model(model_id):
    """Switch to a different AI model (LM Studio or local Qwen2.5-VL-7B)."""
    global LLM_MODEL
    try:
        # For LM Studio models (including Qwen served via LM Studio), check availability
        try:
            lm_studio_response = requests.get("http://localhost:1234/v1/models", timeout=5)
            if lm_studio_response.ok:
                lm_studio_models = lm_studio_response.json().get('data', [])
                available_model_names = [model.get('id', '') for model in lm_studio_models]
                
                if model_id not in available_model_names:
                    return jsonify({
                        "status": "ERROR",
                        "message": f"Model {model_id} is not loaded in LM Studio. Available models: {', '.join(available_model_names)}"
                    })
            else:
                return jsonify({
                    "status": "ERROR",
                    "message": "Cannot connect to LM Studio"
                })
        except Exception as e:
            return jsonify({
                "status": "ERROR",
                "message": f"Error checking model availability: {str(e)}"
            })
        
        # Update global model for LM Studio models
        LLM_MODEL = model_id
        
        return jsonify({
            "status": "SUCCESS",
            "message": f"Switched to {model_id}",
            "current_model": LLM_MODEL,
            "lm_studio_name": model_id
        })
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "message": f"Error switching model: {str(e)}"
        })

@app.route('/api/lm-studio/status', methods=['GET'])
def check_lm_studio_status():
    """Check LM Studio connection status and provide diagnostic info."""
    try:
        # Check if LM Studio is accessible
        health_check = requests.get("http://localhost:1234/v1/models", timeout=5)
        if health_check.ok:
            models = health_check.json().get('data', [])
            return jsonify({
                "status": "OK",
                "lm_studio_running": True,
                "models_available": [m.get('id', 'Unknown') for m in models],
                "model_count": len(models),
                "message": f"LM Studio is running with {len(models)} model(s) available"
            })
        else:
            return jsonify({
                "status": "ERROR",
                "lm_studio_running": False,
                "message": "LM Studio server is not responding properly"
            })
    except requests.exceptions.ConnectionError:
        return jsonify({
            "status": "ERROR",
            "lm_studio_running": False,
            "message": "LM Studio server is not running. Please start LM Studio server.",
            "help": {
                "windows": "Open LM Studio application, go to 'Local Server' tab, and click 'Start Server'",
                "mac_linux": "Open LM Studio application, go to 'Local Server' tab, and click 'Start Server'",
                "check": "Check LM Studio 'Local Server' tab to verify server is running"
            }
        })
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "lm_studio_running": False,
            "message": f"Error checking LM Studio: {str(e)}"
        })


@app.route('/api/llm-provider/status', methods=['GET'])
def check_llm_provider_status():
    """Check health for selected/default provider (manual backup switching support)."""
    try:
        requested = request.args.get("provider")
        provider = normalize_llm_provider(requested or session.get("llm_provider") or LLM_PROVIDER_DEFAULT)
        ok, msg = llm_provider_health_check(provider, timeout=5)
        return jsonify({
            "status": "OK" if ok else "ERROR",
            "provider": provider,
            "provider_name": _provider_display_name(provider),
            "healthy": bool(ok),
            "message": msg,
            "model": resolve_effective_llm_model(provider),
            "url": resolve_effective_llm_url(provider),
        }), (200 if ok else 503)
    except Exception as e:
        logger.error(f"Error checking provider status: {e}")
        return jsonify({
            "status": "ERROR",
            "healthy": False,
            "message": str(e),
        }), 500

@app.route('/api/qwen-vl/status', methods=['GET'])
def qwen_vl_status():
    """Check Qwen2.5-VL-7B model status."""
    try:
        if not USE_QWEN_VL:
            return jsonify({
                "available": False,
                "enabled": False,
                "message": "Qwen2.5-VL-7B is disabled"
            })
        
        model, processor = init_qwen_vl_model()
        
        if model is None or processor is None:
            return jsonify({
                "available": False,
                "enabled": True,
                "message": "Qwen2.5-VL-7B model not loaded. Check logs for details.",
                "model_name": QWEN_VL_MODEL_NAME
            })
        
        return jsonify({
            "available": True,
            "enabled": True,
            "loaded": QWEN_VL_LOADED,
            "model_name": QWEN_VL_MODEL_NAME,
            "message": "Qwen2.5-VL-7B is ready for multimodal analysis"
        })
    except Exception as e:
        return jsonify({
            "available": False,
            "enabled": USE_QWEN_VL,
            "error": str(e),
            "message": f"Error checking Qwen2.5-VL status: {str(e)}"
        })

@app.route('/api/chat/clear', methods=['POST'])
def clear_chat_history():
    """Clear chat history for current session and reset data caches."""
    try:
        # Prefer Flask session, but allow caller to provide session_id for robustness
        session_id = None
        if 'session_id' in session:
            session_id = session['session_id']
        else:
            try:
                data = request.get_json(silent=True) or {}
                if isinstance(data, dict) and data.get('session_id'):
                    session_id = data.get('session_id')
                    session['session_id'] = session_id
            except Exception:
                session_id = None

        if session_id:
            if session_id in CHAT_HISTORIES:
                CHAT_HISTORIES[session_id] = []
            if session_id in FOLLOWUP_BASE_CONTEXT:
                del FOLLOWUP_BASE_CONTEXT[session_id]
            # Also clear from database (use imported function from session_db)
            if SESSION_DB_AVAILABLE:
                # Import the database function to avoid conflict with this Flask route handler
                from session_db import clear_chat_history as db_clear_chat_history
                db_clear_chat_history(session_id)
        
        # Reset semantic extractor's data index cache to prevent old data references
        global semantic_extractor
        if semantic_extractor:
            semantic_extractor._data_index = {}  # Clear cached data index
            logger.info("✅ Cleared semantic extractor data index cache")
        
        # Rebuild RAG index with current ACTIVE_DATA (in case data changed)
        try:
            rebuild_rag_index()
            logger.info("✅ Rebuilt RAG index after chat clear")
        except Exception as e:
            logger.warning(f"Error rebuilding RAG index after chat clear: {e}")
        
        return jsonify({"status": "SUCCESS", "message": "Chat history cleared and data caches reset"})
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/query-feedback', methods=['POST'])
def api_query_feedback():
    """
    Persist investigator review of a query outcome (pipeline learning, not model fine-tuning).

    JSON body: raw_query, parsed_intent, guarantee_class, route_primary, packet_type, llm_used,
    answer_quality (good|bad), failure_type (optional), corrected_* fields, replay_context (optional).
    """
    try:
        data = request.get_json(silent=True) or {}
        if not (data.get("raw_query") or data.get("query")):
            return jsonify({"ok": False, "error": "raw_query required"}), 400
        ft = data.get("failure_type")
        if ft and ft not in ALL_FAILURE_TYPES:
            return jsonify(
                {"ok": False, "error": "invalid failure_type", "allowed": list(ALL_FAILURE_TYPES)}
            ), 400
        rec = record_from_api_payload(data)
        append_feedback_record(rec)
        invalidate_feedback_cache()
        return jsonify({"ok": True, "id": rec.id, "stored_path": str(default_feedback_path())})
    except Exception as e:
        logger.exception("api_query_feedback failed")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/api/query-feedback/failure-types', methods=['GET'])
def api_query_feedback_failure_types():
    """Structured failure labels for review UI / integrations."""
    return jsonify({"failure_types": list(ALL_FAILURE_TYPES)})

# Session Management API Endpoints
@app.route('/api/sessions', methods=['GET'])
@login_required
def list_sessions():
    """List all sessions for the current user, optionally filtered by case_id"""
    try:
        if not SESSION_DB_AVAILABLE:
            return jsonify({"status": "ERROR", "message": "Session database not available"})
        
        # Get current user ID for security
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"status": "ERROR", "message": "User not authenticated"}), 401
        
        case_id = request.args.get('case_id', None)
        if case_id:
            # Get sessions for this case, filtered by user_id
            sessions = get_sessions_by_case(case_id, user_id=user_id)
        else:
            # Get all sessions for this user
            sessions = get_all_sessions(user_id=user_id)
        
        return jsonify({
            "status": "SUCCESS",
            "sessions": sessions,
            "count": len(sessions)
        })
    except Exception as e:
        logger.error(f"Error listing sessions: {e}")
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/sessions', methods=['POST'])
@login_required
def create_new_session():
    """Create a new session"""
    try:
        data = request.get_json() or {}
        case_id = data.get('case_id')
        title = data.get('title', 'New Investigation')
        
        # Get current user ID
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"status": "ERROR", "message": "User not authenticated"}), 401
        
        # Generate session ID
        import uuid
        session_id = str(uuid.uuid4())
        
        # Create in database with user_id
        if SESSION_DB_AVAILABLE:
            success, error_msg = create_session(session_id, case_id=case_id, title=title, user_id=user_id)
            if not success:
                error_message = error_msg or "Failed to create session in database"
                logger.error(f"Failed to create session: {error_message}")
                return jsonify({"status": "ERROR", "message": error_message}), 500
        
        # Store in Flask session
        session['session_id'] = session_id
        if case_id:
            session['case_id'] = case_id
        
        return jsonify({
            "status": "SUCCESS",
            "session_id": session_id,
            "case_id": case_id,
            "title": title,
            "message": "Session created successfully"
        })
    except Exception as e:
        logger.error(f"Error creating session: {e}")
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/sessions/<session_id>', methods=['GET'])
@login_required
def get_session_info(session_id):
    """Get session information and restore state"""
    try:
        if not SESSION_DB_AVAILABLE:
            return jsonify({
                "status": "ERROR",
                "message": "Session database not available"
            })
        
        # Get current user ID for security
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({
                "status": "ERROR",
                "message": "User not authenticated"
            }), 401
        
        # Get session info (filtered by user_id for security)
        sess = get_session(session_id, user_id=user_id)
        if not sess:
            return jsonify({
                "status": "ERROR",
                "message": "Session not found or access denied"
            }), 404
        
        # Get chat history
        chat_history = get_chat_history(session_id)
        logger.info(f"📜 Retrieved {len(chat_history)} chat message(s) for session {session_id}")
        
        # Get preferences
        preferences = get_preferences(session_id)
        logger.info(f"⚙️ Retrieved preferences for session {session_id}: {preferences}")
        if 'sound_enabled' in preferences:
            logger.info(f"🔊 sound_enabled value: {preferences['sound_enabled']} (type: {type(preferences['sound_enabled']).__name__})")
        
        # Get query history (last 50)
        query_history = get_query_history(session_id, limit=50)
        
        # Update last accessed
        update_session_access(session_id)
        
        # Store in Flask session
        session['session_id'] = session_id
        if sess.get('case_id'):
            session['case_id'] = sess['case_id']
        
        return jsonify({
            "status": "SUCCESS",
            "session": sess,
            "chat_history": chat_history,
            "preferences": preferences,
            "query_history": query_history
        })
    except Exception as e:
        logger.error(f"Error getting session: {e}")
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/sessions/<session_id>/preferences', methods=['POST'])
def update_session_preferences(session_id):
    """Update session preferences"""
    try:
        if not SESSION_DB_AVAILABLE:
            return jsonify({"status": "ERROR", "message": "Session database not available"})
        
        data = request.get_json() or {}
        logger.info(f"💾 Saving preferences for session {session_id}: {list(data.keys())}")
        logger.info(f"📥 Received data: {data}")
        
        # Update each preference
        for key, value in data.items():
            original_value = value
            save_result = save_preference(session_id, key, value)
            if save_result:
                logger.info(f"   ✅ Saved {key} = {original_value} (original) -> converted in save_preference()")
            else:
                logger.error(f"   ❌ Failed to save {key} = {original_value}")
        
        updated_prefs = get_preferences(session_id)
        logger.info(f"📋 Updated preferences after save: {updated_prefs}")
        if 'sound_enabled' in updated_prefs:
            logger.info(f"🔊 sound_enabled in response: {updated_prefs['sound_enabled']} (type: {type(updated_prefs['sound_enabled']).__name__})")
        
        return jsonify({
            "status": "SUCCESS",
            "message": "Preferences updated",
            "preferences": updated_prefs
        })
    except Exception as e:
        logger.error(f"Error updating preferences: {e}", exc_info=True)
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/sessions/<session_id>/preferences', methods=['GET'])
def get_session_preferences(session_id):
    """Get session preferences"""
    try:
        if not SESSION_DB_AVAILABLE:
            return jsonify({"status": "ERROR", "message": "Session database not available"})
        
        prefs = get_preferences(session_id)
        return jsonify({
            "status": "SUCCESS",
            "preferences": prefs
        })
    except Exception as e:
        logger.error(f"Error getting preferences: {e}")
        return jsonify({"status": "ERROR", "message": str(e)})

# Case Management API Endpoints
@app.route('/api/cases', methods=['GET'])
@login_required
def list_cases():
    """List all cases for the current user, optionally filtered by status (disabled in DEV_MODE)"""
    if DEV_MODE:
        return jsonify({"status": "ERROR", "message": "Case Manager is disabled in DEV_MODE. Use chat interface directly."}), 403
    try:
        if not SESSION_DB_AVAILABLE:
            logger.error("Session database not available for listing cases")
            return jsonify({"status": "ERROR", "message": "Session database not available"}), 500
        
        # Get current user's username to filter cases
        username = session.get('username')
        status_filter = request.args.get('status', None)
        
        # Filter cases by created_by (username) to show only user's cases
        cases = get_all_cases(status_filter=status_filter, created_by=username)
        
        logger.info(f"Retrieved {len(cases)} cases for user {username} (filter: {status_filter or 'all'})")
        
        return jsonify({
            "status": "SUCCESS",
            "cases": cases,
            "count": len(cases)
        })
    except Exception as e:
        logger.error(f"Error listing cases: {e}", exc_info=True)
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route('/api/cases', methods=['POST'])
@login_required
def create_new_case():
    """Create a new case (disabled in DEV_MODE)"""
    if DEV_MODE:
        return jsonify({"status": "ERROR", "message": "Case Manager is disabled in DEV_MODE. Use chat interface directly."}), 403
    try:
        if not SESSION_DB_AVAILABLE:
            return jsonify({"status": "ERROR", "message": "Session database not available"})
        
        # RBAC: Check permission
        if SECURITY_AVAILABLE:
            user_id = session.get('user_id')
            if not RBAC.has_permission('create_case', user_id):
                if audit_logger:
                    audit_logger.log_action('create_case_denied', success=False, 
                                          details={'reason': 'insufficient_permissions'})
                return jsonify({"status": "ERROR", "message": "Access denied: Insufficient permissions"}), 403
        
        data = request.get_json() or {}
        case_name = data.get('case_name', '').strip()
        evidence_device = data.get('evidence_device', '').strip()  # Optional, can be added later
        description = data.get('description', '').strip()
        status = data.get('status', 'Active')
        
        # Get investigator from logged-in user's profile (name or username)
        investigator = session.get('name') or session.get('username') or 'Unknown Investigator'
        
        # Sanitize inputs
        if SECURITY_AVAILABLE:
            case_name = sanitize_input(case_name, max_length=200)
            investigator = sanitize_input(investigator, max_length=100)
            evidence_device = sanitize_input(evidence_device, max_length=100)
            description = sanitize_input(description, max_length=5000)
        
        if not case_name:
            return jsonify({"status": "ERROR", "message": "Case name is required"})
        
        # Generate case ID
        import uuid
        case_id = data.get('case_id') or f"C-{datetime.now().strftime('%Y')}-{str(uuid.uuid4())[:3].upper()}"
        
        # Store investigator in metadata or description
        metadata = {'investigator': investigator}
        if description:
            description = f"Investigator: {investigator}\n\n{description}"
        else:
            description = f"Investigator: {investigator}"
        
        # Get current user info
        created_by = session.get('username', 'system')
        
        # Create case
        if create_case(case_id, case_name, evidence_device=evidence_device, created_by=created_by, description=description, status=status, metadata=metadata):
            # Audit logging
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('create_case', resource=case_id, success=True,
                                      details={'case_name': case_name, 'investigator': investigator})
            
            # Get the freshly created case to ensure we have the correct timestamps
            case = get_case(case_id)
            if case:
                return jsonify({
                    "status": "SUCCESS",
                    "case": case,
                    "message": "Case created successfully"
                })
            else:
                return jsonify({"status": "ERROR", "message": "Case created but could not retrieve it"})
        else:
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('create_case', resource=case_id, success=False,
                                      details={'error': 'database_error'})
            return jsonify({"status": "ERROR", "message": "Failed to create case"})
    except Exception as e:
        logger.error(f"Error creating case: {e}")
        if SECURITY_AVAILABLE and audit_logger:
            audit_logger.log_action('create_case', success=False, details={'error': str(e)})
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/cases/<case_id>', methods=['GET'])
@login_required
def get_case_info(case_id):
    """Get case information (disabled in DEV_MODE)"""
    if DEV_MODE:
        return jsonify({"status": "ERROR", "message": "Case Manager is disabled in DEV_MODE. Use chat interface directly."}), 403
    """Get case information"""
    try:
        if not SESSION_DB_AVAILABLE:
            return jsonify({"status": "ERROR", "message": "Session database not available"})
        
        # Get case first to check ownership
        case = get_case(case_id)
        if not case:
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('view_case', resource=case_id, success=False,
                                      details={'error': 'case_not_found'})
            return jsonify({"status": "ERROR", "message": "Case not found"}), 404
        
        # Verify case belongs to current user (unless admin)
        username = session.get('username')
        user_role = 'viewer'
        if SECURITY_AVAILABLE:
            user_id = session.get('user_id')
            user_role = RBAC.get_user_role(user_id) if user_id else 'viewer'
        
        case_owner = case.get('created_by', 'unknown')
        is_admin_access = (user_role == 'admin' and case_owner != username)
        
        # Check permissions: admin can view all, others can only view their own
        if user_role != 'admin' and case_owner != username:
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('view_case_denied', resource=case_id, success=False,
                                      details={'reason': 'not_owner', 'case_owner': case_owner})
            return jsonify({"status": "ERROR", "message": "Access denied: Case does not belong to you"}), 403
        
        # Audit logging - indicate if admin accessed someone else's case
        if SECURITY_AVAILABLE and audit_logger:
            log_details = {}
            if is_admin_access:
                log_details['admin_access'] = True
                log_details['case_owner'] = case_owner
                log_details['access_type'] = 'admin_viewing_other_case'
            else:
                log_details['access_type'] = 'owner_viewing_own_case'
            
            audit_logger.log_action('view_case', resource=case_id, success=True, details=log_details)
        
        # Get the most recent session's last_accessed time for this case (for last_opened)
        if SESSION_DB_AVAILABLE:
            # Import get_db_connection from session_db
            import sys
            import os
            _database_code_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'code')
            if _database_code_path not in sys.path:
                sys.path.insert(0, _database_code_path)
            from session_db import get_db_connection
            conn = get_db_connection()
            if conn:
                try:
                    cur = conn.cursor()
                    cur.execute("""
                        SELECT last_accessed 
                        FROM sessions 
                        WHERE case_id = ? 
                        ORDER BY last_accessed DESC 
                        LIMIT 1
                    """, (case_id,))
                    session_row = cur.fetchone()
                    if session_row:
                        case['last_opened'] = session_row['last_accessed']
                    else:
                        case['last_opened'] = None
                    cur.close()
                    conn.close()
                except Exception as e:
                    logger.error(f"Error getting last_opened for case: {e}")
                    case['last_opened'] = None
        
        # Get current user ID for security
        user_id = session.get('user_id')
        
        # Get sessions for this case, filtered by user_id
        sessions = get_sessions_by_case(case_id, user_id=user_id) if user_id else get_sessions_by_case(case_id)
        
        return jsonify({
            "status": "SUCCESS",
            "case": case,
            "sessions": sessions,
            "session_count": len(sessions)
        })
    except Exception as e:
        logger.error(f"Error getting case: {e}")
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/cases/<case_id>', methods=['PUT'])
@login_required
def update_case_info(case_id):
    """Update case information (disabled in DEV_MODE)"""
    if DEV_MODE:
        return jsonify({"status": "ERROR", "message": "Case Manager is disabled in DEV_MODE. Use chat interface directly."}), 403
    """Update case information"""
    try:
        if not SESSION_DB_AVAILABLE:
            return jsonify({"status": "ERROR", "message": "Session database not available"})
        
        # Get case first to check ownership
        case = get_case(case_id)
        if not case:
            return jsonify({"status": "ERROR", "message": "Case not found"}), 404
        
        # RBAC: Check permission and case ownership
        username = session.get('username')
        user_role = 'viewer'
        if SECURITY_AVAILABLE:
            user_id = session.get('user_id')
            user_role = RBAC.get_user_role(user_id) if user_id else 'viewer'
            
            has_edit_permission = RBAC.has_permission('edit_case', user_id)
            has_edit_own_permission = RBAC.has_permission('edit_own_case', user_id)
            
            if not has_edit_permission and not has_edit_own_permission:
                if audit_logger:
                    audit_logger.log_action('update_case_denied', resource=case_id, success=False,
                                          details={'reason': 'insufficient_permissions'})
                return jsonify({"status": "ERROR", "message": "Access denied: Insufficient permissions"}), 403
            
            # If user has edit_own_case but not edit_case, check ownership
            case_owner = case.get('created_by', 'unknown')
            if has_edit_own_permission and not has_edit_permission:
                if user_role != 'admin' and case_owner != username:
                    if audit_logger:
                        audit_logger.log_action('update_case_denied', resource=case_id, success=False,
                                              details={'reason': 'not_owner', 'case_owner': case_owner})
                    return jsonify({"status": "ERROR", "message": "Access denied: You don't have permission to edit this case"}), 403
        
        data = request.get_json() or {}
        updates = {}
        
        if 'case_name' in data:
            updates['case_name'] = sanitize_input(data['case_name'], max_length=200) if SECURITY_AVAILABLE else data['case_name']
        if 'status' in data:
            updates['status'] = data['status']
        if 'evidence_device' in data:
            updates['evidence_device'] = sanitize_input(data['evidence_device'], max_length=100) if SECURITY_AVAILABLE else data['evidence_device']
        if 'description' in data:
            updates['description'] = sanitize_input(data['description'], max_length=5000) if SECURITY_AVAILABLE else data['description']
        
        if update_case(case_id, **updates):
            # Audit logging
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('update_case', resource=case_id, success=True,
                                      details={'updated_fields': list(updates.keys())})
            
            case = get_case(case_id)
            return jsonify({
                "status": "SUCCESS",
                "case": case,
                "message": "Case updated successfully"
            })
        else:
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('update_case', resource=case_id, success=False,
                                      details={'error': 'database_error'})
            return jsonify({"status": "ERROR", "message": "Failed to update case"})
    except Exception as e:
        logger.error(f"Error updating case: {e}")
        if SECURITY_AVAILABLE and audit_logger:
            audit_logger.log_action('update_case', resource=case_id, success=False, details={'error': str(e)})
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/cases/<case_id>', methods=['DELETE'])
@login_required
def delete_case_info(case_id):
    """Delete case (disabled in DEV_MODE)"""
    if DEV_MODE:
        return jsonify({"status": "ERROR", "message": "Case Manager is disabled in DEV_MODE. Use chat interface directly."}), 403
    """Delete a case"""
    try:
        if not SESSION_DB_AVAILABLE:
            logger.error("Session database not available for delete operation")
            return jsonify({"status": "ERROR", "message": "Session database not available"}), 500
        
        # RBAC: Check permission (allow delete_case or edit_own_case for investigators)
        if SECURITY_AVAILABLE:
            has_delete_permission = RBAC.has_permission('delete_case')
            has_edit_own_permission = RBAC.has_permission('edit_own_case')
            
            if not has_delete_permission and not has_edit_own_permission:
                if audit_logger:
                    audit_logger.log_action('delete_case_denied', resource=case_id, success=False,
                                          details={'reason': 'insufficient_permissions'})
                return jsonify({"status": "ERROR", "message": "Access denied: Insufficient permissions"}), 403
            
            # If user has edit_own_case but not delete_case, check case ownership
            if has_edit_own_permission and not has_delete_permission:
                # Get case to check ownership
                case = get_case(case_id)
                if case:
                    username = session.get('username')
                    user_id = session.get('user_id')
                    user_role = RBAC.get_user_role(user_id) if user_id else 'viewer'
                    case_owner = case.get('created_by', 'unknown')
                    if user_role != 'admin' and case_owner != username:
                        if audit_logger:
                            audit_logger.log_action('delete_case_denied', resource=case_id, success=False,
                                                  details={'reason': 'not_owner', 'case_owner': case_owner})
                        return jsonify({"status": "ERROR", "message": "Access denied: You don't have permission to delete this case"}), 403
        
        # Verify case exists before deleting
        case = get_case(case_id)
        if not case:
            logger.warning(f"Attempted to delete non-existent case: {case_id}")
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('delete_case', resource=case_id, success=False,
                                      details={'error': 'case_not_found'})
            return jsonify({"status": "ERROR", "message": "Case not found"}), 404
        
        # Delete the case
        if delete_case(case_id):
            logger.info(f"Case {case_id} deleted successfully")
            # Audit logging
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('delete_case', resource=case_id, success=True,
                                      details={'case_name': case.get('case_name', 'Unknown')})
            return jsonify({
                "status": "SUCCESS",
                "message": "Case deleted successfully"
            })
        else:
            logger.error(f"Failed to delete case {case_id}")
            if SECURITY_AVAILABLE and audit_logger:
                audit_logger.log_action('delete_case', resource=case_id, success=False,
                                      details={'error': 'database_error'})
            return jsonify({"status": "ERROR", "message": "Failed to delete case"}), 500
    except Exception as e:
        logger.error(f"Error deleting case {case_id}: {e}", exc_info=True)
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route('/api/cases/<case_id>/create-session', methods=['POST'])
def create_case_session(case_id):
    """Create a new EVI session for a case"""
    # Declare global variables at the top of the function
    global ACTIVE_FILENAME, ACTIVE_DATA, enhanced_nl_engine, ai_retrieval_engine
    
    try:
        if not SESSION_DB_AVAILABLE:
            return jsonify({"status": "ERROR", "message": "Session database not available"})
        
        # Verify case exists
        case = get_case(case_id)
        if not case:
            return jsonify({"status": "ERROR", "message": "Case not found"})
        
        # Get request data to check if this is a new session (not continuing existing)
        data = request.get_json() or {}
        is_new_session = data.get('is_new_session', True)  # Default to True for new sessions
        
        # Check if this is a brand new case (no previous sessions) or restoring existing
        existing_sessions = []
        if SESSION_DB_AVAILABLE:
            existing_sessions = get_sessions_by_case(case_id)
        
        is_brand_new_case = len(existing_sessions) == 0
        
        # Declare globals for XML data layers
        global ACTIVE_DATA_LAYERS, ACTIVE_DB_PATHS
        
        # If creating a NEW CASE (no previous sessions), clear everything including files
        if is_new_session and is_brand_new_case:
            logger.info(f"Creating NEW CASE {case_id} (no previous sessions) - clearing ALL files and ACTIVE_DATA")
            
            # Clear all uploaded files from disk for brand new cases (including XML and .db files)
            if os.path.exists(UPLOAD_FOLDER):
                for file in os.listdir(UPLOAD_FOLDER):
                    file_path = os.path.join(UPLOAD_FOLDER, file)
                    try:
                        if os.path.isfile(file_path):
                            # Remove all files including XML and .db files
                            os.remove(file_path)
                            logger.info(f"Removed uploaded file: {file}")
                    except Exception as e:
                        logger.warning(f"Error removing file {file}: {e}")
            
            # Clear ACTIVE_DATA and reset engines
            ACTIVE_FILENAME = None
            ACTIVE_DATA = {}
            
            # Clear XML data layers
            ACTIVE_DATA_LAYERS = {}
            ACTIVE_DB_PATHS = {}
            
            # Reset engines with empty data
            try:
                nl_engine.update_data(ACTIVE_DATA)
                enhanced_nl_engine = EnhancedNaturalLanguageUFDR(ACTIVE_DATA)
                ai_retrieval_engine = AIUFDRRetrievalEngine(ACTIVE_DATA)
                rebuild_rag_index()
                logger.info("Cleared ALL files, ACTIVE_DATA, and XML data layers for brand new case")
            except Exception as e:
                logger.error(f"Error resetting engines: {e}")
        elif is_new_session:
            # Creating a new session for an existing case (user chose "Create New" after warning)
            logger.info(f"Creating new session for existing case {case_id} - clearing ALL previous session data")
            
            # Clear all uploaded files from disk for new sessions (including XML and .db files)
            # This ensures stats reset completely
            if os.path.exists(UPLOAD_FOLDER):
                for file in os.listdir(UPLOAD_FOLDER):
                    file_path = os.path.join(UPLOAD_FOLDER, file)
                    try:
                        if os.path.isfile(file_path):
                            # Remove all files including XML and .db files
                            os.remove(file_path)
                            logger.info(f"Removed uploaded file: {file}")
                    except Exception as e:
                        logger.warning(f"Error removing file {file}: {e}")
            
            # Clear ACTIVE_DATA and XML data layers
            ACTIVE_FILENAME = None
            ACTIVE_DATA = {}
            ACTIVE_DATA_LAYERS = {}
            ACTIVE_DB_PATHS = {}
            
            # Clear session files from database for ALL previous sessions of this case
            # This marks them as inactive so they won't be loaded in the new session
            if existing_sessions:
                # clear_session_files is already imported at the top of the file
                for prev_session in existing_sessions:
                    prev_session_id = prev_session.get('session_id')
                    if prev_session_id:
                        clear_session_files(prev_session_id)
                        logger.info(f"✅ Marked session_files as inactive for previous session {prev_session_id}")
                
                logger.info(f"✅ Cleared {len(existing_sessions)} previous session(s) file records from database")
            
            # Clear chat history for previous sessions when creating a new session
            # This ensures a completely fresh start
            if existing_sessions and SESSION_DB_AVAILABLE:
                # Import the database function (not the Flask route handler)
                from session_db import clear_chat_history as db_clear_chat_history
                for prev_session in existing_sessions:
                    prev_session_id = prev_session.get('session_id')
                    if prev_session_id:
                        db_clear_chat_history(prev_session_id)
                        logger.info(f"✅ Cleared chat history for previous session {prev_session_id}")
                
                logger.info(f"✅ Cleared chat history for {len(existing_sessions)} previous session(s)")
            
            # Reset engines with empty data
            try:
                nl_engine.update_data(ACTIVE_DATA)
                enhanced_nl_engine = EnhancedNaturalLanguageUFDR(ACTIVE_DATA)
                ai_retrieval_engine = AIUFDRRetrievalEngine(ACTIVE_DATA)
                rebuild_rag_index()
                logger.info("✅ Cleared ALL files, ACTIVE_DATA, XML data layers, and previous session files for new session")
            except Exception as e:
                logger.error(f"Error resetting engines: {e}")
        
        # Get current user ID for security
        # In DEV_MODE, allow access without authentication
        if DEV_MODE:
            user_id = session.get('user_id') or 1  # Default to user_id 1 in dev mode
            username = session.get('username') or 'dev_user'
            logger.info(f"DEV_MODE: Using default user_id={user_id}, username={username}")
        else:
            user_id = session.get('user_id')
            username = session.get('username')
            logger.info(f"Creating session for case {case_id}, user_id: {user_id}, username: {username}")
            
            if not user_id:
                logger.warning(f"User not authenticated - session keys: {list(session.keys())}")
                return jsonify({"status": "ERROR", "message": "User not authenticated"}), 401
        
        # Verify case belongs to current user (skip in DEV_MODE)
        case_creator = case.get('created_by')
        logger.info(f"Case creator: {case_creator}, Current user: {username}")
        if not DEV_MODE and case_creator != username:
            logger.warning(f"Access denied: Case {case_id} created by {case_creator}, but current user is {username}")
            return jsonify({"status": "ERROR", "message": f"Access denied: Case does not belong to you (created by: {case_creator})"}), 403
        
        # Create session
        import uuid
        session_id = str(uuid.uuid4())
        title = data.get('title', f"Investigation - {case['case_name']}")
        
        success, error_msg = create_session(session_id, case_id=case_id, title=title, user_id=user_id)
        if success:
            # Update session access time immediately when created
            update_session_access(session_id)
            # Also update the case's updated_at timestamp when investigation is opened
            # This makes "Last Updated" and "Last Opened" synchronized
            # update_case already imported at top
            update_case(case_id)  # This will update updated_at to current time
            return jsonify({
                "status": "SUCCESS",
                "session_id": session_id,
                "case_id": case_id,
                "evi_scan_url": f"/evi-scan?session_id={session_id}",
                "message": "Session created successfully"
            })
        else:
            error_message = error_msg or "Failed to create session"
            logger.error(f"Failed to create session: {error_message}")
            return jsonify({"status": "ERROR", "message": error_message})
    except Exception as e:
        logger.error(f"Error creating case session: {e}")
        return jsonify({"status": "ERROR", "message": str(e)})

@app.route('/api/chat/stream', methods=['POST'])
def chat_query_stream():
    """Forensic AI Chat Assistant with Streaming Response - Real-time token streaming like ChatGPT."""
    import time
    import json as json_lib
    start_time = time.time()
    
    def calculate_response_time():
        """Calculate and format response time."""
        elapsed = time.time() - start_time
        return round(elapsed, 2)
    
    def generate_stream():
        """Generator function that yields streaming tokens."""
        # Declare globals at the top of the function
        global ACTIVE_DATA_LAYERS, ACTIVE_FILENAME, ACTIVE_DATA
        turn_user_saved = False
        session_id = None
        user_message_to_store = ""
        
        # SSE format requires double newline
        sse_end = "\n\n"

        def sse_json(obj, **kwargs):
            """Serialize SSE payloads; keep Unicode as UTF-8 in the stream (not \\uXXXX-only)."""
            return json_lib.dumps(obj, ensure_ascii=False, **kwargs)

        def _sse_deterministic_done(txt: str, done_extra=None):
            """Emit SSE like LLM streaming: client simulates progressive reveal for UX consistency."""
            extra = dict(done_extra) if done_extra else {}
            txt = repair_llm_mojibake(txt if txt is not None else "")
            _persist_user_query_once()
            _persist_assistant_response(
                txt,
                metadata={
                    "deterministic": True,
                    "llm_used": False,
                    "route_primary": extra.get("route_primary"),
                    "guarantee_class": extra.get("guarantee_class"),
                },
            )
            start_payload = {'type': 'start', 'simulated_stream': True}
            yield f"data: {sse_json(start_payload)}{sse_end}"
            token_payload = {
                'type': 'token',
                'content': txt if txt is not None else '',
                'simulated_stream': True,
            }
            yield f"data: {sse_json(token_payload)}{sse_end}"
            done_payload = {
                'type': 'done',
                'response': txt if txt is not None else '',
                'confidence': 1.0,
                'response_time': calculate_response_time(),
                'llm_used': False,
                'simulated_stream': True,
            }
            done_payload.update(extra)
            yield f"data: {sse_json(done_payload)}{sse_end}"

        followup_llm_only = False
        query_route = None  # populated after routing; used in SSE metadata
        feedback_route_meta = None  # query_feedback.apply_feedback_to_query_route
        llm_provider_used = "local"
        llm_model_used = LLM_MODEL

        def _persist_user_query_once():
            nonlocal turn_user_saved, session_id, user_message_to_store
            if turn_user_saved or not session_id:
                return
            content = (user_message_to_store or "").strip()
            if not content:
                return
            if session_id not in CHAT_HISTORIES:
                CHAT_HISTORIES[session_id] = []
            CHAT_HISTORIES[session_id].append({
                "role": "user",
                "content": content,
                "timestamp": datetime.now().isoformat(),
            })
            persist_chat_message(session_id, "user", content, metadata={"source": "chat_stream"})
            turn_user_saved = True

        def _persist_assistant_response(content, metadata=None):
            nonlocal session_id
            if not session_id:
                return
            text = (content or "").strip()
            if not text:
                return
            if session_id not in CHAT_HISTORIES:
                CHAT_HISTORIES[session_id] = []
            CHAT_HISTORIES[session_id].append({
                "role": "assistant",
                "content": text,
                "timestamp": datetime.now().isoformat(),
            })
            persist_chat_message(session_id, "assistant", text, metadata=metadata)

        try:
            data = request.get_json() or {}
            query = (data.get('query') or data.get('message') or '')
            user_query_original = query
            followup_base = data.get('followup_base') if isinstance(data, dict) else None
            followup_mode = bool(data.get('followup_mode', False)) if isinstance(data, dict) else False
            # Ensure query is a string and not None
            if query is None:
                query = ''
            if not isinstance(query, str):
                query = str(query) if query else ''
            query = query.strip()
            user_query_original = user_query_original.strip() if isinstance(user_query_original, str) else str(user_query_original or "").strip()
            user_message_to_store = user_query_original or query

            # Session + follow-up anchor persistence (must run before planner / FOLLOWUP_BASE reads).
            if 'session_id' not in session:
                import uuid
                session['session_id'] = str(uuid.uuid4())
                CHAT_HISTORIES[session['session_id']] = []
            session_id = session['session_id']
            llm_provider_used = resolve_effective_llm_provider(
                session_id=session_id,
                request_data=data,
            )
            llm_model_used = resolve_effective_llm_model(llm_provider_used)
            session['llm_provider'] = llm_provider_used
            if isinstance(followup_base, dict):
                base_early = str(followup_base.get('content') or '').strip()
                if base_early:
                    FOLLOWUP_BASE_CONTEXT[session_id] = {
                        "message_id": str(followup_base.get('message_id') or ''),
                        "content": base_early[:12000],
                        "timestamp": str(followup_base.get('timestamp') or datetime.now().isoformat())
                    }
                    logger.info(f"✅ Follow-up base context stored for session {session_id[:8]}...")

            # Multilingual retrieval normalization:
            # keep original query for LLM response language, but normalize query for
            # deterministic routing/classification/data retrieval.
            query_for_retrieval = _normalize_multilingual_query_for_retrieval(query)
            if query_for_retrieval != query:
                logger.info(f"🌐 Retrieval-normalized query: '{query}' → '{query_for_retrieval}'")
            query = query_for_retrieval

            # Query understanding layer (structured intent)
            # Build canonical form so deterministic execution does not depend on exact wording.
            parsed_intent = parse_query_intent(user_query_original or query)
            # Do not merge base platform context in follow-up mode (keeps intent stable for routing).
            if not followup_mode:
                _merge_followup_platform_context(parsed_intent, False, followup_base, user_query_original)
            canonical_query = to_canonical_query(parsed_intent)
            if canonical_query and canonical_query != query:
                logger.info(f"🧭 Canonical intent query: '{query}' -> '{canonical_query}'")
            use_json_extraction = data.get('use_json', False)  # New option: let LLM extract from JSON
            # When True, SSE `done` includes capped `llm_evidence_text` (full user message sent to the LLM after truncation)
            _raw_dbg = data.get('debug_llm_context', False)
            debug_llm_context = _raw_dbg in (True, 'true', 'True', 1, '1', 'yes', 'on')
            logger.info(f"🔧 debug_llm_context: raw={_raw_dbg!r} enabled={debug_llm_context}")
            
            # CRITICAL: Rewrite vague questions to prevent hallucination
            # For multilingual/non-ASCII queries, preserve original wording for LLM language handling.
            original_query = query
            if any(ord(ch) > 127 for ch in query):
                logger.info("🌐 Multilingual/non-ASCII query detected; skipping vague-query rewrite")
            else:
                query = rewrite_vague_query(query)
            if query != original_query:
                logger.info(f"✅ Query rewritten: '{original_query}' → '{query}'")
            
            # CRITICAL: Log the received query
            logger.info(f"🔍 RECEIVED QUERY FROM CLIENT: {repr(query)}")
            logger.info(f"🔍 Query length: {len(query)} characters")
            logger.info(f"🔍 Query type: {type(query)}")
            logger.info(f"🔍 Request data keys: {list(data.keys())}")
            
            if not query:
                logger.error(f"❌ ERROR: Empty query received from client! Data: {data}")
                error_data = sse_json({'type': 'error', 'message': 'No query provided', 'response': 'I need a question to investigate. What would you like me to analyze?'})
                try:
                    yield f"data: {error_data}{sse_end}"
                except GeneratorExit:
                    logger.info("🛑 Client disconnected while sending empty query error")
                    raise
                return

            # Follow-up mode: route all questions through the LLM with the selected base context;
            # deterministic pulls (lists, correlation SQL, etc.) are skipped — see followup_llm_only below.
            if followup_mode:
                followup_llm_only = True
            
            # Classify query to determine routing
            # Prefer canonical query for robust intent mapping.
            classification = classify_query(canonical_query or query)
            logger.info(f"🔍 Query classification: {classification}")

            # Query planning layer: decide deterministic/hybrid/llm route using structured intent.
            query_plan = build_query_plan(
                parsed_intent=parsed_intent,
                followup_mode_active=bool(followup_mode),
                has_base=bool(followup_base)
            )
            logger.info(f"🗺️ Query plan: {query_plan}")

            route_scores = compute_route_scores(
                canonical_query or query,
                parsed_intent,
            )
            logger.info(
                "ROUTE_SCORES det=%s analysis=%s hint=%s expects_records=%s expects_meaning=%s",
                route_scores.get("det_score"),
                route_scores.get("analysis_score"),
                route_scores.get("route_hint"),
                route_scores.get("expects_records"),
                route_scores.get("expects_meaning"),
            )
            if os.environ.get("EVI_PURE_DETERMINISTIC", "").lower() in ("1", "true", "yes"):
                logger.info(
                    "EVI_PURE_DETERMINISTIC is set; high det / low analysis may skip redundant LLM steps where supported."
                )

            _log_pipeline_trace(session_id, "post_plan", {
                "parsed_action": parsed_intent.get("action"),
                "parsed_domains": parsed_intent.get("domains"),
                "parsed_platform": parsed_intent.get("platform"),
                "parsed_platforms": parsed_intent.get("platforms"),
                "parsed_special": parsed_intent.get("special"),
                "parsed_filters": parsed_intent.get("filters"),
                "planner_intent": query_plan.get("intent"),
                "planner_mode": query_plan.get("mode"),
                "planner_operators": query_plan.get("operators"),
                "planner_fallback_reason": query_plan.get("fallback_reason"),
                "canonical_query": canonical_query,
                "followup_llm_only": followup_llm_only,
                "route_scores": route_scores,
            })

            # Ambiguous overlap / planner clarification — do not fall through to generic contact dump
            if not followup_llm_only and query_plan.get("intent") == "clarify":
                reason = query_plan.get("fallback_reason") or ""
                if reason == "ambiguous_contact_overlap_need_two_platforms" or parsed_intent.get("special") == "ambiguous_contact_overlap":
                    clar = (
                        "**Contact overlap** — name two apps, e.g. `which contacts appear in both line and whatsapp`."
                    )
                elif reason == "contact_intersection_insufficient_platforms":
                    clar = "**Contact overlap** — add two platform names (e.g. line and whatsapp)."
                else:
                    clar = (
                        f"**Need a bit more detail** ({reason or 'unspecified'}). "
                        "Try naming domains, two platforms for overlap, and a date (YYYY-MM-DD) if relevant."
                    )
                logger.info(f"PIPELINE: clarify response ({reason})")
                yield from _sse_deterministic_done(clar)
                return

            if not followup_llm_only and query_plan.get("intent") == "contact_intersection":
                plats = (query_plan.get("filters") or {}).get("platforms") or []
                if len(plats) >= 2:
                    data_layer_ci = _get_active_data_layer()
                    if not data_layer_ci:
                        logger.warning("PIPELINE: contact_intersection — no data_layer")
                        yield from _sse_deterministic_done(
                            "**Contact overlap** — load a case first (no database attached)."
                        )
                        return
                    ci = run_contact_platform_intersection(data_layer_ci, plats[0], plats[1])
                    _log_pipeline_trace(session_id, "contact_intersection_done", {
                        "platforms": plats[:2],
                        "output_count": ci.get("count"),
                    })
                    if ci.get("handled"):
                        ci_text = _prepend_deterministic_evidence_summary(
                            query=user_query_original or query,
                            response_text=ci.get("response") or "",
                            scope_label="contact overlap",
                            count=ci.get("count"),
                            platform_hint=(parsed_intent.get("platform") if isinstance(parsed_intent, dict) else None),
                        )
                        yield from _sse_deterministic_done(ci_text)
                        return

            if not followup_llm_only and query_plan.get("intent") == "reconstruct":
                data_layer_rt = _get_active_data_layer()
                if not data_layer_rt:
                    logger.warning("PIPELINE: reconstruct — no data_layer")
                    yield from _sse_deterministic_done(
                        "**Timeline** — load a case first (no database attached)."
                    )
                    return
                rt = run_deterministic_timeline_reconstruction(
                    parsed_intent, data_layer_rt, followup_base, user_query_original
                )
                _log_pipeline_trace(session_id, "reconstruct_done", {
                    "fallback_reason": rt.get("fallback_reason"),
                    "output_count": rt.get("count"),
                })
                if rt.get("handled"):
                    rt_text = _prepend_deterministic_evidence_summary(
                        query=user_query_original or query,
                        response_text=rt.get("response") or "",
                        scope_label="timeline reconstruction",
                        count=rt.get("count"),
                        platform_hint=(parsed_intent.get("platform") if isinstance(parsed_intent, dict) else None),
                    )
                    yield from _sse_deterministic_done(rt_text)
                    return

            # Global deterministic correlation (normal + follow-up mode), v1
            if (
                not followup_llm_only
                and query_plan.get("intent") == "correlation"
                and query_plan.get("mode") in ("deterministic", "hybrid")
            ):
                data_layer = _get_active_data_layer()
                if data_layer:
                    corr_text = _run_planned_deterministic_correlation(query_plan, data_layer)
                    corr_text = _prepend_deterministic_evidence_summary(
                        query=user_query_original or query,
                        response_text=corr_text,
                        scope_label="cross-domain correlation",
                        count=None,
                        platform_hint=((query_plan.get("filters") or {}).get("platform") if isinstance(query_plan, dict) else None),
                    )
                    _log_pipeline_trace(session_id, "correlation_done", {"response_chars": len(corr_text or "")})
                    yield from _sse_deterministic_done(corr_text)
                    logger.info("✅ Global deterministic correlation served from query plan")
                    return
                logger.warning("PIPELINE: correlation skipped — no data_layer")
                yield from _sse_deterministic_done(
                    "**Correlation** — load a case first (no database attached)."
                )
                return

            # BASIC DETERMINISTIC LAYER (5 domains)
            # Explicit routing: deterministic list vs LLM synthesis vs person-comprehensive hybrid
            # (see core/query_route.py). Avoids mixing raw SQL dumps with interpretive questions.
            early_extracted_person_name = None
            _xml_loaded = bool(ACTIVE_DATA_LAYERS)
            _route_q = user_query_original or query or ""
            _route_ql = _route_q.lower()
            _route_is_person = _is_person_investigation_query(_route_ql)
            _route_person_name = (
                _extract_person_name_from_investigation_query(_route_q)
                if _route_is_person and _xml_loaded
                else None
            )
            query_route = decide_query_route(
                followup_llm_only=bool(followup_llm_only),
                user_query_original=_route_q,
                canonical_query=canonical_query or query,
                parsed_intent=parsed_intent,
                query_plan=query_plan,
                has_xml_data=_xml_loaded,
                person_name_extracted=_route_person_name,
                is_person_investigation=_route_is_person,
            )
            query_route, feedback_route_meta = apply_feedback_to_query_route(
                query_route,
                raw_query=_route_q,
                parsed_intent=parsed_intent,
            )
            if feedback_route_meta.get("feedback_bias_applied"):
                logger.info("QUERY_FEEDBACK_ROUTE %s", feedback_route_meta)
            query_route, score_bias_meta = apply_route_score_bias(
                query_route,
                route_scores,
                followup_llm_only=bool(followup_llm_only),
                user_query=_route_q,
                feedback_bias_applied=bool(feedback_route_meta.get("feedback_bias_applied")),
            )
            if score_bias_meta.get("score_bias_applied"):
                logger.info("ROUTE_SCORE_BIAS applied=%s", score_bias_meta)
            _log_pipeline_trace(session_id, "query_route", {
                **(query_route or {}),
                "score_bias": score_bias_meta,
            })
            logger.info(
                f"GUARANTEE_CLASS={query_route.get('guarantee_class')} "
                f"({query_route.get('guarantee_reason')}) | "
                f"ROUTE primary={query_route['primary']} "
                f"skip_basic_det={query_route['skip_basic_deterministic']} "
                f"reason={query_route.get('reason')}"
            )
            # Reuse for person-comprehensive block below (same extraction, user + canonical safe)
            early_extracted_person_name = _route_person_name

            deterministic_result = None
            if not followup_llm_only and not query_route.get("skip_basic_deterministic"):
                deterministic_result = run_basic_deterministic_retrieval(
                    query=canonical_query or query,
                    platform=parsed_intent.get("platform") or classification.get('platform'),
                    limit=20,
                    intent_filters=parsed_intent.get("filters"),
                    user_query_for_dates=user_query_original,
                )
            if deterministic_result and deterministic_result.get("handled"):
                response_text = deterministic_result.get("response") or "No deterministic result available."
                response_text = _prepend_deterministic_evidence_summary(
                    query=user_query_original or query,
                    response_text=response_text,
                    scope_label=(deterministic_result.get("domain") or "deterministic retrieval"),
                    count=deterministic_result.get("count"),
                    platform_hint=parsed_intent.get("platform") if isinstance(parsed_intent, dict) else None,
                )
                _log_pipeline_trace(session_id, "deterministic_retrieval", {
                    "domain": deterministic_result.get("domain"),
                    "output_count": deterministic_result.get("count"),
                    "fallback_reason": deterministic_result.get("fallback_reason"),
                })
                yield from _sse_deterministic_done(response_text, {
                    'guarantee_class': (query_route or {}).get('guarantee_class'),
                    'guarantee_reason': (query_route or {}).get('guarantee_reason'),
                    'route_primary': (query_route or {}).get('primary'),
                })
                logger.info(
                    f"✅ Deterministic response served | domain={deterministic_result.get('domain')} "
                    f"count={deterministic_result.get('count')}"
                )
                return

            _log_pipeline_trace(session_id, "fallthrough_to_llm", {
                "fallback_reason": "deterministic_retrieval_did_not_handle",
                "parsed_action": parsed_intent.get("action"),
                "planner_intent": query_plan.get("intent"),
            })

            def is_followup_style_query(text: str) -> bool:
                """Heuristic: identify queries that depend on prior answer context."""
                if not text or not isinstance(text, str):
                    return False
                q = text.strip().lower()
                if not q:
                    return False
                # Full-case investigative questions — never force "select base message"
                if _is_standalone_investigative_query(q):
                    return False
                # Epistemic / evidence-strength questions (standalone; not "about this prior message")
                if re.match(
                    r"^(does|do|can|could|would|is|are)\s+(this|that|it)\s+",
                    q,
                ) or re.match(r"^can\s+we\s+(infer|conclude|say|prove|know)\b", q):
                    return False
                if re.match(r"^(does|is)\s+this\s+(prove|show|mean|imply|suggest)\b", q):
                    return False
                followup_starters = [
                    "and ", "also ", "what about", "how about", "why", "how", "explain this",
                    "explain that", "more on", "elaborate", "continue", "go deeper", "based on that"
                ]
                # Exclude "this"/"that": they appear in contact names (e.g. "This Is DFIR") and
                # caused false positives for short queries.
                # Exclude "they"/"them": appear in standalone questions ("does this prove they…") and are not reliable deictic signals alone.
                followup_terms = {"it", "those", "these", "he", "she", "his", "her", "their"}
                if any(q.startswith(s) for s in followup_starters):
                    return True
                words = re.findall(r"[a-zA-Z']+", q)
                if len(words) <= 12 and any(w in followup_terms for w in words):
                    return True
                return False
            
            # Check if this is a confirmation response (user said "yes", "confirm", etc.)
            is_confirmation = is_confirmation_response(query)
            has_confirmation_data = False
            confirmation_chat_data = None
            
            # If user confirmed, fetch and display data with insights
            if not followup_llm_only and is_confirmation:
                # Check chat history to see if LLM asked for confirmation
                # Look for previous extraction query context
                try:
                    data_layer = None
                    if ACTIVE_FILENAME and ACTIVE_FILENAME in ACTIVE_DATA_LAYERS:
                        data_layer = ACTIVE_DATA_LAYERS[ACTIVE_FILENAME]
                    elif ACTIVE_DATA_LAYERS:
                        data_layer = list(ACTIVE_DATA_LAYERS.values())[0]
                    
                    if data_layer:
                        # Try to detect platform from recent context or use a default
                        # For now, we'll need to store the platform in session/context
                        # But let's check if we can infer from chat history
                        platform = None
                        # Check if there's a stored extraction context (we'll add this)
                        # For now, try to detect from query patterns
                        platform_keywords = ['native messages', 'whatsapp', 'telegram', 'facebook messenger', 
                                           'twitter', 'instagram', 'snapchat', 'line', 'skype', 'viber', 
                                           'kik', 'textnow', 'tiktok', 'wickr pro']
                        query_lower = query.lower()
                        for kw in platform_keywords:
                            if kw in query_lower:
                                platform = kw
                                break
                        
                        # If no platform in current query, check classification from previous context
                        # We'll need to store this in session - for now, try to get from classification
                        if not platform and classification.get('platform'):
                            platform = classification.get('platform')
                        
                        if platform:
                            # Fetch chat data
                            chat_data = data_layer.get_chat_data_for_display(
                                platform=platform,
                                chat_id=classification.get('chat_id'),
                                limit=100
                            )
                            
                            # Format data for LLM analysis (no chat-style display)
                            confirmation_chat_data = format_chat_data_for_llm(chat_data)
                            
                            # Continue to LLM processing below - we'll add this data to context
                            # Set a flag so we know to include this data
                            has_confirmation_data = True
                        else:
                            logger.warning("Could not determine platform for confirmation")
                            has_confirmation_data = False
                            confirmation_chat_data = None
                except Exception as e:
                    logger.error(f"Error handling confirmation: {str(e)}", exc_info=True)
                    has_confirmation_data = False
                    confirmation_chat_data = None
            
            # NEW FLOW: Extraction queries go through LLM first for confirmation
            # LLM will ask "Do you want to pull messages from [platform]?" 
            # After user confirms, we'll fetch and display data with insights
            # So we skip direct routing and let LLM handle it
            
            # Route hybrid queries (get data + analysis)
            # NOTE: For "analyze all messages" type queries without specific platform,
            # we should skip direct_data and go straight to LLM streaming
            if not followup_llm_only and classification['type'] == 'hybrid' and classification.get('platform'):
                # Only send direct_data if we have a specific platform to extract
                try:
                    # Get data layer (ACTIVE_DATA_LAYERS already declared as global at top of function)
                    data_layer = None
                    if ACTIVE_FILENAME and ACTIVE_FILENAME in ACTIVE_DATA_LAYERS:
                        data_layer = ACTIVE_DATA_LAYERS[ACTIVE_FILENAME]
                    elif ACTIVE_DATA_LAYERS:
                        data_layer = list(ACTIVE_DATA_LAYERS.values())[0]
                    
                    if data_layer:
                        # Get chat data for specific platform
                        chat_data = data_layer.get_chat_data_for_display(
                            platform=classification.get('platform'),
                            chat_id=classification.get('chat_id'),
                            limit=100
                        )
                        
                        # Only send direct_data if we actually got chat data
                        if chat_data and chat_data.get('chats'):
                            # Return data first
                            response_data = sse_json({
                                'type': 'direct_data',
                                'data': chat_data,
                                'classification': classification
                            })
                            yield f"data: {response_data}{sse_end}"
                            logger.info(f"✅ Sent direct_data for platform: {classification.get('platform')}")
                        else:
                            logger.info(f"ℹ️ No chat data for platform {classification.get('platform')}, skipping direct_data and going to LLM")
                        
                        # Continue to LLM processing below (don't return)
                        data_src = get_current_data()
                    else:
                        logger.warning("No data layer available for hybrid query")
                except Exception as e:
                    logger.error(f"Error in hybrid query processing: {str(e)}", exc_info=True)
                    # Fall through to LLM processing
            elif not followup_llm_only and classification['type'] == 'hybrid' and not classification.get('platform'):
                # Hybrid query without specific platform (e.g., "analyze all messages")
                # Skip direct_data, go straight to LLM streaming
                logger.info("ℹ️ Hybrid query without specific platform - skipping direct_data, going to LLM streaming")
                # Send start event immediately to let frontend know streaming is starting
                start_data = sse_json({'type': 'start'})
                try:
                    yield f"data: {start_data}{sse_end}"
                    logger.info("✅ Sent start event for hybrid query without platform")
                except GeneratorExit:
                    logger.info("🛑 Client disconnected while sending start signal")
                    raise
            
            data_src = get_current_data()
            # Check for XML data layers even if ACTIVE_DATA is empty
            has_xml_data = bool(ACTIVE_DATA_LAYERS)
            
            # session_id + FOLLOWUP_BASE_CONTEXT were initialized at stream start.

            # Strict follow-up mode: follow-up style queries must use selected base message context.
            followup_mode_active = False
            base_ctx = FOLLOWUP_BASE_CONTEXT.get(session_id)
            if followup_mode:
                # If UI says follow-up mode is active, FORCE the query to be treated as follow-up.
                if not base_ctx or not base_ctx.get('content'):
                    strict_msg = (
                        "Follow-up mode is active, but no base message was selected. "
                        "Please click 'Analyze this result' on a previous assistant message first."
                    )
                    error_data = sse_json({'type': 'error', 'message': strict_msg, 'response': strict_msg})
                    yield f"data: {error_data}{sse_end}"
                    return
                followup_mode_active = True
            else:
                # Otherwise only enforce follow-up-style questions to require a base.
                if is_followup_style_query(query):
                    if not base_ctx or not base_ctx.get('content'):
                        strict_msg = (
                            "This looks like a follow-up question, but no base message was selected. "
                            "Please click 'Analyze this result' on a previous assistant message first."
                        )
                        error_data = sse_json({'type': 'error', 'message': strict_msg, 'response': strict_msg})
                        yield f"data: {error_data}{sse_end}"
                        return

            # Deterministic follow-up cross-reference across core domains.
            # This avoids generic LLM-only responses when user explicitly asks to cross-reference/correlate.
            query_lower = query.lower()
            # Normalize dash variants so "cross‑reference" / "cross–reference" still match.
            query_norm = query_lower.replace("‑", "-").replace("–", "-").replace("—", "-")
            if not followup_llm_only and followup_mode_active and base_ctx and base_ctx.get("content"):
                crossref_intent = _is_cross_reference_intent(query_norm)
                query_domains = _detect_domains_in_text(query_norm)
                if crossref_intent and len(query_domains) > 0:
                    data_layer = _get_active_data_layer()
                    if not data_layer:
                        err = "**Cross-reference** — load a case first (no database attached)."
                        start_data = sse_json({'type': 'start'})
                        token_data = sse_json({'type': 'token', 'content': err})
                        done_data = sse_json({
                            'type': 'done', 'response': err, 'confidence': 1.0,
                            'response_time': calculate_response_time(), 'llm_used': False
                        })
                        yield f"data: {start_data}{sse_end}"
                        yield f"data: {token_data}{sse_end}"
                        yield f"data: {done_data}{sse_end}"
                        return
                    response_text = _build_cross_reference_response(
                        data_layer=data_layer,
                        base_content=str(base_ctx.get("content") or ""),
                        query_text=query
                    )
                    # If deterministic cross-reference cannot run, return explicit failure (no silent LLM fallback).
                    if response_text and "Cross-reference could not run" in response_text:
                        logger.warning(
                            "PIPELINE: follow-up cross-reference failed — returning error to client (LLM fallback suppressed)"
                        )
                        fail_body = response_text
                        start_data = sse_json({'type': 'start'})
                        token_data = sse_json({'type': 'token', 'content': fail_body})
                        done_data = sse_json({
                            'type': 'done',
                            'response': fail_body,
                            'confidence': 1.0,
                            'response_time': calculate_response_time(),
                            'llm_used': False
                        })
                        yield f"data: {start_data}{sse_end}"
                        yield f"data: {token_data}{sse_end}"
                        yield f"data: {done_data}{sse_end}"
                        return
                    start_data = sse_json({'type': 'start'})
                    token_data = sse_json({'type': 'token', 'content': response_text})
                    done_data = sse_json({
                        'type': 'done',
                        'response': response_text,
                        'confidence': 1.0,
                        'response_time': calculate_response_time(),
                        'llm_used': False
                    })
                    yield f"data: {start_data}{sse_end}"
                    yield f"data: {token_data}{sse_end}"
                    yield f"data: {done_data}{sse_end}"
                    logger.info("✅ Deterministic follow-up cross-reference served")
                    return
            
            # Initialize variable for comprehensive analysis data (needed for scope)
            comprehensive_data_context = None
            
            # DIAGNOSTIC: Log XML data availability
            logger.info(f"🔍 XML Data Check:")
            logger.info(f"   - ACTIVE_DATA_LAYERS: {list(ACTIVE_DATA_LAYERS.keys()) if ACTIVE_DATA_LAYERS else 'EMPTY'}")
            logger.info(f"   - ACTIVE_FILENAME: {ACTIVE_FILENAME}")
            logger.info(f"   - has_xml_data: {has_xml_data}")
            
            # Check if query is asking for comprehensive person analysis
            query_lower = query.lower() if query else ""
            is_person_query = _is_person_investigation_query(query_lower)
            
            # Extract person name from query (e.g., "show chats with Josh Hickman", "know more about josh hickman")
            person_name = early_extracted_person_name if early_extracted_person_name else None
            if person_name is None and is_person_query and has_xml_data:
                person_name = _extract_person_name_from_investigation_query(query)
                if person_name:
                    logger.info(f"✅ Extracted person name from query: '{person_name}'")
            
            # Use comprehensive analysis if person name found
            if not followup_llm_only and person_name and has_xml_data and ACTIVE_DATA_LAYERS:
                try:
                    logger.info(f"🔍 Comprehensive analysis triggered for: '{person_name}'")
                    data_layer = list(ACTIVE_DATA_LAYERS.values())[0]  # Get first data layer
                    
                    # DIAGNOSTIC: Check database directly
                    if hasattr(data_layer, 'db_path'):
                        import sqlite3
                        try:
                            test_conn = sqlite3.connect(data_layer.db_path)
                            test_cursor = test_conn.cursor()
                            test_cursor.execute("SELECT COUNT(*) FROM chats")
                            chat_count = test_cursor.fetchone()[0]
                            test_cursor.execute("SELECT COUNT(*) FROM chat_messages")
                            msg_count = test_cursor.fetchone()[0]
                            test_cursor.execute("SELECT chat_name, participants FROM chats LIMIT 5")
                            sample_chats = test_cursor.fetchall()
                            test_conn.close()
                            logger.info(f"📊 Database check: {chat_count} chats, {msg_count} chat messages")
                            logger.info(f"📊 Sample chats: {sample_chats}")
                        except Exception as e:
                            logger.error(f"❌ Database check failed: {e}")
                    
                    communications = data_layer.get_all_communications_for_person(person_name, limit=1000)
                    total_found = (communications['summary']['total_chats'] + 
                                  communications['summary']['total_messages'] + 
                                  communications['summary']['total_calls'])
                    logger.info(f"📊 Found: {communications['summary']['total_chats']} chats, {communications['summary']['total_messages']} messages, {communications['summary']['total_calls']} calls")
                    
                    # Only use comprehensive analysis if we found data, otherwise fall through to regular query
                    if total_found > 0:
                        logger.info(f"✅ Comprehensive data found for {person_name}, sending to LLM for natural formatting...")
                        # Instead of using format_comprehensive_analysis directly, prepare structured data for LLM
                        # This allows LLM to create a natural, conversational response
                        structured_data = data_layer.format_comprehensive_analysis(person_name, communications)
                        # Store in a variable that will be picked up by LLM processing below
                        comprehensive_data_context = f"""COMPREHENSIVE ANALYSIS DATA FOR {person_name}:

{structured_data}

IMPORTANT INSTRUCTIONS FOR LLM:
- Format this data in a natural, conversational forensic analysis style
- Present findings as if you're a forensic investigator explaining evidence to a colleague
- Use clear sections with headers, but make it flow naturally
- Do NOT just list raw data - provide context, insights, and professional analysis
- Be conversational and engaging, not robotic
- Highlight key findings and patterns
- Use professional forensic terminology appropriately"""
                        logger.info(f"✅ Prepared comprehensive data context ({len(comprehensive_data_context)} chars), passing to LLM...")
                        # Continue to LLM processing below (don't return here)
                    else:
                        logger.warning(f"⚠️ Comprehensive analysis found no data for '{person_name}', falling through to regular query")
                except Exception as e:
                    logger.error(f"Error in comprehensive person analysis: {e}", exc_info=True)
                    # Fall through to normal processing
            
            if not data_src and not has_xml_data:
                error_data = sse_json({'type': 'error', 'message': 'Upload a UFDR JSON file first.', 'response': 'I need UFDR data to investigate. Please upload a forensic report first.'})
                try:
                    yield f"data: {error_data}{sse_end}"
                except GeneratorExit:
                    logger.info("🛑 Client disconnected while sending no data error")
                    raise
                return
            
            # Session already initialized earlier, just get it
            session_id = session.get('session_id')
            if not session_id:
                import uuid
                session_id = str(uuid.uuid4())
                session['session_id'] = session_id
                CHAT_HISTORIES[session_id] = []
            
            # Check if query needs Qwen2.5-VL (images/videos) - STREAMING ENDPOINT
            use_qwen_vl = False
            if USE_QWEN_VL and has_images_or_videos(data_src) and query:
                # Check if query is image/video related
                query_lower = query.lower() if query else ""
                image_keywords = ['image', 'photo', 'picture', 'screenshot', 'visual', 'see', 'show', 'what', 'describe']
                video_keywords = ['video', 'footage', 'recording', 'clip', 'movie']
                
                if query_lower and any(kw in query_lower for kw in image_keywords + video_keywords):
                    use_qwen_vl = True
                    logger.info("Using Qwen2.5-VL-7B for multimodal analysis (streaming)")
            
            # Try Qwen2.5-VL first if needed (for streaming, we'll return a single response)
            if use_qwen_vl:
                try:
                    # Chat history disabled for forensic queries to prevent hallucinations
                    response, error = process_with_qwen_vl(query, data_src, chat_history=None)
                    if response:
                        _persist_user_query_once()
                        _persist_assistant_response(response, metadata={"model_used": "Qwen2.5-VL-7B", "provider_used": "local", "multimodal": True})
                        
                        # Send response as streaming (single chunk for Qwen)
                        response_data = sse_json({
                            'type': 'token',
                            'content': response,
                            'model_used': 'Qwen2.5-VL-7B',
                            'provider_used': 'local',
                            'multimodal': True
                        })
                        try:
                            yield f"data: {response_data}{sse_end}"
                            
                            # Send done signal
                            done_data = sse_json({
                                'type': 'done',
                                'response_time': calculate_response_time(),
                                'model_used': 'Qwen2.5-VL-7B',
                                'provider_used': 'local',
                                'multimodal': True,
                                'guarantee_class': (query_route or {}).get('guarantee_class') if query_route else None,
                                'route_primary': (query_route or {}).get('primary') if query_route else None,
                            })
                            yield f"data: {done_data}{sse_end}"
                        except GeneratorExit:
                            logger.info("🛑 Client disconnected during Qwen2.5-VL response")
                            raise
                        return
                    elif error:
                        logger.warning(f"Qwen2.5-VL processing failed: {error}, falling back to LLM")
                except Exception as e:
                    logger.error(f"Error in Qwen2.5-VL processing: {e}", exc_info=True)
                    # Fall through to LLM processing
            
            if not USE_LLM:
                error_data = sse_json({'type': 'error', 'message': 'LLM service unavailable', 'response': 'LLM integration is disabled. Please enable it in the configuration.'})
                try:
                    yield f"data: {error_data}{sse_end}"
                except GeneratorExit:
                    logger.info("🛑 Client disconnected while sending LLM unavailable error")
                    raise
                return
            
            # Full user message sent to LM Studio (system + this); captured when debug_llm_context is enabled
            stream_llm_evidence = None
            try:
                # Quick provider-aware health check
                ok, health_msg = llm_provider_health_check(llm_provider_used, timeout=5)
                if not ok:
                    provider_name = _provider_display_name(llm_provider_used)
                    error_data = sse_json({
                        'type': 'error',
                        'message': f'{provider_name} health check failed',
                        'response': f'🔌 **CONNECTION ERROR**\n\n{provider_name}: {health_msg}'
                    })
                    try:
                        yield f"data: {error_data}{sse_end}"
                    except GeneratorExit:
                        logger.info("🛑 Client disconnected while sending health check error")
                        raise
                    return
                
                # Initialize chat history if needed
                if session_id not in CHAT_HISTORIES:
                    CHAT_HISTORIES[session_id] = []
                
                # Get chat history
                chat_history = CHAT_HISTORIES.get(session_id, [])
                
                # Save user query to history BEFORE sending to LLM (for proper follow-up context)
                # This ensures the query is available for the next follow-up even if the response fails
                _persist_user_query_once()
                
                # If query is overly broad, return refinement suggestions instead of a generic LLM answer
                # Broad query detection removed per user request
                
                # Get data context and image citations
                data_context = ""
                image_citations = []
                evidence_packet_meta = None
                
                # Check if we have comprehensive analysis data prepared earlier (from person query)
                if comprehensive_data_context:
                    data_context = comprehensive_data_context
                    logger.info(f"✅ Using comprehensive analysis data prepared earlier ({len(data_context)} chars)")
                    evidence_packet_meta = {
                        "LLM_PACKET_TYPE": "comprehensive_person_bundle",
                        "ENTITY_SCOPE": (person_name or early_extracted_person_name or "unspecified"),
                        "PLATFORM_SCOPE": "multi",
                        "DATE_SCOPE": "unspecified",
                        "EVIDENCE_ROWS": len([ln for ln in data_context.splitlines() if ln.strip()]),
                        "EVIDENCE_CHAR_COUNT": len(data_context),
                        "EVIDENCE_TRUNCATED": False,
                        "GUARANTEE_CLASS": (query_route or {}).get("guarantee_class"),
                        "CORRELATION_PRECOMPUTED": False,
                    }
                    log_llm_packet_debug(
                        EvidencePacket(text=data_context, metadata=evidence_packet_meta),
                        logger,
                    )
                
                # Check if we have a data access layer (fast Cellebrite parser or XML parser)
                data_layer = None
                if ACTIVE_DATA_LAYERS:
                    # Try ACTIVE_FILENAME first
                    if ACTIVE_FILENAME and ACTIVE_FILENAME in ACTIVE_DATA_LAYERS:
                        data_layer = ACTIVE_DATA_LAYERS[ACTIVE_FILENAME]
                        logger.info(f"✅ Using fast data access layer for {ACTIVE_FILENAME} in stream")
                    else:
                        # Use first available data layer
                        first_filename = list(ACTIVE_DATA_LAYERS.keys())[0]
                        data_layer = ACTIVE_DATA_LAYERS[first_filename]
                        logger.info(f"✅ Using fast data access layer for {first_filename} in stream (first available)")
                        ACTIVE_FILENAME = first_filename  # Update active filename
                
                # PRIORITY: Use fast data access layer if available (better query-aware extraction)
                # Only if we don't already have comprehensive analysis data
                if data_layer and not data_context:
                    logger.info(f"Using fast data access layer for query extraction (stream)")
                    try:
                        # Increase limit significantly for "list all" queries or "analyze messages that were just displayed"
                        query_lower = query.lower()
                        is_analyze_displayed = 'just displayed' in query_lower or 'that were displayed' in query_lower or 'were just displayed' in query_lower
                        _gc_stream = (query_route or {}).get("guarantee_class")
                        _llm_synthesis_bucket = _gc_stream in (
                            GUARANTEE_HYBRID,
                            GUARANTEE_FOLLOWUP_ANALYSIS,
                        )
                        max_items = (
                            500
                            if any(
                                word in query_lower
                                for word in [
                                    "list",
                                    "all",
                                    "every",
                                    "entire",
                                    "complete",
                                    "full",
                                    "72",
                                    "144",
                                ]
                            )
                            or is_analyze_displayed
                            or _llm_synthesis_bucket
                            else 100
                        )
                        
                        _pkt = build_llm_evidence_packet(
                            query=query,
                            parsed_intent=parsed_intent,
                            data_layer=data_layer,
                            query_route=query_route,
                            person_name_extracted=early_extracted_person_name,
                            max_items=max_items,
                            guarantee_class=(query_route or {}).get("guarantee_class"),
                            followup_llm_only=bool(followup_llm_only),
                            followup_mode_active=bool(followup_mode_active),
                            max_chars=LLM_MAX_FORENSIC_CHARS,
                        )
                        data_context = _pkt.text
                        evidence_packet_meta = _pkt.metadata
                        log_llm_packet_debug(_pkt, logger)
                        
                        logger.info(f"✅ Fast data extraction (scoped packet): {len(data_context)} characters")
                        if data_context:
                            logger.info(f"📊 Data context preview: {data_context[:500]}...")
                        else:
                            logger.warning(f"⚠️ Data context is empty after extraction. Query: {query[:100]}")
                    except Exception as e:
                        logger.error(f"Error using data access layer: {e}, falling back to standard extraction", exc_info=True)
                        import traceback
                        logger.error(f"Traceback: {traceback.format_exc()}")
                        data_layer = None  # Fall back to standard extraction
                elif data_context and 'COMPREHENSIVE ANALYSIS DATA' in data_context:
                    logger.info(f"✅ Using comprehensive analysis data for LLM formatting")
                
                # Standard extraction if no data layer or fallback needed
                if not data_context and data_src:
                    # DIAGNOSTIC: Log what data we have
                    logger.info(f"📊 Data source check: {len(data_src)} file(s) in ACTIVE_DATA")
                    logger.info(f"📊 ACTIVE_DATA keys: {list(data_src.keys())}")
                    
                    # CRITICAL: Check if this is a summary/overview question
                    is_summary_query = is_query_too_broad(query)
                    
                    if is_summary_query:
                        # Generate pre-summarized overview instead of raw data dump
                        logger.info("📊 Summary query detected - generating forensic overview instead of raw data")
                        overview = generate_forensic_overview(data_src)
                        
                        # Format as structured data for LLM
                        data_context = f"""FORENSIC OVERVIEW (AUTHORITATIVE):
- Contacts: {overview['contacts_count']}
- Messages: {overview['messages_count']}
- Calls: {overview['calls_count']}
- Locations: {overview['locations_count']}
- Date Range: {overview['date_range'] or 'Not available'}
- Platforms: {', '.join(overview['top_apps']) if overview['top_apps'] else 'Not available'}
- Most Active Contacts: {', '.join(overview['most_active_contacts']) if overview['most_active_contacts'] else 'Not available'}"""
                        
                        logger.info(f"✅ Generated forensic overview: {overview}")
                    # NEW: Option to let LLM extract directly from JSON
                    elif use_json_extraction:
                        logger.info("Using JSON extraction mode in stream - LLM will extract data directly from JSON")
                        for filename, data in data_src.items():
                            # Skip metadata keys like '_zip_info' - only process actual UFDR data
                            if filename.startswith('_'):
                                logger.debug(f"Skipping metadata key: {filename}")
                                continue
                            
                            if isinstance(data, dict):
                                try:
                                    # DIAGNOSTIC: Log data structure
                                    logger.info(f"📊 Processing file: {filename}")
                                    logger.info(f"📊 Data keys: {list(data.keys())}")
                                    
                                    # Check for devices array
                                    if 'devices' in data:
                                        devices = data['devices']
                                        logger.info(f"📊 Found {len(devices)} device(s) in data")
                                        for i, device in enumerate(devices):
                                            if isinstance(device, dict):
                                                contacts_count = len(device.get('contacts', []))
                                                messages_count = len(device.get('messages', []))
                                                calls_count = len(device.get('call_logs', []))
                                                locations_count = len(device.get('locations', []))
                                                logger.info(f"📊 Device {i+1}: {contacts_count} contacts, {messages_count} messages, {calls_count} calls, {locations_count} locations")
                                    else:
                                        # Check flat structure
                                        contacts_count = len(data.get('contacts', []))
                                        messages_count = len(data.get('messages', []))
                                        calls_count = len(data.get('call_logs', []))
                                        locations_count = len(data.get('locations', []))
                                        logger.info(f"📊 Flat structure: {contacts_count} contacts, {messages_count} messages, {calls_count} calls, {locations_count} locations")
                                        if locations_count > 0:
                                            logger.info(f"📍 Location data found at root level: {locations_count} location records")
                                            sample_loc = data.get('locations', [])[0] if data.get('locations') else {}
                                            logger.info(f"📍 Sample location: {sample_loc.get('address', 'N/A')} at ({sample_loc.get('latitude', 'N/A')}, {sample_loc.get('longitude', 'N/A')})")
                                    
                                    # Ensure query is safe for prepare_json_for_llm
                                    safe_query = query if query and isinstance(query, str) else ""
                                    json_context = prepare_json_for_llm(data, safe_query, max_chars=8000)
                                    logger.info(f"📊 Prepared JSON context: {len(json_context)} characters")
                                    if data_context:
                                        data_context += "\n\n--- Additional Data ---\n\n"
                                    data_context += json_context
                                except Exception as e:
                                    logger.error(f"❌ Error preparing JSON for LLM: {e}", exc_info=True)
                                    # Fallback to semantic extraction (Magnet AXIOM style)
                                    safe_query = query if query and isinstance(query, str) else ""
                                    try:
                                        extracted_context = semantic_extractor.extract_relevant_data(data, safe_query)
                                        # Truncate to fit context window
                                        extracted_context = truncate_for_context(extracted_context, max_tokens=3500, reserved_tokens=1000)
                                        logger.info(f"🔍 Semantic extraction (fallback): {len(extracted_context)} characters")
                                    except Exception as e:
                                        logger.warning(f"Semantic extraction failed: {e}, using enhanced extractor")
                                        extracted_context = enhanced_extractor.extract_relevant_data(data, safe_query)
                                        # Truncate to fit context window
                                        extracted_context = truncate_for_context(extracted_context, max_tokens=3500, reserved_tokens=1000)
                                    data_context = extracted_context
                    else:
                        # Original approach: Use enhanced extractor
                        for filename, data in data_src.items():
                            # Skip metadata keys like '_zip_info' - only process actual UFDR data
                            if filename.startswith('_'):
                                logger.debug(f"Skipping metadata key: {filename}")
                                continue
                            
                            if isinstance(data, dict):
                                # DIAGNOSTIC: Log data structure
                                logger.info(f"📊 Processing file: {filename}")
                                logger.info(f"📊 Data keys: {list(data.keys())}")
                                
                                # Check for devices array
                                if 'devices' in data:
                                    devices = data['devices']
                                    logger.info(f"📊 Found {len(devices)} device(s) in data")
                                    for i, device in enumerate(devices):
                                        if isinstance(device, dict):
                                            contacts_count = len(device.get('contacts', []))
                                            messages_count = len(device.get('messages', []))
                                            calls_count = len(device.get('call_logs', []))
                                            locations_count = len(device.get('locations', []))
                                            logger.info(f"📊 Device {i+1}: {contacts_count} contacts, {messages_count} messages, {calls_count} calls, {locations_count} locations")
                                else:
                                    # Check flat structure
                                    contacts_count = len(data.get('contacts', []))
                                    messages_count = len(data.get('messages', []))
                                    calls_count = len(data.get('call_logs', []))
                                    locations_count = len(data.get('locations', []))
                                    logger.info(f"📊 Flat structure: {contacts_count} contacts, {messages_count} messages, {calls_count} calls, {locations_count} locations")
                                    if locations_count > 0:
                                        logger.info(f"📍 Location data found at root level: {locations_count} location records")
                                        sample_loc = data.get('locations', [])[0] if data.get('locations') else {}
                                        logger.info(f"📍 Sample location: {sample_loc.get('address', 'N/A')} at ({sample_loc.get('latitude', 'N/A')}, {sample_loc.get('longitude', 'N/A')})")
                                
                                # Ensure query is safe
                                safe_query = query if query and isinstance(query, str) else ""
                                # Use semantic extractor (Magnet AXIOM style) - extracts ALL relevant data
                                try:
                                    extracted_context = semantic_extractor.extract_relevant_data(data, safe_query)
                                    # Truncate to fit context window
                                    extracted_context = truncate_for_context(extracted_context, max_tokens=3500, reserved_tokens=1000)
                                    logger.info(f"🔍 Semantic extraction from {filename}: {len(extracted_context)} characters")
                                    logger.debug(f"📊 Extracted context preview (first 500 chars): {extracted_context[:500]}")
                                except Exception as e:
                                    logger.warning(f"Semantic extraction failed: {e}, falling back to enhanced extractor")
                                    extracted_context = enhanced_extractor.extract_relevant_data(data, safe_query)
                                    # Truncate to fit context window
                                    extracted_context = truncate_for_context(extracted_context, max_tokens=3500, reserved_tokens=1000)
                                    logger.info(f"📊 Fallback extraction from {filename}: {len(extracted_context)} characters")
                                
                                # Combine data from all files
                                if data_context:
                                    data_context += f"\n\n--- Data from {filename} ---\n\n"
                                else:
                                    data_context = f"--- Data from {filename} ---\n\n"
                                data_context += extracted_context
                            
                                # Extract image citations
                                try:
                                    if query and isinstance(query, str):  # Safety check
                                        image_citations = image_citation_extractor.extract_image_citations(data, query)
                                        if image_citations and image_citation_extractor.is_image_query(query):
                                            image_info = image_citation_extractor.format_image_citations(image_citations)
                                            if data_context:
                                                data_context += "\n\n"
                                            data_context += image_info
                                except Exception as e:
                                    logger.warning(f"Error extracting image citations in stream: {e}")
                            
                            # Continue processing all files (removed break to support multiple files)
                
                # Check if query is asking for suspicious contacts/data - if so, also search the data
                query_lower = query.lower() if query else ""
                
                # Detect queries asking for suspicious contacts/data or communication patterns
                is_suspicious_query = any(phrase in query_lower for phrase in [
                    'suspicious contact', 'list suspicious', 'show suspicious', 'find suspicious', 
                    'suspicious contacts', 'suspicious data', 'suspicious activity', 'suspicious pattern',
                    'suspicious communication', 'suspicious communication pattern', 'suspicious patterns',
                    'communication patterns', 'patterns from all messages', 'patterns across all platforms'
                ])
                
                # Detect queries specifically asking for patterns across all platforms
                is_platform_pattern_query = any(phrase in query_lower for phrase in [
                    'suspicious communication patterns from all the messages across all the platforms',
                    'suspicious patterns from all messages across all platforms',
                    'communication patterns from all platforms',
                    'patterns from all messages across platforms',
                    'find suspicious patterns across all platforms'
                ])
                
                # Handle platform-specific pattern analysis
                if is_platform_pattern_query:
                    logger.info("🔍 Query asks for suspicious communication patterns across all platforms - performing comprehensive analysis...")
                    try:
                        # Import suspicious keywords
                        try:
                            from engines.nl_query_engine import SUSPICIOUS_GENERIC_KEYWORDS, SUSPICIOUS_MONEY_KEYWORDS
                        except ImportError:
                            SUSPICIOUS_GENERIC_KEYWORDS = [
                                "send package", "otp", "one time password", "pin", "password",
                                "confidential", "credential", "delete", "erase"
                            ]
                            SUSPICIOUS_MONEY_KEYWORDS = [
                                "money", "transfer", "wire", "payment", "pay", "fee", "processing fee",
                                "UPI", "bank", "account", "deposit", "withdraw", "wallet"
                            ]
                        
                        all_suspicious_keywords = SUSPICIOUS_GENERIC_KEYWORDS + SUSPICIOUS_MONEY_KEYWORDS
                        
                        # Define legitimate system senders that should be filtered out (unless context is truly suspicious)
                        legitimate_system_senders = [
                            'telegram', 'line', 'textnow', 'snapchat', 'whatsapp', 
                            'facebook', 'messenger', 'twitter', 'instagram', 'kik',
                            'skype', 'discord', 'signal', 'viber', 'fb.com', 'fb.me'
                        ]
                        
                        # Define patterns that indicate legitimate system messages (more comprehensive)
                        legitimate_patterns = [
                            r'login code.*do not give',
                            r'verification code.*do not share',
                            r'system message',
                            r'account.*logged in.*another device',
                            r'logged in to your.*account on another device',
                            r'phone number.*reassigned',
                            r'reassigned your phone number',
                            r'sms.*turn off',
                            r'reply.*stop.*turn off',
                            r'reply "stop"',
                            r'share an update with friends',
                            r'https://fb\.com/',
                            r'https://fb\.me/',
                            r'to turn off sms',
                            r'happy snapping',
                            r'snapchat code',
                            r'do not give this code to anyone',
                            r'even if they say they are from'
                        ]
                        
                        def is_legitimate_system_message(text, sender):
                            """Check if message is a legitimate system notification."""
                            text_lower = text.lower()
                            sender_lower = (sender or '').lower()
                            
                            # First check for legitimate patterns in the message text (regardless of sender)
                            for pattern in legitimate_patterns:
                                if re.search(pattern, text_lower, re.IGNORECASE):
                                    return True
                            
                            # Check if sender is a known platform/system
                            if any(platform in sender_lower for platform in legitimate_system_senders):
                                # If sender is a known platform, check for common system message indicators
                                system_indicators = [
                                    'code:', 'verification', 'login', 'account', 'logged in',
                                    'phone number', 'reassigned', 'turn off', 'stop',
                                    'system', 'notification', 'alert'
                                ]
                                # If message contains system indicators and is from a platform, likely legitimate
                                if any(indicator in text_lower for indicator in system_indicators):
                                    return True
                            
                            # Check for shortcode senders (numeric senders like "32665" for Facebook)
                            # These are often legitimate system messages
                            if sender and sender.isdigit() and len(sender) <= 6:
                                # Check if message contains common SMS service patterns
                                if any(pattern in text_lower for pattern in ['turn off', 'reply stop', 'fb.com', 'fb.me', 'share an update']):
                                    return True
                            
                            return False
                        
                        def calculate_suspicion_score(text, keywords_found, sender):
                            """Calculate suspicion score based on context."""
                            text_lower = text.lower()
                            score = 0.0
                            
                            # High-risk keywords in suspicious context
                            high_risk_keywords = ['otp', 'one time password', 'pin', 'password', 'transfer', 'wire', 'payment']
                            for kw in high_risk_keywords:
                                if kw in keywords_found:
                                    # Check if it's in a suspicious context (not a system message)
                                    if not is_legitimate_system_message(text, sender):
                                        # Check for urgency indicators
                                        if any(word in text_lower for word in ['urgent', 'immediate', 'asap', 'now', 'quick']):
                                            score += 0.4
                                        elif any(word in text_lower for word in ['secret', 'confidential', 'private']):
                                            score += 0.3
                                        else:
                                            score += 0.2
                            
                            # Financial keywords
                            financial_keywords = ['money', 'bank', 'account', 'deposit', 'withdraw', 'fee']
                            for kw in financial_keywords:
                                if kw in keywords_found:
                                    if not is_legitimate_system_message(text, sender):
                                        score += 0.15
                            
                            return min(score, 1.0)
                        
                        # Analyze messages grouped by platform
                        platform_analysis = {}
                        total_chats = 0
                        total_messages = 0
                        all_suspicious_messages = []
                        
                        # First, try to get messages from data layer (for XML/Cellebrite files)
                        data_layer = None
                        if ACTIVE_DATA_LAYERS:
                            if ACTIVE_FILENAME and ACTIVE_FILENAME in ACTIVE_DATA_LAYERS:
                                data_layer = ACTIVE_DATA_LAYERS[ACTIVE_FILENAME]
                            elif ACTIVE_DATA_LAYERS:
                                data_layer = list(ACTIVE_DATA_LAYERS.values())[0]
                        
                        if data_layer:
                            logger.info("✅ Using data layer to query messages from database...")
                            try:
                                # Query all chat messages from database (no filter = all platforms)
                                all_messages = data_layer.query_chat_messages("", limit=10000)
                                logger.info(f"📊 Retrieved {len(all_messages)} messages from data layer")
                                
                                # Process messages from data layer
                                for msg in all_messages:
                                    text = (msg.get('text_content') or msg.get('text') or '').lower()
                                    platform = msg.get('platform') or 'Unknown'
                                    
                                    # Initialize platform entry if needed
                                    if platform not in platform_analysis:
                                        platform_analysis[platform] = {
                                            'platform': platform,
                                            'total_messages': 0,
                                            'suspicious_messages': [],
                                            'chats': set(),
                                            'keywords_found': set()
                                        }
                                    
                                    # Track chat IDs
                                    chat_id = msg.get('chat_id') or msg.get('chat_name') or 'unknown'
                                    platform_analysis[platform]['chats'].add(chat_id)
                                    
                                    platform_analysis[platform]['total_messages'] += 1
                                    total_messages += 1
                                    
                                    # Check for suspicious keywords (use word boundaries for better matching)
                                    found_keywords = []
                                    for kw in all_suspicious_keywords:
                                        # Use word boundary matching to avoid false positives like "pin" in "typing"
                                        pattern = r'\b' + re.escape(kw) + r'\b'
                                        if re.search(pattern, text, re.IGNORECASE):
                                            found_keywords.append(kw)
                                    
                                    if found_keywords:
                                        sender = msg.get('from_participant') or msg.get('from', '')
                                        msg_text = msg.get('text_content') or msg.get('text', '')
                                        
                                        # Filter out legitimate system messages
                                        if not is_legitimate_system_message(msg_text, sender):
                                            suspicion_score = calculate_suspicion_score(msg_text, found_keywords, sender)
                                            
                                            # Only include messages with meaningful suspicion score (> 0.1)
                                            if suspicion_score > 0.1:
                                                suspicious_msg = {
                                                    'timestamp': msg.get('timestamp'),
                                                    'from': sender,
                                                    'to': msg.get('to_participant') or msg.get('to', ''),
                                                    'text': msg_text,
                                                    'keywords_found': found_keywords,
                                                    'suspicion_score': suspicion_score,
                                                    'chat_id': chat_id,
                                                    'message_type': msg.get('message_type', 'text'),
                                                    'source_file': 'database'
                                                }
                                                platform_analysis[platform]['suspicious_messages'].append(suspicious_msg)
                                                all_suspicious_messages.append(suspicious_msg)
                                                platform_analysis[platform]['keywords_found'].update(found_keywords)
                            except Exception as e:
                                logger.warning(f"Error querying data layer: {e}", exc_info=True)
                        
                        # Also check data_src if available (for JSON UFDR files)
                        if data_src:
                            logger.info("✅ Also checking data_src for messages...")
                            for filename, data in data_src.items():
                                if filename.startswith('_'):
                                    continue
                                
                                # Analyze messages and group by platform
                                for msg in data.get('messages', []):
                                    text = (msg.get('text') or msg.get('content') or '').lower()
                                    
                                    # Determine platform from message
                                    platform = msg.get('platform') or msg.get('source') or 'Unknown'
                                    if platform == 'Unknown':
                                        # Try to infer from other fields
                                        if 'whatsapp' in str(msg.get('chat_name', '')).lower() or 'whatsapp' in str(msg.get('source_table', '')).lower():
                                            platform = 'WhatsApp'
                                        elif 'telegram' in str(msg.get('chat_name', '')).lower() or 'telegram' in str(msg.get('source_table', '')).lower():
                                            platform = 'Telegram'
                                        elif 'snapchat' in str(msg.get('chat_name', '')).lower() or 'snapchat' in str(msg.get('source_table', '')).lower():
                                            platform = 'Snapchat'
                                        elif 'twitter' in str(msg.get('chat_name', '')).lower() or 'twitter' in str(msg.get('source_table', '')).lower():
                                            platform = 'Twitter'
                                        elif 'messenger' in str(msg.get('chat_name', '')).lower() or 'facebook' in str(msg.get('chat_name', '')).lower():
                                            platform = 'Facebook Messenger'
                                        elif 'line' in str(msg.get('chat_name', '')).lower():
                                            platform = 'Line'
                                        elif 'skype' in str(msg.get('chat_name', '')).lower():
                                            platform = 'Skype'
                                        elif 'textnow' in str(msg.get('chat_name', '')).lower():
                                            platform = 'TextNow'
                                        elif 'sms' in str(msg.get('source_table', '')).lower() or 'native' in str(msg.get('source_table', '')).lower():
                                            platform = 'Native Messages'
                                    
                                    # Initialize platform entry if needed
                                    if platform not in platform_analysis:
                                        platform_analysis[platform] = {
                                            'platform': platform,
                                            'total_messages': 0,
                                            'suspicious_messages': [],
                                            'chats': set(),
                                            'keywords_found': set()
                                        }
                                    
                                    # Track chat IDs
                                    chat_id = msg.get('chat_id') or msg.get('chat_name') or 'unknown'
                                    platform_analysis[platform]['chats'].add(chat_id)
                                    
                                    platform_analysis[platform]['total_messages'] += 1
                                    total_messages += 1
                                    
                                    # Check for suspicious keywords
                                    # Check for suspicious keywords (use word boundaries)
                                    found_keywords = []
                                    for kw in all_suspicious_keywords:
                                        pattern = r'\b' + re.escape(kw) + r'\b'
                                        if re.search(pattern, text, re.IGNORECASE):
                                            found_keywords.append(kw)
                                    
                                    if found_keywords:
                                        sender = msg.get('from') or msg.get('sender', '')
                                        msg_text = msg.get('text') or msg.get('content', '')
                                        
                                        # Filter out legitimate system messages
                                        if not is_legitimate_system_message(msg_text, sender):
                                            suspicion_score = calculate_suspicion_score(msg_text, found_keywords, sender)
                                            
                                            # Only include messages with meaningful suspicion score (> 0.1)
                                            if suspicion_score > 0.1:
                                                suspicious_msg = {
                                                    'timestamp': msg.get('timestamp'),
                                                    'from': sender,
                                                    'to': msg.get('to') or msg.get('receiver', ''),
                                                    'text': msg_text,
                                                    'keywords_found': found_keywords,
                                                    'suspicion_score': suspicion_score,
                                                    'chat_id': chat_id,
                                                    'message_type': msg.get('message_type', 'text'),
                                                    'source_file': filename
                                                }
                                                platform_analysis[platform]['suspicious_messages'].append(suspicious_msg)
                                                all_suspicious_messages.append(suspicious_msg)
                                                platform_analysis[platform]['keywords_found'].update(found_keywords)
                                
                                # Also check chat_messages if available
                                for chat_msg in data.get('chat_messages', []):
                                    text = (chat_msg.get('text_content') or chat_msg.get('text') or '').lower()
                                    platform = chat_msg.get('platform') or 'Unknown'
                                    
                                    if platform not in platform_analysis:
                                        platform_analysis[platform] = {
                                            'platform': platform,
                                            'total_messages': 0,
                                            'suspicious_messages': [],
                                            'chats': set(),
                                            'keywords_found': set()
                                        }
                                    
                                    chat_id = chat_msg.get('chat_id') or 'unknown'
                                    platform_analysis[platform]['chats'].add(chat_id)
                                    platform_analysis[platform]['total_messages'] += 1
                                    total_messages += 1
                                    
                                    # Check for suspicious keywords (use word boundaries)
                                    found_keywords = []
                                    for kw in all_suspicious_keywords:
                                        pattern = r'\b' + re.escape(kw) + r'\b'
                                        if re.search(pattern, text, re.IGNORECASE):
                                            found_keywords.append(kw)
                                    
                                    if found_keywords:
                                        sender = chat_msg.get('from_participant') or chat_msg.get('from', '')
                                        msg_text = chat_msg.get('text_content') or chat_msg.get('text', '')
                                        
                                        # Filter out legitimate system messages
                                        if not is_legitimate_system_message(msg_text, sender):
                                            suspicion_score = calculate_suspicion_score(msg_text, found_keywords, sender)
                                            
                                            # Only include messages with meaningful suspicion score (> 0.1)
                                            if suspicion_score > 0.1:
                                                suspicious_msg = {
                                                    'timestamp': chat_msg.get('timestamp'),
                                                    'from': sender,
                                                    'to': chat_msg.get('to_participant') or chat_msg.get('to', ''),
                                                    'text': msg_text,
                                                    'keywords_found': found_keywords,
                                                    'suspicion_score': suspicion_score,
                                                    'chat_id': chat_id,
                                                    'message_type': chat_msg.get('message_type', 'text'),
                                                    'source_file': filename
                                                }
                                                platform_analysis[platform]['suspicious_messages'].append(suspicious_msg)
                                                all_suspicious_messages.append(suspicious_msg)
                                                platform_analysis[platform]['keywords_found'].update(found_keywords)
                        
                        # Calculate total chats
                        for platform, analysis in platform_analysis.items():
                            total_chats += len(analysis['chats'])
                        
                        # Format analysis context for LLM
                        pattern_analysis_context = f"""
SUSPICIOUS COMMUNICATION PATTERNS ANALYSIS - ALL PLATFORMS

Analysis Context:
These messages were analyzed across various platforms to identify suspicious communication patterns. The analysis focused on keywords and patterns that might indicate malicious or suspicious activity, such as "OTP," "transfer," "payment," and other similar terms.

Detection Basis:
Searched through {total_chats} chats containing {total_messages} messages using keywords like "OTP," "transfer," "payment," and other suspicious terms across all platforms.

PLATFORM BREAKDOWN:
"""
                        
                        # Sort suspicious messages by suspicion score (highest first)
                        for platform in platform_analysis:
                            platform_analysis[platform]['suspicious_messages'].sort(
                                key=lambda x: x.get('suspicion_score', 0), 
                                reverse=True
                            )
                        
                        # Add platform-specific findings
                        for platform, analysis in sorted(platform_analysis.items(), key=lambda x: len(x[1]['suspicious_messages']), reverse=True):
                            chat_count = len(analysis['chats'])
                            msg_count = analysis['total_messages']
                            suspicious_count = len(analysis['suspicious_messages'])
                            
                            if suspicious_count > 0:
                                # Calculate average suspicion score
                                avg_score = sum(m.get('suspicion_score', 0) for m in analysis['suspicious_messages']) / suspicious_count
                                
                                pattern_analysis_context += f"""
{platform}:
- Total Chats Analyzed: {chat_count}
- Total Messages: {msg_count}
- Suspicious Messages Found: {suspicious_count}
- Average Suspicion Score: {avg_score:.2f}
- Keywords Detected: {', '.join(sorted(list(analysis['keywords_found']))[:10])}{'...' if len(analysis['keywords_found']) > 10 else ''}
- Top Suspicious Messages (sorted by suspicion score):
"""
                                # Add sample messages (limit to 5 per platform, highest suspicion first)
                                for i, msg in enumerate(analysis['suspicious_messages'][:5], 1):
                                    suspicion_score = msg.get('suspicion_score', 0)
                                    pattern_analysis_context += f"""
  {i}. Timestamp: {msg.get('timestamp', 'N/A')}
     From: {msg.get('from', 'N/A')}
     To: {msg.get('to', 'N/A')}
     Suspicion Score: {suspicion_score:.2f}
     Keywords: {', '.join(msg.get('keywords_found', []))}
     Message Preview: {msg.get('text', '')[:150]}{'...' if len(msg.get('text', '')) > 150 else ''}
"""
                                if suspicious_count > 5:
                                    pattern_analysis_context += f"  [Note: Showing top 5 of {suspicious_count} suspicious messages from {platform}]\n"
                        
                        # Calculate confidence score
                        if total_messages > 0:
                            suspicious_ratio = len(all_suspicious_messages) / total_messages
                            confidence = min(0.95, 0.5 + (suspicious_ratio * 2))  # Scale to 0.5-0.95 range
                        else:
                            confidence = 0.5
                        
                        pattern_analysis_context += f"""

SUMMARY:
- Total Platforms Analyzed: {len(platform_analysis)}
- Total Chats: {total_chats}
- Total Messages: {total_messages}
- Total Suspicious Messages: {len(all_suspicious_messages)}
- Confidence: {confidence:.3f}

RECOMMENDATIONS:
1. Review the WhatsApp messages for any suspicious transfers or OTPs.
2. Check Telegram and Snapchat for media files and system messages which could be indicators of malware or phishing attempts.
3. Investigate Twitter and Facebook Messenger for any unusual location data or text patterns that might suggest fraudulent activity.
4. Consider examining Line, Skype, and TextNow for any unexpected system messages or media exchanges.
"""
                        
                        # Add to data_context
                        if data_context:
                            data_context = pattern_analysis_context + "\n\n--- Additional Forensic Data ---\n\n" + data_context
                        else:
                            data_context = pattern_analysis_context
                        
                        logger.info(f"✅ Added platform pattern analysis context ({len(pattern_analysis_context)} chars, {len(all_suspicious_messages)} suspicious messages found)")
                    except Exception as e:
                        logger.warning(f"Error analyzing platform patterns: {e}", exc_info=True)
                        # Continue with existing data_context even if pattern analysis fails
                
                if is_suspicious_query and data_src:
                    logger.info("🔍 Query asks for suspicious contacts/data - performing data search in stream...")
                    try:
                        # Import suspicious keywords
                        try:
                            from engines.nl_query_engine import SUSPICIOUS_GENERIC_KEYWORDS, SUSPICIOUS_MONEY_KEYWORDS
                        except ImportError:
                            # Fallback suspicious keywords if import fails
                            SUSPICIOUS_GENERIC_KEYWORDS = [
                                "send package", "otp", "one time password", "pin", "password",
                                "confidential", "credential", "delete", "erase"
                            ]
                            SUSPICIOUS_MONEY_KEYWORDS = [
                                "money", "transfer", "wire", "payment", "pay", "fee", "processing fee",
                                "UPI", "bank", "account", "deposit", "withdraw", "wallet"
                            ]
                        
                        all_suspicious_keywords = SUSPICIOUS_GENERIC_KEYWORDS + SUSPICIOUS_MONEY_KEYWORDS
                        
                        # Search for suspicious contacts
                        suspicious_contacts = []
                        suspicious_messages = []
                        contacts_dict = {}
                        
                        for filename, data in data_src.items():
                            if filename.startswith('_'):
                                continue
                            
                            # Build contacts dictionary
                            for contact in data.get('contacts', []):
                                phone = contact.get('phone', '')
                                name = contact.get('name', '')
                                if phone and phone not in contacts_dict:
                                    contacts_dict[phone] = {
                                        'name': name or 'Unknown',
                                        'phone': phone,
                                        'email': contact.get('email', ''),
                                        'suspicious_count': 0,
                                        'suspicious_messages': [],
                                        'source_file': filename
                                    }
                            
                            # Check messages for suspicious keywords
                            for msg in data.get('messages', []):
                                text = (msg.get('text') or msg.get('content') or '').lower()
                                if any(kw in text for kw in all_suspicious_keywords):
                                    from_phone = msg.get('from') or msg.get('sender', '')
                                    to_phone = msg.get('to') or msg.get('receiver', '')
                                    
                                    # Track suspicious activity for contacts
                                    if from_phone in contacts_dict:
                                        contacts_dict[from_phone]['suspicious_count'] += 1
                                        contacts_dict[from_phone]['suspicious_messages'].append({
                                            'timestamp': msg.get('timestamp'),
                                            'text': msg.get('text') or msg.get('content', ''),
                                            'to': to_phone
                                        })
                                    
                                    if to_phone and to_phone in contacts_dict:
                                        contacts_dict[to_phone]['suspicious_count'] += 1
                                        contacts_dict[to_phone]['suspicious_messages'].append({
                                            'timestamp': msg.get('timestamp'),
                                            'text': msg.get('text') or msg.get('content', ''),
                                            'from': from_phone
                                        })
                                    
                                    suspicious_messages.append({
                                        'type': 'message',
                                        'timestamp': msg.get('timestamp'),
                                        'from': from_phone,
                                        'to': to_phone,
                                        'text': msg.get('text') or msg.get('content', ''),
                                        'source_file': filename
                                    })
                            
                            # Also check for contacts with suspicious names/emails
                            for contact in data.get('contacts', []):
                                phone = contact.get('phone', '')
                                name = (contact.get('name') or '').lower()
                                email = (contact.get('email') or '').lower()
                                
                                # Check if contact name/email looks suspicious
                                suspicious_name_keywords = ['unknown', 'external', 'temp', 'suspicious', 'blocked']
                                if any(kw in name for kw in suspicious_name_keywords) or any(kw in email for kw in suspicious_name_keywords):
                                    if phone not in contacts_dict:
                                        contacts_dict[phone] = {
                                            'name': contact.get('name', 'Unknown'),
                                            'phone': phone,
                                            'email': contact.get('email', ''),
                                            'suspicious_count': 1,
                                            'suspicious_messages': [],
                                            'source_file': filename
                                        }
                        
                        # Add contacts with suspicious activity
                        for phone, contact_info in contacts_dict.items():
                            if contact_info['suspicious_count'] > 0:
                                suspicious_contacts.append({
                                    'type': 'contact',
                                    'name': contact_info['name'],
                                    'phone': phone,
                                    'email': contact_info.get('email', ''),
                                    'suspicious_count': contact_info['suspicious_count'],
                                    'source_file': contact_info.get('source_file', filename)
                                })
                        
                        if suspicious_contacts or suspicious_messages:
                            # Format suspicious contacts data with detection criteria for LLM
                            suspicious_data_context = f"""
SUSPICIOUS CONTACTS DETECTION RESULTS:

DETECTION METHOD: Analyzed all messages across all platforms for suspicious keywords and patterns.

DETECTION CRITERIA:
- Suspicious Keywords Searched: {', '.join(all_suspicious_keywords[:10])}{'...' if len(all_suspicious_keywords) > 10 else ''} (Total: {len(all_suspicious_keywords)} keywords)
- Contact Name/Email Keywords: unknown, external, temp, suspicious, blocked
- Analysis Scope: All messages from all platforms in the forensic data

SUSPICIOUS CONTACTS FOUND ({len(suspicious_contacts)} total):
"""
                            for i, contact in enumerate(suspicious_contacts[:50], 1):  # Limit to 50 for context
                                contact_info = f"""
{i}. Phone: {contact.get('phone', 'N/A')}
   Name: {contact.get('name', 'Unknown')}
   Email: {contact.get('email', 'N/A')}
   Suspicious Message Count: {contact.get('suspicious_count', 0)}
   Source File: {contact.get('source_file', 'N/A')}
"""
                                suspicious_data_context += contact_info
                            
                            if len(suspicious_contacts) > 50:
                                suspicious_data_context += f"\n[Note: Showing first 50 of {len(suspicious_contacts)} suspicious contacts]"
                            
                            if suspicious_messages:
                                suspicious_data_context += f"\n\nSUSPICIOUS MESSAGES FOUND ({len(suspicious_messages)} total):\n"
                                for i, msg in enumerate(suspicious_messages[:20], 1):  # Limit to 20 messages
                                    msg_info = f"""
{i}. Timestamp: {msg.get('timestamp', 'N/A')}
   From: {msg.get('from', 'N/A')}
   To: {msg.get('to', 'N/A')}
   Message: {msg.get('text', '')[:200]}{'...' if len(msg.get('text', '')) > 200 else ''}
   Source: {msg.get('source_file', 'N/A')}
"""
                                    suspicious_data_context += msg_info
                                
                                if len(suspicious_messages) > 20:
                                    suspicious_data_context += f"\n[Note: Showing first 20 of {len(suspicious_messages)} suspicious messages]"
                            
                            # Add to data_context so LLM can see detection criteria
                            if data_context:
                                data_context = suspicious_data_context + "\n\n--- Additional Forensic Data ---\n\n" + data_context
                            else:
                                data_context = suspicious_data_context
                            
                            logger.info(f"✅ Added suspicious contacts detection context to data_context in stream ({len(suspicious_data_context)} chars)")
                    except Exception as e:
                        logger.warning(f"Error searching for suspicious contacts in stream: {e}", exc_info=True)
                        # Continue with existing data_context even if suspicious search fails
                
                # DIAGNOSTIC: Log final context
                if data_context:
                    logger.info(f"📊 Final data_context length: {len(data_context)} characters")
                    logger.debug(f"📊 Final data_context preview (first 1000 chars):\n{data_context[:1000]}")
                else:
                    logger.warning(f"⚠️ WARNING: data_context is EMPTY! LLM will not receive any UFDR data!")
                
                # Detect query language and add language instruction
                from utils.language_detector import detect_language, get_language_instruction
                detected_language = detect_language(user_query_original or query)
                # Safety: if detector returns English but query is clearly non-ASCII,
                # force multilingual handling instead of default English.
                if detected_language == 'english' and any(ord(ch) > 127 for ch in (user_query_original or query)):
                    detected_language = 'hindi'
                language_instruction = get_language_instruction(detected_language)
                
                # Extract query intent and qualifiers
                intent_info = query_analyzer.extract_specific_intent(query)
                qualifiers = intent_info.get('qualifiers', {})
                primary_intent = intent_info.get('primary_intent', 'exploratory')
                should_be_brief = intent_info.get('should_be_brief', False)
                should_be_comprehensive = intent_info.get('should_be_comprehensive', False)
                
                # Strict formatting path ONLY for explicit "pull messages ..." commands
                is_pull_messages_command = bool(re.match(r'^\s*pull\s+messages?\b', query.lower()))
                
                logger.info(f"🎯 Query intent: {primary_intent}, Brief: {should_be_brief}, Comprehensive: {should_be_comprehensive}")
                logger.info(f"🎯 Qualifiers detected: {qualifiers}")

                response_format_tier = select_response_format_tier(
                    query=user_query_original or query,
                    data_context_chars=len(data_context or ""),
                    should_be_brief=bool(
                        should_be_brief or qualifiers.get('brief') or qualifiers.get('simple') or qualifiers.get('just')
                    ),
                    should_be_comprehensive=bool(
                        should_be_comprehensive or qualifiers.get('detailed') or qualifiers.get('comprehensive')
                    ),
                    classification_type=(classification.get("type") if isinstance(classification, dict) else None),
                    primary_intent=primary_intent,
                    is_pull_messages=is_pull_messages_command,
                )
                universal_format_instructions = format_universal_response_instructions(response_format_tier)
                logger.info(
                    f"📐 Universal response format tier: {response_format_tier} "
                    f"({describe_tier_for_logging(response_format_tier)})"
                )
                
                # Build response style instructions based on query intent
                response_style_instructions = ""
                if should_be_brief or qualifiers.get('brief') or qualifiers.get('simple') or qualifiers.get('just'):
                    response_style_instructions = """
⚠️ CRITICAL: QUERY-SPECIFIC RESPONSE REQUIRED
- The user asked for a BRIEF/SIMPLE answer - provide ONLY what was asked, nothing more
- Do NOT add extra information, statistics, or analysis unless explicitly requested
- Answer the specific question directly and concisely
- If asked for "device info in brief", provide ONLY device metadata (model, ID, phone number, carrier, OS)
- Do NOT include platform classifications, message counts, or other statistics unless asked
- Respect qualifiers like "brief", "simple", "just", "only" - these mean the user wants minimal information
"""
                elif should_be_comprehensive or qualifiers.get('detailed') or qualifiers.get('comprehensive'):
                    response_style_instructions = """
⚠️ COMPREHENSIVE RESPONSE REQUESTED
- The user asked for a DETAILED/COMPREHENSIVE answer
- Provide thorough analysis with all relevant information
- Include statistics, patterns, and insights
- Structure your response with clear sections
"""
                else:
                    response_style_instructions = """
⚠️ QUERY-SPECIFIC RESPONSE REQUIRED
- Answer ONLY what the user asked for - do not add extra information
- If the user asks for device info, provide ONLY device metadata
- If the user asks for contacts, provide ONLY contact information
- If the user asks for location, provide ONLY location data
- Do NOT include platform classifications, message statistics, or other data unless explicitly requested
- Match the scope of your answer to the scope of the question
"""
                
                # Pull-only output format (LLM still used; only structure is constrained)
                # Applies strictly to explicit "pull messages ..." commands.
                pull_messages_format_instructions = ""
                question_header = "QUESTION"
                if 'followup_mode_active' in locals() and followup_mode_active:
                    question_header = "FOLLOW-UP QUESTION"

                if is_pull_messages_command:
                    response_style_instructions += """

⚠️ STRICT FORMAT FOR "PULL MESSAGES" COMMANDS
- This is an explicit evidence-pull command. Present pulled evidence first, then analysis.
- Use EXACT section headers in this order:
  1) "Pulled Messages"
  2) "Analysis Context"
  3) "Recommendations"
- Do NOT merge these sections.
- In "Pulled Messages", list chats and messages only (timestamp, from, to, content/media/system marker).
- Include exact counts:
  - "Total Chats Pulled: X"
  - "Total Messages Pulled: Y"
- Do NOT say "No messages found" if any messages are listed.
- If zero results, write exactly:
  - "Pulled Messages"
  - "Total Chats Pulled: 0"
  - "Total Messages Pulled: 0"
  - "No messages found for the requested platform."
- Keep "Analysis Context" concise and evidence-based (2-4 bullets).
- Keep "Recommendations" concise and actionable (2-4 bullets).
"""
                    pull_messages_format_instructions = """
OUTPUT TEMPLATE (for this query):

Pulled Messages
Total Chats Pulled: <number>
Total Messages Pulled: <number>
<chat/message listing>

Analysis Context
- <how data was pulled / scope / basis>
- <key observation>

Recommendations
1. <actionable next step>
2. <actionable next step>
"""
                
                # Prepare messages
                messages = []
                
                messages.append({
                    "role": "system",
                    "content": f"""You are an elite digital forensics analyst with expertise in mobile device forensics, communication analysis, and evidence investigation. Your role is to conduct professional forensic examinations of UFDR (Universal Forensic Data Report) files.

🌐 LANGUAGE REQUIREMENT: {language_instruction}
You MUST respond in the same language as the user's query. Match the user's language exactly.
If the user query is non-English or uses non-Latin script, DO NOT switch to English.
Do not transliterate unless the user explicitly asks for transliteration.

{response_style_instructions}

📋 DATA INTEGRITY GUIDELINES:
1. Base your analysis SOLELY on the FORENSIC DATA section provided below
2. Answer ONLY what the user asked for - do not add extra information unless explicitly requested
3. If the query asks for "device info" or "device information", provide ONLY device metadata (model, Android ID, phone number, carrier, OS, etc.)
4. If the query asks for "contacts", provide ONLY contact information
5. If the query asks for "location", provide ONLY location data
6. Do NOT include platform classifications, message statistics, or chat breakdowns unless explicitly requested
7. You may make reasonable inferences from the data, but only to answer the specific question asked
8. MULTI-TABLE FORENSIC DATA: The block may include BOTH third-party app chats (e.g. sections titled "SAMPLE CHAT MESSAGES", "CHAT MESSAGES", platform names) AND a separate native/SMS section (e.g. "SMS / NATIVE MESSAGES TABLE"). If chat samples or call rows involving a person exist, those ARE communications. Never treat "no SMS/native rows matched" (or similar) as "no interaction" with that person when chat or call evidence for them appears elsewhere in the same FORENSIC DATA.

⚠️ CRITICAL: QUERY INTENT COMPLIANCE
- Primary Intent Detected: {primary_intent}
- Your response MUST be limited to answering this specific intent
- Do NOT provide information about other data types unless the query explicitly asks for them
- If asked for "device info in brief", provide ONLY: device model, Android ID, phone number, carrier, OS type, location services status
- Do NOT add platform usage statistics, message counts, or chat breakdowns to device info responses

⚠️ CRITICAL: RESPONSE CLARITY
- If you are providing data/messages, do NOT say "No messages found" or "No data found" when you are actually showing data
- If messages exist and you are displaying them, start with: "Here are the [platform] messages found:" or "Found [X] messages from [platform]:"
- Do NOT use contradictory language like "No messages found" followed by a list of messages
- Be direct: if data exists, present it without negative qualifiers

CORE CAPABILITIES:
- Device metadata extraction and analysis
- Contact information retrieval
- Message content analysis (SMS, WhatsApp, iMessage)
- Call log analysis
- Location data extraction
- Timeline reconstruction
- Relationship mapping

RESPONSE METHODOLOGY:
1. IDENTIFY QUERY INTENT: Determine exactly what the user is asking for
2. EXTRACT RELEVANT DATA: Pull ONLY the data needed to answer the specific question
3. ANSWER DIRECTLY: Provide a direct answer to the question without adding extra information
4. RESPECT QUALIFIERS: If the query says "brief", "simple", or "just", provide minimal information
5. NO EXTRA DATA: Do not include statistics, breakdowns, or analysis unless explicitly requested

LLM ROLE IN THIS SYSTEM (CRITICAL):
- Deterministic retrieval is the source of factual truth. You are the reasoning layer.
- Do NOT re-run retrieval logic mentally or invent missing records.
- Convert evidence into investigator-grade meaning, not generic summaries.

CORRELATION SAFETY RULES (MANDATORY):
- Treat deterministic counters/fields as immutable facts. Never override them.
- If `same_contact_overlap_count: 0`, you MUST NOT claim same-contact overlap or "same contacts" coordination.
- Day-level overlap (same date) is weak evidence. Frame it as "temporal association" unless tight time/entity linkage is explicitly present.
- Never infer intent (e.g., "coordinated activity") as fact from date overlap alone; use uncertainty language and record limits in **Uncertainty / Limits**.
- Do NOT infer physical co-presence at a place, or that specific individuals were "at the locations," from day-level location+chat overlap alone; that requires location+identity/time linkage not shown in summary stats.
- Every interpretation sentence must be supported by at least one explicit fact from **Key Supporting Observations** (or the ultra-short combined section).
- If evidence is insufficient for a strong claim, say so in **Uncertainty / Limits** and give one targeted next action.

{FORENSIC_SPECULATION_RULE}

{MANDATORY_UNCERTAINTY_SECTION_HINT}

{universal_format_instructions}

REASONING DISCIPLINE:
- Follow the universal section structure above (unless this is an explicit "pull messages" command with its own template).
- Do not add a separate heading titled "Hypotheses"; use **Interpretation / Insight** (or the ultra-short combined section) for cautious alternatives.
- Cross-domain statements only when directly supported by facts in the provided data.

EVIDENCE-LOCK SELF-CHECK (run silently before final answer):
1) Contradiction check: no statement may conflict with any deterministic counter/field.
2) Strength check: if only date-level overlap is present, avoid strong conclusions.
3) Provenance check: each major claim is traceable to **Key Supporting Observations** bullets (or equivalent in the ultra-short layout).

ANTI-GENERIC RULES:
- Avoid filler such as "investigate further" without naming exactly what to inspect.
- If evidence is insufficient, say what is missing and ask a targeted follow-up retrieval query.
- If deterministic evidence says 0 matches, explicitly keep that constraint; do not contradict it.

PHONE NUMBER HANDLING:
- If asked for international phone numbers and none are found in the data, explicitly state 'No international phone numbers found in the data'
- NEVER invent or make up phone numbers, even if the pattern seems logical (e.g., +44 for UK, +1 for US)
- Only list phone numbers that actually appear in the FORENSIC DATA section
- If the FORENSIC DATA shows 'No international phone numbers found', you MUST say exactly that - do not create examples
- International phone numbers are those starting with '+' followed by country code

Your goal is to provide a precise, query-specific answer that addresses exactly what the user asked for, WITH context about how the data was found and actionable recommendations for next steps."""
                })
                
                # DISABLED: Chat history excluded for all forensic queries to prevent hallucinations
                # Chat history causes hallucination when combined with forensic data
                # Each query is treated independently with only the current forensic data context
                logger.info(f"🔒 Chat history disabled for forensic queries (prevents hallucination)")
                
                # Add user query with data context - emphasize the query
                # (The query is already in CHAT_HISTORIES, but we add it here with data context)
                
                # If we have confirmation data, prepend it to data_context
                if 'has_confirmation_data' in locals() and has_confirmation_data and 'confirmation_chat_data' in locals() and confirmation_chat_data:
                    if data_context:
                        data_context = confirmation_chat_data + "\n\n" + data_context
                    else:
                        data_context = confirmation_chat_data

                # FOLLOW-UP MODE: anchor to selected assistant summary + optional raw forensic snapshot
                # from the same assistant turn (so "examples" can cite timestamps/lines).
                if 'followup_mode_active' in locals() and followup_mode_active:
                    base_ctx_for_prompt = FOLLOWUP_BASE_CONTEXT.get(session_id, {})
                    base_content = base_ctx_for_prompt.get("content")
                    if base_content:
                        _snap = _find_evidence_snapshot_for_followup(session_id, base_content)
                        _sup = _followup_supplementary_deterministic_block(
                            user_query_original,
                            parsed_intent if isinstance(parsed_intent, dict) else None,
                            str(base_content),
                        )
                        _sup_pri = ""
                        if _sup:
                            _sup_pri = (
                                "ANSWER PRIORITY (read carefully): The user's follow-up may target data that appears ONLY in "
                                "the **SUPPLEMENTARY DETERMINISTIC FORENSIC DATA** block at the end of this section. "
                                "The chat/message summary above is a DIFFERENT artifact — do not infer \"no locations\", "
                                "\"no calls\", etc. from that summary when the supplementary block lists timestamped rows.\n\n"
                            )
                        if _snap:
                            data_context = _sup_pri + (
                                "FOLLOW-UP BASE CONTENT (prior analysis summary — same scope as selected message):\n"
                                f"{base_content}\n\n"
                                "---\n\n"
                                "DETERMINISTIC FORENSIC SNAPSHOT (raw rows from the same investigation turn; "
                                "use for concrete timestamps, quotes, and examples):\n"
                                f"{_snap}\n\n"
                                "IMPORTANT: For line-level examples, cite the SNAPSHOT. The summary may omit row detail. "
                                "Do not invent rows not shown in the SNAPSHOT."
                            )
                        else:
                            data_context = _sup_pri + (
                                "FOLLOW-UP BASE CONTENT (selected assistant summary):\n"
                                f"{base_content}\n\n"
                                "IMPORTANT: If a SUPPLEMENTARY DETERMINISTIC block appears below, it was pulled from the "
                                "loaded case for this follow-up question — use it for line-level facts in that domain. "
                                "If no SNAPSHOT was stored for this message, the summary above may omit row detail."
                            )
                        if _sup:
                            data_context = (data_context or "") + _sup
                
                # CRITICAL: Check if data context indicates no data found
                # Only mark as "no data" if it explicitly says NO_DATA_FOUND or is completely empty
                # If it contains helpful info (like "database contains X contacts"), still try to answer
                has_no_data = (data_context and "NO_DATA_FOUND" in data_context and 
                              "but the database contains" not in data_context) or not data_context or len(data_context.strip()) == 0
                
                # Log data context for validation
                logger.info(f"📊 Data context length: {len(data_context)} chars")
                logger.info(f"📊 Data context preview: {data_context[:500]}...")
                logger.info(f"📊 Has no data marker: {'NO_DATA_FOUND' in data_context if data_context else 'N/A'}")
                
                if data_context and not has_no_data:
                    available_chars, effective_ctx = compute_llm_forensic_char_budget(messages, query)
                    logger.info(
                        "📊 Forensic char budget: %s (effective_ctx=%s, LLM_MAX_FORENSIC_CHARS=%s)",
                        available_chars,
                        effective_ctx,
                        LLM_MAX_FORENSIC_CHARS,
                    )
                    if len(data_context) > available_chars:
                        logger.warning(
                            "⚠️ Truncating forensic data from %s to %s characters",
                            len(data_context),
                            available_chars,
                        )
                        data_context = truncate_forensic_text_to_budget(data_context, available_chars)
                    else:
                        logger.info(
                            "✅ Data fits within budget: %s characters (budget=%s)",
                            len(data_context),
                            available_chars,
                        )
                    
                    # Check if this is an extraction query (user wants to pull/display messages)
                    is_extraction_query = classification.get('type') == 'extraction'
                    platform = classification.get('platform', '')
                    
                # Let LLM handle all queries naturally, with optional strict pull-messages format
                followup_base_block = ""
                selected_base = FOLLOWUP_BASE_CONTEXT.get(session_id)
                if selected_base and selected_base.get("content"):
                    # Avoid pasting the same assistant summary again after FORENSIC DATA: duplicating the chat-only
                    # bubble at the end causes models to ignore SUPPLEMENTARY blocks (recency bias). Metadata-only when
                    # SNAPSHOT or supplementary rows are already embedded above.
                    _dc_has_snap = data_context and "DETERMINISTIC FORENSIC SNAPSHOT" in data_context
                    _dc_has_sup = data_context and "SUPPLEMENTARY DETERMINISTIC FORENSIC DATA" in data_context
                    if (
                        locals().get("followup_mode_active")
                        and data_context
                        and (_dc_has_snap or _dc_has_sup)
                    ):
                        followup_base_block = f"""

FOLLOW-UP ANCHOR (metadata only; full base + snapshot/supplementary are in FORENSIC DATA above — do not ignore supplementary rows):
- Base Message ID: {selected_base.get('message_id', '')}
- Base Timestamp: {selected_base.get('timestamp', '')}
"""
                    else:
                        followup_base_block = f"""

FOLLOW-UP BASE MESSAGE (authoritative context selected by user):
- Base Message ID: {selected_base.get('message_id', '')}
- Base Timestamp: {selected_base.get('timestamp', '')}
- Base Content:
{selected_base.get('content', '')}
"""
                followup_mode_instructions_block = ""
                if 'followup_mode_active' in locals() and followup_mode_active:
                    _snap_here = data_context and (
                        "DETERMINISTIC FORENSIC SNAPSHOT" in data_context
                        or "UNIFIED_TIMELINE" in data_context
                    )
                    _sup_here = data_context and "SUPPLEMENTARY DETERMINISTIC FORENSIC DATA" in data_context
                    followup_mode_instructions_block = """

FOLLOW-UP MODE IS ACTIVE:
- Ground answers in the evidence blocks in this prompt: selected **base** summary, optional **DETERMINISTIC FORENSIC SNAPSHOT** (same turn as the base), and any **SUPPLEMENTARY DETERMINISTIC FORENSIC DATA** (case DB rows retrieved for this follow-up when you asked for a different domain, e.g. locations while the base was messages).
- Do not invent rows, counts, or identifiers that are not present in those blocks.
- If the user asks for locations/calls/etc. and the supplementary block shows none for that scope, say clearly that no matching records were returned (do not infer from chat text alone).
- You MAY interpret, compare, and summarize across blocks when the facts support it (including cautious cross-domain notes).
- Do NOT paste the entire base back; quote only what you need. Keep any recap minimal.
- If evidence is insufficient, say what is missing and which scope (date/platform/domain) would need to be queried.
"""
                    if _snap_here:
                        followup_mode_instructions_block += (
                            "- **Line-level detail**: Prefer concrete lines from the DETERMINISTIC FORENSIC SNAPSHOT when present "
                            "(timestamps + channel/direction).\n"
                        )
                    if _sup_here:
                        followup_mode_instructions_block += (
                            "- **Cross-domain follow-up**: The supplementary block is authoritative for that domain on this turn; "
                            "do not answer location questions using only chat bubbles unless the supplementary block is empty.\n"
                        )
                    if _sup_here and _followup_supplementary_has_data_rows(data_context or ""):
                        followup_mode_instructions_block += (
                            "\nCRITICAL (NON-NEGOTIABLE): The **SUPPLEMENTARY DETERMINISTIC** section in FORENSIC DATA "
                            "contains timestamped row bullets. Your **Direct Answer / Core Finding** MUST reflect that evidence "
                            "(state approximate row count or \"multiple\", time span, and sources/apps such as WhatsApp, Telegram). "
                            "You MUST NOT claim \"no locations\", \"no records\", \"none in supplementary data\", or zero rows "
                            "when those bullets are present. If you reference the chat summary, explicitly separate it from "
                            "GPS/location rows (different artifact).\n"
                        )
                    prompt_query = user_query_original or query
                    user_message = f"""{question_header}:
{prompt_query}

FORENSIC DATA (Use this data to answer the question):
{data_context}
{pull_messages_format_instructions}
{followup_base_block}{followup_mode_instructions_block}

{EVIDENCE_CONTRACT_TEXT}"""
                elif has_no_data:
                    prompt_query = user_query_original or query
                    user_message = f"""{question_header}:
{prompt_query}

FORENSIC DATA: NO_DATA_FOUND - No relevant data found for this query.

{EVIDENCE_CONTRACT_TEXT}"""
                else:
                    prompt_query = user_query_original or query
                    user_message = f"""{question_header}:
{prompt_query}

FORENSIC DATA:
{data_context if data_context else 'No relevant data found for this query.'}

{EVIDENCE_CONTRACT_TEXT}"""
                messages.append({
                    "role": "user",
                    "content": user_message
                })
                if debug_llm_context:
                    # Exact text the model receives in the last user turn (includes QUESTION + FORENSIC DATA after truncation)
                    stream_llm_evidence = messages[-1].get("content") or ""
                
                # CRITICAL: Verify query is in the messages
                logger.info(f"🔍 QUERY VERIFICATION:")
                logger.info(f"   - Original query: {repr(query[:100])}")
                logger.info(f"   - Query in last message: {repr(messages[-1]['content'][:100])}")
                logger.info(f"   - Query found in last message: {'QUESTION:' in messages[-1]['content'] or query[:50] in messages[-1]['content']}")
                logger.info(f"   - Total messages: {len(messages)}")
                logger.info(f"   - Last message role: {messages[-1]['role']}")
                logger.info(f"   - Last message starts with: {repr(messages[-1]['content'][:50])}")
                
                # Estimate total token count (rough: 1 token ≈ 1.67 characters)
                total_chars = sum(len(msg.get('content', '')) for msg in messages)
                estimated_tokens = int(total_chars / 1.67)
                
                # Warn if prompt might exceed context limits
                if estimated_tokens > int(LLM_CONTEXT_LENGTH * 0.9):
                    logger.warning(f"⚠️ Large prompt detected: ~{estimated_tokens} tokens ({total_chars} chars)")
                    logger.warning(f"   - This may exceed models with {LLM_CONTEXT_LENGTH} token context limits")
                    logger.warning(f"   - Consider increasing model context length in LM Studio to {LLM_CONTEXT_LENGTH * 2}+ tokens")
                
                # Tell client to open streaming UI (single start — duplicate start caused double cursors)
                start_data = sse_json({
                    'type': 'start',
                    'message': 'Routing query and building forensic context…',
                })
                try:
                    yield f"data: {start_data}{sse_end}"
                except GeneratorExit:
                    logger.info("🛑 Client disconnected while sending start signal")
                    raise

                pipe_build = sse_json({
                    'type': 'pipeline',
                    'message': f"Sending request to {_provider_display_name(llm_provider_used)}…",
                })
                try:
                    yield f"data: {pipe_build}{sse_end}"
                except GeneratorExit:
                    raise
                
                # Make provider-aware streaming request
                llm_start = time.time()
                llm_url = resolve_effective_llm_url(llm_provider_used)
                logger.info(
                    "📤 Sending request: provider=%s url=%s model=%s messages=%s",
                    llm_provider_used,
                    llm_url,
                    llm_model_used,
                    len(messages),
                )
                logger.info(f"📤 System message length: {len(messages[0]['content'])} characters")
                logger.info(f"📤 User message (last) length: {len(messages[-1]['content'])} characters")
                logger.info(f"📤 Total prompt: {total_chars} characters (~{estimated_tokens} tokens)")
                logger.info(f"📤 User query in message: {repr(query[:100])}")
                logger.debug(f"📤 First message preview: {messages[0]['content'][:200]}...")
                logger.debug(f"📤 Last message preview: {messages[-1]['content'][:500]}...")
                
                # DIAGNOSTIC: Verify data is in the prompt
                last_message_content = messages[-1]['content']
                if 'FORENSIC DATA' in last_message_content or 'FORENSIC DATA (JSON FORMAT)' in last_message_content:
                    data_section_start = last_message_content.find('FORENSIC DATA')
                    if data_section_start != -1:
                        data_section = last_message_content[data_section_start:data_section_start+500]
                        logger.info(f"✅ Data section found in prompt (starts at position {data_section_start})")
                        logger.debug(f"📊 Data section preview: {data_section}")
                        # Check if data section has actual content (more lenient check)
                        # The data might be formatted differently, so check for various indicators
                        has_json_indicators = ('{' in data_section or '[' in data_section or 
                                              '"contacts"' in data_section or '"messages"' in data_section or
                                              '"call_logs"' in data_section or len(data_section) > 200)
                        if not has_json_indicators:
                            logger.warning(f"⚠️ Data section preview may be malformed (first 500 chars), but full data context is {len(data_context)} chars")
                        else:
                            logger.debug(f"✅ Data section preview looks valid")
                    else:
                        logger.error(f"❌ ERROR: 'FORENSIC DATA' marker not found in prompt!")
                else:
                    logger.error(f"❌ ERROR: 'FORENSIC DATA' section not found in prompt! LLM will not receive data!")
                
                # Check if data_context was actually included
                if data_context and data_context.strip():
                    if data_context in last_message_content:
                        logger.info(f"✅ Verified: data_context is included in prompt ({len(data_context)} chars)")
                    else:
                        logger.error(f"❌ ERROR: data_context is NOT in the prompt! This is a critical bug!")
                else:
                    logger.error(f"❌ ERROR: data_context is empty! LLM cannot access any data!")
                
                # Prepare request payload (speed vs length: LLM_MAX_OUTPUT_TOKENS, LLM_TEMPERATURE)
                request_payload = {
                    "model": llm_model_used,
                    "messages": messages,
                    "temperature": LLM_TEMPERATURE,
                    "max_tokens": LLM_MAX_OUTPUT_TOKENS,
                    "stream": True,
                }
                
                logger.info(
                    "📤 Request: model=%s, messages=%s, user_chars=%s, max_tokens=%s, temperature=%s",
                    llm_model_used,
                    len(messages),
                    len(messages[-1].get("content", "")),
                    LLM_MAX_OUTPUT_TOKENS,
                    LLM_TEMPERATURE,
                )
                
                resp = llm_request(llm_provider_used, request_payload, stream=True, timeout=90)
                
                logger.info(
                    "📥 Provider response status: provider=%s status=%s",
                    llm_provider_used,
                    resp.status_code,
                )
                
                if not resp.ok:
                    error_msg = resp.text[:500] if resp.text else "No error message"
                    provider_name = _provider_display_name(llm_provider_used)
                    or_hint = _openrouter_client_error_hint(llm_provider_used, resp.status_code, error_msg)
                    logger.error(f"❌ {provider_name} API error: HTTP {resp.status_code}, Response: {error_msg}")
                    error_data = sse_json({
                        'type': 'error',
                        'message': f'{provider_name} API error: HTTP {resp.status_code}',
                        'response': f'❌ **API ERROR**\n\n{provider_name} returned HTTP {resp.status_code}.\n\nError: {error_msg}{or_hint}',
                    })
                    try:
                        yield f"data: {error_data}{sse_end}"
                    except GeneratorExit:
                        logger.info("🛑 Client disconnected while sending API error")
                        raise
                    return

                pipe_wait = sse_json({
                    'type': 'pipeline',
                    'message': 'Connected — waiting for model output…',
                })
                try:
                    yield f"data: {pipe_wait}{sse_end}"
                except GeneratorExit:
                    logger.info("🛑 Client disconnected before token stream")
                    raise
                
                # Stream tokens from LM Studio
                full_response = ""
                buffer = ""
                chunk_count = 0
                content_chunks_received = 0
                non_data_lines = 0
                client_disconnected = False
                
                logger.info(f"🔄 Starting to stream response from LM Studio...")
                logger.info(f"📊 Response headers: {dict(resp.headers)}")
                logger.info(f"📊 Response encoding: {resp.encoding}")
                
                try:
                    # Use iter_lines with decode_unicode=True and chunk_size for better control
                    # Note: iter_lines() will block until data arrives, which might take time with large prompts
                    logger.info(f"📥 Starting to iterate over response lines (this may take time with large prompts)...")
                    line_iterator = resp.iter_lines(decode_unicode=True, chunk_size=8192)
                    first_line_received = False
                    iterator_start_time = time.time()
                    max_wait_time = 180  # Maximum 3 minutes to wait for first line (increased for large prompts)
                    last_log_time = iterator_start_time
                    
                    for line in line_iterator:
                        # Check if we've been waiting too long for the first line
                        if not first_line_received:
                            elapsed = time.time() - iterator_start_time
                            # Log progress every 15 seconds while waiting
                            if elapsed - last_log_time >= 15:
                                logger.info(f"⏳ Still waiting for first line from LM Studio... ({elapsed:.0f}s elapsed)")
                                last_log_time = time.time()
                                # Send heartbeat to client so they know we're still processing
                                heartbeat_data = sse_json({
                                    'type': 'heartbeat', 
                                    'message': f'Processing... ({elapsed:.0f}s elapsed)'
                                })
                                try:
                                    yield f"data: {heartbeat_data}{sse_end}"
                                except GeneratorExit:
                                    logger.info("🛑 Client disconnected during wait")
                                    raise
                            
                            if elapsed > max_wait_time:
                                logger.error(f"❌ Timeout: No data received from LM Studio stream after {elapsed:.1f} seconds")
                                error_data = sse_json({
                                    'type': 'error', 
                                    'message': 'Stream timeout - no data received', 
                                    'response': f'⏱️ **STREAM TIMEOUT**\n\nLM Studio did not start streaming after {max_wait_time} seconds.\n\n**This query is very large** (analyzing all messages from all platforms).\n\n**Possible causes:**\n1. Very large prompt taking too long to process\n2. LM Studio is overloaded or frozen\n3. Model needs more time to generate response\n\n**Try:**\n1. Use a more specific query (e.g., "analyze messages from Telegram")\n2. Check LM Studio logs for errors\n3. Restart LM Studio\n4. Query individual platforms instead of all at once'
                                })
                                try:
                                    yield f"data: {error_data}{sse_end}"
                                except GeneratorExit:
                                    logger.info("🛑 Client disconnected while sending timeout error")
                                    raise
                                return
                        # Check if client has disconnected (Flask raises GeneratorExit when client disconnects)
                        try:
                            # Try to check if request is still active
                            if not request.environ.get('wsgi.input'):
                                client_disconnected = True
                                logger.info("🛑 Client disconnected detected (request.environ check)")
                                break
                        except:
                            pass  # Ignore errors in disconnection check
                        
                        if line:
                            # Line is already decoded if decode_unicode=True
                            if isinstance(line, bytes):
                                line = line.decode('utf-8')
                            
                            if not first_line_received:
                                first_line_received = True
                                logger.info(f"✅ First line received from LM Studio stream after {chunk_count} iterations")
                            
                            chunk_count += 1
                            
                            # Log first few lines for debugging
                            if chunk_count <= 10:  # Increased from 5 to 10 for better debugging
                                logger.info(f"📥 Stream line {chunk_count}: {line[:300]}")
                            
                            # LM Studio uses Server-Sent Events format
                            if line.startswith('data: '):
                                try:
                                    data_str = line[6:]  # Remove 'data: ' prefix
                                    if data_str.strip() == '[DONE]':
                                        logger.info(f"✅ Received [DONE] signal after {chunk_count} chunks")
                                        break
                                    
                                    chunk_data = json_lib.loads(data_str)
                                    
                                    # Enhanced debugging for empty responses
                                    if chunk_count <= 5:
                                        logger.info(f"🔍 Chunk {chunk_count} structure: {sse_json(chunk_data, indent=2)[:500]}")
                                    
                                    # Check for error responses from LM Studio
                                    if 'error' in chunk_data:
                                        error_info = chunk_data.get('error', {})
                                        error_message = error_info.get('message', 'Unknown error from LM Studio')
                                        logger.error(f"❌ LM Studio returned an error: {error_message}")
                                        
                                        # Context / token errors from llama.cpp (n_ctx, n_keep, etc.)
                                        if (
                                            "context" in error_message.lower()
                                            or "token" in error_message.lower()
                                            or "n_ctx" in error_message.lower()
                                            or str(LLM_CONTEXT_LENGTH) in error_message
                                        ):
                                            _uc = messages[-1].get("content", "") if messages else ""
                                            error_msg = llm_context_overflow_user_message(
                                                error_message,
                                                int(len(_uc) / 1.67),
                                                len(_uc),
                                            )
                                        else:
                                            error_msg = f"""⚠️ **LM STUDIO ERROR**

The LLM server returned an error:

**Error:** {error_message}

**Troubleshooting:**
1. Check if LM Studio is running and the model is loaded
2. Verify the model is compatible with the API
3. Check LM Studio logs for more details
4. Try restarting LM Studio server"""
                                        
                                        error_data = sse_json({'type': 'error', 'message': 'LM Studio error', 'response': error_msg})
                                        try:
                                            yield f"data: {error_data}{sse_end}"
                                        except GeneratorExit:
                                            client_disconnected = True
                                            logger.info("🛑 Client disconnected while sending error")
                                            raise
                                        return
                                    
                                    choices = chunk_data.get('choices', [])
                                    
                                    if not choices:
                                        logger.warning(f"⚠️ No choices in chunk {chunk_count}, chunk_data keys: {list(chunk_data.keys())}, full chunk: {sse_json(chunk_data)[:200]}")
                                        continue
                                    
                                    delta = choices[0].get('delta', {})
                                    
                                    # Enhanced debugging for delta structure
                                    if chunk_count <= 5:
                                        logger.info(f"🔍 Chunk {chunk_count} delta keys: {list(delta.keys())}, delta content: {repr(delta.get('content', ''))[:100]}")
                                    
                                    content = delta.get('content', '')
                                    
                                    # Check for role in delta (some models send role first)
                                    if 'role' in delta and not content:
                                        logger.debug(f"📝 Chunk {chunk_count} contains role: {delta.get('role')}, no content yet")
                                    
                                    if content:
                                        content_chunks_received += 1
                                        full_response += content
                                        
                                        # Send token to client - catch GeneratorExit if client disconnected
                                        token_data = sse_json({'type': 'token', 'content': content})
                                        try:
                                            yield f"data: {token_data}{sse_end}"
                                        except GeneratorExit:
                                            client_disconnected = True
                                            logger.info(f"🛑 Client disconnected during streaming (chunk {chunk_count})")
                                            raise
                                    
                                    # Check if this is the final chunk
                                    finish_reason = choices[0].get('finish_reason')
                                    if finish_reason:
                                        logger.info(f"✅ Stream finished with reason: {finish_reason} after {chunk_count} chunks, {content_chunks_received} content chunks")
                                        if finish_reason != 'stop' and finish_reason != 'length':
                                            logger.warning(f"⚠️ Unusual finish_reason: {finish_reason}")
                                        break
                                except json_lib.JSONDecodeError as e:
                                    logger.warning(f"⚠️ Failed to parse SSE chunk {chunk_count}: {e}, line: {line[:100]}")
                                    continue
                                except GeneratorExit:
                                    client_disconnected = True
                                    logger.info(f"🛑 Client disconnected during chunk processing (chunk {chunk_count})")
                                    raise
                                except Exception as e:
                                    logger.error(f"❌ Error processing stream chunk {chunk_count}: {e}", exc_info=True)
                                    continue
                            else:
                                non_data_lines += 1
                                if non_data_lines <= 3:
                                    logger.debug(f"📥 Non-data line {non_data_lines}: {line[:100]}")
                except requests.exceptions.Timeout as e:
                    logger.error(f"❌ Timeout waiting for LM Studio stream: {e}")
                    error_data = sse_json({
                        'type': 'error', 
                        'message': 'Stream timeout', 
                        'response': '⏱️ **STREAM TIMEOUT**\n\nThe LLM response is taking too long to start streaming. This may happen with very large prompts.\n\n**Try:**\n1. Use a more specific query\n2. Check if LM Studio is processing the request\n3. Restart LM Studio if needed'
                    })
                    try:
                        yield f"data: {error_data}{sse_end}"
                    except GeneratorExit:
                        logger.info("🛑 Client disconnected while sending timeout error")
                        raise
                    return
                except requests.exceptions.ChunkedEncodingError as e:
                    logger.error(f"❌ Chunked encoding error in stream: {e}")
                    error_data = sse_json({
                        'type': 'error', 
                        'message': 'Stream encoding error', 
                        'response': '❌ **STREAM ERROR**\n\nThere was an error reading the streaming response from LM Studio.\n\n**Possible causes:**\n1. LM Studio connection interrupted\n2. Network issue\n3. LM Studio server error\n\n**Try:**\n1. Check LM Studio logs\n2. Restart LM Studio\n3. Try the query again'
                    })
                    try:
                        yield f"data: {error_data}{sse_end}"
                    except GeneratorExit:
                        logger.info("🛑 Client disconnected while sending encoding error")
                        raise
                    return
                except GeneratorExit:
                    # Client disconnected - clean up and exit
                    client_disconnected = True
                    logger.info("🛑 Client disconnected - stopping stream")
                    try:
                        resp.close()  # Close the LM Studio connection
                    except:
                        pass
                    raise  # Re-raise to properly handle disconnection
                except Exception as e:
                    # Other errors during streaming
                    if not client_disconnected:
                        logger.error(f"❌ Error during streaming: {e}", exc_info=True)
                
                # If client disconnected, don't process further
                if client_disconnected:
                    logger.info(f"🛑 Stream stopped by client after {chunk_count} chunks, {content_chunks_received} content chunks")
                    try:
                        resp.close()  # Ensure connection is closed
                    except:
                        pass
                    return  # Exit generator early
                
                llm_time = time.time() - llm_start
                logger.info(f"📊 Stream complete: {len(full_response)} characters received, {content_chunks_received} content chunks, {chunk_count} total chunks, {non_data_lines} non-data lines, {llm_time:.2f}s elapsed")
                
                # Check if response is empty
                if not full_response or len(full_response.strip()) == 0:
                    logger.error(f"❌ CRITICAL: Empty response received from LLM!")
                    logger.error(f"   - Total chunks processed: {chunk_count}")
                    logger.error(f"   - Content chunks received: {content_chunks_received}")
                    logger.error(f"   - Non-data lines: {non_data_lines}")
                    logger.error(f"   - Response time: {llm_time:.2f}s")
                    logger.error(f"   - Prompt length: {len(messages[-1]['content'])} characters")
                    logger.error(f"   - This suggests LM Studio is not generating content or stream format is incorrect")

                    # Auto-retry once (silent to user except pipeline hint) to mask transient LM Studio stalls.
                    logger.info("🔁 Empty stream detected; attempting one automatic retry (non-stream)")
                    retry_pipe = sse_json({
                        'type': 'pipeline',
                        'message': 'No content received from model; retrying once automatically…',
                    })
                    try:
                        yield f"data: {retry_pipe}{sse_end}"
                    except GeneratorExit:
                        logger.info("🛑 Client disconnected while sending retry status")
                        raise

                    retry_content = ""
                    retry_error = None
                    try:
                        retry_payload = dict(request_payload)
                        retry_payload["stream"] = False
                        retry_resp = llm_request(
                            llm_provider_used,
                            retry_payload,
                            stream=False,
                            timeout=90,
                        )
                        if retry_resp.ok:
                            retry_json = retry_resp.json() if retry_resp.content else {}
                            retry_choices = retry_json.get("choices", []) if isinstance(retry_json, dict) else []
                            if retry_choices and isinstance(retry_choices[0], dict):
                                retry_message = retry_choices[0].get("message", {}) or {}
                                retry_content = (retry_message.get("content", "") or "").strip()
                        else:
                            retry_error = f"HTTP {retry_resp.status_code}"
                    except Exception as retry_ex:
                        retry_error = str(retry_ex)
                        logger.warning("Automatic retry after empty stream failed: %s", retry_ex, exc_info=True)

                    if retry_content:
                        logger.info("✅ Automatic retry recovered %s characters", len(retry_content))
                        retry_content = repair_llm_mojibake(retry_content)
                        full_response = retry_content
                        content_chunks_received = max(content_chunks_received, 1)
                        retry_token_data = sse_json({'type': 'token', 'content': retry_content})
                        try:
                            yield f"data: {retry_token_data}{sse_end}"
                        except GeneratorExit:
                            logger.info("🛑 Client disconnected while sending retry content")
                            raise
                    else:
                        if retry_error:
                            logger.error("❌ Automatic retry returned no content (%s)", retry_error)
                        else:
                            logger.error("❌ Automatic retry returned no content")

                    # If still empty after retry, return error as before.
                    if not full_response or len(full_response.strip()) == 0:
                        # Send error message to client
                        error_msg = f"""⚠️ **EMPTY RESPONSE DETECTED**

The LLM did not generate any content. 

**Diagnostics:**
- Total chunks received: {chunk_count}
- Content chunks: {content_chunks_received}
- Non-data lines: {non_data_lines}
- Response time: {llm_time:.2f}s
- Prompt length: {len(messages[-1]['content'])} characters

**Possible causes:**
1. LM Studio model not responding properly
2. Prompt too long
3. Model configuration issue
4. Stream format mismatch

**Try:**
1. Check if LM Studio is running and model is loaded
2. Try a shorter query
3. Restart LM Studio server
4. Check LM Studio logs for errors"""

                        error_data = sse_json({'type': 'error', 'message': 'Empty response from LLM', 'response': error_msg})
                        try:
                            yield f"data: {error_data}{sse_end}"
                        except GeneratorExit:
                            logger.info("🛑 Client disconnected while sending empty response error")
                            raise
                        return

                full_response = repair_llm_mojibake(full_response)

                # Store in chat history
                # Note: datetime is already imported at module level (line 27)
                # User query was already added to CHAT_HISTORIES before sending to LLM
                # Now add the assistant response
                assistant_metadata = {}
                # Preserve raw forensic text for follow-up "examples" (same assistant message scope)
                if not locals().get("followup_mode_active", False) and data_context:
                    assistant_metadata["evidence_snapshot"] = (data_context or "")[:20000]
                if query_route:
                    assistant_metadata["route_primary"] = query_route.get("primary")
                    assistant_metadata["guarantee_class"] = query_route.get("guarantee_class")
                assistant_metadata["llm_used"] = True
                _persist_assistant_response(full_response, metadata=assistant_metadata)
                
                # NO LIMIT - Keep all chat history
                # Removed limit to allow full conversation context
                
                # Calculate confidence
                intent_strength = confidence_calculator.calculate_intent_strength(query, "llm_query")
                query_complexity = confidence_calculator.calculate_query_complexity(query)
                confidence = confidence_calculator.calculate_confidence(
                    retrieval_scores=[0.9],
                    intent_strength=intent_strength,
                    data_completeness=1.0,
                    query_complexity=query_complexity,
                    response_quality=0.95
                )
                
                # Prepare image citations for response
                image_citations_response = []
                for citation in image_citations:
                    image_citations_response.append({
                        "filename": citation.get("filename", ""),
                        "relative_path": citation.get("relative_path", ""),
                        "path": citation.get("path", ""),
                        "context": citation.get("context", ""),
                        "relevance_score": citation.get("relevance_score", 0)
                    })
                
                display_response = full_response

                # Post-hoc check: claimed facts (timestamps, phones, quoted text) vs evidence text sent to the model
                validation_ok = True
                validation_warnings = []
                try:
                    _evidence_for_validation = (
                        (messages[-1].get("content") or "") if messages else (data_context or "")
                    )
                    validation_ok, validation_warnings = validate_response(
                        full_response, _evidence_for_validation
                    )
                    log_validation_results(
                        full_response, _evidence_for_validation, validation_ok, validation_warnings
                    )
                except Exception as _val_err:
                    logger.debug(f"Response validation skipped: {_val_err}")
                
                # Persist to database (after confidence is calculated) - store original for audit
                persist_chat_message(session_id, "user", query)
                persist_chat_message(session_id, "assistant", full_response, metadata={
                    "llm_used": True,
                    "rag_used": False,
                    "confidence": confidence,
                    "response_time": calculate_response_time(),
                    "model_used": llm_model_used,
                    "provider_used": llm_provider_used,
                    "response_length": len(full_response)
                    })
                
                # Send completion message with metadata and image citations
                done_payload = {
                    'type': 'done',
                    'response': display_response,
                    'confidence': confidence,
                    'response_time': calculate_response_time(),
                    'llm_used': True,
                    'image_citations': image_citations_response,
                    'has_images': len(image_citations_response) > 0,
                    'response_length': len(display_response),
                    'guarantee_class': (query_route or {}).get('guarantee_class') if query_route else None,
                    'guarantee_reason': (query_route or {}).get('guarantee_reason') if query_route else None,
                    'route_primary': (query_route or {}).get('primary') if query_route else None,
                    'response_validation_ok': validation_ok,
                    'response_validation_warnings': [
                        (w[:220] + '…') if len(w) > 220 else w
                        for w in (validation_warnings or [])[:8]
                    ],
                    'provider_used': llm_provider_used,
                    'model_used': llm_model_used,
                }
                if feedback_route_meta:
                    done_payload['feedback_route_meta'] = feedback_route_meta
                if evidence_packet_meta:
                    done_payload['evidence_packet'] = evidence_packet_meta
                if debug_llm_context:
                    done_payload['debug_llm_context_ack'] = True
                    # Re-snapshot from `messages` so we always attach what was actually POSTed to LM Studio
                    try:
                        _last_user = next(
                            (m for m in reversed(messages) if m.get('role') == 'user'),
                            None,
                        )
                        if _last_user:
                            stream_llm_evidence = (_last_user.get('content') or '')
                    except Exception as _e:
                        logger.warning(f"debug_llm_context: could not re-read user message: {_e}")
                    _max_ev = 80000
                    _ev = stream_llm_evidence if stream_llm_evidence is not None else ''
                    done_payload['llm_evidence_text'] = _ev[:_max_ev]
                    done_payload['llm_evidence_truncated'] = len(_ev) > _max_ev
                    done_payload['llm_evidence_char_count'] = len(_ev)
                done_data = sse_json(done_payload)
                try:
                    yield f"data: {done_data}{sse_end}"
                    logger.info(f"✅ Stream completed successfully: {len(display_response)} characters, confidence: {confidence:.3f}")
                except GeneratorExit:
                    logger.info("🛑 Client disconnected while sending completion signal")
                    raise
                
            except requests.exceptions.Timeout:
                timeout_msg = (
                    f"⏱️ **TIMEOUT ERROR**\n\nThe request to {_provider_display_name(llm_provider_used)} "
                    "timed out after 90 seconds."
                )
                error_data = sse_json({'type': 'error', 'message': 'Request timed out', 'response': timeout_msg})
                try:
                    yield f"data: {error_data}{sse_end}"
                except GeneratorExit:
                    logger.info("🛑 Client disconnected while sending timeout error")
                    raise
            except requests.exceptions.ConnectionError:
                provider_name = _provider_display_name(llm_provider_used)
                conn_msg = f'🔌 **CONNECTION ERROR**\n\nCannot connect to {provider_name}.'
                error_data = sse_json({'type': 'error', 'message': f'Cannot connect to {provider_name}', 'response': conn_msg})
                try:
                    yield f"data: {error_data}{sse_end}"
                except GeneratorExit:
                    logger.info("🛑 Client disconnected while sending connection error")
                    raise
            except GeneratorExit:
                # Client disconnected - re-raise to handle properly
                logger.info("🛑 Client disconnected during error handling")
                raise
            except Exception as e:
                import traceback
                error_trace = traceback.format_exc()
                logger.error(f"Streaming error: {str(e)}\nFull traceback:\n{error_trace}")
                error_msg = f'❌ **ERROR**\n\nAn error occurred: {str(e)}'
                error_data = sse_json({'type': 'error', 'message': str(e), 'response': error_msg})
                try:
                    yield f"data: {error_data}{sse_end}"
                except GeneratorExit:
                    logger.info("🛑 Client disconnected while sending error message")
                    raise
                
        except GeneratorExit:
            # Client disconnected - re-raise to handle properly
            logger.info("🛑 Client disconnected - stream generation stopped")
            raise
        except Exception as e:
            logger.error(f"Stream generation error: {str(e)}")
            error_msg = f'Error in chat query: {str(e)}'
            error_data = sse_json({'type': 'error', 'message': str(e), 'response': error_msg})
            try:
                yield f"data: {error_data}{sse_end}"
            except GeneratorExit:
                logger.info("🛑 Client disconnected while sending final error")
                raise
    
    return Response(
        stream_with_context(generate_stream()),
        mimetype="text/event-stream; charset=utf-8",
    )

@app.route('/api/chat/data', methods=['POST'])
def get_chat_data_direct():
    """
    Direct chat data retrieval endpoint.
    Returns structured JSON with chats and messages.
    No LLM processing - pure data extraction.
    """
    try:
        data = request.get_json() or {}
        query = (data.get('query') or data.get('message') or '').strip()
        platform = data.get('platform')
        chat_id = data.get('chat_id')
        
        if not query and not platform and not chat_id:
            return jsonify({
                "status": "ERROR",
                "message": "No query, platform, or chat_id provided"
            }), 400
        
        # Get data layer
        global ACTIVE_DATA_LAYERS, ACTIVE_FILENAME
        data_layer = None
        
        if ACTIVE_FILENAME and ACTIVE_FILENAME in ACTIVE_DATA_LAYERS:
            data_layer = ACTIVE_DATA_LAYERS[ACTIVE_FILENAME]
        elif ACTIVE_DATA_LAYERS:
            # Use first available data layer
            data_layer = list(ACTIVE_DATA_LAYERS.values())[0]
        
        if not data_layer:
            return jsonify({
                "status": "ERROR",
                "message": "No forensic data loaded. Please upload a UFDR file first."
            }), 400
        
        # Extract platform from query if not provided
        if not platform and query:
            classification = classify_query(query)
            platform = classification.get('platform')
            if not chat_id:
                chat_id = classification.get('chat_id')
        
        # Get chat data
        chat_data = data_layer.get_chat_data_for_display(
            platform=platform,
            chat_id=chat_id,
            limit=100  # Get up to 100 messages per chat
        )
        
        # Log chat data for debugging
        if chat_data and chat_data.get('chats'):
            total_messages = sum(len(chat.get('messages', [])) for chat in chat_data['chats'])
            logger.info(f"📊 get_chat_data_direct: Platform='{platform}', Chats={len(chat_data['chats'])}, Total messages={total_messages}")
            for i, chat in enumerate(chat_data['chats']):
                msg_count = len(chat.get('messages', []))
                logger.info(f"  Chat {i+1}: '{chat.get('chat_name', 'Unknown')}' - {msg_count} messages (total_messages: {chat.get('total_messages', 0)})")
        else:
            logger.warning(f"⚠️ get_chat_data_direct: No chat data returned for platform='{platform}'")
        
        # Return data without chat-style formatting
        return jsonify({
            "status": "SUCCESS",
            "type": "direct_data",
            "data": chat_data
        })
        
    except Exception as e:
        logger.error(f"Error in get_chat_data_direct: {str(e)}", exc_info=True)
        return jsonify({
            "status": "ERROR",
            "message": str(e)
        }), 500

@app.route('/api/chat/analyze', methods=['POST'])
def analyze_chat_data():
    """
    LLM analysis endpoint.
    Takes chat data and returns insights:
    - Participant analysis
    - Conversation patterns
    - Timeline analysis
    - Suspicious activity detection
    - Metadata interpretation
    """
    import time
    start_time = time.time()
    
    def calculate_response_time():
        elapsed = time.time() - start_time
        return round(elapsed, 2)
    
    try:
        data = request.get_json() or {}
        chat_data = data.get('chat_data')
        query = (data.get('query') or data.get('message') or 'Analyze this conversation').strip()
        
        if not chat_data:
            return jsonify({
                "status": "ERROR",
                "message": "No chat_data provided"
            }), 400
        
        # Get data layer for LLM processing
        global ACTIVE_DATA_LAYERS, ACTIVE_FILENAME
        data_layer = None
        
        if ACTIVE_FILENAME and ACTIVE_FILENAME in ACTIVE_DATA_LAYERS:
            data_layer = ACTIVE_DATA_LAYERS[ACTIVE_FILENAME]
        elif ACTIVE_DATA_LAYERS:
            data_layer = list(ACTIVE_DATA_LAYERS.values())[0]
        
        if not data_layer:
            return jsonify({
                "status": "ERROR",
                "message": "No forensic data loaded"
            }), 400
        
        # Get insights structure
        insights_structure = data_layer.get_chat_insights(chat_data, query)
        
        # Format chat data for LLM context
        context_parts = []
        context_parts.append("=== CHAT DATA FOR ANALYSIS ===")
        context_parts.append(f"Platform: {chat_data.get('platform', 'Unknown')}")
        context_parts.append(f"Total Chats: {len(chat_data.get('chats', []))}")
        
        for chat in chat_data.get('chats', [])[:5]:  # Limit to first 5 chats for context
            context_parts.append(f"\n--- Chat: {chat.get('chat_name', 'Unknown')} ---")
            context_parts.append(f"Participants: {', '.join(chat.get('participants', []))}")
            context_parts.append(f"Start Time: {chat.get('start_time', 'N/A')}")
            context_parts.append(f"Last Activity: {chat.get('last_activity', 'N/A')}")
            context_parts.append(f"Total Messages: {chat.get('total_messages', 0)}")
            context_parts.append(f"Attachments: {chat.get('attachment_count', 0)}")
            context_parts.append(f"Location Data: {'Yes' if chat.get('has_location_data') else 'No'}")
            
            # Add sample messages
            messages = chat.get('messages', [])[:10]  # First 10 messages
            for msg in messages:
                msg_type = msg.get('message_type', 'unknown')
                from_part = msg.get('from_participant', 'Unknown')
                text = msg.get('text_content', '')
                timestamp = msg.get('timestamp', '')
                is_deleted = msg.get('is_deleted', False)
                deleted_marker = " [DELETED]" if is_deleted else ""
                
                if msg_type == 'text' and text:
                    context_parts.append(f"  [{timestamp}]{deleted_marker} {from_part}: {text[:200]}")
                elif msg_type == 'media':
                    att_count = len(msg.get('attachments', []))
                    context_parts.append(f"  [{timestamp}]{deleted_marker} {from_part}: [Media: {att_count} attachment(s)]")
                elif msg_type == 'location':
                    context_parts.append(f"  [{timestamp}]{deleted_marker} {from_part}: [Location Share]")
                elif msg_type == 'system':
                    context_parts.append(f"  [{timestamp}]{deleted_marker} [System]: {text[:200] if text else 'System notification'}")
        
        data_context = "\n".join(context_parts)
        
        # Process with LLM
        if USE_LLM and LLM_URL:
            try:
                system_prompt = """You are a forensic analyst. Analyze the provided chat data and provide insights about:
- Participants and their roles
- Conversation patterns and flow
- Timeline and chronology
- Suspicious or notable activity
- Key findings and observations

Be concise but thorough. Focus on actionable insights."""
                
                if len(data_context) > LLM_MAX_FORENSIC_CHARS:
                    data_context = truncate_forensic_text_to_budget(data_context, LLM_MAX_FORENSIC_CHARS)
                messages_for_llm = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"{query}\n\n{data_context}"},
                ]
                _sid = session.get("session_id")
                _prov = resolve_effective_llm_provider(session_id=_sid, request_data=data)
                _model = resolve_effective_llm_model(_prov)
                response = llm_request(
                    _prov,
                    {
                        "model": _model,
                        "messages": messages_for_llm,
                        "temperature": LLM_TEMPERATURE,
                        "max_tokens": LLM_MAX_OUTPUT_TOKENS,
                    },
                    stream=False,
                    timeout=60,
                )
                
                if response.status_code == 200:
                    llm_response = response.json()
                    insights_text = repair_llm_mojibake(
                        llm_response['choices'][0]['message']['content'] or ""
                    )
                    
                    return jsonify({
                        "status": "SUCCESS",
                        "type": "analysis",
                        "insights": insights_text,
                        "response_time": calculate_response_time()
                    })
                else:
                    logger.error(f"LLM API error: {response.status_code} - {response.text}")
                    return jsonify({
                        "status": "ERROR",
                        "message": f"LLM API error: {response.status_code}"
                    }), 500
                    
            except Exception as e:
                logger.error(f"Error calling LLM: {str(e)}", exc_info=True)
                return jsonify({
                    "status": "ERROR",
                    "message": f"LLM processing failed: {str(e)}"
                }), 500
        else:
            # Fallback: return structured insights without LLM
            return jsonify({
                "status": "SUCCESS",
                "type": "analysis",
                "insights": "LLM not available. Please enable LLM for detailed analysis.",
                "insights_structure": insights_structure,
                "response_time": calculate_response_time()
            })
            
    except Exception as e:
        logger.error(f"Error in analyze_chat_data: {str(e)}", exc_info=True)
        return jsonify({
            "status": "ERROR",
            "message": str(e)
        }), 500

@app.route('/api/chat', methods=['POST'])
def chat_query():
    """Forensic AI Chat Assistant - Conversational Investigator."""
    import time
    start_time = time.time()
    
    # Declare globals at the top of the function
    global ACTIVE_DATA_LAYERS, ACTIVE_FILENAME
    
    def calculate_response_time():
        """Calculate and format response time."""
        elapsed = time.time() - start_time
        return round(elapsed, 2)
    
    try:
        data = request.get_json() or {}
        query = (data.get('query') or data.get('message') or '')
        # Ensure query is a string and not None
        if query is None:
            query = ''
        if not isinstance(query, str):
            query = str(query) if query else ''
        query = query.strip()
        use_json_extraction = data.get('use_json', False)  # New option: let LLM extract from JSON
        
        # CRITICAL: Rewrite vague questions to prevent hallucination
        original_query = query
        query = rewrite_vague_query(query)
        if query != original_query:
            logger.info(f"✅ Query rewritten: '{original_query}' → '{query}'")
        
        if not query:
            return jsonify({
                "status": "ERROR",
                "message": "No query provided",
                "response": "I need a question to investigate. What would you like me to analyze?",
                "confidence": 0.0,
                "response_time": calculate_response_time()
            })
        
        # Classify query to determine routing
        classification = classify_query(query)
        logger.info(f"🔍 Query classification: {classification}")
        
        # Route extraction queries to direct data endpoint
        if classification['type'] == 'extraction' and classification['needs_direct_data']:
            try:
                # Get data layer (globals already declared at top of function)
                data_layer = None
                if ACTIVE_FILENAME and ACTIVE_FILENAME in ACTIVE_DATA_LAYERS:
                    data_layer = ACTIVE_DATA_LAYERS[ACTIVE_FILENAME]
                elif ACTIVE_DATA_LAYERS:
                    data_layer = list(ACTIVE_DATA_LAYERS.values())[0]
                
                if data_layer:
                    # Get chat data directly
                    chat_data = data_layer.get_chat_data_for_display(
                        platform=classification.get('platform'),
                        chat_id=classification.get('chat_id'),
                        limit=100
                    )
                    
                    # Return as direct data response
                    return jsonify({
                        "status": "SUCCESS",
                        "type": "direct_data",
                        "data": chat_data,
                        "classification": classification,
                        "response_time": calculate_response_time()
                    })
                else:
                    logger.warning("No data layer available for extraction query")
            except Exception as e:
                logger.error(f"Error in direct data extraction: {str(e)}", exc_info=True)
                # Fall through to LLM processing as fallback
        
        # Route hybrid queries (get data + analysis)
        elif classification['type'] == 'hybrid':
            try:
                # Get data layer
                data_layer = None
                if ACTIVE_FILENAME and ACTIVE_FILENAME in ACTIVE_DATA_LAYERS:
                    data_layer = ACTIVE_DATA_LAYERS[ACTIVE_FILENAME]
                elif ACTIVE_DATA_LAYERS:
                    data_layer = list(ACTIVE_DATA_LAYERS.values())[0]
                
                if data_layer:
                    # Get chat data
                    chat_data = data_layer.get_chat_data_for_display(
                        platform=classification.get('platform'),
                        chat_id=classification.get('chat_id'),
                        limit=100
                    )
                    
                    # Return data with note that analysis should be requested separately
                    return jsonify({
                        "status": "SUCCESS",
                        "type": "hybrid_data",
                        "data": chat_data,
                        "classification": classification,
                        "message": "Data retrieved. Use /api/chat/analyze endpoint for LLM analysis.",
                        "response_time": calculate_response_time()
                    })
                else:
                    logger.warning("No data layer available for hybrid query")
            except Exception as e:
                logger.error(f"Error in hybrid query processing: {str(e)}", exc_info=True)
                # Fall through to LLM processing
        
        data_src = get_current_data()
        
        # Check if we have a data access layer (fast Cellebrite parser or XML parser)
        data_layer = None
        
        # Try to get data layer from ACTIVE_FILENAME first
        if ACTIVE_FILENAME and ACTIVE_FILENAME in ACTIVE_DATA_LAYERS:
            data_layer = ACTIVE_DATA_LAYERS[ACTIVE_FILENAME]
            logger.info(f"Using fast data access layer for {ACTIVE_FILENAME}")
        # If no ACTIVE_FILENAME but we have XML data layers, use the first one
        elif ACTIVE_DATA_LAYERS:
            # Get the first available data layer (for XML files)
            first_filename = list(ACTIVE_DATA_LAYERS.keys())[0]
            data_layer = ACTIVE_DATA_LAYERS[first_filename]
            ACTIVE_FILENAME = first_filename  # Set it as active
            logger.info(f"Using XML data access layer for {first_filename}")
        
        # Check if query is asking for comprehensive person analysis
        query_lower = query.lower() if query else ""
        is_person_query = _is_person_investigation_query(query_lower)
        
        # Extract person name from query
        person_name = None
        if is_person_query and data_layer:
            person_name = _extract_person_name_from_investigation_query(query)
            if person_name:
                logger.info(f"✅ Extracted person name from query: '{person_name}'")
        
        # Use comprehensive analysis if person name found
        if person_name and data_layer:
            try:
                logger.info(f"🔍 Comprehensive analysis triggered for: '{person_name}'")
                communications = data_layer.get_all_communications_for_person(person_name, limit=1000)
                total_found = (communications['summary']['total_chats'] + 
                              communications['summary']['total_messages'] + 
                              communications['summary']['total_calls'])
                logger.info(f"📊 Found: {communications['summary']['total_chats']} chats, {communications['summary']['total_messages']} messages, {communications['summary']['total_calls']} calls")
                
                # Only use comprehensive analysis if we found data, otherwise fall through to regular query
                if total_found > 0:
                    formatted_analysis = data_layer.format_comprehensive_analysis(person_name, communications)
                    
                    # Store in chat history
                    if session_id not in CHAT_HISTORIES:
                        CHAT_HISTORIES[session_id] = []
                    CHAT_HISTORIES[session_id].append({"role": "user", "content": query})
                    CHAT_HISTORIES[session_id].append({"role": "assistant", "content": formatted_analysis})
                    persist_chat_message(session_id, "user", query)
                    persist_chat_message(session_id, "assistant", formatted_analysis)
                    
                    return jsonify({
                        "status": "SUCCESS",
                        "query": query,
                        "response": formatted_analysis,
                        "confidence": 1.0,
                        "llm_used": False,
                        "comprehensive_analysis": True,
                        "summary": communications.get('summary', {}),
                        "response_time": calculate_response_time()
                    })
                else:
                    logger.warning(f"⚠️ Comprehensive analysis found no data for '{person_name}', falling through to regular query")
            except Exception as e:
                logger.error(f"Error in comprehensive person analysis: {e}", exc_info=True)
                # Fall through to normal processing
        
        # Check if we have data (either ACTIVE_DATA or XML data layers)
        has_data = bool(data_src and data_src.get('_xml_data_available') != True) or bool(data_layer)
        
        if not has_data:
            return jsonify({
                "status": "ERROR",
                "message": "Upload a UFDR JSON file first.",
                "response": "I need UFDR data to investigate. Please upload a forensic report first.",
                "confidence": 0.0,
                "response_time": calculate_response_time()
            })

        # If query is overly broad, return refinement suggestions instead of a generic LLM answer
        # Broad query detection removed per user request
        
        # Initialize session if needed
        if 'session_id' not in session:
            import uuid
            session['session_id'] = str(uuid.uuid4())
        session_id = session['session_id']
        
        # Initialize chat history if needed
        if session_id not in CHAT_HISTORIES:
            CHAT_HISTORIES[session_id] = []
        
        # Save user query to history BEFORE sending to LLM (for proper follow-up context)
        CHAT_HISTORIES[session_id].append({
            "role": "user",
            "content": query,
            "timestamp": datetime.now().isoformat()
        })
        
        # Check if query needs Qwen2.5-VL (images/videos)
        use_qwen_vl = False
        if USE_QWEN_VL and has_images_or_videos(data_src) and query:
            # Check if query is image/video related
            query_lower = query.lower() if query else ""
            image_keywords = ['image', 'photo', 'picture', 'screenshot', 'visual', 'see', 'show', 'what', 'describe']
            video_keywords = ['video', 'footage', 'recording', 'clip', 'movie']
            
            if query_lower and any(kw in query_lower for kw in image_keywords + video_keywords):
                use_qwen_vl = True
                logger.info("Using Qwen2.5-VL-7B for multimodal analysis")
        
        # Try Qwen2.5-VL first if needed
        if use_qwen_vl:
            # Chat history disabled for forensic queries to prevent hallucinations
            response, error = process_with_qwen_vl(query, data_src, chat_history=None)
            if response:
                response = repair_llm_mojibake(response)
                # Store in chat history
                if session_id not in CHAT_HISTORIES:
                    CHAT_HISTORIES[session_id] = []
                CHAT_HISTORIES[session_id].append({"role": "user", "content": query})
                CHAT_HISTORIES[session_id].append({"role": "assistant", "content": response})
                
                # Persist to database
                persist_chat_message(session_id, "user", query)
                persist_chat_message(session_id, "assistant", response, metadata={
                    "llm_used": True,
                    "rag_used": False,  # RAG not used in non-streaming endpoint
                    "confidence": 0.9,  # Default confidence
                    "response_time": calculate_response_time(),
                    "model_used": LLM_MODEL
                })
                
                return jsonify({
                    "status": "SUCCESS",
                    "response": response,
                    "confidence": 0.9,
                    "response_time": calculate_response_time(),
                    "model_used": "Qwen2.5-VL-7B",
                    "multimodal": True
                })
            elif error:
                logger.warning(f"Qwen2.5-VL processing failed: {error}, falling back to LLM")
        
        # All queries now go through LLM processing - no hardcoded responses

        # Always try LLM first for better conversational responses
        logger.debug(f"USE_LLM = {USE_LLM} (type: {type(USE_LLM)})")
        if USE_LLM:
            logger.info("LLM integration enabled, processing with AI Chat Assistant")
            llm_provider_used = resolve_effective_llm_provider(
                session_id=session.get('session_id'),
                request_data=data,
            )
            llm_model_used = resolve_effective_llm_model(llm_provider_used)
            session['llm_provider'] = llm_provider_used
            # Initialize session if needed for conversation memory (do this early)
            if 'session_id' not in session:
                import uuid
                session['session_id'] = str(uuid.uuid4())
                CHAT_HISTORIES[session['session_id']] = []
            
            session_id = session['session_id']
            
            try:
                provider_name = _provider_display_name(llm_provider_used)
                logger.info(f"Checking {provider_name} health...")
                ok, health_msg = llm_provider_health_check(llm_provider_used, timeout=5)
                if not ok:
                    logger.error(f"{provider_name} health check failed: {health_msg}")
                    raise Exception(health_msg)
                logger.info(f"{provider_name} health check passed")
                
                # Get chat history for this session
                chat_history = CHAT_HISTORIES.get(session_id, [])
                logger.debug(f"Chat history: {len(chat_history)} messages in session")
                
                # Get enhanced data context for LLM with actual details
                data_context = ""
                image_citations = []
                evidence_packet_meta_ns = None
                
                # PRIORITY: Use fast data access layer if available (better query-aware extraction)
                if data_layer:
                    logger.info(f"Using fast data access layer for query extraction")
                    try:
                        # Extract number from query if specified (e.g., "5 chats", "10 messages")
                        number_pattern = r'\b(\d+)\s+(?:chat|chats|message|messages|contact|contacts|call|calls)\b'
                        number_match = re.search(number_pattern, query.lower())
                        if number_match:
                            requested_number = int(number_match.group(1))
                            max_items = min(requested_number, 50)  # Cap at 50 for safety
                            logger.info(f"🔢 User requested {requested_number} items, using max_items={max_items}")
                        elif any(word in query.lower() for word in ['list', 'all', 'every', 'entire', 'complete', 'full', '72', '144']):
                            max_items = 500
                        elif re.search(
                            r"\b(analyze|analyse|analysis|insights?|summarize|summarise|interpret|explain)\b",
                            query.lower(),
                        ):
                            max_items = 500
                        else:
                            max_items = 100
                        _ns_intent = parse_query_intent(query)
                        _pkt_ns = build_llm_evidence_packet(
                            query=query,
                            parsed_intent=_ns_intent,
                            data_layer=data_layer,
                            query_route=None,
                            person_name_extracted=person_name,
                            max_items=max_items,
                            guarantee_class=None,
                            followup_llm_only=False,
                            followup_mode_active=False,
                            max_chars=LLM_MAX_FORENSIC_CHARS,
                        )
                        data_context = _pkt_ns.text
                        evidence_packet_meta_ns = _pkt_ns.metadata
                        log_llm_packet_debug(_pkt_ns, logger)
                        logger.info(f"✅ Fast data extraction (scoped packet): {len(data_context)} characters")
                        if data_context:
                            logger.info(f"📊 Data context preview: {data_context[:500]}...")
                    except Exception as e:
                        logger.error(f"Error using data access layer: {e}, falling back to standard extraction", exc_info=True)
                        data_layer = None  # Fall back to standard extraction
                
                # Standard extraction if no data layer or fallback needed
                if not data_context and data_src:
                    logger.info(f"Extracting data from {len(data_src)} file(s)...")
                    
                    # CRITICAL: Check if this is a summary/overview question
                    is_summary_query = is_query_too_broad(query)
                    
                    if is_summary_query:
                        # Generate pre-summarized overview instead of raw data dump
                        logger.info("📊 Summary query detected - generating forensic overview instead of raw data")
                        overview = generate_forensic_overview(data_src)
                        
                        # Format as structured data for LLM
                        data_context = f"""FORENSIC OVERVIEW (AUTHORITATIVE):
- Contacts: {overview['contacts_count']}
- Messages: {overview['messages_count']}
- Calls: {overview['calls_count']}
- Locations: {overview['locations_count']}
- Date Range: {overview['date_range'] or 'Not available'}
- Platforms: {', '.join(overview['top_apps']) if overview['top_apps'] else 'Not available'}
- Most Active Contacts: {', '.join(overview['most_active_contacts']) if overview['most_active_contacts'] else 'Not available'}"""
                        
                        logger.info(f"✅ Generated forensic overview: {overview}")
                    else:
                        # NEW: Option to let LLM extract directly from JSON
                        if use_json_extraction:
                            logger.info("Using JSON extraction mode - LLM will extract data directly from JSON")
                            for filename, data in data_src.items():
                                # Skip metadata keys like '_zip_info' - only process actual UFDR data
                                if filename.startswith('_'):
                                    continue
                                
                                if isinstance(data, dict):
                                    try:
                                        logger.debug(f"Preparing JSON for LLM from file: {filename}")
                                        # Ensure query is safe for prepare_json_for_llm
                                        safe_query = query if query and isinstance(query, str) else ""
                                        json_context = prepare_json_for_llm(data, safe_query, max_chars=500000)
                                        if data_context:
                                            data_context += "\n\n--- Additional Data ---\n\n"
                                        data_context += json_context
                                    except Exception as e:
                                        logger.warning(f"Error preparing JSON for LLM: {e}, falling back to text extraction")
                                        # Fallback to semantic extraction (Magnet AXIOM style)
                                        safe_query = query if query and isinstance(query, str) else ""
                                        try:
                                            extracted_context = semantic_extractor.extract_relevant_data(data, safe_query)
                                            # Truncate to fit context window
                                            extracted_context = truncate_for_context(extracted_context, max_tokens=3500, reserved_tokens=1000)
                                            logger.info(f"🔍 Semantic extraction (fallback): {len(extracted_context)} characters")
                                        except Exception as e:
                                            logger.warning(f"Semantic extraction failed: {e}, using enhanced extractor")
                                            extracted_context = enhanced_extractor.extract_relevant_data(data, safe_query)
                                            # Truncate to fit context window
                                            extracted_context = truncate_for_context(extracted_context, max_tokens=3500, reserved_tokens=1000)
                                        data_context = extracted_context
                                        logger.debug(f"Extracted context length: {len(data_context)} characters")
                                    logger.debug(f"JSON context length: {len(json_context)} characters")
                        else:
                            # Original approach: Use enhanced extractor to get specific UFDR details
                            for filename, data in data_src.items():
                                # Skip metadata keys like '_zip_info' - only process actual UFDR data
                                if filename.startswith('_'):
                                    continue
                                
                                if isinstance(data, dict):
                                    logger.debug(f"Processing file: {filename}")
                                    # Ensure query is safe
                                    safe_query = query if query and isinstance(query, str) else ""
                                    # Use semantic extractor (Magnet AXIOM style) - extracts ALL relevant data
                                    try:
                                        extracted_context = semantic_extractor.extract_relevant_data(data, safe_query)
                                        # Truncate to fit context window
                                        extracted_context = truncate_for_context(extracted_context, max_tokens=3500, reserved_tokens=1000)
                                        logger.info(f"🔍 Semantic extraction from {filename}: {len(extracted_context)} characters")
                                    except Exception as e:
                                        logger.warning(f"Semantic extraction failed: {e}, falling back to enhanced extractor")
                                        extracted_context = enhanced_extractor.extract_relevant_data(data, safe_query)
                                        # Truncate to fit context window
                                        extracted_context = truncate_for_context(extracted_context, max_tokens=3500, reserved_tokens=1000)
                                        logger.info(f"📊 Fallback extraction from {filename}: {len(extracted_context)} characters")
                                    
                                    # Combine data from all files
                                    if data_context:
                                        data_context += f"\n\n--- Data from {filename} ---\n\n"
                                    else:
                                        data_context = f"--- Data from {filename} ---\n\n"
                                    data_context += extracted_context
                                    logger.debug(f"Extracted context length: {len(data_context)} characters")
                                
                                # Extract image citations
                                try:
                                    if query and isinstance(query, str):  # Safety check
                                        image_citations = image_citation_extractor.extract_image_citations(data, query)
                                        if image_citations:
                                            logger.info(f"Found {len(image_citations)} relevant image citations")
                                            # Add image info to context if it's an image query
                                            if image_citation_extractor.is_image_query(query):
                                                image_info = image_citation_extractor.format_image_citations(image_citations)
                                                if data_context:
                                                    data_context += "\n\n"
                                                data_context += image_info
                                except Exception as e:
                                    logger.warning(f"Error extracting image citations: {e}")
                                
                                # Continue processing all files (removed break to support multiple files)
                else:
                    logger.warning("No data source available")

                intent_info_ns = query_analyzer.extract_specific_intent(query)
                qual_ns = intent_info_ns.get('qualifiers', {}) or {}
                primary_intent_ns = intent_info_ns.get('primary_intent', 'exploratory')
                is_pull_ns = bool(re.match(r'^\s*pull\s+messages?\b', query.lower()))
                response_format_tier_ns = select_response_format_tier(
                    query=query,
                    data_context_chars=len(data_context or ""),
                    should_be_brief=bool(
                        intent_info_ns.get('should_be_brief')
                        or qual_ns.get('brief')
                        or qual_ns.get('simple')
                        or qual_ns.get('just')
                    ),
                    should_be_comprehensive=bool(
                        intent_info_ns.get('should_be_comprehensive')
                        or qual_ns.get('detailed')
                        or qual_ns.get('comprehensive')
                    ),
                    classification_type=(classification.get("type") if isinstance(classification, dict) else None),
                    primary_intent=primary_intent_ns,
                    is_pull_messages=is_pull_ns,
                )
                universal_format_instructions_ns = format_universal_response_instructions(response_format_tier_ns)
                logger.info(
                    f"📐 Universal response format tier (non-stream): {response_format_tier_ns} "
                    f"({describe_tier_for_logging(response_format_tier_ns)})"
                )
                
                # Detect query language and add language instruction
                from utils.language_detector import detect_language, get_language_instruction
                detected_language = detect_language(query)
                language_instruction = get_language_instruction(detected_language)
                
                # Prepare messages for LM Studio (OpenAI-compatible format)
                messages = []
                
                messages.append({
                    "role": "system",
                    "content": f"""You are an elite digital forensics analyst with expertise in mobile device forensics, communication analysis, and evidence investigation. Your role is to conduct thorough, professional forensic examinations of UFDR (Universal Forensic Data Report) files.

🌐 LANGUAGE REQUIREMENT: {language_instruction}
You MUST respond in the same language as the user's query. Match the user's language exactly.

📋 DATA INTEGRITY GUIDELINES:
1. Base your analysis on the FORENSIC DATA section provided below
2. When data is present, provide comprehensive analysis and insights
3. You may make reasonable inferences and connections from the data (e.g., identifying patterns, relationships, trends)
4. If data is partial or incomplete, you can still provide analysis based on what is available
5. When listing items, prioritize items from the FORENSIC DATA section, but you can also provide context and analysis
6. If asked about a specific person/contact and some related data exists (even indirectly), provide what you can find and explain the connections

⚠️ IMPORTANT: Answer the user's question directly and helpfully. Provide analysis, insights, and professional interpretation of the forensic data.

{universal_format_instructions_ns}

REASONING DISCIPLINE:
- Follow the universal section structure above (unless this is an explicit "pull messages" command with its own template).
- Do not add a separate heading titled "Hypotheses"; use **Interpretation / Insight** for cautious alternatives.
- Cross-domain statements only when directly supported by facts in the provided data.

CORE CAPABILITIES (apply inside the universal sections):
- Messages, call logs, contacts, device metadata, locations, and media context
- Timeline and sequence reasoning when data supports it
- Pattern and frequency description when statistics are present

CORRELATION SAFETY RULES (MANDATORY):
- Treat deterministic counters/fields as immutable facts. Never override them.
- If `same_contact_overlap_count: 0`, do NOT claim same-contact overlap.
- Date-level overlap alone is weak evidence; describe as temporal association, not proof of coordination.
- Do not present intent/coordination as fact unless explicitly supported by tighter evidence (time-window/entity linkage).
- Do NOT infer that people were physically present at coordinates from day-level overlap summaries alone.
- If evidence is insufficient for strong claims, say so in **Uncertainty / Limits** and give one precise next action.

{FORENSIC_SPECULATION_RULE}

{MANDATORY_UNCERTAINTY_SECTION_HINT}

DATA HANDLING:
- When the FORENSIC DATA section contains actual data, use it inside the structured sections above
- If the data includes statistics or summaries (like "most active contacts"), use those to answer questions
- If asked about "most contacted" or "top N", base rankings on what the data actually shows

PHONE NUMBER HANDLING:
- If asked for international phone numbers and none are found in the data, explicitly state 'No international phone numbers found in the data'
- NEVER invent or make up phone numbers, even if the pattern seems logical (e.g., +44 for UK, +1 for US)
- Only list phone numbers that actually appear in the FORENSIC DATA section
- If the FORENSIC DATA shows 'No international phone numbers found', you MUST say exactly that - do not create examples
- International phone numbers are those starting with '+' followed by country code

Your goal is to provide helpful, comprehensive forensic analysis that answers the user's question using the available data. Be thorough, analytical, and professional."""
                })
                
                # DISABLED: Chat history excluded for all forensic queries to prevent hallucinations
                # Chat history causes hallucination when combined with forensic data
                # Each query is treated independently with only the current forensic data context
                logger.info(f"🔒 Chat history disabled for forensic queries (prevents hallucination)")
                
                # Add current query with forensic data
                # (The query is already in CHAT_HISTORIES, but we add it here with data context)
                
                # CRITICAL: Check if data context indicates no data found
                # Only mark as "no data" if it explicitly says NO_DATA_FOUND or is completely empty
                # If it contains helpful info (like "database contains X contacts"), still try to answer
                has_no_data = (data_context and "NO_DATA_FOUND" in data_context and 
                              "but the database contains" not in data_context) or not data_context or len(data_context.strip()) == 0
                
                # Log data context for validation
                logger.info(f"📊 Data context length: {len(data_context)} chars")
                logger.info(f"📊 Data context preview: {data_context[:500]}...")
                logger.info(f"📊 Has no data marker: {'NO_DATA_FOUND' in data_context if data_context else 'N/A'}")
                
                if data_context and not has_no_data:
                    available_chars, effective_ctx = compute_llm_forensic_char_budget(messages, query)
                    logger.info(
                        "📊 Forensic char budget (non-stream): %s (effective_ctx=%s)",
                        available_chars,
                        effective_ctx,
                    )
                    if len(data_context) > available_chars:
                        logger.warning(
                            "⚠️ Truncating forensic data from %s to %s characters",
                            len(data_context),
                            available_chars,
                        )
                        data_context = truncate_forensic_text_to_budget(data_context, available_chars)
                    else:
                        logger.info(
                            "✅ Data fits within budget: %s characters (budget=%s)",
                            len(data_context),
                            available_chars,
                        )
                    
                    user_message = f"""{query}

FORENSIC DATA:
{data_context}

{EVIDENCE_CONTRACT_TEXT}"""
                elif has_no_data:
                    user_message = f"""{query}

FORENSIC DATA: NO_DATA_FOUND - No relevant data found for this query.

{EVIDENCE_CONTRACT_TEXT}"""
                else:
                    user_message = f"""{query}

FORENSIC DATA:
{data_context if data_context else 'No relevant data found for this query.'}

{EVIDENCE_CONTRACT_TEXT}"""
                messages.append({
                    "role": "user",
                    "content": user_message
                })
                
                logger.info(f"Using provider={llm_provider_used} model={llm_model_used}")
                logger.debug(f"Prompt length: {len(prompt)} characters")
                logger.debug(f"Sending request to provider URL {resolve_effective_llm_url(llm_provider_used)} ...")
                
                import time
                llm_start = time.time()
                # Provider uses OpenAI-compatible API format
                # CRITICAL: 3B models MUST be cold and short for forensic work
                resp = llm_request(
                    llm_provider_used,
                    {
                        "model": llm_model_used,
                        "messages": messages,
                        "temperature": LLM_TEMPERATURE,
                        "max_tokens": LLM_MAX_OUTPUT_TOKENS,
                        "stream": False,
                    },
                    stream=False,
                    timeout=90,
                )
                llm_time = time.time() - llm_start
                logger.info(f"{provider_name} responded in {llm_time:.2f} seconds with status {resp.status_code}")
                
                if resp.ok:
                    try:
                        response_data = resp.json()
                        
                        # Check for error responses from provider
                        if 'error' in response_data:
                            error_info = response_data.get('error', {})
                            error_message = error_info.get('message', f'Unknown error from {provider_name}')
                            logger.error(f"❌ {provider_name} returned an error: {error_message}")
                            
                            if (
                                "context" in error_message.lower()
                                or "token" in error_message.lower()
                                or "n_ctx" in error_message.lower()
                                or str(LLM_CONTEXT_LENGTH) in error_message
                            ):
                                _allc = sum(len(msg.get("content", "")) for msg in messages)
                                error_msg = llm_context_overflow_user_message(
                                    error_message,
                                    int(_allc / 1.67),
                                    _allc,
                                )
                            else:
                                error_msg = f"""⚠️ **{provider_name.upper()} ERROR**

The LLM server returned an error:

**Error:** {error_message}

**Troubleshooting:**
1. Check if {provider_name} is available and the model is configured
2. Verify the model is compatible with the API
3. Check backend logs for more details
4. Try switching provider in settings and retry"""
                            
                            return jsonify({
                                "status": "ERROR",
                                "message": f"{provider_name} error",
                                "error_type": "LLM_ERROR",
                                "error_details": {
                                    "error_message": error_message,
                                    "user_message": error_msg
                                }
                            })
                        
                        # Provider returns OpenAI format: choices[0].message.content
                        llm_response = response_data.get('choices', [{}])[0].get('message', {}).get('content', '').strip()
                        llm_response = repair_llm_mojibake(llm_response)

                        if not llm_response:
                            logger.warning(f"Empty response from {provider_name}. Full response: {response_data}")
                            raise Exception(f"{provider_name} returned empty response")
                        
                        # User query was already added to CHAT_HISTORIES before sending to LLM
                        # Now add the assistant response
                        # Ensure session history exists
                        if session_id not in CHAT_HISTORIES:
                            CHAT_HISTORIES[session_id] = []
                        
                        CHAT_HISTORIES[session_id].append({
                            "role": "assistant",
                            "content": llm_response,
                            "timestamp": datetime.now().isoformat()
                        })
                        
                        # Persist to database
                        # NO LIMIT - Keep all chat history
                        # Removed limit to allow full conversation context
                        
                        # Calculate confidence for LLM response
                        intent_strength = confidence_calculator.calculate_intent_strength(query, "llm_query")
                        query_complexity = confidence_calculator.calculate_query_complexity(query)
                        confidence = confidence_calculator.calculate_confidence(
                            retrieval_scores=[0.9],  # High confidence for LLM responses
                            intent_strength=intent_strength,
                            data_completeness=1.0,
                            query_complexity=query_complexity,
                            response_quality=0.95  # High quality LLM response
                        )
                        
                        # Persist to database (after confidence is calculated)
                        persist_chat_message(session_id, "user", query)
                        persist_chat_message(session_id, "assistant", llm_response, metadata={
                            "llm_used": True,
                            "rag_used": False,  # RAG not used in this endpoint
                            "confidence": confidence,
                            "response_time": calculate_response_time(),
                            "model_used": llm_model_used,
                            "provider_used": llm_provider_used,
                        })
                        
                        logger.info("LLM response received successfully")
                        
                        # Prepare image citations for response (only include essential fields)
                        image_citations_response = []
                        for citation in image_citations:
                            image_citations_response.append({
                                "filename": citation.get("filename", ""),
                                "relative_path": citation.get("relative_path", ""),
                                "path": citation.get("path", ""),
                                "context": citation.get("context", ""),
                                "relevance_score": citation.get("relevance_score", 0)
                            })
                        
                        # Check if query is asking for suspicious contacts/data - if so, also search the data
                        query_lower = query.lower() if query else ""
                        data_matches = []
                        has_detailed_results = False
                        detailed_summary = "LLM-generated response"
                        
                        # Detect queries asking for suspicious contacts/data
                        is_suspicious_query = any(phrase in query_lower for phrase in [
                            'suspicious contact', 'list suspicious', 'show suspicious', 'find suspicious', 
                            'suspicious contacts', 'suspicious data', 'suspicious activity', 'suspicious pattern',
                            'suspicious communication', 'suspicious communication pattern', 'suspicious patterns',
                            'communication patterns', 'patterns from all messages', 'patterns across all platforms'
                        ])
                        
                        # Detect queries specifically asking for patterns across all platforms
                        is_platform_pattern_query = any(phrase in query_lower for phrase in [
                            'suspicious communication patterns from all the messages across all the platforms',
                            'suspicious patterns from all messages across all platforms',
                            'communication patterns from all platforms',
                            'patterns from all messages across platforms',
                            'find suspicious patterns across all platforms'
                        ])
                        
                        # Handle platform-specific pattern analysis
                        if is_platform_pattern_query:
                            logger.info("🔍 Query asks for suspicious communication patterns across all platforms - performing comprehensive analysis...")
                            try:
                                # Import suspicious keywords
                                try:
                                    from engines.nl_query_engine import SUSPICIOUS_GENERIC_KEYWORDS, SUSPICIOUS_MONEY_KEYWORDS
                                except ImportError:
                                    SUSPICIOUS_GENERIC_KEYWORDS = [
                                        "send package", "otp", "one time password", "pin", "password",
                                        "confidential", "credential", "delete", "erase"
                                    ]
                                    SUSPICIOUS_MONEY_KEYWORDS = [
                                        "money", "transfer", "wire", "payment", "pay", "fee", "processing fee",
                                        "UPI", "bank", "account", "deposit", "withdraw", "wallet"
                                    ]
                                
                                all_suspicious_keywords = SUSPICIOUS_GENERIC_KEYWORDS + SUSPICIOUS_MONEY_KEYWORDS
                                
                                # Define legitimate system senders that should be filtered out (unless context is truly suspicious)
                                legitimate_system_senders = [
                                    'telegram', 'line', 'textnow', 'snapchat', 'whatsapp', 
                                    'facebook', 'messenger', 'twitter', 'instagram', 'kik',
                                    'skype', 'discord', 'signal', 'viber', 'fb.com', 'fb.me'
                                ]
                                
                                # Define patterns that indicate legitimate system messages (more comprehensive)
                                legitimate_patterns = [
                                    r'login code.*do not give',
                                    r'verification code.*do not share',
                                    r'system message',
                                    r'account.*logged in.*another device',
                                    r'logged in to your.*account on another device',
                                    r'phone number.*reassigned',
                                    r'reassigned your phone number',
                                    r'sms.*turn off',
                                    r'reply.*stop.*turn off',
                                    r'reply "stop"',
                                    r'share an update with friends',
                                    r'https://fb\.com/',
                                    r'https://fb\.me/',
                                    r'to turn off sms',
                                    r'happy snapping',
                                    r'snapchat code',
                                    r'do not give this code to anyone',
                                    r'even if they say they are from'
                                ]
                                
                                def is_legitimate_system_message(text, sender):
                                    """Check if message is a legitimate system notification."""
                                    text_lower = text.lower()
                                    sender_lower = (sender or '').lower()
                                    
                                    # First check for legitimate patterns in the message text (regardless of sender)
                                    for pattern in legitimate_patterns:
                                        if re.search(pattern, text_lower, re.IGNORECASE):
                                            return True
                                    
                                    # Check if sender is a known platform/system
                                    if any(platform in sender_lower for platform in legitimate_system_senders):
                                        # If sender is a known platform, check for common system message indicators
                                        system_indicators = [
                                            'code:', 'verification', 'login', 'account', 'logged in',
                                            'phone number', 'reassigned', 'turn off', 'stop',
                                            'system', 'notification', 'alert'
                                        ]
                                        # If message contains system indicators and is from a platform, likely legitimate
                                        if any(indicator in text_lower for indicator in system_indicators):
                                            return True
                                    
                                    # Check for shortcode senders (numeric senders like "32665" for Facebook)
                                    # These are often legitimate system messages
                                    if sender and sender.isdigit() and len(sender) <= 6:
                                        # Check if message contains common SMS service patterns
                                        if any(pattern in text_lower for pattern in ['turn off', 'reply stop', 'fb.com', 'fb.me', 'share an update']):
                                            return True
                                    
                                    return False
                                
                                def calculate_suspicion_score(text, keywords_found, sender):
                                    """Calculate suspicion score based on context."""
                                    text_lower = text.lower()
                                    score = 0.0
                                    
                                    # High-risk keywords in suspicious context
                                    high_risk_keywords = ['otp', 'one time password', 'pin', 'password', 'transfer', 'wire', 'payment']
                                    for kw in high_risk_keywords:
                                        if kw in keywords_found:
                                            # Check if it's in a suspicious context (not a system message)
                                            if not is_legitimate_system_message(text, sender):
                                                # Check for urgency indicators
                                                if any(word in text_lower for word in ['urgent', 'immediate', 'asap', 'now', 'quick']):
                                                    score += 0.4
                                                elif any(word in text_lower for word in ['secret', 'confidential', 'private']):
                                                    score += 0.3
                                                else:
                                                    score += 0.2
                                    
                                    # Financial keywords
                                    financial_keywords = ['money', 'bank', 'account', 'deposit', 'withdraw', 'fee']
                                    for kw in financial_keywords:
                                        if kw in keywords_found:
                                            if not is_legitimate_system_message(text, sender):
                                                score += 0.15
                                    
                                    return min(score, 1.0)
                                
                                # Analyze messages grouped by platform
                                platform_analysis = {}
                                total_chats = 0
                                total_messages = 0
                                all_suspicious_messages = []
                                
                                # First, try to get messages from data layer (for XML/Cellebrite files)
                                data_layer = None
                                if ACTIVE_DATA_LAYERS:
                                    if ACTIVE_FILENAME and ACTIVE_FILENAME in ACTIVE_DATA_LAYERS:
                                        data_layer = ACTIVE_DATA_LAYERS[ACTIVE_FILENAME]
                                    elif ACTIVE_DATA_LAYERS:
                                        data_layer = list(ACTIVE_DATA_LAYERS.values())[0]
                                
                                if data_layer:
                                    logger.info("✅ Using data layer to query messages from database...")
                                    try:
                                        # Query all chat messages from database (no filter = all platforms)
                                        all_messages = data_layer.query_chat_messages("", limit=10000)
                                        logger.info(f"📊 Retrieved {len(all_messages)} messages from data layer")
                                        
                                        # Process messages from data layer
                                        for msg in all_messages:
                                            text = (msg.get('text_content') or msg.get('text') or '').lower()
                                            platform = msg.get('platform') or 'Unknown'
                                            
                                            # Initialize platform entry if needed
                                            if platform not in platform_analysis:
                                                platform_analysis[platform] = {
                                                    'platform': platform,
                                                    'total_messages': 0,
                                                    'suspicious_messages': [],
                                                    'chats': set(),
                                                    'keywords_found': set()
                                                }
                                            
                                            # Track chat IDs
                                            chat_id = msg.get('chat_id') or msg.get('chat_name') or 'unknown'
                                            platform_analysis[platform]['chats'].add(chat_id)
                                            
                                            platform_analysis[platform]['total_messages'] += 1
                                            total_messages += 1
                                            
                                            # Check for suspicious keywords (use word boundaries for better matching)
                                            found_keywords = []
                                            for kw in all_suspicious_keywords:
                                                # Use word boundary matching to avoid false positives like "pin" in "typing"
                                                pattern = r'\b' + re.escape(kw) + r'\b'
                                                if re.search(pattern, text, re.IGNORECASE):
                                                    found_keywords.append(kw)
                                            
                                            if found_keywords:
                                                sender = msg.get('from_participant') or msg.get('from', '')
                                                msg_text = msg.get('text_content') or msg.get('text', '')
                                                
                                                # Filter out legitimate system messages
                                                if not is_legitimate_system_message(msg_text, sender):
                                                    suspicion_score = calculate_suspicion_score(msg_text, found_keywords, sender)
                                                    
                                                    # Only include messages with meaningful suspicion score (> 0.1)
                                                    if suspicion_score > 0.1:
                                                        suspicious_msg = {
                                                            'timestamp': msg.get('timestamp'),
                                                            'from': sender,
                                                            'to': msg.get('to_participant') or msg.get('to', ''),
                                                            'text': msg_text,
                                                            'keywords_found': found_keywords,
                                                            'suspicion_score': suspicion_score,
                                                            'chat_id': chat_id,
                                                            'message_type': msg.get('message_type', 'text'),
                                                            'source_file': 'database'
                                                        }
                                                        platform_analysis[platform]['suspicious_messages'].append(suspicious_msg)
                                                        all_suspicious_messages.append(suspicious_msg)
                                                        platform_analysis[platform]['keywords_found'].update(found_keywords)
                                    except Exception as e:
                                        logger.warning(f"Error querying data layer: {e}", exc_info=True)
                                
                                # Also check data_src if available (for JSON UFDR files)
                                if data_src:
                                    logger.info("✅ Also checking data_src for messages...")
                                    for filename, data in data_src.items():
                                        if filename.startswith('_'):
                                            continue
                                        
                                        # Analyze messages and group by platform
                                        for msg in data.get('messages', []):
                                            text = (msg.get('text') or msg.get('content') or '').lower()
                                            
                                            # Determine platform from message
                                            platform = msg.get('platform') or msg.get('source') or 'Unknown'
                                            if platform == 'Unknown':
                                                # Try to infer from other fields
                                                if 'whatsapp' in str(msg.get('chat_name', '')).lower() or 'whatsapp' in str(msg.get('source_table', '')).lower():
                                                    platform = 'WhatsApp'
                                                elif 'telegram' in str(msg.get('chat_name', '')).lower() or 'telegram' in str(msg.get('source_table', '')).lower():
                                                    platform = 'Telegram'
                                                elif 'snapchat' in str(msg.get('chat_name', '')).lower() or 'snapchat' in str(msg.get('source_table', '')).lower():
                                                    platform = 'Snapchat'
                                                elif 'twitter' in str(msg.get('chat_name', '')).lower() or 'twitter' in str(msg.get('source_table', '')).lower():
                                                    platform = 'Twitter'
                                                elif 'messenger' in str(msg.get('chat_name', '')).lower() or 'facebook' in str(msg.get('chat_name', '')).lower():
                                                    platform = 'Facebook Messenger'
                                                elif 'line' in str(msg.get('chat_name', '')).lower():
                                                    platform = 'Line'
                                                elif 'skype' in str(msg.get('chat_name', '')).lower():
                                                    platform = 'Skype'
                                                elif 'textnow' in str(msg.get('chat_name', '')).lower():
                                                    platform = 'TextNow'
                                                elif 'sms' in str(msg.get('source_table', '')).lower() or 'native' in str(msg.get('source_table', '')).lower():
                                                    platform = 'Native Messages'
                                            
                                            # Initialize platform entry if needed
                                            if platform not in platform_analysis:
                                                platform_analysis[platform] = {
                                                    'platform': platform,
                                                    'total_messages': 0,
                                                    'suspicious_messages': [],
                                                    'chats': set(),
                                                    'keywords_found': set()
                                                }
                                            
                                            # Track chat IDs
                                            chat_id = msg.get('chat_id') or msg.get('chat_name') or 'unknown'
                                            platform_analysis[platform]['chats'].add(chat_id)
                                            
                                            platform_analysis[platform]['total_messages'] += 1
                                            total_messages += 1
                                            
                                            # Check for suspicious keywords (use word boundaries)
                                            found_keywords = []
                                            for kw in all_suspicious_keywords:
                                                pattern = r'\b' + re.escape(kw) + r'\b'
                                                if re.search(pattern, text, re.IGNORECASE):
                                                    found_keywords.append(kw)
                                            
                                            if found_keywords:
                                                sender = msg.get('from') or msg.get('sender', '')
                                                msg_text = msg.get('text') or msg.get('content', '')
                                                
                                                # Filter out legitimate system messages
                                                if not is_legitimate_system_message(msg_text, sender):
                                                    suspicion_score = calculate_suspicion_score(msg_text, found_keywords, sender)
                                                    
                                                    # Only include messages with meaningful suspicion score (> 0.1)
                                                    if suspicion_score > 0.1:
                                                        suspicious_msg = {
                                                            'timestamp': msg.get('timestamp'),
                                                            'from': sender,
                                                            'to': msg.get('to') or msg.get('receiver', ''),
                                                            'text': msg_text,
                                                            'keywords_found': found_keywords,
                                                            'suspicion_score': suspicion_score,
                                                            'chat_id': chat_id,
                                                            'message_type': msg.get('message_type', 'text'),
                                                            'source_file': filename
                                                        }
                                                        platform_analysis[platform]['suspicious_messages'].append(suspicious_msg)
                                                        all_suspicious_messages.append(suspicious_msg)
                                                        platform_analysis[platform]['keywords_found'].update(found_keywords)
                                        
                                        # Also check chat_messages if available
                                        for chat_msg in data.get('chat_messages', []):
                                            text = (chat_msg.get('text_content') or chat_msg.get('text') or '').lower()
                                            platform = chat_msg.get('platform') or 'Unknown'
                                            
                                            if platform not in platform_analysis:
                                                platform_analysis[platform] = {
                                                    'platform': platform,
                                                    'total_messages': 0,
                                                    'suspicious_messages': [],
                                                    'chats': set(),
                                                    'keywords_found': set()
                                                }
                                            
                                            chat_id = chat_msg.get('chat_id') or 'unknown'
                                            platform_analysis[platform]['chats'].add(chat_id)
                                            platform_analysis[platform]['total_messages'] += 1
                                            total_messages += 1
                                            
                                            # Check for suspicious keywords (use word boundaries)
                                            found_keywords = []
                                            for kw in all_suspicious_keywords:
                                                pattern = r'\b' + re.escape(kw) + r'\b'
                                                if re.search(pattern, text, re.IGNORECASE):
                                                    found_keywords.append(kw)
                                            
                                            if found_keywords:
                                                sender = chat_msg.get('from_participant') or chat_msg.get('from', '')
                                                msg_text = chat_msg.get('text_content') or chat_msg.get('text', '')
                                                
                                                # Filter out legitimate system messages
                                                if not is_legitimate_system_message(msg_text, sender):
                                                    suspicion_score = calculate_suspicion_score(msg_text, found_keywords, sender)
                                                    
                                                    # Only include messages with meaningful suspicion score (> 0.1)
                                                    if suspicion_score > 0.1:
                                                        suspicious_msg = {
                                                            'timestamp': chat_msg.get('timestamp'),
                                                            'from': sender,
                                                            'to': chat_msg.get('to_participant') or chat_msg.get('to', ''),
                                                            'text': msg_text,
                                                            'keywords_found': found_keywords,
                                                            'suspicion_score': suspicion_score,
                                                            'chat_id': chat_id,
                                                            'message_type': chat_msg.get('message_type', 'text'),
                                                            'source_file': filename
                                                        }
                                                        platform_analysis[platform]['suspicious_messages'].append(suspicious_msg)
                                                        all_suspicious_messages.append(suspicious_msg)
                                                        platform_analysis[platform]['keywords_found'].update(found_keywords)
                                
                                # Calculate total chats
                                for platform, analysis in platform_analysis.items():
                                    total_chats += len(analysis['chats'])
                                
                                # Format analysis context for LLM
                                pattern_analysis_context = f"""
SUSPICIOUS COMMUNICATION PATTERNS ANALYSIS - ALL PLATFORMS

Analysis Context:
These messages were analyzed across various platforms to identify suspicious communication patterns. The analysis focused on keywords and patterns that might indicate malicious or suspicious activity, such as "OTP," "transfer," "payment," and other similar terms.

Detection Basis:
Searched through {total_chats} chats containing {total_messages} messages using keywords like "OTP," "transfer," "payment," and other suspicious terms across all platforms.

PLATFORM BREAKDOWN:
"""
                                
                                # Sort suspicious messages by suspicion score (highest first)
                                for platform in platform_analysis:
                                    platform_analysis[platform]['suspicious_messages'].sort(
                                        key=lambda x: x.get('suspicion_score', 0), 
                                        reverse=True
                                    )
                                
                                # Add platform-specific findings
                                for platform, analysis in sorted(platform_analysis.items(), key=lambda x: len(x[1]['suspicious_messages']), reverse=True):
                                    chat_count = len(analysis['chats'])
                                    msg_count = analysis['total_messages']
                                    suspicious_count = len(analysis['suspicious_messages'])
                                    
                                    if suspicious_count > 0:
                                        # Calculate average suspicion score
                                        avg_score = sum(m.get('suspicion_score', 0) for m in analysis['suspicious_messages']) / suspicious_count
                                        
                                        pattern_analysis_context += f"""
{platform}:
- Total Chats Analyzed: {chat_count}
- Total Messages: {msg_count}
- Suspicious Messages Found: {suspicious_count}
- Average Suspicion Score: {avg_score:.2f}
- Keywords Detected: {', '.join(sorted(list(analysis['keywords_found']))[:10])}{'...' if len(analysis['keywords_found']) > 10 else ''}
- Top Suspicious Messages (sorted by suspicion score):
"""
                                        # Add sample messages (limit to 5 per platform, highest suspicion first)
                                        for i, msg in enumerate(analysis['suspicious_messages'][:5], 1):
                                            suspicion_score = msg.get('suspicion_score', 0)
                                            pattern_analysis_context += f"""
  {i}. Timestamp: {msg.get('timestamp', 'N/A')}
     From: {msg.get('from', 'N/A')}
     To: {msg.get('to', 'N/A')}
     Suspicion Score: {suspicion_score:.2f}
     Keywords: {', '.join(msg.get('keywords_found', []))}
     Message Preview: {msg.get('text', '')[:150]}{'...' if len(msg.get('text', '')) > 150 else ''}
"""
                                        if suspicious_count > 5:
                                            pattern_analysis_context += f"  [Note: Showing top 5 of {suspicious_count} suspicious messages from {platform}]\n"
                                
                                # Calculate confidence score
                                if total_messages > 0:
                                    suspicious_ratio = len(all_suspicious_messages) / total_messages
                                    confidence = min(0.95, 0.5 + (suspicious_ratio * 2))  # Scale to 0.5-0.95 range
                                else:
                                    confidence = 0.5
                                
                                pattern_analysis_context += f"""

SUMMARY:
- Total Platforms Analyzed: {len(platform_analysis)}
- Total Chats: {total_chats}
- Total Messages: {total_messages}
- Total Suspicious Messages: {len(all_suspicious_messages)}
- Confidence: {confidence:.3f}

RECOMMENDATIONS:
1. Review the WhatsApp messages for any suspicious transfers or OTPs.
2. Check Telegram and Snapchat for media files and system messages which could be indicators of malware or phishing attempts.
3. Investigate Twitter and Facebook Messenger for any unusual location data or text patterns that might suggest fraudulent activity.
4. Consider examining Line, Skype, and TextNow for any unexpected system messages or media exchanges.
"""
                                
                                # Add to data_context
                                if data_context:
                                    data_context = pattern_analysis_context + "\n\n--- Additional Forensic Data ---\n\n" + data_context
                                else:
                                    data_context = pattern_analysis_context
                                
                                logger.info(f"✅ Added platform pattern analysis context ({len(pattern_analysis_context)} chars, {len(all_suspicious_messages)} suspicious messages found)")
                            except Exception as e:
                                logger.warning(f"Error analyzing platform patterns: {e}", exc_info=True)
                                # Continue with existing data_context even if pattern analysis fails
                        
                        if is_suspicious_query:
                            logger.info("🔍 Query asks for suspicious contacts/data - performing data search...")
                            try:
                                # Import suspicious keywords
                                try:
                                    from engines.nl_query_engine import SUSPICIOUS_GENERIC_KEYWORDS, SUSPICIOUS_MONEY_KEYWORDS
                                except ImportError:
                                    # Fallback suspicious keywords if import fails
                                    SUSPICIOUS_GENERIC_KEYWORDS = [
                                        "send package", "otp", "one time password", "pin", "password",
                                        "confidential", "credential", "delete", "erase"
                                    ]
                                    SUSPICIOUS_MONEY_KEYWORDS = [
                                        "money", "transfer", "wire", "payment", "pay", "fee", "processing fee",
                                        "UPI", "bank", "account", "deposit", "withdraw", "wallet"
                                    ]
                                
                                all_suspicious_keywords = SUSPICIOUS_GENERIC_KEYWORDS + SUSPICIOUS_MONEY_KEYWORDS
                                
                                # Use enhanced NL engine to search for suspicious contacts
                                if enhanced_nl_engine and data_src:
                                    # Search for suspicious contacts
                                    suspicious_contacts = []
                                    suspicious_messages = []
                                    contacts_dict = {}
                                    
                                    for filename, data in data_src.items():
                                        if filename.startswith('_'):
                                            continue
                                        
                                        # Build contacts dictionary
                                        for contact in data.get('contacts', []):
                                            phone = contact.get('phone', '')
                                            name = contact.get('name', '')
                                            if phone and phone not in contacts_dict:
                                                contacts_dict[phone] = {
                                                    'name': name or 'Unknown',
                                                    'phone': phone,
                                                    'email': contact.get('email', ''),
                                                    'suspicious_count': 0,
                                                    'suspicious_messages': [],
                                                    'source_file': filename
                                                }
                                        
                                        # Check messages for suspicious keywords
                                        for msg in data.get('messages', []):
                                            text = (msg.get('text') or msg.get('content') or '').lower()
                                            if any(kw in text for kw in all_suspicious_keywords):
                                                from_phone = msg.get('from') or msg.get('sender', '')
                                                to_phone = msg.get('to') or msg.get('receiver', '')
                                                
                                                # Track suspicious activity for contacts
                                                if from_phone in contacts_dict:
                                                    contacts_dict[from_phone]['suspicious_count'] += 1
                                                    contacts_dict[from_phone]['suspicious_messages'].append({
                                                        'timestamp': msg.get('timestamp'),
                                                        'text': msg.get('text') or msg.get('content', ''),
                                                        'to': to_phone
                                                    })
                                                
                                                if to_phone and to_phone in contacts_dict:
                                                    contacts_dict[to_phone]['suspicious_count'] += 1
                                                    contacts_dict[to_phone]['suspicious_messages'].append({
                                                        'timestamp': msg.get('timestamp'),
                                                        'text': msg.get('text') or msg.get('content', ''),
                                                        'from': from_phone
                                                    })
                                                
                                                suspicious_messages.append({
                                                    'type': 'message',
                                                    'timestamp': msg.get('timestamp'),
                                                    'from': from_phone,
                                                    'to': to_phone,
                                                    'text': msg.get('text') or msg.get('content', ''),
                                                    'source_file': filename
                                                })
                                        
                                        # Also check for contacts with suspicious names/emails
                                        for contact in data.get('contacts', []):
                                            phone = contact.get('phone', '')
                                            name = (contact.get('name') or '').lower()
                                            email = (contact.get('email') or '').lower()
                                            
                                            # Check if contact name/email looks suspicious
                                            suspicious_name_keywords = ['unknown', 'external', 'temp', 'suspicious', 'blocked']
                                            if any(kw in name for kw in suspicious_name_keywords) or any(kw in email for kw in suspicious_name_keywords):
                                                if phone not in contacts_dict:
                                                    contacts_dict[phone] = {
                                                        'name': contact.get('name', 'Unknown'),
                                                        'phone': phone,
                                                        'email': contact.get('email', ''),
                                                        'suspicious_count': 1,
                                                        'suspicious_messages': [],
                                                        'source_file': filename
                                                    }
                                    
                                    # Add contacts with suspicious activity
                                    for phone, contact_info in contacts_dict.items():
                                        if contact_info['suspicious_count'] > 0:
                                            suspicious_contacts.append({
                                                'type': 'contact',
                                                'name': contact_info['name'],
                                                'phone': phone,
                                                'email': contact_info.get('email', ''),
                                                'suspicious_count': contact_info['suspicious_count'],
                                                'source_file': contact_info.get('source_file', filename)
                                            })
                                    
                                    # Combine contacts and messages
                                    data_matches = suspicious_contacts + suspicious_messages
                                    
                                    if data_matches:
                                        has_detailed_results = True
                                        detailed_summary = f"Found {len(suspicious_contacts)} suspicious contact(s) with {len(suspicious_messages)} suspicious message(s)"
                                        logger.info(f"✅ Found {len(suspicious_contacts)} suspicious contacts and {len(suspicious_messages)} suspicious messages")
                                        
                                        # Format suspicious contacts data with detection criteria for LLM
                                        suspicious_data_context = f"""
SUSPICIOUS CONTACTS DETECTION RESULTS:

DETECTION METHOD: Analyzed all messages across all platforms for suspicious keywords and patterns.

DETECTION CRITERIA:
- Suspicious Keywords Searched: {', '.join(all_suspicious_keywords[:10])}{'...' if len(all_suspicious_keywords) > 10 else ''} (Total: {len(all_suspicious_keywords)} keywords)
- Contact Name/Email Keywords: unknown, external, temp, suspicious, blocked
- Analysis Scope: All messages from all platforms in the forensic data

SUSPICIOUS CONTACTS FOUND ({len(suspicious_contacts)} total):
"""
                                        for i, contact in enumerate(suspicious_contacts[:50], 1):  # Limit to 50 for context
                                            contact_info = f"""
{i}. Phone: {contact.get('phone', 'N/A')}
   Name: {contact.get('name', 'Unknown')}
   Email: {contact.get('email', 'N/A')}
   Suspicious Message Count: {contact.get('suspicious_count', 0)}
   Source File: {contact.get('source_file', 'N/A')}
"""
                                            suspicious_data_context += contact_info
                                        
                                        if len(suspicious_contacts) > 50:
                                            suspicious_data_context += f"\n[Note: Showing first 50 of {len(suspicious_contacts)} suspicious contacts]"
                                        
                                        if suspicious_messages:
                                            suspicious_data_context += f"\n\nSUSPICIOUS MESSAGES FOUND ({len(suspicious_messages)} total):\n"
                                            for i, msg in enumerate(suspicious_messages[:20], 1):  # Limit to 20 messages
                                                msg_info = f"""
{i}. Timestamp: {msg.get('timestamp', 'N/A')}
   From: {msg.get('from', 'N/A')}
   To: {msg.get('to', 'N/A')}
   Message: {msg.get('text', '')[:200]}{'...' if len(msg.get('text', '')) > 200 else ''}
   Source: {msg.get('source_file', 'N/A')}
"""
                                                suspicious_data_context += msg_info
                                            
                                            if len(suspicious_messages) > 20:
                                                suspicious_data_context += f"\n[Note: Showing first 20 of {len(suspicious_messages)} suspicious messages]"
                                        
                                        # Add to data_context so LLM can see detection criteria
                                        if data_context:
                                            data_context = suspicious_data_context + "\n\n--- Additional Forensic Data ---\n\n" + data_context
                                        else:
                                            data_context = suspicious_data_context
                                        
                                        logger.info(f"✅ Added suspicious contacts detection context to data_context ({len(suspicious_data_context)} chars)")
                                    else:
                                        logger.info("ℹ️ No suspicious contacts found in data")
                                        
                            except Exception as e:
                                logger.warning(f"Error searching for suspicious contacts: {e}", exc_info=True)
                                # Continue with LLM response even if data search fails
                        
                        # Use LLM response as-is
                        final_response = llm_response
                        
                        _done_ns = {
                            "status": "SUCCESS",
                            "query": query,
                            "response": final_response,
                            "confidence": confidence,
                            "llm_used": True,
                            "model_used": llm_model_used,
                            "provider_used": llm_provider_used,
                            "rag_used": False,
                            "has_detailed_results": has_detailed_results,
                            "image_citations": image_citations_response,  # Add image citations
                            "has_images": len(image_citations_response) > 0,
                            "detailed_results": {
                                "matches": data_matches,
                                "data_sources": list(data_src.keys()),
                                "semantic_mappings": {},
                                "summary": detailed_summary,
                                "recommendations": ["Ask follow-up questions for more specific analysis"] if not data_matches else [],
                                "total_matches": len(data_matches)
                            },
                            "response_time": calculate_response_time()
                        }
                        if evidence_packet_meta_ns:
                            _done_ns["evidence_packet"] = evidence_packet_meta_ns
                        return jsonify(_done_ns)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse {provider_name} response: {e}")
                        logger.debug(f"Response status: {resp.status_code}")
                        logger.debug(f"Response text (first 500 chars): {resp.text[:500]}")
                        raise Exception(f"Invalid response from {provider_name}: {str(e)}")
                else:
                    logger.error(f"{provider_name} API error: Status {resp.status_code}")
                    logger.debug(f"Response: {resp.text[:500]}")
                    or_hint = _openrouter_client_error_hint(llm_provider_used, resp.status_code, resp.text or "")
                    raise Exception(
                        f"{provider_name} API returned error: HTTP {resp.status_code}{or_hint}"
                    )
            except requests.exceptions.Timeout as e:
                error_msg = f"Request to {provider_name} timed out after 90 seconds."
                print(f"LLM Timeout Error: {error_msg}")
                print(f"Timeout details: {str(e)}")
                return jsonify({
                    "status": "ERROR",
                    "message": "LLM request timed out",
                    "error_type": "TIMEOUT",
                    "error_details": {
                        "reason": f"{provider_name} took too long to respond (90+ seconds)",
                        "possible_causes": [
                            "Model is processing very large context",
                            f"{provider_name} is overloaded or slow",
                            "System resources are limited"
                        ],
                        "solutions": [
                            "Try a simpler query",
                            f"Check/restart {provider_name}",
                            "Check system resources (CPU/RAM/GPU)",
                            "Try reducing the UFDR file size"
                        ],
                        "timeout_seconds": 90,
                        "response_time": calculate_response_time()
                    },
                    "response": f"⏱️ **TIMEOUT ERROR**\n\nThe request to {provider_name} timed out after 90 seconds. This usually means:\n\n• The model is processing a very large context\n• {provider_name} is slow or overloaded\n• Your system needs more resources\n\n**Try:**\n1. Check provider health / switch provider\n2. Use a simpler query\n3. Check system resources (GPU/CPU/RAM)",
                    "confidence": 0.0,
                    "llm_used": False,
                    "rag_used": False,
                    "response_time": calculate_response_time()
                })
            except requests.exceptions.ConnectionError as e:
                error_msg = f"Cannot connect to {provider_name} at {resolve_effective_llm_url(llm_provider_used)}"
                print(f"LLM Connection Error: {error_msg}")
                print(f"Connection error details: {str(e)}")
                
                # Try to diagnose the issue
                diagnostic_info = {
                    "reason": f"Cannot establish connection to {provider_name}",
                    "provider_url": resolve_effective_llm_url(llm_provider_used),
                    "possible_causes": [
                        f"{provider_name} service is not reachable",
                        "Provider endpoint is misconfigured",
                        "Firewall is blocking the connection"
                    ],
                    "solutions": [
                        "Verify provider settings in app/environment",
                        "Check API key/network connectivity",
                        "Switch to the other provider in settings for continuity"
                    ]
                }
                
                return jsonify({
                    "status": "ERROR",
                    "message": f"Cannot connect to {provider_name}",
                    "error_type": "CONNECTION_ERROR",
                    "error_details": diagnostic_info,
                    "response": f"🔌 **CONNECTION ERROR**\n\nCannot connect to {provider_name}.\n\nCheck provider settings, network access, and credentials, or switch provider in settings.",
                    "confidence": 0.0,
                    "llm_used": False,
                    "rag_used": False,
                    "response_time": calculate_response_time()
                })
            except Exception as e:
                error_msg = str(e)
                error_type = type(e).__name__
                print(f"LLM Error ({error_type}): {error_msg}")
                import traceback
                full_traceback = traceback.format_exc()
                print("Full traceback:")
                print(full_traceback)
                
                # Don't expose session IDs or internal details in error message
                if len(error_msg) == 36 and '-' in error_msg:  # Looks like a UUID
                    error_msg = "Internal session error"
                
                # Create user-friendly error message
                user_message = f"❌ **ERROR: {error_type}**\n\n{error_msg}\n\n**What happened:**\nAn unexpected error occurred while processing your request.\n\n**Check:**\n• Flask server console for detailed error logs\n• LM Studio server is running and accessible\n• The UFDR file is properly loaded"
                
                return jsonify({
                    "status": "ERROR",
                    "message": error_msg,
                    "error_type": error_type,
                    "error_details": {
                        "reason": error_msg,
                        "full_error": full_traceback[-500:] if len(full_traceback) > 500 else full_traceback,  # Last 500 chars
                        "solutions": [
                            "Check Flask server console for full error details",
                            "Verify LM Studio server is running: Check LM Studio 'Local Server' tab",
                            "Try restarting both Flask and LM Studio server",
                            "Check if the UFDR file is valid"
                        ]
                    },
                    "response": user_message,
                    "confidence": 0.0,
                    "llm_used": False,
                    "rag_used": False,
                    "response_time": calculate_response_time()
                })

        # If LLM is disabled, return an error message
        print(f"❌ ERROR: USE_LLM is {USE_LLM}, LLM block was not entered!")
        print(f"   USE_LLM type: {type(USE_LLM)}, value: {repr(USE_LLM)}")
        return jsonify({
            "status": "ERROR",
            "message": "LLM service unavailable",
            "error_type": "LLM_DISABLED",
            "error_details": {
                "reason": f"USE_LLM is set to {USE_LLM} (expected True)",
                "actual_value": str(USE_LLM),
                "solution": "Enable LLM in web_interface.py by setting USE_LLM = True, then RESTART the Flask server"
            },
            "response": f"🚨 **LLM_DISABLED**\n\nThe LLM is currently disabled.\n\n**Current setting:** USE_LLM = {USE_LLM}\n\n**Fix:**\n1. Open `FORENSIC/web_interface.py`\n2. Find line 55 and ensure it says: `USE_LLM = True`\n3. **RESTART your Flask server** (Ctrl+C, then start again)\n4. Try again",
            "confidence": 0.0,
            "llm_used": False,
            "rag_used": False,
            "response_time": calculate_response_time()
        })
        
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "message": f"Error in chat query: {str(e)}",
            "response": f"I apologize, but I encountered an error while analyzing your forensic query. Please try rephrasing your question or check if the data is properly loaded.",
            "confidence": 0.0,
            "response_time": calculate_response_time()
        })

def format_chat_data_for_display(chat_data: dict) -> str:
    """
    Format chat data as HTML chat bubbles (blue/green) for display in the chat section.
    Returns formatted HTML string with chat-style message bubbles.
    """
    if not chat_data or not chat_data.get('chats'):
        return "<p>No chat data available.</p>"
    
    # Get device owner identifier for better outgoing/incoming detection
    device_owner_identifier = None
    device_owner_name = None
    try:
        global ACTIVE_DATA_LAYERS, ACTIVE_FILENAME
        data_layer = None
        if ACTIVE_FILENAME and ACTIVE_FILENAME in ACTIVE_DATA_LAYERS:
            data_layer = ACTIVE_DATA_LAYERS[ACTIVE_FILENAME]
        elif ACTIVE_DATA_LAYERS:
            first_filename = list(ACTIVE_DATA_LAYERS.keys())[0]
            data_layer = ACTIVE_DATA_LAYERS[first_filename]
        
        if data_layer:
            conn = data_layer.get_connection()
            try:
                cursor = conn.cursor()
                # Get device phone number (MSISDN) from metadata
                cursor.execute("SELECT value FROM device_metadata WHERE key = 'MSISDN' OR key = 'Phone Number' OR key LIKE '%phone%' LIMIT 1")
                result = cursor.fetchone()
                if result:
                    device_owner_identifier = result['value']
                
                # Also get the most active participant (likely device owner)
                cursor.execute("""
                    SELECT from_participant, COUNT(*) as count 
                    FROM chat_messages 
                    WHERE from_participant IS NOT NULL AND from_participant != '' AND from_participant != 'Device Owner'
                    GROUP BY from_participant
                    ORDER BY count DESC
                    LIMIT 1
                """)
                most_active = cursor.fetchone()
                if most_active:
                    device_owner_name = most_active['from_participant']
            finally:
                conn.close()
    except Exception as e:
        logger.warning(f"Could not determine device owner: {str(e)}")
    
    html = f"<div class='chat-messages-display' style='margin: 1rem 0;'>"
    html += f"<div style='padding: 1rem; background: rgba(59, 130, 246, 0.1); border-radius: 8px; margin-bottom: 1rem;'>"
    html += f"<h3 style='margin: 0 0 0.5rem 0; color: var(--text-primary);'>📱 Messages from {chat_data.get('platform', 'Unknown Platform')}</h3>"
    html += "</div>"
    
    # Display messages from all chats in chronological order
    all_messages = []
    for chat in chat_data.get('chats', []):
        chat_name = chat.get('chat_name', 'Unknown Chat')
        for msg in chat.get('messages', []):
            msg['_chat_name'] = chat_name
            all_messages.append(msg)
    
    # Determine device owner by analyzing message patterns
    # Count messages per participant to identify the most active (likely device owner)
    participant_message_count = {}
    for msg in all_messages:
        from_part = msg.get('from_participant', '')
        if from_part and from_part != 'Device Owner' and msg.get('message_type') != 'system':
            participant_message_count[from_part] = participant_message_count.get(from_part, 0) + 1
    
    # The participant with the most messages is likely the device owner
    if participant_message_count:
        most_active_participant = max(participant_message_count.items(), key=lambda x: x[1])[0]
        if not device_owner_name:
            device_owner_name = most_active_participant
    
    # Sort by timestamp
    all_messages.sort(key=lambda x: x.get('timestamp', '') or '')
    
    # Display messages as chat bubbles
    for msg in all_messages[:100]:  # Limit to 100 messages for display
        timestamp = msg.get('timestamp', 'N/A')
        from_part = msg.get('from_participant', 'Unknown')
        from_identifier = msg.get('from_identifier', '')
        to_identifier = msg.get('to_identifier', '')
        text = msg.get('text_content', '')
        msg_type = msg.get('message_type', 'text')
        is_deleted = msg.get('is_deleted', 0) == 1
        chat_name = msg.get('_chat_name', 'Unknown')
        
        # Format timestamp
        try:
            if timestamp and timestamp != 'N/A':
                from datetime import datetime
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                formatted_time = dt.strftime('%m/%d/%Y %I:%M:%S %p')
                delivered_time = f"Delivered: {formatted_time}(UTC+0)"
                timestamp_display = f"{formatted_time}(UTC+0)"
            else:
                delivered_time = "Delivered: N/A"
                timestamp_display = "N/A"
        except:
            delivered_time = f"Delivered: {timestamp}"
            timestamp_display = timestamp
        
        # Determine if message is incoming (blue, left) or outgoing (green, right)
        # Improved detection using device owner identifier and patterns
        is_outgoing = False
        
        # Method 1: Check if from_participant is explicitly "Device Owner"
        if from_part and 'Device Owner' in from_part:
            is_outgoing = True
        # Method 2: Check if from_identifier matches device owner's phone number
        elif device_owner_identifier and from_identifier:
            # Normalize phone numbers for comparison (remove spaces, dashes, etc.)
            owner_phone = ''.join(c for c in device_owner_identifier if c.isdigit() or c == '+')
            from_phone = ''.join(c for c in from_identifier if c.isdigit() or c == '+')
            if owner_phone and from_phone and (owner_phone in from_phone or from_phone in owner_phone):
                is_outgoing = True
        # Method 3: Check if from_participant matches most active participant (likely device owner)
        elif device_owner_name and from_part:
            if from_part == device_owner_name:
                is_outgoing = True
        # Method 4: Check if from_identifier looks like a phone number (device owner pattern)
        elif from_identifier:
            # If from_identifier looks like a phone number (starts with + or has many digits), it's likely outgoing
            if from_identifier.startswith('+') or (len(from_identifier) > 7 and sum(c.isdigit() for c in from_identifier) > 7):
                is_outgoing = True
        # Method 5: Check if to_identifier indicates this is incoming (message TO device owner)
        elif to_identifier:
            # If to_identifier contains device owner pattern, this is incoming
            if device_owner_identifier and device_owner_identifier in to_identifier:
                is_outgoing = False
            elif 'Device Owner' in to_identifier or 'device' in to_identifier.lower():
                is_outgoing = False
        # Method 6: Fallback - check participant name patterns
        elif from_part:
            # Check if from_participant contains phone number
            if from_part.startswith('+') or (len(from_part) > 5 and any(c.isdigit() for c in from_part)):
                is_outgoing = True
            # Or if it contains "owner", "device", etc.
            elif any(keyword in from_part.lower() for keyword in ['owner', 'device', 'me', 'myself']):
                is_outgoing = True
            # Heuristic: If participant name doesn't have "Two" or similar, might be device owner
            # This is a fallback and may need adjustment based on actual data
            elif 'two' not in from_part.lower() and '2' not in from_part and len(from_part.split()) <= 4:
                # Simple heuristic: shorter names without numbers might be device owner
                # But this is unreliable, so we'll be conservative
                pass
        
        # Determine bubble color and alignment (WhatsApp-style colors, theme-aware)
        # Use actual colors with data-theme attribute for CSS to override
        if is_outgoing:
            # Outgoing: Dark green
            bubble_color = "#006400"  # Dark green for outgoing
            text_color = "#ffffff"  # White text on dark green
            bubble_align = "right"
            icon_color = "#006400"  # Dark green icon
            margin_style = "margin-left: auto; margin-right: 0;"
            bubble_class = "chat-bubble-outgoing"
        else:
            # Incoming/System: Vibrant blue (CSS will ensure consistency)
            bubble_color = "#0080ff"  # Vibrant blue for incoming and system
            text_color = "#ffffff"  # White text on blue
            bubble_align = "left"
            icon_color = "#0080ff"  # Vibrant blue icon
            margin_style = "margin-left: 0; margin-right: auto;"
            bubble_class = "chat-bubble-incoming"
        
        deleted_style = "text-decoration: line-through; opacity: 0.7;" if is_deleted else ""
        deleted_marker = " [DELETED]" if is_deleted else ""
        
        # Create message bubble with WhatsApp-style layout
        html += f"<div class='whatsapp-message-wrapper' style='display: flex; align-items: flex-end; margin: 0.5rem 0; {margin_style} max-width: 75%; gap: 0.5rem;'>"
        
        if not is_outgoing:
            # Avatar on left for incoming messages
            html += f"<div class='whatsapp-avatar' style='width: 40px; height: 40px; border-radius: 50%; background: {icon_color}; flex-shrink: 0; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 16px; margin-bottom: 0.25rem;'>"
            html += f"{from_part[0].upper() if from_part else '?'}"
            html += "</div>"
        
        html += f"<div class='whatsapp-bubble-container' style='flex: 1; display: flex; flex-direction: column; align-items: {'flex-end' if is_outgoing else 'flex-start'};'>"
        
        # Use actual colors with class for CSS theme overrides
        # Add system-message class if it's a system message
        system_class = " system-message-bubble" if msg_type == 'system' else ""
        tail_class = " whatsapp-tail-right" if is_outgoing else " whatsapp-tail-left"
        
        if is_outgoing:
            # Outgoing: Green background with black text, tail on bottom-right
            html += f"<div class='whatsapp-bubble {bubble_class}{system_class}{tail_class}' style='background: {bubble_color}; padding: 0.75rem 1rem; border-radius: 7.5px; box-shadow: 0 1px 2px rgba(0,0,0,0.1); position: relative; max-width: 100%;'>"
        else:
            # Incoming/System: Blue background with white text, tail on bottom-left
            html += f"<div class='whatsapp-bubble {bubble_class}{system_class}{tail_class}' style='background: {bubble_color}; padding: 0.75rem 1rem; border-radius: 7.5px; box-shadow: 0 1px 2px rgba(0,0,0,0.1); position: relative; max-width: 100%;'>"
        
        # Sender name (only show for incoming messages, not system, not outgoing)
        if not is_outgoing and from_part and msg_type != 'system':
            html += f"<div class='whatsapp-sender-name' style='font-weight: 700; margin-bottom: 0.5rem; color: {text_color}; font-size: 0.875rem;'>{from_part}</div>"
        
        # Message content
        if msg_type == 'text' and text:
            html += f"<div style='color: {text_color}; {deleted_style}; line-height: 1.4;'>{text}{deleted_marker}</div>"
        elif msg_type == 'media':
            html += f"<div style='color: {text_color}; {deleted_style}; font-weight: 500;'>[Media Message]{deleted_marker}</div>"
            if text:
                html += f"<div style='color: {text_color}; font-size: 0.85rem; margin-top: 0.25rem; opacity: 0.8;'>{text}</div>"
        elif msg_type == 'location':
            html += f"<div style='color: {text_color}; {deleted_style}; font-weight: 500;'>[Location Share]{deleted_marker}</div>"
            if text:
                html += f"<div style='color: {text_color}; font-size: 0.85rem; margin-top: 0.25rem; opacity: 0.8;'>{text}</div>"
        elif msg_type == 'system':
            # System messages: "System Message" header, padlock icon, and content
            html += f"<div class='system-message-header' style='font-weight: 700; margin-bottom: 0.5rem; color: {text_color}; font-size: 0.875rem;'>{deleted_marker}System Message</div>"
            if text:
                html += f"<div class='system-message-content' style='color: {text_color}; line-height: 1.5; {deleted_style}; display: flex; align-items: flex-start; gap: 0.5rem;'>"
                html += f"<span style='font-size: 1rem;'>🔒</span>"  # Padlock icon
                html += f"<span style='flex: 1;'>{text}</span>"
                html += "</div>"
            else:
                html += f"<div class='system-message-content' style='color: {text_color}; line-height: 1.5; {deleted_style}; display: flex; align-items: flex-start; gap: 0.5rem;'>"
                html += f"<span style='font-size: 1rem;'>🔒</span>"  # Padlock icon
                html += f"<span style='flex: 1;'>System notification</span>"
                html += "</div>"
        else:
            html += f"<div style='color: {text_color}; {deleted_style}; font-weight: 500;'>[{msg_type.title()} Message]{deleted_marker}</div>"
            if text:
                html += f"<div style='color: {text_color}; font-size: 0.85rem; margin-top: 0.25rem; opacity: 0.8;'>{text}</div>"
        
        html += "</div>"  # Close bubble
        
        # Timestamp and icons (WhatsApp style)
        html += f"<div class='whatsapp-meta' style='display: flex; align-items: center; justify-content: {'flex-end' if is_outgoing else 'flex-start'}; gap: 0.5rem; margin-top: 0.5rem; font-size: 0.6875rem;'>"
        if not is_outgoing:
            # Smartphone icon for incoming/system messages (left side)
            html += f"<span style='opacity: 0.7; font-size: 0.875rem;'>📱</span>"
        html += f"<span style='color: rgba(255, 255, 255, 0.7); opacity: 0.9;'>{timestamp_display}</span>"
        if is_outgoing:
            # Read receipt (double checkmark) for outgoing messages
            html += f"<span style='margin-left: 0.25rem; color: #53bdeb;'>✓✓</span>"
        html += "</div>"
        
        html += "</div>"  # Close whatsapp-bubble-container
        
        if is_outgoing:
            # Avatar on right for outgoing messages
            html += f"<div class='whatsapp-avatar' style='width: 40px; height: 40px; border-radius: 50%; background: {icon_color}; flex-shrink: 0; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 16px; margin-bottom: 0.25rem;'>"
            html += f"{from_part[0].upper() if from_part else '?'}"
            html += "</div>"
        
        html += "</div>"  # Close whatsapp-message-wrapper
    
    html += "</div>"  # Close chat-messages-display
    return html


def format_chat_data_for_llm(chat_data: dict) -> str:
    """
    Format chat data as text for LLM context.
    Returns formatted text string.
    """
    if not chat_data or not chat_data.get('chats'):
        return "No chat data available."
    
    text = f"=== CHAT DATA FROM {chat_data.get('platform', 'Unknown Platform').upper()} ===\n\n"
    
    for chat in chat_data.get('chats', [])[:10]:
        chat_name = chat.get('chat_name', 'Unknown Chat')
        participants = ', '.join(chat.get('participants', [])) or 'Unknown'
        total_messages = chat.get('total_messages', 0)
        
        text += f"Chat: {chat_name}\n"
        text += f"Participants: {participants}\n"
        text += f"Total Messages: {total_messages}\n"
        text += f"Start Time: {chat.get('start_time', 'N/A')}\n"
        text += f"Last Activity: {chat.get('last_activity', 'N/A')}\n\n"
        
        # Include message samples
        messages = chat.get('messages', [])[:20]  # Include more for LLM analysis
        for msg in messages:
            timestamp = msg.get('timestamp', 'N/A')
            from_part = msg.get('from_participant', 'Unknown')
            text_content = msg.get('text_content', '')
            msg_type = msg.get('message_type', 'text')
            is_deleted = msg.get('is_deleted', 0) == 1
            
            deleted_marker = " [DELETED]" if is_deleted else ""
            
            if msg_type == 'text' and text_content:
                text += f"  [{timestamp}]{deleted_marker} {from_part}: {text_content[:300]}\n"
            elif msg_type == 'media':
                text += f"  [{timestamp}]{deleted_marker} {from_part}: [Media Message]\n"
            elif msg_type == 'location':
                text += f"  [{timestamp}]{deleted_marker} {from_part}: [Location Share] {text_content}\n"
        
        text += "\n"
    
    return text


def generate_chat_response(result, query):
    """Generate a forensic investigator-style conversational response from AI retrieval results."""
    # Safety check for None query
    if not query:
        return "I need a question to investigate. What would you like me to analyze?"
    
    # Friendly greeting for casual messages
    if query and isinstance(query, str) and query.strip().lower() in {"hi", "hello", "hey", "hey there"}:
        return "Hello! I'm your forensic AI assistant. Upload a UFDR JSON file or ask me to investigate specific patterns in your forensic data (e.g., 'Find suspicious calls', 'Analyze message patterns', 'Who are the top contacts')."
    
    if result.confidence == 0 or not result.matches:
        return (
            f"After thorough analysis, I couldn't find specific evidence related to '{query}' in the forensic data. "
            "Try searching for more specific terms like phone numbers, names, or keywords such as 'OTP', 'payment', or 'suspicious activity'."
        )
    
    # Determine response type based on query
    query_lower = query.lower() if query else ""
    
    if query_lower and any(word in query_lower for word in ['owner', 'who', 'belongs', 'user']):
        return generate_owner_response(result)
    elif any(word in query_lower for word in ['device', 'phone', 'model', 'imei']):
        return generate_device_response(result)
    elif any(word in query_lower for word in ['contact', 'call', 'message', 'communication']):
        return generate_communication_response(result)
    elif any(word in query_lower for word in ['suspicious', 'fraud', 'scam', 'threat']):
        return generate_security_response(result)
    else:
        return generate_general_response(result)

def generate_owner_response(result):
    """Generate owner-specific response."""
    if result.matches:
        match = result.matches[0]
        if match['source'] == 'contacts':
            return f"Based on the contacts, the device likely belongs to **{match['data'].get('name', 'Unknown')}**. I found this information with {result.confidence}% confidence."
        elif match['source'] == 'device_info':
            return f"From device metadata, I found registration information suggesting the owner. Confidence: {result.confidence}%."
    return f"I found some potential owner information with {result.confidence}% confidence. Check the detailed results for more specifics."

def generate_device_response(result):
    """Generate device-specific response."""
    if result.matches:
        match = result.matches[0]
        data = match.get('data', {})
        if isinstance(data, dict):
            model = data.get('model', data.get('device_model', 'Unknown'))
            return f"This appears to be a **{model}** device. I found this information with {result.confidence}% confidence."
    return f"I found device information with {result.confidence}% confidence. Check detailed results for specifications."

def generate_communication_response(result):
    """Generate communication-specific response."""
    total_matches = len(result.matches)
    if total_matches > 0:
        return f"I found **{total_matches}** communication records related to your query. The most relevant results show {result.summary if result.summary else 'various communication patterns'}."
    return f"Found {total_matches} communication records with {result.confidence}% confidence."

def generate_security_response(result):
    """Generate security/threat-specific response."""
    if result.matches:
        return f"⚠️ I found **{len(result.matches)}** potentially suspicious items. This requires immediate attention. Confidence: {result.confidence}%."
    return f"Security analysis complete. Found {len(result.matches)} items of interest with {result.confidence}% confidence."

def generate_general_response(result):
    """Generate general response."""
    total_matches = len(result.matches)
    if total_matches > 0:
        return f"I found **{total_matches}** relevant results for your query. {result.summary if result.summary else 'The information includes various data points from the device.'} Confidence: {result.confidence}%."
    return f"Found {total_matches} results with {result.confidence}% confidence."

@app.route('/api/quick-commands')
def get_quick_commands():
    """Get quick command categories and examples."""
    quick_commands = {
        "Common Queries": {
            "icon": "fas fa-search",
            "color": "success",
            "commands": [
                "Show me all contacts",
                "Find messages about money",
                "Show calls from last week",
                "Find suspicious activities",
                "Show device information"
            ]
        },
        "Analysis Queries": {
            "icon": "fas fa-chart-line",
            "color": "warning", 
            "commands": [
                "Analyze communication patterns",
                "Find financial transactions",
                "Show relationship networks",
                "Identify threat indicators"
            ]
        },
        "Evidence Queries": {
            "icon": "fas fa-file-alt",
            "color": "primary",
            "commands": [
                "Show deleted messages",
                "Find encrypted communications",
                "Show media files",
                "Find location data"
            ]
        }
    }
    return jsonify(quick_commands)

@app.route('/api/rag-reindex', methods=['POST'])
def rag_reindex():
    """Rebuild RAG index from current data (uploads or synthetic)."""
    try:
        if rag_engine is None:
            return jsonify({"status": "DISABLED", "message": "RAG engine is disabled", "ready": False})
        rebuild_rag_index()
        return jsonify({"status": "SUCCESS", "ready": rag_engine.is_ready()})
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)})


@app.route('/api/rag-answer', methods=['POST'])
def rag_answer():
    """Answer NL question using retrieval-augmented generation over UFDR data."""
    try:
        if rag_engine is None:
            return jsonify({
                "status": "DISABLED",
                "message": "RAG engine is disabled - using keyword-based extraction",
                "ready": False,
                "summary": "RAG is disabled. The system will use keyword-based extraction instead.",
                "matches": [],
                "used_rag": False
            })
        data = request.get_json() or {}
        question = (data.get('query') or data.get('message') or '').strip()
        k = int(data.get('k', 10))
        if not question:
            return jsonify({"status": "ERROR", "message": "No query provided"})
        # Ensure uploads present
        if not get_current_data():
            return jsonify({"status": "ERROR", "message": "Upload a UFDR JSON file first."})
        # Ensure index exists
        if not rag_engine.is_ready():
            rebuild_rag_index()
        rag_result = rag_engine.query(question, k)
        return jsonify({
            "status": "SUCCESS",
            "ready": rag_result.get('ready', False),
            "summary": rag_result.get('summary', ''),
            "matches": rag_result.get('matches', []),
            "used_rag": rag_result.get('used_rag', False)
        })
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)})


@app.route('/api/smart-analysis', methods=['POST'])
def smart_analysis():
    """Perform intelligent analysis of uploaded UFDR data."""
    try:
        data_src = get_current_data()
        if not data_src:
            return jsonify({
                "status": "ERROR",
                "message": "No UFDR data loaded. Please upload a file first."
            })
        
        # Perform smart analysis
        analysis_results = smart_analyzer.analyze_data(data_src)
        
        return jsonify({
            "status": "SUCCESS",
            "analysis": analysis_results
        })
        
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "message": f"Error performing smart analysis: {str(e)}"
        })

@app.route('/api/explore-data', methods=['GET'])
def explore_data():
    """Get all raw data (messages, contacts, calls) for exploration."""
    try:
        data_src = get_current_data()
        if not data_src:
            return jsonify({
                "status": "ERROR",
                "message": "No UFDR data loaded. Please upload a file first."
            })
        
        # Prepare exploration data
        exploration_data = {
            "contacts": [],
            "messages": [],
            "calls": [],
            "files": []
        }
        
        for filename, file_data in data_src.items():
            if isinstance(file_data, dict):
                # Handle nested structure with devices array
                devices = file_data.get("devices", [])
                if not devices:
                    devices = [file_data]
                
                for device in devices:
                    if isinstance(device, dict):
                        # Collect contacts
                        for contact in device.get("contacts", []):
                            if isinstance(contact, dict):
                                exploration_data["contacts"].append({
                                    "name": contact.get("name", "Unknown"),
                                    "phone": contact.get("phone", contact.get("number", "")),
                                    "email": contact.get("email", ""),
                                    "source_file": filename
                                })
                        
                        # Collect messages
                        for message in device.get("messages", []):
                            if isinstance(message, dict):
                                exploration_data["messages"].append({
                                    "text": message.get("text", "") or message.get("content", ""),
                                    "from": message.get("from", message.get("sender", "Unknown")),
                                    "to": message.get("to", message.get("receiver", "Unknown")),
                                    "timestamp": message.get("timestamp", ""),
                                    "source_file": filename
                                })
                        
                        # Collect calls
                        for call in device.get("call_logs", device.get("calls", [])):
                            if isinstance(call, dict):
                                exploration_data["calls"].append({
                                    "from": call.get("from", call.get("caller", "Unknown")),
                                    "to": call.get("to", call.get("receiver", "Unknown")),
                                    "duration": call.get("duration", call.get("duration_seconds", 0)),
                                    "direction": call.get("direction", "unknown"),
                                    "timestamp": call.get("timestamp", ""),
                                    "source_file": filename
                                })
                        
                        # Collect files
                        for file_item in device.get("files", []):
                            if isinstance(file_item, dict):
                                filename_ext = file_item.get("filename", "")
                                exploration_data["files"].append({
                                    "filename": filename_ext,
                                    "size_bytes": file_item.get("size_bytes", 0),
                                    "file_type": filename_ext.split(".")[-1].lower() if "." in filename_ext else "unknown",
                                    "source_file": filename,
                                    "sensitive": any(keyword in filename_ext.lower() for keyword in ["password", "secret", "confidential"])
                                })
        
        return jsonify({
            "status": "SUCCESS",
            "data": exploration_data,
            "counts": {
                "contacts": len(exploration_data["contacts"]),
                "messages": len(exploration_data["messages"]),
                "calls": len(exploration_data["calls"]),
                "files": len(exploration_data["files"])
            }
        })
        
    except Exception as e:
        logger.error(f"Error fetching exploration data: {str(e)}")
        return jsonify({
            "status": "ERROR",
            "message": f"Error fetching data: {str(e)}"
        })

@app.route('/api/export/pdf', methods=['POST'])
def export_pdf():
    """Export forensic analysis and chat history as a court-presentable PDF document."""
    if not REPORTLAB_AVAILABLE:
        return jsonify({
            "status": "ERROR",
            "message": "PDF export is not available. Please install reportlab: pip install reportlab"
        }), 500
    
    try:
        data = request.get_json() or {}
        export_type = data.get('type', 'full')  # 'full', 'chat', 'analysis'
        
        # Get current data
        data_src = get_current_data()
        if not data_src and export_type != 'chat':
            return jsonify({
                "status": "ERROR",
                "message": "No UFDR data loaded. Please upload a file first."
            })
        
        # Get chat history with durable-first priority:
        # 1) session DB (current session),
        # 2) related sessions in same case (context continuity),
        # 3) in-memory cache,
        # 4) request payload fallback.
        chat_history = []
        chat_history_source = "none"
        session_id = (
            session.get('session_id')
            or data.get('session_id')
            or request.args.get('session_id')
        )
        if session_id:
            if SESSION_DB_AVAILABLE:
                try:
                    db_history = get_chat_history(session_id)
                    if isinstance(db_history, list) and db_history:
                        chat_history = db_history
                        chat_history_source = "db_current_session"
                except Exception as e:
                    logger.warning(f"Could not load DB chat history for PDF export: {e}")
                if not chat_history:
                    try:
                        related = get_chat_history_from_related_sessions(
                            session_id,
                            include_current=True,
                            limit_per_session=200,
                        )
                        if isinstance(related, list) and related:
                            chat_history = related
                            chat_history_source = "db_related_sessions"
                    except Exception as e:
                        logger.warning(f"Could not load related-session chat history for PDF export: {e}")
            if not chat_history:
                mem_history = CHAT_HISTORIES.get(session_id, [])
                if isinstance(mem_history, list) and mem_history:
                    chat_history = mem_history
                    chat_history_source = "memory"
        else:
            logger.warning("No session_id found for PDF export; DB chat lookup skipped")
        
        # Frontend-provided fallback
        if not chat_history and 'chat_history' in data:
            payload_history = data.get('chat_history', [])
            if isinstance(payload_history, list) and payload_history:
                chat_history = payload_history
                chat_history_source = "request_payload"
                logger.info(f"Retrieved {len(chat_history)} chat messages from request data")

        def _pdf_norm_role(m: dict) -> str:
            r = str(m.get('role') or m.get('sender') or '').lower()
            return 'assistant' if r in ('ai', 'assistant') else 'user' if r == 'user' else r

        # Attach rendered assistant HTML from the browser when lengths align or by assistant order.
        payload_hist = data.get('chat_history') if isinstance(data.get('chat_history'), list) else []
        if chat_history and payload_hist:
            if len(chat_history) == len(payload_hist) and all(
                _pdf_norm_role(a) == _pdf_norm_role(b)
                for a, b in zip(chat_history, payload_hist)
            ):
                for a, b in zip(chat_history, payload_hist):
                    h = (b.get('content_html') or '').strip()
                    if h:
                        a['content_html'] = h
            else:
                p_asst = [m for m in payload_hist if _pdf_norm_role(m) == 'assistant']
                a_iter = iter(p_asst)
                for row in chat_history:
                    if _pdf_norm_role(row) != 'assistant':
                        continue
                    p = next(a_iter, None)
                    if p and (p.get('content_html') or '').strip():
                        row['content_html'] = p['content_html'].strip()
        
        # Log chat history status
        if not chat_history:
            logger.warning(f"No chat history available for export_type={export_type}")
        else:
            logger.info(
                f"Chat history available: {len(chat_history)} messages, "
                f"export_type={export_type}, source={chat_history_source}"
            )
        
        # Create PDF in memory
        buffer = BytesIO()
        page_w, page_h = letter
        content_w = page_w - 144  # 72 pt side margins
        report_stamp = datetime.now()
        report_datetime_long = report_stamp.strftime("%B %d, %Y at %I:%M %p")
        report_datetime_footer = report_stamp.strftime("%Y-%m-%d %H:%M")

        def _pdf_on_first_page(canvas, doc):
            canvas.saveState()
            canvas.setFillColor(colors.HexColor('#1a1a2e'))
            canvas.rect(0, page_h - 6, page_w, 6, fill=1, stroke=0)
            canvas.restoreState()

        def _pdf_on_later_pages(canvas, doc):
            canvas.saveState()
            canvas.setStrokeColor(colors.HexColor('#dee2e6'))
            canvas.setLineWidth(0.75)
            canvas.line(72, page_h - 48, page_w - 72, page_h - 48)
            canvas.setFont('Helvetica', 8)
            canvas.setFillColor(colors.HexColor('#6c757d'))
            canvas.drawString(72, page_h - 42, "EVI — Digital forensic analysis report")
            canvas.drawRightString(page_w - 72, page_h - 42, f"Page {canvas.getPageNumber()}")
            canvas.setFont('Helvetica', 8)
            canvas.drawString(
                72, 36,
                f"Generated {report_datetime_footer} · Confidential — authorized use only",
            )
            canvas.restoreState()

        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=56,
        )

        # Container for the 'Flowable' objects
        elements = []

        # Define styles
        styles = getSampleStyleSheet()

        section_heading_style = ParagraphStyle(
            'SectionHeading',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=12,
            textColor=colors.HexColor('#1a1a2e'),
            spaceBefore=18,
            spaceAfter=4,
            leading=15,
            alignment=TA_LEFT,
        )
        section_heading_tight_style = ParagraphStyle(
            'SectionHeadingTight',
            parent=section_heading_style,
            spaceBefore=6,
        )

        def _append_section_title(elements_list, title: str, tight_top: bool = False):
            """Major section heading with a rule for clear document structure."""
            st = section_heading_tight_style if tight_top else section_heading_style
            elements_list.append(Paragraph(title, st))
            elements_list.append(
                HRFlowable(
                    width=content_w,
                    thickness=0.75,
                    color=colors.HexColor('#ced4da'),
                    spaceBefore=2,
                    spaceAfter=12,
                )
            )

        # Cover / title page
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=colors.HexColor('#1a1a2e'),
            spaceAfter=14,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            leading=26,
        )

        cover_subtitle_style = ParagraphStyle(
            'CoverSubtitle',
            parent=styles['Normal'],
            fontSize=12,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#495057'),
            spaceAfter=28,
            leading=16,
        )

        # Body style
        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#212529'),
            spaceAfter=11,
            alignment=TA_LEFT,
            leading=16,
            leftIndent=0,
            rightIndent=0,
        )

        # Header style (intra-section labels)
        header_style = ParagraphStyle(
            'CustomHeader',
            parent=styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#343a40'),
            spaceAfter=6,
            spaceBefore=14,
            alignment=TA_LEFT,
            fontName='Helvetica-Bold',
            leading=14,
        )

        # Readable investigation-log styles
        query_box_style = ParagraphStyle(
            'QueryBox',
            parent=styles['Normal'],
            fontSize=10.5,
            textColor=colors.HexColor('#1a1a2e'),
            leading=14,
            leftIndent=8,
            rightIndent=8,
            spaceAfter=8,
        )
        response_heading_style = ParagraphStyle(
            'ResponseHeading',
            parent=styles['Normal'],
            fontSize=12.5,
            textColor=colors.HexColor('#16213e'),
            fontName='Helvetica-Bold',
            spaceBefore=6,
            spaceAfter=8,
            leading=15,
        )
        response_section_style = ParagraphStyle(
            'ResponseSection',
            parent=styles['Normal'],
            fontSize=11.5,
            textColor=colors.HexColor('#533483'),
            fontName='Helvetica-Bold',
            spaceBefore=8,
            spaceAfter=5,
            leading=14,
        )
        response_para_style = ParagraphStyle(
            'ResponsePara',
            parent=styles['Normal'],
            fontSize=10.5,
            textColor=colors.HexColor('#0f3460'),
            leading=15,
            spaceBefore=2,
            spaceAfter=7,
        )
        response_bullet_style = ParagraphStyle(
            'ResponseBullet',
            parent=response_para_style,
            leftIndent=16,
            bulletIndent=6,
            spaceAfter=5,
        )

        def _escape_pdf_text(text: str) -> str:
            text = (text or "")
            return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        def _normalize_for_pdf(text: str) -> str:
            # Keep markdown-like structure, remove HTML tags from chat DOM output.
            t = re.sub(r'<[^>]+>', '', text or '')
            # Some persisted chat rows carry escaped newlines (e.g. "\\n") - expand them.
            t = t.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\t", "    ")
            t = t.replace('\r\n', '\n').replace('\r', '\n')
            # Ensure markdown section markers and bullets start on their own line.
            t = re.sub(r'(?<!\n)(#{1,6}\s+)', r'\n\1', t)
            t = re.sub(r'([^\n])(\s+[-\u2022]\s+)', r'\1\n\2', t)
            t = re.sub(r'\n{3,}', '\n\n', t).strip()
            return t

        def _md_bold_to_pdf(text: str) -> str:
            # Convert markdown bold to ReportLab inline bold tags after escaping.
            escaped = _escape_pdf_text(text)
            return re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', escaped)

        chat_pdf_ctx = ChatPdfStyles(
            body=response_para_style,
            md_heading=ParagraphStyle(
                'PdfLlmMdHeading',
                parent=response_section_style,
                fontSize=11.5,
                spaceBefore=6,
                spaceAfter=4,
            ),
            md_subheading=ParagraphStyle(
                'PdfLlmMdSub',
                parent=response_para_style,
                fontName='Helvetica-Bold',
                fontSize=10.5,
                spaceBefore=6,
                spaceAfter=3,
            ),
            section_header=response_section_style,
            bullet=response_bullet_style,
            table_cell=ParagraphStyle(
                'PdfChatTblCell',
                parent=response_para_style,
                fontSize=8,
                leading=10.5,
            ),
            table_header_cell=ParagraphStyle(
                'PdfChatTblHead',
                parent=response_para_style,
                fontName='Helvetica-Bold',
                fontSize=8,
                leading=10.5,
            ),
            content_width=content_w,
        )

        def _append_assistant_answer(elements_list, msg: dict):
            """Match on-screen chat: HTML from client, else same formatter as the UI."""
            raw = (msg.get('content') or '').strip()
            html_fragment = (msg.get('content_html') or '').strip()
            if not html_fragment and raw:
                html_fragment = format_structured_response_html(raw)
            if not html_fragment:
                return
            fl = chat_html_fragment_to_flowables(html_fragment, chat_pdf_ctx)
            if fl:
                elements_list.extend(fl)
            elif raw:
                joined = "<br/>".join(
                    _md_bold_to_pdf(ln)
                    for ln in _normalize_for_pdf(raw).splitlines()
                    if ln.strip()
                )
                if joined:
                    elements_list.append(Paragraph(joined, response_para_style))
        
        # Title page
        elements.append(Spacer(1, 1.1 * inch))
        elements.append(Paragraph("Digital forensic analysis report", title_style))
        elements.append(
            Paragraph(
                "EVI — AI-assisted forensic investigation platform",
                cover_subtitle_style,
            )
        )
        elements.append(
            HRFlowable(
                width=content_w,
                thickness=1,
                color=colors.HexColor('#adb5bd'),
                spaceBefore=4,
                spaceAfter=20,
            )
        )

        report_info = [
            ['Report generated', report_datetime_long],
            ['System version', 'EVI v3.0.0'],
            ['Export scope', str(export_type).replace('_', ' ').title()],
            ['Analysis type', 'Digital forensic investigation'],
        ]
        if ACTIVE_FILENAME:
            report_info.append(['Primary evidence file', ACTIVE_FILENAME])
        if chat_history:
            report_info.append(['Investigation exchanges', f"{len(chat_history)} messages in transcript"])

        label_w = 2.15 * inch
        info_table = Table(report_info, colWidths=[label_w, content_w - label_w])
        info_table.setStyle(
            TableStyle(
                [
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f3f5')),
                    ('BACKGROUND', (1, 0), (1, -1), colors.white),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#212529')),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('LEFTPADDING', (0, 0), (-1, -1), 10),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                    ('TOPPADDING', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 9),
                    ('LINEABOVE', (0, 0), (-1, 0), 0.75, colors.HexColor('#dee2e6')),
                    ('LINEBELOW', (0, -1), (-1, -1), 0.75, colors.HexColor('#dee2e6')),
                    ('LINEAFTER', (0, 0), (0, -1), 0.5, colors.HexColor('#dee2e6')),
                    ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.HexColor('#e9ecef')),
                ]
            )
        )
        elements.append(info_table)
        elements.append(PageBreak())

        # Executive summary
        _append_section_title(elements, "Executive summary", tight_top=True)
        summary_text = dedent(
            """
            This report presents a digital forensic analysis produced with the EVI
            AI-assisted forensic investigation platform. The analysis examines evidence
            derived from UFDR (unified forensic data records), including communications,
            contacts, call logs, and related metadata where present.

            The investigation may use pattern recognition, natural-language processing, and
            AI-assisted reasoning to highlight items of interest. Human review remains
            essential before any legal or operational conclusion.
            """
        ).strip()
        elements.append(Paragraph(summary_text, body_style))

        # Source data overview
        if data_src and export_type in ['full', 'analysis']:
            _append_section_title(elements, "Source data overview")
            file_heading_style = ParagraphStyle(
                'FileHeading',
                parent=header_style,
                spaceBefore=10,
                fontSize=11,
            )
            for filename, file_data in data_src.items():
                elements.append(Paragraph(f"Evidence container: {_escape_pdf_text(filename)}", file_heading_style))
                stats = []
                if isinstance(file_data, dict):
                    total_records = 0
                    if 'messages' in file_data:
                        total_records += len(file_data.get('messages', []))
                    if 'contacts' in file_data:
                        total_records += len(file_data.get('contacts', []))
                    if 'call_logs' in file_data:
                        total_records += len(file_data.get('call_logs', []))
                    stats.append(['Total records indexed', str(total_records)])
                    if 'messages' in file_data:
                        stats.append(['Messages', str(len(file_data.get('messages', [])))])
                    if 'contacts' in file_data:
                        stats.append(['Contacts', str(len(file_data.get('contacts', [])))])
                    if 'call_logs' in file_data:
                        stats.append(['Call logs', str(len(file_data.get('call_logs', [])))])
                if stats:
                    stat_label_w = 2.6 * inch
                    stats_table = Table(stats, colWidths=[stat_label_w, content_w - stat_label_w])
                    stats_table.setStyle(
                        TableStyle(
                            [
                                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8f9fa')),
                                ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#212529')),
                                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                                ('FONTSIZE', (0, 0), (-1, -1), 10),
                                ('TOPPADDING', (0, 0), (-1, -1), 7),
                                ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
                                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
                                ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.HexColor('#e9ecef')),
                            ]
                        )
                    )
                    elements.append(stats_table)
                elements.append(Spacer(1, 0.18 * inch))

        # Investigation transcript
        if export_type in ['full', 'chat']:
            if chat_history and len(chat_history) > 0:
                elements.append(PageBreak())
                _append_section_title(elements, "Investigation transcript", tight_top=True)
                elements.append(
                    Paragraph(
                        "This section records investigator questions and the platform's "
                        "analysis responses as captured in the session. It is presented in "
                        "chronological order.",
                        body_style,
                    )
                )
                elements.append(Spacer(1, 0.12 * inch))

                query_header_style = ParagraphStyle(
                    'QueryHeader',
                    parent=header_style,
                    spaceBefore=6,
                    textColor=colors.HexColor('#495057'),
                )
                timestamp_style = ParagraphStyle(
                    'Timestamp',
                    parent=styles['Normal'],
                    fontSize=9,
                    textColor=colors.HexColor('#868e96'),
                    spaceAfter=4,
                )

                query_count = 0
                for msg in chat_history:
                    role = msg.get('role', 'unknown')
                    content = msg.get('content', '') or ''
                    timestamp = msg.get('timestamp', '')
                    html_extra = (msg.get('content_html') or '').strip()
                    if role == 'assistant':
                        if not content.strip() and not html_extra:
                            continue
                    elif not content.strip():
                        continue

                    if role == 'user':
                        query_count += 1
                        elements.append(Spacer(1, 0.14 * inch))
                        elements.append(
                            Paragraph(
                                f"<b>Investigator query {query_count}</b>",
                                query_header_style,
                            )
                        )
                        if timestamp:
                            try:
                                from datetime import datetime as dt

                                if 'T' in timestamp:
                                    dt_obj = dt.fromisoformat(timestamp.replace('Z', '+00:00'))
                                    formatted_time = dt_obj.strftime("%B %d, %Y at %I:%M %p")
                                else:
                                    formatted_time = timestamp
                            except Exception:
                                formatted_time = timestamp
                            elements.append(
                                Paragraph(
                                    f"<i>{_escape_pdf_text(formatted_time)}</i>",
                                    timestamp_style,
                                )
                            )
                        query_text = _normalize_for_pdf(content)
                        query_box = Table(
                            [[Paragraph(_md_bold_to_pdf(query_text), query_box_style)]],
                            colWidths=[content_w],
                        )
                        query_box.setStyle(
                            TableStyle(
                                [
                                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
                                    ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#ced4da')),
                                    ('LEFTPADDING', (0, 0), (-1, -1), 10),
                                    ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                                ]
                            )
                        )
                        elements.append(query_box)
                    elif role == 'assistant':
                        elements.append(Spacer(1, 0.1 * inch))
                        elements.append(
                            HRFlowable(
                                width=content_w,
                                thickness=0.5,
                                color=colors.HexColor('#e9ecef'),
                                spaceBefore=2,
                                spaceAfter=10,
                            )
                        )
                        elements.append(
                            Paragraph(
                                "<b>Platform analysis</b>",
                                response_heading_style,
                            )
                        )
                        _append_assistant_answer(elements, msg)
                        elements.append(Spacer(1, 0.18 * inch))
            elif export_type == 'chat':
                elements.append(PageBreak())
                _append_section_title(elements, "Investigation transcript", tight_top=True)
                elements.append(
                    Paragraph(
                        "<i>No chat history is available for this session. Interact with the "
                        "assistant before exporting a transcript-only PDF.</i>",
                        ParagraphStyle(
                            'NoChat',
                            parent=styles['Normal'],
                            fontSize=10,
                            textColor=colors.HexColor('#868e96'),
                            alignment=TA_LEFT,
                        ),
                    )
                )

        # Findings, limitations, and use
        elements.append(PageBreak())
        _append_section_title(elements, "Findings, limitations, and use of this report", tight_top=True)
        findings_text = dedent(
            """
            This document summarizes automated and AI-assisted processing of the materials
            described above. Factual statements depend on the integrity and completeness of the
            underlying UFDR and on the scope of the session captured in the transcript.

            <b>Limitation:</b> Outputs are intended to support investigation, not to replace
            qualified forensic examination or legal judgment. Review all conclusions with
            appropriate subject-matter experts before reliance in court or administrative
            proceedings.
            """
        ).strip()
        elements.append(Paragraph(findings_text, body_style))
        elements.append(Spacer(1, 0.25 * inch))

        elements.append(
            Paragraph(
                "<i>This report was generated by the EVI forensic analysis system. "
                "Retain chain-of-custody records and working notes that accompany this export.</i>",
                ParagraphStyle(
                    'Disclaimer',
                    parent=styles['Normal'],
                    fontSize=9,
                    textColor=colors.HexColor('#868e96'),
                    alignment=TA_CENTER,
                    leading=12,
                ),
            )
        )

        # Build PDF
        try:
            doc.build(
                elements,
                onFirstPage=_pdf_on_first_page,
                onLaterPages=_pdf_on_later_pages,
            )
        except Exception as build_error:
            logger.error(f"Error building PDF: {str(build_error)}")
            raise
        
        buffer.seek(0)
        
        # Verify PDF was created (check if buffer has content)
        pdf_size = len(buffer.getvalue())
        if pdf_size == 0:
            logger.error("PDF buffer is empty")
            return jsonify({
                "status": "ERROR",
                "message": "Failed to generate PDF: Empty PDF buffer"
            }), 500
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"Forensic_Report_{timestamp}.pdf"
        
        # Create response with proper headers
        response = send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
        # Add security headers to prevent browser warnings
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Length'] = str(pdf_size)
        
        return response
        
    except Exception as e:
        logger.error(f"Error generating PDF: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({
            "status": "ERROR",
            "message": f"Error generating PDF: {str(e)}"
        }), 500

@app.route('/api/media/<path:filename>')
def serve_media(filename):
    """
    Serve media files (images) from the UFDR Media folder or ZIP extraction.
    Handles both regular Media/images/ structure and ZIP-extracted images.
    """
    try:
        # Security: prevent directory traversal
        if '..' in filename or filename.startswith('/'):
            return jsonify({"status": "ERROR", "message": "Invalid filename"}), 400
        
        # First, check if we have ZIP-extracted images
        data_src = get_current_data()
        zip_extracted_path = None
        
        # Normalize the filename parameter (handle URL encoding)
        import urllib.parse
        decoded_filename = urllib.parse.unquote(filename)
        
        # Check for ZIP info at top level
        if data_src and '_zip_info' in data_src:
            zip_info = data_src.get('_zip_info', {})
            if zip_info.get('is_zip'):
                # Find the image by matching rel_path or name
                for img_info in zip_info.get('images', []):
                    rel_path = img_info.get('rel_path', '')
                    img_name = img_info.get('name', '')
                    # Match by full rel_path, or by filename, or if rel_path ends with filename
                    if (rel_path == decoded_filename or 
                        img_name == decoded_filename or 
                        rel_path.endswith(decoded_filename) or
                        decoded_filename in rel_path):
                        zip_extracted_path = img_info.get('path')
                        if zip_extracted_path and os.path.exists(zip_extracted_path):
                            break
        
        # Also check in file data
        if not zip_extracted_path and data_src:
            for file_data in data_src.values():
                if isinstance(file_data, dict) and '_zip_info' in file_data:
                    zip_info = file_data.get('_zip_info', {})
                    if zip_info.get('is_zip'):
                        for img_info in zip_info.get('images', []):
                            rel_path = img_info.get('rel_path', '')
                            img_name = img_info.get('name', '')
                            if (rel_path == decoded_filename or 
                                img_name == decoded_filename or 
                                rel_path.endswith(decoded_filename) or
                                decoded_filename in rel_path):
                                zip_extracted_path = img_info.get('path')
                                if zip_extracted_path and os.path.exists(zip_extracted_path):
                                    break
                    if zip_extracted_path:
                        break
        
        # If found in ZIP extraction, serve from there
        if zip_extracted_path and os.path.exists(zip_extracted_path):
            # Determine MIME type from file extension
            ext = os.path.splitext(filename)[1].lower()
            mime_types = {
                '.jpg': 'image/jpeg',
                '.jpeg': 'image/jpeg',
                '.png': 'image/png',
                '.gif': 'image/gif',
                '.bmp': 'image/bmp',
                '.webp': 'image/webp'
            }
            mimetype = mime_types.get(ext, 'image/jpeg')
            return send_file(zip_extracted_path, mimetype=mimetype)
        
        # Otherwise, try to find media folder relative to uploaded UFDR file
        media_paths = []
        
        # Option 1: Check relative to uploaded UFDR file
        if ACTIVE_FILENAME:
            ufdr_dir = os.path.dirname(ACTIVE_FILENAME) if os.path.dirname(ACTIVE_FILENAME) else UPLOAD_FOLDER
            media_paths.append(os.path.join(ufdr_dir, "Media", "images", filename))
            # Also check parent directory (for UFDRBuilder structure)
            parent_dir = os.path.dirname(ufdr_dir) if os.path.dirname(ufdr_dir) else ufdr_dir
            media_paths.append(os.path.join(parent_dir, "Media", "images", filename))
        
        # Option 2: Check in upload folder
        media_paths.append(os.path.join(UPLOAD_FOLDER, "Media", "images", filename))
        
        # Option 3: Check in data folder
        media_paths.append(os.path.join("data", "Media", "images", filename))
        
        # Try each path
        for media_path in media_paths:
            if os.path.exists(media_path) and os.path.isfile(media_path):
                # Verify it's an image file
                ext = os.path.splitext(filename)[1].lower()
                if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
                    # Determine MIME type
                    mime_types = {
                        '.jpg': 'image/jpeg',
                        '.jpeg': 'image/jpeg',
                        '.png': 'image/png',
                        '.gif': 'image/gif',
                        '.bmp': 'image/bmp',
                        '.webp': 'image/webp'
                    }
                    mimetype = mime_types.get(ext, 'image/jpeg')
                    return send_file(media_path, mimetype=mimetype)
        
        # Image not found
        logger.warning(f"Image not found: {filename}. Tried paths: {media_paths}")
        return jsonify({
            "status": "ERROR",
            "message": f"Image not found: {filename}",
            "tried_paths": media_paths
        }), 404
        
    except Exception as e:
        logger.error(f"Error serving media file {filename}: {e}")
        return jsonify({
            "status": "ERROR",
            "message": f"Error serving image: {str(e)}"
        }), 500


@app.route('/api/debug/rbac', methods=['GET'])
@login_required
def debug_rbac():
    """Debug endpoint to check RBAC permissions for current user."""
    try:
        user_id = session.get('user_id')
        username = session.get('username')
        email = session.get('email')
        
        if not user_id:
            return jsonify({
                "error": "Not logged in",
                "user_id": None,
                "session_data": dict(session)
            }), 401
        
        # Ensure user_id is integer
        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            return jsonify({
                "error": f"Invalid user_id type: {user_id} (type: {type(user_id).__name__})",
                "user_id": user_id,
                "session_data": dict(session)
            }), 400
        
        if not SECURITY_AVAILABLE:
            return jsonify({
                "error": "Security module not available",
                "SECURITY_AVAILABLE": False,
                "user_id": user_id,
                "username": username,
                "email": email
            }), 500
        
        user_role = RBAC.get_user_role(user_id)
        has_audit_permission = RBAC.has_permission('view_audit_logs', user_id)
        has_manage_users = RBAC.has_permission('manage_users', user_id)
        
        # Get all permissions for this role
        role_permissions = RBAC.ROLES.get(user_role, [])
        
        # Check database path
        current_file = os.path.abspath(__file__)
        security_dir = os.path.dirname(os.path.join(os.path.dirname(current_file), 'security', 'security_enhancements.py'))
        forensic_dir = os.path.dirname(current_file)
        evi_scan_dir = os.path.dirname(forensic_dir)
        auth_db = os.path.join(evi_scan_dir, 'Authentication', 'evi_scan.db')
        
        # Get user info from database to verify
        try:
            import sqlite3
            conn = sqlite3.connect(auth_db)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT id, email, username, role FROM users WHERE id = ?", (user_id,))
            db_user = cur.fetchone()
            conn.close()
            
            db_role = db_user['role'] if db_user else None
            db_email = db_user['email'] if db_user else None
        except Exception as db_error:
            db_role = None
            db_email = None
            logger.warning(f"Could not verify user in database: {db_error}")
        
        return jsonify({
            "user_id": user_id,
            "username": username,
            "email": email,
            "user_role": user_role,
            "db_role": db_role,
            "db_email": db_email,
            "has_view_audit_logs": has_audit_permission,
            "has_manage_users": has_manage_users,
            "role_permissions": role_permissions,
            "available_roles": list(RBAC.ROLES.keys()),
            "auth_db_path": auth_db,
            "auth_db_exists": os.path.exists(auth_db),
            "SECURITY_AVAILABLE": SECURITY_AVAILABLE,
            "session_keys": list(session.keys())
        })
    except Exception as e:
        logger.error(f"Error in debug_rbac: {e}", exc_info=True)
        return jsonify({
            "error": str(e),
            "traceback": str(e.__traceback__) if hasattr(e, '__traceback__') else None
        }), 500

@app.route('/api/debug/active-data', methods=['GET'])
@login_required
def debug_active_data():
    """Diagnostic endpoint to check what data is loaded in ACTIVE_DATA"""
    try:
        global ACTIVE_DATA, ACTIVE_FILENAME
        
        debug_info = {
            "active_filename": ACTIVE_FILENAME,
            "active_data_keys": list(ACTIVE_DATA.keys()) if ACTIVE_DATA else [],
            "active_data_count": len(ACTIVE_DATA) if ACTIVE_DATA else 0,
            "data_summary": {}
        }
        
        # Analyze each file in ACTIVE_DATA
        for filename, data in ACTIVE_DATA.items():
            if filename.startswith('_'):
                debug_info["data_summary"][filename] = {"type": "metadata", "content": str(data)[:200]}
                continue
            
            file_summary = {
                "type": "ufdr_data",
                "is_dict": isinstance(data, dict),
                "keys": list(data.keys()) if isinstance(data, dict) else []
            }
            
            if isinstance(data, dict):
                # Check for devices array
                if 'devices' in data and isinstance(data['devices'], list):
                    devices = data['devices']
                    file_summary["devices_count"] = len(devices)
                    file_summary["devices"] = []
                    for i, device in enumerate(devices):
                        if isinstance(device, dict):
                            device_info = {
                                "device_index": i,
                                "contacts_count": len(device.get('contacts', [])),
                                "messages_count": len(device.get('messages', [])),
                                "call_logs_count": len(device.get('call_logs', [])),
                                "device_info": device.get('device', {})
                            }
                            file_summary["devices"].append(device_info)
                else:
                    # Flat structure
                    file_summary["contacts_count"] = len(data.get('contacts', []))
                    file_summary["messages_count"] = len(data.get('messages', []))
                    file_summary["call_logs_count"] = len(data.get('call_logs', []))
            
            debug_info["data_summary"][filename] = file_summary
        
        return jsonify({
            "status": "SUCCESS",
            "debug_info": debug_info
        })
    except Exception as e:
        logger.error(f"Error in debug_active_data: {e}", exc_info=True)
        return jsonify({
            "status": "ERROR",
            "message": str(e)
        }), 500

@app.route('/audit-logs')
@login_required
def view_audit_logs():
    """View audit logs - Chain of Custody (Admin and Auditor only)"""
    try:
        # RBAC: Check permission - Admin and Auditor only
        if not SECURITY_AVAILABLE:
            logger.error("SECURITY_AVAILABLE is False - security enhancements not loaded")
            flash('🔒 Security module not available. Audit logs cannot be accessed.', 'error')
            return redirect('/case-manager')
        
        try:
            user_id = session.get('user_id')
            if not user_id:
                logger.error("No user_id in session")
                flash('🔒 Not logged in. Please log in to access audit logs.', 'error')
                return redirect('/case-manager')
            
            # Ensure user_id is an integer (session might store it as string)
            try:
                user_id = int(user_id)
            except (ValueError, TypeError):
                logger.error(f"Invalid user_id in session: {user_id} (type: {type(user_id)})")
                flash('🔒 Invalid session. Please log in again.', 'error')
                return redirect('/case-manager')
            
            logger.info(f"🔍 Audit logs access check - User ID: {user_id} (type: {type(user_id).__name__})")
            
            # Get user role
            try:
                user_role = RBAC.get_user_role(user_id)
                logger.info(f"   → User role: {user_role}")
            except Exception as role_error:
                logger.error(f"   ❌ Error getting user role: {role_error}", exc_info=True)
                flash(f'🔒 Access Denied: Unable to verify user role. Error: {str(role_error)}. Please contact your administrator.', 'error')
                return redirect('/case-manager')
            
            # Check permission
            try:
                has_permission = RBAC.has_permission('view_audit_logs', user_id)
                logger.info(f"   → Has 'view_audit_logs' permission: {has_permission}")
            except Exception as perm_error:
                logger.error(f"   ❌ Error checking permission: {perm_error}", exc_info=True)
                flash(f'🔒 Access Denied: Unable to verify permissions. Error: {str(perm_error)}. Please contact your administrator.', 'error')
                return redirect('/case-manager')
            
            # Debug: Check what permissions the role has
            if user_role in RBAC.ROLES:
                role_permissions = RBAC.ROLES[user_role]
                logger.info(f"   → Role '{user_role}' has permissions: {role_permissions}")
                logger.info(f"   → 'view_audit_logs' in permissions: {'view_audit_logs' in role_permissions}")
            else:
                logger.warning(f"   ⚠️ Role '{user_role}' not found in RBAC.ROLES. Available roles: {list(RBAC.ROLES.keys())}")
                # If role not found, deny access
                flash(f'🔒 Access Denied: Unknown role "{user_role}". Please contact your administrator.', 'error')
                return redirect('/case-manager')
            
            if not has_permission:
                logger.warning(f"   ❌ User {user_id} (role: {user_role}) denied access to audit logs")
                # Show user-friendly error message with role info
                flash(f'🔒 Access Denied: You do not have permission to access Audit Logs. Your role is "{user_role}". This section is restricted to Administrators and Auditors only.', 'error')
                return redirect('/case-manager')
            
            logger.info(f"   ✅ User {user_id} (role: {user_role}) granted access to audit logs")
        except Exception as e:
            logger.error(f"❌ RBAC check failed for audit logs: {e}", exc_info=True)
            # Deny access if RBAC check fails (security-first approach)
            flash(f'🔒 Access Denied: Unable to verify permissions. Error: {str(e)}. Please contact your administrator.', 'error')
            return redirect('/case-manager')
        
        if not SESSION_DB_AVAILABLE:
            flash('Session database not available', 'error')
            return redirect('/case-manager')
        
        # Get audit logs from database
        import sys
        import os
        _database_code_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'code')
        if _database_code_path not in sys.path:
            sys.path.insert(0, _database_code_path)
        from session_db import get_db_connection
        
        conn = get_db_connection()
        if not conn:
            flash('Could not connect to database', 'error')
            return redirect('/case-manager')
        
        # Get filter parameters
        limit = request.args.get('limit', 100, type=int)
        action_filter = request.args.get('action', None)
        user_filter = request.args.get('user_id', None, type=int)
        
        cur = conn.cursor()
        
        # Build query
        query = "SELECT * FROM audit_logs WHERE 1=1"
        params = []
        
        if action_filter:
            query += " AND action LIKE ?"
            params.append(f"%{action_filter}%")
        
        if user_filter:
            query += " AND user_id = ?"
            params.append(user_filter)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        # Ensure row factory is set (get_db_connection should already set it, but ensure it)
        if not hasattr(conn, 'row_factory') or conn.row_factory is None:
            conn.row_factory = sqlite3.Row
        
        cur.execute(query, params)
        rows = cur.fetchall()
        
        # Convert rows to dictionaries
        logs = []
        for row in rows:
            if isinstance(row, sqlite3.Row):
                log_dict = {key: row[key] for key in row.keys()}
            else:
                # Fallback if row is not a Row object
                column_names = [description[0] for description in cur.description]
                log_dict = dict(zip(column_names, row))
            logs.append(log_dict)
        
        # Audit logging: Log that audit logs were viewed
        if SECURITY_AVAILABLE and audit_logger:
            user_role = RBAC.get_user_role() if SECURITY_AVAILABLE else 'unknown'
            audit_logger.log_action('view_audit_logs', resource='audit_logs', success=True,
                                  details={
                                      'role': user_role,
                                      'limit': limit,
                                      'filters': {
                                          'action': action_filter,
                                          'user_id': user_filter
                                      },
                                      'results_count': len(logs)
                                  })
        
        # Parse JSON details - keep as string for template rendering
        for log in logs:
            if log.get('details'):
                # If details is already a dict (from row factory), convert to JSON string
                if isinstance(log['details'], dict):
                    try:
                        log['details'] = json.dumps(log['details'], indent=2)
                    except:
                        log['details'] = str(log['details'])
                # If it's a string, try to parse and re-stringify for pretty printing
                elif isinstance(log['details'], str):
                    try:
                        parsed = json.loads(log['details'])
                        log['details'] = json.dumps(parsed, indent=2)
                    except:
                        # Keep as-is if not valid JSON
                        pass
        
        cur.close()
        conn.close()
        
        return render_template('security/audit_logs.html', logs=logs, 
                             action_filter=action_filter, user_filter=user_filter)
    except Exception as e:
        logger.error(f"Error viewing audit logs: {e}")
        flash(f'Error loading audit logs: {str(e)}', 'error')
        return redirect('/case-manager')

@app.route('/profile')
@login_required
def profile():
    """Profile page"""
    try:
        user_id = session.get('user_id')
        username = session.get('username')
        email = session.get('email')
        name = session.get('name', '')
        
        # Get user info from database
        conn = sqlite3.connect(AUTH_DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        
        if not user:
            flash('User not found', 'error')
            return redirect('/case-manager')
        
        user_data = dict(user) if user else {}
        cur.close()
        conn.close()
        
        return render_template('profile.html', 
                             user_id=user_id,
                             username=username or user_data.get('username', ''),
                             email=email or user_data.get('email', ''),
                             name=name or f"{user_data.get('first_name', '')} {user_data.get('last_name', '')}".strip(),
                             first_name=user_data.get('first_name', ''),
                             last_name=user_data.get('last_name', ''),
                             role=user_data.get('role', 'investigator'),
                             last_login=user_data.get('last_login', ''),
                             created_at=user_data.get('created_at', ''))
    except Exception as e:
        logger.error(f"Error loading profile: {e}")
        flash(f'Error loading profile: {str(e)}', 'error')
        return redirect('/case-manager')

@app.route('/api/profile/stats', methods=['GET'])
@login_required
def get_profile_stats():
    """Get profile statistics (active case count, recent activity)"""
    try:
        user_id = session.get('user_id')
        username = session.get('username')
        
        # Get active case count
        active_cases = 0
        if SESSION_DB_AVAILABLE:
            cases = get_all_cases(status_filter='Active', created_by=username)
            active_cases = len(cases)
        
        # Get recent activity (last 10 audit log entries for this user)
        recent_activity = []
        if SECURITY_AVAILABLE:
            try:
                import sys
                import os
                _database_code_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'code')
                if _database_code_path not in sys.path:
                    sys.path.insert(0, _database_code_path)
                from session_db import get_db_connection
                
                conn = get_db_connection()
                if conn:
                    cur = conn.cursor()
                    cur.execute("""
                        SELECT action, resource, timestamp, success, details
                        FROM audit_logs
                        WHERE user_id = ?
                        ORDER BY timestamp DESC
                        LIMIT 10
                    """, (str(user_id),))
                    rows = cur.fetchall()
                    for row in rows:
                        recent_activity.append({
                            'action': row['action'],
                            'resource': row['resource'],
                            'timestamp': row['timestamp'],
                            'success': row['success'],
                            'details': row['details']
                        })
                    cur.close()
                    conn.close()
            except Exception as e:
                logger.warning(f"Error getting recent activity: {e}")
        
        return jsonify({
            "status": "SUCCESS",
            "active_cases": active_cases,
            "recent_activity": recent_activity
        })
    except Exception as e:
        logger.error(f"Error getting profile stats: {e}")
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route('/api/profile/update', methods=['POST'])
@login_required
def update_profile():
    """Update user profile"""
    try:
        user_id = session.get('user_id')
        data = request.get_json() or {}
        
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        email = data.get('email', '').strip()
        username = data.get('username', '').strip()
        phone = data.get('phone', '').strip()
        location = data.get('location', '').strip()
        bio = data.get('bio', '').strip()
        
        if not first_name or not last_name or not email or not username:
            return jsonify({"status": "ERROR", "message": "All required fields are required"}), 400
        
        conn = sqlite3.connect(AUTH_DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Check if columns exist, if not add them
        cur.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cur.fetchall()]
        
        if 'phone' not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN phone TEXT")
        if 'location' not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN location TEXT")
        if 'bio' not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN bio TEXT")
        if 'profile_picture' not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN profile_picture TEXT")
        
        # Check if email or username is already taken by another user
        cur.execute("SELECT id FROM users WHERE (email = ? OR username = ?) AND id != ?", (email, username, user_id))
        existing = cur.fetchone()
        if existing:
            cur.close()
            conn.close()
            return jsonify({"status": "ERROR", "message": "Email or username already taken"}), 400
        
        # Update user - build query dynamically based on available columns
        update_fields = []
        update_values = []
        
        update_fields.append("first_name = ?")
        update_values.append(first_name)
        update_fields.append("last_name = ?")
        update_values.append(last_name)
        update_fields.append("email = ?")
        update_values.append(email)
        update_fields.append("username = ?")
        update_values.append(username)
        
        if 'phone' in columns:
            update_fields.append("phone = ?")
            update_values.append(phone if phone else None)
        if 'location' in columns:
            update_fields.append("location = ?")
            update_values.append(location if location else None)
        if 'bio' in columns:
            update_fields.append("bio = ?")
            update_values.append(bio if bio else None)
        
        update_values.append(user_id)
        
        update_query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
        cur.execute(update_query, update_values)
        
        conn.commit()
        cur.close()
        conn.close()
        
        # Update session with all profile data (ensures persistence across server restarts)
        session['username'] = username
        session['email'] = email
        session['name'] = f"{first_name} {last_name}"
        if 'phone' in columns:
            session['phone'] = phone if phone else ''
        if 'location' in columns:
            session['location'] = location if location else ''
        if 'bio' in columns:
            session['bio'] = bio if bio else ''
        
        # Audit logging
        if SECURITY_AVAILABLE and audit_logger:
            updated_fields = ['first_name', 'last_name', 'email', 'username']
            if phone:
                updated_fields.append('phone')
            if location:
                updated_fields.append('location')
            if bio:
                updated_fields.append('bio')
            audit_logger.log_action('update_profile', resource=f"user_{user_id}", success=True,
                                  details={'updated_fields': updated_fields})
        
        return jsonify({"status": "SUCCESS", "message": "Profile updated successfully"})
    except Exception as e:
        logger.error(f"Error updating profile: {e}")
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route('/api/profile/upload-picture', methods=['POST'])
@login_required
def upload_profile_picture():
    """Upload profile picture"""
    try:
        user_id = session.get('user_id')
        
        if 'file' not in request.files:
            return jsonify({"status": "ERROR", "message": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"status": "ERROR", "message": "No file selected"}), 400
        
        # Validate file type
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
        filename = secure_filename(file.filename)
        file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        
        if file_ext not in allowed_extensions:
            return jsonify({"status": "ERROR", "message": "Invalid file type. Allowed: PNG, JPG, JPEG, GIF, WEBP"}), 400
        
        # Create profile pictures directory
        profile_pics_dir = os.path.join(BASE_DIR, 'static', 'profile_pictures')
        os.makedirs(profile_pics_dir, exist_ok=True)
        
        # Generate unique filename
        file_ext = filename.rsplit('.', 1)[1].lower()
        new_filename = f"user_{user_id}_{secrets.token_hex(8)}.{file_ext}"
        filepath = os.path.join(profile_pics_dir, new_filename)
        
        # Save file
        file.save(filepath)
        
        # Update database
        conn = sqlite3.connect(AUTH_DB_PATH)
        cur = conn.cursor()
        
        # Check if profile_picture column exists
        cur.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cur.fetchall()]
        if 'profile_picture' not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN profile_picture TEXT")
        
        # Delete old profile picture if exists
        cur.execute("SELECT profile_picture FROM users WHERE id = ?", (user_id,))
        old_pic = cur.fetchone()
        if old_pic and old_pic[0]:
            old_pic_path = os.path.join(profile_pics_dir, old_pic[0].replace('profile_pictures/', ''))
            if os.path.exists(old_pic_path):
                try:
                    os.remove(old_pic_path)
                except:
                    pass
        
        # Update database with new picture path
        relative_path = f"profile_pictures/{new_filename}"
        cur.execute("UPDATE users SET profile_picture = ? WHERE id = ?", (relative_path, user_id))
        conn.commit()
        cur.close()
        conn.close()
        
        # Update session
        session['profile_picture'] = relative_path
        
        # Audit logging
        if SECURITY_AVAILABLE and audit_logger:
            audit_logger.log_action('upload_profile_picture', resource=f"user_{user_id}", success=True)
        
        return jsonify({
            "status": "SUCCESS",
            "message": "Profile picture uploaded successfully",
            "profile_picture": f"/static/{relative_path}"
        })
    except Exception as e:
        logger.error(f"Error uploading profile picture: {e}")
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route('/api/profile/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    try:
        user_id = session.get('user_id')
        data = request.get_json() or {}
        
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')
        
        if not current_password or not new_password or not confirm_password:
            return jsonify({"status": "ERROR", "message": "All password fields are required"}), 400
        
        if new_password != confirm_password:
            return jsonify({"status": "ERROR", "message": "New passwords do not match"}), 400
        
        if len(new_password) < 8:
            return jsonify({"status": "ERROR", "message": "Password must be at least 8 characters"}), 400
        
        conn = sqlite3.connect(AUTH_DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Verify current password
        cur.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        if not user:
            cur.close()
            conn.close()
            return jsonify({"status": "ERROR", "message": "User not found"}), 404
        
        if not bcrypt.checkpw(current_password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            cur.close()
            conn.close()
            return jsonify({"status": "ERROR", "message": "Current password is incorrect"}), 400
        
        # Hash new password
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update password
        cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_password_hash, user_id))
        conn.commit()
        cur.close()
        conn.close()
        
        # Audit logging
        if SECURITY_AVAILABLE and audit_logger:
            audit_logger.log_action('change_password', resource=f"user_{user_id}", success=True)
        
        return jsonify({"status": "SUCCESS", "message": "Password changed successfully"})
    except Exception as e:
        logger.error(f"Error changing password: {e}")
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route('/api/profile/security', methods=['GET', 'POST'])
@login_required
def account_security():
    """Get or update account security settings"""
    try:
        user_id = session.get('user_id')
        
        if request.method == 'GET':
            # Get security settings
            conn = sqlite3.connect(AUTH_DB_PATH)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT is_active, last_login, created_at FROM users WHERE id = ?", (user_id,))
            user = cur.fetchone()
            
            security_info = {
                'is_active': user['is_active'] if user else True,
                'last_login': user['last_login'] if user else None,
                'created_at': user['created_at'] if user else None,
                'two_factor_enabled': False,  # Placeholder for future 2FA
                'session_count': 1  # Placeholder
            }
            
            cur.close()
            conn.close()
            
            return jsonify({"status": "SUCCESS", "security": security_info})
        
        else:  # POST - Update security settings
            data = request.get_json() or {}
            # Placeholder for future security settings updates
            return jsonify({"status": "SUCCESS", "message": "Security settings updated"})
            
    except Exception as e:
        logger.error(f"Error with account security: {e}")
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route('/chimes/<filename>')
def serve_chime(filename):
    """Serve chime sound files."""
    try:
        # Updated path to match new folder structure
        chime_path = os.path.join('static', 'chimes', filename)
        if os.path.exists(chime_path):
            from flask import send_file
            return send_file(chime_path, mimetype='audio/wav')
        else:
            # Try alternative path for backward compatibility
            alt_path = os.path.join('Chimes', filename)
            if os.path.exists(alt_path):
                from flask import send_file
                return send_file(alt_path, mimetype='audio/wav')
            return jsonify({"error": f"Chime file not found: {filename}"}), 404
    except Exception as e:
        return jsonify({"error": f"Error serving chime: {str(e)}"}), 500

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    # Load any existing uploaded files
    uploaded_count = load_uploaded_files()
    if uploaded_count > 0:
        print(f"Loaded {uploaded_count} existing uploaded files")
    # Build RAG index on startup
    rebuild_rag_index()
    
    print("Starting UFDR Forensic Command Engine Web Interface...")
    print("Open your browser and go to: http://localhost:5000")
    if DEV_MODE:
        print("⚠️  DEVELOPMENT MODE: Login is bypassed - you can access directly")
        print("⚠️  Set DEV_MODE=False in code or export DEV_MODE=False for production")
    # Use 'stat' reloader instead of 'watchdog' to avoid issues with file uploads
    # 'stat' is slower but more stable for file operations
    app.run(debug=True, host='0.0.0.0', port=5000, reloader_type='stat')
