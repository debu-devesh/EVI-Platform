#!/usr/bin/env python3
"""
Language Detection Utility
Detects the language of user queries to enable multilingual responses.
"""

import re
import logging

logger = logging.getLogger(__name__)

# Common language patterns (simple heuristic-based detection)
LANGUAGE_PATTERNS = {
    'hindi': [
        r'[क-ह]', r'[अ-औ]',  # Devanagari script
    ],
    'spanish': [
        r'\b(qué|quién|cuándo|dónde|cómo|por qué|es|está|tiene|son|del|de la|el|la|los|las)\b',
        r'[áéíóúñü]',
    ],
    'french': [
        r'\b(qui|quoi|quand|où|comment|pourquoi|est|sont|le|la|les|de|du|des)\b',
        r'[àâäéèêëïîôùûüÿç]',
    ],
    'german': [
        r'\b(wer|was|wann|wo|wie|warum|ist|sind|der|die|das|von|zu)\b',
        r'[äöüß]',
    ],
    'chinese': [
        r'[\u4e00-\u9fff]',  # Chinese characters
    ],
    'japanese': [
        r'[\u3040-\u309f]',  # Hiragana
        r'[\u30a0-\u30ff]',  # Katakana
        r'[\u4e00-\u9fff]',  # Kanji
    ],
    'arabic': [
        r'[\u0600-\u06ff]',  # Arabic script
    ],
    'russian': [
        r'[а-яё]', r'[А-ЯЁ]',  # Cyrillic script
    ],
}

def detect_language(text):
    """
    Detect the language of the input text.
    Returns language code (e.g., 'hindi', 'spanish', 'english') or 'english' as default.
    """
    if not text or not isinstance(text, str):
        return 'english'
    
    text = text.strip()
    if not text:
        return 'english'
    
    # Count matches for each language
    language_scores = {}
    
    for lang, patterns in LANGUAGE_PATTERNS.items():
        score = 0
        for pattern in patterns:
            matches = len(re.findall(pattern, text, re.IGNORECASE))
            score += matches
        if score > 0:
            language_scores[lang] = score
    
    # If we found a language with significant matches, return it
    if language_scores:
        detected_lang = max(language_scores.items(), key=lambda x: x[1])[0]
        # Only return if we have a reasonable confidence (at least 2 matches)
        if language_scores[detected_lang] >= 2:
            logger.info(f"🌐 Detected language: {detected_lang} (confidence: {language_scores[detected_lang]} matches)")
            return detected_lang
    
    # Default to English
    logger.info("🌐 Language detection: Defaulting to English")
    return 'english'

def get_language_instruction(language):
    """
    Get instruction text for the LLM to respond in the specified language.
    """
    language_instructions = {
        'hindi': 'कृपया हिंदी में उत्तर दें। (Please respond in Hindi.)',
        'spanish': 'Por favor, responde en español.',
        'french': 'Veuillez répondre en français.',
        'german': 'Bitte antworten Sie auf Deutsch.',
        'chinese': '请用中文回答。',
        'japanese': '日本語で回答してください。',
        'arabic': 'يرجى الرد بالعربية.',
        'russian': 'Пожалуйста, ответьте на русском языке.',
        'english': 'Please respond in English.',
    }
    
    return language_instructions.get(language.lower(), 'Please respond in English.')


