# app/engine/sanitize.py
"""
Sanitization module - removes injection segments while preserving legitimate content.
"""

import re
from typing import List, Dict, Any, Tuple

# Patterns to remove (aggressive removal for sanitization)
REMOVAL_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'^.*ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?.*$', re.I | re.M), 'instruction_override'),
    (re.compile(r'^.*disregard\s+(all\s+)?(previous|prior|above).*$', re.I | re.M), 'instruction_override'),
    (re.compile(r'^.*forget\s+(everything|all|what).*$', re.I | re.M), 'forget_command'),
    (re.compile(r'^.*(show|reveal|display|print|output)\s+(the\s+)?system\s+prompt.*$', re.I | re.M), 'exfil_attempt'),
    (re.compile(r'^.*what\s+(is|are)\s+(your\s+)?(system\s+)?instructions?.*$', re.I | re.M), 'exfil_attempt'),
    (re.compile(r'^.*(you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(a\s+)?.*$', re.I | re.M), 'role_manipulation'),
    (re.compile(r'^.*DAN\s+mode.*$', re.I | re.M), 'role_manipulation'),
    (re.compile(r'^.*(bypass|disable|ignore)\s+(the\s+)?(security|safety|filter).*$', re.I | re.M), 'security_bypass'),
    (re.compile(r'\[\s*SYSTEM\s*\].*?(?=\n|$)', re.I | re.S), 'fake_system_tag'),
    (re.compile(r'<\s*system\s*>.*?<\s*/\s*system\s*>', re.I | re.S), 'fake_system_tag'),
    (re.compile(r'^---+\s*(new|real|actual)\s+(instructions?|task|prompt).*$', re.I | re.M), 'delimiter_injection'),
    (re.compile(r'^={3,}.*$', re.M), 'delimiter_injection'),
    (re.compile(r'^.*<\s*/\s*(user|input|message)\s*>.*$', re.I | re.M), 'context_break'),
]


def sanitize_message(text: str, signals: List[Dict[str, Any]]) -> Tuple[str, bool, List[str]]:
    """
    Remove injection segments from message.
    Returns: (sanitized_text, was_modified, removed_patterns)
    """
    sanitized = text
    removed_patterns = []

    for pattern, pattern_name in REMOVAL_PATTERNS:
        if pattern.search(sanitized):
            sanitized = pattern.sub('', sanitized)
            if pattern_name not in removed_patterns:
                removed_patterns.append(pattern_name)

    sanitized = re.sub(r'\n{3,}', '\n\n', sanitized).strip()
    was_modified = sanitized != text.strip()
    return sanitized, was_modified, removed_patterns


def has_meaningful_content(text: str, min_words: int = 3) -> bool:
    """Check if sanitized text still has meaningful content."""
    words = re.findall(r'\b[a-zA-Z0-9]+\b', text)
    return len(words) >= min_words


def get_reprompt_message() -> str:
    """Return reprompt message asking user to restate request."""
    return (
        "Your message contained patterns that could be interpreted as instruction manipulation. "
        "Please restate your request without meta-instructions. What would you like help with?"
    )


def get_block_message(reason: str = "security") -> str:
    """Return block message explaining refusal."""
    reasons = {
        "security": "This request has been blocked due to detected security policy violations.",
        "exfiltration": "Requests to reveal system instructions are not allowed.",
        "override": "Attempts to override my instructions are not permitted.",
    }
    return reasons.get(reason, reasons["security"])
