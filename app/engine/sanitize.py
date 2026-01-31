"""
Sanitization module for prompt injection defense.
Removes or neutralizes detected injection segments while preserving legitimate content.
"""

import re
from typing import List, Dict, Any, Tuple

# Patterns to remove (more aggressive than detection - these are for removal)
REMOVAL_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # Direct instruction overrides
    (re.compile(r'^.*ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?.*$', re.I | re.M),
     'instruction_override'),
    (re.compile(r'^.*disregard\s+(all\s+)?(previous|prior|above).*$', re.I | re.M),
     'instruction_override'),
    (re.compile(r'^.*forget\s+(everything|all|what).*$', re.I | re.M),
     'forget_command'),

    # System prompt exfiltration attempts
    (re.compile(r'^.*(show|reveal|display|print|output)\s+(the\s+)?system\s+prompt.*$', re.I | re.M),
     'exfil_attempt'),
    (re.compile(r'^.*what\s+(is|are)\s+(your\s+)?(system\s+)?instructions?.*$', re.I | re.M),
     'exfil_attempt'),

    # Role manipulation lines
    (re.compile(r'^.*(you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(a\s+)?.*$', re.I | re.M),
     'role_manipulation'),
    (re.compile(r'^.*DAN\s+mode.*$', re.I | re.M),
     'role_manipulation'),

    # Security bypass attempts
    (re.compile(r'^.*(bypass|disable|ignore)\s+(the\s+)?(security|safety|filter).*$', re.I | re.M),
     'security_bypass'),

    # Fake system tags
    (re.compile(r'\[\s*SYSTEM\s*\].*?(?=\n|$)', re.I | re.S),
     'fake_system_tag'),
    (re.compile(r'<\s*system\s*>.*?<\s*/\s*system\s*>', re.I | re.S),
     'fake_system_tag'),

    # Delimiter injection attempts
    (re.compile(r'^---+\s*(new|real|actual)\s+(instructions?|task|prompt).*$', re.I | re.M),
     'delimiter_injection'),
    (re.compile(r'^={3,}.*$', re.M),
     'delimiter_injection'),

    # Hidden instruction markers
    (re.compile(r'^.*<\s*/\s*(user|input|message)\s*>.*$', re.I | re.M),
     'context_break'),
    (re.compile(r'^.*(end|close)\s+(of\s+)?(user\s+)?(input|message).*$', re.I | re.M),
     'context_break'),
]


def sanitize_message(text: str, signals: List[Dict[str, Any]]) -> Tuple[str, bool, List[str]]:
    """
    Remove injection segments from message while preserving legitimate content.
    """
    sanitized = text
    removed_patterns: List[str] = []

    for pattern, pattern_name in REMOVAL_PATTERNS:
        if pattern.search(sanitized):
            sanitized = pattern.sub('', sanitized)
            if pattern_name not in removed_patterns:
                removed_patterns.append(pattern_name)

    # Clean up: remove excessive blank lines
    sanitized = re.sub(r'\n{3,}', '\n\n', sanitized).strip()

    was_modified = sanitized != text.strip()
    return sanitized, was_modified, removed_patterns


def has_meaningful_content(text: str, min_words: int = 3) -> bool:
    """Check if sanitized text still has meaningful content."""
    words = re.findall(r'\b[a-zA-Z0-9]+\b', text)
    return len(words) >= min_words


def get_reprompt_message() -> str:
    """
    Friendly reprompt message asking user to restate clearly.

    Note: We intentionally avoid accusing the user; many false positives are
    quotation/discussion of injection phrases.
    """
    return (
        "I may have detected instruction-manipulation patterns in your message. "
        "If you're quoting or discussing a phrase (e.g., from a file), please say so explicitly. "
        "Otherwise, please restate your request plainly without meta-instructions about system prompts, "
        "developer messages, or bypassing safety. What would you like help with?"
    )


def get_block_message(reason: str = "security") -> str:
    """Return a block message explaining why the request was refused."""
    reasons = {
        "security": "This request has been blocked due to detected security policy violations.",
        "exfiltration": "Requests to reveal system instructions or internal configurations are not allowed.",
        "override": "Attempts to override or manipulate my instructions are not permitted.",
    }
    return reasons.get(reason, reasons["security"])