# app/engine/signals.py
"""
Heuristic signal detection for prompt injection.
Each detector returns signals: {name, weight, evidence}.
"""

import re
from typing import List, Dict, Any

Signal = Dict[str, Any]

# Patterns: (regex, signal_name, weight)
INJECTION_PATTERNS: List[tuple] = [
    # Override instructions (Critical)
    (re.compile(r'ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)', re.I),
     'override_instructions', 60),
    (re.compile(r'disregard\s+(all\s+)?(previous|prior|above|earlier)', re.I),
     'override_instructions', 60),
    (re.compile(r'forget\s+(everything|all|what)\s+(you\s+)?(know|learned|were told)', re.I),
     'override_instructions', 55),
    (re.compile(r'new\s+instructions?\s*:', re.I), 'override_instructions', 50),
    (re.compile(r'from\s+now\s+on[,\s]+(you\s+)?(are|will|must|should)', re.I), 'override_instructions', 45),

    # System prompt exfiltration (Critical)
    (re.compile(r'(show|reveal|display|print|output|repeat|tell\s+me)\s+(the\s+)?(system\s+prompt|initial\s+prompt)', re.I),
     'exfiltrate_system_prompt', 70),
    (re.compile(r'(what|show)\s+(is|are)\s+(your\s+)?(system\s+)?instructions?', re.I),
     'exfiltrate_system_prompt', 65),
    (re.compile(r'output\s+(your\s+)?(full\s+)?(system\s+)?prompt', re.I), 'exfiltrate_system_prompt', 65),

    # Developer mode access
    (re.compile(r'(show|reveal|access)\s+(the\s+)?(developer|admin|hidden)\s+(message|mode|panel)', re.I),
     'access_developer_mode', 60),
    (re.compile(r'enter\s+(developer|admin|debug|god)\s+mode', re.I), 'access_developer_mode', 55),

    # Role manipulation
    (re.compile(r'(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\'?re))\s+(a\s+)?(different|new|my)', re.I),
     'role_confusion', 40),
    (re.compile(r'(you\s+are|imagine\s+you\'?re)\s+(a\s+)?(jailbroken|unrestricted|unfiltered)', re.I),
     'role_confusion', 55),
    (re.compile(r'DAN\s+mode|do\s+anything\s+now', re.I), 'role_confusion', 60),

    # Security bypass
    (re.compile(r'(bypass|disable|ignore|skip|turn\s+off)\s+(the\s+)?(security|safety|filter|moderation)', re.I),
     'disable_security', 65),
    (re.compile(r'(mark|flag|report)\s+(as\s+)?(safe|compliant|approved)\s+(regardless|anyway)', re.I),
     'disable_security', 60),

    # Fake system tags
    (re.compile(r'\[\s*SYSTEM\s*\]|\[\s*ADMIN\s*\]|\[\s*DEV\s*\]', re.I), 'fake_system_tag', 50),
    (re.compile(r'<\s*system\s*>|<\s*/\s*system\s*>', re.I), 'fake_system_tag', 50),

    # Delimiter injection
    (re.compile(r'---+\s*(new|real|actual)\s+(instructions?|task|prompt)', re.I), 'delimiter_injection', 45),
    (re.compile(r'={3,}\s*(ignore\s+above|real\s+task)', re.I), 'delimiter_injection', 45),

    # Context manipulation
    (re.compile(r'(end|close|terminate)\s+(of\s+)?(the\s+)?(user\s+)?(input|message|prompt)', re.I),
     'context_manipulation', 40),
    (re.compile(r'<\s*/\s*(user|input|message)\s*>', re.I), 'context_manipulation', 45),
]


def detect_signals(text: str, decoded_layers: List[Dict] = None, 
                   obfuscation_flags: Dict[str, Any] = None) -> List[Signal]:
    """Run all heuristic detectors on text and decoded layers."""
    signals = []
    seen = set()

    texts_to_check = [text]
    if decoded_layers:
        for layer in decoded_layers:
            if layer.get('decoded'):
                texts_to_check.append(layer['decoded'])

    for check_text in texts_to_check:
        for pattern, name, weight in INJECTION_PATTERNS:
            if name in seen:
                continue
            match = pattern.search(check_text)
            if match:
                signals.append({'name': name, 'weight': weight, 'evidence': match.group()[:80]})
                seen.add(name)

    # Add signal for confusables (homoglyph obfuscation attempt)
    if obfuscation_flags and obfuscation_flags.get('confusables_detected'):
        count = obfuscation_flags.get('confusables_count', 0)
        categories = obfuscation_flags.get('confusables_categories', [])
        
        # Higher weight for more confusables or suspicious categories
        weight = 15  # Base weight
        if count > 5:
            weight += 10
        if 'math_alphanumeric' in categories or 'cyrillic' in categories:
            weight += 10  # These are commonly used in attacks
        
        signals.append({
            'name': 'confusables_obfuscation',
            'weight': min(weight, 35),  # Cap at 35
            'evidence': f'{count} confusable chars detected ({", ".join(categories)})'
        })

    return signals


def calculate_risk_score(signals: List[Signal]) -> int:
    """Calculate risk score from signals (sum, capped at 100)."""
    return min(sum(s['weight'] for s in signals), 100)


def classify_risk(risk_score: int) -> str:
    """Classify risk level based on score."""
    if risk_score >= 50:
        return 'malicious'
    elif risk_score >= 25:
        return 'uncertain'
    return 'benign'
