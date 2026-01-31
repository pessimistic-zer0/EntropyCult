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
    
    # Partial override phrases (lower weight, but suspicious especially with encoding)
    (re.compile(r'ignore\s+(all\s+)?(previous|prior|above|earlier)$', re.I | re.M),
     'partial_override_phrase', 35),
    (re.compile(r'^(previous|prior)\s+(instructions?|prompts?|rules?)', re.I | re.M),
     'partial_override_phrase', 30),
    (re.compile(r'ignore\s+all\s*$', re.I | re.M),
     'partial_override_phrase', 25),

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
    (re.compile(r'(you\s+are|imagine\s+you\'?re)\s+(a\s+|an\s+)?(jailbroken|unrestricted|unfiltered)', re.I),
     'role_confusion', 55),
    (re.compile(r'DAN\s+mode|do\s+anything\s+now', re.I), 'role_confusion', 60),
    # Additional role manipulation patterns
    (re.compile(r'unrestricted\s+(AI|assistant|model|chatbot)', re.I),
     'role_confusion', 50),
    (re.compile(r'no\s+(content\s+)?polic(y|ies)', re.I),
     'role_confusion', 45),
    (re.compile(r'(reveal|show|tell|output)\s+(your\s+)?(system\s+)?(instructions?|prompt)', re.I),
     'exfiltrate_system_prompt', 65),
    (re.compile(r'as\s+\w+[,\s]+(reveal|show|tell|output)', re.I),
     'role_confusion', 40),

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

    # =================================================================
    # DAN/Jailbreak variants (NEW)
    # =================================================================
    (re.compile(r'(DAN|STAN|GPT-?4|JailbreakGPT|EvilGPT|DevMode|Developer Mode)\s*(mode|2\.0|enabled|activated|on)?', re.I),
     'jailbreak_variant', 60),
    (re.compile(r'(DUDE|AIM|KEVIN|OMEGA|ALPHA|JAILBREAK)\s*(mode|enabled|activated)?', re.I),
     'jailbreak_variant', 55),
    (re.compile(r'(unlock|enable|activate)\s+(your\s+)?(full|true|real)\s+(potential|capabilities|power)', re.I),
     'jailbreak_variant', 50),

    # =================================================================
    # Roleplay/fictional framing (NEW)
    # =================================================================
    (re.compile(r'in this (fictional|hypothetical|imaginary|alternate)', re.I),
     'roleplay_framing', 35),
    (re.compile(r'let\'?s?\s+(play|pretend|imagine|roleplay)', re.I),
     'roleplay_framing', 35),
    (re.compile(r'imagine (a|you|that|we|there)', re.I),
     'roleplay_framing', 30),
    (re.compile(r'(write|create)\s+(a\s+)?(story|fiction|scenario)\s+where', re.I),
     'roleplay_framing', 30),

    # =================================================================
    # Virtualization (NEW)
    # =================================================================
    (re.compile(r'(simulate|emulate|create)\s+(a\s+)?(terminal|shell|conversation|AI|assistant)', re.I),
     'virtualization', 40),
    (re.compile(r'(act as|pretend to be|you are)\s+(a\s+)?(Linux|Windows|Unix|bash|command)', re.I),
     'virtualization', 40),
    (re.compile(r'(run|execute|start)\s+(a\s+)?(virtual|simulated)\s+(machine|environment|session)', re.I),
     'virtualization', 35),

    # =================================================================
    # Completion attacks (NEW)
    # =================================================================
    (re.compile(r'(complete|finish|continue)\s+(this|the)?\s*(sentence|phrase|text|prompt)', re.I),
     'completion_attack', 35),
    (re.compile(r'(fill in|complete)\s+(the\s+)?(blank|rest|following)', re.I),
     'completion_attack', 30),

    # =================================================================
    # Hypothetical framing (NEW)
    # =================================================================
    (re.compile(r'hypothetically|in theory|theoretically', re.I),
     'hypothetical_framing', 25),
    (re.compile(r'if you could|what if you were able|if you had no restrictions', re.I),
     'hypothetical_framing', 30),
    (re.compile(r'assume (you|there|we) (can|could|have|had)', re.I),
     'hypothetical_framing', 25),

    # =================================================================
    # Translation bypass (NEW)
    # =================================================================
    (re.compile(r'translate\s+(this|the following|to|into)', re.I),
     'translation_bypass', 25),
    (re.compile(r'(say|write|output)\s+(this|the following)\s+in\s+(another|different)\s+language', re.I),
     'translation_bypass', 30),

    # =================================================================
    # Output format manipulation (NEW)
    # =================================================================
    (re.compile(r'(output|respond|reply)\s+(only|in|with)?\s*(json|xml|code|raw|unfiltered)', re.I),
     'format_manipulation', 30),
    (re.compile(r'(respond|answer|output)\s+(without|no)\s+(restrictions|filters|moderation)', re.I),
     'format_manipulation', 45),
    (re.compile(r'raw\s+(output|response|text)\s+(only|mode)', re.I),
     'format_manipulation', 35),

    # =================================================================
    # Instruction echo / nested quotes (NEW)
    # =================================================================
    (re.compile(r'(say|repeat|output|type)\s*["\']', re.I),
     'instruction_echo', 30),
    (re.compile(r'(echo|print|write)\s+(exactly|verbatim|literally)', re.I),
     'instruction_echo', 35),
    (re.compile(r'repeat\s+after\s+me', re.I),
     'instruction_echo', 30),

    # =================================================================
    # Exfiltration variants (NEW)
    # =================================================================
    (re.compile(r'(your|the)\s+(hidden|secret|internal|real)\s+(instructions?|prompt|purpose)', re.I),
     'exfiltrate_variant', 55),
    (re.compile(r'(reveal|show|tell)\s+(your|the)\s+(true|real|actual)\s+(purpose|instructions?|nature)', re.I),
     'exfiltrate_variant', 55),
    (re.compile(r'what\s+(were|are)\s+you\s+(really|actually|truly)\s+(told|instructed|programmed)', re.I),
     'exfiltrate_variant', 50),
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

    # Boost risk when partial phrases are found in encoded content
    # This catches split/partial injection attempts
    if obfuscation_flags and obfuscation_flags.get('encoding_detected'):
        partial_phrase_detected = 'partial_override_phrase' in seen
        if partial_phrase_detected:
            # Encoding + partial phrase = highly suspicious
            signals.append({
                'name': 'encoded_injection_attempt',
                'weight': 35,
                'evidence': 'Partial injection phrase found in encoded content'
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
