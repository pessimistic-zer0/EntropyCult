# app/engine/signals.py
"""
Heuristic signal detection for prompt injection.

Now uses data-driven patterns from YAML config files:
- data/patterns_hard_block.yml → high-confidence malicious signals
- data/patterns_soft_cues.yml → patterns that trigger ML backstop

Categories:
1. MALICIOUS signals - from YAML config (high weight)
2. BENIGN CONTEXT signals - hardcoded (indicate quotation/discussion)
3. STRUCTURAL signals - hardcoded (distinguish real commands from mentions)

Each detector returns signals: {name, weight, evidence}.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from app.engine.patterns import detect_hard_block_signals, check_soft_cues

Signal = Dict[str, Any]


# =============================================================================
# BENIGN CONTEXT PATTERNS (weight=0, used by policy to downgrade)
# These stay hardcoded since they're for FP reduction, not attack detection
# =============================================================================

BENIGN_CONTEXT_PATTERNS: List[tuple] = [
    # Quotation context - user is discussing/quoting text
    (re.compile(
        r'\b(it\s+says|in\s+this\s+(file|text|document|log|message|error)|'
        r'this\s+string|the\s+(phrase|text|message)|'
        r'found\s+this\s+in|'
        r'quoted|example|for\s+instance|'
        r'what\s+does\s+(that|this|it)\s+mean|'
        r'meaning\s+of|definition\s+of|'
        r'is\s+this\s+(a\s+)?prompt\s+injection)\b',
        re.I
    ), 'benign_quotation_context', 0),

    # Also trigger if suspicious phrase is inside quotes
    (re.compile(
        r'["\'].*?(ignore|forget|disregard|bypass).*?["\']',
        re.I
    ), 'benign_quotation_context', 0),

    # Self-correction - user is correcting themselves
    (re.compile(
        r'\b(sorry|correction|I\s+meant|'
        r'let\s+me\s+rephrase|what\s+I\s+meant\s+(was|is)|'
        r'scratch\s+that|never\s+mind\s+that)\b',
        re.I
    ), 'benign_self_correction', 0),

    # Analysis intent - user wants to understand prompt injection
    (re.compile(
        r'\b(is\s+this\s+(a\s+)?prompt\s+injection|'
        r'why\s+is\s+this\s+(unsafe|dangerous|malicious)|'
        r'how\s+does\s+prompt\s+injection\s+work|'
        r'explain\s+(why|how)\s+this\s+is\s+(malicious|an?\s+attack)|'
        r'analyze\s+this\s+(for|as)\s+(security|injection)|'
        r'is\s+this\s+(safe|malicious|an?\s+attack)|'
        r'what\s+makes\s+this\s+(dangerous|an?\s+injection)|'
        r'for\s+(research|analysis|testing|educational))\b',
        re.I
    ), 'benign_analysis_intent', 0),
]


# =============================================================================
# STRUCTURAL PATTERNS (help distinguish real commands from mentions)
# =============================================================================

# Imperative verbs that follow override phrases indicate real attack intent
IMPERATIVE_VERBS = (
    r'(reveal|show|display|print|output|tell|give|send|'
    r'approve|accept|allow|execute|run|do|perform|'
    r'ignore|forget|disregard|bypass|disable|skip|'
    r'act|pretend|become|switch|change|'
    r'write|say|respond|reply|answer|make\s+me\s+understand)'
)

STRUCTURAL_PATTERNS: List[tuple] = [
    # Override followed by imperative action = real attack
    (re.compile(
        rf'(ignore|forget|disregard)\s+(all\s+)?(previous|prior|above|earlier|everything)\s+'
        rf'(instructions?|prompts?|rules?|I\s+said)?\s*(and|,|then|now)?\s*{IMPERATIVE_VERBS}',
        re.I
    ), 'imperative_override_structure', 25),

    # Direct command structure after override
    (re.compile(
        r'(ignore|forget|disregard)\s+.*?\s+(and|,)\s+(instead|now|then)\s+',
        re.I
    ), 'imperative_override_structure', 20),
    
    # "forget X and Y" where Y is an action
    (re.compile(
        r'\bforget\s+everything\s+.*?\s+and\s+(give|show|tell|reveal|make)',
        re.I
    ), 'imperative_override_structure', 25),
]


# =============================================================================
# DETECTION FUNCTIONS
# =============================================================================

def detect_signals(
    text: str,
    decoded_layers: List[Dict] = None,
    obfuscation_flags: Dict[str, Any] = None
) -> List[Signal]:
    """
    Run all heuristic detectors on text and decoded layers.
    Returns list of detected signals with name, weight, and evidence.
    
    Now uses YAML-based patterns for attack detection.
    """
    signals = []
    seen = set()

    # Combine main text with decoded content for analysis
    texts_to_check = [text]
    if decoded_layers:
        for layer in decoded_layers:
            if layer.get('decoded'):
                texts_to_check.append(layer['decoded'])

    # Run YAML-based hard-block pattern detection
    for check_text in texts_to_check:
        yaml_signals = detect_hard_block_signals(check_text)
        for sig in yaml_signals:
            if sig['name'] not in seen:
                signals.append(sig)
                seen.add(sig['name'])

    # Run hardcoded benign context patterns
    for check_text in texts_to_check:
        for pattern, name, weight in BENIGN_CONTEXT_PATTERNS:
            if name in seen:
                continue
            match = pattern.search(check_text)
            if match:
                signals.append({
                    'name': name,
                    'weight': weight,
                    'evidence': match.group()[:80],
                })
                seen.add(name)

    # Run structural patterns
    for check_text in texts_to_check:
        for pattern, name, weight in STRUCTURAL_PATTERNS:
            if name in seen:
                continue
            match = pattern.search(check_text)
            if match:
                signals.append({
                    'name': name,
                    'weight': weight,
                    'evidence': match.group()[:80],
                })
                seen.add(name)

    # Add obfuscation-based signals if flags present
    if obfuscation_flags:
        if obfuscation_flags.get('mixed_script') and 'mixed_script_obfuscation' not in seen:
            signals.append({
                'name': 'mixed_script_obfuscation',
                'weight': 15,
                'evidence': f"scripts: {obfuscation_flags.get('scripts_detected', [])}",
            })
        if obfuscation_flags.get('base64_detected') and 'encoded_payload' not in seen:
            signals.append({
                'name': 'encoded_payload',
                'weight': 10,
                'evidence': 'base64 content detected',
            })

    return signals


def calculate_risk_score(signals: List[Signal]) -> int:
    """
    Calculate risk score from signals (sum of weights, capped at 100).
    Note: benign context signals have weight=0 so they don't add to risk.
    """
    return min(sum(s['weight'] for s in signals), 100)


def classify_risk(risk_score: int) -> str:
    """Classify risk level based on score."""
    if risk_score >= 50:
        return 'malicious'
    elif risk_score >= 25:
        return 'uncertain'
    return 'benign'


# =============================================================================
# HELPER FUNCTIONS FOR POLICY
# =============================================================================

# Signal categories for policy decisions
HARD_BLOCK_SIGNAL_NAMES = frozenset([
    'exfiltrate_system_prompt',
    'access_developer_mode',
])

HIGH_RISK_SIGNAL_NAMES = frozenset([
    'override_instructions',
    'disable_security',
    'role_confusion',
    'fake_system_tag',
    'delimiter_injection',
    'context_manipulation',
])

BENIGN_CONTEXT_SIGNAL_NAMES = frozenset([
    'benign_quotation_context',
    'benign_self_correction',
    'benign_analysis_intent',
])


def has_benign_context(signals: List[Signal]) -> bool:
    """Check if any benign context signals are present."""
    signal_names = {s.get('name', '') for s in signals}
    return bool(signal_names & BENIGN_CONTEXT_SIGNAL_NAMES)


def has_hard_block_signals(signals: List[Signal]) -> bool:
    """Check if any hard-block signals are present."""
    signal_names = {s.get('name', '') for s in signals}
    return bool(signal_names & HARD_BLOCK_SIGNAL_NAMES)


def has_imperative_structure(signals: List[Signal]) -> bool:
    """Check if imperative override structure is present (real attack indicator)."""
    signal_names = {s.get('name', '') for s in signals}
    return 'imperative_override_structure' in signal_names


def get_signal_names(signals: List[Signal]) -> set:
    """Extract signal names as a set."""
    return {s.get('name', '') for s in signals}
