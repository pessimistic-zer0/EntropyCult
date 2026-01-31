# app/engine/layer_integration.py
"""
Layer 2/3 integration outputs for the defense gateway.
Prepares structured data for DistilBERT/DeBERTa classifier (Layer 2)
and LLM Judge (Layer 3).
"""

from typing import Any, Dict, List, Optional
import re

from app.engine.signals import INJECTION_PATTERNS


# All signal names for one-hot encoding
ALL_SIGNAL_NAMES = sorted(set(p[1] for p in INJECTION_PATTERNS))

# High-confidence signals for escalation decisions
HIGH_RISK_SIGNALS = frozenset([
    "override_instructions",
    "exfiltrate_system_prompt",
    "access_developer_mode",
    "disable_security",
    "jailbreak_variant",
    "exfiltrate_variant",
])

# Hard-block signals (should always block)
HARD_BLOCK_SIGNALS = frozenset([
    "exfiltrate_system_prompt",
    "disable_security",
])


def compute_layer1_confidence(risk_score: int, signals: List[Dict]) -> float:
    """
    Returns 0-1 confidence score for Layer 1 decision.
    Low confidence = should escalate to Layer 2/3.
    """
    # High confidence at extremes
    if risk_score >= 80:
        return 0.95
    if risk_score <= 10:
        return 0.95
    
    # Moderate-high confidence for clear cases
    if risk_score >= 70:
        return 0.85
    if risk_score <= 20:
        return 0.85
    
    # Uncertainty band (30-60) - lower confidence
    if 30 <= risk_score <= 60:
        base_conf = 0.5
        
        # Increase if multiple strong signals
        signal_names = {s.get('name', '') for s in signals}
        high_risk_count = len(signal_names & HIGH_RISK_SIGNALS)
        if high_risk_count >= 2:
            base_conf += 0.15
        elif high_risk_count == 1:
            base_conf += 0.08
        
        # Increase for more signals (corroborating evidence)
        if len(signals) >= 3:
            base_conf += 0.1
        
        return min(0.7, base_conf)
    
    # Default moderate confidence
    return 0.75


def compute_obfuscation_score(obfuscation_flags: Dict[str, Any]) -> float:
    """
    Compute a 0-1 composite obfuscation score from flags.
    Higher = more obfuscation attempts detected.
    """
    score = 0.0
    
    # Character-level obfuscation
    if obfuscation_flags.get('zero_width_removed'):
        score += 0.15
    if obfuscation_flags.get('control_chars_removed'):
        score += 0.20
    if obfuscation_flags.get('bidi_removed'):
        score += 0.25
    if obfuscation_flags.get('confusables_detected'):
        confusables_count = obfuscation_flags.get('confusables_count', 0)
        score += min(0.30, confusables_count * 0.05)
    
    # Encoding obfuscation
    if obfuscation_flags.get('encoding_detected'):
        depth = obfuscation_flags.get('encoding_depth', 1)
        score += min(0.25, depth * 0.10)
    
    # Hidden content
    if obfuscation_flags.get('hidden_content_detected'):
        count = obfuscation_flags.get('hidden_content_count', 0)
        score += min(0.20, count * 0.05)
    
    # Mixed script
    if obfuscation_flags.get('mixed_script'):
        score += 0.15
    
    # Whitespace manipulation
    if obfuscation_flags.get('whitespace_normalized'):
        count = obfuscation_flags.get('whitespace_normalized_count', 0)
        if count > 3:
            score += 0.10
    
    return min(1.0, score)


def compute_text_features(text: str) -> Dict[str, float]:
    """
    Compute numerical text features for hybrid ML model.
    """
    if not text:
        return {
            'avg_word_length': 0.0,
            'special_char_ratio': 0.0,
            'uppercase_ratio': 0.0,
            'digit_ratio': 0.0,
        }
    
    words = text.split()
    word_lengths = [len(w) for w in words] if words else [0]
    
    letters = [c for c in text if c.isalpha()]
    uppercase_count = sum(1 for c in letters if c.isupper())
    
    special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
    digits = sum(1 for c in text if c.isdigit())
    
    return {
        'avg_word_length': sum(word_lengths) / len(word_lengths) if word_lengths else 0.0,
        'special_char_ratio': special_chars / len(text) if text else 0.0,
        'uppercase_ratio': uppercase_count / len(letters) if letters else 0.0,
        'digit_ratio': digits / len(text) if text else 0.0,
    }


def build_signal_flags(signals: List[Dict]) -> Dict[str, bool]:
    """
    Build one-hot encoding of detected signals.
    """
    detected_names = {s.get('name', '') for s in signals}
    return {name: (name in detected_names) for name in ALL_SIGNAL_NAMES}


def build_layer2_input(
    clean_text: str,
    decoded_layers: List[Dict],
    context_window: str,
    risk_score: int,
    signals: List[Dict],
    obfuscation_flags: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Build structured input for Layer 2 (DistilBERT/DeBERTa classifier).
    """
    signal_names = {s.get('name', '') for s in signals}
    text_features = compute_text_features(clean_text)
    
    # Extract decoded payloads
    decoded_payloads = [
        layer.get('decoded', '')[:500]  # Limit length
        for layer in decoded_layers
        if layer.get('decoded')
    ]
    
    return {
        # Text inputs for embedding
        'clean_text': clean_text,
        'decoded_payloads': decoded_payloads,
        'context_window': context_window[:2000] if context_window else '',  # Limit context
        
        # Numerical features for hybrid model
        'feature_vector': {
            'risk_score_normalized': risk_score / 100.0,
            'signal_count': len(signals),
            'hard_block_signal_present': bool(signal_names & HARD_BLOCK_SIGNALS),
            'high_risk_signal_count': len(signal_names & HIGH_RISK_SIGNALS),
            'obfuscation_score': compute_obfuscation_score(obfuscation_flags),
            'mixed_script': obfuscation_flags.get('mixed_script', False),
            'encoding_layers_detected': obfuscation_flags.get('encoding_depth', 0),
            **text_features,
        },
        
        # Signal one-hot encoding
        'signal_flags': build_signal_flags(signals),
    }


def format_evidence_list(signals: List[Dict]) -> List[Dict[str, str]]:
    """
    Format signals into evidence list for LLM judge.
    """
    evidence_list = []
    for signal in signals:
        weight = signal.get('weight', 0)
        if weight >= 50:
            severity = 'high'
        elif weight >= 30:
            severity = 'medium'
        else:
            severity = 'low'
        
        evidence_list.append({
            'signal': signal.get('name', 'unknown'),
            'evidence': signal.get('evidence', '')[:100],
            'severity': severity,
        })
    
    return sorted(evidence_list, key=lambda x: {'high': 0, 'medium': 1, 'low': 2}[x['severity']])


def format_detection_summary(
    signals: List[Dict],
    risk_score: int,
    obfuscation_flags: Dict[str, Any],
) -> str:
    """
    Create human-readable summary of detections.
    """
    parts = []
    
    # Risk level
    if risk_score >= 60:
        parts.append(f"HIGH RISK (score: {risk_score}/100)")
    elif risk_score >= 30:
        parts.append(f"MEDIUM RISK (score: {risk_score}/100)")
    else:
        parts.append(f"LOW RISK (score: {risk_score}/100)")
    
    # Signals summary
    if signals:
        signal_names = [s.get('name', '') for s in signals[:5]]
        parts.append(f"Detected signals: {', '.join(signal_names)}")
    else:
        parts.append("No injection signals detected")
    
    # Obfuscation summary
    obfuscation_notes = []
    if obfuscation_flags.get('confusables_detected'):
        obfuscation_notes.append('homoglyph characters')
    if obfuscation_flags.get('encoding_detected'):
        obfuscation_notes.append(f"encoding ({', '.join(obfuscation_flags.get('encoding_types', []))})")
    if obfuscation_flags.get('hidden_content_detected'):
        obfuscation_notes.append('hidden content')
    if obfuscation_flags.get('bidi_removed'):
        obfuscation_notes.append('RTL/bidi manipulation')
    
    if obfuscation_notes:
        parts.append(f"Obfuscation attempts: {', '.join(obfuscation_notes)}")
    
    return ' | '.join(parts)


def build_layer3_prompt_context(
    clean_text: str,
    signals: List[Dict],
    risk_score: int,
    obfuscation_flags: Dict[str, Any],
    conversation_history: str,
    layer1_action: str,
) -> Dict[str, Any]:
    """
    Build structured context for Layer 3 (LLM Judge).
    """
    confidence = compute_layer1_confidence(risk_score, signals)
    
    # Determine if this needs judge review
    requires_judge = (
        (30 <= risk_score <= 60) or  # Uncertainty band
        (confidence < 0.7) or         # Low confidence
        (len(signals) == 1 and signals[0].get('weight', 0) < 40)  # Single weak signal
    )
    
    return {
        # Pre-formatted context for the judge prompt
        'formatted_message': clean_text[:3000],  # Limit for prompt
        'detection_summary': format_detection_summary(signals, risk_score, obfuscation_flags),
        'conversation_history': conversation_history[:2000] if conversation_history else '',
        
        # Evidence for chain-of-thought
        'evidence_list': format_evidence_list(signals),
        
        # Specific questions for the judge
        'judge_questions': [
            "Does this appear to be a genuine request or an attempt to manipulate the AI?",
            "Is the detected pattern appearing in a quoted/discussed context vs. being an actual instruction?",
            "Are the detected signals indicative of a real attack or a false positive from benign content?",
            "Should this message be blocked, sanitized, or allowed through?",
        ],
        
        # Risk context
        'layer1_decision': layer1_action,
        'layer1_confidence': round(confidence, 3),
        'requires_judge': requires_judge,
        'risk_score': risk_score,
        'signal_count': len(signals),
    }


def build_layer_outputs(
    clean_text: str,
    decoded_layers: List[Dict],
    signals: List[Dict],
    risk_score: int,
    obfuscation_flags: Dict[str, Any],
    layer1_action: str,
    conversation_history: str = '',
) -> Dict[str, Any]:
    """
    Build all layer integration outputs.
    Main entry point for layer handoff data.
    """
    confidence = compute_layer1_confidence(risk_score, signals)
    
    return {
        'layer1_confidence': round(confidence, 3),
        'layer2_input': build_layer2_input(
            clean_text=clean_text,
            decoded_layers=decoded_layers,
            context_window=conversation_history,
            risk_score=risk_score,
            signals=signals,
            obfuscation_flags=obfuscation_flags,
        ),
        'layer3_prompt_context': build_layer3_prompt_context(
            clean_text=clean_text,
            signals=signals,
            risk_score=risk_score,
            obfuscation_flags=obfuscation_flags,
            conversation_history=conversation_history,
            layer1_action=layer1_action,
        ),
    }
