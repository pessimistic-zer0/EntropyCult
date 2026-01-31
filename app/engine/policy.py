# app/engine/policy.py
"""
Policy decision engine for prompt injection defense.
Maps detection results to defense actions: allow, sanitize, reprompt, block.

Features:
- Reduces false positives for quoted/discussed injection phrases
- Supports multi-turn context (reprompt_count, pivot_detected)
- Escalation rules for persistent attackers
- Returns classification directly for consistency
"""

from __future__ import annotations

import re
from typing import Any, Dict, List


# Action constants
ACTION_ALLOW = "allow"
ACTION_SANITIZE = "sanitize"
ACTION_REPROMPT = "reprompt"
ACTION_BLOCK = "block"

# Signals that trigger HARD BLOCK (high confidence malicious intent)
HARD_BLOCK_SIGNALS = frozenset(["exfiltrate_system_prompt", "access_developer_mode"])

# High risk signals (not always hard block by themselves)
HIGH_RISK_SIGNALS = frozenset(["override_instructions", "disable_security", "role_confusion"])

# Thresholds (tuneable)
THRESHOLD_BLOCK = 85
THRESHOLD_SANITIZE = 40

# Mixed-script escalation
MIXED_SCRIPT_BLOCK_DELTA = 10
MIXED_SCRIPT_SANITIZE_DELTA = 5

# Pivot escalation
PIVOT_BLOCK_DELTA = 15
PIVOT_SANITIZE_DELTA = 10

# Benign discussion / quotation contexts
BENIGN_QUOTE_CONTEXT_RE = re.compile(
    r"\b("
    r"what does that mean|"
    r"what does this mean|"
    r"meaning of|"
    r"explain|"
    r"definition|"
    r"in this (text|file|document|log)|"
    r"it says|"
    r"the string|"
    r"this phrase|"
    r"quoted|"
    r"example|"
    r"for research|"
    r"for analysis|"
    r"how does prompt injection work"
    r")\b",
    re.I,
)


def _is_benign_quote_context(message: str) -> bool:
    """Check if user is discussing/quoting an injection phrase."""
    return bool(BENIGN_QUOTE_CONTEXT_RE.search(message))


def decide_action(
    risk_score: int,
    signals: List[Dict[str, Any]],
    sanitized_has_content: bool,
    obfuscation_flags: Dict[str, Any],
    message: str | None = None,
    # Multi-turn context (optional for backwards compatibility)
    reprompt_count: int = 0,
    pivot_detected: bool = False,
) -> Dict[str, Any]:
    """
    Decide defense action based on detection results.

    Args:
        risk_score: The effective risk score (may include history pressure)
        signals: Current message signals
        sanitized_has_content: Whether sanitized message has meaningful content
        obfuscation_flags: Detected obfuscation techniques
        message: Original message (for quote context detection)
        reprompt_count: Number of times user was reprompted (for escalation)
        pivot_detected: Whether a benign→malicious pivot was detected

    Returns dict with:
        - action: allow|sanitize|reprompt|block
        - reason: human-readable reason
        - classification: benign|uncertain|malicious
    """
    signal_names = {s.get("name", "") for s in signals}

    # -------------------------------------------------------------------------
    # Rule 1: Hard block on exfiltration/developer access (always malicious)
    # -------------------------------------------------------------------------
    hard_block_found = signal_names & HARD_BLOCK_SIGNALS
    if hard_block_found:
        return {
            "action": ACTION_BLOCK,
            "reason": f"Hard block: {', '.join(sorted(hard_block_found))}",
            "classification": "malicious",
        }

    # -------------------------------------------------------------------------
    # Context-aware downgrade for quoted/discussed injection phrases
    # -------------------------------------------------------------------------
    benign_quote = bool(message) and _is_benign_quote_context(message)

    if benign_quote and not pivot_detected:
        high_risk_found = signal_names & HIGH_RISK_SIGNALS
        if high_risk_found and len(high_risk_found) == 1 and "override_instructions" in high_risk_found:
            return {
                "action": ACTION_REPROMPT,
                "reason": "Injection phrase in likely quoted context; asking for clarification.",
                "classification": "uncertain",
            }

    # -------------------------------------------------------------------------
    # Compute dynamic thresholds based on context
    # -------------------------------------------------------------------------
    block_threshold = THRESHOLD_BLOCK
    sanitize_threshold = THRESHOLD_SANITIZE

    # Tighten thresholds for mixed-script obfuscation
    if obfuscation_flags.get("mixed_script") or obfuscation_flags.get("mixed_script_detected"):
        block_threshold -= MIXED_SCRIPT_BLOCK_DELTA
        sanitize_threshold -= MIXED_SCRIPT_SANITIZE_DELTA

    # Tighten thresholds significantly on pivot (sneaky attack pattern)
    if pivot_detected:
        block_threshold -= PIVOT_BLOCK_DELTA
        sanitize_threshold -= PIVOT_SANITIZE_DELTA

    # Tighten on repeated reprompts (escalation)
    if reprompt_count >= 2:
        block_threshold -= 10
        sanitize_threshold -= 5

    # Ensure thresholds stay reasonable
    block_threshold = max(50, block_threshold)
    sanitize_threshold = max(20, sanitize_threshold)

    # -------------------------------------------------------------------------
    # Rule 2: Multiple high-risk signals => block
    # -------------------------------------------------------------------------
    high_risk_found = signal_names & HIGH_RISK_SIGNALS
    if len(high_risk_found) >= 2:
        return {
            "action": ACTION_BLOCK,
            "reason": f"Multiple high-risk signals: {', '.join(sorted(high_risk_found))}",
            "classification": "malicious",
        }

    # -------------------------------------------------------------------------
    # Rule 3: Very high risk score => block
    # -------------------------------------------------------------------------
    if risk_score >= block_threshold:
        reason = f"Risk score {risk_score} >= {block_threshold}"
        if pivot_detected:
            reason += " (pivot detected)"
        return {
            "action": ACTION_BLOCK,
            "reason": reason,
            "classification": "malicious",
        }

    # -------------------------------------------------------------------------
    # Rule 4: Medium risk => sanitize or reprompt
    # -------------------------------------------------------------------------
    if risk_score >= sanitize_threshold:
        if sanitized_has_content:
            return {
                "action": ACTION_SANITIZE,
                "reason": "Medium risk; sanitizing while preserving task.",
                "classification": "uncertain",
            }
        return {
            "action": ACTION_REPROMPT,
            "reason": "Medium risk but no content after sanitization.",
            "classification": "uncertain",
        }

    # -------------------------------------------------------------------------
    # Rule 5: Low risk => allow
    # -------------------------------------------------------------------------
    return {
        "action": ACTION_ALLOW,
        "reason": "No significant threats detected.",
        "classification": "benign",
    }


def get_classification(risk_score: int) -> str:
    """
    Backwards-compatible helper.
    Prefer using the classification returned by decide_action().
    """
    if risk_score >= 60:
        return "malicious"
    if risk_score >= 30:
        return "uncertain"
    return "benign"