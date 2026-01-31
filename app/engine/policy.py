"""
Policy decision engine - maps detection results to defense actions.

Upgrades vs previous version:
- Reduces false positives when the user is *quoting/discussing* injection phrases (e.g. “it says: ignore previous…”).
- Makes SANITIZE reachable for “mixed benign + injection” prompts by raising the hard BLOCK threshold.
- Keeps HARD BLOCK for prompt/system/developer exfiltration attempts.
- Treats mixed-script as an *escalator* (adds strictness) but not an automatic block at medium risk.
- Returns classification directly (so orchestrator can use it consistently).
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
# - Keep hard-block for explicit exfil signals regardless of score.
# - Raise block threshold so "override only" can sanitize/reprompt instead of always block.
THRESHOLD_BLOCK = 85
THRESHOLD_SANITIZE = 40

# If mixed-script obfuscation is present, we tighten thresholds slightly (escalation).
MIXED_SCRIPT_BLOCK_DELTA = 10
MIXED_SCRIPT_SANITIZE_DELTA = 5

# Benign discussion / quotation contexts that often include injection phrases safely.
# This is a pragmatic hackathon heuristic to reduce false positives.
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
    """
    Heuristic: user appears to be discussing/quoting an injection phrase,
    not issuing it as an instruction.
    """
    return bool(BENIGN_QUOTE_CONTEXT_RE.search(message))


def decide_action(
    risk_score: int,
    signals: List[Dict[str, Any]],
    sanitized_has_content: bool,
    obfuscation_flags: Dict[str, Any],
    message: str | None = None,
) -> Dict[str, Any]:
    """
    Decide defense action based on detection results.

    Returns a dict with:
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
    # Optional: context-aware downgrade for quoted/discussed injection phrases
    # -------------------------------------------------------------------------
    benign_quote = bool(message) and _is_benign_quote_context(message)

    # Example: user asks "In this text file it says: ignore previous instructions. What does that mean?"
    # We should not immediately block; ask them to clarify or treat as uncertain.
    if benign_quote:
        # If it's only an override-like phrase, reprompt rather than block/sanitize.
        # If there are multiple strong signals (e.g., disable_security + role_confusion), still act.
        high_risk_found = signal_names & HIGH_RISK_SIGNALS
        if high_risk_found and len(high_risk_found) == 1 and "override_instructions" in high_risk_found:
            return {
                "action": ACTION_REPROMPT,
                "reason": "Detected injection phrase in a likely quoted/discussion context; asking for clarification.",
                "classification": "uncertain",
            }

    # -------------------------------------------------------------------------
    # Escalate thresholds slightly if mixed-script obfuscation detected
    # -------------------------------------------------------------------------
    block_threshold = THRESHOLD_BLOCK
    sanitize_threshold = THRESHOLD_SANITIZE
    if obfuscation_flags.get("mixed_script") or obfuscation_flags.get("mixed_script_detected"):
        block_threshold = max(0, block_threshold - MIXED_SCRIPT_BLOCK_DELTA)
        sanitize_threshold = max(0, sanitize_threshold - MIXED_SCRIPT_SANITIZE_DELTA)

    # -------------------------------------------------------------------------
    # Rule 2: Multiple high-risk signals => block (high confidence)
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
        return {
            "action": ACTION_BLOCK,
            "reason": f"Risk score {risk_score} >= {block_threshold}",
            "classification": "malicious",
        }

    # -------------------------------------------------------------------------
    # Rule 4: Medium risk => sanitize or reprompt
    # -------------------------------------------------------------------------
    if risk_score >= sanitize_threshold:
        if sanitized_has_content:
            return {
                "action": ACTION_SANITIZE,
                "reason": "Medium risk; sanitizing detected injection-like segments while preserving task.",
                "classification": "uncertain",
            }
        return {
            "action": ACTION_REPROMPT,
            "reason": "Medium risk but sanitization removed too much content; requesting clean restatement.",
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
    Prefer using the classification returned by decide_action() for consistency.
    """
    if risk_score >= 60:
        return "malicious"
    if risk_score >= 30:
        return "uncertain"
    return "benign"