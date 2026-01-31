"""
Policy decision engine for prompt injection defense.

Features:
- Context-aware downgrade: reduces false positives for quoted/discussed phrases
- Structural awareness: real attacks have imperative structure
- Multi-turn escalation: repeated attempts trigger stricter responses
- Behavior-based escalation: historical patterns influence decisions
- (NEW) ML tie-breaker: logistic regression score used only in ambiguous cases

Actions: allow, sanitize, reprompt, block
"""

from __future__ import annotations

from typing import Any, Dict, List


# Action constants
ACTION_ALLOW = "allow"
ACTION_SANITIZE = "sanitize"
ACTION_REPROMPT = "reprompt"
ACTION_BLOCK = "block"

# Signal categories
HARD_BLOCK_SIGNALS = frozenset([
    "exfiltrate_system_prompt",
    "access_developer_mode",
])

HIGH_RISK_SIGNALS = frozenset([
    "override_instructions",
    "disable_security",
    "role_confusion",
    "fake_system_tag",
    "delimiter_injection",
])

BENIGN_CONTEXT_SIGNALS = frozenset([
    "benign_quotation_context",
    "benign_self_correction",
    "benign_analysis_intent",
])

# Base thresholds (dynamically adjusted based on context)
THRESHOLD_BLOCK = 85
THRESHOLD_SANITIZE = 40

# ML thresholds (used as tie-breaker; tuneable)
ML_BLOCK_THRESHOLD = 0.90
ML_SUSPICIOUS_THRESHOLD = 0.70


def decide_action(
    risk_score: int,
    signals: List[Dict[str, Any]],
    sanitized_has_content: bool,
    obfuscation_flags: Dict[str, Any],
    message: str | None = None,
    # Multi-turn context
    reprompt_count: int = 0,
    pivot_detected: bool = False,
    # Behavior counters (from orchestrator)
    behavior_counters: Dict[str, int] | None = None,
    # Context awareness (from orchestrator)
    has_benign_context: bool = False,
    has_imperative_structure: bool = False,
    # ML tie-breaker
    ml_score: float | None = None,
) -> Dict[str, Any]:
    """
    Decide defense action based on detection results and context.

    Returns dict with: action, reason, classification
    """
    signal_names = {s.get("name", "") for s in signals}
    behavior = behavior_counters or {}

    # -------------------------------------------------------------------------
    # Rule 0: HARD BLOCK on exfiltration/developer access (always)
    # -------------------------------------------------------------------------
    hard_block_found = signal_names & HARD_BLOCK_SIGNALS
    if hard_block_found:
        return {
            "action": ACTION_BLOCK,
            "reason": f"Hard block: {', '.join(sorted(hard_block_found))}",
            "classification": "malicious",
        }

    # -------------------------------------------------------------------------
    # Rule 1: Behavior escalation - prior exfil attempt makes us strict
    # -------------------------------------------------------------------------
    if behavior.get("repeat_exfil", 0) >= 1:
        if signal_names & HIGH_RISK_SIGNALS:
            return {
                "action": ACTION_BLOCK,
                "reason": "Prior exfiltration attempt + current high-risk signals",
                "classification": "malicious",
            }

    # -------------------------------------------------------------------------
    # Rule 2: Context-aware downgrade for quoted/discussed injection phrases
    # -------------------------------------------------------------------------
    has_override = "override_instructions" in signal_names
    has_other_high_risk = bool((signal_names & HIGH_RISK_SIGNALS) - {"override_instructions"})

    if has_benign_context and has_override and not has_other_high_risk:
        # If imperative structure is present, it looks like a real command
        if not has_imperative_structure:
            return {
                "action": ACTION_REPROMPT,
                "reason": "Override phrase in benign context (quotation/discussion/self-correction); requesting clarification.",
                "classification": "uncertain",
            }

        # -------------------------------------------------------------------------
    # Rule 2.5: ML tie-breaker (only when present)
    # -------------------------------------------------------------------------
    if ml_score is not None:
        # If ML is extremely confident it's an attack, escalate even if heuristics are mild.
        if ml_score >= ML_BLOCK_THRESHOLD:
            # If we don't have any heuristic anchors, "sanitize" can't remove anything safely.
            if not signal_names:
                return {
                    "action": ACTION_REPROMPT,
                    "reason": f"ML high confidence (p={ml_score:.2f}) but no heuristic anchors; requesting restatement.",
                    "classification": "malicious",
                }

            if sanitized_has_content:
                return {
                    "action": ACTION_SANITIZE,
                    "reason": f"ML high confidence (p={ml_score:.2f}); sanitizing suspicious segments.",
                    "classification": "malicious",
                }
            return {
                "action": ACTION_BLOCK,
                "reason": f"ML high confidence (p={ml_score:.2f}); blocking.",
                "classification": "malicious",
            }

        if ml_score >= ML_SUSPICIOUS_THRESHOLD and risk_score >= 20:
            if sanitized_has_content:
                return {
                    "action": ACTION_SANITIZE,
                    "reason": f"ML suspicious (p={ml_score:.2f}) + elevated risk; sanitizing.",
                    "classification": "uncertain",
                }
            return {
                "action": ACTION_REPROMPT,
                "reason": f"ML suspicious (p={ml_score:.2f}) + elevated risk; requesting restatement.",
                "classification": "uncertain",
            }

    # -------------------------------------------------------------------------
    # Compute dynamic thresholds
    # -------------------------------------------------------------------------
    block_threshold = THRESHOLD_BLOCK
    sanitize_threshold = THRESHOLD_SANITIZE

    if obfuscation_flags.get("mixed_script") or obfuscation_flags.get("mixed_script_detected"):
        block_threshold -= 10
        sanitize_threshold -= 5

    if pivot_detected:
        block_threshold -= 15
        sanitize_threshold -= 10

    if reprompt_count >= 2:
        block_threshold -= 10
        sanitize_threshold -= 5

    if behavior.get("repeat_override", 0) >= 2:
        block_threshold -= 10
        sanitize_threshold -= 5

    if has_imperative_structure:
        block_threshold -= 10
        sanitize_threshold -= 5

    block_threshold = max(45, block_threshold)
    sanitize_threshold = max(20, sanitize_threshold)

    # -------------------------------------------------------------------------
    # Rule 3: Multiple high-risk signals => block
    # -------------------------------------------------------------------------
    high_risk_found = signal_names & HIGH_RISK_SIGNALS
    if len(high_risk_found) >= 2:
        return {
            "action": ACTION_BLOCK,
            "reason": f"Multiple high-risk signals: {', '.join(sorted(high_risk_found))}",
            "classification": "malicious",
        }

    # -------------------------------------------------------------------------
    # Rule 4: Very high risk score => block
    # -------------------------------------------------------------------------
    if risk_score >= block_threshold:
        reason = f"Risk score {risk_score} >= {block_threshold}"
        if pivot_detected:
            reason += " (pivot detected)"
        if has_imperative_structure:
            reason += " (imperative structure)"
        return {
            "action": ACTION_BLOCK,
            "reason": reason,
            "classification": "malicious",
        }

    # -------------------------------------------------------------------------
    # Rule 5: Medium risk => sanitize or reprompt
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
    # Rule 6: Low risk but with benign context signals => allow (only if no high-risk)
    # -------------------------------------------------------------------------
    if has_benign_context and risk_score > 0 and not (signal_names & HIGH_RISK_SIGNALS):
        return {
            "action": ACTION_ALLOW,
            "reason": "Low risk with benign context (quotation/analysis/self-correction).",
            "classification": "benign",
        }

    # -------------------------------------------------------------------------
    # Rule 7: Low risk => allow
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