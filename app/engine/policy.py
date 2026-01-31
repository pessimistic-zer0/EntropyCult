# app/engine/policy.py
"""
Policy decision engine - maps detection results to defense actions.
"""

from typing import Dict, Any, List

# Action constants
ACTION_ALLOW = "allow"
ACTION_SANITIZE = "sanitize"
ACTION_REPROMPT = "reprompt"
ACTION_BLOCK = "block"

# Signals that trigger HARD BLOCK
HARD_BLOCK_SIGNALS = frozenset(['exfiltrate_system_prompt', 'access_developer_mode'])

# High risk signals
HIGH_RISK_SIGNALS = frozenset(['override_instructions', 'disable_security', 'role_confusion'])

# Thresholds
THRESHOLD_BLOCK = 60
THRESHOLD_SANITIZE = 30


def decide_action(
    risk_score: int,
    signals: List[Dict[str, Any]],
    sanitized_has_content: bool,
    obfuscation_flags: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Decide defense action based on detection results.
    Returns: {action, reason}
    """
    signal_names = {s['name'] for s in signals}

    # Rule 1: Hard block on exfiltration/developer access
    hard_block_found = signal_names & HARD_BLOCK_SIGNALS
    if hard_block_found:
        return {'action': ACTION_BLOCK, 'reason': f"Hard block: {', '.join(hard_block_found)}"}

    # Rule 2: Block on high risk score
    if risk_score >= THRESHOLD_BLOCK:
        return {'action': ACTION_BLOCK, 'reason': f"Risk score {risk_score} >= {THRESHOLD_BLOCK}"}

    # Rule 3: Block if multiple high-risk signals
    high_risk_found = signal_names & HIGH_RISK_SIGNALS
    if len(high_risk_found) >= 2:
        return {'action': ACTION_BLOCK, 'reason': f"Multiple high-risk: {', '.join(high_risk_found)}"}

    # Rule 4: Medium risk + mixed-script = block
    if risk_score >= THRESHOLD_SANITIZE and obfuscation_flags.get('mixed_script'):
        return {'action': ACTION_BLOCK, 'reason': "Medium risk + mixed-script obfuscation"}

    # Rule 5: Medium risk -> sanitize or reprompt
    if risk_score >= THRESHOLD_SANITIZE:
        if sanitized_has_content:
            return {'action': ACTION_SANITIZE, 'reason': "Sanitizing detected patterns"}
        return {'action': ACTION_REPROMPT, 'reason': "No content after sanitization"}

    # Rule 6: Low risk -> allow
    return {'action': ACTION_ALLOW, 'reason': "No significant threats"}


def get_classification(risk_score: int) -> str:
    """Map risk score to classification label."""
    if risk_score >= 50:
        return "malicious"
    elif risk_score >= 25:
        return "uncertain"
    return "benign"
