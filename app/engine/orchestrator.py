# app/engine/orchestrator.py
"""
Main orchestrator for the defense gateway pipeline.

Pipeline (multi-turn enabled):
  1. Retrieve conversation history
  2. Preprocess current message
  3. Detect signals on current message
  4. Detect signals on history context (separately)
  5. Compute history_pressure + effective_risk
  6. Detect pivot behavior
  7. Sanitize (prepare candidate)
  8. Policy decision (with escalation)
  9. Store turn + mark action
  10. Return response with explainability

This is the single entrypoint used by the API route:
  analyze_message(conversation_id, message, attachments) -> dict
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.engine.utils import Timer, log_request
from app.engine.preprocess import preprocess
from app.engine.signals import detect_signals, calculate_risk_score
from app.engine.sanitize import (
    sanitize_message,
    has_meaningful_content,
    get_reprompt_message,
)
from app.engine.policy import decide_action, get_classification
from app.engine.memory import conversation_store


# Multi-turn configuration
MAX_HISTORY_TURNS = 6        # How many past turns to analyze
HISTORY_PRESSURE_CAP = 20    # Max pressure from history
HIGH_RISK_SIGNAL_NAMES = frozenset([
    "override_instructions",
    "disable_security",
    "role_confusion",
    "exfiltrate_system_prompt",
    "access_developer_mode",
])


def _compute_history_pressure(history_turns: List[Dict]) -> int:
    """
    Compute pressure score from conversation history.
    +5 for each turn containing high-risk signals, capped at HISTORY_PRESSURE_CAP.
    """
    pressure = 0
    for turn in history_turns:
        turn_signals = set(turn.get("signals", []))
        if turn_signals & HIGH_RISK_SIGNAL_NAMES:
            pressure += 5
    return min(pressure, HISTORY_PRESSURE_CAP)


def _detect_pivot(
    history_turns: List[Dict],
    current_signals: List[Dict],
    current_risk: int
) -> bool:
    """
    Detect a "pivot" attack: benign history followed by high-risk current message.
    Returns True if pivot pattern detected.
    """
    if not history_turns:
        return False  # No history, can't be a pivot

    # Check if history was mostly benign (no high-risk signals)
    history_had_high_risk = False
    for turn in history_turns[-3:]:  # Check last 3 turns
        turn_signals = set(turn.get("signals", []))
        if turn_signals & HIGH_RISK_SIGNAL_NAMES:
            history_had_high_risk = True
            break

    # Current message is high-risk
    current_signal_names = {s.get("name", "") for s in current_signals}
    current_is_high_risk = bool(current_signal_names & HIGH_RISK_SIGNAL_NAMES)

    # Pivot = history was clean, current is dangerous
    if not history_had_high_risk and current_is_high_risk and current_risk >= 40:
        return True

    return False


def _apply_escalation(
    action: str,
    reprompt_count: int,
    current_risk: int,
    signals: List[Dict]
) -> str:
    """
    Apply escalation rules based on repeated actions.
    - If reprompted 2+ times and still medium/high risk → escalate
    """
    if reprompt_count >= 2 and current_risk >= 30:
        # Escalate reprompt → sanitize or block
        if action == "reprompt":
            return "sanitize"
        elif action == "sanitize" and current_risk >= 50:
            return "block"
    return action


def analyze_message(
    conversation_id: str,
    message: str,
    attachments: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Main entry point for the defense gateway.
    Returns dict matching AnalyzeResponse schema.
    """
    timer = Timer()
    timer.start()

    # =========================================================================
    # Stage 0: Retrieve conversation history
    # =========================================================================
    with timer.stage("history_fetch"):
        history_turns = conversation_store.get_last_turns(
            conversation_id, max_turns=MAX_HISTORY_TURNS
        )
        conv_stats = conversation_store.get_stats(conversation_id)
        reprompt_count = conv_stats.get("reprompt_count", 0)
        recent_signals = conversation_store.get_recent_signals(conversation_id, max_turns=3)

    # =========================================================================
    # Stage 1: Preprocessing / Deobfuscation (current message)
    # =========================================================================
    with timer.stage("preprocess"):
        prep_result = preprocess(message)
        clean_text: str = prep_result["clean_text"]
        decoded_layers = prep_result.get("decoded_layers", [])
        obfuscation_flags: Dict[str, Any] = prep_result["obfuscation_flags"]

    # =========================================================================
    # Stage 2: Signal Detection on CURRENT message
    # =========================================================================
    with timer.stage("signals_current"):
        current_signals = detect_signals(clean_text, decoded_layers)
        current_risk = calculate_risk_score(current_signals)

    # =========================================================================
    # Stage 3: Signal Detection on HISTORY context (separate analysis)
    # =========================================================================
    with timer.stage("signals_history"):
        history_context = conversation_store.get_context_text(
            conversation_id, max_turns=MAX_HISTORY_TURNS
        )
        if history_context:
            # Light analysis of history - just detect signals, no preprocessing
            history_signals = detect_signals(history_context, [])
            history_risk = calculate_risk_score(history_signals)
        else:
            history_signals = []
            history_risk = 0

    # =========================================================================
    # Stage 4: Compute history pressure + effective risk
    # =========================================================================
    history_pressure = _compute_history_pressure(history_turns)
    effective_risk = min(100, current_risk + history_pressure)

    # =========================================================================
    # Stage 5: Pivot detection
    # =========================================================================
    pivot_detected = _detect_pivot(history_turns, current_signals, current_risk)
    if pivot_detected:
        # Boost effective risk on pivot
        effective_risk = min(100, effective_risk + 15)

    # =========================================================================
    # Stage 6: Sanitization (prepare candidate)
    # =========================================================================
    with timer.stage("sanitize"):
        sanitized_text, was_sanitized, removed_patterns = sanitize_message(
            clean_text, current_signals
        )
        sanitized_has_content = has_meaningful_content(sanitized_text)

    # =========================================================================
    # Stage 7: Policy Decision (using effective_risk)
    # =========================================================================
    with timer.stage("policy"):
        decision = decide_action(
            risk_score=effective_risk,  # Use effective risk, not raw
            signals=current_signals,
            sanitized_has_content=sanitized_has_content,
            obfuscation_flags=obfuscation_flags,
            message=message,
            # Pass multi-turn context for advanced policy
            reprompt_count=reprompt_count,
            pivot_detected=pivot_detected,
        )
        action = decision["action"]
        classification = decision.get("classification", get_classification(effective_risk))

    # =========================================================================
    # Stage 8: Apply escalation rules
    # =========================================================================
    original_action = action
    action = _apply_escalation(action, reprompt_count, current_risk, current_signals)
    if action != original_action:
        decision["reason"] = f"Escalated from {original_action} (reprompt_count={reprompt_count})"

    # =========================================================================
    # Stage 9: Store turn + mark action
    # =========================================================================
    with timer.stage("memory_store"):
        # Store the user turn with detected signals
        signal_names = [s.get("name", "") for s in current_signals]
        conversation_store.add_turn(
            conversation_id,
            role="user",
            text=message,
            signals=signal_names
        )
        # Track action for escalation
        conversation_store.mark_action(conversation_id, action)

    # =========================================================================
    # Build Response with multi-turn explainability
    # =========================================================================

    # Add multi-turn metadata to obfuscation_flags (keeps schema compatible)
    obfuscation_flags["multi_turn_enabled"] = True
    obfuscation_flags["turns_used"] = len(history_turns)
    obfuscation_flags["history_pressure"] = history_pressure
    obfuscation_flags["effective_risk_score"] = effective_risk
    obfuscation_flags["current_risk_score"] = current_risk
    obfuscation_flags["pivot_detected"] = pivot_detected
    obfuscation_flags["reprompt_count"] = reprompt_count
    obfuscation_flags["recent_signal_names"] = recent_signals

    response: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "action": action,
        "classification": classification,
        "risk_score": effective_risk,  # Report effective risk as main score
        "signals": current_signals,
        "obfuscation_flags": obfuscation_flags,
        "sanitized_message": sanitized_text if action == "sanitize" else None,
        "reprompt_message": get_reprompt_message() if action == "reprompt" else None,
        "latency_ms": timer.results(),
    }

    # Log the request
    log_request(conversation_id, action, effective_risk, current_signals)

    return response
