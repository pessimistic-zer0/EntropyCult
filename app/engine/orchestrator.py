"""
Main orchestrator for the defense gateway pipeline.

Pipeline (multi-turn + contextual intent + ML tie-breaker):
  1. Retrieve conversation history + behavior stats
  2. Preprocess current message
  3. Detect signals (including benign context signals)
  4. Detect signals on history context (separately)
  5. Compute history pressure + effective risk
  6. (NEW) Compute ML injection probability (gray-zone only, fail-open)
  7. Compute behavior escalation counters
  8. Detect pivot behavior
  9. Sanitize (prepare candidate)
  10. Policy decision (with context awareness + escalation + ML tie-breaker)
  11. Store turn + mark action
  12. Return response with full explainability
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional

from app.engine.ml import score_injection_probability
from app.engine.utils import Timer, log_request
from app.engine.preprocess import preprocess
from app.engine.patterns import check_soft_cues
from app.engine.signals import (
    detect_signals,
    calculate_risk_score,
    has_benign_context,
    has_imperative_structure,
    get_signal_names,
    HIGH_RISK_SIGNAL_NAMES,
)
from app.engine.sanitize import (
    sanitize_message,
    has_meaningful_content,
    get_reprompt_message,
)
from app.engine.policy import decide_action, get_classification
from app.engine.memory import conversation_store


# Multi-turn configuration
MAX_HISTORY_TURNS = 8        # How many past turns to analyze
HISTORY_PRESSURE_CAP = 20    # Max pressure from history

# ML configuration (gray-zone only)
ML_GRAYZONE_MIN = 20
ML_GRAYZONE_MAX = 80


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


def _compute_behavior_counters(history_turns: List[Dict]) -> Dict[str, int]:
    """
    Compute behavioral escalation counters from conversation history.
    Returns counts of specific patterns across recent turns.
    """
    repeat_override = 0
    repeat_exfil = 0
    high_risk_turns = 0

    for turn in history_turns:
        turn_signals = set(turn.get("signals", []))

        if "override_instructions" in turn_signals:
            repeat_override += 1

        if "exfiltrate_system_prompt" in turn_signals:
            repeat_exfil += 1

        if turn_signals & HIGH_RISK_SIGNAL_NAMES:
            high_risk_turns += 1

    return {
        "repeat_override": repeat_override,
        "repeat_exfil": repeat_exfil,
        "high_risk_turns": high_risk_turns,
    }


def _detect_pivot(
    history_turns: List[Dict],
    current_signals: List[Dict],
    current_risk: int
) -> bool:
    """
    Detect a "pivot" attack: benign history followed by high-risk current message.
    """
    if not history_turns:
        return False

    # If current message is clearly benign context (quoting/discussing) and not imperative,
    # don't treat it as a pivot.
    if has_benign_context(current_signals) and not has_imperative_structure(current_signals):
        return False

    # Check if recent history was mostly benign
    history_had_high_risk = False
    for turn in history_turns[-3:]:
        turn_signals = set(turn.get("signals", []))
        if turn_signals & HIGH_RISK_SIGNAL_NAMES:
            history_had_high_risk = True
            break

    # Current message has high-risk signals
    current_signal_names = get_signal_names(current_signals)
    current_is_high_risk = bool(current_signal_names & HIGH_RISK_SIGNAL_NAMES)

    # Pivot = history was clean, current is dangerous
    if not history_had_high_risk and current_is_high_risk and current_risk >= 40:
        return True

    return False


def _apply_escalation(
    action: str,
    reprompt_count: int,
    behavior_counters: Dict[str, int],
    current_risk: int,
) -> str:
    """
    Apply escalation rules based on repeated behavior patterns.
    """
    repeat_override = behavior_counters.get("repeat_override", 0)
    repeat_exfil = behavior_counters.get("repeat_exfil", 0)

    # Escalate if repeated reprompts and still risky
    if reprompt_count >= 2 and current_risk >= 30:
        if action == "reprompt":
            return "sanitize"
        elif action == "sanitize" and current_risk >= 50:
            return "block"

    # Escalate if repeated override attempts
    if repeat_override >= 2 and action in ("allow", "reprompt"):
        return "sanitize"

    # Hard escalate if any prior exfil attempt
    if repeat_exfil >= 1 and current_risk >= 25:
        if action in ("allow", "reprompt", "sanitize"):
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
    # Stage 0: Retrieve conversation history + stats
    # =========================================================================
    with timer.stage("history_fetch"):
        history_turns = conversation_store.get_last_turns(
            conversation_id, max_turns=MAX_HISTORY_TURNS
        )
        conv_stats = conversation_store.get_stats(conversation_id)
        reprompt_count = conv_stats.get("reprompt_count", 0)
        block_count = conv_stats.get("block_count", 0)

        # Compute behavior counters for escalation
        behavior_counters = _compute_behavior_counters(history_turns)

        # Get recent signals for explainability
        recent_signals = conversation_store.get_recent_signals(conversation_id, max_turns=3)

    # =========================================================================
    # Stage 1: Preprocessing / Deobfuscation
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
        current_signals = detect_signals(clean_text, decoded_layers, obfuscation_flags)
        current_risk = calculate_risk_score(current_signals)

        # Extract context awareness flags
        has_benign_ctx = has_benign_context(current_signals)
        has_imperative = has_imperative_structure(current_signals)

    # =========================================================================
    # Stage 3: Signal Detection on HISTORY context (optional, kept for now)
    # =========================================================================
    with timer.stage("signals_history"):
        history_context = conversation_store.get_context_text(
            conversation_id, max_turns=MAX_HISTORY_TURNS
        )
        if history_context:
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
    # Stage 4.5: ML tie-breaker (fail-open, data-driven soft cues)
    # =========================================================================
    with timer.stage("ml"):
        ml_score = None
        soft_cue_result = {"matched": False, "cues": []}
        current_signal_names = get_signal_names(current_signals)

        # Skip ML if we already have a hard-block signal (heuristics are decisive)
        has_hard_block = (
            "exfiltrate_system_prompt" in current_signal_names
            or "access_developer_mode" in current_signal_names
        )

        # Check soft cues from YAML config (data-driven, not hardcoded)
        soft_cue_result = check_soft_cues(clean_text)
        soft_cues_matched = soft_cue_result["matched"]

        # Run ML if:
        # 1. In gray-zone (risk 20-80) OR
        # 2. Soft cues matched (even if risk=0, catches paraphrases) OR  
        # 3. Has imperative structure (looks like a real command)
        should_run_ml = (
            (ML_GRAYZONE_MIN <= effective_risk <= ML_GRAYZONE_MAX)
            or soft_cues_matched
            or has_imperative
        )

        if (not has_hard_block) and should_run_ml:
            ml_score = score_injection_probability(clean_text)

    # =========================================================================
    # Stage 5: Pivot detection
    # =========================================================================
    pivot_detected = bool(_detect_pivot(history_turns, current_signals, current_risk))
    if pivot_detected:
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
    # Stage 7: Policy Decision (context-aware + escalation + ML tie-breaker)
    # =========================================================================
    with timer.stage("policy"):
        decision = decide_action(
            risk_score=effective_risk,
            signals=current_signals,
            sanitized_has_content=sanitized_has_content,
            obfuscation_flags=obfuscation_flags,
            message=message,
            # Multi-turn context
            reprompt_count=reprompt_count,
            pivot_detected=pivot_detected,
            # Behavior counters for escalation
            behavior_counters=behavior_counters,
            # Context awareness
            has_benign_context=has_benign_ctx,
            has_imperative_structure=has_imperative,
            # ML
            ml_score=ml_score,
        )
        action = decision["action"]
        classification = decision.get("classification", get_classification(effective_risk))

    # =========================================================================
    # Stage 8: Apply behavioral escalation
    # =========================================================================
    original_action = action
    action = _apply_escalation(action, reprompt_count, behavior_counters, current_risk)
    if action != original_action:
        decision["reason"] = (
            f"Escalated {original_action}→{action} "
            f"(reprompts={reprompt_count}, repeat_override={behavior_counters['repeat_override']})"
        )
        if action == "block":
            classification = "malicious"

    # =========================================================================
    # Stage 9: Store turn + mark action
    # =========================================================================
    with timer.stage("memory_store"):
        signal_names = [s.get("name", "") for s in current_signals]

        # Prevent benign quotation/discussion of override phrases from poisoning history.
        if has_benign_ctx and not has_imperative:
            if "override_instructions" in signal_names:
                signal_names = [
                    ("override_mentioned" if n == "override_instructions" else n)
                    for n in signal_names
                ]

        conversation_store.add_turn(
            conversation_id,
            role="user",
            text=message,
            signals=signal_names,
        )
        conversation_store.mark_action(conversation_id, action)

    # =========================================================================
    # Build Response with full explainability
    # =========================================================================

    # Add multi-turn + behavior metadata to obfuscation_flags
    obfuscation_flags["multi_turn_enabled"] = True
    obfuscation_flags["turns_used"] = len(history_turns)
    obfuscation_flags["history_pressure"] = history_pressure
    obfuscation_flags["effective_risk_score"] = effective_risk
    obfuscation_flags["current_risk_score"] = current_risk
    obfuscation_flags["pivot_detected"] = pivot_detected
    obfuscation_flags["reprompt_count"] = reprompt_count
    obfuscation_flags["block_count"] = block_count

    # Optional: include history risk for transparency/debug
    obfuscation_flags["history_risk_score"] = history_risk

    # ML explainability
    obfuscation_flags["ml_score"] = ml_score
    obfuscation_flags["soft_cues_matched"] = soft_cue_result.get("cues", [])

    # Behavior escalation fields
    obfuscation_flags["behavior_repeat_override"] = behavior_counters["repeat_override"]
    obfuscation_flags["behavior_repeat_exfil"] = behavior_counters["repeat_exfil"]
    obfuscation_flags["behavior_high_risk_turns"] = behavior_counters["high_risk_turns"]
    obfuscation_flags["behavior_recent_signals"] = recent_signals

    # Context awareness fields
    obfuscation_flags["context_has_benign_context"] = has_benign_ctx
    obfuscation_flags["context_has_imperative_structure"] = has_imperative

    response: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "action": action,
        "classification": classification,
        "risk_score": effective_risk,
        "signals": current_signals,
        "obfuscation_flags": obfuscation_flags,
        "sanitized_message": sanitized_text if action == "sanitize" else None,
        "reprompt_message": get_reprompt_message() if action == "reprompt" else None,
        "latency_ms": timer.results(),
    }

    log_request(conversation_id, action, effective_risk, current_signals)
    return response