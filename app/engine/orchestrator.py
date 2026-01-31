# app/engine/orchestrator.py
"""
Main orchestrator - coordinates the full defense pipeline.
Pipeline: preprocess → signals → sanitize → policy → response
"""

from typing import Dict, Any, Optional

from app.engine.utils import Timer, log_request
from app.engine.preprocess import preprocess
from app.engine.signals import detect_signals, calculate_risk_score
from app.engine.sanitize import sanitize_message, has_meaningful_content, get_reprompt_message
from app.engine.classifier import SklearnClassifier
from app.engine.policy import decide_action, get_classification
from app.memory.store import add_message, get_recent_history

# Initialize classifier
classifier = SklearnClassifier()


def analyze_message(
    conversation_id: str,
    message: str,
    attachments: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Main entry point for the defense gateway.
    Returns dict matching AnalyzeResponse schema.
    """
    timer = Timer()
    timer.start()

    # Stage 1: Preprocessing
    with timer.stage("preprocess"):
        prep_result = preprocess(message)
        clean_text = prep_result['clean_text']
        
        # Multi-turn context
        history_text = get_recent_history(conversation_id)
        # Combine history + current message for analysis (optional: weigh current more)
        full_context = f"{history_text}\n{clean_text}" if history_text else clean_text
        
        decoded_layers = prep_result['decoded_layers']
        obfuscation_flags = prep_result['obfuscation_flags']

    # Stage 2: Signal Detection
    with timer.stage("signals"):
        # We run signals on the FULL context to catch "ignore previous..." that refers to history
        signals = detect_signals(full_context, decoded_layers)
        risk_score = calculate_risk_score(signals)
        # ML Prediction
        try:
            # We predict on the specific message primarily, but could use context
            # For now, let's stick to current message for ML to avoid noise from old turns?
            # actually, let's use full_context.
            ml_scores = classifier.predict(full_context)
            ml_score = ml_scores[0] if ml_scores else 0.0
        except Exception as e:
            print(f"ML PREDICTION ERROR: {e}")
            ml_score = 0.0
        
        # Combine heuristics and ML into a single risk score
        risk_score = max(risk_score, int(ml_score * 100))

    # Stage 3: Sanitization
    with timer.stage("sanitize"):
        sanitized_text, was_sanitized, removed_patterns = sanitize_message(clean_text, signals)
        sanitized_has_content = has_meaningful_content(sanitized_text)

    # Stage 4: Policy Decision
    with timer.stage("policy"):
        decision = decide_action(
            risk_score=risk_score,
            signals=signals,
            sanitized_has_content=sanitized_has_content,
            obfuscation_flags=obfuscation_flags,
            ml_score=ml_score,
            message=message,  # optional but recommended if policy supports it
        )
        action = decision['action']
        classification = decision.get('classification', get_classification(risk_score))

    # Build Response
    response: Dict[str, Any] = {
        'conversation_id': conversation_id,
        'action': action,
        'classification': classification,
        'risk_score': risk_score,
        'p_malicious': ml_score,
        'signals': signals,
        'obfuscation_flags': obfuscation_flags,
        'sanitized_message': sanitized_text if action == "sanitize" else None,
        'reprompt_message': get_reprompt_message() if action == "reprompt" else None,
        'latency_ms': timer.results(),
    }

    log_request(conversation_id, action, risk_score, signals)
    
    # Save to history if allowed or just save everything? 
    # Usually we save everything to track context, even if blocked.
    add_message(conversation_id, clean_text)
    
    return response
