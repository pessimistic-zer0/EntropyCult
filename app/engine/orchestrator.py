# app/engine/orchestrator.py
"""
Main orchestrator - coordinates the full defense pipeline.
Pipeline: preprocess → signals → sanitize → policy → response
"""

import os
import joblib
from typing import Dict, Any, Optional

from app.engine.utils import Timer, log_request
from app.engine.preprocess import preprocess
from app.engine.signals import detect_signals, calculate_risk_score as calculate_heuristic_score
from app.engine.sanitize import sanitize_message, has_meaningful_content, get_reprompt_message
from app.engine.policy import decide_action, get_classification

# Load Model if available
MODEL_PATH = "app/engine/data/model.joblib"
ML_MODEL = None

try:
    if os.path.exists(MODEL_PATH):
        ML_MODEL = joblib.load(MODEL_PATH)
        print(f"Loaded ML model from {MODEL_PATH}")
    else:
        print(f"ML model not found at {MODEL_PATH}, using heuristics only.")
except Exception as e:
    print(f"Error loading ML model: {e}")


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
        decoded_layers = prep_result['decoded_layers']
        obfuscation_flags = prep_result['obfuscation_flags']

    # Stage 2: Signal Detection & Risk Scoring
    with timer.stage("signals"):
        signals = detect_signals(clean_text, decoded_layers)
        
        # Default to heuristic score
        risk_score = calculate_heuristic_score(signals)
        
        # If ML model exists, use it for the primary score (0-100)
        # We can blend them or override. Here we override if model is confident.
        if ML_MODEL:
            try:
                # Predict probability of class 1 (Malicious)
                # Model expects a list/iterable of strings
                prob = ML_MODEL.predict_proba([clean_text])[0][1]
                ml_score = int(prob * 100)
                
                # Logic: Use the higher of the two scores to be safe,
                # or prefer ML. Let's trust ML but ensure signals are meant for explanation.
                risk_score = ml_score
                
                # Add a synthetic signal for the ML score to show up in UI
                signals.append({
                    "name": "ml_model_prediction",
                    "weight": ml_score,
                    "evidence": f"Model confidence: {prob:.2f}"
                })
            except Exception as e:
                print(f"ML Prediction failed: {e}")

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
        )
        action = decision['action']
        classification = get_classification(risk_score)

    # Build Response
    response: Dict[str, Any] = {
        'conversation_id': conversation_id,
        'action': action,
        'classification': classification,
        'risk_score': risk_score,
        'signals': signals,
        'obfuscation_flags': obfuscation_flags,
        'sanitized_message': sanitized_text if action == "sanitize" else None,
        'reprompt_message': get_reprompt_message() if action == "reprompt" else None,
        'latency_ms': timer.results(),
    }

    log_request(conversation_id, action, risk_score, signals)
    return response
