# app/engine/__init__.py
"""
Defense Engine - unified module for prompt injection detection and mitigation.
"""

from app.engine.orchestrator import analyze_message
from app.engine.preprocess import preprocess
from app.engine.signals import detect_signals, calculate_risk_score
from app.engine.sanitize import sanitize_message
from app.engine.policy import decide_action

__all__ = [
    'analyze_message',
    'preprocess',
    'detect_signals',
    'calculate_risk_score',
    'sanitize_message',
    'decide_action',
]
