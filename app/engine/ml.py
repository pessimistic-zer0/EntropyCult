from __future__ import annotations

import os
from typing import Optional

import joblib

_MODEL = None
_MODEL_PATH = os.environ.get("PI_MODEL_PATH", "models/pi_model.joblib")


def _tune_model_for_inference(model):
    """
    Reduce per-request overhead from parallelism.
    Joblib parallelism can be slower than single-thread for short texts.
    """
    try:
        feats = model.named_steps.get("tfidf")
        if feats is not None and hasattr(feats, "n_jobs"):
            feats.n_jobs = 1
    except Exception:
        pass

    try:
        clf = model.named_steps.get("clf")
        if clf is not None and hasattr(clf, "n_jobs"):
            clf.n_jobs = 1
    except Exception:
        pass

    return model


def _get_model():
    global _MODEL
    if _MODEL is not None:
        return _MODEL
    if not os.path.exists(_MODEL_PATH):
        _MODEL = None
        return None
    _MODEL = joblib.load(_MODEL_PATH)
    _MODEL = _tune_model_for_inference(_MODEL)
    return _MODEL


def score_injection_probability(text: str) -> Optional[float]:
    """
    Returns P(injection) in [0, 1].
    Returns None if model file is missing (fail-open).
    """
    model = _get_model()
    if model is None:
        return None
    return float(model.predict_proba([text])[0][1])