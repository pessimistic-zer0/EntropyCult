# app/engine/utils.py
"""
Timing utilities for the defense gateway.
Keeps latency tracking simple and hackathon-friendly.
"""

import time
from typing import Dict


class Timer:
    """Context manager for tracking stage latencies."""

    def __init__(self):
        self._stages: Dict[str, float] = {}
        self._start: float = 0.0

    def start(self) -> None:
        """Start overall timer."""
        self._start = time.perf_counter()

    def stage(self, name: str):
        """Context manager for timing a named stage."""
        return _StageContext(self, name)

    def record(self, name: str, elapsed_ms: float) -> None:
        """Manually record a stage timing."""
        self._stages[name] = elapsed_ms

    def total(self) -> float:
        """Get total elapsed time in ms since start()."""
        return (time.perf_counter() - self._start) * 1000

    def results(self) -> Dict[str, float]:
        """Return all recorded timings + total."""
        return {**self._stages, "total": round(self.total(), 3)}


class _StageContext:
    """Helper context manager for Timer.stage()."""

    def __init__(self, timer: Timer, name: str):
        self._timer = timer
        self._name = name
        self._start: float = 0.0

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_):
        elapsed_ms = (time.perf_counter() - self._start) * 1000
        self._timer.record(self._name, round(elapsed_ms, 3))


def log_request(conversation_id: str, action: str, risk_score: int, signals: list) -> None:
    """Simple structured log output."""
    signal_names = [s.get("name", s) if isinstance(s, dict) else getattr(s, "name", str(s)) for s in signals]
    print(f"[GATEWAY] conv={conversation_id} action={action} risk={risk_score} signals={signal_names}")
