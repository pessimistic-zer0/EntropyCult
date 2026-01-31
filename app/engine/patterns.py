# app/engine/patterns.py
"""
Pattern loader module for data-driven signal detection.

Loads regex patterns from YAML config files at startup and caches compiled patterns.
This avoids "hardcode hell" by making patterns easily maintainable in config files.

Usage:
    from app.engine.patterns import get_hard_block_patterns, get_soft_cue_patterns
    
    for signal_name, patterns in get_hard_block_patterns().items():
        for pattern in patterns:
            if pattern['compiled'].search(text):
                # matched!
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# Default paths relative to project root
DATA_DIR = Path(__file__).parent.parent.parent / "data"
HARD_BLOCK_FILE = DATA_DIR / "patterns_hard_block.yml"
SOFT_CUES_FILE = DATA_DIR / "patterns_soft_cues.yml"


def _load_yaml(path: Path) -> Dict[str, Any]:
    """Load YAML file, return empty dict if not found."""
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _compile_patterns(config: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Compile regex patterns from config structure.
    
    Input format (per signal):
        signal_name:
          weight: int
          description: str
          patterns:
            - id: str
              regex: str
              description: str
    
    Output:
        {signal_name: [
            {id, regex: str, compiled: re.Pattern, description, weight}, ...
        ]}
    """
    result: Dict[str, List[Dict[str, Any]]] = {}
    
    for signal_name, signal_config in config.items():
        if not isinstance(signal_config, dict):
            continue
        
        weight = signal_config.get("weight", 0)
        patterns_list = signal_config.get("patterns", [])
        
        compiled_patterns = []
        for p in patterns_list:
            if not isinstance(p, dict) or "regex" not in p:
                continue
            try:
                compiled = re.compile(p["regex"], re.IGNORECASE)
                compiled_patterns.append({
                    "id": p.get("id", signal_name),
                    "regex": p["regex"],
                    "compiled": compiled,
                    "description": p.get("description", ""),
                    "weight": weight,
                    "signal_name": signal_name,
                })
            except re.error as e:
                # Log but don't crash on bad regex
                print(f"Warning: Invalid regex in {signal_name}: {p['regex']} - {e}")
        
        if compiled_patterns:
            result[signal_name] = compiled_patterns
    
    return result


@lru_cache(maxsize=1)
def get_hard_block_patterns() -> Dict[str, List[Dict[str, Any]]]:
    """
    Load and cache compiled hard-block patterns.
    These trigger high-confidence signals.
    """
    config = _load_yaml(HARD_BLOCK_FILE)
    return _compile_patterns(config)


@lru_cache(maxsize=1)
def get_soft_cue_patterns() -> List[Dict[str, Any]]:
    """
    Load and cache compiled soft-cue patterns.
    These trigger ML backstop when matched.
    Returns flat list of patterns (no weight needed, just trigger ML).
    """
    config = _load_yaml(SOFT_CUES_FILE)
    patterns = _compile_patterns(config)
    
    # Flatten into a single list
    flat: List[Dict[str, Any]] = []
    for signal_name, pattern_list in patterns.items():
        for p in pattern_list:
            flat.append(p)
    
    return flat


def detect_hard_block_signals(text: str) -> List[Dict[str, Any]]:
    """
    Run hard-block patterns against text.
    Returns list of signals: [{name, weight, evidence, pattern_id}, ...]
    """
    signals = []
    seen_signal_names = set()
    
    for signal_name, patterns in get_hard_block_patterns().items():
        if signal_name in seen_signal_names:
            continue
        
        for p in patterns:
            match = p["compiled"].search(text)
            if match:
                signals.append({
                    "name": signal_name,
                    "weight": p["weight"],
                    "evidence": match.group()[:80],
                    "pattern_id": p["id"],
                })
                seen_signal_names.add(signal_name)
                break  # One match per signal type is enough
    
    return signals


def check_soft_cues(text: str) -> Dict[str, Any]:
    """
    Check if any soft-cue patterns match.
    Returns: {matched: bool, cues: [list of matched pattern IDs]}
    """
    matched_cues = []
    text_lower = text.lower()
    
    for p in get_soft_cue_patterns():
        if p["compiled"].search(text_lower):
            matched_cues.append(p["id"])
    
    return {
        "matched": len(matched_cues) > 0,
        "cues": matched_cues[:5],  # Cap at 5 for response size
    }


def reload_patterns() -> None:
    """Force reload of patterns (useful for testing/hot-reload)."""
    get_hard_block_patterns.cache_clear()
    get_soft_cue_patterns.cache_clear()
