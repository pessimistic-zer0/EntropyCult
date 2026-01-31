# app/engine/memory.py
"""
In-memory conversation store for multi-turn context analysis.

Features:
- Stores last N turns per conversation (bounded)
- Tracks action counts (reprompt_count, block_count) for escalation
- TTL-based expiration to prevent memory leaks
- Thread-safe with a simple lock

Usage:
    from app.engine.memory import conversation_store
    conversation_store.add_turn(conv_id, "user", "hello")
    turns = conversation_store.get_last_turns(conv_id, max_turns=8)
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# Configuration constants
MAX_TURNS = 8                    # Max turns to keep per conversation
MAX_CHARS_PER_TURN = 2000        # Truncate each stored message
TTL_SECONDS = 3600               # 1 hour expiration
CLEANUP_INTERVAL = 300           # Run cleanup every 5 min (on access)


@dataclass
class Turn:
    """A single conversation turn."""
    role: str           # "user" or "assistant"
    text: str           # The message content (truncated)
    timestamp: float    # Unix timestamp
    signals: List[str] = field(default_factory=list)  # Signal names detected


@dataclass
class ConversationState:
    """State for a single conversation."""
    turns: List[Turn] = field(default_factory=list)
    reprompt_count: int = 0
    block_count: int = 0
    sanitize_count: int = 0
    last_seen_ts: float = field(default_factory=time.time)
    created_ts: float = field(default_factory=time.time)


class ConversationStore:
    """
    Thread-safe in-memory conversation store.
    Automatically evicts expired conversations on access.
    """

    def __init__(self):
        self._store: Dict[str, ConversationState] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    def _cleanup_expired(self) -> None:
        """Remove conversations that haven't been accessed within TTL."""
        now = time.time()
        # Only run cleanup periodically
        if now - self._last_cleanup < CLEANUP_INTERVAL:
            return
        self._last_cleanup = now

        expired = [
            cid for cid, state in self._store.items()
            if now - state.last_seen_ts > TTL_SECONDS
        ]
        for cid in expired:
            del self._store[cid]

    def _get_or_create(self, conversation_id: str) -> ConversationState:
        """Get existing state or create new one."""
        if conversation_id not in self._store:
            self._store[conversation_id] = ConversationState()
        state = self._store[conversation_id]
        state.last_seen_ts = time.time()
        return state

    def add_turn(
        self,
        conversation_id: str,
        role: str,
        text: str,
        signals: Optional[List[str]] = None
    ) -> None:
        """
        Add a turn to the conversation history.
        Truncates text and enforces max turns limit.
        """
        truncated_text = text[:MAX_CHARS_PER_TURN]
        turn = Turn(
            role=role,
            text=truncated_text,
            timestamp=time.time(),
            signals=signals or []
        )

        with self._lock:
            self._cleanup_expired()
            state = self._get_or_create(conversation_id)
            state.turns.append(turn)
            # Keep only last MAX_TURNS
            if len(state.turns) > MAX_TURNS:
                state.turns = state.turns[-MAX_TURNS:]

    def get_last_turns(
        self,
        conversation_id: str,
        max_turns: int = MAX_TURNS
    ) -> List[Dict[str, Any]]:
        """
        Get the last N turns as list of dicts.
        Returns empty list if conversation doesn't exist.
        """
        with self._lock:
            self._cleanup_expired()
            if conversation_id not in self._store:
                return []
            state = self._get_or_create(conversation_id)
            turns = state.turns[-max_turns:]
            return [
                {
                    "role": t.role,
                    "text": t.text,
                    "timestamp": t.timestamp,
                    "signals": t.signals,
                }
                for t in turns
            ]

    def get_context_text(
        self,
        conversation_id: str,
        max_turns: int = MAX_TURNS
    ) -> str:
        """
        Get conversation history as formatted text for analysis.
        Format: "[USER]: message\n[ASSISTANT]: response\n..."
        """
        turns = self.get_last_turns(conversation_id, max_turns)
        lines = []
        for t in turns:
            role_label = t["role"].upper()
            # Limit each turn in context to avoid huge strings
            text = t["text"][:500]
            lines.append(f"[{role_label}]: {text}")
        return "\n".join(lines)

    def get_stats(self, conversation_id: str) -> Dict[str, Any]:
        """
        Get conversation statistics for policy decisions.
        """
        with self._lock:
            if conversation_id not in self._store:
                return {
                    "exists": False,
                    "turn_count": 0,
                    "reprompt_count": 0,
                    "block_count": 0,
                    "sanitize_count": 0,
                    "age_seconds": 0,
                }
            state = self._store[conversation_id]
            return {
                "exists": True,
                "turn_count": len(state.turns),
                "reprompt_count": state.reprompt_count,
                "block_count": state.block_count,
                "sanitize_count": state.sanitize_count,
                "age_seconds": time.time() - state.created_ts,
            }

    def mark_action(self, conversation_id: str, action: str) -> None:
        """
        Increment action counters for escalation tracking.
        Call this after policy decides on an action.
        """
        with self._lock:
            if conversation_id not in self._store:
                return
            state = self._store[conversation_id]
            if action == "reprompt":
                state.reprompt_count += 1
            elif action == "block":
                state.block_count += 1
            elif action == "sanitize":
                state.sanitize_count += 1

    def get_recent_signals(
        self,
        conversation_id: str,
        max_turns: int = 3
    ) -> List[str]:
        """
        Get unique signal names from recent turns.
        Useful for explainability.
        """
        turns = self.get_last_turns(conversation_id, max_turns)
        seen = []
        for t in turns:
            for sig in t.get("signals", []):
                if sig not in seen:
                    seen.append(sig)
        return seen[:10]  # Cap at 10 for response size

    def clear(self, conversation_id: str) -> None:
        """Remove a conversation (for testing/admin)."""
        with self._lock:
            if conversation_id in self._store:
                del self._store[conversation_id]


# Global singleton instance
conversation_store = ConversationStore()
