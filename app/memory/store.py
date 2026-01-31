from typing import List, Dict, Any
from collections import defaultdict, deque

# In-memory store: conversation_id -> list of messages
# Restrict to last 10 messages to prevent memory explosion
_store: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10))

def add_message(conversation_id: str, message: str, sender: str = "user"):
    """Append a message to the history."""
    _store[conversation_id].append({"sender": sender, "content": message})

def get_recent_history(conversation_id: str, limit: int = 5) -> str:
    """
    Get recent history as a single string for analysis.
    Joins the user's previous messages.
    """
    history = list(_store[conversation_id])
    # Filter for user messages only, or include assistant? 
    # Usually attacks are in user messages, but context matters.
    # For simplicity, we just join the last `limit` messages to give context.
    
    recent = history[-limit:]
    # return "\n".join([f"{msg['sender']}: {msg['content']}" for msg in recent])
    return "\n".join([msg['content'] for msg in recent])

def clear_history(conversation_id: str):
    if conversation_id in _store:
        del _store[conversation_id]
