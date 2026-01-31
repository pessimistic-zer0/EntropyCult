from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

#input to be received from the user
class AnalyzeRequest(BaseModel):
    conversation_id: str = Field(..., description="Client-provided conversation/session id")
    message: str = Field(..., description="User message to analyze")
    attachments: Optional[Dict[str, Any]] = Field(default=None, description="Optional extra data (diff/log/etc.)")


class Signal(BaseModel):
    name: str
    weight: int
    evidence: str

# output to sent
class AnalyzeResponse(BaseModel):
    conversation_id: str
    action: str  # allow | block | reprompt | sanitize
    classification: str  # benign | malicious | uncertain
    risk_score: int  # 0..100
    signals: List[Signal]
    obfuscation_flags: Dict[str, Any]
    sanitized_message: Optional[str] = None
    reprompt_message: Optional[str] = None
    latency_ms: Dict[str, float]