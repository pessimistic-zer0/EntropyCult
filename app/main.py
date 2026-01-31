"""
Prompt Injection Defense Gateway - FastAPI Backend
Includes /chat endpoint for Live Attack Simulation Dashboard
"""
import time
from typing import List, Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.api.routes import router as api_router
from app.engine.victim import get_victim
from app.engine.pipeline import SecurityScanner

app = FastAPI(title="Prompt Injection Defense Gateway", version="0.2.0")

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/v1")

# Lazy-loaded scanner
_scanner = None

def get_scanner() -> SecurityScanner:
    global _scanner
    if _scanner is None:
        _scanner = SecurityScanner()
    return _scanner


# ============================================================
# Chat Endpoint for Live Attack Simulation Dashboard
# ============================================================

class ChatRequest(BaseModel):
    message: str
    history: Optional[List[dict]] = None
    shield_active: bool = True
    conversation_id: Optional[str] = None


class ChatResponse(BaseModel):
    status: str  # "danger", "blocked", "sanitized", "allowed"
    response: Optional[str] = None
    original_text: Optional[str] = None
    sanitized_text: Optional[str] = None
    layer: Optional[int] = None
    reason: Optional[str] = None
    latency_ms: float
    signals: Optional[List[dict]] = None
    risk_score: Optional[int] = None


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Chat endpoint with Shield ON/OFF toggle.
    
    Shield OFF: Direct attack on VictimAI (dangerous!)
    Shield ON: Protected by SecurityScanner
    """
    start_time = time.time()
    victim = get_victim()
    
    # ====================================
    # SHIELD OFF: Direct attack (DANGER!)
    # ====================================
    if not request.shield_active:
        result = victim.get_response(request.message, request.history)
        total_latency = (time.time() - start_time) * 1000
        
        return ChatResponse(
            status="danger",
            response=result["response"],
            latency_ms=round(total_latency, 2)
        )
    
    # ====================================
    # SHIELD ON: Protected mode
    # ====================================
    scanner = get_scanner()
    
    # Extract history as list of strings for scanner
    history_list = []
    if request.history:
        for turn in request.history:
            if turn.get("role") == "user":
                history_list.append(turn.get("content", ""))
    
    # Run security scan
    scan_result = scanner.scan(
        request.message,
        session_history=history_list
    )
    
    action = scan_result.action
    
    # Build signals list for frontend
    signals = []
    if scan_result.details:
        if scan_result.details.get("layer1"):
            signals.append({"name": "regex_pattern", "weight": 50})
        if scan_result.details.get("layer2", {}).get("is_malicious"):
            conf = scan_result.details["layer2"].get("confidence", 0)
            signals.append({"name": "ml_injection_detected", "weight": int(conf * 100)})
        if scan_result.details.get("semantic", {}).get("is_dangerous"):
            sim = scan_result.details["semantic"].get("max_similarity", 0)
            signals.append({"name": "semantic_intent_danger", "weight": int(sim * 100)})
    
    risk_score = int(scan_result.confidence * 100) if scan_result.confidence else 0
    
    # ---- BLOCKED ----
    if action == "block":
        total_latency = (time.time() - start_time) * 1000
        return ChatResponse(
            status="blocked",
            response=None,
            layer=scan_result.layer,
            reason=scan_result.reason,
            latency_ms=round(total_latency, 2),
            signals=signals,
            risk_score=risk_score
        )
    
    # ---- SANITIZED ----
    if action == "sanitize" and scan_result.sanitized_message:
        # Call VictimAI with sanitized prompt
        result = victim.get_response(scan_result.sanitized_message, request.history)
        total_latency = (time.time() - start_time) * 1000
        
        return ChatResponse(
            status="sanitized",
            response=result["response"],
            original_text=request.message,
            sanitized_text=scan_result.sanitized_message,
            layer=scan_result.layer,
            reason=scan_result.reason,
            latency_ms=round(total_latency, 2),
            signals=signals,
            risk_score=risk_score
        )
    
    # ---- ALLOWED ----
    result = victim.get_response(request.message, request.history)
    total_latency = (time.time() - start_time) * 1000
    
    return ChatResponse(
        status="allowed",
        response=result["response"],
        latency_ms=round(total_latency, 2),
        signals=signals,
        risk_score=risk_score
    )


@app.get("/health")
def health():
    return {"status": "ok"}