from fastapi import APIRouter
from app.api.schemas import AnalyzeRequest, AnalyzeResponse
from app.engine.orchestrator import analyze_message

router = APIRouter()


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    return analyze_message(req.conversation_id, req.message, req.attachments)