from fastapi import FastAPI
from app.api.routes import router as api_router
from app.engine.ml import score_injection_probability

app = FastAPI(title="Prompt Injection Defense Gateway", version="0.1.0")
app.include_router(api_router, prefix="/v1")


@app.on_event("startup")
def _warm_ml_model() -> None:
    # Warm the model so first user request doesn't pay disk-load cost.
    # Fail-open: if model missing, score_injection_probability returns None.
    score_injection_probability("warmup: hello world")