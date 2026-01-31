from fastapi import FastAPI
from app.api.routes import router as api_router

app = FastAPI(title="Prompt Injection Defense Gateway", version="0.1.0")
app.include_router(api_router, prefix="/v1")

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Mount the static directory
app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.get("/")
async def read_root():
    return FileResponse('app/static/index.html')


@app.get("/health")
def health():
    return {"status": "ok"}