from fastapi import FastAPI
from app.api.routes_analyze import router as analyze_router

app = FastAPI(
    title="Gmail Risk Scanner",
    version="1.0.0",
    description="Backend for analyzing Gmail messages and calculating maliciousness risk score."
)

app.include_router(analyze_router, prefix="/api")


@app.get("/health")
def health_check():
    return {"status": "ok"}
