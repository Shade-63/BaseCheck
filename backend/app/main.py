from fastapi import FastAPI
from backend.app.routers import auth

app = FastAPI(
    title= "BaseCheck API",
    description="Website security scanner API",
    version="0.1.0",
)

#router inclusion
app.include_router(auth.router)

@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "ok",
        "service": "basecheck-api",
    }