from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import Base, engine
from app.ratelimit import RateLimitMiddleware
from app.routers import auth, explain, me, practice, scan, teacher

Base.metadata.create_all(bind=engine)

app = FastAPI(title="VulnScope API")

# Added first so that CORS (added last) wraps it and 429 replies still carry CORS headers.
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)
app.include_router(auth.router)
app.include_router(explain.router)
app.include_router(me.router)
app.include_router(teacher.router)
app.include_router(practice.router)


@app.get("/health")
def health():
    return {"status": "ok"}