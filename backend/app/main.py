from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine
from app.routers import scan

Base.metadata.create_all(bind=engine)

app = FastAPI(title="VulnScope API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)


@app.get("/health")
def health():
    return {"status": "ok"}