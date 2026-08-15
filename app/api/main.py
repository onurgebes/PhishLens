"""FastAPI application entry point."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.errors import register_exception_handlers
from app.api.routes.analyze import router as analyze_router
from app.api.routes.health import router as health_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="PhishLens API",
        description="Email parsing, IOC extraction, phishing analysis, and risk scoring.",
        version="0.1.0",
    )
    
    # Configure CORS for frontend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:61822",  # Browser preview proxy
            "https://phishlens-eight.vercel.app",  # Production frontend
            "https://phish-lens-pearl.vercel.app",  # Deployed frontend
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    register_exception_handlers(app)
    app.include_router(health_router)
    app.include_router(analyze_router)
    return app


app = create_app()
