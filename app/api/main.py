"""FastAPI application entry point."""

from __future__ import annotations

from fastapi import FastAPI

from app.api.errors import register_exception_handlers
from app.api.routes.analyze import router as analyze_router
from app.api.routes.health import router as health_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="PhishLens API",
        description="Email parsing, IOC extraction, phishing analysis, and risk scoring.",
        version="0.1.0",
    )
    register_exception_handlers(app)
    app.include_router(health_router)
    app.include_router(analyze_router)
    return app


app = create_app()
