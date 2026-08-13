"""FastAPI application entry point."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.errors import register_exception_handlers
from app.api.routes.analyze import router as analyze_router
from app.api.routes.health import router as health_router
from app.api.routes.history import router as history_router
from app.infrastructure.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="PhishLens API",
        description="Email parsing, IOC extraction, phishing analysis, and risk scoring.",
        version="0.1.0",
        lifespan=lifespan,
    )
    register_exception_handlers(app)
    app.include_router(health_router)
    app.include_router(analyze_router)
    app.include_router(history_router)
    return app


app = create_app()
