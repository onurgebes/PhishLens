"""Health check route."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from fastapi import APIRouter

from app.api.schemas.responses import HealthResponse

router = APIRouter(tags=["health"])


def _app_version() -> str:
    try:
        return version("phishlens-backend")
    except PackageNotFoundError:
        return "0.1.0"


@router.get("/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    return HealthResponse(status="ok", version=_app_version())
