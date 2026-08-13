"""HTTP exception handlers for domain and API errors."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.domain.parser import EmailTooLargeError


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(EmailTooLargeError)
    async def email_too_large_handler(
        request: Request, exc: EmailTooLargeError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=413,
            content={"detail": "Email exceeds the maximum allowed size."},
        )
