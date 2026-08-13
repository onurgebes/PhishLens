"""API request schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AnalyzeRawRequest(BaseModel):
    raw_email: str = Field(
        ...,
        min_length=1,
        description="Raw RFC 822 email source encoded as UTF-8 text.",
    )
