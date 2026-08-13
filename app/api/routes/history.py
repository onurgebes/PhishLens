"""Analysis history routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.dependencies import get_history_repository
from app.api.schemas.responses import AnalyzeResponse, HistoryListResponse
from app.infrastructure.history_repository import HistoryRepository

router = APIRouter(prefix="/api", tags=["history"])

DEFAULT_LIMIT = 20
DEFAULT_OFFSET = 0
MAX_LIMIT = 100


@router.get("/history", response_model=HistoryListResponse)
def list_history(
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(DEFAULT_OFFSET, ge=0),
    repository: HistoryRepository = Depends(get_history_repository),
) -> HistoryListResponse:
    items, total = repository.list(limit=limit, offset=offset)
    return HistoryListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/history/{analysis_id}", response_model=AnalyzeResponse)
def get_history_item(
    analysis_id: str,
    repository: HistoryRepository = Depends(get_history_repository),
) -> AnalyzeResponse:
    result = repository.get_by_id(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return result
