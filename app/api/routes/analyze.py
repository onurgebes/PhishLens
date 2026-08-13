"""Email analysis routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from app.api.dependencies import get_analyzer, get_history_repository
from app.api.schemas.requests import AnalyzeRawRequest
from app.api.schemas.responses import AnalyzeResponse
from app.api.serializers.analysis_result import serialize_analysis_result
from app.domain.parser import EmailTooLargeError, MAX_EMAIL_SIZE_BYTES
from app.domain.pipeline import PhishLensAnalyzer
from app.infrastructure.history_repository import HistoryRepository

router = APIRouter(prefix="/api", tags=["analyze"])

_READ_CHUNK_SIZE = 1024 * 1024


def _validate_eml_filename(filename: str | None) -> None:
    if not filename:
        raise HTTPException(status_code=400, detail="Uploaded file must have a filename.")
    if not filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted.")


async def _read_upload_bytes(upload: UploadFile) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await upload.read(_READ_CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_EMAIL_SIZE_BYTES:
            raise EmailTooLargeError(
                f"Email is {total} bytes, exceeds the "
                f"{MAX_EMAIL_SIZE_BYTES}-byte limit"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _analyze_and_persist(
    analyzer: PhishLensAnalyzer,
    repository: HistoryRepository,
    raw_bytes: bytes,
    *,
    source_type: str,
    source_filename: str | None = None,
) -> AnalyzeResponse:
    try:
        result = analyzer.analyze(raw_bytes)
    except EmailTooLargeError:
        raise
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while analyzing the email.",
        ) from None

    payload = serialize_analysis_result(result)
    response = AnalyzeResponse.model_validate(payload)
    analysis_id = repository.save(
        response,
        source_type=source_type,
        source_filename=source_filename,
    )
    return response.model_copy(update={"analysis_id": analysis_id})


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_upload(
    file: UploadFile = File(...),
    analyzer: PhishLensAnalyzer = Depends(get_analyzer),
    repository: HistoryRepository = Depends(get_history_repository),
) -> AnalyzeResponse:
    _validate_eml_filename(file.filename)
    raw_bytes = await _read_upload_bytes(file)
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    return _analyze_and_persist(
        analyzer,
        repository,
        raw_bytes,
        source_type="upload",
        source_filename=file.filename,
    )


@router.post("/analyze/raw", response_model=AnalyzeResponse)
def analyze_raw(
    request: AnalyzeRawRequest,
    analyzer: PhishLensAnalyzer = Depends(get_analyzer),
    repository: HistoryRepository = Depends(get_history_repository),
) -> AnalyzeResponse:
    raw_bytes = request.raw_email.encode("utf-8")
    if len(raw_bytes) > MAX_EMAIL_SIZE_BYTES:
        raise EmailTooLargeError(
            f"Email is {len(raw_bytes)} bytes, exceeds the "
            f"{MAX_EMAIL_SIZE_BYTES}-byte limit"
        )
    return _analyze_and_persist(
        analyzer,
        repository,
        raw_bytes,
        source_type="raw",
    )
