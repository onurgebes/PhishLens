"""Analysis history persistence repository."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas.responses import AnalyzeResponse, HistorySummaryResponse
from app.infrastructure.models import AnalysisHistoryRecord


class HistoryRepository:
    """Persist and retrieve completed email analyses."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def save(
        self,
        response: AnalyzeResponse,
        *,
        source_type: str,
        source_filename: str | None = None,
    ) -> str:
        analysis_id = str(uuid.uuid4())
        payload = response.model_dump(mode="json")

        record = AnalysisHistoryRecord(
            id=analysis_id,
            created_at=datetime.now(UTC),
            source_type=source_type,
            source_filename=source_filename,
            subject=response.parsed_email.subject,
            from_address=response.parsed_email.from_address,
            risk_score=response.risk_score.score,
            risk_level=response.risk_score.level,
            ioc_count=len(response.iocs),
            finding_count=len(response.findings),
            result_json=json.dumps(payload),
        )
        self._session.add(record)
        self._session.commit()
        return analysis_id

    def get_by_id(self, analysis_id: str) -> AnalyzeResponse | None:
        record = self._session.get(AnalysisHistoryRecord, analysis_id)
        if record is None:
            return None

        payload = json.loads(record.result_json)
        return AnalyzeResponse.model_validate(
            {**payload, "analysis_id": record.id}
        )

    def list(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[HistorySummaryResponse], int]:
        total = self._session.scalar(
            select(func.count()).select_from(AnalysisHistoryRecord)
        )
        total = int(total or 0)

        stmt = (
            select(AnalysisHistoryRecord)
            .order_by(AnalysisHistoryRecord.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        rows = self._session.scalars(stmt).all()

        items = [
            HistorySummaryResponse(
                analysis_id=row.id,
                created_at=row.created_at.isoformat(),
                source_type=row.source_type,
                source_filename=row.source_filename,
                subject=row.subject,
                from_address=row.from_address,
                risk_score=row.risk_score,
                risk_level=row.risk_level,
                ioc_count=row.ioc_count,
                finding_count=row.finding_count,
            )
            for row in rows
        ]
        return items, total
