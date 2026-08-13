"""SQLite engine and session management."""

from __future__ import annotations

import os
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.infrastructure.models import Base

DEFAULT_DB_PATH = "phishlens.db"

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def get_database_url() -> str:
    path = os.environ.get("PHISHLENS_DB_PATH", DEFAULT_DB_PATH)
    return f"sqlite:///{path}"


def configure_engine(
    database_url: str | None = None,
    *,
    connect_args: dict[str, Any] | None = None,
    poolclass: type | None = None,
) -> Engine:
    """Create (or replace) the global engine and session factory."""
    global _engine, _SessionLocal

    url = database_url if database_url is not None else get_database_url()
    kwargs: dict[str, Any] = {"connect_args": connect_args or {"check_same_thread": False}}
    if poolclass is not None:
        kwargs["poolclass"] = poolclass

    _engine = create_engine(url, **kwargs)
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)
    return _engine


def get_engine() -> Engine:
    if _engine is None:
        configure_engine()
    assert _engine is not None
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    if _SessionLocal is None:
        configure_engine()
    assert _SessionLocal is not None
    return _SessionLocal


def init_db(engine: Engine | None = None) -> None:
    """Create tables if they do not exist (idempotent)."""
    target = engine if engine is not None else get_engine()
    Base.metadata.create_all(bind=target)


def reset_database_state() -> None:
    """Clear cached engine/session factory (used in tests)."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None
