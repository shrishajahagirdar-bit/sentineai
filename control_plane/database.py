from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from control_plane.config import settings


Base = declarative_base()
_ENGINE = None
_SESSION_FACTORY = None


def get_engine():
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = create_engine(settings.database_url, future=True, pool_pre_ping=True)
    return _ENGINE


def get_session_factory():
    global _SESSION_FACTORY
    if _SESSION_FACTORY is None:
        _SESSION_FACTORY = sessionmaker(bind=get_engine(), autoflush=False, autocommit=False, future=True)
    return _SESSION_FACTORY


def get_db() -> Generator[Session, None, None]:
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()


def set_tenant_context(db: Session, tenant_id: str | None) -> None:
    if tenant_id:
        db.execute(text("select set_config('app.current_tenant_id', :tenant_id, true)"), {"tenant_id": tenant_id})
