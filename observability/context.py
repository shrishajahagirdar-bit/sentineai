from __future__ import annotations

from contextvars import ContextVar
from uuid import uuid4


_CORRELATION_ID: ContextVar[str | None] = ContextVar("correlation_id", default=None)
_TENANT_ID: ContextVar[str | None] = ContextVar("tenant_id", default=None)


def new_correlation_id() -> str:
    value = str(uuid4())
    _CORRELATION_ID.set(value)
    return value


def set_correlation_id(value: str | None) -> str:
    resolved = value or str(uuid4())
    _CORRELATION_ID.set(resolved)
    return resolved


def get_correlation_id() -> str:
    current = _CORRELATION_ID.get()
    if current:
        return current
    return new_correlation_id()


def set_tenant_id(value: str | None) -> None:
    _TENANT_ID.set(value)


def get_tenant_id() -> str | None:
    return _TENANT_ID.get()
