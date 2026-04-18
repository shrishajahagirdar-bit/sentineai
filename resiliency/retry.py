from __future__ import annotations

import time
from collections.abc import Callable
from typing import TypeVar


T = TypeVar("T")


def with_retry(func: Callable[[], T], *, attempts: int = 3, base_delay: float = 0.5, factor: float = 2.0) -> T:
    delay = base_delay
    last_exc: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return func()
        except Exception as exc:  # noqa: PERF203
            last_exc = exc
            if attempt == attempts:
                break
            time.sleep(delay)
            delay *= factor
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("retry wrapper failed without exception")
