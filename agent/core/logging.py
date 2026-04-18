from __future__ import annotations

import logging
from pathlib import Path

from observability.logging import configure_json_logger


def configure_logger(path: Path) -> logging.Logger:
    return configure_json_logger("sentinelai.agent", path)
