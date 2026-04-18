#!/usr/bin/env python3
"""
Windows Telemetry Stream Processor Service
===========================================

Startup script for the Windows telemetry stream processor.
Consumes raw Windows events and produces enriched security intelligence.

Usage:
    python scripts/run_windows_stream_processor.py
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline.windows_stream_processor import main

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | WindowsStreamProcessor | %(levelname)s | %(message)s"
    )

    main()