from __future__ import annotations

from pathlib import Path

import pandas as pd


def find_files(directory: Path, patterns: list[str]) -> list[Path]:
    discovered: list[Path] = []
    for pattern in patterns:
        discovered.extend(sorted(directory.rglob(pattern)))
    return discovered


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [column.strip().lower().replace(" ", "_").replace("/", "_") for column in df.columns]
    return df


def first_available(df: pd.DataFrame, candidates: list[str], default: str | int | float | None = None) -> pd.Series:
    for candidate in candidates:
        if candidate in df.columns:
            return df[candidate]
    return pd.Series([default] * len(df))

