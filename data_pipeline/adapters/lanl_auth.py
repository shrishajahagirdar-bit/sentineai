from __future__ import annotations

from pathlib import Path

import pandas as pd

from data_pipeline.adapters.common import find_files, normalize_columns


LANL_COLUMNS = [
    "time",
    "user",
    "src",
    "dst",
    "auth_type",
    "logon_type",
    "auth_orientation",
    "success",
]


def load_lanl_auth(dataset_dir: Path) -> pd.DataFrame:
    files = find_files(dataset_dir, ["*.csv", "*.txt", "*.txt.gz"])
    if not files:
        raise FileNotFoundError("LANL authentication files were not found in datasets/lanl_auth/")

    frames: list[pd.DataFrame] = []
    for path in files:
        if path.suffix == ".csv":
            frame = pd.read_csv(path, low_memory=False)
        else:
            frame = pd.read_csv(path, names=LANL_COLUMNS, header=None)
        frames.append(normalize_columns(frame))

    df = pd.concat(frames, ignore_index=True)
    df["time"] = pd.to_numeric(df["time"], errors="coerce").fillna(0).astype(int)
    df["timestamp"] = pd.to_datetime(df["time"], unit="s", origin="unix")
    df["success"] = df["success"].astype(str)

    auth = pd.DataFrame(
        {
            "dataset": "LANL",
            "timestamp": df["timestamp"],
            "user_id": df["user"].astype(str),
            "source_host": df["src"].astype(str),
            "destination_host": df["dst"].astype(str),
            "auth_type": df["auth_type"].astype(str),
            "logon_type": df["logon_type"].astype(str),
            "auth_orientation": df["auth_orientation"].astype(str),
            "action": (df["auth_type"].astype(str) + ":" + df["logon_type"].astype(str)),
            "failed_logins": (~df["success"].str.upper().isin(["1", "TRUE", "SUCCESS"])).astype(int),
        }
    )

    return auth

