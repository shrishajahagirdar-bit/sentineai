from __future__ import annotations

from pathlib import Path

import pandas as pd

from data_pipeline.adapters.common import find_files, first_available, normalize_columns


def load_unsw_nb15(dataset_dir: Path) -> pd.DataFrame:
    files = find_files(dataset_dir, ["*.csv"])
    if not files:
        raise FileNotFoundError("UNSW-NB15 CSV files were not found in datasets/unsw_nb15/")

    frames = [normalize_columns(pd.read_csv(path, low_memory=False)) for path in files]
    df = pd.concat(frames, ignore_index=True)

    label = first_available(df, ["label", "attack_label"], default=0)
    attack_cat = first_available(df, ["attack_cat", "attack_category"], default="normal")

    network = pd.DataFrame(
        {
            "dataset": "UNSW-NB15",
            "timestamp": first_available(df, ["timestamp", "stime"], default=None),
            "src_ip": first_available(df, ["srcip", "src_ip"], default="unknown"),
            "dst_ip": first_available(df, ["dstip", "dst_ip"], default="unknown"),
            "src_port": pd.to_numeric(first_available(df, ["sport", "src_port"], default=0), errors="coerce").fillna(0),
            "dst_port": pd.to_numeric(first_available(df, ["dsport", "dst_port"], default=0), errors="coerce").fillna(0),
            "protocol": first_available(df, ["proto", "protocol"], default="unknown"),
            "service": first_available(df, ["service"], default="unknown"),
            "state": first_available(df, ["state"], default="unknown"),
            "duration": pd.to_numeric(first_available(df, ["dur", "duration"], default=0), errors="coerce").fillna(0),
            "bytes_sent": pd.to_numeric(first_available(df, ["sbytes"], default=0), errors="coerce").fillna(0),
            "bytes_received": pd.to_numeric(first_available(df, ["dbytes"], default=0), errors="coerce").fillna(0),
            "packets": (
                pd.to_numeric(first_available(df, ["spkts"], default=0), errors="coerce").fillna(0)
                + pd.to_numeric(first_available(df, ["dpkts"], default=0), errors="coerce").fillna(0)
            ),
            "attack_category": attack_cat.astype(str),
            "label": pd.to_numeric(label, errors="coerce").fillna(0).astype(int),
        }
    )

    return network

