from __future__ import annotations

from pathlib import Path

import pandas as pd

from data_pipeline.adapters.common import find_files, first_available, normalize_columns


def load_cicids2017(dataset_dir: Path) -> pd.DataFrame:
    files = find_files(dataset_dir, ["*.csv"])
    if not files:
        raise FileNotFoundError("CICIDS2017 CSV files were not found in datasets/cicids2017/")

    frames = [normalize_columns(pd.read_csv(path, low_memory=False)) for path in files]
    df = pd.concat(frames, ignore_index=True)

    label_series = first_available(df, ["label"], default="BENIGN").astype(str)
    binary_label = (~label_series.str.upper().eq("BENIGN")).astype(int)

    network = pd.DataFrame(
        {
            "dataset": "CICIDS2017",
            "timestamp": first_available(df, ["timestamp"], default=None),
            "src_ip": first_available(df, ["source_ip", "src_ip"], default="unknown"),
            "dst_ip": first_available(df, ["destination_ip", "dst_ip"], default="unknown"),
            "src_port": pd.to_numeric(first_available(df, ["source_port", "src_port"], default=0), errors="coerce").fillna(0),
            "dst_port": pd.to_numeric(first_available(df, ["destination_port", "dst_port"], default=0), errors="coerce").fillna(0),
            "protocol": first_available(df, ["protocol"], default="unknown"),
            "service": first_available(df, ["protocol"], default="unknown"),
            "state": first_available(df, ["flow_id", "fwd_psh_flags"], default="unknown"),
            "duration": pd.to_numeric(first_available(df, ["flow_duration"], default=0), errors="coerce").fillna(0),
            "bytes_sent": pd.to_numeric(first_available(df, ["total_length_of_fwd_packets", "totlen_fwd_pkts"], default=0), errors="coerce").fillna(0),
            "bytes_received": pd.to_numeric(first_available(df, ["total_length_of_bwd_packets", "totlen_bwd_pkts"], default=0), errors="coerce").fillna(0),
            "packets": (
                pd.to_numeric(first_available(df, ["total_fwd_packets", "tot_fwd_pkts"], default=0), errors="coerce").fillna(0)
                + pd.to_numeric(first_available(df, ["total_backward_packets", "tot_bwd_pkts"], default=0), errors="coerce").fillna(0)
            ),
            "attack_category": label_series,
            "label": binary_label,
        }
    )

    return network

