from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from backend.config import settings
from data_pipeline.build_assets import build_processed_assets


NUMERIC_FEATURES = ["src_port", "dst_port", "duration", "bytes_sent", "bytes_received", "packets"]
CATEGORICAL_FEATURES = ["dataset", "src_ip", "dst_ip", "protocol", "service", "state"]


def build_preprocessor() -> ColumnTransformer:
    numeric_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )
    categorical_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("encoder", OneHotEncoder(handle_unknown="ignore")),
        ]
    )
    return ColumnTransformer(
        transformers=[
            ("numeric", numeric_pipeline, NUMERIC_FEATURES),
            ("categorical", categorical_pipeline, CATEGORICAL_FEATURES),
        ]
    )


def load_training_frame() -> pd.DataFrame:
    if not settings.network_export.exists() or not settings.auth_export.exists():
        build_processed_assets()

    network_df = pd.read_csv(settings.network_export)
    network_df["timestamp"] = pd.to_datetime(network_df["timestamp"], errors="coerce")
    return network_df


def train() -> dict[str, object]:
    network_df = load_training_frame()
    if network_df.empty:
        raise RuntimeError("No network events were loaded from the required real datasets.")

    X = network_df[NUMERIC_FEATURES + CATEGORICAL_FEATURES].copy()
    y = network_df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    supervised_pipeline = Pipeline(
        steps=[
            ("preprocessor", build_preprocessor()),
            ("classifier", RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")),
        ]
    )
    supervised_pipeline.fit(X_train, y_train)

    benign_train = X_train[y_train == 0]
    unsupervised_pipeline = Pipeline(
        steps=[
            ("preprocessor", build_preprocessor()),
            ("detector", IsolationForest(n_estimators=200, contamination=0.08, random_state=42)),
        ]
    )
    unsupervised_pipeline.fit(benign_train)

    probabilities = supervised_pipeline.predict_proba(X_test)[:, 1]
    predictions = supervised_pipeline.predict(X_test)
    anomaly_raw = unsupervised_pipeline.decision_function(X_test)

    metrics = {
        "roc_auc": round(float(roc_auc_score(y_test, probabilities)), 4),
        "classification_report": classification_report(y_test, predictions, output_dict=True),
        "anomaly_score_range": {
            "min": round(float(anomaly_raw.min()), 4),
            "max": round(float(anomaly_raw.max()), 4),
        },
        "training_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
    }

    settings.artifacts_dir.mkdir(parents=True, exist_ok=True)
    with settings.metrics_file.open("w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)

    joblib.dump(supervised_pipeline, settings.artifacts_dir / "supervised_pipeline.joblib")
    joblib.dump(unsupervised_pipeline, settings.artifacts_dir / "unsupervised_pipeline.joblib")

    return metrics


if __name__ == "__main__":
    try:
        result = train()
        print(json.dumps(result, indent=2))
    except FileNotFoundError as exc:
        print(
            json.dumps(
                {
                    "status": "dataset_missing",
                    "message": str(exc),
                    "required_datasets": ["UNSW-NB15", "CICIDS2017", "LANL authentication dataset"],
                },
                indent=2,
            )
        )
        raise SystemExit(1)
