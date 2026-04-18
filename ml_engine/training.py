from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from collector.attack_simulator import AttackSimulator
from collector.storage import save_json
from data_pipeline.balancer import balance_features_and_labels
from data_pipeline.dataset_validator import validate_telemetry_dataset
from ml_engine.features import events_to_frame
from sentinel_config import CONFIG
from validation.dataset_checker import check_dataset
from validation.labels import attach_standard_labels, normalize_label

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _standardize_labels(events: list[dict[str, Any]]) -> pd.Series:
    return pd.Series([normalize_label(event) for event in events], dtype=int)


def _normalize_supervised_labels(labels: pd.Series) -> pd.Series:
    if labels.dtype == object:
        normalized = labels.astype(str).str.strip().str.lower()
        return normalized.apply(lambda value: 0 if value in {"0", "normal", "benign"} else 1).astype(int)
    numeric = pd.to_numeric(labels, errors="coerce").fillna(0)
    return numeric.apply(lambda value: 0 if float(value) <= 0 else 1).astype(int)


def _clean_feature_matrix(frame: pd.DataFrame) -> pd.DataFrame:
    clean = frame.apply(pd.to_numeric, errors="coerce")
    clean = clean.replace([np.inf, -np.inf], 0.0).fillna(0.0)
    return clean.astype(float)


def _log_dataset_stats(check) -> None:
    logger.info("Dataset statistics:")
    logger.info(f"  Total samples: {check.total_samples}")
    logger.info(f"  Class distribution: normal={check.normal_count}, anomaly={check.anomaly_count}")
    logger.info(f"  Anomaly ratio: {check.anomaly_ratio:.2%}")
    logger.info(f"  Feature shape: {check.feature_shape}")
    if check.warning:
        logger.warning(f"  {check.warning}")


def _build_bootstrap_telemetry(current_events: list[dict[str, Any]], min_events: int) -> list[dict[str, Any]]:
    telemetry = list(current_events)
    if len(telemetry) >= min_events:
        return telemetry

    bootstrap_size = max(min_events, 120) - len(telemetry)
    simulator = AttackSimulator(seed=CONFIG.random_seed, attack_ratio=CONFIG.simulated_attack_ratio)
    simulated = [attach_standard_labels(event) for event in simulator.generate_stream(batch_size=bootstrap_size)]
    telemetry.extend(simulated)
    logger.info(f"Added {len(simulated)} simulated SOC events to bootstrap training")
    return telemetry


def _prepare_telemetry_dataset(
    min_events: int,
) -> tuple[pd.DataFrame, pd.Series, dict[str, Any], int, int, int] | tuple[None, None, dict[str, Any], int, int, int]:
    validation_report, telemetry = validate_telemetry_dataset(min_events=min_events)
    logger.info("Telemetry dataset validation report")
    logger.info(f"  Total events loaded: {validation_report.total_events}")
    logger.info(f"  Event type distribution: {validation_report.event_type_distribution}")
    logger.info(f"  Label distribution: {validation_report.label_distribution}")
    logger.info(f"  Imbalance ratio: {validation_report.imbalance_ratio:.2f}")

    if validation_report.total_events < min_events:
        telemetry = _build_bootstrap_telemetry(telemetry, min_events=min_events)

    telemetry = [attach_standard_labels(event) for event in telemetry]
    labels = _standardize_labels(telemetry)
    features = _clean_feature_matrix(events_to_frame(telemetry))

    total_events = len(telemetry)
    normal_count = int((labels == 0).sum())
    anomaly_count = int((labels == 1).sum())

    if total_events < min_events:
        metadata = {
            "status": "invalid_dataset",
            "message": f"Need at least {min_events} training events, found {total_events}.",
            "validation_report": validation_report.as_dict(),
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }
        save_json(CONFIG.model_metadata_store, metadata)
        return None, None, metadata, total_events, normal_count, anomaly_count

    if normal_count == 0 or anomaly_count == 0:
        metadata = {
            "status": "invalid_dataset",
            "message": "Training blocked: only one class exists after label normalization.",
            "validation_report": validation_report.as_dict(),
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }
        save_json(CONFIG.model_metadata_store, metadata)
        return None, None, metadata, total_events, normal_count, anomaly_count

    return features, labels, validation_report.as_dict(), total_events, normal_count, anomaly_count


def train_models(min_events: int = 50, use_datasets: bool = False) -> dict[str, Any]:
    logger.info("Training SentinelAI ML Models")
    logger.info("=" * 70)

    validation_report: dict[str, Any] | None = None
    total_events_loaded = 0
    normal_count = 0
    anomaly_count = 0

    if use_datasets:
        logger.info("Loading real cybersecurity datasets...")
        try:
            from data_pipeline.build_assets import DataPipeline

            pipeline = DataPipeline()
            network_data, _auth_data = pipeline.load_all_datasets()

            if network_data is None or network_data.empty:
                logger.error("Failed to load network datasets")
                return {
                    "status": "failed",
                    "message": "Could not load CICIDS2017 or UNSW-NB15",
                    "trained_at": datetime.now(timezone.utc).isoformat(),
                }

            X = pipeline.engineer_network_features(network_data)
            X = pipeline.normalize_features(X)
            if "label" not in X.columns:
                logger.error("Dataset missing label column")
                return {
                    "status": "failed",
                    "message": "Dataset missing 'label' column",
                    "trained_at": datetime.now(timezone.utc).isoformat(),
                }

            y = _normalize_supervised_labels(X["label"].copy())
            X = _clean_feature_matrix(X.drop(columns=["label"], errors="ignore"))
            total_events_loaded = len(X)
            normal_count = int((y == 0).sum())
            anomaly_count = int((y == 1).sum())
            logger.info(f"Loaded {len(X):,} network samples")
        except Exception as exc:
            logger.error(f"Dataset loading failed: {exc}")
            return {
                "status": "failed",
                "message": f"Dataset loading error: {str(exc)}",
                "trained_at": datetime.now(timezone.utc).isoformat(),
            }
    else:
        logger.info("Loading Windows telemetry...")
        X, y, validation_report, total_events_loaded, normal_count, anomaly_count = _prepare_telemetry_dataset(
            min_events=min_events
        )
        if X is None or y is None:
            return validation_report
        logger.info(f"Loaded {len(X)} telemetry samples")

    initial_check = check_dataset(X.to_numpy(dtype=float), y.to_numpy(dtype=int), minimum_samples=min_events)
    _log_dataset_stats(initial_check)
    if not initial_check.valid:
        metadata = {
            "status": "invalid_dataset",
            "message": initial_check.error,
            "dataset_check": initial_check.as_dict(),
            "validation_report": validation_report,
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }
        save_json(CONFIG.model_metadata_store, metadata)
        return metadata

    X, y = balance_features_and_labels(X, y, seed=CONFIG.random_seed)
    balanced_check = check_dataset(X.to_numpy(dtype=float), y.to_numpy(dtype=int), minimum_samples=min_events)
    _log_dataset_stats(balanced_check)
    if not balanced_check.valid:
        metadata = {
            "status": "invalid_dataset",
            "message": balanced_check.error,
            "dataset_check": balanced_check.as_dict(),
            "validation_report": validation_report,
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }
        save_json(CONFIG.model_metadata_store, metadata)
        return metadata

    logger.info("dataset validated")
    logger.info("balanced classes confirmed")
    logger.info(f"total events loaded: {total_events_loaded}")
    logger.info(f"normal count: {normal_count}")
    logger.info(f"anomaly count: {anomaly_count}")
    logger.info(f"final balanced dataset size: {len(X)}")
    logger.info(f"feature shape: {X.shape}")
    logger.info("training started")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    classifier = RandomForestClassifier(
        n_estimators=250,
        random_state=42,
        class_weight="balanced",
        min_samples_leaf=2,
        n_jobs=1,
        max_depth=20,
    )
    classifier.fit(X_train.to_numpy(dtype=float), y_train.to_numpy(dtype=int))

    x_test_np = X_test.to_numpy(dtype=float)
    y_test_np = y_test.to_numpy(dtype=int)
    y_pred = classifier.predict(x_test_np)
    y_proba = classifier.predict_proba(x_test_np)

    try:
        auc_score = roc_auc_score(y_test_np, y_proba[:, 1])
    except Exception:
        auc_score = 0.0

    logger.info(f"Accuracy: {classifier.score(x_test_np, y_test_np):.4f}")
    logger.info(f"Precision: {precision_score(y_test_np, y_pred, zero_division=0):.4f}")
    logger.info(f"Recall: {recall_score(y_test_np, y_pred, zero_division=0):.4f}")
    logger.info(f"F1-Score: {f1_score(y_test_np, y_pred, zero_division=0):.4f}")
    logger.info(f"AUC-ROC: {auc_score:.4f}")

    contamination_rate = min(max(float(np.mean(y_train)), 0.02), 0.25)
    anomaly_model = IsolationForest(
        n_estimators=200,
        contamination=contamination_rate,
        random_state=42,
        n_jobs=1,
    )
    benign_data = X_train[y_train == 0] if (y_train == 0).any() else X_train
    anomaly_model.fit(benign_data.to_numpy(dtype=float))

    package = {
        "classifier": classifier,
        "anomaly_model": anomaly_model,
        "feature_columns": list(X.columns),
        "scaler": StandardScaler(),
    }
    joblib.dump(package, CONFIG.model_store)

    metadata = {
        "status": "trained",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "data_source": "datasets" if use_datasets else "telemetry",
        "observed_events": len(X),
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "class_balance": {
            "normal": int((y == 0).sum()),
            "anomaly": int((y == 1).sum()),
        },
        "dataset_check": balanced_check.as_dict(),
        "validation_report": validation_report,
        "model_performance": {
            "accuracy": round(float(classifier.score(x_test_np, y_test_np)), 4),
            "precision": round(float(precision_score(y_test_np, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test_np, y_pred, zero_division=0)), 4),
            "f1": round(float(f1_score(y_test_np, y_pred, zero_division=0)), 4),
            "auc_roc": round(float(auc_score), 4),
        },
        "confusion_matrix": confusion_matrix(y_test_np, y_pred).tolist(),
        "feature_count": len(X.columns),
        "features": list(X.columns),
    }
    save_json(CONFIG.model_metadata_store, metadata)

    logger.info("model saved successfully")
    logger.info("=" * 70)
    logger.info("Model training complete")
    logger.info(f"Accuracy: {metadata['model_performance']['accuracy']}")
    logger.info(f"F1-Score: {metadata['model_performance']['f1']}")
    logger.info("=" * 70)
    return metadata


if __name__ == "__main__":
    print(json.dumps(train_models(), indent=2))
