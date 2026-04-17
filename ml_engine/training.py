from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from collector.storage import read_jsonl, save_json
from ml_engine.features import events_to_frame
from sentinel_config import CONFIG

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _bootstrap_label(event: dict[str, Any]) -> int:
    """Bootstrap labels from event data and feedback."""
    if event.get("feedback_label") == "confirmed_threat":
        return 1
    if event.get("feedback_label") == "false_positive":
        return 0

    # Heuristic scoring for anomalies
    score = 0
    if event.get("event_type") == "login_failure":
        score += 1
    if event.get("unknown_process"):
        score += 1
    if event.get("unusual_network_ip"):
        score += 1
    if event.get("suspicious_port"):
        score += 1
    if event.get("sensitive_file_access"):
        score += 1
    if event.get("event_type") == "privileged_logon":
        score += 1
    return 1 if score >= 2 else 0


def train_models(min_events: int = 50, use_datasets: bool = False) -> dict[str, Any]:
    """
    Train ML models on telemetry or real cybersecurity datasets.
    
    Args:
        min_events: Minimum events required to train
        use_datasets: If true, load from CICIDS2017/UNSW-NB15/LANL
    
    Returns:
        Training metadata with status and metrics
    """
    logger.info("🚀 Training SentinelAI ML Models")
    logger.info("=" * 70)
    
    # Load training data
    if use_datasets:
        logger.info("📊 Loading real cybersecurity datasets...")
        try:
            from data_pipeline.build_assets import DataPipeline
            pipeline = DataPipeline()
            network_data, auth_data = pipeline.load_all_datasets()
            
            if network_data is None or network_data.empty:
                logger.error("❌ Failed to load network datasets")
                return {
                    "status": "failed",
                    "message": "Could not load CICIDS2017 or UNSW-NB15",
                    "trained_at": datetime.now(timezone.utc).isoformat(),
                }
            
            X = pipeline.engineer_network_features(network_data)
            X = pipeline.normalize_features(X)
            
            if "label" not in X.columns:
                logger.error("❌ No labels in dataset")
                return {
                    "status": "failed",
                    "message": "Dataset missing 'label' column",
                    "trained_at": datetime.now(timezone.utc).isoformat(),
                }
            
            y = X["label"].copy()
            X = X.drop(columns=["label"], errors="ignore")
            
            logger.info(f"✓ Loaded {len(X):,} network samples")
            
        except Exception as e:
            logger.error(f"❌ Dataset loading failed: {e}")
            return {
                "status": "failed",
                "message": f"Dataset loading error: {str(e)}",
                "trained_at": datetime.now(timezone.utc).isoformat(),
            }
    else:
        # Use Windows telemetry
        logger.info("📝 Loading Windows telemetry...")
        events = read_jsonl(CONFIG.event_store, limit=None)
        telemetry = [event for event in events if event.get("status") == "ok"]
        
        if len(telemetry) < min_events:
            logger.warning(f"⚠ Insufficient telemetry: {len(telemetry)}/{min_events}")
            metadata = {
                "status": "insufficient_data",
                "message": f"Need at least {min_events} telemetry events before training.",
                "observed_events": len(telemetry),
                "trained_at": datetime.now(timezone.utc).isoformat(),
            }
            save_json(CONFIG.model_metadata_store, metadata)
            return metadata
        
        labels = [_bootstrap_label(event) for event in telemetry]
        if len(set(labels)) < 2:
            logger.warning("⚠ Insufficient class balance")
            metadata = {
                "status": "insufficient_class_balance",
                "message": "Training requires both benign and suspicious examples.",
                "observed_events": len(telemetry),
                "trained_at": datetime.now(timezone.utc).isoformat(),
            }
            save_json(CONFIG.model_metadata_store, metadata)
            return metadata
        
        X = events_to_frame(telemetry)
        y = pd.Series(labels)
        logger.info(f"✓ Loaded {len(X)} telemetry samples")
    
    # Train/test split
    logger.info("📐 Train/test split (75/25, stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )
    
    logger.info(f"  Training: {len(X_train)} samples")
    logger.info(f"  Testing: {len(X_test)} samples")
    logger.info(f"  Class distribution: {(y_train == 0).sum()} benign, {(y_train == 1).sum()} suspicious")
    
    # Train RandomForest Classifier
    logger.info("🌳 Training RandomForestClassifier...")
    classifier = RandomForestClassifier(
        n_estimators=250,
        random_state=42,
        class_weight="balanced",
        min_samples_leaf=2,
        n_jobs=-1,
        max_depth=20,
    )
    classifier.fit(X_train, y_train)
    
    # Evaluate classifier
    y_pred = classifier.predict(X_test)
    y_proba = classifier.predict_proba(X_test)
    
    try:
        auc_score = roc_auc_score(y_test, y_proba[:, 1])
    except:
        auc_score = 0.0
    
    logger.info(f"  Accuracy: {classifier.score(X_test, y_test):.4f}")
    logger.info(f"  Precision: {precision_score(y_test, y_pred, zero_division=0):.4f}")
    logger.info(f"  Recall: {recall_score(y_test, y_pred, zero_division=0):.4f}")
    logger.info(f"  F1-Score: {f1_score(y_test, y_pred, zero_division=0):.4f}")
    logger.info(f"  AUC-ROC: {auc_score:.4f}")
    
    # Train Isolation Forest for anomaly detection
    logger.info("🔍 Training IsolationForest (anomaly detection)...")
    contamination_rate = min(max(float(np.mean(y_train)), 0.02), 0.25)
    anomaly_model = IsolationForest(
        n_estimators=200,
        contamination=contamination_rate,
        random_state=42,
        n_jobs=-1,
    )
    
    # Fit on benign data to detect anomalies
    benign_data = X_train[y_train == 0] if (y_train == 0).any() else X_train
    anomaly_model.fit(benign_data)
    logger.info(f"  Anomaly contamination rate: {contamination_rate:.4f}")
    
    # Save models
    logger.info("💾 Saving model artifacts...")
    package = {
        "classifier": classifier,
        "anomaly_model": anomaly_model,
        "feature_columns": list(X.columns),
        "scaler": StandardScaler(),
    }
    joblib.dump(package, CONFIG.model_store)
    logger.info(f"  ✓ {CONFIG.model_store}")
    
    # Generate report
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    
    metadata = {
        "status": "trained",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "data_source": "datasets" if use_datasets else "telemetry",
        "observed_events": len(X),
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "class_balance": {
            "benign": int((y == 0).sum()),
            "suspicious": int((y == 1).sum()),
        },
        "model_performance": {
            "accuracy": round(float(classifier.score(X_test, y_test)), 4),
            "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
            "f1": round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
            "auc_roc": round(float(auc_score), 4),
        },
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "feature_count": len(X.columns),
        "features": list(X.columns),
    }
    
    save_json(CONFIG.model_metadata_store, metadata)
    logger.info(f"  ✓ {CONFIG.model_metadata_store}")
    
    logger.info("=" * 70)
    logger.info("✅ Model training complete!")
    logger.info(f"   Accuracy: {metadata['model_performance']['accuracy']}")
    logger.info(f"   F1-Score: {metadata['model_performance']['f1']}")
    logger.info("=" * 70)
    
    return metadata


if __name__ == "__main__":
    print(json.dumps(train_models(), indent=2))
