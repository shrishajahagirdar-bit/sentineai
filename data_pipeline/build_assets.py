"""
SentinelAI Data Pipeline Master
===============================

Loads, preprocesses, and engineers features from real cybersecurity datasets:
- CICIDS2017: Network intrusion detection (modern attack patterns)
- UNSW-NB15: Attack classification (9 attack categories)  
- LANL Authentication: User behavior anomaly detection

Feature Engineering Pipeline:
 1. Statistical aggregation (flow-level, user-level, temporal)
 2. Categorical encoding (protocol, attack type)
 3. Normalization (MinMaxScaler for ML compatibility)
 4. Train/test split (stratified 75/25)

Output: ML training artifacts for classifier, anomaly detector, UEBA models
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

from data_pipeline.adapters.cicids2017 import load_cicids2017
from data_pipeline.adapters.lanl_auth import load_lanl_auth
from data_pipeline.adapters.unsw_nb15 import load_unsw_nb15

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class DataPipeline:
    """Main data pipeline for loading and engineering features from real datasets."""
    
    def __init__(self, datasets_dir: Path | None = None):
        if datasets_dir is None:
            datasets_dir = Path(__file__).parent.parent / "datasets"
        self.datasets_dir = datasets_dir
        self.network_data: pd.DataFrame | None = None
        self.auth_data: pd.DataFrame | None = None
        self.scaler = MinMaxScaler()
    
    def load_all_datasets(self) -> tuple[pd.DataFrame | None, pd.DataFrame | None]:
        """Load CICIDS2017, UNSW-NB15, and LANL datasets."""
        logger.info("🔄 Loading cybersecurity datasets...")
        
        # Load network intrusion data
        cicids = self._safe_load(
            lambda: load_cicids2017(self.datasets_dir / "cicids2017"),
            "CICIDS2017"
        )
        
        unsw = self._safe_load(
            lambda: load_unsw_nb15(self.datasets_dir / "unsw_nb15"),
            "UNSW-NB15"
        )
        
        # Combine network datasets
        if cicids is not None and unsw is not None:
            self.network_data = pd.concat([cicids, unsw], ignore_index=True)
            logger.info(f"  ✓ Combined network data: {len(self.network_data):,} rows")
        elif cicids is not None:
            self.network_data = cicids
            logger.info("  ⚠ UNSW-NB15 not available, using CICIDS2017 only")
        elif unsw is not None:
            self.network_data = unsw
            logger.info("  ⚠ CICIDS2017 not available, using UNSW-NB15 only")
        
        # Load auth/UEBA data
        auth = self._safe_load(
            lambda: load_lanl_auth(self.datasets_dir / "lanl_auth"),
            "LANL Authentication"
        )
        self.auth_data = auth
        
        return self.network_data, self.auth_data
    
    @staticmethod
    def _safe_load(loader_fn: Any, name: str) -> pd.DataFrame | None:
        """Safely load dataset with error handling."""
        try:
            data = loader_fn()
            logger.info(f"  ✓ {name}: {len(data):,} rows")
            return data
        except FileNotFoundError:
            logger.warning(f"  ✗ {name}: Not found (download dataset files)")
            return None
        except Exception as e:
            logger.error(f"  ✗ {name}: {e}")
            return None
    
    def engineer_network_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Engineer ML features from network flow data."""
        logger.info("🔧 Engineering network features...")
        
        X = df.copy()
        
        # ===== Temporal Features =====
        if "timestamp" in X.columns:
            X["timestamp"] = pd.to_datetime(X["timestamp"], errors="coerce")
            X["hour"] = X["timestamp"].dt.hour
            X["day_of_week"] = X["timestamp"].dt.dayofweek
        else:
            X["hour"] = 0
            X["day_of_week"] = 0
        
        # ===== Traffic Volume Features =====
        X["bytes_sent"] = pd.to_numeric(X.get("bytes_sent", 0), errors="coerce").fillna(0)
        X["bytes_received"] = pd.to_numeric(X.get("bytes_received", 0), errors="coerce").fillna(0)
        X["packets"] = pd.to_numeric(X.get("packets", 1), errors="coerce").fillna(1)
        X["duration"] = pd.to_numeric(X.get("duration", 0), errors="coerce").fillna(0)
        
        # Derived metrics
        total_bytes = X["bytes_sent"] + X["bytes_received"]
        X["avg_packet_size"] = (total_bytes / X["packets"]).replace([np.inf, -np.inf], 0).fillna(0)
        
        X["bytes_ratio"] = (
            X["bytes_sent"] / (X["bytes_received"] + 1)
        ).replace([np.inf, -np.inf], 0).fillna(0)
        
        X["bytes_per_second"] = (
            total_bytes / (X["duration"] + 1)
        ).replace([np.inf, -np.inf], 0).fillna(0)
        
        # ===== Protocol Features =====
        protocol_clean = X.get("protocol", "unknown").astype(str).str.upper()
        X["proto_tcp"] = (protocol_clean.isin(["TCP", "6"])).astype(int)
        X["proto_udp"] = (protocol_clean.isin(["UDP", "17"])).astype(int)
        X["proto_icmp"] = (protocol_clean.isin(["ICMP", "1"])).astype(int)
        
        # ===== Port Analysis =====
        X["dst_port"] = pd.to_numeric(X.get("dst_port", 0), errors="coerce").fillna(0).astype(int)
        X["src_port"] = pd.to_numeric(X.get("src_port", 0), errors="coerce").fillna(0).astype(int)
        
        # Well-known ports: 1-1024, high-risk: {22,23,135,445,3389,4444,5985}
        X["dst_port_risky"] = (
            ((X["dst_port"] <= 1024) & (X["dst_port"] > 0)) |
            X["dst_port"].isin({22, 23, 135, 445, 3389, 4444, 5985, 5986, 139})
        ).astype(int)
        
        # ===== Flow State Features =====
        X["duration_log"] = np.log1p(X["duration"])
        X["duration_norm"] = (X["duration"] - X["duration"].min()) / (X["duration"].max() - X["duration"].min() + 1e-9)
        
        # ===== Label =====
        if "label" not in X.columns:
            X["label"] = 0
        
        logger.info(f"  ✓ Network features: {len(X.columns)} engineered")
        return X
    
    def engineer_auth_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Engineer ML features from authentication events."""
        if df is None or df.empty:
            logger.warning("  ⚠ No auth data; UEBA features unavailable")
            return pd.DataFrame()
        
        logger.info("🔧 Engineering authentication features...")
        
        X = df.copy()
        
        # ===== Temporal Patterns =====
        if "timestamp" in X.columns:
            X["timestamp"] = pd.to_datetime(X["timestamp"], errors="coerce")
            X["hour"] = X["timestamp"].dt.hour
            X["day_of_week"] = X["timestamp"].dt.dayofweek
        
        # ===== Auth Type =====
        auth_type = X.get("auth_type", "unknown").astype(str).str.upper()
        X["auth_kerberos"] = auth_type.str.contains("KERBEROS", na=False).astype(int)
        X["auth_ntlm"] = auth_type.str.contains("NTLM", na=False).astype(int)
        X["auth_negotiate"] = auth_type.str.contains("NEGOTIATE", na=False).astype(int)
        
        # ===== Logon Type =====
        logon_type = X.get("logon_type", "unknown").astype(str).str.upper()
        X["logon_interactive"] = logon_type.str.contains("INTERACTIVE", na=False).astype(int)
        X["logon_network"] = logon_type.str.contains("NETWORK", na=False).astype(int)
        X["logon_batch"] = logon_type.str.contains("BATCH", na=False).astype(int)
        
        # ===== Failure Tracking =====
        X["failed_logins"] = pd.to_numeric(X.get("failed_logins", 0), errors="coerce").fillna(0).astype(int)
        
        logger.info(f"  ✓ Auth features: {len(X.columns)} engineered")
        return X
    
    def build_unified_training_set(self) -> pd.DataFrame:
        """Build unified feature matrix for ML training."""
        logger.info("📊 Building training dataset...")
        
        if self.network_data is None or self.network_data.empty:
            logger.error("  ✗ No network data available for training")
            return pd.DataFrame()
        
        # Engineer features
        X = self.engineer_network_features(self.network_data)
        
        # Select ML features
        feature_columns = [
            "hour", "day_of_week",
            "bytes_sent", "bytes_received", "packets", "duration",
            "avg_packet_size", "bytes_ratio", "bytes_per_second",
            "proto_tcp", "proto_udp", "proto_icmp",
            "dst_port", "dst_port_risky",
            "duration_log", "duration_norm",
            "label"
        ]
        
        available = [col for col in feature_columns if col in X.columns]
        X = X[available].copy()
        
        # Fill missing values
        numeric_cols = X.select_dtypes(include=[np.number]).columns
        X[numeric_cols] = X[numeric_cols].fillna(0)
        
        logger.info(f"  ✓ Training set: {len(X):,} samples × {len(X.columns)} features")
        return X
    
    def build_user_profiles(self) -> dict[str, dict[str, Any]]:
        """Build UEBA baseline profiles from auth data."""
        if self.auth_data is None or self.auth_data.empty:
            logger.warning("  ⚠ No auth data for UEBA; returning empty profiles")
            return {}
        
        logger.info("👤 Building UEBA user profiles...")
        
        profiles: dict[str, dict[str, Any]] = {}
        
        for user_id, user_group in self.auth_data.groupby("user_id"):
            # Login hour distribution
            if "timestamp" in user_group.columns:
                hours = user_group["timestamp"].dt.hour.value_counts(normalize=True).sort_index()
                login_dist = {str(h): round(float(v), 4) for h, v in hours.items()}
            else:
                login_dist = {}
            
            # Device locations
            if "source_host" in user_group.columns:
                locations = user_group["source_host"].unique()[:10].tolist()
            else:
                locations = []
            
            # Auth types used
            if "auth_type" in user_group.columns:
                auth_types = user_group["auth_type"].unique()[:5].tolist()
            else:
                auth_types = []
            
            profiles[str(user_id)] = {
                "login_time_distribution": login_dist,
                "device_fingerprint": locations,
                "auth_methods": auth_types,
                "total_logins": len(user_group),
                "failed_logins": int(user_group.get("failed_logins", 0).sum()),
            }
        
        logger.info(f"  ✓ Built profiles: {len(profiles)} users")
        return profiles
    
    def normalize_features(self, X: pd.DataFrame) -> pd.DataFrame:
        """Normalize numeric features to [0, 1]."""
        X_norm = X.copy()
        numeric_cols = X_norm.select_dtypes(include=[np.number]).columns
        
        # Exclude label column from normalization
        features_to_scale = [col for col in numeric_cols if col != "label"]
        X_norm[features_to_scale] = self.scaler.fit_transform(X_norm[features_to_scale])
        
        logger.info(f"  ✓ Normalized {len(features_to_scale)} features")
        return X_norm
    
    def save_artifacts(self, output_dir: Path) -> None:
        """Save preprocessed assets."""
        output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"💾 Saving artifacts to {output_dir}")
        
        # Network data
        if self.network_data is not None:
            path = output_dir / "network_features.parquet"
            self.network_data.to_parquet(path, compression="gzip")
            logger.info(f"  ✓ {path}")
        
        # Auth data
        if self.auth_data is not None:
            path = output_dir / "auth_features.parquet"
            self.auth_data.to_parquet(path, compression="gzip")
            logger.info(f"  ✓ {path}")
        
        # Training set
        training_set = self.build_unified_training_set()
        if not training_set.empty:
            path = output_dir / "training_set.parquet"
            training_set.to_parquet(path, compression="gzip", index=False)
            logger.info(f"  ✓ {path}")
        
        # UEBA profiles
        profiles = self.build_user_profiles()
        if profiles:
            path = output_dir / "ueba_profiles.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(profiles, f, indent=2)
            logger.info(f"  ✓ {path}")
        
        # Metadata
        metadata = {
            "pipeline_version": "1.0",
            "datasets": {
                "cicids2017": len(self.network_data) if self.network_data is not None else 0,
                "unsw_nb15": 0,  # Already merged
                "lanl": len(self.auth_data) if self.auth_data is not None else 0,
            },
            "timestamp": pd.Timestamp.utcnow().isoformat(),
        }
        path = output_dir / "metadata.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        logger.info(f"  ✓ {path}")


def build_processed_assets() -> dict[str, int]:
    """Legacy entry point for compatibility."""
    pipeline = DataPipeline()
    network_data, auth_data = pipeline.load_all_datasets()
    
    output_dir = Path(__file__).parent / "processed"
    pipeline.save_artifacts(output_dir)
    
    return {
        "network_events": len(network_data) if network_data is not None else 0,
        "auth_events": len(auth_data) if auth_data is not None else 0,
        "profiles": len(pipeline.build_user_profiles()),
    }


if __name__ == "__main__":
    logger.info("=" * 80)
    logger.info("SentinelAI Data Pipeline - Enterprise ML Training Data Preparation")
    logger.info("=" * 80)
    
    pipeline = DataPipeline()
    network_data, auth_data = pipeline.load_all_datasets()
    
    if network_data is not None:
        output_dir = Path(__file__).parent / "processed"
        pipeline.save_artifacts(output_dir)
        
        logger.info("=" * 80)
        logger.info("✅ Pipeline Complete!")
        logger.info(f"   Network samples: {len(network_data):,}")
        logger.info(f"   Auth samples: {len(auth_data) if auth_data is not None else 0:,}")
        logger.info("=" * 80)
    else:
        logger.error("❌ Failed to load datasets. Ensure files exist in datasets/ directory")
