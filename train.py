"""
SentinelAI Master Training Script
=================================

Trains complete ML ensemble on real cybersecurity datasets:
- CICIDS2017: Network intrusion detection
- UNSW-NB15: Modern attack classification
- LANL: User behavior anomaly detection

Produces deployable models for:
1. Supervised classification (RandomForest)
2. Unsupervised anomaly detection (IsolationForest)
3. UEBA behavioral profiles
"""

import argparse
import json
import logging
import sys
from pathlib import Path

import pandas as pd

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s"
)
logger = logging.getLogger(__name__)


def train_from_datasets() -> None:
    """Train models on real cybersecurity datasets."""
    logger.info("=" * 80)
    logger.info("SentinelAI Enterprise Model Training")
    logger.info("=" * 80)
    
    # Step 1: Load and preprocess datasets
    logger.info("\n✅ STAGE 1: Data Pipeline")
    logger.info("-" * 80)
    
    try:
        from data_pipeline.build_assets import DataPipeline
        pipeline = DataPipeline()
        network_data, auth_data = pipeline.load_all_datasets()
        
        if network_data is None or network_data.empty:
            logger.error("❌ Failed to load network datasets")
            return
        
        logger.info(f"✓ Network records loaded: {len(network_data):,}")
        logger.info(f"✓ Auth records loaded: {len(auth_data) if auth_data is not None else 0:,}")
        
        # Save preprocessed assets
        output_dir = Path(__file__).parent / "data_pipeline" / "processed"
        pipeline.save_artifacts(output_dir)
        logger.info(f"✓ Artifacts saved to {output_dir}")
        
    except Exception as e:
        logger.error(f"❌ Data pipeline failed: {e}")
        return
    
    # Step 2: Retrain ML models
    logger.info("\n✅ STAGE 2: ML Model Training")
    logger.info("-" * 80)
    
    try:
        from ml_engine.training import train_models
        metadata = train_models(use_datasets=True)
        
        logger.info(f"\n✓ ModelTraining Status: {metadata.get('status')}")
        if metadata.get("status") == "trained":
            perf = metadata.get("model_performance", {})
            logger.info(f"  Accuracy:  {perf.get('accuracy', 0):.4f}")
            logger.info(f"  Precision: {perf.get('precision', 0):.4f}")
            logger.info(f"  Recall:    {perf.get('recall', 0):.4f}")
            logger.info(f"  F1-Score:  {perf.get('f1', 0):.4f}")
            logger.info(f"  AUC-ROC:   {perf.get('auc_roc', 0):.4f}")
        
    except Exception as e:
        logger.error(f"❌ ML training failed: {e}")
        return
    
    # Step 3: Build UEBA profiles
    logger.info("\n✅ STAGE 3: UEBA User Profiling")
    logger.info("-" * 80)
    
    try:
        if auth_data is not None and not auth_data.empty:
            from risk_engine.ueba import UebaEngine
            ueba = UebaEngine()
            
            # Convert auth data to events format
            events = auth_data.to_dict(orient="records")
            profiles = ueba.rebuild(events)
            
            logger.info(f"✓ Built UEBA profiles for {len(profiles)} users")
            
            # Show sample profile
            if profiles:
                sample_user = list(profiles.keys())[0]
                logger.info(f"\n  Sample Profile ({sample_user}):")
                for key, value in list(profiles[sample_user].items())[:3]:
                    logger.info(f"    - {key}: {str(value)[:50]}...")
        else:
            logger.warning("⚠ No auth data for UEBA")
    
    except Exception as e:
        logger.error(f"❌ UEBA training failed: {e}")
    
    # Final summary
    logger.info("\n" + "=" * 80)
    logger.info("✅ SentinelAI Training Complete!")
    logger.info("=" * 80)
    logger.info("\nNext steps:")
    logger.info("1. Start collector:  python scripts/run_collector.py")
    logger.info("2. Open dashboard:   streamlit run dashboard/app.py")
    logger.info("3. Start API:        python scripts/run_api.py  (optional)")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SentinelAI Model Training Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Train on real datasets:
    python train.py --datasets

  Train on Windows telemetry (default):
    python train.py

  Full pipeline:
    python train.py --pipeline
        """
    )
    
    parser.add_argument(
        "--datasets",
        action="store_true",
        help="Train on CICIDS2017, UNSW-NB15, LANL datasets"
    )
    parser.add_argument(
        "--pipeline",
        action="store_true",
        help="Run complete data pipeline + training"
    )
    
    args = parser.parse_args()
    
    if args.datasets or args.pipeline:
        train_from_datasets()
    else:
        # Train on telemetry
        try:
            from ml_engine.training import train_models
            from risk_engine.ueba import UebaEngine
            
            logger.info("Training on Windows telemetry...")
            metadata = train_models()
            logger.info(f"Status: {metadata.get('status')}")
            
            ueba = UebaEngine()
            ueba.rebuild()
            logger.info("UEBA profiles rebuilt")
            
        except Exception as e:
            logger.error(f"Training failed: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
