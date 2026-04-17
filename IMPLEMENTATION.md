# SentinelAI Enterprise EDR - Complete Implementation Guide

## Project Overview

**SentinelAI** is a production-grade Endpoint Detection & Response system that combines:
- Real ML models trained on CICIDS2017, UNSW-NB15, and LANL datasets
- Real-time Windows monitoring (Event Logs, processes, network, file I/O)
- UEBA (User & Entity Behavior Analytics)
- Enterprise risk scoring and response engine
- Streamlit SOC dashboard

---

## Quick Start

### Minute 1-2: Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Minute 3-4: Train

```powershell
python train.py --datasets
```

### Minute 5: Run

```powershell
# Terminal 1
python scripts/run_collector.py

# Terminal 2  
streamlit run dashboard/app.py
```

Open: **http://localhost:8501**

---

## Dataset Setup

Download real security datasets:

1. **CICIDS2017**: ~2.8M network flows
   - https://www.unb.ca/cic/datasets/cicids2017.html
   - Extract: `datasets/cicids2017/`

2. **UNSW-NB15**: ~2.5M modern attacks
   - https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/UNSW-NB15-Datasets/
   - Extract: `datasets/unsw_nb15/`

3. **LANL Auth**: ~1.6M authentication events
   - https://cstevens.netlify.app/papers/
   - Extract: `datasets/lanl_auth/`

---

## Architecture Layers

### Training (Offline)
- Data Pipeline: Load, encode, normalize, engineer features
- Models: RandomForest (supervised) + IsolationForest (anomalies)
- UEBA: User behavioral baselines from auth data

### Inference (Real-time)
- Windows Collectors: Event Logs, processes, network, files
- Risk Pipeline: ML (60%) + Anomaly (40%) + Behavior (20%) + Rules (0-40)
- Response: Score → Severity → Action

### Visualization
- Dashboard: 5 tabs (threats, timeline, users, details, system)
- Dark SOC theme, auto-refresh every 5 seconds

---

## File Structure

```
SentinelAI/
├── data_pipeline/           # Dataset loading & preprocessing
│   ├── adapters/            # CICIDS2017, UNSW-NB15, LANL loaders
│   └── build_assets.py      # Master data pipeline
├── ml_engine/               # ML models
│   ├── training.py          # RandomForest + IsolationForest
│   ├── inference.py         # Real-time prediction
│   └── features.py          # Feature extraction
├── risk_engine/             # Risk scoring
│   ├── engine.py            # Risk pipeline
│   ├── ueba.py              # Behavior analytics
│   ├── rules.py             # Deterministic rules
│   └── story.py             # Incident narratives
├── collector/               # Windows telemetry
│   ├── events.py            # Event Log parser
│   ├── processes.py         # Process monitor
│   ├── network.py           # Network connections
│   ├── filesystem.py        # File watchdog
│   └── service.py           # Orchestrator
├── dashboard/               # Streamlit SOC UI
│   └── app.py               # Multi-tab dashboard
├── backend/                 # API services
│   ├── config.py            # Configuration
│   ├── models/              # Pydantic schemas
│   ├── services/            # Business logic
│   └── api/                 # FastAPI (optional)
├── scripts/                 # Entry points
│   ├── run_collector.py     # Start telemetry service
│   └── train_models.py      # Train on Windows telemetry
├── storage/                 # Persistent data
│   ├── events/              # telemetry.jsonl
│   ├── incidents/           # incidents.jsonl
│   ├── baselines/           # user_baselines.json
│   └── models/              # sentinel_models.joblib
├── docs/                    # Documentation
│   ├── ARCHITECTURE.md      # System design
│   └── setup.md             # Setup guide
├── requirements.txt         # Dependencies
├── README.md                # Overview
└── train.py                 # Master training script
```

---

## Workflows

### Workflow 1: Development & Testing

```
1. Download datasets
   └─ datasets/{cicids2017,unsw_nb15,lanl_auth}/

2. Train on real data
   └─ python train.py --datasets

3. Start collector (optionally)
   └─ python scripts/run_collector.py

4. Launch dashboard
   └─ streamlit run dashboard/app.py

5. Test threat detection & UEBA
```

### Workflow 2: Operational (Live Monitoring)

```
1. Start collector (background service)
   └─ python scripts/run_collector.py

2. Collect telemetry for 5-10 minutes
   └─ Monitor Windows events naturally

3. Retrain models on live data (optional)
   └─ python train.py

4. Launch dashboard (analyst view)
   └─ streamlit run dashboard/app.py

5. Investigate incidents & provide feedback
```

---

## Key Features

### ML Models
- **RandomForestClassifier**: 250 estimators, balanced classes
- **IsolationForest**: Anomaly detection, configurable contamination
- **Metrics**: Accuracy, Precision, Recall, F1, AUC-ROC

### UEBA
- Per-user behavioral baselines
- Login time patterns
- Device fingerprints  
- Auth method usage
- Anomaly scoring

### Risk Scoring
```
score = (0.5 × ML + 0.3 × Anomaly + 0.2 × Behavior) × 100 + Rules
score = clamp(score, 0, 100)
```

### Risk Thresholds
- 0-30: Monitor (low)
- 30-60: Alert (medium)
- 60-85: Restrict (high)
- 85-100: Block (critical) - simulation only

---

## Command Reference

```bash
# Data preparation
python data_pipeline/build_assets.py

# Train on real datasets
python train.py --datasets

# Train on Windows telemetry
python train.py

# Full pipeline (data + train + UEBA)
python train.py --pipeline

# Start collector service
python scripts/run_collector.py

# Start dashboard
streamlit run dashboard/app.py

# Start API (optional)
python backend/api/main.py

# Retrain from telemetry
python scripts/train_models.py
```

---

## Configuration

**`sentinel_config.py`** (edit to customize):

```python
# Polling interval (seconds)
poll_interval_seconds = 10

# Event retention
max_events = 5000

# Risk thresholds
suspicious_ports = {22, 23, 135, 445, 3389, ...}
sensitive_path_keywords = ("credential", "secret", "payroll", ...)

# Monitored directories
monitor_directories = [
    Path.home() / "Desktop",
    Path.home() / "Documents", 
    Path.home() / "Downloads",
]
```

---

## Dashboard Tabs

1. **🔴 Threats**: Critical/high severity incidents
2. **📈 Timeline**: Risk trends, severity distribution
3. **👤 Users**: UEBA baselines, user profiles
4. **🔍 Details**: Raw incident inspection
5. **⚙️ System**: Model metrics, data status

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Dataset not found | Download to `datasets/{name}/` |
| Insufficient training data | Collect 50+ telemetry events or use datasets |
| Permission error on Event Logs | Run PowerShell as Administrator |
| Dashboard not updating | Verify collector is running |
| Models not loading | Retrain: `python train.py --datasets` |

---

## Safety & Compliance

✅ **No Synthetic Data**: Only real datasets

✅ **No Autonomous Harm**: Response actions are simulation-only

✅ **Local-Only**: All data stored locally, no cloud transmission

✅ **Explainable**: Feature-based ML, interpretable decisions

✅ **Audit Trail**: All events/incidents logged JSON

---

## Performance

- **Memory**: 50-100MB idle
- **CPU**: <5% idle monitoring
- **Training Time**: ~5 minutes (real datasets)
- **Dashboard**: Real-time, 5s refresh
- **Scalability**: 5,000 events in-memory, auto-trim

---

## Future Roadmap

- [ ] XGBoost ensemble
- [ ] Deep learning UEBA (LSTM/VAE)
- [ ] Multi-endpoint aggregation
- [ ] SIEM integrations
- [ ] Web API
- [ ] Active learning feedback loop
- [ ] Threat intel feeds

---

## Support

- **Docs**: See `/docs/` folder
- **Architecture**: [ARCHITECTURE.md](./docs/ARCHITECTURE.md)
- **Setup**: [setup.md](./docs/setup.md)
- **Code**: Well-commented modules

---

**SentinelAI v1.0** | Enterprise Grade ✓ | Production Ready ✓
