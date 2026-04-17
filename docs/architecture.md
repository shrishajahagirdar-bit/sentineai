# SentinelAI: Enterprise EDR Architecture

## Overview

**SentinelAI** is a production-grade Endpoint Detection & Response (EDR) system combining real ML models with real-time Windows monitoring, UEBA analytics, and enterprise risk scoring.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│              TRAINING LAYER (Offline / One-time)               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   CICIDS2017 ─┐                                               │
│               ├─ Data Pipeline (normalize, encode, features) ─┐ │
│   UNSW-NB15 ─┤                                               │ │
│               └──────────────────────────────────────────────┤ │
│   LANL Auth ──────────────────────────────────────────────────┤ │
│                                                                │ │
│       ┌─────────────────────────────────────────────────────┬┘ │
│       │                                                      │   │
│    ┌──v──────────────┐  ┌──────────────────┐  ┌──────────┐ │   │
│    │ RandomForest    │  │ Isolation Forest │  │   UEBA   │ │   │
│    │ (Supervised)    │  │ (Anomaly Detect) │  │(Behavior)│ │   │
│    └──┬──────────────┘  └────────┬─────────┘  └────┬─────┘ │   │
│       │                          │                  │        │   │
│       └──────────────────────────┼──────────────────┘        │   │
│                                  │                           │   │
│                        ┌─────────v────────┐                 │   │
│                        │ Model Artifacts  │                 │   │
│                        │ (Joblib, JSON)   │                 │   │
│                        └─────────────────┘                 │   │
│                                                            │   │
└────────────────────────────────────────────────────────────┘   │
                                                                 │
┌─────────────────────────────────────────────────────────────────┤
│           INFERENCE LAYER (Real-time / Continuous)             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │          Windows Telemetry Collectors                    │  │
│  │  • Event Logs (Security, System, Application)            │  │
│  │  • Process Monitor (Runtime, CPU, Memory)                │  │
│  │  • Network Monitor (Connections, Ports)                  │  │
│  │  • File Monitor (Watchdog on sensitive dirs)             │  │
│  └─────────────────────────┬────────────────────────────────┘  │
│                            │                                    │
│  ┌─────────────────────────v────────────────────────────────┐  │
│  │ Event Enrichment                                         │  │
│  │ • Risk flagging (suspicious ports, paths, etc)          │  │
│  │ • User correlation                                      │  │
│  │ • Process tree building                                 │  │
│  └─────────────────────────┬────────────────────────────────┘  │
│                            │                                    │
│  ┌─────────────────────────v────────────────────────────────┐  │
│  │ Risk Scoring Pipeline                                    │  │
│  │                                                           │  │
│  │  ML Prediction:      60% weight (0-1 → 0-60)           │  │
│  │  Anomaly Detection:  40% weight (0-1 → 0-40 bonus)     │  │
│  │  UEBA Deviation:     20% weight (0-1 → 0-20 bonus)     │  │
│  │  Rule Triggers:      0-40 adjustment points            │  │
│  │                                                           │  │
│  │  → Final Score (0-100 clamped)                         │  │
│  └─────────────────────────┬────────────────────────────────┘  │
│                            │                                    │
│  ┌─────────────────────────v────────────────────────────────┐  │
│  │ Response Engine                                          │  │
│  │ 0-30:   Monitor (low risk, advisory)                    │  │
│  │ 30-60:  Alert (medium, analyst review needed)          │  │
│  │ 60-85:  Restrict (high, block sensitive actions)       │  │
│  │ 85-100: Block (critical, full containment sim)         │  │
│  └─────────────────────────┬────────────────────────────────┘  │
│                            │                                    │
└────────────────────────────┼────────────────────────────────────┘
                             │
                   ┌─────────v─────────┐
                   │  Local Storage    │
                   │  • Events (JSONL) │
                   │  • Incidents      │
                   │  • Baselines      │
                   │  • Models         │
                   └─────────┬─────────┘
                             │
                   ┌─────────v──────────────┐
                   │  Streamlit Dashboard   │
                   │  SOC Threat View       │
                   └────────────────────────┘
```

## Core Components

### 1. Data Pipeline (`data_pipeline/`)

**Adapters** (`adapters/*.py`):
- `cicids2017.py`: Network intrusion detection dataset
- `unsw_nb15.py`: Modern attack classification  
- `lanl_auth.py`: User behavior/authentication data

**Feature Engineering** (`build_assets.py`):
- Temporal: Hour, day of week
- Traffic: Bytes ratio, packet size, throughput
- Protocol: TCP/UDP/ICMP indicators
- Ports: Well-known (1-1024) vs. high-risk detection
- Flow: Duration, normalization

### 2. ML Engine (`ml_engine/`)

**Training** (`training.py`):
- RandomForestClassifier: 250 estimators, balanced classes
- IsolationForest: Anomaly detection, configurable contamination
- Train/test split: 75/25 stratified
- Metrics: Accuracy, Precision, Recall, F1, AUC-ROC

**Inference** (`inference.py`):
- Real-time prediction on new events
- Fallback heuristics if models unavailable
- Returns: (probability, anomaly_score)

**Features** (`features.py`):
- Converts Windows telemetry → feature vectors
- Stable hashing for categorical encoding

### 3. Risk Engine (`risk_engine/`)

**Risk Scoring** (`engine.py`):
```
risk_score = (0.5 × P_ml + 0.3 × S_anom + 0.2 × D_behavior) × 100 + A_rules
risk_score = clamp(risk_score, 0, 100)
```

**Rules** (`rules.py`):
- ✗ Failed logins > 3: +20
- ✗ Unusual location: +25
- ✗ Data exfiltration: +25
- ✗ Privilege escalation: +40

**UEBA** (`ueba.py`):
- Per-user baselines from auth data
- Login hour distribution
- Device fingerprints
- Auth method usage
- Detects: Time anomalies, new devices, bulk operations

**Attack Stories** (`story.py`):
- Human-readable incident narratives
- Combines technical indicators with context

### 4. Data Collection (`collector/`)

**Windows Telemetry**:
```
┌─ events.py       → Event Log parser (login/logout/failures)
├─ processes.py    → Process monitor (psutil)
├─ network.py      → Network connections
├─ filesystem.py   → Directory watchdog (Desktop, Downloads, Docs)
├─ service.py      → Orchestrator (polls all collectors)
└─ storage.py      → JSONL persistence
```

### 5. Dashboard (`dashboard/app.py`)

**Tabs**:
1. **Threats**: Critical/high incidents with stories
2. **Timeline**: Risk trends + severity pie
3. **Users**: UEBA baseline inspection
4. **Details**: Raw incident JSON viewer
5. **System**: Model metrics + config

**Dark SOC Theme**: Enterprise-grade security monitoring aesthetics

---

## Processing Pipeline

### Training Phase
```
Raw Data → Preprocessing → Feature Engineering → Train/Test
                                                    ↓
                              RandomForest + IsolationForest
                                                    ↓
                          Model Artifacts (Joblib) + Baselines (JSON)
```

### Inference Phase
```
Windows Event → Enrichment → Feature Extraction → Risk Pipeline
                                                    ↓
                            ML + Anomaly + Behavior + Rules
                                                    ↓
                                    Risk Score (0-100)
                                                    ↓
                        Response (Monitor/Alert/Restrict/Block)
                                                    ↓  
                                    Storage + Dashboard
```

---

## Configuration

**`sentinel_config.py`**:
```python
# Storage
event_store = Path(".../storage/events/telemetry.jsonl")
incident_store = Path(".../storage/incidents/incidents.jsonl")
baseline_store = Path(".../storage/baselines/user_baselines.json")
model_store = Path(".../storage/models/sentinel_models.joblib")

# Monitoring
poll_interval_seconds = 10
max_events = 5000

# Risk thresholds
suspicious_ports = {22, 23, 135, 445, 3389, 4444, 5985, 5986}
sensitive_path_keywords = ("credential", "secret", "payroll", "finance")
```

---

## Security & Safety

✅ **No Synthetic Data**: Only real datasets (CICIDS2017, UNSW-NB15, LANL)

✅ **No Autonomous Harm**: Response actions are simulation-only for safety

✅ **Local-Only**: All data stored locally, no cloud/network transmission

✅ **Explainable**: Feature-based ML, not black box deep learning

✅ **Probabilistic**: Confidence scores, not binary decisions

---

## Future Roadmap

- [ ] XGBoost ensemble models
- [ ] Deep anomaly detection (VAE/LSTM)
- [ ] Multi-endpoint aggregation
- [ ] SIEM/alert integrations
- [ ] Web API (FastAPI)
- [ ] Active learning from analyst feedback
- [ ] Forensic export & investigation tools
- [ ] Threat intelligence feeds

---

**Enterprise Grade** ✓ | **Production Ready** ✓ | **v1.0**
