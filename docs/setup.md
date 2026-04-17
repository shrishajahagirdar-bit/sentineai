# SentinelAI Windows Setup

## 1. Python Environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 2. Recommended Windows Permissions

Run the collector terminal as Administrator for best visibility into:

- Security Event Log
- full process enumeration
- network connections owned by privileged services

If the collector is not elevated, SentinelAI will continue running and will emit warning events when data cannot be read.

## 3. Enable File Auditing Support

SentinelAI uses `watchdog` to observe file changes in monitored directories:

- `%USERPROFILE%\\Desktop`
- `%USERPROFILE%\\Documents`
- `%USERPROFILE%\\Downloads`

For deeper file forensics, enable Windows object access auditing:

1. Open `Local Security Policy`
2. Go to `Security Settings -> Advanced Audit Policy Configuration -> Object Access`
3. Enable `Audit File System`
4. Add auditing entries to the folders you care about

The app still runs without this, but Windows Security log coverage for file access will be lighter.

## 4. Start Telemetry Collection

```powershell
python scripts\run_collector.py
```

This starts:

- Windows Event Log polling
- process start detection
- network connection observation
- live file activity watcher
- threat scoring and incident generation

## 5. Train or Refresh the ML Models

Collect telemetry for a while first, then run:

```powershell
python scripts\train_models.py
```

Training is based on real local telemetry plus analyst feedback and rule-assisted bootstrap labels.

## 6. Launch the SOC Dashboard

```powershell
streamlit run dashboard\app.py
```

## 7. Operational Notes

- `storage/events/telemetry.jsonl`: raw and status telemetry
- `storage/incidents/incidents.jsonl`: scored threat events
- `storage/baselines/user_baselines.json`: per-user UEBA baselines
- `storage/models/`: trained model package and metadata

## 8. Safety Model

Response states are:

- `0-30`: Monitor
- `30-60`: Alert
- `60-85`: Restrict actions (log only)
- `85-100`: Block process (simulation only)

SentinelAI does not terminate processes automatically.
