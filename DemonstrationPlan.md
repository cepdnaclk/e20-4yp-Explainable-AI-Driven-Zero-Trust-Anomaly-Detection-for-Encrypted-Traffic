# Demonstration Plan — Zero-Trust XAI Pipeline
**Date:** March 2026 | **Team:** e20420Janith, e20449Sandaru, e20288

---

## Pre-Demo Checklist (Night Before)

- [ ] Verify models exist: `ls models/{sentry_model_v2.pkl,ddl_40feat.pkl}`
- [ ] Train DDL if missing (see QUICK_START.md Step 1)
- [ ] Test demo script: `bash FullSDNPipeline/run_demo.sh demo`
- [ ] Confirm CIC-IDS PCAPs accessible: `ls /scratch1/.../CICDataset/PCAP/Labeled/Friday/`
- [ ] Bring: Switch, patch cables (×3), laptop with SSH, HDMI cable

---

## Hardware Setup

```
┌───────────────┐         ┌──────────────────────┐
│  Laptop 1     │ Port 1  │  Switch (Cisco/HP)   │
│  (Traffic     │────────▶│                      │
│   Source)     │         │  Port 1 = source     │
└───────────────┘         │  Port 2 = unused     │
                          │  Port 3 = SPAN dest  │────────▶ Pipeline Machine (eth1)
                          └──────────────────────┘
```

### Switch Config (Cisco)
```
enable
configure terminal
monitor session 1 source interface GigabitEthernet0/1 both
monitor session 1 destination interface GigabitEthernet0/3
end
write memory
```

### Switch Config (HP ProCurve)
```
configure
mirror 1 port 3
interface 1
  monitor all both mirror 1
write memory
```

---

## Demo Day — Four Terminal Layout

| Terminal | Purpose | Command |
|----------|---------|---------|
| **T1** | Pipeline | `python FullSDNPipeline/sdn_pipeline.py --pcap-dir .../Labeled/Friday --limit 200` |
| **T2** | Packet Shooter | `python FullSDNPipeline/packet_shooter.py --pcap-dir .../Labeled/Friday --rate-multiplier 1.0 --limit 200` |
| **T3** | Monitor Logs | `tail -f logs/sdn_pipeline_results.json` |
| **T4** | GPU Monitor | `watch -n2 nvidia-smi` |

---

## Demo Script (Step by Step)

### Act 1 — Setup (2 min)
```bash
# All terminals:
cd /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate
```

### Act 2 — Demo Mode (3 min)
```bash
# T1: Run synthetic demo first to show the pipeline works
python FullSDNPipeline/sdn_pipeline.py --demo --n-flows 30
```

**Talking points:**
- "Stage 1 (BCC v2) uses 28 features from a Decision Tree to pre-screen traffic"
- "Only flows flagged ATTACK go to Stage 2 (DDL + XAI)"
- "Features are extracted ONCE and shared between both models"
- "Watch the confusion matrix at the end — zero leaks"

### Act 3 — Real PCAP Replay (5 min)
```bash
# T1: Run against real CIC-IDS-2017 PCAPs
python FullSDNPipeline/sdn_pipeline.py \
    --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \
    --limit 500 \
    --output logs/friday_demo.json
```

**Talking points:**
- "These are REAL network captures from the CIC-IDS-2017 dataset"
- "DDoS, PortScan, and Bot attacks mixed with normal HTTPS traffic"
- "The pipeline processes ~50-100 flows/second"
- "XAI explains WHY each anomaly was blocked"

### Act 4 — Packet Shooter with Real Timing (3 min)
```bash
# T2: Replay with realistic inter-flow timing
python FullSDNPipeline/packet_shooter.py \
    --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \
    --rate-multiplier 2.0 \
    --limit 100
```

**Talking points:**
- "Packet shooter replays traffic at 2x real speed from the original PCAP timestamps"
- "Every flow is processed through the full pipeline — same path as live traffic"
- "Switch table rules are installed for each decision"

### Act 5 — Results & Summary (2 min)

Show the JSON results:
```bash
python -c "
import json
with open('logs/friday_demo.json') as f:
    data = json.load(f)
print('Stats:', json.dumps(data['stats'], indent=2))
print('Rules:', len(data['switch_rules']))
"
```

---

## Fallback Options

| Issue | Fallback |
|-------|----------|
| No physical switch available | Skip Act 1 hardware, use demo + PCAP modes |
| DDL model not trained | Use `--demo` mode; DDL disabled but BCC still works |
| GPU not available | DDL works on CPU (slower) |
| PCAPs not accessible | Use `--demo` mode |

---

## Key Metrics to Highlight

| Metric | Target | Expected |
|--------|--------|----------|
| Attack Recall | > 99% | ~99.5%+ |
| False Positive Rate | < 5% | ~2-3% |
| Stage 1 latency | < 1ms | ~50 µs |
| Stage 2 latency | < 100ms | ~45 ms |
| Throughput | > 50 flows/s | ~100 flows/s |
