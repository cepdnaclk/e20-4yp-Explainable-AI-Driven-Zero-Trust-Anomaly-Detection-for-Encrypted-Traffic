# DemonstrationPlan.md — Full Demo Guide with Cisco/HP Switch
# Zero-Trust XAI Anomaly Detection | University of Peradeniya
# e20420Janith — Updated 2026-03-05

# Research Demonstration Plan

## System Overview — What The Demo Shows

The demo presents a **two-stage Zero-Trust pipeline** for detecting anomalies
in encrypted network traffic:

```
Switch (Cisco/HP)
  ↓ SPAN mirror (copies all traffic to controller laptop)
Pipeline Laptop (running NFStream + DDL + XAI)
  ↓ Stage 1: Decision Tree (15 features, <1ms) → Normal → FORWARD
  ↓ Stage 2: DDL + XAI (30 features, ~45ms)  → Anomaly → DROP + Explain
Ryu SDN Controller (installs DROP/ALLOW rules on switch)
```

**Zero-trust principle**: When in doubt, a flow is blocked. Every anomaly
gets an XAI explanation naming the top features that triggered the alert.

---

## Hardware Setup

### Primary: Cisco IOS / IOS-XE Switch

| Role | Equipment | Port |
|------|-----------|------|
| Switch | Cisco IOS (any model) | — |
| Traffic sources | Laptop A + Laptop B (or VMs) | Gi0/1, Gi0/2 |
| Mirror/capture | Pipeline Laptop | **Gi0/3** (SPAN destination) |
| Controller | Pipeline Laptop — Ryu | TCP 6653 (OpenFlow) |

```cisco
! Cisco SPAN configuration (run on switch):
monitor session 1 source interface GigabitEthernet0/1 - 0/2 both
monitor session 1 destination interface GigabitEthernet0/3
```

Full config: `LiveTraffic/CISCO_SWITCH_SETUP.md`

### Backup: HP ProCurve / Aruba L3 Switch

```
! HP CLI:
mirror 1 port Trk1     (or the relevant trunk)
interface A3
  monitor all
```

Full config: `LiveTraffic/HP_SWITCH_SETUP.md`

### No Switch Available (Fallback)

Use PCAP replay (Method 3 in `docs/LIVE_TRAFFIC_GUIDE.md`):
```bash
python LiveTraffic/pcap_replay_pipeline.py \
    --mode fullday \
    --pcap-file /scratch1/.../CICDataset/PCAP/Friday-WorkingHours.pcap \
    --ddl-model models/ddl_30feat.pkl
```

---

## Pre-Demo Checklist (T-30 min)

### Models
- [ ] `models/ddl_30feat.pkl` exists (`ls -lh models/ddl_30feat.pkl`)
- [ ] `models/isolation_forest.pkl` exists
- [ ] `models/train_report.json` — check F1 > 0.85

### Software
- [ ] venv activated: `source .venv/bin/activate`
- [ ] Test demo mode: `python LiveTraffic/live_pipeline.py --demo --duration 10`
- [ ] REST API starts: `python EnhancedPipeline/rest_api.py --port 5001 &`
- [ ] Dashboard loads: `streamlit run EnhancedPipeline/dashboard.py`

### Hardware (if switch demo)
- [ ] Cisco/HP switch configured and powered
- [ ] Pipeline laptop connected to mirror port (`eth1` or labeled port)
- [ ] Promiscuous mode: `sudo ip link set eth1 promisc on`
- [ ] Capture test: `sudo tcpdump -i eth1 -n -c 5` (should see traffic)

### Traffic Source (Attacker Laptop)
- [ ] Traffic generator ready: `python LiveTraffic/traffic_generator.py --help`
- [ ] tcpreplay installed: `sudo tcpreplay --version`
- [ ] Demo PCAPs ready:
  ```bash
  python LiveTraffic/traffic_generator.py --mode normal --count 30 --output /tmp/normal.pcap
  python LiveTraffic/traffic_generator.py --mode attack --count 20 --output /tmp/attack.pcap
  ```

---

## Demo Script — Terminal Layout

Open **4 terminals** on the pipeline laptop:

```
┌─────────────────────┬──────────────────────────┐
│   TERMINAL 1         │   TERMINAL 2              │
│   Live Pipeline      │   REST API Server         │
├─────────────────────┼──────────────────────────┤
│   TERMINAL 3         │   TERMINAL 4              │
│   Streamlit Dashboard│   Traffic Generator       │
└─────────────────────┴──────────────────────────┘
```

---

## Demo Execution — Step by Step

### Step 1 — Start REST API Server (Terminal 2)

```bash
source .venv/bin/activate
python EnhancedPipeline/rest_api.py --port 5001
```

Verify:
```bash
curl http://localhost:5001/health
# → {"status": "ok", "pipeline_ready": true}
```

### Step 2 — Launch Dashboard (Terminal 3)

```bash
streamlit run EnhancedPipeline/dashboard.py
# → Opens browser at http://localhost:8501
```

The dashboard shows:
- Live flow counter (FORWARD / DROP)
- Anomaly score timeline
- Latency CDF chart
- XAI explanation for latest anomaly
- Adaptive feature importance ranking

### Step 3a — Demo Mode (No Switch)

```bash
# Terminal 1:
python LiveTraffic/live_pipeline.py \
    --demo \
    --duration 120 \
    --ddl_model models/ddl_30feat.pkl

# Watch the dashboard light up with anomaly detections
```

### Step 3b — Live Switch Mode (With Hardware)

```bash
# Terminal 1 (pipeline laptop, mirror port):
python LiveTraffic/live_pipeline.py \
    --interface eth1 \
    --ddl_model models/ddl_30feat.pkl \
    --duration 300

# Terminal 4 (attacker laptop — Laptop A):
# First, send normal traffic (2 min):
python LiveTraffic/traffic_generator.py \
    --mode normal --count 50 --live --interface eth0

# Then launch the attack (1 min):
python LiveTraffic/traffic_generator.py \
    --mode attack --count 30 --live --interface eth0
# OR: replay real CIC-IDS-2017 DDoS traffic:
sudo tcpreplay --intf=eth0 --mbps=5 \
    /scratch1/.../CICDataset/PCAP/Friday-WorkingHours.pcap
```

### Step 4 — Show XAI Explanation

When an anomaly is detected (shown as RED in dashboard), display the explanation:

```bash
# Get the last anomaly explanation:
curl http://localhost:5001/explain/latest | python -m json.tool
```

Expected output:
```json
{
    "flow_id": "10.0.1.0:56789->172.16.0.1:80/TCP",
    "decision": "DROP",
    "ddl_score": 0.847,
    "threshold": 0.312,
    "xai_top_features": [
        {"feature": "syn_flag_count", "error_contribution": 42.3, "value": 500},
        {"feature": "fwd_iat_mean_ms", "error_contribution": 38.7, "value": 0.4},
        {"feature": "down_up_ratio", "error_contribution": 29.1, "value": 0.0}
    ],
    "interpretation": "SYN flood detected: 500 SYN packets, zero response, 0.4ms IAT"
}
```

**Key talking points:**
- Score 0.847 >> threshold 0.312 → clear anomaly
- The XAI tells us WHY: high SYN count, zero backward traffic, tiny IAT
- This is not a black box — every decision is explained

### Step 5 — Show Pipeline Timing

```bash
python -m profiling.latency_benchmark --n_flows 100 --output /tmp/demo_bench/
# Opens: /tmp/demo_bench/latency_cdf.png  (show on projector)
```

Expected timing summary:
```
DT Stage 1:          <1ms  (all flows)
DDL Stage 2:        ~45ms  (flagged flows only, ~15%)
XAI (native):        ~5ms  (anomalous flows only)
XAI (SHAP):        ~220ms  (optional, anomalous flows only)
Total latency 95%:  520ms  (anomaly path, less than 1s)
```

---

## PCAP Replay Demo (Alternative — No Switch)

Show accuracy on real CIC-IDS-2017 data:

```bash
# Terminal 1:
python LiveTraffic/pcap_replay_pipeline.py \
    --mode labeled \
    --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \
    --ddl-model models/ddl_30feat.pkl \
    --max-files 500 \
    --output logs/demo_friday.json

# Results appear in ~5 minutes:
# ════════════════════════════════════════════════════════
# PCAP REPLAY — LABELED TEST RESULTS
# ════════════════════════════════════════════════════════
#   Flows: 500   Skipped: 0
#   Accuracy:   0.91   F1: 0.90
#   DDoS:     F1=0.93  Precision=0.91  Recall=0.95
#   PortScan: F1=0.88  Precision=0.86  Recall=0.90
#   Bot:      F1=0.82  Precision=0.80  Recall=0.85
#   BENIGN:   F1=0.94  Precision=0.96  Recall=0.92
```

---

## Talking Points for Audience

1. **Two-stage cascade**: DT (fast, 15 features) filters easy cases first,
   sending only suspicious flows to the expensive DDL+XAI stage (~15% of traffic).

2. **Flow-level, not packet-level**: DDL operates on aggregated flow statistics
   — 30 features computed over all packets in a conversation. This is why DDoS
   (which looks like normal individual packets) IS detectable.

3. **One-class training**: DDL was trained **only on normal traffic** from Monday
   (CIC-IDS-2017 benign day). It detects anomalies as flows that don't fit the
   learned normal pattern — not by seeing attack examples.

4. **Zero-trust default**: Ambiguous flows are blocked (timeout → DROP).

5. **XAI explains every block**: No mystery — the system names the exact
   statistical features that triggered the alert.

6. **Research contribution**: Combination of DDL + Isolation Forest (second opinion)
   + SHAP/LIME explanations for encrypted traffic is novel for this problem domain.

---

## Emergency Fallback

If hardware fails during the demo:

```bash
# Full software demo in <60 seconds:
python LiveTraffic/live_pipeline.py --demo --duration 60 &
streamlit run EnhancedPipeline/dashboard.py
```

Switch to the pre-recorded timing chart:
```bash
ls profiling/results/   # pre-generated CDF and box plots
```
