# Demonstration Plan
**Zero-Trust XAI Anomaly Detection | Live Demo**

---

## Prerequisites

```bash
cd /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate
```

Verify models exist:
```bash
ls -lh models/sentry_model_v2.pkl models/ddl_40feat.pkl models/isolation_forest.pkl
```

---

## Demo Option 1: Full Evaluation Report (5 min)

Shows all model results + XAI explanations in one run.

```bash
PYTHONPATH=/tmp/lime_pkg:$PYTHONPATH \
    python FullSDNPipeline/run_full_evaluation.py --max-rows 50000 --xai-samples 5

# Show results
cat results/summary.md
cat results/stage2_xai/xai_summary.md
```

**What to show the supervisors:**
- Per-model confusion matrices (BCC, DDL, IF)
- Full pipeline precision (93.6%) and FPR (0.25%)
- XAI explanation showing which features triggered the detection
- Timing: BCC=0.05µs, DDL=133µs, pipeline avg=8µs

---

## Demo Option 2: Synthetic Traffic Demo (30 sec)

Quick pipeline demo with generated flows.

```bash
python FullSDNPipeline/sdn_pipeline.py --demo --n-flows 50
```

**What to show:**
- Pipeline loads all 3 models
- Each flow gets a decision (FORWARD/DROP)
- Confusion matrix at the end

---

## Demo Option 3: PCAP Replay (2 min)

Uses real CIC-IDS-2017 labeled PCAPs.

```bash
# Friday (DDoS, PortScan, Bot attacks):
python FullSDNPipeline/sdn_pipeline.py \
    --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \
    --limit 200 --output logs/pcap_friday.json

# View results:
cat logs/pcap_friday.json | python3 -m json.tool | head -30
```

---

## Demo Option 4: Real-Time Packet Shooter (5 min)

Replays PCAPs with realistic timing.

```bash
python FullSDNPipeline/packet_shooter.py \
    --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \
    --rate-multiplier 1.0 --limit 100
```

---

## Demo Option 5: Live Switch (requires hardware)

See `docs/setup/switch-overview.md` for switch configuration.

```bash
sudo ip link set eth1 promisc on
python LiveTraffic/live_pipeline.py --interface eth1 --duration 300
```

---

## Talking Points for Supervisors

### 1. Pipeline Design

> "We use a two-stage architecture. The first stage is a very fast Decision Tree (~0.05 microseconds) that filters 95% of traffic as benign. Only the 5% flagged traffic goes to the second stage."

### 2. Deep Analysis

> "The second stage uses Deep Dictionary Learning — it learns what normal traffic looks like and flags anything that doesn't reconstruct well. Isolation Forest provides a second opinion. A flow is only blocked when BOTH agree it's anomalous."

### 3. Explainability

> "Every DROP decision comes with LIME and SHAP explanations. For example, this flow was blocked because it had no SYN flags, very high forward idle time, and unusual backward packet sizes — consistent with a scanning attack."

### 4. Performance

> "On our test data: 93.6% precision on drops (when we block, 94% are real attacks), 0.25% false positive rate (virtually no legitimate traffic disrupted), average 8 microseconds per flow."

### 5. Impact

> "Without this system, SDN controllers either trust all traffic (no security) or inspect everything (too slow). Our pipeline gives near-real-time security with human-readable explanations."
