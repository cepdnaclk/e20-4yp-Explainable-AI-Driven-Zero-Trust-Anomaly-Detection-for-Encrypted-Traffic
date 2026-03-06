# Pipeline Guide — Zero-Trust XAI Anomaly Detection

**University of Peradeniya | e20420Janith**

---

## Architecture Overview

```
                    +---------------------+
                    |    Network Switch   |
                    |  SPAN Mirror Port   |
                    +---------------------+
                              |
                              v
                    +---------------------+
                    | Unified Feature     |
                    | Extraction (DPKT)   |
                    | One pass, 46 feats  |
                    +--------+------------+
                             |
               +-------------+-------------+
               |                           |
        28 features                  40 features
               |                           |
               v                           |
      +-----------------+                  |
      | Stage 1: BCC v2 |                  |
      | Decision Tree   |                  |
      | Threshold: 0.5  |                  |
      +--------+--------+                  |
               |                           |
        +------+------+                    |
        |             |                    |
     BENIGN        ATTACK                  |
        |             |                    |
   FORWARD +     SDN Buffer               |
   ALLOW rule    (hold flows)              |
                      |                    |
                      +--------------------+
                      |
                      v
              +-----------------+
              | Stage 2: DDL    |
              | 40 features     |
              | 2-layer ISTA    |
              +--------+--------+
                       |
                +------+------+
                |             |
             Normal        Anomaly
                |             |
           +----+----+   +----+----+
           |         |   |         |
        FORWARD   ALLOW  DROP    XAI
           +     rule    rule    explain
```

---

## Stage 1: BCC v2 (28 features)

**Model:** `models/sentry_model_v2.pkl` (Sandaru's gatekeeper DT)
**Latency:** <100 us per flow
**Purpose:** Fast pre-screening. Allows benign, flags attacks for deeper analysis.

### BCC v2 Feature Set (28)

| # | Feature | CIC-IDS Column |
|---|---------|---------------|
| 0 | Packet Length Variance | Packet Length Variance |
| 1 | Fwd Packet Length Max | Fwd Packet Length Max |
| 2 | Fwd Header Length | Fwd Header Length |
| 3 | Init Win bytes forward | Init_Win_bytes_forward |
| 4 | Bwd Header Length | Bwd Header Length |
| 5 | Total Length of Fwd Packets | Total Length of Fwd Packets |
| 6 | Init Win bytes backward | Init_Win_bytes_backward |
| 7 | Bwd Packets/s | Bwd Packets/s |
| 8 | Flow IAT Min | Flow IAT Min |
| 9 | Fwd IAT Min | Fwd IAT Min |
| 10 | Flow Bytes/s | Flow Bytes/s |
| 11 | Active Min | Active Min |
| 12 | Bwd IAT Total | Bwd IAT Total |
| 13 | Flow IAT Max | Flow IAT Max |
| 14 | Flow Duration | Flow Duration |
| 15 | Total Fwd Packets | Total Fwd Packets |
| 16 | Total Bwd Packets | Total Backward Packets |
| 17 | Fwd Packet Length Mean | Fwd Packet Length Mean |
| 18 | Bwd Packet Length Mean | Bwd Packet Length Mean |
| 19 | Fwd Packet Length Std | Fwd Packet Length Std |
| 20 | Bwd Packet Length Max | Bwd Packet Length Max |
| 21 | Flow IAT Mean | Flow IAT Mean |
| 22 | Flow IAT Std | Flow IAT Std |
| 23 | Fwd IAT Total | Fwd IAT Total |
| 24 | Fwd Packets/s | Fwd Packets/s |
| 25 | Down/Up Ratio | Down/Up Ratio |
| 26 | SYN Flag Count | SYN Flag Count |
| 27 | RST Flag Count | RST Flag Count |

---

## Stage 2: DDL + IF + XAI (40 features)

**Model:** `models/ddl_40feat.pkl`
**Latency:** ~45 ms per flow
**Purpose:** Deep anomaly detection on flows flagged by BCC.

### DDL Feature Set (40)

| # | Feature | CIC-IDS Column |
|---|---------|---------------|
| 0-3 | Fwd pkt len (mean, std, min, max) | Fwd Packet Length Mean/Std/Min/Max |
| 4-5 | Bwd pkt len (mean, std) | Bwd Packet Length Mean/Std |
| 6-8 | Fwd IAT (mean, std, max) | Fwd IAT Mean/Std/Max |
| 9-11 | Bwd IAT (mean, std, max) | Bwd IAT Mean/Std/Max |
| 12-13 | Flow rates (bytes/s, pkts/s) | Flow Bytes/s, Flow Packets/s |
| 14-15 | Dir rates (fwd bytes/s, bwd bytes/s) | derived |
| 16-17 | Pkt len (variance, mean) | Packet Length Variance/Mean |
| 18-23 | TCP flags (SYN, ACK, FIN, RST, PSH, URG) | *Flag Count columns |
| 24-25 | Total bytes (fwd, bwd) | Total Length of Fwd/Bwd Packets |
| 26 | Flow duration (s) | Flow Duration |
| 27-28 | Init TCP window (fwd, bwd) | Init_Win_bytes_forward/backward |
| 29 | Down/Up ratio | Down/Up Ratio |
| **30-31** | **Bwd pkt len (min, max)** | **Bwd Packet Length Min/Max** |
| **32-33** | **Flow IAT (mean, std)** | **Flow IAT Mean/Std** |
| **34** | **Fwd IAT total** | **Fwd IAT Total** |
| **35** | **Bwd IAT min** | **Bwd IAT Min** |
| **36-37** | **Dir pkt rates (fwd/bwd pkts/s)** | **Fwd/Bwd Packets/s** |
| **38** | **Fwd header length** | **Fwd Header Length** |
| **39** | **Active min** | **Active Min** |

> **Bold rows** = 10 new features added in v2 expansion for improved detection.
> 22 features overlap between BCC-28 and DDL-40 — extracted ONCE by the unified extractor.

### Isolation Forest (Consensus Vote)

**Model:** `models/isolation_forest.pkl`
**Input:** Same 40 DDL features
**Purpose:** Second opinion on DDL anomalies to reduce false positives.

A flow is only **DROPPED** when BOTH DDL AND IF agree it's anomalous.

### XAI Explanations

For each dropped flow, the pipeline generates:
- **Top contributing features** — which of the 40 features drove the anomaly score
- **Reconstruction error** — how far from "normal" this flow's pattern is
- **Feature deviation** — which features deviate most from learned normal dictionaries

---

## Decision Logic

```python
# Stage 1: BCC v2
bcc_score = bcc_model.predict_proba(bcc_28_features)
if bcc_score < 0.5:
    decision = "FORWARD"   # ALLOW rule
else:
    send_to_buffer(flow)   # Hold for Stage 2

# Stage 2: DDL + IF
ddl_recon_error = ddl_model.compute_error(ddl_40_features)
if ddl_recon_error > ddl_threshold:
    if isolation_forest.predict(ddl_40_features) == -1:
        decision = "DROP"  # Both agree = anomaly
    else:
        decision = "FORWARD"  # DDL says anomaly, IF disagrees
else:
    decision = "FORWARD"  # DDL says normal
```

---

## Training

### BCC v2 (already trained)
Pre-trained by Sandaru. Model file: `models/sentry_model_v2.pkl`

### DDL + IF Training

```bash
# GPU (recommended, ~30 min):
apptainer exec --nv \
    /scratch1/e20-fyp-xai-anomaly-detection/pytorch_2.4.0-cuda12.4-cudnn9-runtime.sif \
    python DDLModel/train_ddl_enhanced.py \
        --train dataset/TRAIN_Traffic.csv \
        --test  dataset/TEST_Traffic.csv \
        --epochs 150 --gpu --batch-size 512

# CPU (~9 hours):
python DDLModel/train_ddl_enhanced.py \
    --train dataset/TRAIN_Traffic.csv \
    --test  dataset/TEST_Traffic.csv \
    --epochs 150
```

**Output files:**
- `models/ddl_40feat.pkl` — Trained 2-layer DDL
- `models/isolation_forest.pkl` — Trained IF voter
- `models/train_report.json` — Metrics and feature mapping

### Training Data

CIC-IDS-2017 processed CSV files:
- `dataset/TRAIN_Traffic.csv` — Training set (70 columns, ~2M rows)
- `dataset/TEST_Traffic.csv` — Test set (~500K rows)

Labels: `Normal` = benign, everything else = attack.

---

## Running the Pipeline

```bash
# Demo mode (synthetic flows):
python FullSDNPipeline/sdn_pipeline.py --demo --n-flows 30

# CIC-IDS-2017 labeled PCAPs:
python FullSDNPipeline/sdn_pipeline.py \
    --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \
    --limit 500

# Packet replay with real timing:
python FullSDNPipeline/packet_shooter.py \
    --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \
    --rate-multiplier 1.0
```

---

## Target Metrics

| Metric | Target | Notes |
|--------|--------|-------|
| Attack Recall | > 99% | Zero leaks goal |
| False Positive Rate | < 5% | IF consensus reduces FP |
| Stage 1 latency | < 1 ms | DT inference |
| Stage 2 latency | < 100 ms | DDL + IF + XAI |
| Throughput | > 50 flows/s | Pipeline aggregate |
