# Pipeline Architecture Guide
**Zero-Trust XAI Anomaly Detection | e20420Janith**

---

## System Overview

The pipeline implements a **two-stage zero-trust anomaly detection system** for SDN environments. Every packet flow is analyzed — no traffic is inherently trusted.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SDN Controller (Pipeline Host)                    │
│                                                                     │
│  PacketIN ──→ Feature Extraction ──→ Stage 1 (BCC) ──→ Decision    │
│                    │                      │                         │
│                    │                   BENIGN → FORWARD             │
│                    │                   ATTACK → Buffer → Stage 2    │
│                    │                                      │         │
│                    └──────────→ DDL + IF + XAI ──→ Decision         │
│                                    │                                │
│                                 Normal → FORWARD                   │
│                                 Anomaly → DROP + Explanation        │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Stage 1: Base Check Classifier (BCC v2)

**Model**: Decision Tree (scikit-learn `DecisionTreeClassifier`)
**Features**: 28 network flow features
**Latency**: **0.05 µs per flow**
**Role**: Fast binary filter — pass benign traffic instantly, flag suspicious traffic

### How It Works
1. Extract 28 flow features (packet sizes, timing, flags, header lengths)
2. Decision Tree predicts P(ATTACK)
3. If P(ATTACK) ≥ 0.5 → flag to Stage 2
4. If P(ATTACK) < 0.5 → FORWARD immediately

### Features Used (28)
`Packet Length Variance`, `Fwd Packet Length Max`, `Fwd Header Length`,
`Init_Win_bytes_forward`, `Bwd Header Length`, `Total Length of Fwd Packets`,
`Init_Win_bytes_backward`, `Bwd Packets/s`, `Flow IAT Min`, `Fwd IAT Min`,
`Flow Bytes/s`, `Active Min`, `Bwd IAT Total`, `Flow IAT Max`,
`Flow Duration`, `Total Fwd Packets`, `Total Bwd Packets`,
`Fwd Packet Length Mean`, `Bwd Packet Length Mean`, `Fwd Packet Length Std`,
`Bwd Packet Length Max`, `Flow IAT Mean`, `Flow IAT Std`, `Fwd IAT Total`,
`Fwd Packets/s`, `Down/Up Ratio`, `SYN Flag Count`, `RST Flag Count`

### Performance
- **On preprocessed data**: 99.89% attack recall, 96.3% precision
- **On raw CIC-IDS CSV**: 21.25% recall, 87.5% precision (different feature distributions)

---

## Stage 2: Deep Analysis (DDL + IF + XAI)

Only flows flagged by BCC (~5% of traffic) reach Stage 2.

### Deep Dictionary Learning (DDL)

**Model**: 2-layer ISTA (Iterative Shrinkage-Thresholding Algorithm)
**Features**: 40 flow features (superset of BCC's 28)
**Latency**: **133 µs per flow**
**Training**: One-class — trained on 1,682,457 **normal** flows only

#### How It Works
1. DDL learns a dictionary of "normal" traffic patterns
2. Each flow is reconstructed using the learned dictionary
3. **Reconstruction error** = anomaly score
4. If error > threshold (0.7597) → anomalous

#### Architecture
```
Input (40 features)
  ↓
Layer 1: ISTA sparse coding (64 atoms)
  ↓
Layer 2: ISTA sparse coding (128 atoms)
  ↓
Reconstruction → Error computation → Threshold check
```

### Isolation Forest (IF)

**Model**: 100-tree ensemble (scikit-learn `IsolationForest`)
**Features**: Same 40 as DDL
**Latency**: **2.83 µs per flow**
**Training**: One-class — same 1,682,457 normal samples as DDL

#### How It Works
1. IF builds random trees that isolate data points
2. Anomalies are points that require **fewer splits** to isolate
3. Returns isolation score: negative = anomalous

### Consensus Decision
A flow is **DROPped only if BOTH DDL AND IF agree it's anomalous**. This dual-verification reduces false positives from ~5% (either model alone) to **0.25%** (consensus).

```
DDL says Anomaly + IF says Anomaly → DROP (consensus)
DDL says Anomaly + IF says Normal  → FORWARD (no consensus)
DDL says Normal  + IF says Anomaly → FORWARD (no consensus)
DDL says Normal  + IF says Normal  → FORWARD
```

---

## XAI: Explainable AI (LIME + SHAP)

### Why XAI?

In a zero-trust environment, automated decisions must be **auditable**. When the pipeline DROPs a flow, LIME and SHAP explain **which features** triggered the detection and **how much** each contributed.

### LIME (Local Interpretable Model-agnostic Explanations)

- Creates **local perturbations** around the flagged flow
- Fits a simple linear model to the perturbations
- Outputs feature weights showing contribution direction and magnitude
- **Timing**: ~44ms per flow (DDL), ~20ms per flow (IF)

### SHAP (SHapley Additive exPlanations)

- Uses **Shapley values** from cooperative game theory
- Theoretically optimal: only method with consistency, local accuracy, and missingness guarantees
- Shows each feature's contribution to the anomaly score
- **Timing**: ~100ms+ per flow (computationally heavier)

### XAI in Practice

Both LIME and SHAP explain **DDL AND IF decisions separately**:

| XAI | Explains DDL | Explains IF | Per-flow Time |
|-----|:---:|:---:|:---:|
| LIME | ✓ Top features → DDL anomaly score | ✓ Top features → IF isolation score | ~64ms |
| SHAP | ✓ Feature SHAP values for DDL | ✓ Feature SHAP values for IF | ~200ms |

#### Example Explanation
For a DROPped flow (true attack):
```
DDL-LIME:  syn_flag_count=-0.037 | fwd_iat_total=+0.032 | flow_iat_std=+0.026
IF-LIME:   bwd_pkt_len_mean=+0.031 | fwd_iat_total=+0.029 | flow_duration=+0.028
```
**Interpretation**: The flow has no SYN flags (abnormal), very high forward idle time, and unusual timing patterns — consistent with a scanning or DDoS attack.

---

## Unified Feature Extraction

Features are extracted **once** and shared between stages:

```python
# Single extraction pass
superset = unified_extractor.extract(packet_data)

# Stage 1 gets 28 features
bcc_features = superset["bcc_28"]

# Stage 2 gets 40 features (superset of BCC's 28)
ddl_features = superset["ddl_40"]
```

### DDL's 10 Additional Features (beyond BCC's 28)

| Feature | Why Added |
|---------|-----------|
| `bwd_pkt_len_min` | Backward packet size profile |
| `bwd_pkt_len_max` | DDoS signature (identical sizes) |
| `flow_iat_mean` | Flow-level timing average |
| `flow_iat_std` | Timing variability |
| `fwd_iat_total` | Total forward idle time |
| `bwd_iat_min` | Fast backward bursts = scanning |
| `fwd_pkts_per_s` | Forward packet rate |
| `bwd_pkts_per_s` | Backward packet rate |
| `fwd_header_len` | Header overhead ratio |
| `active_min` | Shortest active period |

---

## Timing Breakdown

| Component | Per-Flow | Applies To | Percentage of Traffic |
|-----------|:--------:|:----------:|:---------------------:|
| Feature extraction | ~50 µs | All flows | 100% |
| **BCC v2** | **0.05 µs** | All flows | 100% |
| **DDL** | **133 µs** | Flagged only | ~5% |
| **IF** | **2.83 µs** | Flagged only | ~5% |
| **LIME** | **~64 ms** | Anomalous only | ~1% |
| **SHAP** | **~200 ms** | Anomalous only | ~1% |

**Average total latency per flow**: ~8 µs (since only 5% go to Stage 2)

---

## How to Deploy in Your SDN

1. **Install models** on the SDN controller
2. **Configure switch port mirroring** to send packet copies
3. **Run `sdn_pipeline.py`** — it processes PacketIN events
4. **Pipeline outputs**:
   - `FORWARD` + ALLOW rule → benign traffic passes
   - `DROP` + XAI explanation → attack traffic blocked with audit trail

See `QUICK_START.md` for exact commands and `DemonstrationPlan.md` for demo procedure.
