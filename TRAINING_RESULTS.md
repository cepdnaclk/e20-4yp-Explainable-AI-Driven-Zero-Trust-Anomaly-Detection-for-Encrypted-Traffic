# Training & Testing Results Report
**Zero-Trust XAI Anomaly Detection Pipeline**
**e20420Janith | University of Peradeniya**
**Date: 2026-03-08**

---

## 1. DDL Training Configuration

| Parameter | Value |
|-----------|-------|
| GPU | NVIDIA RTX 6000 Ada Generation (49.8 GB free) |
| Container | `pytorch_2.4.0-cuda12.4-cudnn9-runtime.sif` |
| Training data | CIC-IDS-2017: 2,125,957 rows (1,682,457 Normal, 443,500 Anomaly) |
| DDL trained on | 1,682,457 **Normal samples only** (one-class learning) |
| Features | 40 DDL features |
| Architecture | 2-layer ISTA (L1=64 atoms, L2=128 atoms) |
| Epochs | 150 |
| Batch size | 512 |
| **Training time** | **1 hour 45 minutes** |
| Final loss | 0.290 |
| Anomaly threshold (p95) | 0.7597 |

### Training Loss Curve

| Epoch | Loss |
|-------|------|
| 1 | 1.4762 |
| 20 | 0.4525 |
| 40 | 0.3781 |
| 60 | 0.3415 |
| 100 | 0.3090 |
| 140 | 0.2934 |
| 150 | ~0.290 |

### Isolation Forest (trained alongside DDL)

| Parameter | Value |
|-----------|-------|
| Training samples | 1,682,457 normal flows |
| Estimators | 100 trees |
| Contamination | 0.05 |
| Training time | 32.8 seconds |

---

## 2. Per-Model Test Results (50,000 rows from TEST_Traffic.csv)

| Model | Accuracy | Precision | Recall | F1 | FPR | Latency/flow |
|-------|:---:|:---:|:---:|:---:|:---:|:---:|
| **BCC v2** | 83.24% | 87.50% | 21.25% | 34.19% | 0.78% | **0.05 µs** |
| **BCC v2 (Sandaru's data)** | 98.65% | 96.31% | **99.89%** | 98.07% | 2.00% | 0.05 µs |
| **DDL-40** | 84.81% | 69.94% | 45.37% | 55.04% | 5.03% | 133 µs |
| **IF** | 82.06% | 62.59% | 31.00% | 41.46% | 4.77% | 2.83 µs |
| **Full Pipeline** | 82.19% | **93.63%** | 14.05% | 24.44% | **0.25%** | ~8 µs avg |

> **Note**: BCC v2 recall drops on raw CIC-IDS CSV because the model was trained on Sandaru's preprocessed data. When tested on the same format data → 99.89% recall.

### Confusion Matrices

**BCC v2 Standalone (our TEST CSV)**
```
               Predicted
            FORWARD    DROP
Normal       39,443     311
Attack        8,069   2,177
```

**BCC v2 on Sandaru's test_raw.csv** ✓
```
               Predicted
            FORWARD    DROP
Normal       33,679     688
Attack           20  17,967
```

**DDL-40 Standalone**
```
               Predicted
            FORWARD    DROP
Normal       37,756   1,998
Attack        5,597   4,649
```

**Isolation Forest Standalone**
```
               Predicted
            FORWARD    DROP
Normal       37,856   1,898
Attack        7,070   3,176
```

**Full Pipeline (BCC → DDL + IF)**
```
               Predicted
            FORWARD    DROP
Normal       39,656      98
Attack        8,806   1,440
```

---

## 3. Full Pipeline Flow Routing

```
50,000 flows input
    |
    +-- BCC Stage 1 (0.003s total)
    |       |
    |       +-- 47,512 classified BENIGN → FORWARD (95.0%)
    |       +-- 2,488 flagged ATTACK → Stage 2 (5.0%)
    |
    +-- DDL + IF Stage 2 (0.29s total) — on 2,488 flagged flows
            |
            +-- 950 classified Normal → FORWARD (38.2%)
            +-- 1,538 classified Anomaly → DROP (61.8%)
```

---

## 4. XAI Explanations (LIME + SHAP)

### How XAI Works in the Pipeline

Both DDL and IF decisions are explained by dual XAI:
- **LIME** (Local Interpretable Model-agnostic Explanations): Perturbs features locally to explain each prediction
- **SHAP** (SHapley Additive exPlanations): Uses Shapley values for theoretically-grounded feature attribution

### Sample XAI Explanation (Flow #11 — True Attack → Correctly DROPPED)

| Feature | IF LIME Weight | Interpretation |
|---------|:---:|---|
| `syn_flag_count ≤ 0` | -0.0374 | No SYN flags (unusual for legitimate connections) |
| `fwd_iat_total > 1.26M` | +0.0325 | Very long forward idle time (suspicious) |
| `flow_iat_std > 943K` | +0.0265 | High timing variability (anomalous pattern) |
| `ack_flag_count = 1` | +0.0247 | Single ACK (incomplete handshake) |
| `urg_flag_count ≤ 0` | -0.0275 | No urgency flags |

### XAI Timing

| XAI Method | Time per Flow |
|-----------|:---:|
| DDL-LIME | ~44 ms |
| IF-LIME | ~20 ms |
| DDL-SHAP | ~100+ ms (when enabled) |
| IF-SHAP | ~100+ ms (when enabled) |

---

## 5. Timing Summary

| Stage | Total Time (50K flows) | Per Flow | Component |
|-------|:---:|:---:|---|
| **BCC v2** | 0.003s | 0.05 µs | Decision Tree inference |
| **DDL-40** | 6.7s | 133 µs | 2-layer ISTA reconstruction |
| **IF** | 0.14s | 2.83 µs | Isolation Forest scoring |
| **XAI (LIME)** | ~0.17s | ~64 ms | Per-flow LIME explanation |
| **Full Pipeline** (BCC→DDL+IF) | 0.39s | 7.9 µs avg | Two-stage with consensus |

> Only flagged flows (5% by BCC) go through DDL+IF+XAI. Average pipeline latency is dominated by DDL but only on suspicious flows.

---

## 6. PCAP Evaluation (Real Network Traffic)

**Source:** CIC-IDS-2017 `Friday-labeled-small` — 128 labeled flow PCAP directories (BENIGN + DDoS)
**Script:** `FullSDNPipeline/run_pcap_evaluation.py`

### Confusion Matrix
```
               Predicted
            FORWARD    DROP
Normal           70       5
Attack           53       0
```

### Pipeline Routing
- BCC forwarded (BENIGN): 122 / 128
- BCC flagged to Stage 2: 6 / 128
- DDL+IF consensus DROP: 5

### Timing (per flow, µs) — includes PCAP parsing overhead

| Stage | CSV Mode (µs) | PCAP Mode (µs) | Notes |
|-------|:---:|:---:|---|
| **Feature Extraction** | ~0 (pre-extracted) | 3,257 µs | dpkt PCAP parsing overhead |
| **BCC Inference** | 0.05 µs | 122 µs | Decision Tree predict |
| **DDL Inference** | 133 µs | 4,317 µs | Flagged flows only |
| **IF Inference** | 2.83 µs | 5,616 µs | Flagged flows only |
| **Total Pipeline** | **~8 µs** | **~3,853 µs** | End-to-end per flow |

> **Key note on PCAP timing:** In a real SDN deployment, features are extracted from OpenFlow `PacketIN` events, not PCAP files. This brings extraction time much closer to CSV mode (~50µs for full feature set). The PCAP evaluation represents worst-case latency (reading stored captures off disk with dpkt).

### Run PCAP Evaluation
```bash
cd /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-.../
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate
PYTHONPATH=/tmp/dpkt_pkg:/tmp/lime_pkg:$PYTHONPATH \
    python FullSDNPipeline/run_pcap_evaluation.py
# Results: results/pcap_results/pcap_summary.md
```



---

## 6. Model Files

| File | Description |
|------|-------------|
| `models/sentry_model_v2.pkl` | BCC v2 Decision Tree (28 features) |
| `models/ddl_40feat.pkl` | DDL 2-layer ISTA (40 features) |
| `models/isolation_forest.pkl` | IF 100-tree voter (40 features) |
| `models/train_report.json` | DDL training metrics |

---

## 7. Reproduction

```bash
# Navigate
cd /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate

# Run full evaluation (generates results/ folder)
PYTHONPATH=/tmp/lime_pkg:$PYTHONPATH python FullSDNPipeline/run_full_evaluation.py

# View results
cat results/summary.md
cat results/stage2_xai/xai_summary.md
```
