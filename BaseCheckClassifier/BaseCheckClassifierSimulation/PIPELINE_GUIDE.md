# Zero-Trust Anomaly Detection Pipeline — Complete Guide

> **Project**: Explainable AI-Driven Zero-Trust Anomaly Detection for Encrypted Traffic  
> **Module**: CO425 — Final Year Project II  
> **Last Updated**: February 2026

---

## Table of Contents

1. [Overview — What This Pipeline Does](#1-overview)
2. [Architecture — How It Works](#2-architecture)
3. [Directory Structure — What Each File Does](#3-directory-structure)
4. [Setup — How to Recreate the Environment](#4-setup)
5. [The 15 Features — What They Are & Why](#5-the-15-features)
6. [Pipeline Stages — Detailed Walkthrough](#6-pipeline-stages)
7. [Using Classified PCAPs (normal/ & attack/)](#7-using-classified-pcaps)
8. [Training the Models](#8-training-the-models)
9. [Running the Pipeline](#9-running-the-pipeline)
10. [Understanding the Output](#10-understanding-the-output)
11. [Analysing Results & Taking Action](#11-analysing-results)
12. [Integration Guide — For Future Developers](#12-integration-guide)
13. [Known Limitations & Next Steps](#13-known-limitations)
14. [Quick Reference — Commands Cheat Sheet](#14-quick-reference)

---

## 1. Overview

This system detects anomalous (malicious) traffic in an encrypted network environment using a **three-stage pipeline** without ever inspecting packet payloads:

```
.pcap stream → Encryption Sim → Feature Extraction (15 metadata features)
    → Stage 1: Decision Tree (fast base check)
        ├─ Normal → FORWARD immediately
        └─ Flagged → Stage 2: SDN Buffer (hold the stream)
                   → Stage 3: DDL + SHAP XAI (parallel deep analysis)
                       ├─ Normal → RELEASE from buffer
                       └─ Anomaly → DROP + Human-readable explanation
```

**Key principles:**
- **Zero-Trust**: Every stream is inspected. Flagged streams are HELD until proven clean.
- **Zero-Leak**: Only metadata/behavioral features are used — payloads stay encrypted.
- **Explainable**: Every DROP decision comes with a SHAP + DDL explanation (why it was flagged, which features were anomalous, what values were expected vs. observed).

**Components at a glance:**

| Component | What it does | File |
|-----------|-------------|------|
| Feature Extraction | Extracts 15 behavioral features from pcap headers using DPKT + NFStream | `extraction/feature_extractor.py` |
| Encryption Sim | Simulates AES-256-GCM encryption overhead and network latency | `encryption/traffic_encryptor.py` |
| Decision Tree | Fast first-pass classifier (base check) | Trained via `Decision_tree_model_creator/DecisionTree.py` |
| DDL Model | Deep Dictionary Learning — learns "what normal looks like", flags anything that can't be reconstructed | `ddl/ddl_model.py` |
| SHAP XAI | Explains WHY a stream was flagged using feature attributions | `xai/explainer.py` |
| Pipeline Orchestrator | Wires everything together, manages SDN buffer, produces verdicts | `pipeline.py` |

---

## 2. Architecture

### High-Level Flow

```
┌──────────────────────────────────────────────────────────────┐
│                        INPUT                                 │
│  .pcap files (live capture or pre-classified datasets)       │
│  ├── normal/   (benign traffic .pcap files)                  │
│  └── attack/   (malicious traffic .pcap files)               │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│  STAGE 0: Encryption & Latency Simulation                    │
│  Module: encryption/traffic_encryptor.py                     │
│  - Simulates AES-256-GCM encryption overhead                │
│  - Injects realistic network latency + jitter                │
│  - Returns the pcap path (payload treated as opaque)         │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│  STAGE 1: Feature Extraction                                 │
│  Module: extraction/feature_extractor.py                     │
│  - DPKT pass: extracts TCP handshake data, init window       │
│    sizes, header lengths (per direction)                     │
│  - NFStream pass: extracts flow statistics (IAT, byte        │
│    rates, packet lengths, duration, active periods)          │
│  - Output: 15-dimensional feature vector                     │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│  STAGE 2: Base Check Classifier (Decision Tree)              │
│  Model: sentry_zero_leak_v1.pkl                              │
│  - Trained on CIC-IDS-2017 dataset (TRAIN_Traffic.csv)       │
│  - entropy criterion, max_depth=15, Attack weight=50×        │
│  - FAST: <1ms per sample                                     │
│  Decision:                                                   │
│    Normal (high confidence) → FORWARD immediately            │
│    Flagged → send to Stage 3                                 │
└──────────────────┬───────────────────────────────────────────┘
                   │ (only flagged streams)
                   ▼
┌──────────────────────────────────────────────────────────────┐
│  SDN BUFFER                                                  │
│  Class: SDNBuffer (in pipeline.py)                           │
│  - Holds the flagged stream while deep analysis runs         │
│  - Simulates OpenFlow buffering in a real SDN switch         │
│  - Tracks buffer time, enforces timeout                      │
└──────────────────┬───────────────────────────────────────────┘
                   │
          ┌────────┴────────┐
          │   (parallel)    │
          ▼                 ▼
┌─────────────────┐ ┌──────────────────┐
│  DDL Analysis   │ │  SHAP XAI        │
│  ddl/ddl_model  │ │  xai/explainer   │
│                 │ │                  │
│ Reconstruct the │ │ Compute feature  │
│ sample through  │ │ attributions via │
│ two dictionary  │ │ KernelExplainer  │
│ layers. High    │ │ (model-agnostic) │
│ error = anomaly │ │                  │
└────────┬────────┘ └────────┬─────────┘
         │                   │
         └────────┬──────────┘
                  ▼
┌──────────────────────────────────────────────────────────────┐
│  STAGE 3: Final Decision + Explanation                       │
│  - DDL says Normal → RELEASE buffer, FORWARD stream          │
│  - DDL says Anomaly → DROP + attach explanation              │
│    Explanation includes:                                     │
│    • Which features had highest reconstruction error         │
│    • SHAP attribution: which features pushed score up/down   │
│    • Human-readable summary for SOC analyst                  │
└──────────────────────────────────────────────────────────────┘
```

### Why Two Stages of Classification?

| Aspect | Decision Tree (Stage 2) | DDL (Stage 3) |
|--------|------------------------|---------------|
| **Speed** | <1ms per stream | ~100–1000ms per stream |
| **Type** | Supervised (needs labels) | Unsupervised (learns "normal" only) |
| **Strength** | High recall for known attack patterns | Catches novel/zero-day anomalies |
| **When used** | Every stream | Only DT-flagged streams |
| **Explainability** | Feature importance (static) | Per-sample XAI explanations |

In a real SDN deployment, the Decision Tree handles 99%+ of traffic at wire speed.
Only the suspicious 1% gets buffered and deeply inspected by DDL + SHAP.

---

## 3. Directory Structure

```
BaseCheckClassifierSimulation/
├── pipeline.py                    # Main pipeline orchestrator
├── run_pipeline_demo.py           # End-to-end demo runner
├── test_pipeline.py               # Integration test suite (27 tests)
├── generate_synthetic_pcap.py     # Creates synthetic .pcap files
├── requirements.txt               # Python dependencies
├── PIPELINE_GUIDE.md              # This document
│
├── extraction/
│   └── feature_extractor.py       # Hybrid DPKT + NFStream feature extraction
│
├── encryption/
│   └── traffic_encryptor.py       # Encryption simulation (AES-256-GCM)
│
├── ddl/
│   ├── __init__.py
│   ├── ddl_model.py               # Deep Dictionary Learning model
│   └── train_ddl.py               # DDL training from CSV or pcaps
│
├── xai/
│   ├── __init__.py
│   └── explainer.py               # SHAP + DDL-native explanations
│
├── decision/
│   └── sentry_controller.py       # Original simple controller (DT only)
│
├── dashboard/
│   └── dashboard.py               # Streamlit dashboard (optional)
│
├── normal/                         # BENIGN .pcap files
│   ├── benign_1.pcap              # Real CIC-IDS-2017 traffic snips
│   └── benign_2.pcap
│
├── attack/                         # MALICIOUS .pcap files
│   ├── bot_1.pcap                 # Bot traffic from CIC-IDS-2017
│   └── bot_2.pcap
│
├── synthetic_attack.pcap           # Synthetic DDoS traffic (7019 packets)
├── synthetic_benign.pcap           # Synthetic HTTP-like traffic (104 packets)
│
└── models/                         # Trained model artifacts (generated)
    ├── ddl_demo.pkl                # DDL model trained on synthetic data
    └── test_ddl.pkl                # DDL model used by tests
```

### Files Outside This Directory

```
BaseCheckClassifier/
├── Decision_tree_model_creator/
│   └── DecisionTree.py             # DT training script (runs on server with CIC-IDS-2017)
├── Decision_tree_results/
│   └── sentry_confusion_matrix.png # DT evaluation results
└── CICDataset_filteration_for_DT/
    ├── Data_filteration/            # Missing value analysis notebooks
    └── Data_selection/
        ├── SELECTED_FEATURES.txt    # The 15 selected features
        ├── Full_Feature_Ranking.csv # All features ranked by importance
        └── Feature_Redundancy_Log.csv
```

---

## 4. Setup

### Prerequisites

- Python 3.10+ (tested on 3.12 and 3.13)
- `libpcap` / `npcap` installed on the system (required by NFStream)
- Git (for cloning the project)

### Step-by-Step Setup

```bash
# 1. Navigate to the simulation directory
cd BaseCheckClassifier/BaseCheckClassifierSimulation/

# 2. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate     # Linux/Mac
# .venv\Scripts\activate      # Windows

# 3. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. Verify installation
python -c "import nfstream, dpkt, shap, sklearn; print('All dependencies OK')"
```

### Dependencies (requirements.txt)

```
pandas
nfstream
scikit-learn
joblib
dpkt
numpy
streamlit
seaborn
matplotlib
shap
scapy
```

> **Note on NFStream**: NFStream requires `libpcap-dev` on Linux. Install with:
> ```bash
> sudo apt-get install libpcap-dev   # Debian/Ubuntu
> sudo yum install libpcap-devel     # RHEL/CentOS
> ```

---

## 5. The 15 Features

These 15 features were selected through importance ranking from the CIC-IDS-2017 dataset. They are all **metadata-based** — they don't require inspecting packet payloads, making them suitable for encrypted traffic analysis.

| # | Feature | Importance | What It Captures | Extraction Method |
|---|---------|-----------|-----------------|-------------------|
| 1 | Packet Length Variance | 0.357 | How much packet sizes vary (DDoS = high variance) | NFStream |
| 2 | Fwd Packet Length Max | 0.211 | Largest packet in forward direction | NFStream |
| 3 | Fwd Header Length | 0.107 | Total header bytes in forward direction | DPKT |
| 4 | Init_Win_bytes_forward | 0.093 | TCP initial window size (forward) — handshake fingerprint | DPKT |
| 5 | Bwd Header Length | 0.054 | Total header bytes in backward direction | DPKT |
| 6 | Total Length of Fwd Packets | 0.050 | Total bytes sent forward | NFStream |
| 7 | Init_Win_bytes_backward | 0.039 | TCP initial window size (backward) — OS fingerprint | DPKT |
| 8 | Bwd Packets/s | 0.013 | Backward packet rate (high in reflection attacks) | NFStream |
| 9 | Flow IAT Min | 0.012 | Minimum inter-arrival time (very low in floods) | NFStream |
| 10 | Fwd IAT Min | 0.012 | Minimum forward inter-arrival time | NFStream |
| 11 | Flow Bytes/s | 0.011 | Throughput rate (abnormally high in volumetric attacks) | NFStream |
| 12 | Active Min | 0.011 | Minimum active period duration | NFStream |
| 13 | Bwd IAT Total | 0.007 | Total backward inter-arrival time | NFStream |
| 14 | Flow IAT Max | 0.003 | Maximum inter-arrival time (scanning = high) | NFStream |
| 15 | Flow Duration | 0.002 | Total flow duration in microseconds | NFStream |

**Source**: `CICDataset_filteration_for_DT/Data_selection/Full_Feature_Ranking.csv`

### Feature Extraction in Detail

The feature extractor (`extraction/feature_extractor.py`) does two passes over each pcap:

**Pass 1 — DPKT (packet-level)**:
- Reads every packet, parses Ethernet → IP → TCP headers
- Extracts TCP initial window size (from SYN packets) per direction
- Accumulates header lengths per direction
- This captures features 3, 4, 5, 7 (header lengths and init window sizes)

**Pass 2 — NFStream (flow-level)**:
- Processes the pcap into flows (bidirectional aggregation)
- Computes statistical features: variance, min/max, rates, durations
- This captures features 1, 2, 6, 8–15

---

## 6. Pipeline Stages — Detailed Walkthrough

### Stage 0: Encryption Simulation

**Module**: `encryption/traffic_encryptor.py`

```python
result = simulate_encryption_and_latency("attack/bot_1.pcap")
# Returns: {"valid_metadata": True, "latency_ms": 2.3, "encrypted_path": "attack/bot_1.pcap", ...}
```

- Calculates latency based on file size (0.05ms per KB + jitter)
- Adds 2–5ms simulated encryption overhead
- In a real system, this would be actual TLS/ESP encryption
- The pcap is treated as "encrypted" — only metadata headers are used downstream

### Stage 1: Feature Extraction

**Module**: `extraction/feature_extractor.py`

```python
from extraction.feature_extractor import extract_features
result = extract_features("attack/bot_1.pcap")
# Returns: {"valid": True, "features": {...}, "ordered_features": [list of 15 values], ...}
```

The `ordered_features` list is what gets fed into the ML models. Order matches the 15 features listed above.

### Stage 2: Base Check (Decision Tree)

**Model**: `sentry_zero_leak_v1.pkl` (trained on CIC-IDS-2017 server data)

- **Training**: See `Decision_tree_model_creator/DecisionTree.py`
- **Runs on the HPC server** (the model is trained there, the `.pkl` is downloaded)
- **Configuration**: `criterion='entropy'`, `max_depth=15`, `class_weight={'Normal':1, 'Attack':50}`
- **Why weight=50?** Missing an attack is 50× worse than a false positive (zero-trust philosophy)

If no DT model `.pkl` is available locally, the pipeline defaults to **flagging everything** for DDL analysis (fail-closed).

### Stage 3: DDL + SHAP XAI (Deep Analysis)

This is the innovative core of the system. Only streams flagged by the DT reach here.

#### Deep Dictionary Learning (DDL)

**Module**: `ddl/ddl_model.py`

DDL learns a "dictionary" of normal traffic patterns during training. At inference:
1. It tries to **reconstruct** the input sample using its learned dictionaries
2. If reconstruction error is high → the sample doesn't match normal patterns → **Anomaly**

**Architecture**:
```
Input (15 features) → z-score normalize
    → Layer 1: Sparse code α₁ using D₁ (15 × k₁ atoms)
        → ISTA sparse coding: find sparsest representation
    → Layer 2: Sparse code α₂ using D₂ (k₁ × k₂ atoms)  
        → Deeper encoding of L1 sparse codes
    → Reconstruct: x̂ = (α₂ · D₂ᵀ) · D₁ᵀ
    → Error = ||x - x̂||²
    → If Error > threshold → ANOMALY
```

**Why DDL (vs autoencoder, isolation forest, etc.)?**
- Dictionary learning is **interpretable** — we can inspect which dictionary atoms activated
- Sparse codes tell us about the structure of the input
- Two layers capture both coarse and fine-grained patterns
- No need for GPU or deep learning frameworks (pure NumPy)

#### SHAP XAI

**Module**: `xai/explainer.py`

Uses `shap.KernelExplainer` to treat the DDL as a black box and compute:
- **SHAP values**: How much each of the 15 features pushes the anomaly score up or down
- **Base value**: Expected anomaly score on normal traffic
- **Per-feature attribution**: "Init_Win_bytes_backward increased the anomaly score by +0.42"

Additionally, **DDL-native explanations** decompose reconstruction error per feature:
- "Feature X had 35% of the total reconstruction error"
- "Expected value ≈ 65535, observed 0 → massive deviation"

Both are combined into a **composite report** suitable for SOC analyst dashboards.

---

## 7. Using Classified PCAPs (normal/ & attack/)

The `normal/` and `attack/` directories contain real CIC-IDS-2017 traffic snippets that are already **ground-truth classified**. This is how the pipeline uses them:

### Current PCAP Inventory

| File | Type | Packets | Size | Source |
|------|------|---------|------|--------|
| `normal/benign_1.pcap` | Benign | 6 | 666B | CIC-IDS-2017 normal traffic snippet |
| `normal/benign_2.pcap` | Benign | 6 | 647B | CIC-IDS-2017 normal traffic snippet |
| `attack/bot_1.pcap` | Attack (Bot) | 6 | 1.1KB | CIC-IDS-2017 bot traffic snippet |
| `attack/bot_2.pcap` | Attack (Bot) | 6 | 1.1KB | CIC-IDS-2017 bot traffic snippet |
| `synthetic_attack.pcap` | Attack (DDoS) | 7019 | 3.3MB | Synthetically generated |
| `synthetic_benign.pcap` | Benign (HTTP) | 104 | 17KB | Synthetically generated |

### How the Pipeline Uses Them

The pipeline **auto-discovers** pcaps from directories and infers ground truth from folder names:

```python
# In pipeline.py and run_pipeline_demo.py:
# Files in attack/ → ground truth = "Attack"
# Files in normal/ → ground truth = "Normal"
# Files with "attack" in name → "Attack"
# Files with "benign" in name → "Normal"
```

**To add more classified pcaps**, simply place them in the appropriate directory:
```bash
# Add a new benign pcap
cp /path/to/new_benign.pcap normal/

# Add a new attack pcap
cp /path/to/ddos_sample.pcap attack/
```

### Important: PCAP Size Matters

The small pcaps (6 packets each) **produce features but with limited statistical richness**. For better DDL training and evaluation:

- **Ideal pcap size**: 50+ packets per flow (so NFStream can compute meaningful variance, IAT statistics, etc.)
- **For DDL training**: Use the `normal/` directory with larger benign pcap files, OR use the CIC-IDS-2017 CSV directly (recommended, see Section 8)
- **For pipeline evaluation**: Both small and large pcaps work — the pipeline handles any valid pcap

### Adding More CIC-IDS-2017 PCAPs

If you have access to the full CIC-IDS-2017 dataset pcaps:

```bash
# Organize by label
mkdir -p normal/http normal/dns normal/browsing
mkdir -p attack/ddos attack/portscan attack/bot attack/infiltration

# Copy pcaps into appropriate directories
# The pipeline auto-discovers them recursively
```

### Alternative: Using CSV Data Instead of PCAPs

If you don't have pcap files but have the processed CIC-IDS-2017 CSV (`TRAIN_Traffic.csv`, `TEST_Traffic.csv`), you can:

1. **Train DDL directly from CSV** (recommended):
   ```bash
   python ddl/train_ddl.py --csv /path/to/TRAIN_Traffic.csv --output models/ddl_production.pkl
   ```

2. **Create synthetic pcaps from CSV feature distributions** (for demo purposes):
   ```bash
   python generate_synthetic_pcap.py
   # Generates synthetic_attack.pcap and synthetic_benign.pcap
   ```

---

## 8. Training the Models

### A) Decision Tree (Base Check Classifier)

The DT is trained on the HPC server where the full CIC-IDS-2017 CSV lives:

```bash
# On the server:
python Decision_tree_model_creator/DecisionTree.py
# Outputs: sentry_zero_leak_v1.pkl, sentry_features.pkl, sentry_confusion_matrix.png
```

**To use the trained model locally**, copy the `.pkl` file:
```bash
scp server:/scratch1/.../Models/sentry_zero_leak_v1.pkl ./models/
```

If you don't have the DT model file, the pipeline still works — it just flags everything for DDL analysis (zero-trust fallback).

### B) DDL Model (Deep Analysis)

The DDL has three training modes:

#### Option 1: Train from CSV (Recommended for production)
```bash
cd BaseCheckClassifierSimulation/
source .venv/bin/activate

python ddl/train_ddl.py \
  --csv /path/to/TRAIN_Traffic.csv \
  --output models/ddl_production.pkl \
  --atoms-l1 64 \
  --atoms-l2 128 \
  --epochs 100 \
  --threshold-pct 95
```

This filters only the "Normal" rows from the CSV and trains DDL to learn what normal traffic looks like. Attack samples are **not** used during training — they're used only for evaluation.

#### Option 2: Train from benign pcap directory
```bash
python ddl/train_ddl.py \
  --pcap-dir ./normal/ \
  --output models/ddl_pcap.pkl \
  --epochs 100
```

This extracts features from each pcap in `normal/` and trains on them. **Requires at least 5 valid pcap files** with enough packets for NFStream to produce meaningful statistics.

#### Option 3: Train on synthetic data (for testing/demo only)
```bash
python run_pipeline_demo.py --no-shap
# Automatically trains DDL on 200 synthetic samples
```

### Training Hyperparameters

| Parameter | Default | What it controls |
|-----------|---------|-----------------|
| `--atoms-l1` | 64 | Layer 1 dictionary size (more = finer patterns) |
| `--atoms-l2` | 128 | Layer 2 dictionary size (more = deeper encoding) |
| `--epochs` | 100 | Training iterations |
| `--threshold-pct` | 95 | Percentile for anomaly threshold (95 = top 5% of training errors are "borderline") |

**Rule of thumb**: If you get too many false positives, increase `threshold-pct` to 97 or 99. If you miss attacks, decrease it to 90 or 92.

---

## 9. Running the Pipeline

### Quick Demo (No models needed)

```bash
cd BaseCheckClassifierSimulation/
source .venv/bin/activate

# Trains DDL on synthetic data and runs all local pcaps
python run_pipeline_demo.py --no-shap
```

### With Pre-trained Models

```bash
# Full pipeline with DT + DDL + SHAP
python run_pipeline_demo.py \
  --dt-model models/sentry_zero_leak_v1.pkl \
  --ddl-model models/ddl_production.pkl

# Specific pcap files only
python run_pipeline_demo.py \
  --ddl-model models/ddl_production.pkl \
  --files attack/bot_1.pcap normal/benign_1.pcap

# Entire directories
python run_pipeline_demo.py \
  --ddl-model models/ddl_production.pkl \
  --pcap-dir ./attack/ ./normal/
```

### Run Integration Tests

```bash
python test_pipeline.py
# Expected: 27/27 passed
```

### Programmatic Usage (From Your Own Code)

```python
from pipeline import ZeroTrustPipeline

# Initialize
pipeline = ZeroTrustPipeline(
    dt_model_path="models/sentry_zero_leak_v1.pkl",  # optional
    ddl_model_path="models/ddl_production.pkl",
    enable_shap=True,
)

# Process a single stream
result = pipeline.process_stream("attack/bot_1.pcap", ground_truth="Attack")
print(result["final_action"])      # "DROP" or "FORWARD"
print(result["explanation"])       # XAI explanation dict

# Process a batch
pcap_list = [
    ("attack/bot_1.pcap", "Attack"),
    ("normal/benign_1.pcap", "Normal"),
]
output = pipeline.run_batch(pcap_list, output_log="results.json")
```

---

## 10. Understanding the Output

The pipeline produces a JSON log (`pipeline_results.json`) with full details for every stream processed. Here's how to read it:

### Per-Stream Result Structure

```json
{
  "stream_id": "stream_0001_bot_1.pcap",
  "input_file": "bot_1.pcap",
  "ground_truth": "Attack",
  "final_action": "DROP",
  "stages": {
    "encryption": {
      "latency_ms": 2.3,
      "algorithm": "AES-256-GCM"
    },
    "extraction": {
      "features": {
        "Packet Length Variance": 3201.44,
        "Fwd Packet Length Max": 249,
        ...
      },
      "flow_id": "192.168.10.14:6842->205.174.165.73:80",
      "protocol": "HTTP"
    },
    "base_check": {
      "prediction": "Attack",
      "confidence": 0.85,
      "model": "DecisionTree (entropy, depth=15, attack_weight=50)"
    },
    "deep_analysis": {
      "ddl_prediction": "Anomaly",
      "anomaly_score": 23.65,
      "threshold": 2.81,
      "analysis_time_ms": 1160
    },
    "buffer": {
      "action": "DROPPED",
      "hold_time_ms": 1160
    }
  },
  "explanation": {
    "summary": "Decision: Anomaly\nThe DDL reconstruction error is 8.42x the normal threshold.\nPrimary anomalous features: Init_Win_bytes_backward, Init_Win_bytes_forward\nRecommendation: DROP stream and alert SOC analyst.",
    "ddl_native": {
      "feature_contributions": [
        {
          "feature": "Init_Win_bytes_backward",
          "pct_of_total_error": 54.6,
          "original_value": 29200,
          "reconstructed_value": 29553.49
        }
      ]
    },
    "shap": {
      "attributions": [
        {
          "feature": "Init_Win_bytes_backward",
          "shap_value": 0.42,
          "direction": "increases anomaly score"
        }
      ]
    }
  }
}
```

### Key Fields to Check

| Field | What to look for |
|-------|-----------------|
| `final_action` | `"DROP"` (anomaly detected) or `"FORWARD"` (clean) |
| `stages.base_check.prediction` | DT verdict (`"Normal"` or `"Attack"`) |
| `stages.deep_analysis.anomaly_score` | DDL score — higher = more anomalous |
| `stages.deep_analysis.threshold` | The learned normal boundary |
| `explanation.summary` | Human-readable explanation (show to SOC analyst) |
| `explanation.ddl_native.feature_contributions` | Which features had highest reconstruction error |
| `explanation.shap.attributions` | SHAP-based feature importance for this specific sample |

### Execution Summary

The pipeline also prints a summary:

```
  Total streams processed:       6
  ├─ DT passed (Normal):         2     ← forwarded immediately
  └─ DT flagged → buffered:      4     ← sent to DDL
      ├─ DDL cleared (released):  1     ← DDL said clean
      └─ DDL confirmed (dropped): 3     ← DDL confirmed anomaly

  Ground Truth Evaluation:
    TP (Attack correctly dropped):  3
    TN (Normal correctly forwarded): 2
    FP (Normal incorrectly dropped): 1
    FN (Attack incorrectly passed):  0

    Accuracy:  0.8333
    Precision: 0.7500
    Recall:    1.0000
    F1-Score:  0.8571
```

---

## 11. Analysing Results & Taking Action

### For SOC Analysts

When a stream is **DROPPED**, the explanation tells you:

1. **What was anomalous**: "Primary anomalous features: Init_Win_bytes_backward, Flow Bytes/s"
2. **How anomalous**: "Reconstruction error is 8.42× the normal threshold"
3. **What was expected**: "Expected ≈65535, observed 29200"
4. **What to do**: "DROP stream and alert SOC analyst"

**Action items when you see a DROP:**
- Check the source IP in your SIEM
- Look for the specific anomalous features — do they match a known attack pattern?
- If `Init_Win_bytes` values are unusual → possible OS fingerprinting or spoofing
- If `Flow Bytes/s` or `Bwd Packets/s` are extreme → volumetric attack
- If `Flow IAT Min` is near zero → flood attack
- If `Packet Length Variance` is unusually high → mixed payload sizes (DDoS)

### For Researchers

To evaluate the pipeline on a labeled dataset:

```python
from pipeline import ZeroTrustPipeline
import json

# Load pipeline with trained models
pipeline = ZeroTrustPipeline(
    dt_model_path="models/sentry_zero_leak_v1.pkl",
    ddl_model_path="models/ddl_production.pkl",
)

# Prepare labeled pcaps
pcap_list = []
for pcap_file in os.listdir("attack/"):
    pcap_list.append((f"attack/{pcap_file}", "Attack"))
for pcap_file in os.listdir("normal/"):
    pcap_list.append((f"normal/{pcap_file}", "Normal"))

# Run evaluation
output = pipeline.run_batch(pcap_list, output_log="evaluation_results.json")

# The summary prints TP/TN/FP/FN, Accuracy, Precision, Recall, F1
```

### Interpreting False Positives

If benign traffic gets flagged as anomaly (FP), check:
1. Is the DDL trained on representative benign data? Small synthetic training → high FP rate
2. Is `threshold-pct` too low? Try increasing to 97 or 99
3. Does the benign pcap have enough packets for meaningful feature extraction?

### Interpreting False Negatives

If attack traffic passes as normal (FN), check:
1. Does the DT model catch this attack type? (Check confusion matrix from training)
2. Is the attack "close" to normal patterns? (Some subtle attacks mimic normal traffic)
3. For the DT: is the `class_weight` for Attack high enough?

---

## 12. Integration Guide — For Future Developers

### How to Add a New ML Model

To replace or add alongside the DDL:

1. **Create your model class** in a new directory (e.g., `autoencoder/`):
   ```python
   class MyModel:
       def fit(self, X_normal): ...
       def predict(self, X):
           return {"labels": ..., "scores": ..., "threshold": ...}
       def save(self, path): ...
       @classmethod
       def load(cls, path): ...
   ```

2. **Update `pipeline.py`** to load and use your model:
   ```python
   # In _deep_analysis():
   my_model_future = self.executor.submit(self.my_model.predict, features_arr)
   ```

3. **Update `xai/explainer.py`** if your model has its own explanation method.

### How to Add New Features

If you need to extract additional features beyond the current 15:

1. Add the feature extraction logic to `extraction/feature_extractor.py`
2. Update `REQUIRED_FEATURES` list (order matters!)
3. Retrain both the DT and DDL models with the new feature set
4. Update `FEATURE_NAMES` in `pipeline.py` and `xai/explainer.py`

### How to Use Real SDN Integration

Replace `SDNBuffer` with actual OpenFlow commands:

```python
# Instead of:
self.sdn_buffer.add(stream_id, features)

# Use OpenFlow:
switch.send_msg(ofproto_parser.OFPFlowMod(
    match=match, instructions=[hold_in_buffer_instruction]
))
```

### How to Deploy as a Service

```python
# Example Flask endpoint:
@app.route('/analyze', methods=['POST'])
def analyze_stream():
    pcap_file = request.files['pcap']
    pcap_file.save('/tmp/stream.pcap')
    result = pipeline.process_stream('/tmp/stream.pcap')
    return jsonify(result)
```

### Key Interfaces At a Glance

```python
# Feature extraction
from extraction.feature_extractor import extract_features
result = extract_features("path/to/file.pcap")
# → {"valid": bool, "features": dict, "ordered_features": list[15]}

# DDL prediction
from ddl.ddl_model import DeepDictionaryLearning
ddl = DeepDictionaryLearning.load("models/ddl.pkl")
result = ddl.predict(feature_vector_15d)
# → {"labels": "Normal"/"Anomaly", "scores": float, "threshold": float, ...}

# DDL explanation
from xai.explainer import DDLExplainer
explainer = DDLExplainer(ddl, background_data=normal_samples)
report = explainer.explain(feature_vector_15d)
# → {"summary": str, "ddl_explanation": dict, "shap_explanation": dict}

# Full pipeline
from pipeline import ZeroTrustPipeline
pipe = ZeroTrustPipeline(dt_model_path=..., ddl_model_path=...)
result = pipe.process_stream("file.pcap", ground_truth="Attack")
# → {"final_action": "DROP"/"FORWARD", "explanation": dict, "stages": dict}
```

---

## 13. Known Limitations & Next Steps

### Current Limitations

| Issue | Impact | Resolution |
|-------|--------|-----------|
| **DT model not available locally** | Pipeline flags everything for DDL | Copy `.pkl` from HPC server |
| **Feature distribution mismatch** | DT trained on CICFlowMeter features, extraction uses NFStream → predictions may differ | Retrain DT on NFStream-extracted features, OR use CICFlowMeter for extraction |
| **Small pcaps (6 packets)** | NFStream statistics are less meaningful with few packets | Use larger pcap captures (50+ packets per flow) |
| **DDL trained on synthetic data** | High false positive rate on real traffic | Retrain on actual CIC-IDS-2017 TRAIN_Traffic.csv benign rows |
| **SHAP is slow** | ~500-1000ms per sample | Use `--no-shap` for speed, or pre-compute SHAP on representative samples |
| **Single-flow extraction** | Only first flow per pcap is analyzed | Extend to handle multi-flow pcaps |

### Recommended Next Steps

1. **Train DDL on real CIC-IDS-2017 data**:
   ```bash
   python ddl/train_ddl.py --csv /path/to/TRAIN_Traffic.csv --output models/ddl_v1.pkl
   ```

2. **Collect larger pcap samples** for the `normal/` and `attack/` directories (50+ packets each)

3. **Evaluate on CIC-IDS-2017 test set**:
   - Extract features from TEST_Traffic.csv
   - Run through DDL
   - Compare confusion matrix with the DT-only baseline

4. **Address CICFlowMeter ↔ NFStream feature gap**:
   - Option A: Retrain DT on features extracted by NFStream
   - Option B: Use CICFlowMeter for extraction (requires Java)
   - Option C: Train a calibration layer between NFStream and CICFlowMeter features

5. **Multi-flow pcap support**: Extend `pipeline.py` to iterate over all flows in a pcap, not just the first

---

## 14. Quick Reference — Commands Cheat Sheet

```bash
# ──────────────────────────────────────
# SETUP
# ──────────────────────────────────────
cd BaseCheckClassifier/BaseCheckClassifierSimulation/
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# ──────────────────────────────────────
# TRAIN MODELS
# ──────────────────────────────────────
# Decision Tree (on HPC server with CIC-IDS-2017 data):
python ../Decision_tree_model_creator/DecisionTree.py

# DDL from CSV:
python ddl/train_ddl.py --csv /path/to/TRAIN_Traffic.csv --output models/ddl_v1.pkl

# DDL from pcap directory:
python ddl/train_ddl.py --pcap-dir ./normal/ --output models/ddl_pcap.pkl

# ──────────────────────────────────────
# RUN PIPELINE
# ──────────────────────────────────────
# Quick demo (auto-trains DDL on synthetic data):
python run_pipeline_demo.py --no-shap

# With trained models:
python run_pipeline_demo.py --dt-model models/sentry_zero_leak_v1.pkl --ddl-model models/ddl_v1.pkl

# Specific files:
python run_pipeline_demo.py --ddl-model models/ddl_v1.pkl --files attack/bot_1.pcap normal/benign_1.pcap

# Directories:
python run_pipeline_demo.py --ddl-model models/ddl_v1.pkl --pcap-dir ./attack/ ./normal/

# ──────────────────────────────────────
# TEST
# ──────────────────────────────────────
python test_pipeline.py      # 27 integration tests

# ──────────────────────────────────────
# EXTRACT FEATURES FROM A SINGLE PCAP
# ──────────────────────────────────────
python extraction/feature_extractor.py attack/bot_1.pcap

# ──────────────────────────────────────
# GENERATE SYNTHETIC TRAFFIC
# ──────────────────────────────────────
python generate_synthetic_pcap.py
```

---

## Appendix: Recreating Everything From Scratch

If you need to rebuild the pipeline on a fresh machine:

```bash
# 1. Clone the repository
git clone https://github.com/cepdnaclk/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic.git
cd e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/BaseCheckClassifier/BaseCheckClassifierSimulation/

# 2. Set up environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Verify tests pass
python test_pipeline.py

# 4. (Optional) Train DDL on real data
#    Replace /path/to/TRAIN_Traffic.csv with actual CIC-IDS-2017 CSV path
python ddl/train_ddl.py --csv /path/to/TRAIN_Traffic.csv --output models/ddl_v1.pkl

# 5. (Optional) Copy DT model from HPC server
scp server:/scratch1/.../Models/sentry_zero_leak_v1.pkl ./models/

# 6. Run the full pipeline
python run_pipeline_demo.py --ddl-model models/ddl_v1.pkl --dt-model models/sentry_zero_leak_v1.pkl

# 7. Review results
cat pipeline_results.json | python -m json.tool | less
```

The pipeline is fully modular — each component can be used independently or replaced:
- Swap the DT for a Random Forest by loading a different `.pkl`
- Swap DDL for an Autoencoder by implementing the same `predict()` interface
- Replace NFStream with CICFlowMeter by changing `feature_extractor.py`
- Replace the SDN buffer simulation with real OpenFlow commands
