# Explainable AI-Driven Zero-Trust Anomaly Detection for Encrypted Traffic

**University of Peradeniya — e20420Janith**
**CIC-IDS-2017 Dataset | SDN Pipeline**

---

## Overview

This system implements a **two-stage anomaly detection pipeline** for Software-Defined Networks (SDN), using a lightweight Decision Tree as the first filter and Deep Dictionary Learning (DDL) + Isolation Forest with dual XAI (LIME + SHAP) as the second stage.

### Why Two Stages?

Traditional IDS approaches use a single model, which creates a trade-off: fast but inaccurate, or accurate but slow. Our pipeline resolves this:

- **Stage 1 (BCC)**: Sub-microsecond Decision Tree classifies 95% of traffic instantly
- **Stage 2 (DDL+IF+XAI)**: Only the 5% flagged traffic gets deep analysis
- **Result**: Near-zero false positives (0.25% FPR) with sub-10µs average latency

---

## Pipeline Architecture

```
PacketIN ──→ Unified Feature Extraction (DPKT, single pass)
                |
                ├── 28 features ──→ BCC v2 (Decision Tree, <1µs)
                |                      |
                |                   BENIGN ──→ FORWARD + ALLOW rule
                |                   ATTACK ──→ SDN Buffer
                |                                |
                └── 40 features ──→ DDL (reconstruction error) + IF (isolation score)
                                       |
                                    Both agree Normal  ──→ FORWARD + ALLOW rule
                                    Both agree Anomaly ──→ DROP + XAI explanation
                                       |
                                   LIME + SHAP explain the decision
```

### Design Decisions

1. **Feature extraction once, used twice**: The unified extractor computes a superset of features in a single pass. BCC uses 28 features, DDL+IF use 40. No redundant computation.

2. **DDL + IF consensus**: A flow is DROPped only when **both** DDL (reconstruction error > threshold) **and** IF (isolation score indicates outlier) agree. This dual check reduces false positives to 0.25%.

3. **XAI for transparency**: LIME and SHAP explain **why** each flow was flagged, showing which features (packet sizes, timing patterns, flag counts) contributed most. This helps security analysts trust and audit the system.

---

## Models

| Model | Role | Features | Type | Training |
|-------|------|----------|------|----------|
| **BCC v2** | Stage 1 gatekeeper | 28 | Decision Tree | Supervised (BENIGN/ATTACK) |
| **DDL** | Stage 2 anomaly detector | 40 | Deep Dictionary Learning (ISTA) | One-class (Normal only) |
| **IF** | Stage 2 consensus voter | 40 | Isolation Forest | One-class (Normal only) |

---

## Key Results

| Model | Precision | Recall | FPR | Latency |
|-------|:---------:|:------:|:---:|:-------:|
| BCC v2 (Sandaru's data) | 96.3% | **99.89%** | 2.0% | 0.05 µs |
| DDL-40 standalone | 69.9% | 45.4% | 5.0% | 133 µs |
| **Full Pipeline** | **93.6%** | 14.1% | **0.25%** | ~8 µs avg |

> **Interpretation**: The pipeline prioritizes precision over recall — when it DROPs a flow, it's 94% likely to be a real attack. Only 0.25% of legitimate traffic is ever blocked.

---

## Directory Structure

```
├── DDLModel/                # DDL model, training, feature extraction
│   ├── ddl_model.py         # DeepDictionaryLearning class
│   ├── ddl_feature_extractor.py  # 40-feature DDL extractor
│   └── train_ddl_enhanced.py     # Training script (GPU/CPU)
├── BaseCheckClassifier/     # BCC v2 feature extractor
├── FullSDNPipeline/         # Full pipeline scripts
│   ├── sdn_pipeline.py      # Main SDN pipeline
│   ├── xai_explainer.py     # LIME + SHAP XAI
│   ├── run_full_evaluation.py    # Comprehensive per-model testing
│   ├── test_pipeline_csv.py      # CSV-based pipeline test
│   ├── packet_shooter.py         # PCAP replay
│   └── unified_feature_extractor.py  # Shared feature extraction
├── models/                  # Trained model files
│   ├── sentry_model_v2.pkl  # BCC v2
│   ├── ddl_40feat.pkl       # DDL (40 features)
│   └── isolation_forest.pkl # IF
├── results/                 # Test results (generated)
│   ├── summary.md
│   ├── stage1_bcc/
│   ├── stage2_ddl/
│   ├── stage2_if/
│   └── stage2_xai/
├── dataset/                 # CIC-IDS-2017 CSV files
├── docs/guides/quick-start.md           # Copy-paste commands
├── docs/architecture/pipeline.md        # Detailed architecture
├── docs/reports/training-results.md      # All test results
└── docs/planning/demonstration-plan.md     # Demo procedure
```

---

## Quick Start

```bash
cd /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate

# Run full evaluation:
PYTHONPATH=/tmp/lime_pkg:$PYTHONPATH python FullSDNPipeline/run_full_evaluation.py

# View results:
cat results/summary.md
```

See `docs/guides/quick-start.md` for full step-by-step guide.

---

## Impact Assessment

### Without This System
- All traffic is either trusted (no security) or manually inspected (impractical at scale)
- No explainability — security teams cannot audit automated decisions
- Single-model approaches sacrifice either speed or accuracy

### With This System
- **95% of traffic** processed in <1µs (BCC passes benign instantly)
- **5% suspicious traffic** gets deep 40-feature analysis within milliseconds
- **Every DROP decision** is explained by LIME + SHAP (audit trail)
- **0.25% false positive rate** — virtually no legitimate traffic disrupted
- **Zero-trust architecture** — no traffic is inherently trusted

---

## References

- **Dataset**: CIC-IDS-2017 (Canadian Institute for Cybersecurity)
- **DDL**: Deep Dictionary Learning for anomaly detection
- **LIME**: Ribeiro et al., "Why Should I Trust You?" (KDD 2016)
- **SHAP**: Lundberg & Lee, "A Unified Approach to Interpreting Model Predictions" (NeurIPS 2017)
