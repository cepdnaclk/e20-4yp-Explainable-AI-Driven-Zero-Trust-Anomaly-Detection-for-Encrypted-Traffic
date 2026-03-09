# 🏗️ Gatekeeper Model — Architecture & Training Plan

**Document:** Gatekeeper Model Design  
**Project:** XAI Zero-Trust Anomaly Detection for Encrypted Traffic  
**Date:** 2026-03-05  

---

## 🎯 Purpose

This model is **Stage 1** of a two-stage detection pipeline. Its sole job is to act as a
**fast, ultra-aggressive binary filter** — any flow that is not confidently BENIGN is
forwarded to the Stage 2 deep learning (DL) model for thorough analysis.

```
Live TCP Flow
      │
      ▼
┌─────────────────────────┐
│   Gatekeeper  (Stage 1) │  ← This model (Decision Tree)
│   Binary: BENIGN/ATTACK │
└─────────────────────────┘
      │
   ───┴───
   ▼       ▼
BENIGN   NOT-BENIGN
(pass)  (→ DL model, Stage 2)
```

**Design rule:** If in ANY doubt → flag as NOT-BENIGN and send to DL.  
Computational cost of the DL model is acceptable. Missing an attack is not.

---

## 🌳 Model Choice: Decision Tree

A **single Decision Tree** is the right model for this gatekeeper role.

| Property | Decision Tree | Random Forest |
|----------|:---:|:---:|
| Inference speed | ⚡ ~1–5 µs per flow | ~0.5–2 ms (200 trees) |
| Binary accuracy | ~97–98% | ~99% |
| Network congestion risk | **None** | Very Low |
| Interpretable / auditable | ✅ | ❌ |
| Threshold tuning | ✅ | ✅ |
| Right for gatekeeper | ✅ **Best fit** | Overkill |

RF's extra 1–2% accuracy is irrelevant here — the DL model handles all ambiguous flows.
What matters is **microsecond inference** and **zero missed attacks**.

### Training Configuration
```python
DecisionTreeClassifier(
    max_depth=20,
    min_samples_leaf=5,
    class_weight={
        'BENIGN': 1,
        'ATTACK': 10    # 10× penalty for missing an attack
    }
)
```

---

## ⚖️ Dataset Balancing

### Raw distribution (from 702,007 labeled streams)
| Class | Count | % |
|-------|------:|---|
| BENIGN | 522,139 | 74.4% |
| ATTACK | 179,868 | 25.6% |

### Balancing strategy: Undersample BENIGN only
```
ATTACK  →  179,868   (keep ALL — never drop a single attack sample)
BENIGN  →  179,868   (random undersample from 522,139)
─────────────────────────────────────────────────────────
Total   →  359,736   (50% / 50% perfectly balanced)
```

**Why no SMOTE?**  
We already have 179,868 real attack samples — synthetic generation is unnecessary
and risks introducing unrealistic patterns. Undersampling BENIGN keeps the dataset
clean, fast to process, and free of synthetic bias.

---

## 📚 Train / Test Split

### Training data: balanced dataset
```
Balanced dataset: 359,736 rows
        │
        ▼
Stratified 80/20 split
        │
        ├── train.csv:          287,789 rows  (50% BENIGN, 50% ATTACK)
        └── test_balanced.csv:   71,947 rows  (50% BENIGN, 50% ATTACK)
```

`test_balanced.csv` is used only for **threshold tuning** during training.

---

## 🎯 Threshold System (2-Zone, Binary)

After training, use `predict_proba` to get P(ATTACK) for each flow.
Apply a **single aggressive threshold**:

```
P(ATTACK) < 0.15  →  ✅ BENIGN   — let through to network
P(ATTACK) ≥ 0.15  →  ⛔ NOT-BENIGN — forward to DL model (Stage 2)
```

Setting the threshold at 0.15 means: any flow with even a **15% probability of being an
attack** is immediately escalated. This is deliberately aggressive — the DL model exists
precisely to handle these forwarded flows.

**Result:**
- Attack recall → ~99.9% (almost no attack leaks through as BENIGN)
- Some BENIGN flagged as NOT-BENIGN → acceptable, DL handles them
- DL receives ALL suspicious + borderline flows for deep analysis

---

## 🧪 Testing Plan

### Two-phase evaluation

**Phase 1 — Threshold tuning** (on `test_balanced.csv`, 50/50):
- Sweep threshold from 0.50 down to 0.05
- Find the lowest threshold where attack recall ≥ 99.9%
- That threshold is saved with the model

**Phase 2 — Real-world evaluation** (on `test_raw.csv`, 74% BENIGN / 26% ATTACK):
- This is a fresh hold-out never seen during training
- Reflects actual live traffic distribution
- Measures what the model does on real-world data

### Metrics to report

| Metric | Target | Meaning |
|--------|--------|---------|
| **Attack Recall** | ≥ 99.9% | Almost zero attacks leak through |
| Attack Precision | > 60% | Acceptable false alarm rate |
| BENIGN Recall | > 75% | Most normal traffic passes directly |
| Avg inference time | < 0.1 ms | No packet queuing / congestion |
| % forwarded to DL | < 25% | DL workload stays manageable |

---

## 📁 Output Files

| File | Purpose |
|------|---------|
| `train.csv` | Balanced 80% training data |
| `test_balanced.csv` | Balanced 20% for threshold tuning |
| `test_raw.csv` | Raw unbalanced hold-out for real-world evaluation |
| `sentry_model_v2.pkl` | Trained DT + threshold + feature list |
| `evaluation_report.md` | Full metrics from both test phases |

---

## 🔁 Full Pipeline Summary

```
dataset_raw.csv  (702k rows, 74/26 split)
        │
        ▼  [prepare_dataset.py]
Undersample BENIGN → 179,868
All ATTACK kept   → 179,868
 = 359,736 balanced rows
        │
        ▼ Stratified 80/20
train.csv (287k)   test_balanced.csv (72k)   test_raw.csv (70k raw)
        │
        ▼  [train_model.py]
DecisionTree(max_depth=20, class_weight={ATTACK:10})
        │
        ▼  Threshold tuning on test_balanced.csv
threshold = 0.15  (or lowest for recall ≥ 99.9%)
        │
        ▼  Save
sentry_model_v2.pkl
        │
        ▼  [evaluate_model.py] on test_raw.csv
evaluation_report.md
```

---

## 📌 Key Design Decisions

| Decision | Reason |
|----------|--------|
| Binary only (BENIGN / NOT-BENIGN) | Speed + simplicity; DL identifies attack type |
| Decision Tree not RF | 1000× faster inference; DL handles hard cases |
| Undersample not SMOTE | Clean real data; no synthetic bias |
| Threshold 0.15 (aggressive) | Zero tolerance for attack leakage |
| Test on raw unbalanced data | Reflects real-world live traffic distribution |
