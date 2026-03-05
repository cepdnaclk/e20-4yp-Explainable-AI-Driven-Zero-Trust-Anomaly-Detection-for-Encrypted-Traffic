# EnhancedPipeline/docs/ARCHITECTURE.md
# Enhanced DDL+XAI Pipeline Architecture
**Proposed Improvement | Zero-Trust Anomaly Detection | University of Peradeniya**

> **Purpose:** This folder contains a proposed improved architecture that adds an Isolation Forest second-opinion vote, adaptive mutual-information feature selection, SHAP+LIME dual explanations, a REST API for switch integration, and a Streamlit monitoring dashboard.
>
> The original ZeroTrustPipeline/ is kept unchanged — this is an alternative implementation.

---

## Why an Enhanced Pipeline?

| Limitation in Original | Enhancement |
|------------------------|-------------|
| DDL uses same 15 features as DT | DDL now uses 30 purpose-built statistical features |
| Single anomaly detector (DDL) | DDL + Isolation Forest vote (reduces false positives) |
| Fixed threshold (percentile) | F1-optimal threshold calibration |
| SHAP only | SHAP + LIME (complementary explanations) |
| No API | FastAPI REST endpoint for switch integration |
| No live dashboard | Streamlit real-time monitoring |

---

## Architecture Diagram

```
Physical Switch (SPAN port)
         │
         ▼
[NFStream Live Capture]
         │
    ┌────┴──────────────────────────────────┐
    │           FEATURE EXTRACTION           │
    │  ├─ 15 DT features → Base Check       │
    │  └─ 30 DDL features → Enhanced check  │
    └────┬──────────────────────────────────┘
         │
    ┌────▼──────────────────────┐
    │  BASE CHECK CLASSIFIER    │  ← Teammate's DT (not modified)
    │  (DT, 15 features)        │
    └────┬──────────────────────┘
         │
    Normal ──────────────────────────────────► FORWARD
         │
    Anomaly
         │
    ┌────▼──────────────────────────────────────────────┐
    │               SDN BUFFER                          │
    │  (Holds packets while deep analysis runs)          │
    └────┬──────────────────────────────────────────────┘
         │
    ┌────▼──────────────────────────────────────────────┐
    │              ENHANCED DEEP ANALYSIS                │
    │                                                    │
    │  ┌─────────────────┐    ┌──────────────────────┐  │
    │  │  DDL (30 feat)  │    │  Isolation Forest     │  │
    │  │  Reconstruction │    │  Second Opinion       │  │
    │  │  error check    │    │  (trained on same     │  │
    │  └────────┬────────┘    │   normal data)        │  │
    │           │             └──────────┬───────────┘  │
    │           └──────────┬────────────┘              │
    │                   VOTE                            │
    │          Both Normal   → RELEASE                  │
    │          Both Anomaly  → DROP (high confidence)   │
    │          Disagreement  → DDL threshold adjusted    │
    └────┬──────────────────────────────────────────────┘
         │
    ┌────▼──────────────────────────────────────────────┐
    │              DUAL XAI EXPLANATION                  │
    │                                                    │
    │  ┌─────────────────┐    ┌──────────────────────┐  │
    │  │  SHAP           │    │  LIME TabularExp.    │  │
    │  │  KernelExplainer│    │  LocalExplanation    │  │
    │  │  (model-agnostic│    │  (linear approx)     │  │
    │  │   perturbation) │    │                      │  │
    │  └─────────────────┘    └──────────────────────┘  │
    │                                                    │
    │  DDL-native: per-feature reconstruction error      │
    │                                                    │
    │  Agreement analysis (SHAP ∩ LIME ∩ DDL-native)    │
    │  → High confidence when all 3 agree on top feature │
    └────┬──────────────────────────────────────────────┘
         │
    ┌────▼──────────────────────────────────────────────┐
    │              DECISION + ENFORCEMENT                │
    │                                                    │
    │  Normal  → Release SDN buffer → FORWARD            │
    │  Anomaly → DROP + XAI report → REST API notify    │
    │             └─► OpenFlow controller installs rule  │
    └───────────────────────────────────────────────────┘
```

---

## Adaptive Feature Selection

Instead of fixed 30 features, the system periodically re-ranks features by **mutual information** with detected anomalies, allowing the DDL to focus on the most discriminative features for the current attack pattern.

```
Every N_BATCH flows:
  anomaly_set = flows classified as anomaly in last batch
  normal_set  = flows classified as normal in last batch
  MI_scores   = mutual_information(features, labels)
  top_k       = argsort(MI_scores)[-K:]   # Keep top K features
  ddl.retrain(normal_set[:, top_k])       # Retrain DDL on new feature subset
```

---

## REST API Endpoints

See `rest_api.py` for full implementation.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/predict` | POST | Classify a flow (30-feature JSON) |
| `/predict_live` | POST | Classify from NFStream-format flow JSON |
| `/status` | GET | Pipeline stats (flows, drops, latency) |
| `/explain/{flow_id}` | GET | Retrieve XAI report for a previous decision |
| `/health` | GET | Health check |

---

## Configuration

All parameters in `EnhancedPipeline/config.py`:

```python
DDL_N_FEATURES     = 30          # Use ddl_feature_extractor.py
DDL_N_ATOMS_L1     = 64
DDL_N_ATOMS_L2     = 128
DDL_N_ATOMS_L3     = 0           # Set > 0 to enable 3-layer DDL
DDL_SPARSITY       = 0.1
DDL_EPOCHS         = 150
DDL_THRESHOLD_MODE = "f1_optimal"  # or "percentile"

IF_N_ESTIMATORS    = 100          # Isolation Forest trees
IF_CONTAMINATION   = 0.05         # Expected anomaly rate

TOP_K_FEATURES     = 25           # Adaptive feature selection
RETRAIN_EVERY_N    = 500          # Flows between MI re-ranking

SHAP_NSAMPLES      = 100          # SHAP perturbation samples
LIME_NSAMPLES      = 500          # LIME perturbation samples
```

---

## File Index

| File | Purpose |
|------|---------|
| `enhanced_pipeline.py` | Main orchestrator |
| `if_second_vote.py` | Isolation Forest second opinion |
| `adaptive_features.py` | MI-based feature selection + retraining |
| `dual_xai.py` | SHAP + LIME combined XAI |
| `rest_api.py` | FastAPI REST server |
| `dashboard.py` | Streamlit live monitoring |
| `docs/ARCHITECTURE.md` | This document |
| `docs/TESTING_GUIDE.md` | Testing with real + simulated traffic |
| `docs/SWITCH_SETUP.md` | Physical switch configuration |
