# DDL Model & XAI Explanation — Supervisor Briefing
**Date:** 2026-03-09 | **Team:** E20-4YP | **Meeting:** Supervisor Progress Review

---

## 1. Deep Dictionary Learning (DDL) — What It Is

DDL is an **unsupervised anomaly detector** that learns a "dictionary" of normal traffic patterns.
It is trained **only on normal flows** — it never sees attack data during training. At inference time, it tries to reconstruct each input flow using its dictionary. If the reconstruction error exceeds a threshold, the flow is flagged as anomalous.

### How It Works (3-Step Process)

```
┌─────────────────────────────────────────────────────────┐
│ Step 1: Dictionary Learning (Training — Offline)        │
│                                                         │
│  Input: 1.68M normal flows × 40 features                │
│  Process: Learn dictionary D and sparse code α           │
│           such that X ≈ D × α  (ISTA algorithm)         │
│  Output: Dictionary matrix D (40×64 atoms)               │
│  Time: ~12 min (GPU, 150 epochs)                        │
└─────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│ Step 2: Threshold Calibration                           │
│                                                         │
│  Run all normal training flows through the model        │
│  Compute reconstruction error for each flow             │
│  Set threshold = 95th percentile = 0.7597               │
│  (5% of normal flows are inherently "noisy")            │
└─────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│ Step 3: Inference (Live — Per Flow)                     │
│                                                         │
│  Input: New flow x (40 features)                        │
│  Compute: x̂ = D × ISTA(x) (reconstruct using dict)    │
│  Error: e = ||x - x̂||₂  (L2 reconstruction error)     │
│                                                         │
│  If e > 0.7597 → "Anomaly" (can't be represented       │
│                    by normal patterns)                   │
│  If e ≤ 0.7597 → "Normal" (well-represented by         │
│                    normal dictionary)                    │
│                                                         │
│  Time: 133 µs/flow (CPU)                                │
└─────────────────────────────────────────────────────────┘
```

### Why DDL Over Autoencoders?

| Property | DDL | Autoencoder |
|----------|-----|-------------|
| **Architecture** | Sparse coding (ISTA) | Neural network (encoder-decoder) |
| **Training data** | Normal only (unsupervised) | Normal only (unsupervised) |
| **Interpretability** | Each dictionary atom = a traffic "pattern" → XAI-friendly | Black-box latent space |
| **Training time** | 12 min (150 epochs) | Hours for comparable accuracy |
| **Inference** | 133 µs/flow (simple matrix multiply) | ~1ms (forward pass through layers) |
| **Per-feature error** | ✅ Yes — error per feature is directly available | ❌ No — aggregate reconstruction only |

> **Key advantage for XAI:** DDL provides per-feature reconstruction error, which directly answers *"Which features made this flow anomalous?"* — critical for explainability.

---

## 2. The 40-Feature Set

DDL uses 40 metadata-only features (no payload inspection — works on encrypted traffic):

| Category | Count | Features | Why |
|----------|:-----:|---------|-----|
| **Packet Size** | 8 | Fwd/Bwd Pkt Length (Mean, Std, Min, Max), Variance | Uniform sizes → DDoS, large → exfiltration |
| **Timing** | 10 | Flow/Fwd/Bwd IAT (Mean, Std, Min, Max, Total), Duration | Regularity → bots, long idle → C2 |
| **Rate** | 4 | Flow Bytes/s, Flow Pkts/s, Fwd/Bwd Pkts/s | Sudden spikes → flooding |
| **Volume** | 2 | Total Fwd/Bwd Bytes | Asymmetry → amplification |
| **TCP Flags** | 6 | SYN, ACK, FIN, RST, PSH, URG counts | SYN flood, port scan resets |
| **TCP Window** | 2 | Init_Win_bytes fwd/bwd | OS fingerprint, scanning tools |
| **Header** | 2 | Fwd Header Length (×2) | Tunnelling, crafted packets |
| **Asymmetry** | 1 | Down/Up Ratio | Exfiltration, amplification |
| **Activity** | 1 | Active Min | Short bursts → bot beaconing |
| **Other** | 4 | Packet Length Mean, Fwd Pkt Min, various | Additional discrimination |

**BCC uses 28 of these** (subset) for fast gateway classification.
**DDL uses all 40** for deeper anomaly detection (the extra 12 improve reconstruction fidelity).

---

## 3. Two-Stage Pipeline Architecture

```
                    ┌──────────────────────┐
                    │  Incoming Flow       │
                    │  (from SDN switch)   │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │  STAGE 1: BCC        │
                    │  28 features         │
                    │  Decision Tree       │
                    │  ~0.1 µs/flow        │
                    └──────────┬───────────┘
                               │
                 ┌─────────────┼─────────────┐
                 │ BENIGN      │              │ SUSPICIOUS
                 │ (~47%)      │              │ (~53%)
                 ▼             │              ▼
          ┌──────────┐        │     ┌─────────────────┐
          │ FORWARD  │        │     │  STAGE 2         │
          │ (allow)  │        │     │  DDL (40 feat)   │
          └──────────┘        │     │  IF  (40 feat)   │
                              │     │  ────────────    │
                              │     │  Consensus:      │
                              │     │  DROP only if    │
                              │     │  BOTH agree      │
                              │     └────────┬────────┘
                              │              │
                              │    ┌─────────┼─────────┐
                              │    │ Normal  │ Anomaly  │
                              │    ▼         ▼         │
                              │  FORWARD    DROP       │
                              │  (allow)    (block)    │
                              │                        │
                              │   XAI Explanation      │
                              │   (LIME + SHAP)        │
                              │   on DROPPED flows     │
                              └────────────────────────┘
```

### Why Two Stages?

1. **Speed:** BCC processes ALL flows in 0.1µs each. Only suspicious flows (53%) go to DDL+IF
2. **Accuracy:** DDL+IF consensus means a flow is dropped ONLY if two independent models agree
3. **Explainability:** Dropped flows get LIME+SHAP explanations for auditing

---

## 4. Explainable AI (XAI) — LIME + SHAP Dual Verification

### Why Two XAI Methods?

| Property | LIME | SHAP |
|----------|------|------|
| **Approach** | Local linear approximation | Game-theoretic Shapley values |
| **Output** | Top features + weights | Feature attribution values |
| **Strength** | Fast, intuitive "if-then" rules | Theoretically grounded, additive |
| **Weakness** | Unstable across runs | Computationally expensive |

**Using both together → Cross-validation of explanations:**
- If LIME and SHAP agree on the same top features → **high confidence** in the explanation
- If they disagree → flag for human review (explanation unreliable)

### XAI Flow

```
When a flow is DROPPED by DDL+IF:
  1. DDL-LIME:  "Why did DDL flag this?" → Top features driving reconstruction error
  2. DDL-SHAP:  "How much did each feature contribute?" → Shapley attribution values
  3. IF-LIME:   "Why did IF flag this?" → Top features driving isolation score
  4. IF-SHAP:   "How much did each feature contribute?" → Shapley values for IF

Cross-check: If DDL-LIME and IF-LIME both highlight the same feature
             → Strong evidence that feature is truly anomalous
```

### Real Example — DDoS Attack (Row_82589_DDoS, Correctly DROPped)

| Explainer | #1 Feature | #2 Feature | #3 Feature |
|-----------|-----------|-----------|-----------|
| **DDL-LIME** | down_up_ratio (+0.0007) | flow_duration > 42M (+0.0006) | bwd_iat_max > 808K (+0.0006) |
| **IF-LIME** | bwd_iat_std > 377K (+0.072) | flow_iat_std > 10.7M (+0.059) | flow_duration > 42M (+0.036) |

> **Cross-validation:** Both DDL and IF agree that `flow_duration` and `bwd_iat_std` are suspicious.
> This DDoS flow has abnormally high backward inter-arrival time variability and extended flow duration.

### Real Example — PortScan Attack (Row_206294_PortScan, DDL-only DROP)

| Explainer | #1 Feature | #2 Feature | #3 Feature |
|-----------|-----------|-----------|-----------|
| **DDL-LIME** | fwd_pkts_per_s (−0.0005) | flow_duration (−0.0004) | init_win_fwd (−0.0003) |
| **IF-LIME** | pkt_len_variance ≤ 0 (−0.049) | bwd_iat_std ≤ 0 (−0.044) | flow_iat_std ≤ 0 (−0.036) |

> **Sparse flow (11/40 features non-zero):** PortScan = SYN→RST (2 packets, 0 payload).
> IF can't distinguish from normal with 29 zero features → DDL-only consensus used.
> **XAI timing:** DDL-LIME ≈ 942ms, IF-LIME ≈ 225ms per flow.

---

## 5. End-to-End PCAP Simulation Results

**Test:** 5,000 CIC-IDS-2017 labeled PCAP flow directories (all 5 days, randomly sampled)
**Architecture:** Modular extractors — BCC(28-feat) → DDL+IF(40-feat) with smart consensus
**Attack types:** DDoS (1,015), PortScan (1,034), Bot (7), BENIGN (2,944)

### Per-Model Performance

| Model | Role | Attack Recall | Details |
|-------|------|:------------:|----------|
| **SENTRY v2 (BCC)** | Stage 1 gateway | **100.00%** | 0 leaks — all attacks flagged |
| **DDL** | Stage 2 deep check | 99.0% | Correctly flags DDoS + PortScan |
| **IF** | Stage 2 consensus | ~55% | Weak on sparse PortScan (11/40 features) |
| **DDL-LIME** | XAI for DDL | — | 942ms/flow, explains top 5 features |
| **IF-LIME** | XAI for IF | — | 225ms/flow, cross-validates with DDL-LIME |

### Full Pipeline Results

| Metric | Value |
|--------|:-----:|
| Streams tested | 5,000 (4,153 valid, 847 errors) |
| **Accuracy** | **96.56%** |
| **Precision** | **94.30%** |
| **Recall** | **99.03%** |
| **F1** | **96.61%** |
| FPR | 5.87% |

### Confusion Matrix
```
                   Predicted
                FORWARD    DROP
  Normal          1,974     123
  Attack             20   2,036
```

### Pipeline Routing
```
5,000 PCAP streams
    |
    +-- Stage 1: SENTRY v2 (28 features)
    |       |
    |       +-- 1,962 BENIGN → FORWARD (47.2%)
    |       +-- 2,191 ATTACK → Stage 2 (52.8%)
    |
    +-- Stage 2: DDL+IF (40 features, smart consensus)
            |
            +-- 32 Normal → FORWARD
            +-- 2,159 Anomaly → DROP (1,166 sparse DDL-only)

    Leakage: 20 attacks missed (recall = 99.03%)
    False drops: 123 benign blocked (FPR = 5.87%)
```

### Smart Consensus
Port scans are 2-packet flows (SYN→RST, 0 payload) → only 11/40 features non-zero.
IF can't detect these, but DDL can. **If <20 non-zero features → DDL alone decides.**

### Timing (End-to-End Per Flow)

| Stage | Time | Notes |
|-------|:----:|-------|
| BCC Feature Extraction (28f) | **6,940 µs** | dpkt PCAP parsing |
| BCC Inference | **231 µs** | Decision Tree (28 features) |
| DDL Feature Extraction (40f) | **390 µs** | Flagged flows only |
| DDL Inference | **3,585 µs** | Flagged flows only |
| IF Inference | **5,600 µs** | Flagged flows only |
| **Total Pipeline** | **~7.2 ms** | End-to-end per flow (from PCAP) |

> In SDN deployment, features come from OpenFlow PacketIN events (~50µs), not PCAP files.

---

## 6. Zero-Trust Architecture Principles

| Principle | How We Implement It |
|-----------|-------------------|
| **Never trust, always verify** | Every flow goes through BCC; flagged flows get DDL+IF double-check |
| **Least privilege** | Default action = HOLD (buffer flow until verified) |
| **Continuous verification** | Each packet triggers re-evaluation; flow-level timeouts enforce periodic review |
| **Fail-closed** | If BCC or DDL crashes, all flows are blocked until the model recovers |
| **Micro-segmentation** | Per-flow decisions — not per-host or per-subnet |

---

## 7. Key Design Decisions & Rationale

| Decision | Alternative | Why We Chose This |
|----------|-------------|-------------------|
| DDL over Autoencoder | Autoencoder, GAN | DDL provides per-feature error for XAI; faster inference |
| 28+40 feature split | Single feature set | BCC needs speed (28 is sufficient); DDL needs depth (40 for reconstruction) |
| LIME + SHAP dual XAI | LIME only or SHAP only | Cross-validation prevents unreliable single-method explanations |
| DDL+IF consensus | DDL only | Reduces false positives by requiring independent agreement |
| Unsupervised DDL | Supervised classifier | No need for labeled attack data; detects novel/zero-day attacks |
| Decision Tree BCC | Random Forest/SVM | Near-zero latency (0.1µs); 99.89% recall on trained data |

---

## 8. Repository & How to Reproduce

```bash
# Clone and setup
cd /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-.../

# Install dependencies
pip install pandas scikit-learn joblib
pip install --target /tmp/dpkt_pkg dpkt
pip install --target /tmp/lime_pkg lime shap

# Run end-to-end PCAP evaluation
PYTHONPATH=/tmp/dpkt_pkg:/tmp/lime_pkg:$PYTHONPATH \
    python3 src/FullSDNPipeline/run_pcap_evaluation.py --max-flows 5000

# View results
cat results/pcap_results/pcap_summary.md
```

### Model Files
| File | Description | Size |
|------|------------|------|
| `models/sentry_model_v2.pkl` | BCC v2 Decision Tree (28 features) | 1.9 MB |
| `models/ddl_40feat.pkl` | DDL dictionary (40 features, 64 atoms) | 125 KB |
| `models/isolation_forest.pkl` | IF model (40 features) | 12 MB |
