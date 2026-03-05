# WORKPLAN.md — Zero-Trust Anomaly Detection Pipeline

> **HOW TO RESUME:** Read this file first. Start from the first unchecked `[ ]` item.
> Project root: `e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/`

---

## Corrected Pipeline Architecture

```
Physical Switch (SPAN/mirror port)
   │
   ▼
[LIVE CAPTURE — NFStream promiscuous mode on mirror port]
   │
   ├──[15-feature extraction]──▶ BASE CHECK CLASSIFIER (teammate, DT)
   │                                      │
   │                            Normal ───┼──▶ FORWARD to switch
   │                            Anomaly ──┘──▶ SDN BUFFER
   │                                              │
   └──[30-feature extraction]──▶ DDL + XAI ◄────┘
                                      │
                               Normal ─┼──▶ Release buffer → FORWARD
                               Anomaly ─┘──▶ DROP + XAI explanation report
```

**Key principle:** DT and DDL use *different, purpose-built feature sets*.

---

## Status Legend
- ✅ Done  |  🔄 In progress  |  ⬜ Not started

---

## SECTION 1 — Research & Planning
- ✅ Read DDL model code (`DDLModel/ddl_model.py`)
- ✅ Read XAI explainer code (`XAIExplainer/explainer.py`)
- ✅ Read pipeline orchestrator (`ZeroTrustPipeline/pipeline.py`)
- ✅ Read PIPELINE_GUIDE.md
- ✅ Survey 40 research papers in `Research Papers/`
- ✅ Write implementation plan (user approved)

**Key findings from research papers:**
- *Detecting_Anomalies_in_Encrypted_Traffic_via_Deep_Dictionary_Learning.pdf* (Tariyal et al.): DDL works best with 30+ packet-level statistical features, NOT the same 15 flow-level DT features
- *Interpretable Anomaly Detection in Encrypted Traffic Using SHAP*: 78 NFStream features → top-30 by MI as optimal DDL input
- *Anomaly Detection in Imbalanced Encrypted Traffic*: Packet size distributions + timing features are most discriminative for encrypted traffic

---

## SECTION 2 — DDL Feature Expansion  ✅ DONE
- ✅ `DDLModel/ddl_feature_extractor.py` — 30-feature DDL-specific extractor
- ✅ `DDLModel/ddl_model.py` — refactored (n_features configurable, optional L3, F1-optimal threshold)
- ✅ `DDLModel/train_ddl_enhanced.py` — training script for 30-feature DDL
- ✅ `XAIExplainer/explainer.py` — dynamic feature names (not hardcoded to 15)
- ✅ `ZeroTrustPipeline/pipeline.py` — DDL stage now uses 30-feature extraction

---

## SECTION 3 — Timing Profiler  ✅ DONE
- ✅ `profiling/timing_profiler.py` — per-stage wall-clock timing with statistics
- ✅ `profiling/latency_benchmark.py` — N=500 flows, CDF + per-stage box plots

How to run:
```bash
python -m profiling.timing_profiler --mode pcap --input path/to/file.pcap
python -m profiling.latency_benchmark --n_flows 500 --output profiling/results/
```

---

## SECTION 4 — Live Traffic (Physical Switch)  ✅ DONE
- ✅ `LiveTraffic/SWITCH_SETUP_GUIDE.md` — SPAN port config (Cisco/HP/Aruba), promiscuous mode
- ✅ `LiveTraffic/live_pipeline.py` — NFStream live capture → ZeroTrust Pipeline
- ✅ `LiveTraffic/openflow_controller.py` — Ryu OpenFlow controller (DROP/FORWARD)
- ✅ `LiveTraffic/traffic_generator.py` — generates test attack + benign traffic for demo

---

## SECTION 5 — EnhancedPipeline  ✅ DONE
Better architecture proposal (separate folder, does not replace existing):
- ✅ `EnhancedPipeline/enhanced_pipeline.py` — DDL + Isolation Forest + SHAP+LIME
- ✅ `EnhancedPipeline/if_second_vote.py` — Isolation Forest second opinion
- ✅ `EnhancedPipeline/adaptive_features.py` — MI-based adaptive feature selection
- ✅ `EnhancedPipeline/dual_xai.py` — SHAP + LIME combined explanations
- ✅ `EnhancedPipeline/rest_api.py` — REST API for switch controller integration
- ✅ `EnhancedPipeline/dashboard.py` — Streamlit real-time monitoring dashboard
- ✅ `EnhancedPipeline/docs/ARCHITECTURE.md` — full design document
- ✅ `EnhancedPipeline/docs/TESTING_GUIDE.md` — testing with real + simulated traffic
- ✅ `EnhancedPipeline/docs/SWITCH_SETUP.md` — physical switch config guide

---

## SECTION 6 — Git Commits ✅
- ✅ Commit 1: WORKPLAN.md + DemonstrationPlan.md + DDL feature extractor
- ✅ Commit 2: Updated DDL model + pipeline
- ✅ Commit 3: Timing profiler + benchmark
- ✅ Commit 4: LiveTraffic setup + scripts
- ✅ Commit 5: EnhancedPipeline complete

---

## Quick Command Reference

```bash
# Activate venv
source .venv/bin/activate

# Run existing pipeline tests
python -m tests.test_pipeline

# Train enhanced DDL (30 features, requires CIC-IDS-2017 CSV)
python DDLModel/train_ddl_enhanced.py \
    --dataset path/to/cicids2017_benign.csv \
    --output models/ddl_30feat.pkl

# Run live traffic pipeline (physical switch mirror port)
python LiveTraffic/live_pipeline.py --interface eth1 --duration 300

# Run timing benchmark
python -m profiling.latency_benchmark --n_flows 500

# Start Enhanced Pipeline demo
python EnhancedPipeline/enhanced_pipeline.py --demo

# Start REST API server
python EnhancedPipeline/rest_api.py --port 5001

# Start Streamlit dashboard
streamlit run EnhancedPipeline/dashboard.py
```

---

## Feature Sets Summary

### DT Features (15) — Base Check Classifier [DO NOT MODIFY]
| # | Feature |
|---|---------|
| 1 | Packet Length Variance |
| 2 | Fwd Packet Length Max |
| 3 | Fwd Header Length |
| 4 | Init_Win_bytes_forward |
| 5 | Bwd Header Length |
| 6 | Total Length of Fwd Packets |
| 7 | Init_Win_bytes_backward |
| 8 | Bwd Packets/s |
| 9 | Flow IAT Min |
| 10 | Fwd IAT Min |
| 11 | Flow Bytes/s |
| 12 | Active Min |
| 13 | Bwd IAT Total |
| 14 | Flow IAT Max |
| 15 | Flow Duration |

### DDL Features (30) — Deep Analysis [Enhanced]
| Group | Features (6 each) |
|-------|-------------------|
| Packet Size | Fwd mean, std, min, max; Bwd mean, std |
| Packet Count | Fwd pkt max, Bwd pkt min; total pkts fwd/bwd; length variance fwd |
| IAT Timing | Fwd IAT mean, std, max; Bwd IAT mean, std, max |
| Byte Rates | Flow bytes/s, pkts/s; Fwd/Bwd rates; active mean |
| TCP Flags | SYN, ACK, FIN, RST count; PSH forward; URG count |
| Flow-Level | Duration, total bytes fwd/bwd; init window fwd/bwd; down/up ratio |

---
*Last updated: 2026-03-05 (Session 1)*
