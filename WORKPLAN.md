# WORKPLAN.md — Zero-Trust Anomaly Detection Pipeline

> **HOW TO RESUME:** Read `QUICK_START.md` first — it covers everything needed for the demo.
> Project root: `e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/`
> Dataset: `dataset/TRAIN_Traffic.csv` and `dataset/TEST_Traffic.csv`
> Hardware: **Cisco IOS switch** (primary) or **HP L3 switch** (backup); laptop wired to mirror port
> PyTorch container: `/scratch1/e20-fyp-xai-anomaly-detection/pytorch_2.4.0-cuda12.4-cudnn9-runtime.sif`

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

## SECTION 7 — Session 2 (2026-03-05) ✅ DONE

**Switch hardware clarified:** Cisco IOS (primary), HP ProCurve L3 (backup). Laptop wired to dedicated SPAN port.

### New Files Created
- ✅ `dataset/` — CIC-IDS-2017 CSV files copied from `CICDataset/Processed-Data/`
- ✅ `dataset/README.md` — dataset documentation and training commands
- ✅ `EnhancedPipeline/config.py` — centralized hyperparameter config
- ✅ `EnhancedPipeline/enhanced_pipeline.py` — main orchestrator (DDL + IF + DualXAI)
- ✅ `EnhancedPipeline/adaptive_features.py` — MI-based adaptive feature selector
- ✅ `EnhancedPipeline/rest_api.py` — FastAPI REST server
- ✅ `EnhancedPipeline/dashboard.py` — Streamlit real-time dashboard
- ✅ `EnhancedPipeline/docs/SWITCH_SETUP.md` — physical switch topology guide
- ✅ `LiveTraffic/traffic_generator.py` — normal/attack/borderline PCAP generator (scapy)
- ✅ `LiveTraffic/CISCO_SWITCH_SETUP.md` — Cisco IOS/IOS-XE SPAN config with full CLI
- ✅ `LiveTraffic/HP_SWITCH_SETUP.md` — HP ProCurve + Aruba mirroring CLI
- ✅ `DDLModel/train_ddl_enhanced.py` — 30-feature DDL training script (reads CIC-IDS-2017 CSV)
- ✅ `profiling/TIMING_GUIDE.md` — how to run benchmarks and interpret timing results
- ✅ `docs/FEATURE_ANALYSIS.md` — justification for 15 DT features vs 30 DDL features

### Remaining Steps
- [x] Run DDL training: `python DDLModel/train_ddl_enhanced.py --train dataset/TRAIN_Traffic.csv --test dataset/TEST_Traffic.csv`
- [x] Check `models/ddl_30feat.pkl` and `models/isolation_forest.pkl` generated
- [ ] Run test suite: `python -m tests.test_pipeline` (run before demo)
- [x] Commit session 2 work (commits 6–10)

---

## Quick Command Reference

```bash
# ── Setup ────────────────────────────────────────────────────────────
# Activate shared venv (from project root)
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate

# ── Training ─────────────────────────────────────────────────────────
# ⭐ GPU via Apptainer (~30 min) — RECOMMENDED:
apptainer exec --nv \
    /scratch1/e20-fyp-xai-anomaly-detection/pytorch_2.4.0-cuda12.4-cudnn9-runtime.sif \
    python DDLModel/train_ddl_enhanced.py \
        --train dataset/TRAIN_Traffic.csv \
        --test  dataset/TEST_Traffic.csv \
        --epochs 150 --gpu --batch-size 512

# CPU full training (~9 hours, background):
nohup python DDLModel/train_ddl_enhanced.py \
    --train dataset/TRAIN_Traffic.csv \
    --test  dataset/TEST_Traffic.csv \
    --epochs 150 > models/training_log.txt 2>&1 &

# Quick debug (CPU, ~10 min):
python DDLModel/train_ddl_enhanced.py \
    --train dataset/TRAIN_Traffic.csv \
    --test  dataset/TEST_Traffic.csv \
    --epochs 30 --max-train-rows 50000

# ── Testing ───────────────────────────────────────────────────────────
python -m tests.test_pipeline

# ── Demo traffic (from Laptop A — requires sudo for live send) ────────
python LiveTraffic/traffic_generator.py --mode normal --count 20 --output /tmp/demo_normal.pcap
python LiveTraffic/traffic_generator.py --mode attack --count 10 --output /tmp/demo_attack.pcap
python LiveTraffic/traffic_generator.py --mode borderline --count 5 --output /tmp/demo_borderline.pcap

# ── Live capture (on Laptop B, from switch mirror port) ─────────────
python LiveTraffic/live_pipeline.py --interface eth1 --duration 300

# ── Enhanced Pipeline demo mode (no hardware needed) ─────────────────
python EnhancedPipeline/enhanced_pipeline.py --demo --n_flows 10

# ── REST API ──────────────────────────────────────────────────────────
python EnhancedPipeline/rest_api.py --port 5001
curl http://localhost:5001/health                           # verify
curl http://localhost:5001/feature_names                   # see feature order

# ── Streamlit dashboard ────────────────────────────────────────────────
streamlit run EnhancedPipeline/dashboard.py

# ── Timing benchmark ──────────────────────────────────────────────────
python -m profiling.latency_benchmark --n_flows 200 --output profiling/results/demo/
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
## SECTION 8 — Session 3 (2026-03-05) ✅ DONE

### New Files Created
- ✅ `docs/DDL_XAI_INSIGHT.md` — 8-part technical insight (flow vs packet, ISTA math, XAI, SDN buffer)
- ✅ `DDLModel/ddl_model.py` — GPU CUDA backend via PyTorch (_sparse_code_gpu, use_gpu param)
- ✅ `DDLModel/train_ddl_enhanced.py` — --gpu flag, Apptainer-compatible
- ✅ `DDLModel/GPU_SETUP.md` — Apptainer SIF training guide + speed table
- ✅ `LiveTraffic/pcap_replay_pipeline.py` — labeled + fullday PCAP accuracy testing
- ✅ `SDNBuffer/sdn_buffer_v2.py` — OpenFlow rule push (Ryu REST API) + zero-trust auto-expire
- ✅ `docs/REPRODUCTION_GUIDE.md` — 12-step full reproduction guide
- ✅ `docs/LIVE_TRAFFIC_GUIDE.md` — 6 traffic methods with decision matrix
- ✅ `DemonstrationPlan.md` — Cisco/HP switch specifics, 4-terminal layout, talking points
- ✅ `QUICK_START.md` — one-page guide for demo day
- ✅ `README.md` — complete rewrite with correct pipeline diagram and Apptainer commands
- ✅ `PIPELINE_GUIDE.md` — corrected pipeline diagram, 30-feat DDL code, Apptainer training

### Remaining
- [ ] Run `python -m tests.test_pipeline` before demo
- [ ] GPU training via Apptainer (see QUICK_START.md Step 1)
- [ ] PCAP accuracy test: `python LiveTraffic/pcap_replay_pipeline.py --mode labeled ...`

---
*Last updated: 2026-03-05 (Session 3 — all docs corrected, QUICK_START.md created)*
