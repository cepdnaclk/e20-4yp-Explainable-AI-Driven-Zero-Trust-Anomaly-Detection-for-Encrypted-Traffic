# Workplan — Zero-Trust XAI Anomaly Detection
**Last updated:** 2026-03-06 Session 4

---

## Session 4 — BCC v2 Integration & Full SDN Pipeline (Current)

### Completed
- [x] **BCC v2 Integration:** Copied `feature_extractor_v2.py` (28-feat DPKT extractor) and `sentry_model_v2.pkl` from e20449Sandaru's folder
- [x] **FullSDNPipeline/ directory:** Created complete new pipeline:
  - `sdn_pipeline.py` — Single unified SDN pipeline script (PacketIN → BCC → Buffer → DDL+XAI → FORWARD/DROP + switch rules)
  - `unified_feature_extractor.py` — Shared feature extraction (extracts once, slices for BCC-28 and DDL-30)
  - `packet_shooter.py` — PCAP replay with real timing (reads timestamps from PCAP headers, sorts chronologically, rate-multiplier support)
  - `run_demo.sh` — One-command launcher (demo/friday/tuesday/realtime modes)
- [x] **Documentation rewrite:**
  - `QUICK_START.md` — Step-by-step demo guide with FullSDNPipeline commands
  - `README.md` — Correct pipeline diagram, repo layout, quickstart
  - `PIPELINE_GUIDE.md` — Full architecture with feature tables, decision logic, training commands
  - `DemonstrationPlan.md` — Demo day script with 4-terminal layout, talking points, hardware setup

### Pending
- [ ] Train DDL model on GPU (if not done)
- [ ] Run FullSDNPipeline on Friday PCAPs and verify accuracy
- [ ] Git commit all Session 4 changes

---

## Session 3 — DDL Enhancement & Docs (Previous)

- [x] DDL flow-level analysis (confirmed, not per-packet)
- [x] GPU support: `ddl_model.py` uses PyTorch CUDA backend
- [x] `train_ddl_enhanced.py` with `--gpu` flag
- [x] SDN buffer v2 with OpenFlow rule push
- [x] REPRODUCTION_GUIDE.md, LIVE_TRAFFIC_GUIDE.md
- [x] Cisco/HP switch configs with DemonstrationPlan

---

## Session 2 — Core Implementation (Previous)

- [x] Created EnhancedPipeline files (config, pipeline, features, REST, dashboard)
- [x] Created LiveTraffic scripts (traffic gen, switch guides)
- [x] DDL training script with 30-feature CSV mapping
- [x] Dataset copied (TRAIN_Traffic.csv, TEST_Traffic.csv)

---

## Quick Command Reference

```bash
# ── Setup ──
cd /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate

# ── Train DDL (GPU, Apptainer) ──
apptainer exec --nv \
    /scratch1/e20-fyp-xai-anomaly-detection/pytorch_2.4.0-cuda12.4-cudnn9-runtime.sif \
    python DDLModel/train_ddl_enhanced.py \
        --train dataset/TRAIN_Traffic.csv --test dataset/TEST_Traffic.csv \
        --epochs 150 --gpu --batch-size 512

# ── Full Pipeline Demo ──
python FullSDNPipeline/sdn_pipeline.py --demo
python FullSDNPipeline/sdn_pipeline.py --pcap-dir .../Labeled/Friday --limit 500

# ── Packet Shooter ──
python FullSDNPipeline/packet_shooter.py --pcap-dir .../Labeled/Friday --rate-multiplier 1.0

# ── One-command Demo ──
bash FullSDNPipeline/run_demo.sh demo
bash FullSDNPipeline/run_demo.sh friday
```
