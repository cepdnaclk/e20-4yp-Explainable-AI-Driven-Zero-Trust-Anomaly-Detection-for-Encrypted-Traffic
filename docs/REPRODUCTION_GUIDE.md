# docs/REPRODUCTION_GUIDE.md — Complete Step-by-Step Reproducibility Guide
# Zero-Trust XAI Anomaly Detection | University of Peradeniya
# e20420Janith — Updated 2026-03-05

# Complete Reproduction Guide

This guide enables anyone to reproduce the full Zero-Trust XAI Anomaly
Detection system from scratch — from environment setup through live demo.

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Ubuntu / Linux | 20.04+ | Tested on the university server |
| Python | 3.9+ | `python3 --version` |
| pip | 23+ | `pip install --upgrade pip` |
| nfstream | latest | `pip install nfstream` |
| scapy | latest | `pip install scapy` (for traffic_generator.py) |
| NVIDIA GPU (optional) | RTX 6000 Ada | For accelerated training |
| Cisco/HP switch | any | For live capture demo |

---

## Step 1 — Clone the Repository

```bash
cd /scratch1/e20-fyp-xai-anomaly-detection/
git clone <repo-url> e20420Janith/
# OR (if already cloned):
cd e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/
git pull
```

## Step 2 — Create & Activate Python Virtual Environment

```bash
# From scratch1 root:
python3 -m venv .venv
source .venv/bin/activate

# Verify:
which python   # should show .venv/bin/python
python --version
```

## Step 3 — Install Python Dependencies

```bash
# Core dependencies:
pip install --upgrade pip
pip install \
    numpy pandas scikit-learn joblib \
    nfstream scapy \
    fastapi uvicorn pydantic \
    streamlit plotly requests \
    shap lime \
    matplotlib seaborn

# Optional: GPU support (requires CUDA 12.4 — see DDLModel/GPU_SETUP.md):
pip install torch --index-url https://download.pytorch.org/whl/cu124

# Verify nfstream works:
python -c "import nfstream; print('nfstream OK:', nfstream.__version__)"

# Verify GPU (if installed):
python -c "import torch; print('CUDA available:', torch.cuda.is_available())"
```

## Step 4 — Prepare Datasets

### 4a. CSV Dataset (for DDL model training)

```bash
# Verify CSV files exist:
ls dataset/
# Should show: TRAIN_Traffic.csv  TEST_Traffic.csv  CLEANED_Combined_Traffic.csv  README.md

# If missing, copy from source:
cp /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/Processed-Data/TRAIN_Traffic.csv dataset/
cp /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/Processed-Data/TEST_Traffic.csv  dataset/
```

### 4b. PCAP Dataset (for live simulation testing)

The original full-day PCAPs and labeled per-flow PCAPs are in the shared folder.
There is no need to copy them — refer by absolute path:

```bash
# Full-day PCAPs (real-world simulation):
ls /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/
# Monday-WorkingHours.pcap  Tuesday-WorkingHours.pcap  ...  Friday-WorkingHours.pcap

# Per-flow labeled PCAPs (accuracy testing):
ls /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/
# Friday/  Monday/  Thursday/  Tuesday/  Wednesday/
# Each contains: Row_X_BENIGN, Row_X_DDoS, Row_X_PortScan, Row_X_Bot folders
```

---

## Step 5 — Train the DDL Model

### Option A: CPU Training (always works, ~9 hours for full dataset)

```bash
# From project root (inside venv):
python DDLModel/train_ddl_enhanced.py \
    --train dataset/TRAIN_Traffic.csv \
    --test  dataset/TEST_Traffic.csv \
    --ddl-output models/ddl_40feat.pkl \
    --if-output  models/isolation_forest.pkl \
    --epochs 150 \
    --atoms-l1 64 --atoms-l2 128

# Run in background (nohup):
nohup python DDLModel/train_ddl_enhanced.py \
    --train dataset/TRAIN_Traffic.csv \
    --test  dataset/TEST_Traffic.csv \
    --epochs 150 > models/training_log.txt 2>&1 &
echo "Training PID: $!"

# Monitor:
tail -f models/training_log.txt
```

### Option B: GPU Training (~20-40 minutes on RTX 6000)

```bash
# Verify GPU is available first:
nvidia-smi
python -c "import torch; print(torch.cuda.is_available())"   # must be True

# GPU training with larger batch size for efficiency:
nohup python DDLModel/train_ddl_enhanced.py \
    --train dataset/TRAIN_Traffic.csv \
    --test  dataset/TEST_Traffic.csv \
    --epochs 150 \
    --gpu --batch-size 512 \
    > models/training_log_gpu.txt 2>&1 &
echo "GPU Training PID: $!"
```

### Option C: Quick Debug Run (~5-10 minutes, CPU)

```bash
python DDLModel/train_ddl_enhanced.py \
    --train dataset/TRAIN_Traffic.csv \
    --test  dataset/TEST_Traffic.csv \
    --epochs 30 \
    --max-train-rows 50000 \
    --max-test-rows  10000
```

### Verify Training Output

```bash
ls -lh models/
# Should show: ddl_40feat.pkl  isolation_forest.pkl  train_report.json  training_log.txt

# View metrics:
python -c "import json; r=json.load(open('models/train_report.json')); \
           m=r['test_metrics']; print(f'F1={m[\"f1\"]}  Prec={m[\"precision\"]}  Rec={m[\"recall\"]}')"
```

---

## Step 6 — Run the Existing Test Suite

```bash
# Run all pipeline tests (uses synthetic data, no models required):
python -m tests.test_pipeline

# Expected: All tests pass (or warnings about missing models)
```

---

## Step 7 — Evaluate Against PCAP Dataset

### Option A: Per-Flow Accuracy (Labeled PCAPs)

Tests DDL accuracy using ground-truth labels from CIC-IDS-2017:

```bash
# Friday dataset (122k flows, ~DDoS/Bot/PortScan/BENIGN):
python LiveTraffic/pcap_replay_pipeline.py \
    --mode labeled \
    --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \
    --ddl-model models/ddl_40feat.pkl \
    --output logs/test_friday_labeled.json \
    --max-files 2000

# View results:
python -c "import json; r=json.load(open('logs/test_friday_labeled.json')); \
           o=r['overall']; print('F1:', o['f1'], 'Acc:', o['accuracy']); \
           [print(f'  {k}: F1={v[\"f1\"]}') for k,v in r['per_label'].items()]"
```

### Option B: Real-World Simulation (Full-Day PCAP)

Simulates how the pipeline performs on continuous mixed traffic:

```bash
# Friday (contains DDoS from 10:02-11:15 + Bot + PortScan):
python LiveTraffic/pcap_replay_pipeline.py \
    --mode fullday \
    --pcap-file /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Friday-WorkingHours.pcap \
    --ddl-model models/ddl_40feat.pkl \
    --output logs/test_friday_fullday.json

# Monday (all BENIGN — should get 0% false positives from DDL):
python LiveTraffic/pcap_replay_pipeline.py \
    --mode fullday \
    --pcap-file /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Monday-WorkingHours.pcap \
    --ddl-model models/ddl_40feat.pkl \
    --output logs/test_monday_benign.json
```

---

## Step 8 — Run the Enhanced Pipeline (Demo Mode)

Test the full cascade pipeline WITHOUT any physical hardware:

```bash
# Demo mode — synthetic flows, 20% simulated attacks:
python LiveTraffic/live_pipeline.py --demo --duration 60

# Expected output:
#   Flows seen:   120
#   DDL normal:    96 (80.0%) → FORWARD
#   DDL anomaly:   24 (20.0%) → DROP
#   Avg DDL latency: ~45ms
```

```bash
# Enhanced Pipeline demo (DDL + IF + DualXAI):
python EnhancedPipeline/enhanced_pipeline.py --demo --n_flows 10
```

---

## Step 9 — Start REST API + Dashboard

```bash
# Terminal 1 — REST API:
python EnhancedPipeline/rest_api.py --port 5001

# Verify it's running:
curl http://localhost:5001/health
# → {"status": "ok", "version": "1.0"}

# Terminal 2 — Streamlit Dashboard:
streamlit run EnhancedPipeline/dashboard.py
# → Opens browser at http://localhost:8501

# The dashboard connects to the REST API automatically
```

---

## Step 10 — Live Traffic with Physical Switch

See the full guide in **`docs/LIVE_TRAFFIC_GUIDE.md`** and the switch-specific
guides in `LiveTraffic/CISCO_SWITCH_SETUP.md` or `LiveTraffic/HP_SWITCH_SETUP.md`.

Quick checklist:
```bash
# 1. Configure SPAN on switch (as per switch-specific guide)

# 2. Enable promiscuous mode on mirror NIC:
sudo ip link set eth1 promisc on

# 3. Verify capture:
sudo tcpdump -i eth1 -n -c 10

# 4. Start live pipeline:
python LiveTraffic/live_pipeline.py \
    --interface eth1 \
    --ddl_model models/ddl_40feat.pkl \
    --duration 300
```

---

## Step 11 — Generate & Inject Demo Traffic

From a second machine (or another terminal with loopback):

```bash
# Activate venv:
source .venv/bin/activate

# Save attack PCAP (no root needed):
python LiveTraffic/traffic_generator.py --mode attack --count 20 --output /tmp/demo_attack.pcap
python LiveTraffic/traffic_generator.py --mode normal --count 30 --output /tmp/demo_normal.pcap

# View in Wireshark:
wireshark /tmp/demo_attack.pcap &

# Replay on wire (root needed for live injection):
sudo tcpreplay -i eth0 --mbps=10 /tmp/demo_attack.pcap
```

---

## Step 12 — Run Timing Benchmark

```bash
# Generate timing report (200 synthetic flows):
python -m profiling.latency_benchmark \
    --n_flows 200 \
    --output profiling/results/demo/

# View charts:
ls profiling/results/demo/
# latency_cdf.png  per_stage_box.png  timing_summary.json

# View numbers:
cat profiling/results/demo/timing_summary.json
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `nfstream not installed` | `pip install nfstream` |
| `torch not installed` | `pip install torch --index-url https://download.pytorch.org/whl/cu124` |
| `models/ddl_40feat.pkl not found` | Run Step 5 first |
| NFStream sees 0 flows on live interface | `sudo ip link set <iface> promisc on` |
| `Operation not permitted` on tcpdump | Use `sudo` or run as root |
| GPU training: `CUDA out of memory` | Reduce `--batch-size` to 128 or 256 |
| Training very slow | Adding `--gpu` flag (see GPU_SETUP.md) reduces from 9hr → ~30min |
| `train_report.json` shows low F1 | Try `calibrate_threshold()` — run more epochs (200+) |

---

## Expected Results (CIC-IDS-2017, 150 epochs)

| Metric | Expected Value |
|--------|---------------|
| DDL F1 (overall) | 0.87–0.92 |
| DDL Precision | 0.85–0.93 |
| DDL Recall | 0.88–0.95 |
| DDoS F1 | 0.91–0.96 |
| PortScan F1 | 0.85–0.90 |
| Bot F1 | 0.80–0.88 |
| BENIGN accuracy | 0.93–0.97 |
| DDL latency p50 | ~45ms |
| DDL latency p95 | ~90ms |
| With SHAP p95 | ~500ms |
