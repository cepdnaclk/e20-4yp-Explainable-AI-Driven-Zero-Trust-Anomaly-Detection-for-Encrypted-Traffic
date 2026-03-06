# QUICK START — Zero-Trust XAI Anomaly Detection
**University of Peradeniya | e20420Janith**

> **Use this file.** Follow the numbered steps in order.

---

## Pipeline in One Diagram

```
Switch SPAN mirror port
   |
   v
PacketIN (per-flow PCAP)
   |
   +-- Unified Feature Extraction (DPKT, one pass)
          |
          +-- 28 features --> Stage 1: BCC v2 (Decision Tree)
          |                      |
          |                   BENIGN -> packetStreamOUT + ALLOW rule
          |                   ATTACK -> hold in SDN Buffer
          |                              |
          +-- 40 features --> Stage 2: DDL + IF + XAI
                                 |
                              Normal  -> packetStreamOUT + ALLOW rule
                              Anomaly -> DROP rule + XAI explanation
```

**Key:** Features are extracted ONCE and shared between both models.

---

## Prerequisites

```bash
# If dpkt is not installed (needed for PCAP feature extraction):
pip install dpkt
# Or in Apptainer:
apptainer exec --nv .../pytorch_2.4.0-cuda12.4-cudnn9-runtime.sif pip install dpkt
```

---

## Step 0 — Navigate & Activate

```bash
cd /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate
```

---

## Step 1 — Train the DDL Model (40 features)

### Option A — GPU via Apptainer (~30 min)

```bash
nvidia-smi --query-gpu=index,memory.free --format=csv,noheader

apptainer exec --nv \
    /scratch1/e20-fyp-xai-anomaly-detection/pytorch_2.4.0-cuda12.4-cudnn9-runtime.sif \
    python DDLModel/train_ddl_enhanced.py \
        --train dataset/TRAIN_Traffic.csv \
        --test  dataset/TEST_Traffic.csv \
        --epochs 150 --gpu --batch-size 512 \
        2>&1 | tee models/training_log_gpu.txt
```

### Option B — CPU (~9 hours, background)

```bash
nohup python DDLModel/train_ddl_enhanced.py \
    --train dataset/TRAIN_Traffic.csv \
    --test  dataset/TEST_Traffic.csv \
    --epochs 150 > models/training_log.txt 2>&1 &
```

### Option C — Quick debug (CPU, ~10 min)

```bash
python DDLModel/train_ddl_enhanced.py \
    --train dataset/TRAIN_Traffic.csv \
    --test  dataset/TEST_Traffic.csv \
    --epochs 30 --max-train-rows 50000
```

---

## Step 2 — Verify Models

```bash
ls -lh models/
# Must see:
#   sentry_model_v2.pkl       (BCC v2 — 28-feat DT, from Sandaru)
#   ddl_40feat.pkl            (DDL — 40-feat, from Step 1)
#   isolation_forest.pkl      (IF  — from Step 1)
```

---

## Step 3 — Run the Full SDN Pipeline

### Demo mode (no hardware, no PCAPs needed)

```bash
python FullSDNPipeline/sdn_pipeline.py --demo --n-flows 30
```

### Against real CIC-IDS-2017 labeled PCAPs

```bash
python FullSDNPipeline/sdn_pipeline.py \
    --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \
    --limit 500 \
    --output logs/friday_results.json
```

### One-command demo (includes venv + model checks)

```bash
bash FullSDNPipeline/run_demo.sh demo      # synthetic flows
bash FullSDNPipeline/run_demo.sh friday     # Friday PCAPs, max speed
bash FullSDNPipeline/run_demo.sh realtime   # Friday PCAPs, real timing
```

---

## Step 4 — Packet Shooter (Real Timing Replay)

```bash
python FullSDNPipeline/packet_shooter.py \
    --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \
    --rate-multiplier 1.0 \
    --limit 500

# 10x faster:
python FullSDNPipeline/packet_shooter.py \
    --pcap-dir .../Labeled/Friday --rate-multiplier 10.0

# Max speed (no delays):
python FullSDNPipeline/packet_shooter.py \
    --pcap-dir .../Labeled/Friday --rate-multiplier 0
```

---

## Step 5 — Configure Switch (for live demo)

**Cisco IOS:**
```
enable
configure terminal
monitor session 1 source interface GigabitEthernet0/1 both
monitor session 1 destination interface GigabitEthernet0/3
end
write memory
```

**HP ProCurve:**
```
configure
mirror 1 port 3
interface 1
  monitor all both mirror 1
write memory
```

Then on the capture laptop:
```bash
sudo ip link set eth1 promisc on
sudo tcpdump -i eth1 -n -c 10
```

---

## Step 6 — Live Traffic Capture

```bash
python LiveTraffic/live_pipeline.py \
    --interface eth1 \
    --ddl_model models/ddl_40feat.pkl \
    --duration 600
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `models/ddl_40feat.pkl not found` | Run Step 1 |
| `models/sentry_model_v2.pkl not found` | Already copied — check models/ |
| `dpkt not installed` | `pip install dpkt` |
| `NFStream: 0 flows` | `sudo ip link set eth1 promisc on` |
| `CUDA not available` in Apptainer | Check `--nv` flag |
| GPU memory full | Use `nvidia-smi` to pick a free GPU |

---

## Quick Latency Reference

| Stage | Latency | Applies to |
|-------|---------|-----------| 
| Feature extraction (DPKT) | ~50 us | All flows |
| BCC v2 (DT, Stage 1) | ~50 us | All flows |
| DDL (Stage 2, 40 features) | ~45 ms | Flagged flows only |
| XAI native | ~5 ms | Anomalous flows only |

---

*Full architecture: `PIPELINE_GUIDE.md` | Demo script: `DemonstrationPlan.md` | Training: `docs/REPRODUCTION_GUIDE.md`*
