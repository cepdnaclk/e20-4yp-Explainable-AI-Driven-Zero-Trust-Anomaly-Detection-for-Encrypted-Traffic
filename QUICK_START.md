# QUICK START — Zero-Trust XAI Anomaly Detection
**University of Peradeniya | e20420Janith**

> **Use this file tomorrow morning.** Follow the numbered steps in order.
> Full details are in the linked guides if anything goes wrong.

---

## Pipeline in One Line

```
Switch mirror port → NFStream → DT (Stage 1) → [SDN Buffer] → DDL+XAI (Stage 2) → DROP/FORWARD
```

---

## Step 0 — Navigate & Activate Environment

Every terminal you open must start with these two commands:

```bash
cd /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/

source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate
```

---

## Step 1 — Train the DDL Model

> **Do this on the server tonight or early tomorrow.** Takes ~30 min (GPU) or ~9 hr (CPU).

### Option A — GPU via Apptainer (recommended, ~30 min)

```bash
# Check which GPU has the most free memory first:
nvidia-smi --query-gpu=index,memory.free,memory.total --format=csv,noheader

# Ensure the models output directory exists:
mkdir -p models

# Run training inside the PyTorch container (GPU 1 typically most free):
# --bind makes /scratch1 visible inside the container
# --env PYTHONPATH points to the libs installed for the container's Python
apptainer exec --nv \
    --bind /scratch1:/scratch1 \
    --env PYTHONPATH=/scratch1/e20-fyp-xai-anomaly-detection/container_libs \
    /scratch1/e20-fyp-xai-anomaly-detection/pytorch_2.4.0-cuda12.4-cudnn9-runtime.sif \
    python DDLModel/train_ddl_enhanced.py \
        --train dataset/TRAIN_Traffic.csv \
        --test  dataset/TEST_Traffic.csv \
        --epochs 150 --gpu --batch-size 512 \
        2>&1 | tee models/training_log_gpu.txt

# Monitor progress in another terminal:
tail -f models/training_log_gpu.txt
```

### Option B — CPU (background, no Apptainer needed)

```bash
mkdir -p models

nohup python DDLModel/train_ddl_enhanced.py \
    --train dataset/TRAIN_Traffic.csv \
    --test  dataset/TEST_Traffic.csv \
    --epochs 150 \
    > models/training_log.txt 2>&1 &

echo "Training PID: $!"
tail -f models/training_log.txt
```

### Option C — Quick Debug Run (~10 min CPU, reduced data)

```bash
python DDLModel/train_ddl_enhanced.py \
    --train dataset/TRAIN_Traffic.csv \
    --test  dataset/TEST_Traffic.csv \
    --epochs 30 --max-train-rows 50000
```

---

## Step 2 — Verify Models Exist

```bash
ls -lh models/
# Must see: ddl_30feat.pkl  isolation_forest.pkl  train_report.json

# View accuracy metrics:
python -c "
import json; r = json.load(open('models/train_report.json'))
m = r['test_metrics']
print(f'F1={m[\"f1\"]:.3f}  Precision={m[\"precision\"]:.3f}  Recall={m[\"recall\"]:.3f}')
print(f'Threshold={r[\"training\"][\"threshold_learned\"]:.4f}')
"
```

---

## Step 3 — Configure the Switch (do before demo)

**Cisco IOS — connect via console/SSH:**
```
enable
configure terminal
monitor session 1 source interface GigabitEthernet0/1 both
monitor session 1 source interface GigabitEthernet0/2 both
monitor session 1 destination interface GigabitEthernet0/3
end
write memory
show monitor session 1
```

**HP ProCurve:**
```
configure
mirror 1 port 3
interface 1
  monitor all both mirror 1
interface 2
  monitor all both mirror 1
write memory
```

> Port 3 (or the last port) is the SPAN destination — connect your capture laptop here.
> Full details: `LiveTraffic/SWITCH_SETUP_GUIDE.md`

---

## Step 4 — Prepare the Capture Laptop (Pipeline Machine)

Run these on the machine physically connected to the switch SPAN port:

```bash
# Find which NIC is connected to the mirror port:
ip link show

# Enable promiscuous mode (replace eth1 with your actual NIC name):
sudo ip link set eth1 promisc on

# Test that mirrored traffic is visible:
sudo tcpdump -i eth1 -n -c 10
# You should see packets from the source ports — even traffic not destined for you
```

---

## Step 5 — Run the Live Pipeline

Open **3 terminals** on the pipeline machine. Run each in parallel:

**Terminal 1 — REST API** (optional, needed for dashboard):
```bash
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate
cd /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/
python EnhancedPipeline/rest_api.py --port 5001
```

**Terminal 2 — Streamlit Dashboard** (opens in browser):
```bash
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate
cd /scratch1/.../
streamlit run EnhancedPipeline/dashboard.py
# → Open http://localhost:8501
```

**Terminal 3 — Live Capture** (main pipeline, captures from switch mirror):
```bash
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate
cd /scratch1/.../

python LiveTraffic/live_pipeline.py \
    --interface eth1 \
    --ddl_model models/ddl_30feat.pkl \
    --duration 600 \
    --log_path logs/live_$(date +%Y%m%d_%H%M).json
```

---

## Step 6 — Inject Demo Traffic (from a second machine or second NIC)

Normal traffic (should FORWARD — shows threshold not too aggressive):
```bash
python LiveTraffic/traffic_generator.py --mode normal --count 30 --output /tmp/demo_normal.pcap
sudo tcpreplay -i eth0 --mbps=5 /tmp/demo_normal.pcap
```

Attack traffic (should DROP with XAI explanation):
```bash
python LiveTraffic/traffic_generator.py --mode attack --count 20 --output /tmp/demo_attack.pcap
sudo tcpreplay -i eth0 --mbps=5 /tmp/demo_attack.pcap
```

Or replay the real CIC-IDS-2017 Friday PCAP (contains real DDoS):
```bash
sudo tcpreplay -i eth0 --mbps=10 \
    /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Friday-WorkingHours.pcap
```

---

## Step 7 — Test Against Labeled PCAPs (accuracy evaluation)

After training, run this to get per-attack-type F1/Precision/Recall:

```bash
python LiveTraffic/pcap_replay_pipeline.py \
    --mode labeled \
    --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \
    --ddl-model models/ddl_30feat.pkl \
    --output logs/accuracy_friday.json \
    --max-files 1000

# View results:
python -c "
import json; r = json.load(open('logs/accuracy_friday.json'))
o = r['overall']
print(f'Overall  F1={o[\"f1\"]:.3f}  Acc={o[\"accuracy\"]:.3f}')
for label, v in r['per_label'].items():
    print(f'  {label:15s}  F1={v[\"f1\"]:.3f}')
"
```

---

## No-Hardware Fallback (if switch not available)

Software demo — no hardware needed, runs instantly:

```bash
# Demo mode (synthetic flows, 20% simulated attacks):
python LiveTraffic/live_pipeline.py --demo --duration 60

# Full enhanced pipeline demo (DDL + IF + XAI):
python EnhancedPipeline/enhanced_pipeline.py --demo --n_flows 10
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `models/ddl_30feat.pkl not found` | Run Step 1 first |
| `CUDA not available` in Apptainer | Check `--nv` flag is present |
| `NFStream: 0 flows captured` | `sudo ip link set eth1 promisc on` |
| tcpdump shows no packets on mirror port | Verify `show monitor session 1` on switch |
| GPU memory full during training | Use GPU 1 or 2 (check via `nvidia-smi`) |
| SHAP very slow | Add `--no_shap` to live_pipeline.py command |
| `ModuleNotFoundError` | Activate venv first |

---

## Quick Latency Reference

| Stage | Typical latency | Applies to |
|-------|----------------|-----------|
| DT (Stage 1) | < 1 ms | All flows |
| DDL (Stage 2) | ~45 ms | Flagged flows only (~10-15%) |
| XAI native | ~5 ms | Anomalous flows only |
| XAI SHAP | ~220 ms | Optional |

---

*For the full demo script with talking points: `DemonstrationPlan.md`*
*For switch hardware commands in detail: `LiveTraffic/SWITCH_SETUP_GUIDE.md`*
*For training options in full: `docs/REPRODUCTION_GUIDE.md`*
