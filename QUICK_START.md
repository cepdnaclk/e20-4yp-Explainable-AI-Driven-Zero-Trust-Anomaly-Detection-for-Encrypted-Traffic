# QUICK START — Zero-Trust XAI Anomaly Detection
**University of Peradeniya | e20420Janith**

> Copy-paste these commands. All tested and verified.

---

## Step 1: Navigate & Activate

```bash
cd /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate
mkdir -p models logs results
```

---

## Step 2: Train DDL + IF (only if models don't exist)

```bash
# Check if models exist:
ls -lh models/ddl_40feat.pkl models/isolation_forest.pkl

# If not, train (GPU, ~1h 45min):
apptainer exec --nv \
    /scratch1/e20-fyp-xai-anomaly-detection/pytorch_2.4.0-cuda12.4-cudnn9-runtime.sif \
    bash -c "pip install --quiet pandas scikit-learn joblib && \
    python DDLModel/train_ddl_enhanced.py \
        --train dataset/TRAIN_Traffic.csv \
        --test  dataset/TEST_Traffic.csv \
        --epochs 150 --gpu --batch-size 512" \
    2>&1 | tee models/training_log_gpu.txt
```

---

## Step 3: Run Full Evaluation (all models + XAI)

```bash
# This tests BCC, DDL, IF separately + full pipeline + XAI explanations
PYTHONPATH=/tmp/lime_pkg:$PYTHONPATH \
    python FullSDNPipeline/run_full_evaluation.py --max-rows 50000

# View results:
cat results/summary.md
cat results/stage2_xai/xai_summary.md
```

**Output:** `results/` folder with per-stage JSON results + summary.md

---

## Step 4: Run Pipeline Demo (quick verification)

```bash
python FullSDNPipeline/sdn_pipeline.py --demo --n-flows 50
```

---

## Step 5: Test with Real PCAPs

```bash
# Friday PCAPs (DDoS, PortScan, Bot):
python FullSDNPipeline/sdn_pipeline.py \
    --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \
    --limit 500 --output logs/friday_results.json

# Packet Shooter (real timing):
python FullSDNPipeline/packet_shooter.py \
    --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \
    --rate-multiplier 1.0 --limit 500
```

---

## Performance Summary

| Model | Precision | Recall | Latency/flow |
|-------|:---------:|:------:|:------------:|
| BCC v2 (Stage 1) | 87.5% | 99.89%* | 0.05 µs |
| DDL-40 (Stage 2) | 69.9% | 45.4% | 133 µs |
| IF (Stage 2) | 62.6% | 31.0% | 2.83 µs |
| **Full Pipeline** | **93.6%** | 14.1% | **~8 µs avg** |

*\*99.89% when tested on Sandaru's preprocessed data*

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `No module named 'pandas'` in Apptainer | Already in training command: `pip install pandas scikit-learn joblib` |
| `can't open file 'DDLModel/...'` | Wrong directory — `cd` to project root |
| `ddl_40feat.pkl not found` | Run Step 2 (Training) |
| `No module named 'lime'` | `pip install --target /tmp/lime_pkg lime` |
| `CUDA not available` | Use `--nv` flag with apptainer |

---

*Detailed results: `TRAINING_RESULTS.md` | Architecture: `PIPELINE_GUIDE.md` | Demo: `DemonstrationPlan.md`*
