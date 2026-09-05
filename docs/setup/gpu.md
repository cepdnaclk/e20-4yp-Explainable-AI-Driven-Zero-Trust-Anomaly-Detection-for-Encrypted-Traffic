# GPU Setup Guide — RTX 6000 Ada + PyTorch CUDA

The server has 3× NVIDIA RTX 6000 Ada Generation GPUs (49GB VRAM each).
GPU training reduces DDL training time from ~9 hours (CPU) to ~30 minutes.

---

## Step 1 — Verify GPU Availability

```bash
nvidia-smi
# Should show: RTX 6000 Ada × 3, CUDA Version: 13.0
```

## Step 2 — Install PyTorch with CUDA 12.4

```bash
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate

# Install PyTorch (CUDA 12.4 build is compatible with CUDA driver 13.0+)
pip install torch --index-url https://download.pytorch.org/whl/cu124

# Verify:
python -c "import torch; print('PyTorch:', torch.__version__); \
           print('CUDA available:', torch.cuda.is_available()); \
           print('GPU count:', torch.cuda.device_count()); \
           [print(f'  GPU {i}:', torch.cuda.get_device_name(i)) \
            for i in range(torch.cuda.device_count())]"
```

Expected output:
```
PyTorch: 2.6.x+cu124
CUDA available: True
GPU count: 3
  GPU 0: NVIDIA RTX 6000 Ada Generation
  GPU 1: NVIDIA RTX 6000 Ada Generation
  GPU 2: NVIDIA RTX 6000 Ada Generation
```

## Step 3 — Check GPU Memory Availability

Other jobs may be using GPU memory. The DDL trainer auto-selects the GPU
with the most free memory:

```bash
nvidia-smi --query-gpu=index,name,memory.free,memory.total \
           --format=csv,noheader,nounits
# Output: 0, NVIDIA RTX 6000 Ada..., 45000, 49140  (free GB / total GB)
```

Minimum required: **8GB free** for training on 1.68M normal samples, batch=512.

## Step 4 — Run GPU Training

```bash
cd /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate

# Full training with GPU (150 epochs, 1.68M samples):
nohup python DDLModel/train_ddl_enhanced.py \
    --train dataset/TRAIN_Traffic.csv \
    --test  dataset/TEST_Traffic.csv \
    --ddl-output models/ddl_40feat.pkl \
    --if-output  models/isolation_forest.pkl \
    --epochs 150 \
    --gpu --batch-size 512 \
    > models/training_log_gpu.txt 2>&1 &
echo "GPU Training PID: $!"
```

Monitor:
```bash
# Training progress:
tail -f models/training_log_gpu.txt

# GPU utilisation (in another terminal):
watch -n 2 nvidia-smi
```

## Speed Comparison

| Mode | Epochs | Dataset | ETA |
|------|--------|---------|-----|
| CPU (NumPy) | 150 | 1.68M rows | ~9 hours |
| CPU (NumPy) | 30 | 50k rows (debug) | ~10 min |
| GPU (RTX 6000) | 150 | 1.68M rows | ~25–35 min |
| GPU (RTX 6000) | 30 | 50k rows (debug) | ~3 min |

## Troubleshooting

| Problem | Solution |
|---------|---------|
| `CUDA not available` after install | Reactivate venv: `source .venv/bin/activate` |
| `CUDA out of memory` | Reduce `--batch-size 256` or `--max-train-rows 500000` |
| All 3 GPUs busy | Check `nvidia-smi` — wait for free memory or use CPU |
| Training slower than expected on GPU | Small batch size: try `--batch-size 512` |
| `ModuleNotFoundError: No module named torch` | Run Step 2 again inside the venv |

## Architecture Note

The GPU backend accelerates the ISTA (Iterative Shrinkage-Thresholding) inner
loop using PyTorch CUDA tensors. During inference (predicting on live flows),
the model always runs on CPU for portability — GPU inference is not needed
since a single flow prediction takes ~45ms on CPU anyway.
