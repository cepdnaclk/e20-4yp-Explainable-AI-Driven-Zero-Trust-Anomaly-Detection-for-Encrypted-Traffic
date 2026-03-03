# DDL Model — Deep Dictionary Learning for Anomaly Detection

This module implements the **Deep Dictionary Learning (DDL)** model used as the second-stage anomaly detector in the zero-trust pipeline.

## Architecture

```
Input (15 features) → Layer 1 (D1: 15×64) → Sparse Code α1
                    → Layer 2 (D2: 64×128) → Sparse Code α2
                    → Reconstruction: x̂ = (α2 · D2ᵀ) · D1ᵀ
                    → Anomaly Score = ||x - x̂||²
```

- **Layer 1**: Learns coarse flow-level traffic patterns
- **Layer 2**: Learns fine-grained sub-patterns from L1 sparse codes
- **Sparse coding**: ISTA (Iterative Shrinkage-Thresholding Algorithm)
- **Anomaly detection**: Reconstruction error exceeding a learned percentile threshold

## Files

| File | Description |
|------|-------------|
| `ddl_model.py` | Core `DeepDictionaryLearning` class — fit, predict, save/load |
| `train_ddl.py` | Training scripts for CSV data or `.pcap` directories |
| `__init__.py` | Package init, exports `DeepDictionaryLearning` |

## Usage

### Train from CSV (CIC-IDS-2017)
```bash
python -m DDLModel.train_ddl --csv /path/to/TRAIN_Traffic.csv --output ./models/ddl_model.pkl
```

### Train from pcap files
```bash
python -m DDLModel.train_ddl --pcap-dir ./BaseCheckClassifier/BaseCheckClassifierSimulation/normal/ --output ./models/ddl_model.pkl
```

### Use in Python
```python
from DDLModel.ddl_model import DeepDictionaryLearning

# Train
ddl = DeepDictionaryLearning(n_features=15, n_atoms_l1=64, n_atoms_l2=128)
ddl.fit(X_normal)  # (n_samples, 15) numpy array of benign traffic

# Predict
result = ddl.predict(X_test)
print(result["labels"])   # "Normal" or "Anomaly"
print(result["scores"])   # Reconstruction error

# Save / Load
ddl.save("models/ddl_model.pkl")
ddl2 = DeepDictionaryLearning.load("models/ddl_model.pkl")
```

## The 15 Features (CIC-IDS-2017)

1. Packet Length Variance
2. Fwd Packet Length Max
3. Fwd Header Length
4. Init_Win_bytes_forward
5. Bwd Header Length
6. Total Length of Fwd Packets
7. Init_Win_bytes_backward
8. Bwd Packets/s
9. Flow IAT Min
10. Fwd IAT Min
11. Flow Bytes/s
12. Active Min
13. Bwd IAT Total
14. Flow IAT Max
15. Flow Duration

## Dependencies

- `numpy`
- `joblib`
- `pandas` (for CSV training only)
