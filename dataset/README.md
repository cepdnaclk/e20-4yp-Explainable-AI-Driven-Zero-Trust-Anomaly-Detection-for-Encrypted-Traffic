# dataset/README.md — CIC-IDS-2017 Dataset Reference
# Zero-Trust XAI Anomaly Detection | University of Peradeniya
# e20420Janith

# Dataset — CIC-IDS-2017

This folder contains the processed CIC-IDS-2017 dataset used for training and
evaluating the DDL + Isolation Forest models.

## Files

| File | Size | Description |
|------|------|-------------|
| `TRAIN_Traffic.csv` | ~750 MB | Training split (80%) — all attack types + normal |
| `TEST_Traffic.csv`  | ~195 MB | Test split (20%) — held out for evaluation |
| `CLEANED_Combined_Traffic.csv` | ~960 MB | Full cleaned dataset (train+test combined) |

## Column Summary

70 columns total. Key columns used:

| Use | Column | Count |
|-----|--------|-------|
| Labels | `Label` (Normal / Attack) | 1 |
| DT features (teammate) | Various (see docs/planning/workplan.md) | 15 |
| DDL features | Mapped to `DDL_TO_CSV` dict in `train_ddl_enhanced.py` | 30 |

## Label Distribution (approximate)

```
Normal  : ~80% of rows
Attack  : ~20% of rows (various attack types: DDoS, PortScan, Brute Force, etc.)
```

## How to Use for Training

### Train DDL 40 features):

```bash
cd e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/

# Full training (may take 5–20 min depending on epochs + CPU):
python DDLModel/train_ddl_enhanced.py \
    --train dataset/TRAIN_Traffic.csv \
    --test  dataset/TEST_Traffic.csv \
    --ddl-output models/ddl_40feat.pkl \
    --if-output  models/isolation_forest.pkl \
    --epochs 150 --atoms-l1 64 --atoms-l2 128

# Quick debug run (limit rows, fewer epochs):
python DDLModel/train_ddl_enhanced.py \
    --train dataset/TRAIN_Traffic.csv \
    --test  dataset/TEST_Traffic.csv \
    --epochs 30 \
    --max-train-rows 50000 \
    --max-test-rows  10000
```

### Train DT model (15 features — teammate's code):

Handled by the BaseCheckClassifier module. See
`src/BaseCheckClassifier/sdn/` for training scripts.

## Source

Original dataset: https://www.unb.ca/cic/datasets/ids-2017.html  
Preprocessed and split by the FYP team. The segmentation done in
`CICDataset/Processed-Data/` was verified — it is safe to use as-is.

## Feature Mapping

The 40 DDL features map to CSV columns via `DDL_TO_CSV` in
`DDLModel/train_ddl_enhanced.py`. All 30 columns exist in the CSV.
See `docs/architecture/features.md` for rationale behind the 30-feature choice.
