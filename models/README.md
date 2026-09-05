# Trained Models

The model binaries are **not committed** — they are large and reproducible.
This folder is where the training scripts write them, and where the pipeline
looks for them.

| File | Model | Produced by |
|---|---|---|
| `sentry_model_v2.pkl` | BCC v2 Decision Tree (stage 1) | `src/BaseCheckClassifier/sdn/training/train_model.py` |
| `ddl_40feat.pkl` | Deep Dictionary Learning (stage 2) | `src/DDLModel/train_ddl_enhanced.py` |
| `isolation_forest.pkl` | Isolation Forest consensus vote | `src/DDLModel/train_ddl_enhanced.py` |

See [docs/guides/reproduction.md](../docs/guides/reproduction.md) for the full
training walkthrough and [docs/setup/gpu.md](../docs/setup/gpu.md) for GPU
training.
