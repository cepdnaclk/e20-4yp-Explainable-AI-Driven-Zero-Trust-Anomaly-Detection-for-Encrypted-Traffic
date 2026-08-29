# Obsolete Experiments

> **Status: ARCHIVED** — These were early-stage experiments using the **BCCC Darknet** dataset.
> The active pipeline now uses **CIC-IDS-2017** features and lives in the top-level modules
> (`DDLModel/`, `XAIExplainer/`, `SDNBuffer/`, `ZeroTrustPipeline/`).

## Contents

| Directory | Description |
|-----------|-------------|
| `BCCCDarknetPipeline/` | Script version of the full pipeline (Isolation Forest + Autoencoder → pseudo-labels → Random Forest) on BCCC Darknet |
| `DataPreprocessing/` | Semi-supervised pseudo-labeling (Isolation Forest + Autoencoder) on BCCC Darknet |
| `pipeline/` | Random Forest notebooks (01 preprocessing → 02 RF → 03 SHAP) on BCCC Darknet |
| `RANDOMFORESTImplementation/` | Standalone RF implementation & results on BCCC Darknet |

## Why Archived

These experiments were built around the **BCCC Darknet** dataset with 50 variance-selected features.
The project has since moved to:
- **CIC-IDS-2017** 15 behavioral features
- **Deep Dictionary Learning** (DDL) instead of Random Forest
- **DDL-native + SHAP** explainability instead of SHAP TreeExplainer alone
- Integration with the **BaseCheckClassifier** simulation pipeline

## If You Need to Run Them

Each sub-directory has its own `guidelines.md` and `requirements.txt` / `Dockerfile`.
They are self-contained and can still be run independently — see the respective guidelines.
