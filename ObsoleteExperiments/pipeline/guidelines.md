# Pipeline Environment & Execution Guide

This guide describes the project layout, how to build/run the Docker container, and the execution order of the notebooks.

---

## 1. Folder Structure

```
pipeline/
├── Dockerfile                         # Single image for all three stages
├── requirements.txt                   # Unified Python dependencies
├── guidelines.md                      # ← you are here
├── data/
│   └── bccc_darknet.csv               # Raw BCCC Darknet dataset
├── artifacts/                         # All model/output artefacts (auto-created)
│   ├── autoencoder_model.h5
│   ├── isolation_forest_model.pkl
│   ├── scaler_pseudo_labeling.pkl
│   ├── bccc_labeled_all_confidence.csv
│   ├── bccc_labeled_high_confidence.csv
│   ├── rf_anomaly_classifier.pkl
│   ├── rf_anomaly_classifier_optimised.pkl
│   ├── shap_values_anomaly.npy
│   └── ... (plots, CSVs, etc.)
├── results/
│   └── RandomForestResults.md
├── 01_data_preprocessing.ipynb        # Stage 1 – IF + AE pseudo-labelling
├── 02_random_forest.ipynb             # Stage 2 – RF classifier + depth optimisation
└── 03_shap_explainability.ipynb       # Stage 3 – SHAP TreeExplainer
```

All notebooks read/write to **`./data/`** (raw input) and **`./artifacts/`** (outputs).  
Run them in order: **01 → 02 → 03**.

---

## 2. Data Cleaning Pipeline Logic

The cleaning process runs in `01_data_preprocessing.ipynb`:

### Step 1: Loading & Initial Selection
- **Input:** `./data/bccc_darknet.csv`
- Only numeric features (`float64`, `int64`) are retained.

### Step 2: Numerical Sanitisation
- `inf` / `-inf` → `NaN`, then median imputation.
- Extreme values clipped to `[-1e9, 1e9]`.

### Step 3: Feature Engineering & Scaling
- Top 50 features by variance are selected.
- `StandardScaler` (mean=0, std=1).

---

## 3. Building the Docker Image

From the **`pipeline/`** directory:

```bash
# CPU build (recommended for most machines)
docker build --build-arg BASE_IMAGE=python:3.10-slim -t ml-pipeline .

# GPU build (requires NVIDIA runtime)
docker build --build-arg BASE_IMAGE=tensorflow/tensorflow:latest-gpu -t ml-pipeline:gpu .
```

---

## 4. Running the Container

```bash
# CPU
docker run -it -p 8888:8888 -v "$(pwd):/app" ml-pipeline

# GPU
docker run --gpus all -it -p 8888:8888 -v "$(pwd):/app" ml-pipeline:gpu
```

The `-v "$(pwd):/app"` mount ensures that your local `pipeline/` folder is live-synced inside the container, so all artefacts saved by the notebooks persist on your host.

---

## 5. Accessing Jupyter

### Browser
Look for a URL in the terminal output:
```
http://127.0.0.1:8888/lab?token=<TOKEN>
```
Open it in your browser.

### VS Code (Remote Kernel)
1. Open the `pipeline/` folder in VS Code.
2. Open any `.ipynb` file.
3. Click **Select Kernel → Existing Jupyter Server**.
4. Paste the `http://127.0.0.1:8888/?token=...` URL.

---

## 6. Execution Order

| # | Notebook | Purpose | Key Outputs |
|---|----------|---------|-------------|
| 1 | `01_data_preprocessing.ipynb` | IF + AE ensemble pseudo-labelling | `bccc_labeled_high_confidence.csv` |
| 2 | `02_random_forest.ipynb` | Train RF, depth optimisation, visualisation | `rf_anomaly_classifier_optimised.pkl` |
| 3 | `03_shap_explainability.ipynb` | SHAP TreeExplainer for XAI | SHAP plots (bar, beeswarm, waterfall) |

---

## 7. Stopping / Starting the Container

```bash
# Find container ID
docker ps

# Stop
docker stop <container_id>

# Restart (re-attach)
docker start -ai <container_id>
```

---

## 8. Pipeline Artefacts

After running all three notebooks, `./artifacts/` will contain:

| File | Source |
|------|--------|
| `scaler_pseudo_labeling.pkl` | Notebook 01 |
| `isolation_forest_model.pkl` | Notebook 01 |
| `autoencoder_model.h5` | Notebook 01 |
| `bccc_labeled_all_confidence.csv` | Notebook 01 |
| `bccc_labeled_high_confidence.csv` | Notebook 01 |
| `rf_anomaly_classifier.pkl` | Notebook 02 |
| `rf_anomaly_classifier_optimised.pkl` | Notebook 02 |
| `depth_optimisation_curves.png` | Notebook 02 |
| `test_predictions.csv` | Notebook 02 |
| `PERFORMANCE_REPORT.md` | Notebook 02 |
| `shap_values_anomaly.npy` | Notebook 03 |
| `shap_summary_bar.png` | Notebook 03 |
| `shap_summary_beeswarm.png` | Notebook 03 |
| `shap_waterfall_anomaly.png` | Notebook 03 |
