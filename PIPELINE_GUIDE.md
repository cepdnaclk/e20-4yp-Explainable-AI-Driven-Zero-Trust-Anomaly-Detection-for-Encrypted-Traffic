# Zero-Trust Pipeline — Architecture Guide

> **Explainable AI-Driven Zero-Trust Anomaly Detection for Encrypted Traffic**

## Directory Structure

```
Project Root/
├── BaseCheckClassifier/          ← Friend's Decision-Tree classifier & simulation
│   └── BaseCheckClassifierSimulation/
│       ├── extraction/           ← Feature extractor (hybrid DPKT + NFStream)
│       ├── encryption/           ← AES-256-GCM traffic encryptor
│       ├── decision/             ← Sentry DT controller
│       ├── dashboard/            ← Streamlit live dashboard
│       ├── normal/ & attack/     ← PCAP test files
│       └── ...
│
├── DDLModel/                     ← Deep Dictionary Learning anomaly detector
│   ├── ddl_model.py              ← Two-layer DDL with ISTA sparse coding
│   ├── train_ddl.py              ← Training script for CIC-IDS-2017 features
│   └── README.md
│
├── XAIExplainer/                 ← Explainability module
│   ├── explainer.py              ← SHAP + DDL-native reconstruction decomposition
│   └── README.md
│
├── SDNBuffer/                    ← SDN flow-buffer simulation
│   ├── sdn_buffer.py             ← OpenFlow-style hold/release/drop
│   └── README.md
│
├── ZeroTrustPipeline/            ← Pipeline orchestrator
│   ├── pipeline.py               ← Ties all modules together
│   ├── run_demo.py               ← End-to-end demo script
│   ├── quickstart.sh             ← One-command setup & run
│   └── requirements.txt          ← Python dependencies (all modules)
│
├── tests/                        ← Integration tests (27 sub-tests)
│   └── test_pipeline.py
│
├── ObsoleteExperiments/          ← Archived early experiments (BCCC Darknet)
│   ├── DataPreprocessing/        ← Semi-supervised pseudo-labeling
│   ├── pipeline/                 ← Random Forest notebooks
│   └── RANDOMFORESTImplementation/
│
└── docs/                         ← Project documentation site
```

## Pipeline Flow

```
┌─────────────┐    ┌───────────────┐    ┌──────────────┐    ┌───────────────┐
│  Raw PCAP   │───▶│  Feature      │───▶│  Decision    │───▶│  DDL Layer    │
│  Stream     │    │  Extraction   │    │  Tree Check  │    │  (Anomaly)    │
└─────────────┘    │  (15 features)│    │  (BaseCheck) │    │               │
                   └───────────────┘    └──────┬───────┘    └──────┬────────┘
                                               │                    │
                                        ┌──────┴───────┐    ┌──────┴────────┐
                                        │  Normal →     │    │  SHAP + DDL   │
                                        │  FORWARD      │    │  Explanation  │
                                        └──────────────┘    └──────┬────────┘
                                                                   │
                                                            ┌──────┴────────┐
                                                            │  SDN Buffer   │
                                                            │  Hold/Release │
                                                            └───────────────┘
```

### Processing Steps

1. **Encryption & Latency Simulation** — `encryption/traffic_encryptor.py` applies AES-256-GCM overhead
2. **Feature Extraction** — `extraction/feature_extractor.py` extracts 15 CIC-IDS-2017 behavioral features
3. **Decision Tree Pre-Check** — Friend's DT model (`decision/sentry_controller.py`) classifies the flow
4. **DDL Anomaly Detection** — If DT says "Normal" or as a second opinion:
   - Two-layer dictionary learning finds sparse representations
   - Reconstruction error exceeding the learned threshold → Anomaly
5. **XAI Explanation** — For anomalies:
   - DDL-native: per-feature reconstruction error decomposition + sparse code analysis
   - SHAP: KernelExplainer with `nsamples` perturbation-based attributions
6. **SDN Buffer Decision** — Anomalous flows are held in an OpenFlow-style buffer, then DROP'd

### 15 Behavioral Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | Packet Length Variance | Variance of packet sizes |
| 2 | Fwd Packet Length Max | Largest forward packet |
| 3 | Fwd Header Length | Forward TCP/IP header bytes |
| 4 | Init_Win_bytes_forward | Initial TCP window (fwd) |
| 5 | Bwd Header Length | Backward header bytes |
| 6 | Total Length of Fwd Packets | Sum of fwd payload |
| 7 | Init_Win_bytes_backward | Initial TCP window (bwd) |
| 8 | Bwd Packets/s | Backward packet rate |
| 9 | Flow IAT Min | Minimum inter-arrival time |
| 10 | Fwd IAT Min | Minimum fwd inter-arrival |
| 11 | Flow Bytes/s | Throughput (bytes/sec) |
| 12 | Active Min | Minimum active period |
| 13 | Bwd IAT Total | Total backward IAT |
| 14 | Flow IAT Max | Maximum inter-arrival time |
| 15 | Flow Duration | Total duration of the flow |

## Requirements

All Python dependencies for the Zero-Trust pipeline modules:

| Package | Min Version | Used By |
|---------|-------------|----------|
| `numpy` | ≥ 1.24.0 | DDLModel, XAIExplainer, Pipeline |
| `pandas` | ≥ 2.0.0 | Pipeline (feature handling) |
| `scikit-learn` | ≥ 1.3.0 | DDLModel (preprocessing) |
| `joblib` | ≥ 1.3.0 | Model persistence |
| `nfstream` | ≥ 6.5.3 | Feature extraction (NFStream flows) |
| `dpkt` | ≥ 1.9.8 | Feature extraction (packet parsing) |
| `scapy` | ≥ 2.5.0 | Feature extraction (fallback) |
| `shap` | ≥ 0.42.0 | XAIExplainer (KernelExplainer) |
| `streamlit` | ≥ 1.28.0 | Dashboard (BaseCheckClassifier) |
| `seaborn` | ≥ 0.12.0 | Visualisation |
| `matplotlib` | ≥ 3.7.0 | Visualisation |

The pinned list is in [ZeroTrustPipeline/requirements.txt](ZeroTrustPipeline/requirements.txt).

## Quick Start

### Option A — Using `uv` (recommended, fastest)

[`uv`](https://docs.astral.sh/uv/) is a fast Python package manager written in Rust.

```bash
# Install uv (once)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create venv and install deps in one shot
uv venv .venv --python 3.12
source .venv/bin/activate
uv pip install -r ZeroTrustPipeline/requirements.txt

# Run tests
python -m tests.test_pipeline

# Run demo
python -m ZeroTrustPipeline.run_demo
```

### Option B — Using `pip` + `venv`

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r ZeroTrustPipeline/requirements.txt

python -m tests.test_pipeline
python -m ZeroTrustPipeline.run_demo
```

### Option C — One-command quickstart

```bash
cd ZeroTrustPipeline
bash quickstart.sh
```

## DDL Model — Deep Dictionary Learning

Two-layer architecture with ISTA sparse coding:

- **Layer 1**: D₁ ∈ ℝ^(n_features × k₁) — learns atomic patterns from raw features
- **Layer 2**: D₂ ∈ ℝ^(k₁ × k₂) — learns higher-level compositions from Layer 1 sparse codes
- **Reconstruction**: x̂ = (α₂ · D₂ᵀ) · D₁ᵀ
- **Anomaly Score**: MSE(x, x̂)
- **Threshold**: Learned at `threshold_percentile` of training errors

Training:
```python
from DDLModel.ddl_model import DeepDictionaryLearning

ddl = DeepDictionaryLearning(
    n_features=15, n_atoms_l1=32, n_atoms_l2=64,
    sparsity_weight=0.05, threshold_percentile=95,
)
ddl.fit(benign_data)  # Train on clean traffic only
ddl.save("models/ddl_trained.pkl")
```

## XAI — Explainability

```python
from XAIExplainer.explainer import DDLExplainer, FEATURE_NAMES

explainer = DDLExplainer(ddl_model, background_data=benign_data)
result = explainer.explain(sample, include_shap=True)
print(result["summary"])
```

Produces:
- **DDL-native**: Per-feature reconstruction error → identifies which features deviate most
- **SHAP**: Perturbation-based attributions → model-agnostic feature importance
- **Sparse code summary**: Sparsity ratios and active atom counts for both layers

## SDN Buffer

```python
from SDNBuffer.sdn_buffer import SDNBuffer

buffer = SDNBuffer(max_buffer_size=100, timeout_ms=5000)
buffer.add("flow_001", packet_data, metadata)
buffer.release("flow_001")  # → FORWARD
buffer.drop("flow_002")     # → DROP
```

## Testing

```bash
python -m tests.test_pipeline
```

Runs 27 sub-tests across 7 test functions:
- `test_ddl_model` — Training, prediction, save/load
- `test_intermediate_representations` — DDL internal state
- `test_xai_explainer` — DDL-native explanations
- `test_xai_with_shap` — SHAP integration (optional)
- `test_pipeline_flow` — Full end-to-end with PCAPs
- `test_sdn_buffer` — Buffer add/release/drop
