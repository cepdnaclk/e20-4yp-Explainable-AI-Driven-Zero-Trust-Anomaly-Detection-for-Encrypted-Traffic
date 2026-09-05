# Zero-Trust Pipeline — Orchestrator

This module is the **main orchestrator** that chains together all pipeline stages:

```
.pcap → [Feature Extraction] → [Decision Tree] → [SDN Buffer] → [DDL + XAI] → Action
```

## Pipeline Flow

```
Stage 1: Feature Extraction (15 CIC-IDS-2017 features)
         └─ Uses: src/BaseCheckClassifier/sdn/extraction/
         
Stage 2: Base Check Classifier (Decision Tree)
         ├─ Normal → FORWARD immediately
         └─ Flagged → Go to Stage 3

Stage 3: SDN Buffer + DDL Deep Analysis + XAI
         ├─ DDL Normal  → RELEASE from buffer → FORWARD
         └─ DDL Anomaly → DROP + XAI Explanation Report
```

## Files

| File | Description |
|------|-------------|
| `pipeline.py` | `ZeroTrustPipeline` class — process_stream(), run_batch() |
| `run_demo.py` | End-to-end demo runner with synthetic DDL training |
| `quickstart.sh` | One-command setup + demo script |
| `requirements.txt` | Python dependencies |
| `docs/architecture/pipeline.md` | Comprehensive documentation |

## Quick Start

### Using `uv` (recommended)

```bash
# Install uv (once)
curl -LsSf https://astral.sh/uv/install.sh | sh

# From project root
uv venv .venv --python 3.12
source .venv/bin/activate
uv pip install -r ZeroTrustPipeline/requirements.txt

# Run demo
python -m ZeroTrustPipeline.run_demo --no-shap
```

### Using `pip`

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r ZeroTrustPipeline/requirements.txt

python -m ZeroTrustPipeline.run_demo --no-shap
```

### One-command

```bash
cd ZeroTrustPipeline && bash quickstart.sh
```

## Dependencies on Other Modules

| Module | Imported From | Purpose |
|--------|--------------|---------|
| `DDLModel` | `DDLModel/ddl_model.py` | Deep Dictionary Learning anomaly detector |
| `XAIExplainer` | `XAIExplainer/explainer.py` | SHAP + DDL-native explanations |
| `SDNBuffer` | `SDNBuffer/sdn_buffer.py` | SDN buffer simulation |
| Feature Extractor | `BaseCheckClassifier/.../extraction/` | 15-feature extraction from pcap |
| Traffic Encryptor | `BaseCheckClassifier/.../encryption/` | AES-256-GCM simulation |
