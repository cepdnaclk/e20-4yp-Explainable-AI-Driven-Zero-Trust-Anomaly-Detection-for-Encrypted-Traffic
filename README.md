# Zero-Trust XAI Anomaly Detection for Encrypted Traffic

**University of Peradeniya | e20420Janith**

## Pipeline Architecture

```
PacketIN (from switch)
   |
   +-- Unified Feature Extraction (DPKT, single pass)
          |
          +-- 28 features --> BCC v2 (Decision Tree, <100us)
          |                     |
          |                  BENIGN -> FORWARD + ALLOW rule
          |                  ATTACK -> SDN Buffer (hold)
          |                              |
          +-- 40 features --> DDL + IF + XAI (<50ms)
                                |
                             Normal  -> FORWARD + ALLOW rule
                             Anomaly -> DROP rule + XAI explanation
```

**Design:** Features extracted ONCE. BCC v2 uses 28, DDL uses 40 (22 shared).

## Repository Structure

```
e20420Janith/e20-4yp-.../
|-- FullSDNPipeline/              <<< MAIN PIPELINE
|   |-- sdn_pipeline.py          Single unified SDN script
|   |-- unified_feature_extractor.py  Shared extraction (28+40)
|   |-- packet_shooter.py        PCAP replay with real timing
|   +-- run_demo.sh              One-command launcher
|
|-- BaseCheckClassifier/
|   +-- feature_extractor_v2.py   BCC v2 (28-feat, Sandaru's DPKT)
|
|-- DDLModel/
|   |-- ddl_model.py             Deep Dictionary Learning (2-layer ISTA)
|   |-- ddl_feature_extractor.py  40-feature DDL extractor
|   +-- train_ddl_enhanced.py    Train DDL + IF (GPU/CPU)
|
|-- models/
|   |-- sentry_model_v2.pkl      BCC v2 DT (28 features)
|   |-- ddl_40feat.pkl           DDL model (40 features)
|   +-- isolation_forest.pkl     IF consensus voter
|
|-- dataset/
|   |-- TRAIN_Traffic.csv        CIC-IDS-2017 training data
|   +-- TEST_Traffic.csv         CIC-IDS-2017 test data
|
|-- QUICK_START.md               Step-by-step guide
|-- PIPELINE_GUIDE.md            Full architecture doc
|-- DemonstrationPlan.md         Demo script
+-- WORKPLAN.md                  Session tracking
```

## Quick Start

```bash
cd /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate

# Demo mode:
python FullSDNPipeline/sdn_pipeline.py --demo --n-flows 30

# Real PCAPs:
python FullSDNPipeline/sdn_pipeline.py \
    --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \
    --limit 500
```

## Feature Sets

| Model | Features | Purpose |
|-------|----------|---------|
| BCC v2 | 28 (DT) | Fast pre-screening (<100us) |
| DDL | 40 (ISTA) | Deep anomaly detection (~45ms) |
| IF | 40 (same) | Consensus vote (reduces FP) |

## Models

| File | Description | Training |
|------|-------------|----------|
| `sentry_model_v2.pkl` | BCC v2 Decision Tree (Sandaru) | Pre-trained |
| `ddl_40feat.pkl` | 2-layer DDL (ISTA sparse coding) | `train_ddl_enhanced.py` |
| `isolation_forest.pkl` | Isolation Forest voter | `train_ddl_enhanced.py` |

## Key Documents

- **[QUICK_START.md](QUICK_START.md)** — Step-by-step demo guide
- **[PIPELINE_GUIDE.md](PIPELINE_GUIDE.md)** — Full architecture documentation
- **[DemonstrationPlan.md](DemonstrationPlan.md)** — Demo day script
- **[WORKPLAN.md](WORKPLAN.md)** — Session tracking
