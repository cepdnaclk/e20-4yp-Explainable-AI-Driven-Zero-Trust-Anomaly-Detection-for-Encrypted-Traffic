# Explainable AI-Driven Zero-Trust Anomaly Detection for Encrypted Traffic

**Department of Computer Engineering, University of Peradeniya**

| Team | Index | Email |
|---|---|---|
| Chalaka Perera | E/20/288 | e20288@eng.pdn.ac.lk |
| Janith Wanasinghe | E/20/420 | e20420@eng.pdn.ac.lk |
| Sandaru Wijewardhana | E/20/449 | e20449@eng.pdn.ac.lk |

Supervised by Dr. Suneth Namal Karunarathna and Dr. Upul Jayasinghe.

---

## Overview

Encrypted traffic hides its payload, so a detector has to judge a flow by its **shape** —
timing, packet sizes, flag counts — instead of by what is inside it. The project attacked
that problem twice, on two different datasets. Both lines are kept in this repository.

| | **Approach 1 — BCCC Darknet** | **Approach 2 — CIC-IDS-2017** |
|---|---|---|
| **Starting problem** | dataset has no anomaly label | dataset is labelled |
| **Method** | Isolation Forest + Autoencoder consensus → pseudo-labels → Random Forest | Decision Tree gate → DDL + Isolation Forest → dual XAI |
| **Explainability** | SHAP | LIME + SHAP |
| **Runs** | offline, in batch | inline, in a live SDN data path |
| **Status** | earlier line, archived | active |
| **Code** | [`experiments/`](experiments/) | [`src/`](src/) |

Approach 1 came first and answered *"can we detect anomalies at all when nobody has
labelled them?"* Approach 2 took that answer inline and made it fast enough to sit in a
switch's data path.

---

## Approach 1 — BCCC Darknet (semi-supervised)

> **Status: archived.** Kept for reproducibility and for the write-up. Code lives in
> [`experiments/BCCCDarknetPipeline/`](experiments/BCCCDarknetPipeline), with the notebook
> form of the same idea in [`experiments/DataPreprocessing/`](experiments/DataPreprocessing)
> and [`experiments/pipeline/`](experiments/pipeline).

### The problem it solves

BCCC Darknet ships with an `Encrypted` / `Non-Encrypted` label. That says **what the traffic
is**, not **whether it is unusual** — so there is nothing to train an anomaly detector on.
Rather than assume a label, the pipeline manufactures one:

1. Run two unsupervised detectors that fail in different ways.
2. Keep only the flows they **both** agree on, and throw the rest away.
3. Train a supervised classifier on what survives.

Agreement is the confidence signal. A flow that only one detector flags is exactly the
borderline case that would poison a supervised model, so it never reaches stage 3.

### The three stages

| Script | Role |
|---|---|
| `src/main.py` | Isolation Forest + Autoencoder over the raw flows, with a PCA scatter showing where the two detectors agree and where they diverge. Exploratory — writes no files. |
| `src/main2.py` | The same ensemble, tuned (300 trees, a deeper 128-64-32-64-128 autoencoder) and turned into a labelling pass. Emits `pseudo_label` and drops the disputed rows. |
| `src/supervised.py` | Random Forest on the surviving high-confidence rows. Reports precision/recall, confusion matrix and ROC-AUC. |

`main.py` is the look-around step and `main2.py` is the one that produces data, so they
overlap on purpose — the first exists to justify the thresholds the second one uses. Both
detectors cut at 5% contamination / the 95th percentile, so each flags roughly 1 flow in 20
on its own.

### Results

| | Flows |
|---|---:|
| Input | 25,538 |
| Dropped as disputed | 1,436 (5.6%) |
| **Kept as high-confidence** | **24,102 (94.4%)** |
| — labelled anomalous | 559 |
| — labelled normal | 23,543 |

The agreement rule is far stricter than either detector on its own, which is the point. The
anomaly set also does not line up with the dataset's own encryption label — 344 of the 559
are `Encrypted` and 215 are not. That is the expected result: the ensemble keys on flow
shape, not on whether the payload happens to be encrypted.

### Preprocessing

Identical across all three scripts, and it matters more than the model choice:

- numeric columns only, so `flow_id`, `src_ip` and friends cannot leak identity into the model
- `inf` / `-inf` → `NaN`, then `NaN` → the column median
- clip to ±1e6 so the autoencoder's backprop stays numerically stable
- `StandardScaler` on everything

---

## Approach 2 — CIC-IDS-2017 (two-stage SDN pipeline)

> **Status: active.** Code lives in [`src/`](src/).

A **two-stage anomaly detection pipeline** for Software-Defined Networks (SDN), using a
lightweight Decision Tree as the first filter and Deep Dictionary Learning (DDL) + Isolation
Forest with dual XAI (LIME + SHAP) as the second stage.

### Why Two Stages?

Traditional IDS approaches use a single model, which creates a trade-off: fast but inaccurate, or accurate but slow. Our pipeline resolves this:

- **Stage 1 (BCC)**: Sub-microsecond Decision Tree classifies 95% of traffic instantly
- **Stage 2 (DDL+IF+XAI)**: Only the 5% flagged traffic gets deep analysis
- **Result**: Near-zero false positives (0.25% FPR) with sub-10µs average latency

---

### Pipeline Architecture

```
PacketIN ──→ Unified Feature Extraction (DPKT, single pass)
                |
                ├── 28 features ──→ BCC v2 (Decision Tree, <1µs)
                |                      |
                |                   BENIGN ──→ FORWARD + ALLOW rule
                |                   ATTACK ──→ SDN Buffer
                |                                |
                └── 40 features ──→ DDL (reconstruction error) + IF (isolation score)
                                       |
                                    Both agree Normal  ──→ FORWARD + ALLOW rule
                                    Both agree Anomaly ──→ DROP + XAI explanation
                                       |
                                   LIME + SHAP explain the decision
```

### Design Decisions

1. **Feature extraction once, used twice**: The unified extractor computes a superset of features in a single pass. BCC uses 28 features, DDL+IF use 40. No redundant computation.

2. **DDL + IF consensus**: A flow is DROPped only when **both** DDL (reconstruction error > threshold) **and** IF (isolation score indicates outlier) agree. This dual check reduces false positives to 0.25%.

3. **XAI for transparency**: LIME and SHAP explain **why** each flow was flagged, showing which features (packet sizes, timing patterns, flag counts) contributed most. This helps security analysts trust and audit the system.

---

### Models

| Model | Role | Features | Type | Training |
|-------|------|----------|------|----------|
| **BCC v2** | Stage 1 gatekeeper | 28 | Decision Tree | Supervised (BENIGN/ATTACK) |
| **DDL** | Stage 2 anomaly detector | 40 | Deep Dictionary Learning (ISTA) | One-class (Normal only) |
| **IF** | Stage 2 consensus voter | 40 | Isolation Forest | One-class (Normal only) |

---

### Key Results

| Model | Precision | Recall | FPR | Latency |
|-------|:---------:|:------:|:---:|:-------:|
| BCC v2 (Sandaru's data) | 96.3% | **99.89%** | 2.0% | 0.05 µs |
| DDL-40 standalone | 69.9% | 45.4% | 5.0% | 133 µs |
| **Full Pipeline** | **93.6%** | 14.1% | **0.25%** | ~8 µs avg |

> **Interpretation**: The pipeline prioritizes precision over recall — when it DROPs a flow, it's 94% likely to be a real attack. Only 0.25% of legitimate traffic is ever blocked.

---

## Repository Layout

```
src/                          # Approach 2 — the active pipeline
├── DDLModel/                 # Deep Dictionary Learning model, training, extractors
├── BaseCheckClassifier/      # Stage 1 gatekeeper (BCC v2) and its SDN modules
├── FullSDNPipeline/          # End-to-end pipeline, evaluation and PCAP replay
├── EnhancedPipeline/         # IF second vote, dual XAI, REST API, dashboard
├── ZeroTrustPipeline/        # Original zero-trust pipeline
├── LiveTraffic/              # Live capture, replay and OpenFlow controller
├── InlineBridgeDemo/         # Three-machine inline bridge demo
├── XAIExplainer/             # LIME + SHAP explanations
├── SDNBuffer/                # Flow buffering between the two stages
└── profiling/                # Latency benchmarking

experiments/                  # Approach 1 — BCCC Darknet, archived
├── BCCCDarknetPipeline/      # Script form: IF + Autoencoder -> pseudo-labels -> RF
├── DataPreprocessing/        # Notebook form of the same pseudo-labelling
├── pipeline/                 # RF notebooks (01 preprocessing -> 02 RF -> 03 SHAP)
└── RANDOMFORESTImplementation/   # Standalone RF implementation

docs/                         # All documentation (see docs/CONTENTS.md)
├── guides/                   # How to run, test and reproduce
├── architecture/             # Design notes
├── setup/                    # GPU and switch setup
├── reports/                  # Results and supervisor reports
├── planning/                 # Workplan and demo plan
├── LitreatureReview/         # Reference material for the review
└── index.html, images/, data/, _config.yml   # Published project page

tests/                        # Pipeline tests
scripts/                      # Build and packaging scripts
research/                     # Reference papers
dataset/                      # CIC-IDS-2017 CSVs (not committed)
models/                       # Trained models (not committed)
results/, logs/               # Generated output (not committed)
```

Datasets and trained models are gitignored — every `*.csv`, `dataset/`, `models/*.pkl`,
`results/` and `logs/` is reproduced by running the pipelines, not pulled from git.

---

## Quick Start

```bash
# From the repository root
source /path/to/venv/bin/activate
```

**Approach 2 — the active pipeline**

```bash
python src/FullSDNPipeline/run_full_evaluation.py
cat results/summary.md
```

**Approach 1 — BCCC Darknet**

```bash
cd experiments/BCCCDarknetPipeline
pip install -r requirements.txt

python src/main.py         # stage 1 — plots only, writes nothing
python src/main2.py        # stage 2 — writes the high-confidence CSV
python src/supervised.py   # stage 3 — prints the evaluation
```

Run those three in order: stage 3 reads what stage 2 writes. The input dataset is not in
git — see [`experiments/BCCCDarknetPipeline/data/README.md`](experiments/BCCCDarknetPipeline/data/README.md)
for what each file is and where it comes from.

Every script derives the repository root from its own location, so it runs from anywhere.
See [docs/guides/quick-start.md](docs/guides/quick-start.md) for the full walkthrough and
[docs/CONTENTS.md](docs/CONTENTS.md) for the documentation index.

---

## Impact Assessment

### Without This System
- All traffic is either trusted (no security) or manually inspected (impractical at scale)
- No explainability — security teams cannot audit automated decisions
- Single-model approaches sacrifice either speed or accuracy

### With This System
- **95% of traffic** processed in <1µs (BCC passes benign instantly)
- **5% suspicious traffic** gets deep 40-feature analysis within milliseconds
- **Every DROP decision** is explained by LIME + SHAP (audit trail)
- **0.25% false positive rate** — virtually no legitimate traffic disrupted
- **Zero-trust architecture** — no traffic is inherently trusted

---

## References

- **Dataset (Approach 1)**: BCCC Darknet flow export — 25,538 flows, 475 features
- **Dataset (Approach 2)**: CIC-IDS-2017 (Canadian Institute for Cybersecurity)
- **DDL**: Deep Dictionary Learning for anomaly detection
- **LIME**: Ribeiro et al., "Why Should I Trust You?" (KDD 2016)
- **SHAP**: Lundberg & Lee, "A Unified Approach to Interpreting Model Predictions" (NeurIPS 2017)
