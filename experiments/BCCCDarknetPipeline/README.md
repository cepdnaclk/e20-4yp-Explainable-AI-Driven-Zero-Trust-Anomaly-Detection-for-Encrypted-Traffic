# BCCC Darknet Pipeline (scripts)

Semi-supervised anomaly detection on the **BCCC Darknet** flow dataset, written as three
plain Python scripts that run end to end without a notebook server.

This is the script form of the BCCC Darknet experiment. It was developed separately in
[chala2001/bcc_darknet_project](https://github.com/chala2001/bcc_darknet_project) and moved
here so the whole team has it in one place. The notebook form of the same idea lives next
door in [`../DataPreprocessing`](../DataPreprocessing) and [`../pipeline`](../pipeline).

> **Status: ARCHIVED**, like everything else under `experiments/`. The active
> pipeline moved to CIC-IDS-2017 features and Deep Dictionary Learning. These scripts are
> kept for reproducibility and for the write-up.

## The idea

The BCCC Darknet dataset ships with an `Encrypted` / `Non-Encrypted` label, which describes
*what the traffic is*, not *whether it is anomalous*. There is no ground-truth anomaly label
to train on, so the pipeline manufactures one:

1. Run two unsupervised detectors that fail in different ways.
2. Keep only the flows they **both** agree on, and throw away the rest.
3. Train a supervised classifier on what is left.

Agreement is the confidence signal. A flow that only one detector flags is exactly the kind
of borderline case that would poison a supervised model, so it never reaches stage 3.

## Stages

| Script | What it does |
|---|---|
| `src/main.py` | Isolation Forest + Autoencoder over the raw dataset, with a PCA scatter showing where the two detectors agree and where they diverge. Exploratory — it writes no files. |
| `src/main2.py` | The same ensemble, tuned (300 trees, deeper 128-64-32-64-128 autoencoder), turned into a labelling pass. Emits `pseudo_label` and drops the disputed rows. |
| `src/supervised.py` | Random Forest on the surviving high-confidence rows. Reports precision/recall, confusion matrix and ROC-AUC. |

`main.py` is the look-around step and `main2.py` is the one that produces data, so they
overlap on purpose — the first exists to justify the thresholds the second one uses.

## Preprocessing

Identical in all three scripts, and it matters more than the model choice:

- keep numeric columns only, so `flow_id`, `src_ip` and friends can't leak identity into the model
- `inf` / `-inf` → `NaN`
- fill `NaN` with the column median (`main.py` uses 0 — an early choice that `main2.py` corrects)
- clip to ±1e6 (`main.py`: ±1e9) so the autoencoder's backprop stays numerically stable
- `StandardScaler` on everything

Both detectors are set to a 5% contamination / 95th-percentile cut, so each flags roughly
1 in 20 flows on its own.

## Results

Of 25,538 flows, 24,102 (94.4%) come out high-confidence and 1,436 are dropped as disputed.
Of those kept, 559 are labelled anomalous and 23,543 normal — so the agreement rule is far
stricter than either detector alone, which is the point.

The anomaly set does not line up with the dataset's own encryption label (344 of the 559 are
`Encrypted`, 215 are not), which is the expected result: the ensemble is picking up on flow
shape, not on whether the payload happens to be encrypted.

## Running it

```bash
pip install -r requirements.txt

python src/main.py         # stage 1 — plots, no output files
python src/main2.py        # stage 2 — writes data/bcc_darknet_labeled_high_confidence.csv
python src/supervised.py   # stage 3 — prints the evaluation
```

Stage 3 depends on the CSV stage 2 writes, so run them in order. See [`data/README.md`](data/README.md)
for where to get the input dataset.
