"""
train_ddl_enhanced.py — Train DDL with 30 Features on CIC-IDS-2017 CSV
=======================================================================
Zero-Trust XAI Anomaly Detection | University of Peradeniya
e20420Janith

Reads the 70-column CIC-IDS-2017 processed CSV, maps the 30 DDL features
by column name, trains the Deep Dictionary Learning model on Normal rows
only (one-class), evaluates on the test set, and saves both the DDL and an
Isolation Forest model.

Usage:
    # CPU training (default):
    python DDLModel/train_ddl_enhanced.py \
        --train dataset/TRAIN_Traffic.csv \
        --test  dataset/TEST_Traffic.csv \
        --epochs 150 --atoms-l1 64 --atoms-l2 128

    # GPU training (CUDA, auto-selects most-free RTX 6000):
    python DDLModel/train_ddl_enhanced.py \
        --train dataset/TRAIN_Traffic.csv \
        --test  dataset/TEST_Traffic.csv \
        --epochs 150 --atoms-l1 64 --atoms-l2 128 \
        --gpu --batch-size 512

    # Quick debug run (fewer epochs, limited rows):
    python DDLModel/train_ddl_enhanced.py \
        --train dataset/TRAIN_Traffic.csv \
        --test  dataset/TEST_Traffic.csv \
        --epochs 30 --max-train-rows 50000

    # GPU quick debug:
    python DDLModel/train_ddl_enhanced.py \
        --train dataset/TRAIN_Traffic.csv --test dataset/TEST_Traffic.csv \
        --epochs 30 --max-train-rows 50000 --gpu --batch-size 512

Output:
    models/ddl_30feat.pkl          — Trained DeepDictionaryLearning model
    models/isolation_forest.pkl    — Trained IsolationForestVoter model
    models/train_report.json       — Training metrics and feature mapping

GPU Setup (if not yet done):
    pip install torch --index-url https://download.pytorch.org/whl/cu124
    See DDLModel/GPU_SETUP.md for full instructions.
"""

import argparse
import json
import logging
import os
import sys
import time
from typing import Optional, Tuple

import numpy as np
import pandas as pd

# ── Path setup ────────────────────────────────────────────────────────────────
_THIS_DIR    = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_THIS_DIR)
sys.path.insert(0, PROJECT_ROOT)

from DDLModel.ddl_model import DeepDictionaryLearning
from DDLModel.ddl_feature_extractor import DDL_FEATURE_NAMES, N_DDL_FEATURES
from EnhancedPipeline.config import CFG

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("DDL-30-Trainer")

# ─────────────────────────────────────────────────────────────────────────────
# Column mapping: DDL feature name → CIC-IDS-2017 CSV column name
# ─────────────────────────────────────────────────────────────────────────────
# CIC-IDS-2017 column names are stripped for safety (they sometimes have spaces).
# All 30 DDL features have direct column equivalents in the 70-column CSV.

DDL_TO_CSV: dict = {
    "fwd_pkt_len_mean":    "Fwd Packet Length Mean",
    "fwd_pkt_len_std":     "Fwd Packet Length Std",
    "fwd_pkt_len_min":     "Fwd Packet Length Min",
    "fwd_pkt_len_max":     "Fwd Packet Length Max",
    "bwd_pkt_len_mean":    "Bwd Packet Length Mean",
    "bwd_pkt_len_std":     "Bwd Packet Length Std",
    "fwd_iat_mean":        "Fwd IAT Mean",
    "fwd_iat_std":         "Fwd IAT Std",
    "fwd_iat_max":         "Fwd IAT Max",
    "bwd_iat_mean":        "Bwd IAT Mean",
    "bwd_iat_std":         "Bwd IAT Std",
    "bwd_iat_max":         "Bwd IAT Max",
    "flow_bytes_per_s":    "Flow Bytes/s",
    "flow_pkts_per_s":     "Flow Packets/s",
    "fwd_bytes_per_s":     "Fwd Packets/s",   # proxy: will be scaled to bytes
    "bwd_bytes_per_s":     "Bwd Packets/s",   # proxy
    "pkt_len_variance":    "Packet Length Variance",
    "pkt_len_mean":        "Packet Length Mean",
    "syn_flag_count":      "SYN Flag Count",
    "ack_flag_count":      "ACK Flag Count",
    "fin_flag_count":      "FIN Flag Count",
    "rst_flag_count":      "RST Flag Count",
    "psh_flag_count":      "PSH Flag Count",
    "urg_flag_count":      "URG Flag Count",
    "total_fwd_bytes":     "Total Length of Fwd Packets",
    "total_bwd_bytes":     "Total Length of Bwd Packets",
    "flow_duration":       "Flow Duration",
    "init_win_fwd":        "Init_Win_bytes_forward",
    "init_win_bwd":        "Init_Win_bytes_backward",
    "down_up_ratio":       "Down/Up Ratio",
}

# Verify all 30 DDL features are mapped
assert len(DDL_TO_CSV) == N_DDL_FEATURES, (
    f"Mapping mismatch: expected {N_DDL_FEATURES}, got {len(DDL_TO_CSV)}"
)


# ─────────────────────────────────────────────────────────────────────────────

def load_and_map_csv(
    csv_path: str,
    label_col: str = "Label",
    normal_label: str = "Normal",
    max_rows: Optional[int] = None,
    normal_only: bool = False,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Load a CIC-IDS-2017 CSV and extract the 30 DDL features.

    Parameters
    ----------
    csv_path     : path to the CSV file
    label_col    : name of the label column
    normal_label : value of the normal/benign label
    max_rows     : cap total rows loaded (useful for fast debug runs)
    normal_only  : if True, return only normal-labelled rows

    Returns
    -------
    X       : np.ndarray shape (N, 30)  — feature matrix
    y       : np.ndarray shape (N,)     — 0=Normal, 1=Anomaly
    is_norm : np.ndarray shape (N,)     — boolean mask for normal rows
    """
    logger.info(f"Reading {csv_path} ...")
    nrows = max_rows if max_rows else None
    df = pd.read_csv(csv_path, nrows=nrows, low_memory=False)
    logger.info(f"  Loaded {len(df):,} rows × {len(df.columns)} columns")

    # Strip whitespace from column names (common issue in CIC CSVs)
    df.columns = df.columns.str.strip()

    # Build label vector
    if label_col not in df.columns:
        raise ValueError(f"Label column '{label_col}' not found. "
                         f"Available: {list(df.columns[:10])}...")
    y_raw = df[label_col].str.strip()
    is_norm = (y_raw.str.lower() == normal_label.lower()).values
    y = (~is_norm).astype(int)   # 0=Normal, 1=Anomaly

    # Build 30-feature matrix in canonical DDL order
    col_order = [DDL_TO_CSV[name] for name in DDL_FEATURE_NAMES]
    missing = [c for c in col_order if c not in df.columns]
    if missing:
        raise ValueError(
            f"CSV is missing required columns: {missing}\n"
            f"Available columns: {list(df.columns)}"
        )

    X = df[col_order].values.astype(np.float64)
    X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=-1e9)
    X = np.clip(X, -1e9, 1e9)

    n_normal  = int(np.sum(is_norm))
    n_anomaly = int(np.sum(~is_norm))
    logger.info(f"  Normal={n_normal:,}  Anomaly={n_anomaly:,}  Total={len(X):,}")

    if normal_only:
        return X[is_norm], y[is_norm], is_norm[is_norm]

    return X, y, is_norm


def evaluate(ddl: DeepDictionaryLearning,
             X: np.ndarray, y: np.ndarray) -> dict:
    """
    Evaluate DDL on a labelled dataset.  Returns precision, recall, F1, accuracy.
    """
    from sklearn.metrics import (
        precision_score, recall_score, f1_score,
        accuracy_score, confusion_matrix, roc_auc_score,
    )

    result = ddl.predict(X)
    preds  = np.array([1 if lbl == "Anomaly" else 0 for lbl in result["labels"]])

    cm = confusion_matrix(y, preds, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

    metrics = {
        "accuracy":  round(float(accuracy_score(y, preds)), 4),
        "precision": round(float(precision_score(y, preds, zero_division=0)), 4),
        "recall":    round(float(recall_score(y, preds, zero_division=0)), 4),
        "f1":        round(float(f1_score(y, preds, zero_division=0)), 4),
        "TP": int(tp), "TN": int(tn), "FP": int(fp), "FN": int(fn),
        "threshold": round(float(ddl.threshold_), 6),
    }

    try:
        scores = result["scores"] if isinstance(result["scores"], np.ndarray) \
                 else np.array([result["scores"]])
        metrics["roc_auc"] = round(float(roc_auc_score(y, scores)), 4)
    except Exception:
        metrics["roc_auc"] = None

    return metrics


# ─────────────────────────────────────────────────────────────────────────────

def train_ddl_enhanced(
    train_csv:   str,
    test_csv:    Optional[str],
    ddl_output:  str,
    if_output:   str,
    n_atoms_l1:  int = CFG.DDL_N_ATOMS_L1,
    n_atoms_l2:  int = CFG.DDL_N_ATOMS_L2,
    n_epochs:    int = CFG.DDL_EPOCHS,
    batch_size:  int = CFG.DDL_BATCH_SIZE,
    threshold_pct: int = CFG.DDL_THRESHOLD_PCT,
    max_train_rows: Optional[int] = None,
    max_test_rows:  Optional[int] = None,
    use_gpu: bool = False,
) -> dict:

    os.makedirs(os.path.dirname(ddl_output),  exist_ok=True)
    os.makedirs(os.path.dirname(if_output),   exist_ok=True)

    # ── Load training data ────────────────────────────────────────────────────
    logger.info("=== STAGE 1: Loading training data ===")
    X_train_all, _, is_norm_train = load_and_map_csv(
        train_csv, max_rows=max_train_rows
    )
    X_normal = X_train_all[is_norm_train]
    logger.info(f"Training DDL on {len(X_normal):,} normal samples × {N_DDL_FEATURES} features")

    # ── Train DDL ─────────────────────────────────────────────────────────────
    logger.info("=== STAGE 2: Training Deep Dictionary Learning model ===")
    if use_gpu:
        logger.info("GPU mode requested — will use CUDA if available (see DDLModel/GPU_SETUP.md)")
        logger.info("  Recommended: --batch-size 512 for GPU efficiency")
    t0 = time.time()
    ddl = DeepDictionaryLearning(
        n_features=N_DDL_FEATURES,
        n_atoms_l1=n_atoms_l1,
        n_atoms_l2=n_atoms_l2,
        n_epochs=n_epochs,
        batch_size=batch_size,
        threshold_percentile=threshold_pct,
        use_gpu=use_gpu,
    )
    ddl.fit(X_normal)
    ddl_train_time = time.time() - t0
    logger.info(f"DDL training complete in {ddl_train_time:.1f}s | threshold={ddl.threshold_:.6f}")
    ddl.save(ddl_output)
    logger.info(f"DDL model saved → {ddl_output}")

    # ── Train Isolation Forest ────────────────────────────────────────────────
    logger.info("=== STAGE 3: Training Isolation Forest ===")
    try:
        from EnhancedPipeline.if_second_vote import IsolationForestVoter
        t1 = time.time()
        if_voter = IsolationForestVoter(
            n_estimators=CFG.IF_N_ESTIMATORS,
            contamination=CFG.IF_CONTAMINATION,
        )
        if_voter.fit(X_normal)
        if_train_time = time.time() - t1
        if_voter.save(if_output)
        logger.info(f"Isolation Forest saved → {if_output} ({if_train_time:.1f}s)")
        if_trained = True
    except Exception as exc:
        logger.warning(f"Isolation Forest training failed: {exc}")
        if_trained = False
        if_train_time = 0.0

    # ── Evaluate on test set ──────────────────────────────────────────────────
    test_metrics = {}
    if test_csv:
        logger.info("=== STAGE 4: Evaluating on test set ===")
        X_test, y_test, _ = load_and_map_csv(test_csv, max_rows=max_test_rows)
        test_metrics = evaluate(ddl, X_test, y_test)
        logger.info("DDL Test Results:")
        logger.info(f"  Accuracy:  {test_metrics['accuracy']}")
        logger.info(f"  Precision: {test_metrics['precision']}")
        logger.info(f"  Recall:    {test_metrics['recall']}")
        logger.info(f"  F1:        {test_metrics['f1']}")
        logger.info(f"  TP={test_metrics['TP']}  TN={test_metrics['TN']}  "
                    f"FP={test_metrics['FP']}  FN={test_metrics['FN']}")
        if test_metrics.get("roc_auc"):
            logger.info(f"  ROC-AUC:   {test_metrics['roc_auc']}")

    # ── Write report ──────────────────────────────────────────────────────────
    report = {
        "model": "Deep Dictionary Learning (30 features)",
        "n_features": N_DDL_FEATURES,
        "feature_names": DDL_FEATURE_NAMES,
        "feature_to_csv_column": DDL_TO_CSV,
        "training": {
            "train_csv":         train_csv,
            "n_normal_samples":  len(X_normal),
            "n_atoms_l1":        n_atoms_l1,
            "n_atoms_l2":        n_atoms_l2,
            "n_epochs":          n_epochs,
            "batch_size":        batch_size,
            "threshold_pct":     threshold_pct,
            "threshold_learned": float(ddl.threshold_),
            "training_time_s":   round(ddl_train_time, 2),
            "device":            ddl.device,
        },
        "isolation_forest": {
            "trained":          if_trained,
            "training_time_s":  round(if_train_time, 2),
            "n_estimators":     CFG.IF_N_ESTIMATORS,
            "contamination":    CFG.IF_CONTAMINATION,
        },
        "test_metrics": test_metrics,
        "outputs": {
            "ddl_model": ddl_output,
            "if_model":  if_output if if_trained else None,
        },
    }

    report_path = os.path.join(os.path.dirname(ddl_output), "train_report.json")
    with open(report_path, "w") as fh:
        json.dump(report, fh, indent=2)
    logger.info(f"Training report saved → {report_path}")

    return report


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train 30-feature DDL + Isolation Forest on CIC-IDS-2017 CSV"
    )
    parser.add_argument(
        "--train", required=True,
        help="Path to TRAIN CSV (e.g. dataset/TRAIN_Traffic.csv)"
    )
    parser.add_argument(
        "--test", default=None,
        help="Path to TEST CSV for evaluation (optional)"
    )
    parser.add_argument(
        "--ddl-output", default=os.path.join(PROJECT_ROOT, "models", "ddl_30feat.pkl"),
        help="Output path for DDL model (default: models/ddl_30feat.pkl)"
    )
    parser.add_argument(
        "--if-output", default=os.path.join(PROJECT_ROOT, "models", "isolation_forest.pkl"),
        help="Output path for Isolation Forest (default: models/isolation_forest.pkl)"
    )
    parser.add_argument("--atoms-l1",  type=int, default=CFG.DDL_N_ATOMS_L1)
    parser.add_argument("--atoms-l2",  type=int, default=CFG.DDL_N_ATOMS_L2)
    parser.add_argument("--epochs",    type=int, default=CFG.DDL_EPOCHS)
    parser.add_argument("--batch-size",type=int, default=CFG.DDL_BATCH_SIZE)
    parser.add_argument("--threshold-pct", type=int, default=CFG.DDL_THRESHOLD_PCT)
    parser.add_argument(
        "--gpu", action="store_true", default=False,
        help="Use CUDA GPU for training (auto-selects most-free GPU). "
             "Requires: pip install torch --index-url https://download.pytorch.org/whl/cu124. "
             "See DDLModel/GPU_SETUP.md. Recommended batch-size: 512."
    )
    parser.add_argument(
        "--max-train-rows", type=int, default=None,
        help="Limit rows read from train CSV (useful for quick debug runs)"
    )
    parser.add_argument(
        "--max-test-rows", type=int, default=None,
        help="Limit rows read from test CSV"
    )
    args = parser.parse_args()

    # GPU tip
    if args.gpu and args.batch_size < 256:
        logger.warning(
            "GPU mode with batch_size=%d is suboptimal. "
            "Consider --batch-size 512 for GPU efficiency.", args.batch_size
        )

    report = train_ddl_enhanced(
        train_csv=args.train,
        test_csv=args.test,
        ddl_output=args.ddl_output,
        if_output=args.if_output,
        n_atoms_l1=args.atoms_l1,
        n_atoms_l2=args.atoms_l2,
        n_epochs=args.epochs,
        batch_size=args.batch_size,
        threshold_pct=args.threshold_pct,
        max_train_rows=args.max_train_rows,
        max_test_rows=args.max_test_rows,
        use_gpu=args.gpu,
    )

    print("\n" + "=" * 55)
    print("TRAINING COMPLETE")
    print(f"  DDL model   : {report['outputs']['ddl_model']}")
    print(f"  IF  model   : {report['outputs']['if_model']}")
    if report["test_metrics"]:
        m = report["test_metrics"]
        print(f"  F1          : {m['f1']}")
        print(f"  Precision   : {m['precision']}")
        print(f"  Recall      : {m['recall']}")
        print(f"  Accuracy    : {m['accuracy']}")
        if m.get("roc_auc"):
            print(f"  ROC-AUC     : {m['roc_auc']}")
    print("=" * 55)
