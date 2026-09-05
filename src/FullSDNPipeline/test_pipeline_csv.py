#!/usr/bin/env python3
"""
test_pipeline_csv.py — Evaluate Full Two-Stage Pipeline on CIC-IDS-2017 CSV
============================================================================
Tests BCC v2 (28 features) → DDL + IF (40 features) on the test CSV.
Produces confusion matrix and per-stage statistics.

Usage:
    cd /scratch1/.../e20-4yp-.../
    source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate
    python FullSDNPipeline/test_pipeline_csv.py
"""
import os
import sys
import json
import time
import logging
import argparse
import numpy as np
import pandas as pd
from sklearn.metrics import (
    confusion_matrix, accuracy_score, precision_score,
    recall_score, f1_score, classification_report
)

# Path setup
_THIS_DIR    = os.path.dirname(os.path.abspath(__file__))
SRC_ROOT     = os.path.dirname(_THIS_DIR)
PROJECT_ROOT = os.path.dirname(SRC_ROOT)
sys.path.insert(0, SRC_ROOT)

from DDLModel.ddl_model import DeepDictionaryLearning
from DDLModel.ddl_feature_extractor import DDL_FEATURE_NAMES, N_DDL_FEATURES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("PipelineTest")

# ── BCC v2 feature names (28) — same order as training ──
BCC_V2_FEATURE_NAMES = [
    'Packet Length Variance', 'Fwd Packet Length Max', 'Fwd Header Length',
    'Init_Win_bytes_forward', 'Bwd Header Length',
    'Total Length of Fwd Packets', 'Init_Win_bytes_backward',
    'Bwd Packets/s', 'Flow IAT Min', 'Fwd IAT Min', 'Flow Bytes/s',
    'Active Min', 'Bwd IAT Total', 'Flow IAT Max', 'Flow Duration',
    'Total Fwd Packets', 'Total Backward Packets', 'Fwd Packet Length Mean',
    'Bwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Flow IAT Mean', 'Flow IAT Std',
    'Fwd IAT Total', 'Fwd Packets/s', 'Down/Up Ratio',
    'SYN Flag Count', 'RST Flag Count',
]

# ── DDL CSV column mapping (40 features) ──
DDL_TO_CSV = {
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
    "fwd_bytes_per_s":     "Fwd Packets/s",
    "bwd_bytes_per_s":     "Bwd Packets/s",
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
    "bwd_pkt_len_min":     "Bwd Packet Length Min",
    "bwd_pkt_len_max":     "Bwd Packet Length Max",
    "flow_iat_mean":       "Flow IAT Mean",
    "flow_iat_std":        "Flow IAT Std",
    "fwd_iat_total":       "Fwd IAT Total",
    "bwd_iat_min":         "Bwd IAT Min",
    "fwd_pkts_per_s":      "Fwd Packets/s",
    "bwd_pkts_per_s":      "Bwd Packets/s",
    "fwd_header_len":      "Fwd Header Length",
    "active_min":          "Active Min",
}


def main():
    parser = argparse.ArgumentParser(description="Test two-stage pipeline on CSV")
    parser.add_argument("--test-csv", default=os.path.join(PROJECT_ROOT, "dataset", "TEST_Traffic.csv"))
    parser.add_argument("--bcc-model", default=os.path.join(PROJECT_ROOT, "models", "sentry_model_v2.pkl"))
    parser.add_argument("--ddl-model", default=os.path.join(PROJECT_ROOT, "models", "ddl_40feat.pkl"))
    parser.add_argument("--if-model", default=os.path.join(PROJECT_ROOT, "models", "isolation_forest.pkl"))
    parser.add_argument("--max-rows", type=int, default=None, help="Limit test rows")
    parser.add_argument("--output", default=os.path.join(PROJECT_ROOT, "logs", "pipeline_test_results.json"))
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    # ── Load models ──
    import joblib

    logger.info("Loading BCC v2 model...")
    bcc_data = joblib.load(args.bcc_model)
    if isinstance(bcc_data, dict):
        bcc_model = bcc_data['model']
        bcc_threshold = bcc_data.get('threshold', 0.5)
        bcc_feature_names = bcc_data.get('feature_names', BCC_V2_FEATURE_NAMES)
        logger.info(f"  BCC loaded: {type(bcc_model).__name__}, threshold={bcc_threshold}")
    else:
        bcc_model = bcc_data
        bcc_threshold = 0.5
        bcc_feature_names = BCC_V2_FEATURE_NAMES
        logger.info(f"  BCC loaded: {type(bcc_model).__name__}")

    logger.info("Loading DDL model...")
    ddl = DeepDictionaryLearning.load(args.ddl_model)
    logger.info(f"  DDL loaded: {ddl.n_features} features, threshold={ddl.threshold_:.6f}")

    if_voter = None
    if os.path.exists(args.if_model):
        logger.info("Loading Isolation Forest...")
        if_data = joblib.load(args.if_model)
        if isinstance(if_data, dict):
            if_voter = if_data['clf']
        else:
            if_voter = if_data
        logger.info(f"  IF loaded: {type(if_voter).__name__}")

    # ── Load test data ──
    logger.info(f"Loading test CSV: {args.test_csv}")
    df = pd.read_csv(args.test_csv, nrows=args.max_rows, low_memory=False)
    df.columns = df.columns.str.strip()
    logger.info(f"  Loaded {len(df):,} rows x {len(df.columns)} columns")

    # Labels
    y_true_str = df["Label"].str.strip()
    is_normal = y_true_str.str.lower().isin(["normal", "benign"])
    y_true = (~is_normal).astype(int)  # 0=Normal, 1=Attack
    logger.info(f"  Normal={is_normal.sum():,}  Attack={(~is_normal).sum():,}")

    # ── Extract BCC-28 features ──
    # Handle column name aliases (BCC model names vs CIC-IDS CSV names)
    COLUMN_ALIASES = {
        'Total Bwd Packets': 'Total Backward Packets',
        'Total Fwd Packets': 'Total Fwd Packets',
    }
    logger.info("Extracting BCC-28 features from CSV...")
    bcc_cols_resolved = []
    for name in bcc_feature_names:
        if name in df.columns:
            bcc_cols_resolved.append(name)
        elif name in COLUMN_ALIASES and COLUMN_ALIASES[name] in df.columns:
            # Rename the CSV column to match BCC's expected name
            df[name] = df[COLUMN_ALIASES[name]]
            bcc_cols_resolved.append(name)
            logger.info(f"  Aliased: '{COLUMN_ALIASES[name]}' → '{name}'")
        else:
            logger.warning(f"  Missing BCC column: {name} (filling with 0)")
            df[name] = 0.0
            bcc_cols_resolved.append(name)
    X_bcc = df[bcc_cols_resolved].values.astype(np.float64)
    X_bcc = np.nan_to_num(X_bcc, nan=0.0, posinf=1e9, neginf=-1e9)

    # ── Extract DDL-40 features ──
    logger.info("Extracting DDL-40 features from CSV...")
    ddl_col_order = [DDL_TO_CSV[name] for name in DDL_FEATURE_NAMES]
    ddl_cols_available = [c for c in ddl_col_order if c in df.columns]
    X_ddl = df[ddl_col_order].values.astype(np.float64)
    X_ddl = np.nan_to_num(X_ddl, nan=0.0, posinf=1e9, neginf=-1e9)
    X_ddl = np.clip(X_ddl, -1e9, 1e9)

    # ── Run two-stage pipeline ──
    logger.info("=" * 60)
    logger.info("Running Two-Stage Pipeline Evaluation")
    logger.info("=" * 60)

    n = len(df)
    pipeline_decisions = np.zeros(n, dtype=int)  # 0=FORWARD, 1=DROP
    stage_used = np.zeros(n, dtype=int)  # 1=BCC, 2=DDL

    # Stage 1: BCC
    t0 = time.time()
    try:
        bcc_proba = bcc_model.predict_proba(X_bcc)[:, 1]
    except Exception:
        bcc_pred = bcc_model.predict(X_bcc)
        bcc_proba = np.where(bcc_pred == 1, 1.0, 0.0)
    bcc_time = time.time() - t0

    bcc_flagged = bcc_proba >= bcc_threshold  # True = flagged as attack
    bcc_benign = ~bcc_flagged
    n_bcc_benign = int(bcc_benign.sum())
    n_bcc_attack = int(bcc_flagged.sum())

    # BCC passes → FORWARD
    pipeline_decisions[bcc_benign] = 0
    stage_used[bcc_benign] = 1

    logger.info(f"Stage 1 (BCC): BENIGN={n_bcc_benign:,}  ATTACK(to DDL)={n_bcc_attack:,}  ({bcc_time:.2f}s)")

    # Stage 2: DDL + IF on flagged flows
    t1 = time.time()
    if n_bcc_attack > 0:
        X_ddl_flagged = X_ddl[bcc_flagged]
        ddl_result = ddl.predict(X_ddl_flagged)
        ddl_labels = np.array([1 if l == "Anomaly" else 0 for l in ddl_result["labels"]])

        if if_voter is not None:
            if_pred = if_voter.predict(X_ddl_flagged)
            # IF returns -1=anomaly, 1=normal → convert: -1→1, 1→0
            if_labels = np.where(if_pred == -1, 1, 0)
            # Consensus: DROP only when BOTH agree
            consensus = (ddl_labels == 1) & (if_labels == 1)
            flagged_decisions = np.where(consensus, 1, 0)
        else:
            flagged_decisions = ddl_labels

        pipeline_decisions[bcc_flagged] = flagged_decisions
        stage_used[bcc_flagged] = 2

        n_ddl_drop = int(flagged_decisions.sum())
        n_ddl_forward = n_bcc_attack - n_ddl_drop
        logger.info(f"Stage 2 (DDL+IF): FORWARD={n_ddl_forward:,}  DROP={n_ddl_drop:,}")
    ddl_time = time.time() - t1

    # ── Compute confusion matrix ──
    logger.info("=" * 60)
    logger.info("CONFUSION MATRIX — Full Two-Stage Pipeline")
    logger.info("=" * 60)

    cm = confusion_matrix(y_true, pipeline_decisions, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

    accuracy  = accuracy_score(y_true, pipeline_decisions)
    precision = precision_score(y_true, pipeline_decisions, zero_division=0)
    recall    = recall_score(y_true, pipeline_decisions, zero_division=0)
    f1        = f1_score(y_true, pipeline_decisions, zero_division=0)

    print("\n" + "=" * 60)
    print("  Full Pipeline Confusion Matrix (Two-Stage)")
    print("=" * 60)
    print(f"                     Predicted")
    print(f"                  FORWARD   DROP")
    print(f"  Actual Normal    {tn:>7d}   {fp:>5d}")
    print(f"  Actual Attack    {fn:>7d}   {tp:>5d}")
    print()
    print(f"  Accuracy:   {accuracy:.4f}")
    print(f"  Precision:  {precision:.4f}")
    print(f"  Recall:     {recall:.4f}")
    print(f"  F1 Score:   {f1:.4f}")
    print(f"  FPR:        {fp/(fp+tn):.4f}" if (fp+tn) > 0 else "")
    print(f"  FNR:        {fn/(fn+tp):.4f}" if (fn+tp) > 0 else "")
    print()
    print(f"  Stage 1 (BCC):  {n_bcc_benign:,} FORWARD, {n_bcc_attack:,} → Stage 2  ({bcc_time:.2f}s)")
    if n_bcc_attack > 0:
        print(f"  Stage 2 (DDL):  {n_ddl_forward:,} FORWARD, {n_ddl_drop:,} DROP   ({ddl_time:.2f}s)")
    print()
    if fn > 0:
        print(f"  ⚠️  {fn} attack flows leaked through (FN)")
    else:
        print(f"  ✅ ZERO LEAKS!")
    if fp > 0:
        print(f"  ⚠️  {fp} normal flows falsely dropped (FP)")
    else:
        print(f"  ✅ ZERO FALSE POSITIVES!")
    print("=" * 60)

    # ── Save results ──
    results = {
        "test_csv": args.test_csv,
        "n_rows": n,
        "n_normal": int(is_normal.sum()),
        "n_attack": int((~is_normal).sum()),
        "pipeline": {
            "stage1_bcc": {
                "benign_forward": n_bcc_benign,
                "attack_to_ddl": n_bcc_attack,
                "latency_s": round(bcc_time, 4),
            },
            "stage2_ddl_if": {
                "forward": n_ddl_forward if n_bcc_attack > 0 else 0,
                "drop": n_ddl_drop if n_bcc_attack > 0 else 0,
                "latency_s": round(ddl_time, 4),
            },
        },
        "confusion_matrix": {
            "TP": int(tp), "TN": int(tn),
            "FP": int(fp), "FN": int(fn),
        },
        "metrics": {
            "accuracy": round(accuracy, 6),
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
            "fpr": round(fp/(fp+tn), 6) if (fp+tn) > 0 else 0,
            "fnr": round(fn/(fn+tp), 6) if (fn+tp) > 0 else 0,
        },
        "models": {
            "bcc": args.bcc_model,
            "ddl": args.ddl_model,
            "if": args.if_model,
            "ddl_threshold": float(ddl.threshold_),
        },
    }

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    logger.info(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
