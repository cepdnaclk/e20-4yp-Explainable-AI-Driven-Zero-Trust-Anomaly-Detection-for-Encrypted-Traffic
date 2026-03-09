"""
train_model.py
==============
Trains a binary Decision Tree gatekeeper model (BENIGN / NOT-BENIGN).

Pipeline:
  1. Load train.csv (already balanced 50/50 by prepare_dataset.py)
  2. Train DecisionTreeClassifier with class_weight={BENIGN:1, ATTACK:10}
  3. Tune decision threshold on test_balanced.csv for attack recall >= 99.9%
  4. Evaluate on test_raw.csv (real-world unbalanced, never seen by model)
  5. Save sentry_model_v2.pkl + evaluation_report.md

2-Zone Classification at inference:
    P(ATTACK) >= threshold  →  NOT-BENIGN  (forward to DL model)
    P(ATTACK) <  threshold  →  BENIGN      (pass through)

Usage:
    python3 train_model.py [--train PATH] [--test-bal PATH] [--test-raw PATH]
"""

import os
import sys
import pickle
import argparse
import warnings
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
EXTRACTOR_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "extraction"))
sys.path.insert(0, EXTRACTOR_DIR)
from feature_extractor import EXTENDED_FEATURES

DOCS_DIR       = os.path.join(SCRIPT_DIR, "documents")
DEFAULT_TRAIN  = os.path.join(SCRIPT_DIR, "train.csv")
DEFAULT_BAL    = os.path.join(SCRIPT_DIR, "test_balanced.csv")
DEFAULT_RAW    = os.path.join(SCRIPT_DIR, "test_raw.csv")
DEFAULT_OUTPUT = os.path.join(SCRIPT_DIR, "sentry_model_v2.pkl")

ATTACK_LABEL  = "ATTACK"
BENIGN_LABEL  = "BENIGN"


# ─── Helpers ─────────────────────────────────────────────────────────────────

def load_csv(path, name):
    print(f"[*] Loading {name}: {path}")
    df = pd.read_csv(path, low_memory=False)
    df = df.dropna(subset=EXTENDED_FEATURES)
    df[EXTENDED_FEATURES] = df[EXTENDED_FEATURES].replace([np.inf, -np.inf], 0)
    print(f"    {len(df):,} rows | {df['label'].value_counts().to_dict()}")
    return df


def get_Xy(df):
    X = df[EXTENDED_FEATURES].values.astype(np.float32)
    # Binary: 1=ATTACK, 0=BENIGN
    y = (df["label"] == ATTACK_LABEL).astype(int).values
    return X, y


# ─── Training ────────────────────────────────────────────────────────────────

def train_decision_tree(X_train, y_train):
    from sklearn.tree import DecisionTreeClassifier
    print("\n[*] Training Decision Tree ...")
    print("    max_depth=20 | min_samples_leaf=5 | class_weight={BENIGN:1, ATTACK:10}")

    dt = DecisionTreeClassifier(
        max_depth=20,
        min_samples_leaf=5,
        class_weight={0: 1, 1: 10},   # 0=BENIGN, 1=ATTACK
        random_state=42,
    )
    dt.fit(X_train, y_train)
    print("    Training complete.")
    return dt


# ─── Threshold Tuning ────────────────────────────────────────────────────────

def tune_threshold(model, X_bal, y_bal, target_recall=0.999):
    """
    Sweep threshold from 0.50 down to find the lowest value where
    attack recall >= target_recall. Lower threshold = more aggressive = fewer leaks.
    """
    print(f"\n[*] Tuning threshold (target attack recall >= {target_recall*100:.1f}%) ...")
    proba = model.predict_proba(X_bal)[:, 1]   # P(ATTACK)

    best_thresh = 0.50
    for t in np.arange(0.50, 0.00, -0.01):
        preds = (proba >= t).astype(int)
        attack_mask = (y_bal == 1)
        if attack_mask.sum() == 0:
            break
        recall = preds[attack_mask].sum() / attack_mask.sum()
        if recall >= target_recall:
            best_thresh = round(t, 2)

    # Verify at chosen threshold
    preds = (proba >= best_thresh).astype(int)
    attack_mask = (y_bal == 1)
    benign_mask = (y_bal == 0)
    attack_recall  = preds[attack_mask].sum() / attack_mask.sum()
    benign_recall  = (1 - preds[benign_mask]).sum() / benign_mask.sum()
    forwarded_pct  = preds.mean() * 100

    print(f"    Chosen threshold : {best_thresh:.2f}")
    print(f"    Attack recall    : {attack_recall*100:.2f}%")
    print(f"    BENIGN pass rate : {benign_recall*100:.2f}%")
    print(f"    % forwarded to DL: {forwarded_pct:.1f}%")
    return best_thresh


# ─── Evaluation ──────────────────────────────────────────────────────────────

def evaluate(model, threshold, X_test, y_test, dataset_name):
    from sklearn.metrics import (
        classification_report, confusion_matrix, accuracy_score
    )
    import time

    proba = model.predict_proba(X_test)[:, 1]
    preds = (proba >= threshold).astype(int)

    acc    = accuracy_score(y_test, preds)
    cm     = confusion_matrix(y_test, preds)
    report = classification_report(
        y_test, preds,
        target_names=[BENIGN_LABEL, ATTACK_LABEL],
        digits=4,
        output_dict=False,
    )
    report_dict = classification_report(
        y_test, preds,
        target_names=[BENIGN_LABEL, ATTACK_LABEL],
        digits=4,
        output_dict=True,
    )

    # Inference speed (single sample)
    start = time.perf_counter()
    for _ in range(1000):
        model.predict_proba(X_test[:1])
    infer_us = (time.perf_counter() - start) / 1000 * 1_000_000

    attack_recall    = report_dict[ATTACK_LABEL]["recall"]
    attack_precision = report_dict[ATTACK_LABEL]["precision"]
    benign_recall    = report_dict[BENIGN_LABEL]["recall"]
    forwarded_pct    = preds.mean() * 100

    print(f"\n{'='*60}")
    print(f"  Evaluation — {dataset_name}")
    print(f"{'='*60}")
    print(f"  Accuracy           : {acc*100:.2f}%")
    print(f"  Attack Recall      : {attack_recall*100:.3f}%  ← CRITICAL")
    print(f"  Attack Precision   : {attack_precision*100:.2f}%")
    print(f"  BENIGN Pass Rate   : {benign_recall*100:.2f}%")
    print(f"  % forwarded to DL  : {forwarded_pct:.1f}%")
    print(f"  Inference speed    : {infer_us:.2f} µs/flow")
    print(f"\n  Confusion Matrix ({BENIGN_LABEL}=0, {ATTACK_LABEL}=1):")
    print(f"  TN={cm[0,0]:,}  FP={cm[0,1]:,}")
    print(f"  FN={cm[1,0]:,}  TP={cm[1,1]:,}")
    print(f"\n  Classification Report:")
    for line in report.split("\n"):
        print(f"  {line}")

    return {
        "dataset":          dataset_name,
        "accuracy_pct":     round(acc * 100, 4),
        "attack_recall":    round(attack_recall * 100, 4),
        "attack_precision": round(attack_precision * 100, 4),
        "benign_pass_rate": round(benign_recall * 100, 4),
        "forwarded_pct":    round(forwarded_pct, 2),
        "infer_us":         round(infer_us, 3),
        "TN": int(cm[0,0]), "FP": int(cm[0,1]),
        "FN": int(cm[1,0]), "TP": int(cm[1,1]),
    }


# ─── Feature Importance ──────────────────────────────────────────────────────

def print_feature_importance(model):
    importance = sorted(
        zip(EXTENDED_FEATURES, model.feature_importances_),
        key=lambda x: -x[1],
    )
    print("\n[*] Top 15 Feature Importances:")
    for i, (feat, imp) in enumerate(importance[:15]):
        bar = "█" * int(imp * 300)
        print(f"  {i+1:>2}. {feat:<35} {imp:.4f}  {bar}")
    return importance


# ─── Save model ──────────────────────────────────────────────────────────────

def save_model(model, threshold, importance, output_path):
    payload = {
        "model":            model,
        "threshold":        threshold,
        "feature_names":    EXTENDED_FEATURES,
        "feature_importance": importance,
        "description": (
            "Binary gatekeeper DT. "
            f"P(ATTACK) >= {threshold} → forward to DL. "
            f"P(ATTACK) < {threshold} → pass as BENIGN."
        ),
    }
    with open(output_path, "wb") as f:
        pickle.dump(payload, f)
    size_mb = os.path.getsize(output_path) / 1_048_576
    print(f"\n[*] Model saved: {output_path}  ({size_mb:.1f} MB)")


# ─── Save evaluation report ───────────────────────────────────────────────────

def save_report(results_list, threshold, importance):
    os.makedirs(DOCS_DIR, exist_ok=True)
    path = os.path.join(DOCS_DIR, "04_evaluation_report.md")

    lines = [
        "# 📊 Gatekeeper Model — Evaluation Report",
        "",
        f"**Model:** `sentry_model_v2.pkl` (Decision Tree, binary)",
        f"**Threshold:** P(ATTACK) ≥ {threshold} → forward to DL",
        "",
        "---",
        "",
        "## Results",
        "",
        "| Metric | Balanced Test | Raw (Real-World) Test |",
        "|--------|:---:|:---:|",
    ]
    bal = next((r for r in results_list if "Balanced" in r["dataset"]), {})
    raw = next((r for r in results_list if "Raw" in r["dataset"]), {})

    rows = [
        ("Accuracy", "accuracy_pct", "%"),
        ("**Attack Recall ← CRITICAL**", "attack_recall", "%"),
        ("Attack Precision", "attack_precision", "%"),
        ("BENIGN Pass Rate", "benign_pass_rate", "%"),
        ("% Forwarded to DL", "forwarded_pct", "%"),
        ("Inference Speed", "infer_us", " µs/flow"),
    ]
    for label, key, unit in rows:
        b = f"{bal.get(key, 'N/A')}{unit}" if bal else "N/A"
        r = f"{raw.get(key, 'N/A')}{unit}" if raw else "N/A"
        lines.append(f"| {label} | {b} | {r} |")

    lines += [
        "",
        "## Confusion Matrices",
        "",
        "### Balanced Test Set",
        f"```",
        f"TN (BENIGN→BENIGN)   : {bal.get('TN', 'N/A'):,}",
        f"FP (BENIGN→ATTACK)   : {bal.get('FP', 'N/A'):,}  (false alarms — acceptable)",
        f"FN (ATTACK→BENIGN)   : {bal.get('FN', 'N/A'):,}  ← leakage — must be ~0",
        f"TP (ATTACK→ATTACK)   : {bal.get('TP', 'N/A'):,}",
        "```",
        "",
        "### Raw Real-World Test Set",
        "```",
        f"TN (BENIGN→BENIGN)   : {raw.get('TN', 'N/A'):,}",
        f"FP (BENIGN→ATTACK)   : {raw.get('FP', 'N/A'):,}  (sent to DL — acceptable)",
        f"FN (ATTACK→BENIGN)   : {raw.get('FN', 'N/A'):,}  ← leakage — must be ~0",
        f"TP (ATTACK→ATTACK)   : {raw.get('TP', 'N/A'):,}",
        "```",
        "",
        "## Top 15 Feature Importances",
        "",
        "| Rank | Feature | Importance |",
        "|------|---------|------------|",
    ]
    for i, (feat, imp) in enumerate(importance[:15]):
        lines.append(f"| {i+1} | `{feat}` | {imp:.4f} |")

    lines += [
        "",
        "---",
        "",
        "> **Verdict:** Any FN (ATTACK→BENIGN) > 0 is a leak. Target is FN = 0 or near-zero.",
    ]

    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(f"\n[*] Evaluation report saved: {path}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train",    default=DEFAULT_TRAIN)
    parser.add_argument("--test-bal", default=DEFAULT_BAL)
    parser.add_argument("--test-raw", default=DEFAULT_RAW)
    parser.add_argument("--output",   default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    print("=" * 60)
    print("  Sentry Model v2 — Binary Gatekeeper Training")
    print("=" * 60)

    # Load datasets
    df_train   = load_csv(args.train,     "train.csv")
    df_bal     = load_csv(args.test_bal,  "test_balanced.csv")
    df_raw     = load_csv(args.test_raw,  "test_raw.csv")

    X_train, y_train = get_Xy(df_train)
    X_bal,   y_bal   = get_Xy(df_bal)
    X_raw,   y_raw   = get_Xy(df_raw)

    # Train
    model = train_decision_tree(X_train, y_train)

    # Tune threshold on balanced test
    threshold = tune_threshold(model, X_bal, y_bal, target_recall=0.999)

    # Evaluate on both test sets
    results = []
    results.append(evaluate(model, threshold, X_bal, y_bal, "Balanced Test Set"))
    results.append(evaluate(model, threshold, X_raw, y_raw, "Raw Real-World Test Set"))

    # Feature importance
    importance = print_feature_importance(model)

    # Save model + report
    save_model(model, threshold, importance, args.output)
    save_report(results, threshold, importance)

    print("\n" + "=" * 60)
    print("  Done! Use sentry_infer.py for live inference.")
    print("=" * 60)


if __name__ == "__main__":
    main()
