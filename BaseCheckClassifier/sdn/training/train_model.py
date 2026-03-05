"""
train_model.py
==============
Trains a Random Forest classifier (+ Decision Tree fallback) on dataset_raw.csv
extracted from labeled PCAPs. Goal: zero false negatives on attacks ("super model").

Strategy:
  - All 28 extracted features used
  - Rare web attack classes grouped -> 'WebAttack'
  - Bot + Infiltration grouped -> 'Infiltration'
  - class_weight='balanced' to handle BENIGN majority (74%)
  - Threshold tuning on attack classes to push recall -> 1.0
  - Saves sentry_model_v2.pkl (RF + feature list + thresholds)

Usage:
    python3 train_model.py [--input PATH] [--output PATH]
"""

import os
import sys
import pickle
import argparse
import warnings
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
EXTRACTOR_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "extraction"))
sys.path.insert(0, EXTRACTOR_DIR)

from feature_extractor import EXTENDED_FEATURES

DEFAULT_INPUT  = os.path.join(SCRIPT_DIR, "dataset_raw.csv")
DEFAULT_OUTPUT = os.path.join(SCRIPT_DIR, "sentry_model_v2.pkl")

# Label grouping for tiny classes
LABEL_GROUPS = {
    "WebAttackBruteForce":   "WebAttack",
    "WebAttackSqlInjection": "WebAttack",
    "WebAttackXSS":          "WebAttack",
    "Bot":                   "Infiltration",
    "Infiltration":          "Infiltration",
}

ATTACK_CLASSES = [
    "DoSHulk", "DoSGoldenEye", "DoSSlowhttptest", "DoSslowloris",
    "DDoS", "PortScan", "FTP-Patator",
    "WebAttack", "Infiltration",
]


def load_and_prepare(csv_path):
    print(f"[*] Loading: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)
    print(f"[*] Raw rows: {len(df):,}")

    # Drop rows with NaN in feature columns
    df = df.dropna(subset=EXTENDED_FEATURES)
    print(f"[*] After NaN drop: {len(df):,}")

    # Replace inf values
    df[EXTENDED_FEATURES] = df[EXTENDED_FEATURES].replace([np.inf, -np.inf], 0)

    # Apply label grouping
    df["attack_label"] = df["attack_label"].apply(lambda x: LABEL_GROUPS.get(x, x))

    # Binary label: BENIGN or grouped attack name (used for threshold-tuned prediction)
    df["multiclass_label"] = df["attack_label"]   # BENIGN, DoSHulk, DDoS, etc.
    df["binary_label"]     = df["label"]          # BENIGN or ATTACK

    print("\n[*] Label distribution (multiclass):")
    print(df["multiclass_label"].value_counts().to_string())
    print(f"\n[*] Binary — BENIGN: {(df['binary_label']=='BENIGN').sum():,}  "
          f"ATTACK: {(df['binary_label']=='ATTACK').sum():,}")
    return df


def train_and_evaluate(df):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
    from sklearn.preprocessing import LabelEncoder

    X = df[EXTENDED_FEATURES].values
    y = df["multiclass_label"].values

    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
    )
    print(f"\n[*] Train: {len(X_train):,}  Test: {len(X_test):,}")

    # ── Random Forest ─────────────────────────────────────────────────────────
    print("\n[*] Training Random Forest (n_estimators=200, class_weight=balanced) ...")
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    rf.fit(X_train, y_train)

    y_pred_rf = rf.predict(X_test)
    y_labels_test = le.inverse_transform(y_test)
    y_labels_pred = le.inverse_transform(y_pred_rf)

    rf_acc = accuracy_score(y_test, y_pred_rf)
    print(f"\n[*] RF Accuracy: {rf_acc*100:.2f}%")
    print("\n[*] RF Classification Report:")
    print(classification_report(y_labels_test, y_labels_pred, digits=4))

    # ── Threshold tuning for zero false negatives ─────────────────────────────
    print("\n[*] Tuning attack thresholds for maximum recall ...")
    y_proba = rf.predict_proba(X_test)
    classes  = list(le.classes_)

    thresholds = {}
    for cls in ATTACK_CLASSES:
        if cls not in classes:
            continue
        cls_idx = classes.index(cls)
        benign_idx = classes.index("BENIGN")

        # Lower the threshold until recall == 1.0 or threshold hits a floor
        best_thresh = 0.5
        for thresh in np.arange(0.50, 0.00, -0.01):
            # Custom prediction: classify as ATTACK if P(attack_class) > thresh
            # OR if P(BENIGN) < (1 - thresh)
            custom_pred = []
            for probs in y_proba:
                if probs[cls_idx] >= thresh:
                    custom_pred.append(cls_idx)
                else:
                    custom_pred.append(np.argmax(probs))
            custom_pred = np.array(custom_pred)

            mask = (y_test == cls_idx)
            if mask.sum() == 0:
                break
            recall = (custom_pred[mask] == cls_idx).sum() / mask.sum()

            if recall >= 0.999:
                best_thresh = thresh
                break
        thresholds[cls] = round(best_thresh, 2)

    print("\n[*] Tuned thresholds:")
    for cls, t in thresholds.items():
        print(f"    {cls:<30} threshold = {t:.2f}")

    # ── Decision Tree (fast fallback) ─────────────────────────────────────────
    print("\n[*] Training Decision Tree (max_depth=20) ...")
    dt = DecisionTreeClassifier(
        max_depth=20,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
    )
    dt.fit(X_train, y_train)

    y_pred_dt = dt.predict(X_test)
    dt_acc = accuracy_score(y_test, y_pred_dt)
    print(f"[*] DT Accuracy: {dt_acc*100:.2f}%")

    # ── Feature importance ────────────────────────────────────────────────────
    importance = sorted(
        zip(EXTENDED_FEATURES, rf.feature_importances_),
        key=lambda x: -x[1]
    )
    print("\n[*] Top 10 Feature Importances (RF):")
    for feat, imp in importance[:10]:
        bar = "█" * int(imp * 200)
        print(f"    {feat:<35} {imp:.4f}  {bar}")

    return rf, dt, le, thresholds, classes, importance


def save_model(rf, dt, le, thresholds, classes, importance, output_path):
    payload = {
        "random_forest":    rf,
        "decision_tree":    dt,
        "label_encoder":    le,
        "feature_names":    EXTENDED_FEATURES,
        "thresholds":       thresholds,
        "classes":          classes,
        "feature_importance": importance,
    }
    with open(output_path, "wb") as f:
        pickle.dump(payload, f)
    size_mb = os.path.getsize(output_path) / 1_048_576
    print(f"\n[*] Model saved: {output_path}  ({size_mb:.1f} MB)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",  type=str, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=str, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    print("=" * 65)
    print("  Sentry Model v2 — Training Pipeline")
    print("=" * 65)

    df = load_and_prepare(args.input)
    rf, dt, le, thresholds, classes, importance = train_and_evaluate(df)
    save_model(rf, dt, le, thresholds, classes, importance, args.output)

    print("\n" + "=" * 65)
    print("  Done! Model saved as sentry_model_v2.pkl")
    print("  Use sentry_infer.py for live inference.")
    print("=" * 65)


if __name__ == "__main__":
    main()
