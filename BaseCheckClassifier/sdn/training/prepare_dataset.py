"""
prepare_dataset.py
==================
Loads dataset_raw.csv (extracted from labeled PCAPs), balances it for
binary BENIGN/ATTACK classification, then splits into train, balanced-test,
and raw-test sets.

Steps:
  1. Load dataset_raw.csv
  2. Use binary 'label' column (BENIGN / ATTACK)
  3. Undersample BENIGN to match ATTACK count (no SMOTE needed)
  4. Stratified 80/20 split → train.csv + test_balanced.csv
  5. Also create test_raw.csv (fresh hold-out from unbalanced raw data)

Usage:
    python3 prepare_dataset.py [--input PATH] [--outdir PATH]

Outputs (all in outdir/):
    train.csv            — 80% of balanced data (training)
    test_balanced.csv    — 20% of balanced data (threshold tuning)
    test_raw.csv         — raw unbalanced hold-out (real-world evaluation)
"""

import os
import sys
import argparse
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
EXTRACTOR_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "extraction"))
sys.path.insert(0, EXTRACTOR_DIR)
from feature_extractor import EXTENDED_FEATURES

DEFAULT_INPUT  = os.path.join(SCRIPT_DIR, "dataset_raw.csv")
DEFAULT_OUTDIR = SCRIPT_DIR

RANDOM_SEED = 42


def load_raw(csv_path):
    print(f"[*] Loading: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)
    print(f"[*] Raw rows: {len(df):,}")

    # Drop rows with NaN or Inf in feature columns
    df = df.dropna(subset=EXTENDED_FEATURES)
    df[EXTENDED_FEATURES] = df[EXTENDED_FEATURES].replace([np.inf, -np.inf], 0)
    print(f"[*] After cleaning: {len(df):,} rows")

    # Ensure binary label column exists (BENIGN / ATTACK)
    if "label" not in df.columns:
        raise ValueError("CSV must have a 'label' column with BENIGN/ATTACK values")

    print(f"\n[*] Raw label distribution:")
    print(df["label"].value_counts().to_string())
    return df


def make_raw_test(df, test_fraction=0.10, outdir="."):
    """
    Carve out a stratified hold-out from the raw unbalanced data BEFORE
    any balancing. This represents real-world traffic distribution.
    """
    _, df_raw_test = train_test_split(
        df,
        test_size=test_fraction,
        stratify=df["label"],
        random_state=RANDOM_SEED,
    )
    path = os.path.join(outdir, "test_raw.csv")
    df_raw_test.to_csv(path, index=False)
    print(f"\n[*] test_raw.csv saved: {len(df_raw_test):,} rows")
    print(f"    {df_raw_test['label'].value_counts().to_dict()}")
    print(f"    → {path}")
    return df_raw_test.index, path


def balance(df, raw_test_idx):
    """
    Undersample BENIGN to match ATTACK count.
    Excludes rows already assigned to raw test set.
    """
    df_pool = df.drop(index=raw_test_idx)

    benign = df_pool[df_pool["label"] == "BENIGN"]
    attack = df_pool[df_pool["label"] == "ATTACK"]

    n_attack = len(attack)
    print(f"\n[*] Balancing pool:")
    print(f"    ATTACK: {n_attack:,} (keep all)")
    print(f"    BENIGN: {len(benign):,} → undersample to {n_attack:,}")

    benign_sampled = benign.sample(n=n_attack, random_state=RANDOM_SEED)
    balanced = pd.concat([attack, benign_sampled]).sample(
        frac=1, random_state=RANDOM_SEED
    ).reset_index(drop=True)

    print(f"\n[*] Balanced dataset: {len(balanced):,} rows (50% / 50%)")
    print(f"    {balanced['label'].value_counts().to_dict()}")
    return balanced


def split_train_test(df_balanced, outdir):
    """
    Stratified 80/20 split on the balanced dataset.
    train.csv → training the model
    test_balanced.csv → threshold tuning
    """
    train, test_bal = train_test_split(
        df_balanced,
        test_size=0.20,
        stratify=df_balanced["label"],
        random_state=RANDOM_SEED,
    )

    train_path    = os.path.join(outdir, "train.csv")
    test_bal_path = os.path.join(outdir, "test_balanced.csv")

    train.to_csv(train_path, index=False)
    test_bal.to_csv(test_bal_path, index=False)

    print(f"\n[*] train.csv:         {len(train):,} rows  → {train_path}")
    print(f"    {train['label'].value_counts().to_dict()}")
    print(f"\n[*] test_balanced.csv: {len(test_bal):,} rows  → {test_bal_path}")
    print(f"    {test_bal['label'].value_counts().to_dict()}")

    return train_path, test_bal_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",  default=DEFAULT_INPUT,  help="Path to dataset_raw.csv")
    parser.add_argument("--outdir", default=DEFAULT_OUTDIR, help="Output directory")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    print("=" * 60)
    print("  Dataset Preparation — Balance + Split")
    print("=" * 60)

    df = load_raw(args.input)

    # Step 1: carve out raw unbalanced test BEFORE balancing (10% of raw)
    raw_test_idx, raw_test_path = make_raw_test(df, test_fraction=0.10, outdir=args.outdir)

    # Step 2: balance remaining data (undersample BENIGN)
    df_balanced = balance(df, raw_test_idx)

    # Step 3: stratified 80/20 split on balanced data
    train_path, test_bal_path = split_train_test(df_balanced, args.outdir)

    print("\n" + "=" * 60)
    print("  Done! Files created:")
    print(f"    train.csv          → training (80% of balanced)")
    print(f"    test_balanced.csv  → threshold tuning (20% of balanced)")
    print(f"    test_raw.csv       → real-world evaluation (10% of raw, unbalanced)")
    print("=" * 60)


if __name__ == "__main__":
    main()
