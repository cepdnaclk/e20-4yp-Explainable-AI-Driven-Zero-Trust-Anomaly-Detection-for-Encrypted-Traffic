"""
DDL Model Trainer
=================

Trains the Deep Dictionary Learning model on CIC-IDS-2017 features.
Can train on:
  1. A CSV file with the 15 features (from CIC-IDS-2017 processed data)
  2. A directory of benign .pcap files (extracts features on the fly)

Usage:
    python -m DDLModel.train_ddl --csv /path/to/TRAIN_Traffic.csv --output ./models/ddl_model.pkl
    python -m DDLModel.train_ddl --pcap-dir ./BaseCheckClassifier/BaseCheckClassifierSimulation/normal/ --output ./models/ddl_model.pkl
"""

import argparse
import os
import sys
import numpy as np
import pandas as pd
import logging

# ── Path setup: add project root and BaseCheckClassifier simulation dir ──
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_THIS_DIR)
sys.path.insert(0, PROJECT_ROOT)

# Friend's feature extractor lives in BaseCheckClassifier/BaseCheckClassifierSimulation/
BASECHK_SIM = os.path.join(PROJECT_ROOT, "BaseCheckClassifier", "BaseCheckClassifierSimulation")
sys.path.insert(0, BASECHK_SIM)

from DDLModel.ddl_model import DeepDictionaryLearning

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DDL-Trainer")

# The 15 features in model-expected order
SELECTED_FEATURES = [
    'Packet Length Variance', 'Fwd Packet Length Max', 'Fwd Header Length',
    'Init_Win_bytes_forward', 'Bwd Header Length', 'Total Length of Fwd Packets',
    'Init_Win_bytes_backward', 'Bwd Packets/s', 'Flow IAT Min', 'Fwd IAT Min',
    'Flow Bytes/s', 'Active Min', 'Bwd IAT Total', 'Flow IAT Max', 'Flow Duration'
]


def train_from_csv(csv_path, output_path, label_col='Label', normal_label='Normal',
                   n_atoms_l1=64, n_atoms_l2=128, n_epochs=100, threshold_pct=95):
    """
    Train DDL on normal traffic rows from a CSV.
    
    Args:
        csv_path: Path to CSV with the 15 features + Label column.
        output_path: Where to save the trained model.
        label_col: Column name for the label.
        normal_label: Value in label_col that indicates normal/benign traffic.
    """
    logger.info(f"Loading data from {csv_path}")
    df = pd.read_csv(csv_path)

    # Filter to just the selected features
    missing = [f for f in SELECTED_FEATURES if f not in df.columns]
    if missing:
        raise ValueError(f"CSV missing required features: {missing}")

    X_all = df[SELECTED_FEATURES].values

    # Filter to normal samples only for training
    if label_col in df.columns:
        mask = df[label_col].str.strip().str.lower() == normal_label.lower()
        X_normal = X_all[mask]
        logger.info(f"Found {mask.sum()} normal samples out of {len(df)} total")
    else:
        logger.warning(f"No '{label_col}' column found — using all rows as normal")
        X_normal = X_all

    # Clean data
    X_normal = np.nan_to_num(X_normal, nan=0.0, posinf=1e9, neginf=-1e9)

    # Train
    ddl = DeepDictionaryLearning(
        n_features=len(SELECTED_FEATURES),
        n_atoms_l1=n_atoms_l1,
        n_atoms_l2=n_atoms_l2,
        n_epochs=n_epochs,
        threshold_percentile=threshold_pct,
    )
    ddl.fit(X_normal)

    # Save
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    ddl.save(output_path)
    logger.info(f"Model saved to {output_path}")

    return ddl


def train_from_pcaps(pcap_dir, output_path, n_atoms_l1=64, n_atoms_l2=128,
                     n_epochs=100, threshold_pct=95):
    """
    Train DDL by extracting features from benign .pcap files.
    
    Uses the feature extractor from BaseCheckClassifier/BaseCheckClassifierSimulation/extraction/.
    
    Args:
        pcap_dir: Directory containing benign .pcap files.
        output_path: Where to save the trained model.
    """
    from extraction.feature_extractor import extract_features

    logger.info(f"Extracting features from pcaps in {pcap_dir}")
    feature_rows = []

    for root, _, files in os.walk(pcap_dir):
        for fname in files:
            if fname.endswith('.pcap'):
                fpath = os.path.join(root, fname)
                result = extract_features(fpath)
                if result["valid"]:
                    feature_rows.append(result["ordered_features"])
                else:
                    logger.warning(f"Skipping {fname}: {result.get('error', 'unknown')}")

    if len(feature_rows) < 5:
        raise ValueError(f"Only {len(feature_rows)} valid pcaps found. Need at least 5.")

    X_normal = np.array(feature_rows, dtype=np.float64)
    X_normal = np.nan_to_num(X_normal, nan=0.0, posinf=1e9, neginf=-1e9)

    logger.info(f"Training on {len(X_normal)} pcap-extracted feature vectors")

    ddl = DeepDictionaryLearning(
        n_features=len(SELECTED_FEATURES),
        n_atoms_l1=n_atoms_l1,
        n_atoms_l2=n_atoms_l2,
        n_epochs=n_epochs,
        threshold_percentile=threshold_pct,
    )
    ddl.fit(X_normal)

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    ddl.save(output_path)
    logger.info(f"Model saved to {output_path}")

    return ddl


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train DDL anomaly detection model")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--csv", help="Path to CSV with 15 features + Label column")
    group.add_argument("--pcap-dir", help="Directory of benign .pcap files")

    parser.add_argument("--output", default="./models/ddl_model.pkl",
                        help="Output model path (default: ./models/ddl_model.pkl)")
    parser.add_argument("--label-col", default="Label", help="Label column name in CSV")
    parser.add_argument("--normal-label", default="Normal", help="Label value for normal traffic")
    parser.add_argument("--atoms-l1", type=int, default=64, help="Number of atoms in Layer 1")
    parser.add_argument("--atoms-l2", type=int, default=128, help="Number of atoms in Layer 2")
    parser.add_argument("--epochs", type=int, default=100, help="Training epochs")
    parser.add_argument("--threshold-pct", type=int, default=95,
                        help="Percentile for anomaly threshold (default: 95)")

    args = parser.parse_args()

    if args.csv:
        train_from_csv(args.csv, args.output, args.label_col, args.normal_label,
                       args.atoms_l1, args.atoms_l2, args.epochs, args.threshold_pct)
    else:
        train_from_pcaps(args.pcap_dir, args.output,
                         args.atoms_l1, args.atoms_l2, args.epochs, args.threshold_pct)
