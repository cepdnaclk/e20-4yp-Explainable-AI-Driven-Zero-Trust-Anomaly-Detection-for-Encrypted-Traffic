"""
Demo Runner for the Zero-Trust Pipeline
========================================

Demonstrates the full pipeline end-to-end:
  1. Trains a DDL model on synthetic benign data
  2. Runs pcap files through the full pipeline
  3. Shows Decision Tree → Buffer → DDL → XAI flow
  4. Prints explanations for detected anomalies

Usage (from project root):
    python -m ZeroTrustPipeline.run_demo
    python -m ZeroTrustPipeline.run_demo --pcap-dir ./src/BaseCheckClassifier/sdn/attack/ ./src/BaseCheckClassifier/sdn/normal/
    python -m ZeroTrustPipeline.run_demo --files path/to/attack.pcap path/to/benign.pcap
"""

import os
import sys
import argparse
import numpy as np
import logging

# ── Path setup ──
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_ROOT     = os.path.dirname(_THIS_DIR)
PROJECT_ROOT = os.path.dirname(SRC_ROOT)
sys.path.insert(0, SRC_ROOT)

BCC_ROOT = os.path.join(SRC_ROOT, "BaseCheckClassifier")
BCC_SDN  = os.path.join(BCC_ROOT, "sdn")
sys.path.insert(0, BCC_ROOT)
sys.path.insert(0, BCC_SDN)

from DDLModel.ddl_model import DeepDictionaryLearning
from ZeroTrustPipeline.pipeline import ZeroTrustPipeline, FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)s] %(levelname)s: %(message)s')
logger = logging.getLogger("Demo")


def generate_training_data(n_normal=200, n_features=15):
    """
    Generate synthetic normal traffic features for DDL training.
    
    These mimic typical benign CIC-IDS-2017 flow statistics.
    In production, use actual CIC-IDS-2017 TRAIN_Traffic.csv with Normal rows.
    """
    np.random.seed(42)
    
    # Typical benign ranges for each of the 15 features
    benign_means = [
        200,     # Packet Length Variance
        120,     # Fwd Packet Length Max
        2000,    # Fwd Header Length
        65535,   # Init_Win_bytes_forward
        1800,    # Bwd Header Length
        5000,    # Total Length of Fwd Packets
        65535,   # Init_Win_bytes_backward
        10,      # Bwd Packets/s
        50000,   # Flow IAT Min (μs)
        50000,   # Fwd IAT Min (μs)
        1000,    # Flow Bytes/s
        100000,  # Active Min (μs)
        80000,   # Bwd IAT Total (μs)
        200000,  # Flow IAT Max (μs)
        300000,  # Flow Duration (μs)
    ]
    
    benign_stds = [
        50,      # Packet Length Variance
        30,      # Fwd Packet Length Max
        400,     # Fwd Header Length
        100,     # Init_Win_bytes_forward (small variation)
        350,     # Bwd Header Length
        1200,    # Total Length of Fwd Packets
        100,     # Init_Win_bytes_backward
        3,       # Bwd Packets/s
        10000,   # Flow IAT Min
        10000,   # Fwd IAT Min
        250,     # Flow Bytes/s
        20000,   # Active Min
        15000,   # Bwd IAT Total
        40000,   # Flow IAT Max
        60000,   # Flow Duration
    ]
    
    X = np.zeros((n_normal, n_features))
    for i in range(n_features):
        X[:, i] = np.random.normal(benign_means[i], benign_stds[i], n_normal)
    
    # Clip to non-negative (feature values can't be negative)
    X = np.maximum(X, 0)
    
    return X


def collect_pcap_files(pcap_dirs=None, explicit_files=None):
    """Collect pcap files with ground truth labels."""
    pcap_list = []
    
    if explicit_files:
        for f in explicit_files:
            path = os.path.abspath(f)
            if os.path.exists(path):
                label = "Attack" if "attack" in f.lower() else "Normal"
                pcap_list.append((path, label))
            else:
                logger.warning(f"File not found: {path}")
    
    elif pcap_dirs:
        for d in pcap_dirs:
            for root, _, files in os.walk(d):
                for fname in files:
                    if fname.endswith('.pcap'):
                        path = os.path.join(root, fname)
                        folder = os.path.basename(root).lower()
                        if "attack" in folder or "bot" in folder or "ddos" in folder:
                            label = "Attack"
                        elif "normal" in folder or "benign" in folder:
                            label = "Normal"
                        elif "attack" in fname.lower():
                            label = "Attack"
                        elif "benign" in fname.lower():
                            label = "Normal"
                        else:
                            label = "Unknown"
                        pcap_list.append((path, label))
    
    else:
        # Default: use pcap files from src/BaseCheckClassifier/sdn
        defaults = [
            ("synthetic_attack.pcap", "Attack"),
            ("synthetic_benign.pcap", "Normal"),
            ("attack/bot_1.pcap", "Attack"),
            ("attack/bot_2.pcap", "Attack"),
            ("normal/benign_1.pcap", "Normal"),
            ("normal/benign_2.pcap", "Normal"),
        ]
        for fname, label in defaults:
            path = os.path.join(BCC_SDN, fname)
            if os.path.exists(path):
                pcap_list.append((path, label))
    
    return pcap_list


def main():
    parser = argparse.ArgumentParser(description="Zero-Trust Pipeline Demo")
    parser.add_argument("--files", nargs='+', help="Specific .pcap files to process")
    parser.add_argument("--pcap-dir", nargs='+', help="Directories containing .pcap files")
    parser.add_argument("--dt-model", help="Path to Decision Tree model (.pkl)")
    parser.add_argument("--ddl-model", help="Path to pre-trained DDL model (.pkl)")
    parser.add_argument("--train-csv", help="CSV with normal traffic for DDL training")
    parser.add_argument("--no-shap", action="store_true", help="Disable SHAP (faster)")
    parser.add_argument("--output", default=os.path.join(_THIS_DIR, "pipeline_results.json"),
                        help="Output results JSON path")
    args = parser.parse_args()

    print("=" * 70)
    print("  ZERO-TRUST ANOMALY DETECTION PIPELINE — DEMO")
    print("  Decision Tree → SDN Buffer → DDL + SHAP XAI")
    print("=" * 70)

    # ─── Step 1: Prepare DDL model ───
    ddl_path = args.ddl_model
    background_data = None
    models_dir = os.path.join(_THIS_DIR, "models")
    os.makedirs(models_dir, exist_ok=True)

    if ddl_path and os.path.exists(ddl_path):
        logger.info(f"Loading pre-trained DDL model from {ddl_path}")
    elif args.train_csv and os.path.exists(args.train_csv):
        # Train from CSV
        logger.info(f"Training DDL from CSV: {args.train_csv}")
        from DDLModel.train_ddl import train_from_csv
        ddl_path = os.path.join(models_dir, "ddl_demo.pkl")
        ddl = train_from_csv(args.train_csv, ddl_path)
        background_data = generate_training_data(100)
    else:
        # Train on synthetic data
        logger.info("No DDL model provided — training on synthetic benign data")
        background_data = generate_training_data(200)

        ddl = DeepDictionaryLearning(
            n_features=15, n_atoms_l1=64, n_atoms_l2=128,
            sparsity_weight=0.1, learning_rate=0.001,
            n_epochs=80, batch_size=16, threshold_percentile=95,
        )
        ddl.fit(background_data)

        ddl_path = os.path.join(models_dir, "ddl_demo.pkl")
        ddl.save(ddl_path)
        logger.info(f"Trained DDL model saved to {ddl_path}")

    # ─── Step 2: Collect pcap files ───
    pcap_list = collect_pcap_files(args.pcap_dir, args.files)

    if not pcap_list:
        logger.error("No .pcap files found to process!")
        logger.info("Hint: Place .pcap files in src/BaseCheckClassifier/sdn/attack/ and normal/")
        sys.exit(1)

    print(f"\nCollected {len(pcap_list)} streams:")
    for path, label in pcap_list:
        print(f"  {'🔴' if label == 'Attack' else '🟢'} [{label}] {os.path.basename(path)}")

    # ─── Step 3: Initialize pipeline ───
    pipeline = ZeroTrustPipeline(
        dt_model_path=args.dt_model,
        ddl_model_path=ddl_path,
        background_data=background_data,
        enable_shap=not args.no_shap,
    )

    # ─── Step 4: Run pipeline ───
    print(f"\n{'─' * 70}")
    output = pipeline.run_batch(pcap_list, output_log=args.output)

    # ─── Step 5: Show explanation details for anomalies ───
    anomalies = [r for r in output["stream_results"] if r["final_action"] == "DROP"]
    if anomalies:
        print("\n" + "=" * 70)
        print("  DETAILED ANOMALY EXPLANATIONS")
        print("=" * 70)

        for r in anomalies:
            print(f"\n┌─ Stream: {r['input_file']} (GT: {r['ground_truth']})")
            print(f"│  Final Action: {r['final_action']}")

            da = r["stages"].get("deep_analysis", {})
            if da.get("ddl_available"):
                print(f"│  DDL Score: {da.get('anomaly_score', 'N/A'):.4f} "
                      f"(threshold: {da.get('threshold', 'N/A'):.4f})")
                print(f"│  Analysis Time: {da.get('analysis_time_ms', 0):.0f}ms")

            if r.get("explanation"):
                exp = r["explanation"]
                if exp.get("summary"):
                    print(f"│")
                    print(f"│  Summary:")
                    for line in exp["summary"].split("\n"):
                        print(f"│    {line}")

                if exp.get("ddl_native") and exp["ddl_native"].get("feature_contributions"):
                    print(f"│")
                    print(f"│  Top Feature Contributions:")
                    for fc in exp["ddl_native"]["feature_contributions"][:5]:
                        print(f"│    • {fc['feature']}: "
                              f"{fc['pct_of_total_error']:.1f}% of error "
                              f"(observed={fc['original_value']:.2f}, "
                              f"expected={fc['reconstructed_value']:.2f})")

                if exp.get("shap") and exp["shap"].get("attributions"):
                    print(f"│")
                    print(f"│  SHAP Attributions:")
                    for attr in exp["shap"]["attributions"][:5]:
                        direction = "↑" if attr["shap_value"] > 0 else "↓"
                        print(f"│    {direction} {attr['feature']}: "
                              f"SHAP={attr['shap_value']:+.4f} "
                              f"(value={attr['feature_value']:.2f})")

            print(f"└{'─' * 60}")

    print(f"\nFull results saved to: {args.output}")


if __name__ == "__main__":
    main()
