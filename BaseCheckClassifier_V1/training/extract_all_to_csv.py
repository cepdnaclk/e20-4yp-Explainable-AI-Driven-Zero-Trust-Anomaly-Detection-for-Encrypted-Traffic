"""
extract_all_to_csv.py
=====================
Walks all labeled PCAP streams across all 5 days and extracts 28 features
from each stream using extract_features_extended(). Writes a CSV with:
  - 28 feature columns (header-observable, no decryption needed)
  - 'attack_label'  : original class name (e.g. DoSHulk, BENIGN, DDoS ...)
  - 'label'         : binary label — 'BENIGN' or 'ATTACK'

Usage:
    python3 extract_all_to_csv.py [--workers N] [--output PATH]

Output:
    training/dataset_raw.csv  (~702k rows × 30 cols)
"""

import os
import sys
import csv
import time
import logging
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed

# ─── Paths ───────────────────────────────────────────────────────────────────
SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
EXTRACTOR_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "extraction"))
sys.path.insert(0, EXTRACTOR_DIR)

LABELED_BASE = "/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled"
DAYS         = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
DEFAULT_OUT  = os.path.join(SCRIPT_DIR, "dataset_raw.csv")

# ─── Feature column order ────────────────────────────────────────────────────
from feature_extractor import EXTENDED_FEATURES   # 28 feature names in order

CSV_COLUMNS = EXTENDED_FEATURES + ["attack_label", "label"]


# ─── Worker ──────────────────────────────────────────────────────────────────
def worker_init():
    """Silence logging in child processes."""
    logging.disable(logging.CRITICAL)
    import warnings
    warnings.filterwarnings("ignore")


def process_stream(args):
    """
    Extract features from one stream PCAP.
    Returns a flat list in CSV_COLUMNS order, or None if extraction fails.
    """
    pcap_path, attack_label, binary_label = args
    try:
        from feature_extractor import extract_features_extended
        result = extract_features_extended(pcap_path)
    except Exception as e:
        return None

    if not result["valid"]:
        return None

    row = result["ordered_features"] + [attack_label, binary_label]
    return row


# ─── Task collection ─────────────────────────────────────────────────────────
def collect_tasks():
    """
    Walk all day/label folders and build the list of (pcap_path, attack_label, binary_label).
    """
    tasks = []
    skipped = 0

    for day in DAYS:
        day_dir = os.path.join(LABELED_BASE, day)
        if not os.path.isdir(day_dir):
            print(f"[!] Day directory not found: {day_dir}")
            continue

        for folder in os.listdir(day_dir):
            # Expected format: Row_<N>_<LABEL>
            parts = folder.split("_", 2)
            if len(parts) < 3 or parts[0] != "Row":
                skipped += 1
                continue

            attack_label = parts[2]           # e.g. "DoSHulk", "BENIGN", "DDoS"
            binary_label = "BENIGN" if attack_label == "BENIGN" else "ATTACK"

            pcap_path = os.path.join(day_dir, folder, "packets.pcap")
            if not os.path.exists(pcap_path):
                skipped += 1
                continue

            tasks.append((pcap_path, attack_label, binary_label))

    print(f"[*] Total tasks: {len(tasks):,} streams  ({skipped} skipped — missing pcap)")
    return tasks


# ─── Main extraction loop ─────────────────────────────────────────────────────
def run_extraction(tasks, output_path, workers):
    total       = len(tasks)
    done        = 0
    valid       = 0
    skipped     = 0
    start       = time.time()

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_COLUMNS)   # header

        with ProcessPoolExecutor(max_workers=workers, initializer=worker_init) as executor:
            futures = {executor.submit(process_stream, t): t for t in tasks}

            for future in as_completed(futures):
                done += 1
                row = future.result()
                if row is not None:
                    writer.writerow(row)
                    valid += 1
                else:
                    skipped += 1

                # Progress every 5,000 streams
                if done % 5000 == 0 or done == total:
                    elapsed  = time.time() - start
                    rate     = done / elapsed if elapsed > 0 else 0
                    eta      = (total - done) / rate if rate > 0 else 0
                    pct      = 100 * done / total
                    print(
                        f"  [{done:>7,}/{total:,}] {pct:5.1f}% | "
                        f"valid={valid:,} skipped={skipped:,} | "
                        f"{rate:.0f} streams/s | ETA {eta/60:.1f}m"
                    )

    elapsed = time.time() - start
    return valid, skipped, elapsed


# ─── Entry point ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Extract 28 features from all labeled PCAPs")
    parser.add_argument("--workers", type=int, default=16,
                        help="Number of parallel worker processes (default: 16)")
    parser.add_argument("--output", type=str, default=DEFAULT_OUT,
                        help=f"Output CSV path (default: {DEFAULT_OUT})")
    args = parser.parse_args()

    print("=" * 65)
    print("  Feature Extraction Pipeline — All Days")
    print("=" * 65)
    print(f"  Labeled PCAP root : {LABELED_BASE}")
    print(f"  Days              : {', '.join(DAYS)}")
    print(f"  Features          : {len(EXTENDED_FEATURES)} (28)")
    print(f"  Workers           : {args.workers}")
    print(f"  Output            : {args.output}")
    print("=" * 65)

    tasks = collect_tasks()
    if not tasks:
        print("[!] No tasks found. Exiting.")
        sys.exit(1)

    print(f"\n[*] Starting extraction with {args.workers} workers ...\n")
    valid, skipped, elapsed = run_extraction(tasks, args.output, args.workers)

    print()
    print("=" * 65)
    print("  Extraction Complete")
    print("=" * 65)
    print(f"  Total streams processed : {valid + skipped:,}")
    print(f"  Valid (written to CSV)  : {valid:,}")
    print(f"  Skipped (non-TCP/error) : {skipped:,}")
    print(f"  Elapsed time            : {elapsed/60:.1f} minutes")
    print(f"  Output CSV              : {args.output}")
    print("=" * 65)

    # Quick label distribution check
    print("\n[*] Verifying label distribution in output CSV ...")
    try:
        import pandas as pd
        df = pd.read_csv(args.output, usecols=["attack_label", "label"])
        print("\n  Binary label counts:")
        print(df["label"].value_counts().to_string())
        print("\n  Attack type counts:")
        print(df["attack_label"].value_counts().to_string())
    except Exception as e:
        print(f"  [!] Could not verify CSV: {e}")


if __name__ == "__main__":
    main()
