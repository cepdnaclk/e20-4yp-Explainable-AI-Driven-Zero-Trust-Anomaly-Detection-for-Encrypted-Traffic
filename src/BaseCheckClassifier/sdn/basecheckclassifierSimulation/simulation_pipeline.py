#!/usr/bin/env python3
"""
simulation_pipeline.py
======================
High-speed simulation of the SDN Gatekeeper pipeline.
Walks the full labeled PCAP dataset, extracts 28 features, and predicts
using sentry_model_v2.pkl. Compares against ground truth and measures latency.

Target: ~702,000 streams.
"""

import os
import sys
import time
import pickle
import argparse
import socket
import logging
from multiprocessing import Pool, cpu_count
from collections import Counter

# Add extractor to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXTRACTOR_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "extraction"))
sys.path.insert(0, EXTRACTOR_DIR)

try:
    from feature_extractor import extract_features_extended, SENTRY_V2_FEATURES
except ImportError:
    print("[-] Error: Could not import feature_extractor.py. Check paths.")
    sys.exit(1)

# Paths
DEFAULT_MODEL = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "training", "sentry_model_v2.pkl"))
DATASET_ROOT  = "/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/"
RESULTS_FILE  = os.path.join(SCRIPT_DIR, "simulation_results.md")

# Globals for workers (initialized once)
_model = None
_threshold = None

def init_worker(model_path):
    global _model, _threshold
    with open(model_path, 'rb') as f:
        data = pickle.load(f)
        _model = data['model']
        _threshold = data['threshold']

def process_stream(arg_tuple):
    """
    Worker function to process a single PCAP stream.
    Returns: (actual_label, predicted_label, extract_us, infer_us, is_valid)
    """
    pcap_path, ground_truth = arg_tuple
    
    try:
        # 1. Extraction
        t0 = time.perf_counter()
        result = extract_features_extended(pcap_path)
        extract_time = (time.perf_counter() - t0) * 1_000_000 # microseconds
        
        if not result['valid']:
            return (ground_truth, "ERROR", extract_time, 0, False)
        
        X = [result['ordered_features']]
        
        # 2. Inference
        t1 = time.perf_counter()
        proba = _model.predict_proba(X)[0, 1] # Probability of ATTACK
        prediction = "ATTACK" if proba >= _threshold else "BENIGN"
        infer_time = (time.perf_counter() - t1) * 1_000_000 # microseconds
        
        return (ground_truth, prediction, extract_time, infer_time, True)
        
    except Exception as e:
        return (ground_truth, "EXCEPTION", 0, 0, False)

def main():
    parser = argparse.ArgumentParser(description="SDN Gatekeeper Simulation")
    parser.add_argument("--model",   default=DEFAULT_MODEL, help="Path to sentry_model_v2.pkl")
    parser.add_argument("--workers", type=int, default=cpu_count(), help="Multiprocessing workers")
    parser.add_argument("--limit",   type=int, default=0, help="Limit number of streams (0=all)")
    args = parser.parse_args()

    if not os.path.exists(args.model):
        print(f"[-] Model not found at {args.model}")
        return

    # 1. Discover tasks
    print(f"[*] Discovering PCAPs in {DATASET_ROOT} ...")
    tasks = []
    for root, dirs, files in os.walk(DATASET_ROOT):
        if "packets.pcap" in files:
            # Ground truth is parsed from directory name (e.g. Row_123_BENIGN -> BENIGN)
            folder_name = os.path.basename(root)
            if "_" in folder_name:
                ground_truth = folder_name.split("_")[-1]
            else:
                ground_truth = "UNKNOWN"
            
            # Map specific attacks to 'ATTACK' for binary Gatekeeper check
            gt_binary = "BENIGN" if ground_truth == "BENIGN" else "ATTACK"
            
            tasks.append((os.path.join(root, "packets.pcap"), gt_binary))
            
            if args.limit > 0 and len(tasks) >= args.limit:
                break

    total_tasks = len(tasks)
    print(f"[*] Found {total_tasks:,} streams to process.")

    # 2. Run simulation
    print(f"[*] Starting simulation using {args.workers} workers ...")
    start_all = time.perf_counter()
    
    cm = Counter() # (Actual, Pred)
    extract_times = []
    infer_times = []
    errors = 0
    
    with Pool(processes=args.workers, initializer=init_worker, initargs=(args.model,)) as pool:
        for idx, (gt, pred, ext_t, inf_t, valid) in enumerate(pool.imap_unordered(process_stream, tasks, chunksize=10)):
            if valid:
                cm[(gt, pred)] += 1
                extract_times.append(ext_t)
                infer_times.append(inf_t)
            else:
                errors += 1
                
            if (idx + 1) % 5000 == 0 or (idx + 1) == total_tasks:
                pct = (idx + 1) / total_tasks * 100
                print(f"    Processed {idx+1:,} / {total_tasks:,} ({pct:.1f}%) ...")

    total_time = time.perf_counter() - start_all
    
    # 3. Calculate Results
    tn = cm[("BENIGN", "BENIGN")]
    fp = cm[("BENIGN", "ATTACK")]
    fn = cm[("ATTACK", "BENIGN")]
    tp = cm[("ATTACK", "ATTACK")]
    
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    
    avg_ext = sum(extract_times) / len(extract_times) if extract_times else 0
    avg_inf = sum(infer_times) / len(infer_times) if infer_times else 0
    
    # 4. Generate Report
    report = f"""# 🛡️ SDN Gatekeeper Simulation Results
Created: {time.strftime('%Y-%m-%d %H:%M:%S')}

## 📊 Summary Metrics
- **Total Streams Processed:** {total_tasks - errors:,}
- **Processing Errors:** {errors:,}
- **Accuracy:** {accuracy*100:.2f}%
- **Attack Recall (Target >= 99.9%):** **{recall*100:.3f}%** {'🎯' if recall >= 0.999 else '⚠️'}
- **Total Duration:** {total_time/60:.2f} minutes

## ⏱️ Latency (Microseconds)
- **Avg Extraction Time:** {avg_ext:.2f} µs
- **Avg Inference Time:** {avg_inf:.2f} µs
- **Total Pipeline Latency:** **{avg_ext + avg_inf:.2f} µs** (Target < 1,000 µs ⚡)

## 🧮 Confusion Matrix
| Actual \\ Predicted | BENIGN | ATTACK (Forward to DL) |
| :--- | :---: | :---: |
| **BENIGN** | {tn:,} (Passed) | {fp:,} (False Positive) |
| **ATTACK** | {fn:,} (Leakage!) | {tp:,} (Detected) |

---
> **Verdict:** Any leakage (FN > 0) is a potential threat. If leakage is high, decrease the model threshold in `train_model.py`.
"""

    with open(RESULTS_FILE, 'w') as f:
        f.write(report)
    
    print("\n" + "="*60)
    print(f"  Simulation Complete!")
    print(f"  Report saved to: {RESULTS_FILE}")
    print("="*60)

if __name__ == "__main__":
    main()
