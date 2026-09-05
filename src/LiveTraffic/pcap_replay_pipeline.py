"""
pcap_replay_pipeline.py — PCAP-Based Testing (Real-World Simulation)
=====================================================================
Zero-Trust XAI Anomaly Detection | University of Peradeniya
e20420Janith

PURPOSE
-------
Test the DDL pipeline against:
  1. CICDataset/PCAP/Labeled/{Day}/ — per-flow labeled PCAPs (Row_X_LABEL)
     → per-flow accuracy with ground truth
  2. CICDataset/PCAP/*.pcap         — full day PCAPs (Monday–Friday)
     → real-world mixed traffic simulation via NFStream offline mode

USAGE
-----
# Per-flow test (labeled PCAPs, Friday):
python LiveTraffic/pcap_replay_pipeline.py \\
    --mode labeled \\
    --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \\
    --ddl-model models/ddl_40feat.pkl \\
    --output logs/test_friday_labeled.json \\
    --max-files 2000

# Real-world PCAP replay (full day, mixed traffic):
python LiveTraffic/pcap_replay_pipeline.py \\
    --mode fullday \\
    --pcap-file /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Friday-WorkingHours.pcap \\
    --ddl-model models/ddl_40feat.pkl \\
    --output logs/test_friday_fullday.json

# Quick sanity check (first 100 labeled PCAPs only):
python LiveTraffic/pcap_replay_pipeline.py \\
    --mode labeled \\
    --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \\
    --ddl-model models/ddl_40feat.pkl \\
    --max-files 100 --output logs/sanity.json

HOW IT WORKS
------------
Labeled mode:
  - Each folder in pcap-dir is a labeled flow (Row_X_LABEL naming)
  - NFStream processes the PCAP inside each folder to get flow statistics
  - DDL predicts: Normal or Anomaly
  - Ground truth extracted from folder name suffix (_BENIGN, _DDoS, etc.)
  - Per-attack-type F1/Precision/Recall reported

Full-day mode:
  - NFStream processes the full PCAP as a stream of flows
  - No ground truth (or use separate CSV label mapping if available)
  - Reports distribution of decisions (FORWARD/DROP), DDL score histogram
"""

import os
import sys
import json
import glob
import logging
import argparse
import time
from collections import defaultdict
from typing import Optional, List, Tuple, Dict

import numpy as np

_THIS_DIR    = os.path.dirname(os.path.abspath(__file__))
SRC_ROOT     = os.path.dirname(_THIS_DIR)
PROJECT_ROOT = os.path.dirname(SRC_ROOT)
sys.path.insert(0, SRC_ROOT)

from DDLModel.ddl_model import DeepDictionaryLearning
from DDLModel.ddl_feature_extractor import DDLFeatureExtractor, DDL_FEATURE_NAMES

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("PCAPReplay")

# ─────────────────────────────────────────────────────────────────────────────
# Label extraction from folder/filename
# ─────────────────────────────────────────────────────────────────────────────

# Maps CIC-IDS-2017 label suffixes to whether they are attacks
ATTACK_LABELS = {
    "BENIGN": False,
    "DDoS":   True,
    "PortScan": True,
    "Bot":    True,
    "FTP-Patator": True,
    "SSH-Patator": True,
    "DoS": True,
    "Heartbleed": True,
    "Web Attack": True,
    "Infiltration": True,
    "XSS": True,
    "SQL Injection": True,
    "Brute Force": True,
}


def parse_label_from_name(name: str) -> Tuple[str, bool]:
    """
    Extract the attack label from a labeled PCAP folder name.

    Name format: Row_<N>_<LABEL>
    e.g. Row_100257_DDoS → label="DDoS", is_attack=True
         Row_10_BENIGN   → label="BENIGN", is_attack=False

    Returns (label_str, is_attack_bool)
    """
    parts = name.rsplit("_", maxsplit=1) if "_" in name else [name, "UNKNOWN"]
    raw_label = parts[-1].strip()

    # Handle multi-word labels (e.g. "Web Attack", encoded as "Web_Attack")
    raw_label = raw_label.replace("-", " ")

    for known_label, is_attack in ATTACK_LABELS.items():
        if raw_label.lower() == known_label.lower():
            return known_label, is_attack

    # Unknown label — treat as attack (zero-trust)
    return raw_label, True


def find_pcap_in_folder(folder_path: str) -> Optional[str]:
    """Find the PCAP file inside a labeled flow folder."""
    for ext in ("*.pcap", "*.pcapng", "*.cap"):
        matches = glob.glob(os.path.join(folder_path, ext))
        if matches:
            return matches[0]
    return None


# ─────────────────────────────────────────────────────────────────────────────
# NFStream processing helpers
# ─────────────────────────────────────────────────────────────────────────────

def _process_pcap_with_nfstream(pcap_path: str, extractor: DDLFeatureExtractor,
                                 idle_timeout: int = 120,
                                 active_timeout: int = 600) -> List[np.ndarray]:
    """
    Use NFStream to read a PCAP file and extract 40-feature vectors.
    Returns a list of feature vectors (one per terminated flow).
    """
    try:
        from nfstream import NFStreamer
    except ImportError:
        raise RuntimeError("nfstream not installed. Run: pip install nfstream")

    feature_vectors = []
    try:
        streamer = NFStreamer(
            source=pcap_path,
            idle_timeout=idle_timeout,
            active_timeout=active_timeout,
            statistical_analysis=True,
            splt_analysis=10,
        )
        for flow in streamer:
            try:
                fv = extractor.from_nfstream(flow)
                feature_vectors.append(fv)
            except Exception:
                pass  # skip bad flows silently
    except Exception as e:
        logger.debug(f"NFStream error on {pcap_path}: {e}")
    return feature_vectors


# ─────────────────────────────────────────────────────────────────────────────
# Labeled PCAP mode
# ─────────────────────────────────────────────────────────────────────────────

def run_labeled_mode(
    pcap_dir: str,
    ddl: DeepDictionaryLearning,
    output_path: str,
    max_files: Optional[int] = None,
    idle_timeout: int = 120,
) -> Dict:
    """
    Test DDL on labeled per-flow PCAPs from CIC-IDS-2017.

    Each sub-folder is one labeled flow: Row_X_LABEL.
    Ground truth is extracted from the folder name.
    """
    extractor = DDLFeatureExtractor()
    entries = sorted(os.listdir(pcap_dir))
    if max_files:
        entries = entries[:max_files]

    logger.info(f"Processing {len(entries)} labeled flows from {pcap_dir}")

    # Metrics per label
    per_label: Dict[str, Dict] = defaultdict(
        lambda: {"TP": 0, "TN": 0, "FP": 0, "FN": 0, "count": 0}
    )
    all_results = []
    skipped = 0

    for i, entry in enumerate(entries):
        folder = os.path.join(pcap_dir, entry)
        if not os.path.isdir(folder):
            continue

        label, is_attack_gt = parse_label_from_name(entry)

        # Find PCAP inside the folder
        pcap_path = find_pcap_in_folder(folder)
        if pcap_path is None:
            # Try using the folder itself as PCAP
            skipped += 1
            continue

        # Process with NFStream
        feature_vecs = _process_pcap_with_nfstream(pcap_path, extractor,
                                                    idle_timeout=idle_timeout)
        if not feature_vecs:
            skipped += 1
            continue

        # Use the FIRST flow (one PCAP = one flow for labeled CIC-IDS-2017)
        fv = feature_vecs[0]
        t0 = time.perf_counter()
        result = ddl.predict(fv)
        latency_ms = (time.perf_counter() - t0) * 1000

        is_attack_pred = (result["labels"] == "Anomaly")

        # Confusion matrix
        m = per_label[label]
        m["count"] += 1
        if is_attack_gt and is_attack_pred:
            m["TP"] += 1
        elif not is_attack_gt and not is_attack_pred:
            m["TN"] += 1
        elif not is_attack_gt and is_attack_pred:
            m["FP"] += 1
        else:
            m["FN"] += 1

        all_results.append({
            "folder":       entry,
            "label":        label,
            "is_attack_gt": is_attack_gt,
            "ddl_label":    result["labels"],
            "ddl_score":    round(float(result["scores"]), 6),
            "threshold":    round(float(result["threshold"]), 6),
            "latency_ms":   round(latency_ms, 3),
        })

        if (i + 1) % 200 == 0:
            logger.info(f"  Processed {i+1}/{len(entries)} ...")

    # Compute per-label metrics
    label_metrics = {}
    for label, m in per_label.items():
        TP, TN, FP, FN = m["TP"], m["TN"], m["FP"], m["FN"]
        total = TP + TN + FP + FN
        precision = TP / (TP + FP + 1e-8)
        recall    = TP / (TP + FN + 1e-8)
        f1        = 2 * precision * recall / (precision + recall + 1e-8)
        accuracy  = (TP + TN) / (total + 1e-8)
        label_metrics[label] = {
            "count": m["count"],
            "TP": TP, "TN": TN, "FP": FP, "FN": FN,
            "precision": round(precision, 4),
            "recall":    round(recall, 4),
            "f1":        round(f1, 4),
            "accuracy":  round(accuracy, 4),
        }

    # Macro-average F1
    attack_labels = [l for l in label_metrics if l != "BENIGN"]
    macro_f1 = np.mean([label_metrics[l]["f1"] for l in attack_labels]) \
               if attack_labels else 0.0

    # Overall stats
    total_TP = sum(m["TP"] for m in per_label.values())
    total_TN = sum(m["TN"] for m in per_label.values())
    total_FP = sum(m["FP"] for m in per_label.values())
    total_FN = sum(m["FN"] for m in per_label.values())
    tot = total_TP + total_TN + total_FP + total_FN + 1e-8
    overall = {
        "TP": total_TP, "TN": total_TN, "FP": total_FP, "FN": total_FN,
        "precision": round(total_TP / (total_TP + total_FP + 1e-8), 4),
        "recall":    round(total_TP / (total_TP + total_FN + 1e-8), 4),
        "accuracy":  round((total_TP + total_TN) / tot, 4),
        "macro_f1_attacks": round(float(macro_f1), 4),
    }
    overall["f1"] = round(
        2 * overall["precision"] * overall["recall"] /
        (overall["precision"] + overall["recall"] + 1e-8), 4)

    report = {
        "mode":          "labeled",
        "pcap_dir":      pcap_dir,
        "total_flows":   len(all_results),
        "skipped":       skipped,
        "overall":       overall,
        "per_label":     label_metrics,
        "decisions":     all_results,
    }

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    _print_labeled_report(report)
    logger.info(f"Full results → {output_path}")
    return report


def _print_labeled_report(report: Dict):
    overall = report["overall"]
    print("\n" + "=" * 65)
    print("  PCAP REPLAY — LABELED TEST RESULTS")
    print("=" * 65)
    print(f"  Flows processed: {report['total_flows']}  Skipped: {report['skipped']}")
    print(f"\n  Overall:")
    print(f"    Accuracy:        {overall['accuracy']}")
    print(f"    Precision:       {overall['precision']}")
    print(f"    Recall:          {overall['recall']}")
    print(f"    F1 (overall):    {overall['f1']}")
    print(f"    F1 (macro-atk):  {overall['macro_f1_attacks']}")
    print(f"    TP={overall['TP']}  TN={overall['TN']}  FP={overall['FP']}  FN={overall['FN']}")
    print(f"\n  Per Label:")
    for label, m in sorted(report["per_label"].items()):
        print(f"    {label:<20} n={m['count']:<6} "
              f"F1={m['f1']:.3f}  Prec={m['precision']:.3f}  Rec={m['recall']:.3f}")
    print("=" * 65)


# ─────────────────────────────────────────────────────────────────────────────
# Full-day PCAP mode (real-world simulation)
# ─────────────────────────────────────────────────────────────────────────────

def run_fullday_mode(
    pcap_file: str,
    ddl: DeepDictionaryLearning,
    output_path: str,
    idle_timeout: int = 15,
    active_timeout: int = 120,
) -> Dict:
    """
    Process a full-day PCAP (e.g. Friday-WorkingHours.pcap) through DDL.
    This simulates real-world mixed traffic — no per-flow ground truth.
    Reports decision distribution and DDL score histogram.
    """
    try:
        from nfstream import NFStreamer
    except ImportError:
        raise RuntimeError("nfstream not installed. Run: pip install nfstream")

    extractor = DDLFeatureExtractor()
    logger.info(f"Full-day replay: {pcap_file}")
    logger.info("This may take several minutes for large PCAP files...")

    decisions = []
    scores    = []
    n_normal  = 0
    n_anomaly = 0
    n_errors  = 0
    latencies = []

    streamer = NFStreamer(
        source=pcap_file,
        idle_timeout=idle_timeout,
        active_timeout=active_timeout,
        statistical_analysis=True,
        splt_analysis=10,
    )

    for i, flow in enumerate(streamer):
        try:
            fv = extractor.from_nfstream(flow)
            t0 = time.perf_counter()
            result = ddl.predict(fv)
            latency_ms = (time.perf_counter() - t0) * 1000

            action = "FORWARD" if result["labels"] == "Normal" else "DROP"
            if action == "FORWARD":
                n_normal += 1
            else:
                n_anomaly += 1

            scores.append(float(result["scores"]))
            latencies.append(latency_ms)

            decisions.append({
                "flow_num":  i,
                "src":       f"{getattr(flow, 'src_ip', '?')}:{getattr(flow, 'src_port', 0)}",
                "dst":       f"{getattr(flow, 'dst_ip', '?')}:{getattr(flow, 'dst_port', 0)}",
                "protocol":  str(getattr(flow, "protocol", "?")),
                "pkts":      int(getattr(flow, "bidirectional_packets", 0)),
                "bytes":     int(getattr(flow, "bidirectional_bytes", 0)),
                "action":    action,
                "ddl_score": round(float(result["scores"]), 6),
                "threshold": round(float(result["threshold"]), 6),
                "latency_ms": round(latency_ms, 3),
            })

            if (i + 1) % 1000 == 0:
                logger.info(f"  Flows: {i+1}  |  Normal: {n_normal}  |  Anomaly: {n_anomaly}")

        except Exception as e:
            n_errors += 1

    total = n_normal + n_anomaly
    scores_arr = np.array(scores) if scores else np.array([0.0])

    report = {
        "mode":       "fullday",
        "pcap_file":  pcap_file,
        "total_flows": total,
        "n_errors":   n_errors,
        "n_forward":  n_normal,
        "n_drop":     n_anomaly,
        "anomaly_pct": round(100 * n_anomaly / (total + 1e-8), 2),
        "ddl_scores": {
            "mean":   round(float(scores_arr.mean()), 6),
            "std":    round(float(scores_arr.std()), 6),
            "p50":    round(float(np.percentile(scores_arr, 50)), 6),
            "p95":    round(float(np.percentile(scores_arr, 95)), 6),
            "max":    round(float(scores_arr.max()), 6),
            "threshold": float(ddl.threshold_),
        },
        "latency_ms": {
            "mean": round(float(np.mean(latencies)), 2) if latencies else 0,
            "p95":  round(float(np.percentile(latencies, 95)), 2) if latencies else 0,
        },
        "decisions": decisions,
    }

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n{'=' * 55}")
    print("  FULL-DAY PCAP REPLAY RESULTS")
    print(f"{'=' * 55}")
    print(f"  Total flows:    {total}")
    print(f"  FORWARD:        {n_normal} ({100*n_normal/(total+1e-8):.1f}%)")
    print(f"  DROP (anomaly): {n_anomaly} ({report['anomaly_pct']}%)")
    print(f"  DDL threshold:  {ddl.threshold_:.6f}")
    print(f"  Score p95:      {report['ddl_scores']['p95']:.6f}")
    print(f"  Latency p95:    {report['latency_ms']['p95']:.1f}ms")
    print(f"{'=' * 55}")
    logger.info(f"Full results → {output_path}")
    return report


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PCAP replay pipeline — labeled per-flow or full-day PCAP"
    )
    parser.add_argument("--mode", choices=["labeled", "fullday"], default="labeled",
                        help="labeled: per-flow PCAP folders; fullday: single mixed PCAP")
    parser.add_argument("--pcap-dir",  default=None,
                        help="[labeled mode] Directory of Row_X_LABEL folders")
    parser.add_argument("--pcap-file", default=None,
                        help="[fullday mode] Path to full-day PCAP file")
    parser.add_argument("--ddl-model",
                        default=os.path.join(PROJECT_ROOT, "models", "ddl_40feat.pkl"),
                        help="Path to trained DDL model .pkl")
    parser.add_argument("--output",
                        default=os.path.join(PROJECT_ROOT, "logs", "pcap_replay.json"),
                        help="Output JSON report path")
    parser.add_argument("--max-files", type=int, default=None,
                        help="[labeled mode] Limit number of flows processed")
    parser.add_argument("--idle-timeout",   type=int, default=15,
                        help="NFStream idle timeout in seconds (fullday mode)")
    parser.add_argument("--active-timeout", type=int, default=120,
                        help="NFStream active timeout in seconds (fullday mode)")
    args = parser.parse_args()

    # Load DDL model
    if not os.path.exists(args.ddl_model):
        logger.error(f"DDL model not found: {args.ddl_model}")
        logger.error("Run: python DDLModel/train_ddl_enhanced.py --train dataset/TRAIN_Traffic.csv ...")
        sys.exit(1)

    logger.info(f"Loading DDL model from {args.ddl_model}")
    ddl = DeepDictionaryLearning.load(args.ddl_model)

    if args.mode == "labeled":
        if not args.pcap_dir:
            parser.error("--pcap-dir required for labeled mode")
        run_labeled_mode(
            pcap_dir=args.pcap_dir,
            ddl=ddl,
            output_path=args.output,
            max_files=args.max_files,
            idle_timeout=args.idle_timeout,
        )
    else:
        if not args.pcap_file:
            parser.error("--pcap-file required for fullday mode")
        run_fullday_mode(
            pcap_file=args.pcap_file,
            ddl=ddl,
            output_path=args.output,
            idle_timeout=args.idle_timeout,
            active_timeout=args.active_timeout,
        )
