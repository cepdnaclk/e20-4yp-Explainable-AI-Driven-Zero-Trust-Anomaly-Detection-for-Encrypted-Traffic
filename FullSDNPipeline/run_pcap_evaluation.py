#!/usr/bin/env python3
"""
PCAP Pipeline Evaluation
Reads labeled flow directories (each contains packets.pcap + label in dir name),
extracts flow features using dpkt, runs BCC→DDL+IF two-stage pipeline,
measures real inference times per flow, saves to results/pcap_results/.

Usage:
    python FullSDNPipeline/run_pcap_evaluation.py
    python FullSDNPipeline/run_pcap_evaluation.py --pcap-dir /path/to/labeled-dir
    python FullSDNPipeline/run_pcap_evaluation.py --limit 100
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

import numpy as np
import joblib

# Add project root to path
PROJ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJ))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ─── Feature extraction from flow PCAP ─────────────────────────────────────

def extract_flow_features_from_pcap(pcap_path: str) -> dict | None:
    """Extract flow-level features from a single-flow PCAP file using dpkt."""
    try:
        import dpkt
    except ImportError:
        logger.error("dpkt not installed. Run: pip install dpkt")
        return None

    try:
        packets = []
        with open(pcap_path, "rb") as f:
            try:
                reader = dpkt.pcap.Reader(f)
            except Exception:
                reader = dpkt.pcapng.Reader(f)
            for ts, buf in reader:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip = eth.data
                    packets.append({"ts": ts, "len": len(buf), "ip": ip})
                except Exception:
                    continue

        if len(packets) < 1:
            return None

        # Split into fwd/bwd by first packet's direction
        first_ip = packets[0]["ip"]
        try:
            src = first_ip.src
        except Exception:
            src = b"\x00"

        fwd = [p for p in packets if p["ip"].src == src]
        bwd = [p for p in packets if p["ip"].src != src]

        def pkt_lens(pkts): return [p["len"] for p in pkts]
        def intervals(pkts):
            ts_list = [p["ts"] for p in pkts]
            return [(ts_list[i+1] - ts_list[i]) * 1e6 for i in range(len(ts_list)-1)] if len(ts_list) > 1 else [0]

        all_lens = pkt_lens(packets)
        fwd_lens = pkt_lens(fwd)
        bwd_lens = pkt_lens(bwd)
        all_iats = intervals(packets)
        fwd_iats = intervals(fwd)
        bwd_iats = intervals(bwd)

        dur_us = (packets[-1]["ts"] - packets[0]["ts"]) * 1e6 if len(packets) > 1 else 0
        dur_s = dur_us / 1e6 if dur_us > 0 else 1e-6

        safe_mean = lambda x: float(np.mean(x)) if x else 0.0
        safe_std  = lambda x: float(np.std(x)) if len(x) > 1 else 0.0
        safe_min  = lambda x: float(min(x)) if x else 0.0
        safe_max  = lambda x: float(max(x)) if x else 0.0
        safe_sum  = lambda x: float(sum(x)) if x else 0.0

        # TCP flags
        syn_cnt = rst_cnt = ack_cnt = urg_cnt = 0
        for p in packets:
            ip = p["ip"]
            if isinstance(ip.data, __import__("dpkt").tcp.TCP):
                tcp = ip.data
                f = tcp.flags
                if f & 0x02: syn_cnt += 1
                if f & 0x04: rst_cnt += 1
                if f & 0x10: ack_cnt += 1
                if f & 0x20: urg_cnt += 1

        # Init window sizes
        fwd_win = bwd_win = 0
        for p in fwd[:1]:
            ip = p["ip"]
            if isinstance(ip.data, __import__("dpkt").tcp.TCP):
                fwd_win = ip.data.win
        for p in bwd[:1]:
            ip = p["ip"]
            if isinstance(ip.data, __import__("dpkt").tcp.TCP):
                bwd_win = ip.data.win

        # Fwd header length (sum of IP+TCP header lengths for fwd packets)
        fwd_hdr_len = 0
        for p in fwd:
            ip = p["ip"]
            fwd_hdr_len += ip.__hdr_len__ if hasattr(ip, '__hdr_len__') else 20
            if isinstance(ip.data, __import__("dpkt").tcp.TCP):
                tcp = ip.data
                fwd_hdr_len += tcp.off * 4 if tcp.off else 20

        bwd_hdr_len = 0
        for p in bwd:
            ip = p["ip"]
            bwd_hdr_len += ip.__hdr_len__ if hasattr(ip, '__hdr_len__') else 20

        down_up = len(bwd) / max(len(fwd), 1)

        return {
            # BCC-28 features
            "Packet Length Variance": float(np.var(all_lens)) if all_lens else 0,
            "Fwd Packet Length Max": safe_max(fwd_lens),
            "Fwd Header Length": float(fwd_hdr_len),
            "Init_Win_bytes_forward": float(fwd_win),
            "Bwd Header Length": float(bwd_hdr_len),
            "Total Length of Fwd Packets": safe_sum(fwd_lens),
            "Init_Win_bytes_backward": float(bwd_win),
            "Bwd Packets/s": len(bwd) / dur_s,
            "Flow IAT Min": safe_min(all_iats),
            "Fwd IAT Min": safe_min(fwd_iats),
            "Flow Bytes/s": safe_sum(all_lens) / dur_s,
            "Active Min": dur_us * 0.1,  # approx
            "Bwd IAT Total": safe_sum(bwd_iats),
            "Flow IAT Max": safe_max(all_iats),
            "Flow Duration": dur_us,
            "Total Fwd Packets": float(len(fwd)),
            "Total Backward Packets": float(len(bwd)),
            "Fwd Packet Length Mean": safe_mean(fwd_lens),
            "Bwd Packet Length Mean": safe_mean(bwd_lens),
            "Fwd Packet Length Std": safe_std(fwd_lens),
            "Bwd Packet Length Max": safe_max(bwd_lens),
            "Flow IAT Mean": safe_mean(all_iats),
            "Flow IAT Std": safe_std(all_iats),
            "Fwd IAT Total": safe_sum(fwd_iats),
            "Fwd Packets/s": len(fwd) / dur_s,
            "Down/Up Ratio": down_up,
            "SYN Flag Count": float(syn_cnt),
            "RST Flag Count": float(rst_cnt),
            # DDL extra features
            "Bwd Packet Length Min": safe_min(bwd_lens),
            "Bwd Packet Length Max": safe_max(bwd_lens),
            "Fwd IAT Std": safe_std(fwd_iats),
            "Bwd IAT Min": safe_min(bwd_iats),
            "Bwd IAT Max": safe_max(bwd_iats),
            "Bwd IAT Std": safe_std(bwd_iats),
            "Bwd IAT Mean": safe_mean(bwd_iats),
            "Bwd Packets/s": len(bwd) / dur_s,
            "Fwd Header Length.1": float(fwd_hdr_len),
            "ACK Flag Count": float(ack_cnt),
            "URG Flag Count": float(urg_cnt),
        }

    except Exception as e:
        logger.debug(f"Error reading {pcap_path}: {e}")
        return None


# ─── Model loaders ─────────────────────────────────────────────────────────

def load_models(models_dir: Path):
    bcc_data = joblib.load(models_dir / "sentry_model_v2.pkl")
    bcc_model = bcc_data["model"] if isinstance(bcc_data, dict) else bcc_data
    bcc_features = bcc_data.get("feature_names", None) if isinstance(bcc_data, dict) else None

    from DDLModel.ddl_model import DeepDictionaryLearning
    ddl = DeepDictionaryLearning.load(models_dir / "ddl_40feat.pkl")

    if_data = joblib.load(models_dir / "isolation_forest.pkl")
    if_model = if_data["clf"] if isinstance(if_data, dict) else if_data
    if_features = if_data.get("feature_names", None) if isinstance(if_data, dict) else None

    return bcc_model, bcc_features, ddl, if_model, if_features


# ─── Feature vectors from raw dict ─────────────────────────────────────────

BCC_28_FEATURES = [
    "Packet Length Variance", "Fwd Packet Length Max", "Fwd Header Length",
    "Init_Win_bytes_forward", "Bwd Header Length", "Total Length of Fwd Packets",
    "Init_Win_bytes_backward", "Bwd Packets/s", "Flow IAT Min", "Fwd IAT Min",
    "Flow Bytes/s", "Active Min", "Bwd IAT Total", "Flow IAT Max",
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Flow IAT Mean", "Flow IAT Std", "Fwd IAT Total",
    "Fwd Packets/s", "Down/Up Ratio", "SYN Flag Count", "RST Flag Count",
]

DDL_40_FEATURES = BCC_28_FEATURES + [
    "Bwd Packet Length Min", "Bwd Packet Length Max", "Flow IAT Mean", "Flow IAT Std",
    "Fwd IAT Total", "Bwd IAT Min", "Fwd Packets/s", "Bwd Packets/s",
    "Fwd Header Length.1", "Active Min", "ACK Flag Count", "URG Flag Count",
][:12]  # 28 + 12 = 40


def make_vector(feat_dict: dict, feature_list: list) -> np.ndarray:
    return np.array([feat_dict.get(f, 0.0) for f in feature_list], dtype=np.float32)


# ─── Main evaluation ────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PCAP pipeline evaluation")
    parser.add_argument("--pcap-dir", default="/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Friday-labeled-small")
    parser.add_argument("--limit", type=int, default=None, help="Max flows to process")
    parser.add_argument("--out-dir", default=None)
    args = parser.parse_args()

    proj = PROJ
    models_dir = proj / "models"
    out_dir = Path(args.out_dir) if args.out_dir else proj / "results" / "pcap_results"
    out_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("PCAP PIPELINE EVALUATION")
    logger.info(f"PCAP dir: {args.pcap_dir}")
    logger.info("=" * 60)

    logger.info("Loading models...")
    bcc_model, bcc_features, ddl, if_model, if_features = load_models(models_dir)

    # Load DDL feature names from model
    try:
        from DDLModel.ddl_feature_extractor import DDL_FEATURES
        ddl_feat_names = DDL_FEATURES
    except Exception:
        ddl_feat_names = DDL_40_FEATURES

    logger.info(f"  BCC: {type(bcc_model).__name__}")
    logger.info(f"  DDL: {ddl.n_features} features, threshold={ddl.threshold_:.4f}")
    logger.info(f"  IF:  {type(if_model).__name__}")

    # Discover flow directories
    pcap_root = Path(args.pcap_dir)
    flow_dirs = sorted([d for d in pcap_root.iterdir() if d.is_dir()])
    if args.limit:
        flow_dirs = flow_dirs[:args.limit]

    logger.info(f"\nFound {len(flow_dirs)} labeled flow directories")

    # ── Per-flow processing ──────────────────────────────────────────────
    results = []
    timing = {
        "feature_extraction_us": [],
        "bcc_us": [],
        "ddl_us": [],
        "if_us": [],
        "total_pipeline_us": [],
    }

    tp = tn = fp = fn = 0
    bcc_flagged = 0
    ddl_if_drop = 0
    skipped = 0

    for i, flow_dir in enumerate(flow_dirs):
        pcap_file = flow_dir / "packets.pcap"
        if not pcap_file.exists():
            skipped += 1
            continue

        # Ground truth from directory name
        dir_name = flow_dir.name.upper()
        is_attack = "BENIGN" not in dir_name
        y_true = 1 if is_attack else 0
        label_str = dir_name.split("_")[-1] if "_" in dir_name else "UNKNOWN"

        t_total_start = time.perf_counter()

        # ── Feature extraction ──
        t0 = time.perf_counter()
        feat_dict = extract_flow_features_from_pcap(str(pcap_file))
        t1 = time.perf_counter()
        feat_time_us = (t1 - t0) * 1e6

        if feat_dict is None:
            skipped += 1
            continue

        timing["feature_extraction_us"].append(feat_time_us)

        # ── BCC Stage 1 ──
        bcc_vec = make_vector(feat_dict, BCC_28_FEATURES).reshape(1, -1)
        t0 = time.perf_counter()
        bcc_pred = int(bcc_model.predict(bcc_vec)[0])
        t1 = time.perf_counter()
        bcc_time_us = (t1 - t0) * 1e6
        timing["bcc_us"].append(bcc_time_us)

        bcc_flagged_flow = (bcc_pred == 1)
        if bcc_flagged_flow:
            bcc_flagged += 1

        # ── DDL + IF Stage 2 (only if BCC flags) ──
        ddl_time_us = if_time_us = 0.0
        final_pred = 0  # default forward

        if bcc_flagged_flow:
            ddl_vec = make_vector(feat_dict, ddl_feat_names).reshape(1, -1)

            # DDL
            t0 = time.perf_counter()
            ddl_out = ddl.predict(ddl_vec)
            ddl_label = ddl_out["labels"][0]
            t1 = time.perf_counter()
            ddl_time_us = (t1 - t0) * 1e6
            timing["ddl_us"].append(ddl_time_us)

            # IF
            t0 = time.perf_counter()
            if_score = if_model.predict(ddl_vec)[0]
            t1 = time.perf_counter()
            if_time_us = (t1 - t0) * 1e6
            timing["if_us"].append(if_time_us)

            # Consensus: DROP only if both agree anomaly
            ddl_anomaly = (ddl_label == "Anomaly")
            if_anomaly = (if_score == -1)
            if ddl_anomaly and if_anomaly:
                final_pred = 1
                ddl_if_drop += 1
        else:
            final_pred = 0  # BCC says benign → forward

        t_total_end = time.perf_counter()
        total_us = (t_total_end - t_total_start) * 1e6
        timing["total_pipeline_us"].append(total_us)

        # Confusion matrix
        if final_pred == 1 and y_true == 1: tp += 1
        elif final_pred == 1 and y_true == 0: fp += 1
        elif final_pred == 0 and y_true == 1: fn += 1
        else: tn += 1

        results.append({
            "flow_dir": flow_dir.name,
            "true_label": label_str,
            "y_true": y_true,
            "bcc_flagged": bcc_flagged_flow,
            "final_pred": final_pred,
            "decision": "DROP" if final_pred == 1 else "FORWARD",
            "feat_time_us": round(feat_time_us, 2),
            "bcc_time_us": round(bcc_time_us, 3),
            "ddl_time_us": round(ddl_time_us, 2) if ddl_time_us else None,
            "if_time_us": round(if_time_us, 2) if if_time_us else None,
            "total_us": round(total_us, 2),
        })

        if (i + 1) % 20 == 0:
            logger.info(f"  Processed {i+1}/{len(flow_dirs)} flows...")

    # ── Metrics ─────────────────────────────────────────────────────────────
    n = tp + tn + fp + fn
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    fpr = fp / max(fp + tn, 1)
    accuracy = (tp + tn) / max(n, 1)

    def avg_us(lst): return round(float(np.mean(lst)), 2) if lst else 0.0

    summary = {
        "data_source": "PCAP (Friday-labeled-small, CIC-IDS-2017)",
        "n_flows": n,
        "n_skipped": skipped,
        "confusion_matrix": {"TP": tp, "TN": tn, "FP": fp, "FN": fn},
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
        },
        "pipeline_routing": {
            "total_flows": n,
            "bcc_forwarded_benign": n - bcc_flagged,
            "bcc_flagged_to_stage2": bcc_flagged,
            "stage2_dropped": ddl_if_drop,
            "stage2_forwarded": bcc_flagged - ddl_if_drop,
        },
        "timing_us": {
            "feature_extraction_avg": avg_us(timing["feature_extraction_us"]),
            "bcc_avg": avg_us(timing["bcc_us"]),
            "ddl_avg_on_flagged": avg_us(timing["ddl_us"]),
            "if_avg_on_flagged": avg_us(timing["if_us"]),
            "total_pipeline_avg": avg_us(timing["total_pipeline_us"]),
        },
    }

    # Print summary
    logger.info("\n" + "=" * 60)
    logger.info("PCAP EVALUATION RESULTS")
    logger.info("=" * 60)
    logger.info(f"  Flows processed: {n} | Skipped: {skipped}")
    logger.info(f"  TP={tp}  TN={tn}  FP={fp}  FN={fn}")
    logger.info(f"  Accuracy={accuracy:.4f}  Precision={precision:.4f}  Recall={recall:.4f}  F1={f1:.4f}")
    logger.info(f"  FPR={fpr:.4f}")
    logger.info(f"\n  Pipeline routing:")
    logger.info(f"    BCC forwarded: {n - bcc_flagged}  BCC flagged: {bcc_flagged}")
    logger.info(f"    DDL+IF dropped: {ddl_if_drop}")
    logger.info(f"\n  Timing (per flow, µs):")
    logger.info(f"    Feature extraction: {avg_us(timing['feature_extraction_us'])}")
    logger.info(f"    BCC inference:      {avg_us(timing['bcc_us'])}")
    logger.info(f"    DDL inference:      {avg_us(timing['ddl_us'])} (flagged flows only)")
    logger.info(f"    IF inference:       {avg_us(timing['if_us'])} (flagged flows only)")
    logger.info(f"    Total pipeline:     {avg_us(timing['total_pipeline_us'])}")

    # Save results
    with open(out_dir / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    with open(out_dir / "per_flow_results.json", "w") as f:
        json.dump(results, f, indent=2)

    # Write markdown summary
    md = f"""# PCAP Evaluation Results
**Source:** Friday-labeled-small (CIC-IDS-2017 real PCAPs)
**Flows tested:** {n} | **Skipped (unreadable):** {skipped}

## Confusion Matrix
```
               Predicted
            FORWARD    DROP
Normal       {tn:>6}   {fp:>5}
Attack       {fn:>6}   {tp:>5}
```

## Metrics
| Metric | Value |
|--------|-------|
| Accuracy | {accuracy:.4f} |
| Precision | {precision:.4f} |
| Recall | {recall:.4f} |
| F1 | {f1:.4f} |
| FPR | {fpr:.4f} |

## Pipeline Routing
- BCC forwarded (BENIGN): {n - bcc_flagged}
- BCC flagged to Stage 2: {bcc_flagged}
- DDL+IF consensus DROP: {ddl_if_drop}

## Timing (per flow, µs)
| Stage | Avg Time (µs) | Notes |
|-------|:---:|---|
| Feature extraction (PCAP→features) | {avg_us(timing['feature_extraction_us'])} | dpkt packet parsing |
| BCC inference | {avg_us(timing['bcc_us'])} | Decision Tree predict |
| DDL inference | {avg_us(timing['ddl_us'])} | Flagged flows only |
| IF inference | {avg_us(timing['if_us'])} | Flagged flows only |
| **Total pipeline** | **{avg_us(timing['total_pipeline_us'])}** | End-to-end per flow |
"""
    with open(out_dir / "pcap_summary.md", "w") as f:
        f.write(md)

    logger.info(f"\n  Results saved to: {out_dir}/")
    logger.info("  Files: summary.json, per_flow_results.json, pcap_summary.md")


if __name__ == "__main__":
    main()
