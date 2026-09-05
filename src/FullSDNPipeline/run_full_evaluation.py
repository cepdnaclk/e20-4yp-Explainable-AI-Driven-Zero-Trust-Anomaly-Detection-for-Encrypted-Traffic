#!/usr/bin/env python3
"""
run_full_evaluation.py — Comprehensive Per-Model & Full Pipeline Evaluation
============================================================================
Tests each model separately and the full pipeline together.
Generates structured results in results/ with confusion matrices, timing, and XAI.

Usage:
    cd /scratch1/.../e20-4yp-.../
    source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate
    python FullSDNPipeline/run_full_evaluation.py
"""

import os, sys, json, time, logging, argparse
import numpy as np
import pandas as pd
from sklearn.metrics import (confusion_matrix, accuracy_score, precision_score,
                             recall_score, f1_score, classification_report)
import joblib

_THIS_DIR    = os.path.dirname(os.path.abspath(__file__))
SRC_ROOT     = os.path.dirname(_THIS_DIR)
PROJECT_ROOT = os.path.dirname(SRC_ROOT)
sys.path.insert(0, SRC_ROOT)

from DDLModel.ddl_model import DeepDictionaryLearning
from DDLModel.ddl_feature_extractor import DDL_FEATURE_NAMES, N_DDL_FEATURES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("FullEval")

# ── Column mapping ───────────────────────────────────────────────────────────
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


def compute_metrics(y_true, y_pred, name=""):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    return {
        "name": name,
        "confusion_matrix": {"TP": int(tp), "TN": int(tn), "FP": int(fp), "FN": int(fn)},
        "metrics": {
            "accuracy": round(acc, 6), "precision": round(prec, 6),
            "recall": round(rec, 6), "f1": round(f1, 6),
            "fpr": round(fpr, 6), "fnr": round(fnr, 6),
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Comprehensive pipeline evaluation")
    parser.add_argument("--test-csv", default=os.path.join(PROJECT_ROOT, "dataset", "TEST_Traffic.csv"))
    parser.add_argument("--bcc-model", default=os.path.join(PROJECT_ROOT, "models", "sentry_model_v2.pkl"))
    parser.add_argument("--ddl-model", default=os.path.join(PROJECT_ROOT, "models", "ddl_40feat.pkl"))
    parser.add_argument("--if-model", default=os.path.join(PROJECT_ROOT, "models", "isolation_forest.pkl"))
    parser.add_argument("--max-rows", type=int, default=50000, help="Limit test rows for speed")
    parser.add_argument("--xai-samples", type=int, default=5, help="Number of flows to explain with XAI")
    parser.add_argument("--results-dir", default=os.path.join(PROJECT_ROOT, "results"))
    args = parser.parse_args()

    os.makedirs(args.results_dir, exist_ok=True)
    for sub in ["stage1_bcc", "stage2_ddl", "stage2_if", "stage2_xai", "full_pipeline"]:
        os.makedirs(os.path.join(args.results_dir, sub), exist_ok=True)

    all_results = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "config": vars(args)}

    # ═══════════════════════════════════════════════════════════════════════════
    # LOAD MODELS
    # ═══════════════════════════════════════════════════════════════════════════
    logger.info("=" * 60)
    logger.info("LOADING MODELS")
    logger.info("=" * 60)

    # BCC
    bcc_data = joblib.load(args.bcc_model)
    bcc_model = bcc_data['model'] if isinstance(bcc_data, dict) else bcc_data
    bcc_thresh = bcc_data.get('threshold', 0.5) if isinstance(bcc_data, dict) else 0.5
    bcc_feat_names = bcc_data.get('feature_names', []) if isinstance(bcc_data, dict) else []
    logger.info(f"  BCC: {type(bcc_model).__name__}, threshold={bcc_thresh}, features={len(bcc_feat_names)}")

    # DDL
    ddl = DeepDictionaryLearning.load(args.ddl_model)
    logger.info(f"  DDL: {ddl.n_features} features, threshold={ddl.threshold_:.6f}")

    # IF
    if_data = joblib.load(args.if_model)
    if_model = if_data['clf'] if isinstance(if_data, dict) else if_data
    logger.info(f"  IF:  {type(if_model).__name__}")

    # ═══════════════════════════════════════════════════════════════════════════
    # LOAD TEST DATA
    # ═══════════════════════════════════════════════════════════════════════════
    logger.info("=" * 60)
    logger.info("LOADING TEST DATA")
    logger.info("=" * 60)

    df = pd.read_csv(args.test_csv, nrows=args.max_rows, low_memory=False)
    df.columns = df.columns.str.strip()
    # Column alias
    if 'Total Backward Packets' in df.columns and 'Total Bwd Packets' not in df.columns:
        df['Total Bwd Packets'] = df['Total Backward Packets']
    labels = df['Label'].str.strip().str.lower()
    y_true = (~labels.isin(['normal', 'benign'])).astype(int).values
    logger.info(f"  Rows: {len(df):,}  Normal: {(y_true==0).sum():,}  Attack: {(y_true==1).sum():,}")

    # BCC features
    bcc_missing = [c for c in bcc_feat_names if c not in df.columns]
    for c in bcc_missing:
        df[c] = 0.0
    X_bcc = df[bcc_feat_names].values.astype(np.float64)
    X_bcc = np.nan_to_num(X_bcc, nan=0.0, posinf=1e9, neginf=-1e9)

    # DDL features
    ddl_cols = [DDL_TO_CSV[n] for n in DDL_FEATURE_NAMES]
    for c in ddl_cols:
        if c not in df.columns:
            df[c] = 0.0
    X_ddl = df[ddl_cols].values.astype(np.float64)
    X_ddl = np.nan_to_num(X_ddl, nan=0.0, posinf=1e9, neginf=-1e9)
    X_ddl = np.clip(X_ddl, -1e9, 1e9)

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST 1: BCC STANDALONE
    # ═══════════════════════════════════════════════════════════════════════════
    logger.info("=" * 60)
    logger.info("TEST 1: BCC v2 Standalone (28 features)")
    logger.info("=" * 60)

    t0 = time.perf_counter()
    bcc_proba = bcc_model.predict_proba(X_bcc)[:, 1]
    bcc_preds = (bcc_proba >= bcc_thresh).astype(int)
    bcc_time = time.perf_counter() - t0
    bcc_per_flow_us = (bcc_time / len(df)) * 1_000_000

    bcc_result = compute_metrics(y_true, bcc_preds, "BCC v2 Standalone")
    bcc_result["timing"] = {
        "total_s": round(bcc_time, 4),
        "per_flow_us": round(bcc_per_flow_us, 2),
        "n_flows": len(df),
    }
    bcc_result["n_flagged_attack"] = int(bcc_preds.sum())
    bcc_result["n_passed_benign"] = int((bcc_preds == 0).sum())

    cm = bcc_result["confusion_matrix"]
    logger.info(f"  TN={cm['TN']:,}  FP={cm['FP']:,}")
    logger.info(f"  FN={cm['FN']:,}  TP={cm['TP']:,}")
    logger.info(f"  Recall: {bcc_result['metrics']['recall']:.4f}  Precision: {bcc_result['metrics']['precision']:.4f}")
    logger.info(f"  Timing: {bcc_time:.4f}s total, {bcc_per_flow_us:.2f} us/flow")

    with open(os.path.join(args.results_dir, "stage1_bcc", "results.json"), "w") as f:
        json.dump(bcc_result, f, indent=2)
    all_results["stage1_bcc"] = bcc_result

    # Also test on Sandaru's data if available
    sandaru_raw = os.path.join(SRC_ROOT, "BaseCheckClassifier", "sdn", "training", "test_raw.csv")
    if os.path.exists(sandaru_raw):
        logger.info("  Testing BCC on Sandaru's test_raw.csv...")
        df_s = pd.read_csv(sandaru_raw, low_memory=False)
        X_s = df_s[bcc_feat_names].values.astype(np.float64)
        X_s = np.nan_to_num(X_s, nan=0.0, posinf=1e9, neginf=-1e9)
        y_s = (df_s['label'] == 'ATTACK').astype(int).values
        s_proba = bcc_model.predict_proba(X_s)[:, 1]
        s_preds = (s_proba >= bcc_thresh).astype(int)
        bcc_sandaru = compute_metrics(y_s, s_preds, "BCC v2 on Sandaru's test_raw.csv")
        cm_s = bcc_sandaru["confusion_matrix"]
        logger.info(f"  Sandaru TN={cm_s['TN']:,}  FP={cm_s['FP']:,}")
        logger.info(f"  Sandaru FN={cm_s['FN']:,}  TP={cm_s['TP']:,}")
        logger.info(f"  Sandaru Recall: {bcc_sandaru['metrics']['recall']:.4f}")
        with open(os.path.join(args.results_dir, "stage1_bcc", "results_sandaru_data.json"), "w") as f:
            json.dump(bcc_sandaru, f, indent=2)
        all_results["stage1_bcc_sandaru"] = bcc_sandaru

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST 2: DDL STANDALONE
    # ═══════════════════════════════════════════════════════════════════════════
    logger.info("=" * 60)
    logger.info("TEST 2: DDL Standalone (40 features)")
    logger.info("=" * 60)

    t0 = time.perf_counter()
    ddl_result_raw = ddl.predict(X_ddl)
    ddl_time = time.perf_counter() - t0
    ddl_per_flow_us = (ddl_time / len(df)) * 1_000_000

    ddl_labels = np.array([1 if l == "Anomaly" else 0 for l in ddl_result_raw["labels"]])
    ddl_result = compute_metrics(y_true, ddl_labels, "DDL Standalone")
    ddl_result["timing"] = {
        "total_s": round(ddl_time, 4),
        "per_flow_us": round(ddl_per_flow_us, 2),
        "n_flows": len(df),
    }
    ddl_result["threshold"] = float(ddl.threshold_)
    ddl_result["mean_score"] = float(ddl_result_raw["scores"].mean())
    ddl_result["max_score"] = float(ddl_result_raw["scores"].max())

    cm = ddl_result["confusion_matrix"]
    logger.info(f"  TN={cm['TN']:,}  FP={cm['FP']:,}")
    logger.info(f"  FN={cm['FN']:,}  TP={cm['TP']:,}")
    logger.info(f"  Recall: {ddl_result['metrics']['recall']:.4f}  Precision: {ddl_result['metrics']['precision']:.4f}")
    logger.info(f"  Timing: {ddl_time:.4f}s total, {ddl_per_flow_us:.2f} us/flow")

    with open(os.path.join(args.results_dir, "stage2_ddl", "results.json"), "w") as f:
        json.dump(ddl_result, f, indent=2)
    all_results["stage2_ddl"] = ddl_result

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST 3: IF STANDALONE
    # ═══════════════════════════════════════════════════════════════════════════
    logger.info("=" * 60)
    logger.info("TEST 3: Isolation Forest Standalone (40 features)")
    logger.info("=" * 60)

    t0 = time.perf_counter()
    if_preds_raw = if_model.predict(X_ddl)
    if_time = time.perf_counter() - t0
    if_per_flow_us = (if_time / len(df)) * 1_000_000

    if_labels = np.where(if_preds_raw == -1, 1, 0)  # -1=anomaly→1, 1=normal→0
    if_result = compute_metrics(y_true, if_labels, "Isolation Forest Standalone")
    if_result["timing"] = {
        "total_s": round(if_time, 4),
        "per_flow_us": round(if_per_flow_us, 2),
        "n_flows": len(df),
    }

    cm = if_result["confusion_matrix"]
    logger.info(f"  TN={cm['TN']:,}  FP={cm['FP']:,}")
    logger.info(f"  FN={cm['FN']:,}  TP={cm['TP']:,}")
    logger.info(f"  Recall: {if_result['metrics']['recall']:.4f}  Precision: {if_result['metrics']['precision']:.4f}")
    logger.info(f"  Timing: {if_time:.4f}s total, {if_per_flow_us:.2f} us/flow")

    with open(os.path.join(args.results_dir, "stage2_if", "results.json"), "w") as f:
        json.dump(if_result, f, indent=2)
    all_results["stage2_if"] = if_result

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST 4: FULL PIPELINE (BCC → DDL + IF consensus)
    # ═══════════════════════════════════════════════════════════════════════════
    logger.info("=" * 60)
    logger.info("TEST 4: Full Pipeline (BCC → DDL + IF + XAI)")
    logger.info("=" * 60)

    pipeline_preds = np.zeros(len(df), dtype=int)
    stage_used = np.full(len(df), "BCC", dtype=object)

    # Stage 1
    t0_pipe = time.perf_counter()
    bcc_flagged = bcc_preds == 1
    n_bcc_pass = int((~bcc_flagged).sum())
    n_bcc_flag = int(bcc_flagged.sum())
    t1_bcc = time.perf_counter() - t0_pipe

    # Stage 2 on flagged only
    t0_s2 = time.perf_counter()
    if n_bcc_flag > 0:
        X_ddl_flagged = X_ddl[bcc_flagged]
        ddl_res_flagged = ddl.predict(X_ddl_flagged)
        ddl_lab_flagged = np.array([1 if l == "Anomaly" else 0 for l in ddl_res_flagged["labels"]])

        if_pred_flagged = if_model.predict(X_ddl_flagged)
        if_lab_flagged = np.where(if_pred_flagged == -1, 1, 0)

        # Consensus: DROP only when BOTH DDL AND IF say anomaly
        consensus_drop = (ddl_lab_flagged == 1) & (if_lab_flagged == 1)
        pipeline_preds[bcc_flagged] = np.where(consensus_drop, 1, 0)
        stage_used[bcc_flagged] = "DDL+IF"

        n_ddl_drop = int(consensus_drop.sum())
        n_ddl_forward = n_bcc_flag - n_ddl_drop
    else:
        n_ddl_drop = 0
        n_ddl_forward = 0
    t2_s2 = time.perf_counter() - t0_s2
    total_pipe_time = time.perf_counter() - t0_pipe

    pipe_result = compute_metrics(y_true, pipeline_preds, "Full Pipeline (BCC→DDL+IF)")
    pipe_result["timing"] = {
        "total_s": round(total_pipe_time, 4),
        "stage1_bcc_s": round(t1_bcc, 4),
        "stage2_ddl_if_s": round(t2_s2, 4),
        "per_flow_total_us": round((total_pipe_time / len(df)) * 1_000_000, 2),
        "n_flows": len(df),
    }
    pipe_result["flow_routing"] = {
        "bcc_passed_benign": n_bcc_pass,
        "bcc_flagged_to_ddl": n_bcc_flag,
        "ddl_if_forward": n_ddl_forward,
        "ddl_if_drop": n_ddl_drop,
    }

    cm = pipe_result["confusion_matrix"]
    logger.info(f"  BCC: {n_bcc_pass:,} BENIGN, {n_bcc_flag:,} → Stage 2")
    logger.info(f"  DDL+IF: {n_ddl_forward:,} FORWARD, {n_ddl_drop:,} DROP")
    logger.info(f"  TN={cm['TN']:,}  FP={cm['FP']:,}")
    logger.info(f"  FN={cm['FN']:,}  TP={cm['TP']:,}")
    logger.info(f"  Recall: {pipe_result['metrics']['recall']:.4f}  Precision: {pipe_result['metrics']['precision']:.4f}")
    logger.info(f"  Timing: {total_pipe_time:.4f}s total")

    with open(os.path.join(args.results_dir, "full_pipeline", "results.json"), "w") as f:
        json.dump(pipe_result, f, indent=2)
    all_results["full_pipeline"] = pipe_result

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST 5: XAI EXPLANATIONS (LIME + SHAP) on sample anomalies
    # ═══════════════════════════════════════════════════════════════════════════
    logger.info("=" * 60)
    logger.info(f"TEST 5: XAI Explanations (LIME + SHAP) on {args.xai_samples} anomalies")
    logger.info("=" * 60)

    try:
        from FullSDNPipeline.xai_explainer import XAIExplainer

        # Get some normal training data for SHAP background
        normal_mask = (y_true == 0)
        bg_data = X_ddl[normal_mask][:200]

        xai = XAIExplainer(ddl, if_model, training_data=bg_data, feature_names=DDL_FEATURE_NAMES)

        # Find flows that were dropped (true anomalies caught by pipeline)
        dropped_indices = np.where(pipeline_preds == 1)[0]
        if len(dropped_indices) == 0:
            dropped_indices = np.where(y_true == 1)[0]  # Fallback: use actual attacks
        sample_indices = dropped_indices[:args.xai_samples]

        t0_xai = time.perf_counter()
        xai_explanations = []
        for i, idx in enumerate(sample_indices):
            logger.info(f"  Explaining flow {i+1}/{len(sample_indices)} (idx={idx})...")
            exp = xai.explain_flow(X_ddl[idx], top_k=10)
            exp["flow_index"] = int(idx)
            exp["ground_truth"] = "Attack" if y_true[idx] == 1 else "Normal"
            exp["pipeline_decision"] = "DROP" if pipeline_preds[idx] == 1 else "FORWARD"
            xai_explanations.append(exp)
        xai_time = time.perf_counter() - t0_xai

        xai_result = {
            "n_explained": len(xai_explanations),
            "timing": {
                "total_s": round(xai_time, 4),
                "per_flow_s": round(xai_time / max(len(xai_explanations), 1), 4),
            },
            "explanations": xai_explanations,
        }

        logger.info(f"  XAI total time: {xai_time:.2f}s ({xai_time/max(len(xai_explanations),1):.2f}s per flow)")

        with open(os.path.join(args.results_dir, "stage2_xai", "explanations.json"), "w") as f:
            json.dump(xai_result, f, indent=2)
        all_results["xai"] = {"n_explained": len(xai_explanations),
                              "timing": xai_result["timing"]}

        # Generate readable XAI summary
        xai_summary_lines = ["# XAI Explanation Samples\n"]
        for exp in xai_explanations:
            xai_summary_lines.append(f"\n## Flow #{exp['flow_index']} — GT: {exp['ground_truth']}, Decision: {exp['pipeline_decision']}\n")
            if exp.get("ddl_lime") and not exp["ddl_lime"].get("error"):
                xai_summary_lines.append("### DDL LIME Top Features\n")
                xai_summary_lines.append("| Feature | Weight |")
                xai_summary_lines.append("|---------|--------|")
                for feat in exp["ddl_lime"]["top_features"][:5]:
                    xai_summary_lines.append(f"| {feat['feature']} | {feat['weight']:.6f} |")
            if exp.get("ddl_shap") and not exp["ddl_shap"].get("error"):
                xai_summary_lines.append("\n### DDL SHAP Top Features\n")
                xai_summary_lines.append("| Feature | SHAP Value | Feature Value |")
                xai_summary_lines.append("|---------|-----------|---------------|")
                for feat in exp["ddl_shap"]["top_features"][:5]:
                    xai_summary_lines.append(f"| {feat['feature']} | {feat['shap_value']:.6f} | {feat['feature_value']:.4f} |")
            if exp.get("if_lime") and not exp["if_lime"].get("error"):
                xai_summary_lines.append("\n### IF LIME Top Features\n")
                xai_summary_lines.append("| Feature | Weight |")
                xai_summary_lines.append("|---------|--------|")
                for feat in exp["if_lime"]["top_features"][:5]:
                    xai_summary_lines.append(f"| {feat['feature']} | {feat['weight']:.6f} |")
            if exp.get("if_shap") and not exp["if_shap"].get("error"):
                xai_summary_lines.append("\n### IF SHAP Top Features\n")
                xai_summary_lines.append("| Feature | SHAP Value | Feature Value |")
                xai_summary_lines.append("|---------|-----------|---------------|")
                for feat in exp["if_shap"]["top_features"][:5]:
                    xai_summary_lines.append(f"| {feat['feature']} | {feat['shap_value']:.6f} | {feat['feature_value']:.4f} |")
            timing = exp.get("timing", {})
            xai_summary_lines.append(f"\n**Timing:** DDL-LIME: {timing.get('ddl_lime_ms', 'N/A')}ms | DDL-SHAP: {timing.get('ddl_shap_ms', 'N/A')}ms | IF-LIME: {timing.get('if_lime_ms', 'N/A')}ms | IF-SHAP: {timing.get('if_shap_ms', 'N/A')}ms\n")

        with open(os.path.join(args.results_dir, "stage2_xai", "xai_summary.md"), "w") as f:
            f.write("\n".join(xai_summary_lines))

    except Exception as e:
        logger.error(f"XAI failed: {e}")
        import traceback
        traceback.print_exc()
        all_results["xai"] = {"error": str(e)}

    # ═══════════════════════════════════════════════════════════════════════════
    # SUMMARY REPORT
    # ═══════════════════════════════════════════════════════════════════════════
    logger.info("=" * 60)
    logger.info("GENERATING SUMMARY REPORT")
    logger.info("=" * 60)

    with open(os.path.join(args.results_dir, "all_results.json"), "w") as f:
        json.dump(all_results, f, indent=2)

    # Generate summary.md
    summary = [
        "# Evaluation Results Summary",
        f"\n**Date:** {all_results['timestamp']}",
        f"**Test data:** {args.test_csv} ({args.max_rows} rows)" if args.max_rows else f"**Test data:** {args.test_csv} (all rows)",
        "",
        "## Per-Model Results\n",
        "| Model | Accuracy | Precision | Recall | F1 | FPR | Time/flow |",
        "|-------|----------|-----------|--------|-----|-----|-----------|",
    ]

    for stage_key, stage_name in [("stage1_bcc", "BCC v2"), ("stage2_ddl", "DDL-40"),
                                   ("stage2_if", "IF"), ("full_pipeline", "Full Pipeline")]:
        if stage_key in all_results:
            m = all_results[stage_key]["metrics"]
            t_str = f"{all_results[stage_key].get('timing', {}).get('per_flow_us', 'N/A')} us"
            summary.append(f"| {stage_name} | {m['accuracy']:.4f} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {m['fpr']:.4f} | {t_str} |")

    if "stage1_bcc_sandaru" in all_results:
        m = all_results["stage1_bcc_sandaru"]["metrics"]
        summary.append(f"| BCC v2 (Sandaru data) | {m['accuracy']:.4f} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {m['fpr']:.4f} | N/A |")

    summary.extend([
        "",
        "## Confusion Matrices\n",
    ])

    for stage_key, stage_name in [("stage1_bcc", "BCC v2"), ("stage2_ddl", "DDL-40"),
                                   ("stage2_if", "IF"), ("full_pipeline", "Full Pipeline")]:
        if stage_key in all_results:
            cm = all_results[stage_key]["confusion_matrix"]
            summary.extend([
                f"### {stage_name}\n",
                "```",
                f"               Predicted",
                f"            FORWARD    DROP",
                f"Normal     {cm['TN']:>8,}  {cm['FP']:>6,}",
                f"Attack     {cm['FN']:>8,}  {cm['TP']:>6,}",
                "```\n",
            ])

    if "full_pipeline" in all_results:
        fr = all_results["full_pipeline"].get("flow_routing", {})
        summary.extend([
            "## Pipeline Flow Routing\n",
            f"- BCC passed as BENIGN: {fr.get('bcc_passed_benign', 'N/A'):,}",
            f"- BCC flagged to DDL+IF: {fr.get('bcc_flagged_to_ddl', 'N/A'):,}",
            f"- DDL+IF → FORWARD: {fr.get('ddl_if_forward', 'N/A'):,}",
            f"- DDL+IF → DROP: {fr.get('ddl_if_drop', 'N/A'):,}",
            "",
        ])

    summary.extend([
        "## Timing Summary\n",
        "| Stage | Total Time | Per Flow |",
        "|-------|-----------|----------|",
    ])
    for stage_key, stage_name in [("stage1_bcc", "BCC v2"), ("stage2_ddl", "DDL-40"),
                                   ("stage2_if", "IF"), ("full_pipeline", "Full Pipeline")]:
        if stage_key in all_results:
            t = all_results[stage_key].get("timing", {})
            summary.append(f"| {stage_name} | {t.get('total_s', 'N/A')}s | {t.get('per_flow_us', 'N/A')} us |")

    with open(os.path.join(args.results_dir, "summary.md"), "w") as f:
        f.write("\n".join(summary))

    logger.info(f"Results saved to {args.results_dir}/")
    logger.info(f"Summary: {args.results_dir}/summary.md")
    logger.info("DONE")


if __name__ == "__main__":
    main()
