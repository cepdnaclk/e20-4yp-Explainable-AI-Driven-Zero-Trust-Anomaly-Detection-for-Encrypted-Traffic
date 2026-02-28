"""
Zero-Trust Anomaly Detection Pipeline
======================================

Full pipeline for encrypted traffic analysis in an SDN environment:

  .pcap stream → [Feature Extraction (15 features)]
               → [Base Check Classifier — Decision Tree]
                   ├─ Normal → FORWARD immediately
                   └─ Flagged → BUFFER stream in SDN
                              → [DDL Deep Analysis] ← parallel → [SHAP XAI]
                                  ├─ Normal → RELEASE buffer, FORWARD
                                  └─ Anomaly → DROP + XAI Explanation Report

Components:
  1. feature_extractor.py — Extracts 15 CIC-IDS-2017 features from pcap
  2. Decision Tree        — Fast base check (entropy, depth=15, class_weight={Attack:50})
  3. ddl_model.py         — Deep Dictionary Learning for deep anomaly analysis
  4. explainer.py         — SHAP + DDL-native explanations
  5. This file            — Pipeline orchestrator with SDN buffer simulation
"""

import os
import sys
import json
import time
import logging
import numpy as np
import joblib
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# Path setup
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from extraction.feature_extractor import extract_features
from encryption.traffic_encryptor import simulate_encryption_and_latency
from ddl.ddl_model import DeepDictionaryLearning
from xai.explainer import DDLExplainer

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)s] %(levelname)s: %(message)s')
logger = logging.getLogger("Pipeline")

# The 15 features
FEATURE_NAMES = [
    'Packet Length Variance', 'Fwd Packet Length Max', 'Fwd Header Length',
    'Init_Win_bytes_forward', 'Bwd Header Length', 'Total Length of Fwd Packets',
    'Init_Win_bytes_backward', 'Bwd Packets/s', 'Flow IAT Min', 'Fwd IAT Min',
    'Flow Bytes/s', 'Active Min', 'Bwd IAT Total', 'Flow IAT Max', 'Flow Duration'
]


class SDNBuffer:
    """
    Simulates the SDN buffer that holds flagged streams while DDL + XAI
    processes them.
    
    In a real deployment, this would be an actual OpenFlow buffer table.
    Here we track buffered streams, their features, and timing.
    """

    def __init__(self, max_buffer_size=1000, timeout_ms=5000):
        self.buffer = {}
        self.max_buffer_size = max_buffer_size
        self.timeout_ms = timeout_ms  # Max time a stream can be buffered

    def add(self, stream_id, features, metadata=None):
        """Buffer a flagged stream."""
        self.buffer[stream_id] = {
            "features": features,
            "metadata": metadata or {},
            "buffered_at": time.time(),
            "status": "BUFFERED"
        }
        logger.info(f"[SDN Buffer] Stream {stream_id} buffered for deep analysis")

    def release(self, stream_id):
        """Release a buffered stream (DDL says clean)."""
        if stream_id in self.buffer:
            entry = self.buffer.pop(stream_id)
            hold_time = (time.time() - entry["buffered_at"]) * 1000
            logger.info(f"[SDN Buffer] Stream {stream_id} RELEASED after {hold_time:.0f}ms")
            return {"action": "FORWARD", "hold_time_ms": hold_time}
        return None

    def drop(self, stream_id):
        """Drop a buffered stream (DDL confirms anomaly)."""
        if stream_id in self.buffer:
            entry = self.buffer.pop(stream_id)
            hold_time = (time.time() - entry["buffered_at"]) * 1000
            logger.info(f"[SDN Buffer] Stream {stream_id} DROPPED after {hold_time:.0f}ms")
            return {"action": "DROP", "hold_time_ms": hold_time}
        return None

    def get_buffered_count(self):
        return len(self.buffer)


class ZeroTrustPipeline:
    """
    Full zero-trust anomaly detection pipeline.
    
    Stage 1: Feature extraction from pcap (15 CIC-IDS-2017 features)
    Stage 2: Base Check Classifier — Decision Tree (fast check)
    Stage 3: If flagged → DDL deep analysis + SHAP XAI (parallel)
    """

    def __init__(self, dt_model_path=None, ddl_model_path=None,
                 background_data=None, enable_shap=True):
        """
        Args:
            dt_model_path: Path to Decision Tree .pkl (base check classifier).
            ddl_model_path: Path to DDL model .pkl (deep analysis).
            background_data: Normal traffic data for SHAP background (n, 15).
            enable_shap: Whether to run SHAP alongside DDL.
        """
        self.enable_shap = enable_shap
        self.sdn_buffer = SDNBuffer()

        # Stats
        self.stats = {
            "total_streams": 0,
            "dt_passed": 0,       # Decision Tree said Normal → forwarded immediately
            "dt_flagged": 0,      # Decision Tree said Attack → sent to DDL
            "ddl_cleared": 0,     # DDL said Normal → released from buffer
            "ddl_confirmed": 0,   # DDL confirmed anomaly → dropped
            "TP": 0, "TN": 0, "FP": 0, "FN": 0,  # Against ground truth
        }

        # Logs
        self.pipeline_logs = []

        # Load models
        self.dt_model = self._load_dt_model(dt_model_path)
        self.ddl_model = self._load_ddl_model(ddl_model_path)

        # Initialize XAI
        self.explainer = None
        if self.ddl_model and self.ddl_model.is_fitted_:
            self.explainer = DDLExplainer(
                self.ddl_model,
                background_data=background_data,
                feature_names=FEATURE_NAMES
            )

        # Thread pool for parallel DDL + XAI
        self.executor = ThreadPoolExecutor(max_workers=2)

    def _load_dt_model(self, path):
        """Load Decision Tree (base check classifier)."""
        if path and os.path.exists(path):
            try:
                model = joblib.load(path)
                logger.info(f"Decision Tree loaded from {path}")
                return model
            except Exception as e:
                logger.error(f"Failed to load DT model: {e}")
        else:
            logger.warning("No Decision Tree model path provided — will flag all streams for DDL.")
        return None

    def _load_ddl_model(self, path):
        """Load DDL model."""
        if path and os.path.exists(path):
            try:
                model = DeepDictionaryLearning.load(path)
                logger.info(f"DDL model loaded from {path}")
                return model
            except Exception as e:
                logger.error(f"Failed to load DDL model: {e}")
        else:
            logger.warning("No DDL model path provided — using only Decision Tree.")
        return None

    def _base_check(self, ordered_features):
        """
        Stage 2: Decision Tree base check.
        
        Returns:
            (prediction, confidence) — e.g. ("Normal", 0.98) or ("Attack", 0.85)
        """
        if self.dt_model is None:
            # No DT → flag everything for deep analysis (zero-trust default)
            return "Attack", 0.0

        try:
            X = [ordered_features]
            pred = self.dt_model.predict(X)[0]
            conf = max(self.dt_model.predict_proba(X)[0]) if hasattr(self.dt_model, 'predict_proba') else 0.0
            return pred, conf
        except Exception as e:
            logger.error(f"DT prediction error: {e}")
            return "Attack", 0.0  # Fail-closed: flag for deep analysis

    def _deep_analysis(self, ordered_features, include_shap=True):
        """
        Stage 3: DDL deep analysis + XAI explanation (run in parallel).
        
        Returns:
            dict with DDL prediction, explanation report, timing.
        """
        if self.ddl_model is None or not self.ddl_model.is_fitted_:
            return {
                "ddl_available": False,
                "prediction": "Unknown",
                "explanation": None,
                "timing_ms": 0
            }

        features_arr = np.array(ordered_features, dtype=np.float64)
        start = time.time()

        # Run DDL prediction and XAI in parallel
        ddl_future = self.executor.submit(self.ddl_model.predict, features_arr)

        xai_future = None
        if include_shap and self.explainer:
            xai_future = self.executor.submit(
                self.explainer.explain, features_arr, include_shap=self.enable_shap
            )

        # Collect DDL result
        ddl_result = ddl_future.result()
        ddl_label = ddl_result["labels"]
        ddl_score = float(ddl_result["scores"])

        # Collect XAI result
        xai_report = None
        if xai_future:
            xai_report = xai_future.result()

        elapsed_ms = (time.time() - start) * 1000

        return {
            "ddl_available": True,
            "prediction": ddl_label,
            "anomaly_score": ddl_score,
            "threshold": float(ddl_result["threshold"]),
            "explanation": xai_report,
            "timing_ms": round(elapsed_ms, 2)
        }

    def process_stream(self, pcap_path, ground_truth=None):
        """
        Process a single .pcap stream through the full pipeline.
        
        Flow:
            1. Simulate encryption + latency
            2. Extract 15 features
            3. Base Check (Decision Tree)
               - Normal → FORWARD
               - Flagged → Buffer + DDL + XAI
                 - DDL Normal → Release buffer
                 - DDL Anomaly → DROP + explanation
        
        Args:
            pcap_path: Path to .pcap file.
            ground_truth: "Normal" or "Attack" (for evaluation, optional).
            
        Returns:
            dict with full pipeline results and logs.
        """
        self.stats["total_streams"] += 1
        filename = os.path.basename(pcap_path)
        stream_id = f"stream_{self.stats['total_streams']:04d}_{filename}"

        logger.info(f"═══ Processing: {filename} (GT: {ground_truth or 'Unknown'}) ═══")

        result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stream_id": stream_id,
            "input_file": filename,
            "ground_truth": ground_truth,
            "stages": {},
            "final_action": None,
            "explanation": None,
        }

        # ─── Stage 1: Encryption simulation + Feature extraction ───
        enc_result = simulate_encryption_and_latency(pcap_path)
        if not enc_result:
            result["final_action"] = "ERROR"
            result["stages"]["encryption"] = {"error": "Encryption simulation failed"}
            self.pipeline_logs.append(result)
            return result

        result["stages"]["encryption"] = {
            "latency_ms": enc_result["latency_ms"],
            "algorithm": enc_result.get("encryption_algo", "AES-256-GCM")
        }

        ext_result = extract_features(enc_result["encrypted_path"])
        if not ext_result["valid"]:
            result["final_action"] = "ERROR"
            result["stages"]["extraction"] = {"error": ext_result.get("error", "Unknown")}
            self.pipeline_logs.append(result)
            return result

        features_dict = ext_result["features"]
        ordered_features = ext_result["ordered_features"]

        result["stages"]["extraction"] = {
            "features": features_dict,
            "flow_id": ext_result.get("flow_id"),
            "protocol": ext_result.get("protocol"),
        }

        # ─── Stage 2: Base Check Classifier (Decision Tree) ───
        dt_pred, dt_conf = self._base_check(ordered_features)

        result["stages"]["base_check"] = {
            "prediction": dt_pred,
            "confidence": round(dt_conf, 4),
            "model": "DecisionTree (entropy, depth=15, attack_weight=50)"
        }

        if dt_pred == "Normal":
            # Decision Tree says clean → immediate FORWARD
            result["final_action"] = "FORWARD"
            result["stages"]["deep_analysis"] = {"skipped": True, "reason": "DT passed as Normal"}
            self.stats["dt_passed"] += 1

            logger.info(f"[Stage 2] DT: Normal (conf={dt_conf:.2f}) → FORWARD immediately")

        else:
            # Decision Tree flagged → Buffer + DDL + XAI
            self.stats["dt_flagged"] += 1
            logger.info(f"[Stage 2] DT: Flagged (conf={dt_conf:.2f}) → Buffering for deep analysis")

            # Buffer the stream
            self.sdn_buffer.add(stream_id, ordered_features, {"pcap": pcap_path})

            # ─── Stage 3: Deep Analysis (DDL + XAI in parallel) ───
            deep_result = self._deep_analysis(ordered_features, include_shap=True)

            result["stages"]["deep_analysis"] = {
                "ddl_available": deep_result["ddl_available"],
                "ddl_prediction": deep_result.get("prediction"),
                "anomaly_score": deep_result.get("anomaly_score"),
                "threshold": deep_result.get("threshold"),
                "analysis_time_ms": deep_result.get("timing_ms"),
            }

            if deep_result["prediction"] == "Normal":
                # DDL says clean → release buffer
                buf_result = self.sdn_buffer.release(stream_id)
                result["final_action"] = "FORWARD"
                result["stages"]["buffer"] = {
                    "action": "RELEASED",
                    "hold_time_ms": buf_result["hold_time_ms"] if buf_result else 0
                }
                self.stats["ddl_cleared"] += 1
                logger.info(f"[Stage 3] DDL: Normal → RELEASE buffer, FORWARD")

            else:
                # DDL confirms anomaly → DROP + explanation
                buf_result = self.sdn_buffer.drop(stream_id)
                result["final_action"] = "DROP"
                result["stages"]["buffer"] = {
                    "action": "DROPPED",
                    "hold_time_ms": buf_result["hold_time_ms"] if buf_result else 0
                }
                self.stats["ddl_confirmed"] += 1

                # Attach XAI explanation
                if deep_result.get("explanation"):
                    result["explanation"] = {
                        "summary": deep_result["explanation"].get("summary"),
                        "ddl_native": deep_result["explanation"].get("ddl_explanation"),
                        "shap": deep_result["explanation"].get("shap_explanation"),
                    }

                logger.info(f"[Stage 3] DDL: Anomaly → DROP + XAI explanation attached")
                if result["explanation"] and result["explanation"].get("summary"):
                    logger.info(f"  Explanation: {result['explanation']['summary']}")

        # ─── Update ground truth stats ───
        if ground_truth:
            gt_is_attack = "attack" in ground_truth.lower()
            pred_is_attack = (result["final_action"] == "DROP")

            if gt_is_attack and pred_is_attack:
                self.stats["TP"] += 1
            elif not gt_is_attack and not pred_is_attack:
                self.stats["TN"] += 1
            elif not gt_is_attack and pred_is_attack:
                self.stats["FP"] += 1
            else:
                self.stats["FN"] += 1

        self.pipeline_logs.append(result)
        return result

    def run_batch(self, pcap_list, output_log="pipeline_results.json"):
        """
        Run the pipeline on a batch of (pcap_path, ground_truth) tuples.
        
        Args:
            pcap_list: List of (file_path, "Normal"/"Attack") tuples.
            output_log: Where to save the full results JSON.
        """
        logger.info(f"Starting pipeline on {len(pcap_list)} streams")
        normal_count = sum(1 for _, l in pcap_list if l and "normal" in l.lower())
        attack_count = sum(1 for _, l in pcap_list if l and "attack" in l.lower())
        logger.info(f"  Normal: {normal_count}, Attack: {attack_count}")

        results = []
        for pcap_path, label in pcap_list:
            result = self.process_stream(pcap_path, ground_truth=label)
            results.append(result)

        # Save results
        output = {
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_streams": len(pcap_list),
            "stats": self.stats,
            "stream_results": results,
        }

        with open(output_log, "w") as f:
            json.dump(output, f, indent=2, default=str)
        logger.info(f"Results saved to {output_log}")

        # Print summary
        self._print_summary()

        return output

    def _print_summary(self):
        """Print human-readable pipeline summary."""
        s = self.stats
        total = s["total_streams"]
        print("\n" + "=" * 70)
        print("  ZERO-TRUST PIPELINE — EXECUTION SUMMARY")
        print("=" * 70)
        print(f"  Total streams processed:       {total}")
        print(f"  ├─ DT passed (Normal):         {s['dt_passed']}")
        print(f"  └─ DT flagged → buffered:      {s['dt_flagged']}")
        if s["dt_flagged"] > 0:
            print(f"      ├─ DDL cleared (released):  {s['ddl_cleared']}")
            print(f"      └─ DDL confirmed (dropped): {s['ddl_confirmed']}")
        print()
        print("  Ground Truth Evaluation:")
        print(f"    TP (Attack correctly dropped):  {s['TP']}")
        print(f"    TN (Normal correctly forwarded): {s['TN']}")
        print(f"    FP (Normal incorrectly dropped): {s['FP']}")
        print(f"    FN (Attack incorrectly passed):  {s['FN']}")

        total_eval = s['TP'] + s['TN'] + s['FP'] + s['FN']
        if total_eval > 0:
            accuracy = (s['TP'] + s['TN']) / total_eval
            precision = s['TP'] / (s['TP'] + s['FP']) if (s['TP'] + s['FP']) > 0 else 0
            recall = s['TP'] / (s['TP'] + s['FN']) if (s['TP'] + s['FN']) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            print(f"\n    Accuracy:  {accuracy:.4f}")
            print(f"    Precision: {precision:.4f}")
            print(f"    Recall:    {recall:.4f}")
            print(f"    F1-Score:  {f1:.4f}")

        print("=" * 70 + "\n")
