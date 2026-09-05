#!/usr/bin/env python3
"""
sdn_pipeline.py — Full SDN Zero-Trust Pipeline (Single Script)
================================================================
Zero-Trust XAI Anomaly Detection | University of Peradeniya

This is the SINGLE script that runs the complete two-stage pipeline:

    PacketIN (PCAP flow from switch mirror)
      │
      ├── Stage 1: BCC v2 (28 features, Decision Tree)
      │     ├── BENIGN → packetStreamOUT + ALLOW switch rule
      │     └── ATTACK → hold in SDN buffer
      │
      └── Stage 2: DDL 40 features, Deep Dictionary Learning)
            ├── Normal  → packetStreamOUT + ALLOW switch rule
            └── Anomaly → DROP switch rule + XAI explanation

USAGE:

    # Process a single PCAP:
    python FullSDNPipeline/sdn_pipeline.py --pcap flow.pcap

    # Process a directory of per-flow PCAPs (e.g. from CIC-IDS-2017 Labeled):
    python FullSDNPipeline/sdn_pipeline.py \\
        --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \\
        --limit 500

    # Demo mode (no hardware, synthetic flows):
    python FullSDNPipeline/sdn_pipeline.py --demo --n-flows 20
"""

import os
import sys
import time
import json
import pickle
import signal
import logging
import argparse
import threading
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional, Dict, Any, List

import numpy as np

# ── Setup path ────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_ROOT     = os.path.dirname(SCRIPT_DIR)
PROJECT_ROOT = os.path.dirname(SRC_ROOT)
sys.path.insert(0, SRC_ROOT)
sys.path.insert(0, SCRIPT_DIR)

from unified_feature_extractor import (
    extract_all_features, BCC_V2_FEATURE_NAMES, DDL_FEATURE_NAMES
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("SDNPipeline")


# ══════════════════════════════════════════════════════════════════════════════
#  BCC Stage (Stage 1) — Sandaru's Decision Tree v2 Gatekeeper
# ══════════════════════════════════════════════════════════════════════════════
class BCCStage:
    """Base Check Classifier v2 — 28-feature Decision Tree."""

    def __init__(self, model_path: str):
        logger.info(f"Loading BCC v2 model from {model_path}")
        with open(model_path, 'rb') as f:
            data = pickle.load(f)
        self.model = data['model']
        self.threshold = data['threshold']
        logger.info(f"BCC loaded: threshold={self.threshold:.4f}")

    def predict(self, features_28: list) -> Dict[str, Any]:
        """
        Classify using BCC v2.
        Returns: {'prediction': 'BENIGN'|'ATTACK', 'proba': float, 'latency_us': int}
        """
        t0 = time.perf_counter()
        X = [features_28]
        proba = self.model.predict_proba(X)[0, 1]  # P(ATTACK)
        prediction = "ATTACK" if proba >= self.threshold else "BENIGN"
        latency_us = int((time.perf_counter() - t0) * 1_000_000)
        return {
            "prediction": prediction,
            "proba": round(float(proba), 4),
            "latency_us": latency_us
        }


# ══════════════════════════════════════════════════════════════════════════════
#  DDL Stage (Stage 2) — Deep Dictionary Learning + XAI
# ══════════════════════════════════════════════════════════════════════════════
class DDLStage:
    """DDL anomaly detection + optional XAI explanation."""

    def __init__(self, ddl_model_path: str, if_model_path: Optional[str] = None):
        from DDLModel.ddl_model import DeepDictionaryLearning

        logger.info(f"Loading DDL model from {ddl_model_path}")
        self.ddl = DeepDictionaryLearning.load(ddl_model_path)
        logger.info(f"DDL loaded: {self.ddl.n_features} features, "
                     f"threshold={getattr(self.ddl, 'threshold_', 'N/A')}")

        self.if_model = None
        if if_model_path and os.path.exists(if_model_path):
            import joblib
            self.if_model = joblib.load(if_model_path)
            logger.info(f"Isolation Forest loaded from {if_model_path}")

        self.explainer = None
        try:
            from XAIExplainer.explainer import DDLExplainer
            self.explainer = DDLExplainer(
                self.ddl,
                feature_names=DDL_FEATURE_NAMES,
            )
            logger.info("XAI explainer initialized")
        except Exception as e:
            logger.warning(f"XAI explainer not available: {e}")

    def predict(self, features_30: np.ndarray) -> Dict[str, Any]:
        """
        Classify using DDL + optional Isolation Forest consensus.
        Returns: {'prediction': 'Normal'|'Anomaly', 'ddl_score': float,
                  'if_score': float, 'xai_summary': str, 'latency_us': int}
        """
        t0 = time.perf_counter()

        # DDL prediction
        result = self.ddl.predict(features_30)
        ddl_label = result["labels"]
        ddl_score = float(result["scores"])
        threshold = float(result["threshold"])

        # Isolation Forest second vote (if available)
        if_score = None
        if self.if_model is not None:
            if_pred = self.if_model.predict(features_30.reshape(1, -1))[0]
            if_score = float(self.if_model.decision_function(features_30.reshape(1, -1))[0])
            # Consensus: only DROP if both agree it's anomaly
            if ddl_label == "Anomaly" and if_pred == -1:
                final = "Anomaly"
            elif ddl_label == "Anomaly" and if_pred == 1:
                final = "Normal"  # DDL says anomaly but IF says normal → let through
                logger.debug("DDL=Anomaly but IF=Normal → overriding to FORWARD")
            else:
                final = ddl_label
        else:
            final = ddl_label

        # XAI explanation (only for anomalies)
        xai_summary = ""
        if final == "Anomaly" and self.explainer:
            try:
                xai = self.explainer.explain_native(features_30)
                xai_summary = xai.get("interpretation", "")
            except Exception as e:
                xai_summary = f"XAI error: {e}"

        latency_us = int((time.perf_counter() - t0) * 1_000_000)
        return {
            "prediction": final,
            "ddl_score": round(ddl_score, 4),
            "ddl_threshold": round(threshold, 4),
            "if_score": round(if_score, 4) if if_score is not None else None,
            "xai_summary": xai_summary,
            "latency_us": latency_us
        }


# ══════════════════════════════════════════════════════════════════════════════
#  SDN Buffer — Holds flagged flows during Stage 2 analysis
# ══════════════════════════════════════════════════════════════════════════════
class SDNBuffer:
    """Thread-safe buffer for flows flagged by Stage 1."""

    def __init__(self, timeout_ms: int = 5000):
        self.buffer = {}
        self.lock = threading.Lock()
        self.timeout_ms = timeout_ms

    def add(self, flow_id: str, features: dict, timestamp: float):
        with self.lock:
            self.buffer[flow_id] = {
                "features": features,
                "timestamp": timestamp,
                "status": "HELD"
            }

    def release(self, flow_id: str, action: str):
        with self.lock:
            if flow_id in self.buffer:
                self.buffer[flow_id]["status"] = action
                del self.buffer[flow_id]

    def get_held_count(self) -> int:
        with self.lock:
            return len(self.buffer)


# ══════════════════════════════════════════════════════════════════════════════
#  Switch Table — Simulates OpenFlow switch table entries
# ══════════════════════════════════════════════════════════════════════════════
class SwitchTable:
    """Simulates the switch flow table (OpenFlow rules)."""

    def __init__(self):
        self.rules = []

    def add_rule(self, flow_id: str, action: str, reason: str, timeout_s: int = 60):
        rule = {
            "flow_id": flow_id,
            "action": action,     # "ALLOW" or "DROP"
            "reason": reason,
            "timeout_s": timeout_s,
            "installed_at": datetime.now(timezone.utc).isoformat()
        }
        self.rules.append(rule)
        return rule

    def get_rules(self) -> list:
        return self.rules[-50:]  # Keep last 50


# ══════════════════════════════════════════════════════════════════════════════
#  Main Pipeline — Ties everything together
# ══════════════════════════════════════════════════════════════════════════════
class FullSDNPipeline:
    """
    Full SDN Zero-Trust Pipeline.

    Processes:
        PacketIN (PCAP) → Feature Extraction → BCC Stage 1 → Buffer → DDL Stage 2
    """

    def __init__(self,
                 bcc_model_path: str = None,
                 ddl_model_path: str = None,
                 if_model_path: str = None):

        # Resolve defaults
        models_dir = os.path.join(PROJECT_ROOT, "models")
        bcc_model_path = bcc_model_path or os.path.join(models_dir, "sentry_model_v2.pkl")
        ddl_model_path = ddl_model_path or os.path.join(models_dir, "ddl_40feat.pkl")
        if_model_path = if_model_path or os.path.join(models_dir, "isolation_forest.pkl")

        # Load Stage 1 — BCC
        self.bcc = None
        if os.path.exists(bcc_model_path):
            self.bcc = BCCStage(bcc_model_path)
        else:
            logger.warning(f"BCC model not found at {bcc_model_path} — "
                          f"Stage 1 disabled (all flows go to DDL)")

        # Load Stage 2 — DDL (+IF, +XAI)
        self.ddl_stage = None
        if os.path.exists(ddl_model_path):
            self.ddl_stage = DDLStage(ddl_model_path, if_model_path)
        else:
            logger.warning(f"DDL model not found at {ddl_model_path} — "
                          f"Stage 2 disabled (passive logging only)")

        self.buffer = SDNBuffer()
        self.switch = SwitchTable()

        # Stats
        self.stats = {
            "total_flows": 0,
            "bcc_benign": 0,
            "bcc_attack": 0,
            "ddl_normal": 0,
            "ddl_anomaly": 0,
            "extraction_errors": 0,
            "stage1_skipped": 0,
        }
        self.decisions = []

    def process_flow(self, pcap_path: str, ground_truth: str = "UNKNOWN") -> Dict[str, Any]:
        """
        Process a single flow PCAP through the full pipeline.

        Args:
            pcap_path: Path to per-flow PCAP file.
            ground_truth: "BENIGN" or "ATTACK" (for accuracy scoring).

        Returns:
            Decision dict with action, scores, timing, and switch rule.
        """
        self.stats["total_flows"] += 1
        ts = time.time()

        # ── Feature Extraction (shared, once) ─────────────────────────────
        t0 = time.perf_counter()
        ext = extract_all_features(pcap_path)
        extract_time_us = int((time.perf_counter() - t0) * 1_000_000)

        if not ext["valid"]:
            self.stats["extraction_errors"] += 1
            return {
                "flow_id": "unknown",
                "action": "FORWARD",
                "stage": "ERROR",
                "error": ext.get("error", "unknown"),
                "ground_truth": ground_truth,
            }

        flow_id = ext["flow_id"]
        bcc_28 = ext["bcc_28"]
        ddl_40 = ext["ddl_40"]

        decision = {
            "flow_id": flow_id,
            "pcap": os.path.basename(pcap_path),
            "ground_truth": ground_truth,
            "extract_time_us": extract_time_us,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # ── Stage 1: BCC v2 Decision Tree ─────────────────────────────────
        if self.bcc:
            bcc_result = self.bcc.predict(bcc_28)
            decision["bcc_prediction"] = bcc_result["prediction"]
            decision["bcc_proba"] = bcc_result["proba"]
            decision["bcc_latency_us"] = bcc_result["latency_us"]

            if bcc_result["prediction"] == "BENIGN":
                # ✅ DT says OK → FORWARD + ALLOW switch rule
                self.stats["bcc_benign"] += 1
                decision["action"] = "FORWARD"
                decision["stage"] = "BCC"
                rule = self.switch.add_rule(flow_id, "ALLOW",
                                           "BCC-BENIGN", timeout_s=300)
                decision["switch_rule"] = rule
                self.decisions.append(decision)
                return decision

            else:
                # ❌ DT says ATTACK → hold in buffer, proceed to DDL
                self.stats["bcc_attack"] += 1
                self.buffer.add(flow_id, ext["all_features"], ts)
        else:
            self.stats["stage1_skipped"] += 1

        # ── Stage 2: DDL + XAI ────────────────────────────────────────────
        if self.ddl_stage:
            ddl_result = self.ddl_stage.predict(ddl_40)
            decision["ddl_prediction"] = ddl_result["prediction"]
            decision["ddl_score"] = ddl_result["ddl_score"]
            decision["ddl_threshold"] = ddl_result["ddl_threshold"]
            decision["if_score"] = ddl_result["if_score"]
            decision["ddl_latency_us"] = ddl_result["latency_us"]

            if ddl_result["prediction"] == "Normal":
                # ✅ DDL says Normal → release buffer, FORWARD, ALLOW rule
                self.stats["ddl_normal"] += 1
                decision["action"] = "FORWARD"
                decision["stage"] = "DDL"
                rule = self.switch.add_rule(flow_id, "ALLOW",
                                           "DDL-NORMAL", timeout_s=300)
                decision["switch_rule"] = rule
                self.buffer.release(flow_id, "FORWARDED")
            else:
                # ❌ DDL says Anomaly → DROP + XAI explanation
                self.stats["ddl_anomaly"] += 1
                decision["action"] = "DROP"
                decision["stage"] = "DDL"
                decision["xai_summary"] = ddl_result["xai_summary"]
                rule = self.switch.add_rule(flow_id, "DROP",
                                           "DDL-ANOMALY", timeout_s=60)
                decision["switch_rule"] = rule
                self.buffer.release(flow_id, "DROPPED")
        else:
            # No DDL model → passive FORWARD with warning
            decision["action"] = "FORWARD"
            decision["stage"] = "PASSIVE"
            self.buffer.release(flow_id, "FORWARDED")

        self.decisions.append(decision)
        return decision

    def print_status(self):
        """Print current pipeline statistics."""
        s = self.stats
        total = s["total_flows"]
        if total == 0:
            print("No flows processed yet.")
            return

        print(f"\n{'='*60}")
        print(f"  SDN Pipeline Status  ({datetime.now().strftime('%H:%M:%S')})")
        print(f"{'='*60}")
        print(f"  Total flows processed:   {total}")
        print(f"  Extraction errors:       {s['extraction_errors']}")
        print(f"  ── Stage 1 (BCC) ──")
        print(f"    BENIGN → FORWARD:      {s['bcc_benign']} "
              f"({s['bcc_benign']/total*100:.1f}%)")
        print(f"    ATTACK → to DDL:       {s['bcc_attack']} "
              f"({s['bcc_attack']/total*100:.1f}%)")
        if s['stage1_skipped']:
            print(f"    Stage 1 skipped:       {s['stage1_skipped']}")
        print(f"  ── Stage 2 (DDL+XAI) ──")
        print(f"    Normal  → FORWARD:     {s['ddl_normal']}")
        print(f"    Anomaly → DROP:        {s['ddl_anomaly']}")
        print(f"  Buffer held:             {self.buffer.get_held_count()}")
        print(f"  Switch rules installed:  {len(self.switch.rules)}")
        print(f"{'='*60}\n")

    def print_confusion_matrix(self):
        """Print accuracy stats if ground truth is available."""
        tp = fp = tn = fn = unknown = 0
        for d in self.decisions:
            gt = d.get("ground_truth", "UNKNOWN").upper()
            action = d.get("action", "FORWARD")
            if gt == "UNKNOWN":
                unknown += 1
                continue
            is_attack = gt not in ("BENIGN", "NORMAL")
            is_dropped = action == "DROP"
            if is_attack and is_dropped:       tp += 1
            elif is_attack and not is_dropped: fn += 1
            elif not is_attack and is_dropped: fp += 1
            else:                              tn += 1

        tested = tp + fp + tn + fn
        if tested == 0:
            print("No ground-truth labels available for accuracy scoring.")
            return

        accuracy = (tp + tn) / tested if tested else 0
        precision = tp / (tp + fp) if (tp + fp) else 0
        recall = tp / (tp + fn) if (tp + fn) else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

        print(f"\n{'='*60}")
        print(f"  Confusion Matrix (Ground Truth)")
        print(f"{'='*60}")
        print(f"                     Predicted")
        print(f"                  FORWARD   DROP")
        print(f"  Actual BENIGN    {tn:>5d}    {fp:>5d}")
        print(f"  Actual ATTACK    {fn:>5d}    {tp:>5d}")
        print(f"")
        print(f"  Accuracy:   {accuracy:.4f}")
        print(f"  Precision:  {precision:.4f}")
        print(f"  Recall:     {recall:.4f}")
        print(f"  F1 Score:   {f1:.4f}")
        if fn > 0:
            print(f"  ⚠️  {fn} ATTACK flows leaked through (FN)!")
        else:
            print(f"  ✅ ZERO LEAKS — all attacks caught!")
        if fp > 0:
            print(f"  ⚠️  {fp} BENIGN flows incorrectly blocked (FP)")
        else:
            print(f"  ✅ ZERO FALSE POSITIVES!")
        print(f"  (Unknown/unlabeled: {unknown})")
        print(f"{'='*60}\n")

    def save_results(self, output_path: str):
        """Save full pipeline results to JSON."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out = {
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
            "stats": self.stats,
            "switch_rules": self.switch.get_rules(),
            "decisions": self.decisions,
        }
        with open(output_path, "w") as f:
            json.dump(out, f, indent=2, default=str)
        logger.info(f"Results saved to {output_path}")


# ══════════════════════════════════════════════════════════════════════════════
#  Demo Mode — Works with no hardware or models
# ══════════════════════════════════════════════════════════════════════════════
def run_demo(pipeline: FullSDNPipeline, n_flows: int = 20):
    """Generate and process synthetic flows for testing."""
    print("\n🚀 Running in DEMO mode (synthetic flows)")
    print(f"   Processing {n_flows} synthetic flows...\n")

    for i in range(n_flows):
        is_attack = (i % 5 == 0)  # 20% attack rate
        label = "ATTACK" if is_attack else "BENIGN"

        # Create a minimal synthetic PCAP or use dummy features
        decision = {
            "flow_id": f"10.0.0.{i%255}:{50000+i}->8.8.8.8:443/TCP",
            "pcap": f"synthetic_{i}.pcap",
            "ground_truth": label,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Simulate BCC decision
        if pipeline.bcc:
            # Generate synthetic features
            feats = [0.0] * 28
            feats[0] = 50000.0 if is_attack else 400.0  # pkt_len_var
            feats[3] = 65535 if is_attack else 29200     # init_win_fwd
            bcc_r = pipeline.bcc.predict(feats)
            decision["bcc_prediction"] = bcc_r["prediction"]
            decision["bcc_proba"] = bcc_r["proba"]
        else:
            decision["bcc_prediction"] = "ATTACK" if is_attack else "BENIGN"
            decision["bcc_proba"] = 0.9 if is_attack else 0.1

        pipeline.stats["total_flows"] += 1

        if decision["bcc_prediction"] == "BENIGN":
            pipeline.stats["bcc_benign"] += 1
            decision["action"] = "FORWARD"
            decision["stage"] = "BCC"
            pipeline.switch.add_rule(decision["flow_id"], "ALLOW", "BCC-BENIGN")
        else:
            pipeline.stats["bcc_attack"] += 1
            # Simulate DDL
            decision["ddl_score"] = 0.85 if is_attack else 0.12
            decision["ddl_threshold"] = 0.50

            if is_attack:
                pipeline.stats["ddl_anomaly"] += 1
                decision["action"] = "DROP"
                decision["stage"] = "DDL"
                decision["xai_summary"] = "syn_flag_count:+42%, pkt_len_variance:+38%"
                pipeline.switch.add_rule(decision["flow_id"], "DROP", "DDL-ANOMALY")
            else:
                pipeline.stats["ddl_normal"] += 1
                decision["action"] = "FORWARD"
                decision["stage"] = "DDL"
                pipeline.switch.add_rule(decision["flow_id"], "ALLOW", "DDL-NORMAL")

        pipeline.decisions.append(decision)

        # Log
        symbol = "✅" if decision["action"] == "FORWARD" else "❌"
        print(f"  {symbol} Flow {i+1:>3d}: {decision['flow_id'][:40]:40s} "
              f"→ {decision['action']:7s}  (Stage: {decision['stage']}, "
              f"GT: {label})")

    pipeline.print_status()
    pipeline.print_confusion_matrix()


# ══════════════════════════════════════════════════════════════════════════════
#  Process Directory of PCAPs
# ══════════════════════════════════════════════════════════════════════════════
def process_pcap_directory(pipeline: FullSDNPipeline, pcap_dir: str,
                           limit: int = 0):
    """
    Process a directory of labeled PCAPs (CIC-IDS-2017 Labeled format).

    Expected structure:
        Friday/
          Row_123_BENIGN/packets.pcap
          Row_456_DDoS/packets.pcap
          Row_789_PortScan/packets.pcap
    """
    tasks = []
    for root, dirs, files in os.walk(pcap_dir):
        if "packets.pcap" in files:
            folder_name = os.path.basename(root)
            # Parse ground truth from folder name
            if "_" in folder_name:
                label = folder_name.split("_")[-1]
            else:
                label = "UNKNOWN"
            gt_binary = "BENIGN" if label == "BENIGN" else "ATTACK"
            tasks.append((os.path.join(root, "packets.pcap"), gt_binary))
            if limit > 0 and len(tasks) >= limit:
                break

    if not tasks:
        logger.error(f"No packets.pcap files found in {pcap_dir}")
        return

    print(f"\n📂 Processing {len(tasks)} flows from {pcap_dir}")
    benign_count = sum(1 for _, gt in tasks if gt == "BENIGN")
    attack_count = len(tasks) - benign_count
    print(f"   BENIGN: {benign_count}  |  ATTACK: {attack_count}\n")

    for i, (pcap_path, gt) in enumerate(tasks):
        decision = pipeline.process_flow(pcap_path, ground_truth=gt)

        symbol = "✅" if decision["action"] == "FORWARD" else "❌"
        logger.info(
            f"[{i+1}/{len(tasks)}] {symbol} {decision.get('flow_id', '?')[:40]:40s} "
            f"→ {decision['action']:7s} (Stage: {decision.get('stage', '?')}, "
            f"GT: {gt})"
        )

        # Print status every 100 flows
        if (i + 1) % 100 == 0:
            pipeline.print_status()

    pipeline.print_status()
    pipeline.print_confusion_matrix()


# ══════════════════════════════════════════════════════════════════════════════
#  Main Entry Point
# ══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="Full SDN Zero-Trust Pipeline — Single Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Demo mode (no hardware needed):
  python sdn_pipeline.py --demo --n-flows 20

  # Process labeled PCAPs:
  python sdn_pipeline.py --pcap-dir .../PCAP/Labeled/Friday --limit 500

  # Single PCAP:
  python sdn_pipeline.py --pcap flow.pcap

  # Custom model paths:
  python sdn_pipeline.py --pcap-dir ... \\
      --bcc-model models/sentry_model_v2.pkl \\
      --ddl-model models/ddl_40feat.pkl \\
      --if-model  models/isolation_forest.pkl
        """
    )

    parser.add_argument("--demo", action="store_true",
                        help="Run in demo mode with synthetic flows")
    parser.add_argument("--n-flows", type=int, default=20,
                        help="Number of demo flows (default: 20)")
    parser.add_argument("--pcap", type=str,
                        help="Single PCAP file to process")
    parser.add_argument("--pcap-dir", type=str,
                        help="Directory of labeled PCAPs (CIC-IDS-2017 format)")
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit number of flows to process (0 = all)")
    parser.add_argument("--bcc-model", type=str, default=None,
                        help="Path to BCC v2 model (sentry_model_v2.pkl)")
    parser.add_argument("--ddl-model", type=str, default=None,
                        help="Path to trained DDL model (ddl_40feat.pkl)")
    parser.add_argument("--if-model", type=str, default=None,
                        help="Path to Isolation Forest model")
    parser.add_argument("--output", type=str,
                        default="logs/sdn_pipeline_results.json",
                        help="Output JSON file for results")

    args = parser.parse_args()

    # Initialize pipeline
    pipeline = FullSDNPipeline(
        bcc_model_path=args.bcc_model,
        ddl_model_path=args.ddl_model,
        if_model_path=args.if_model,
    )

    # Handle signals for clean shutdown
    def signal_handler(sig, frame):
        print("\n\n⏹ Shutting down pipeline...")
        pipeline.print_status()
        pipeline.print_confusion_matrix()
        pipeline.save_results(args.output)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Run the appropriate mode
    if args.demo:
        run_demo(pipeline, n_flows=args.n_flows)
    elif args.pcap:
        decision = pipeline.process_flow(args.pcap)
        print(json.dumps(decision, indent=2, default=str))
    elif args.pcap_dir:
        process_pcap_directory(pipeline, args.pcap_dir, limit=args.limit)
    else:
        parser.print_help()
        return

    # Save results
    pipeline.save_results(args.output)
    print(f"\n📁 Results saved to: {args.output}")


if __name__ == "__main__":
    main()
