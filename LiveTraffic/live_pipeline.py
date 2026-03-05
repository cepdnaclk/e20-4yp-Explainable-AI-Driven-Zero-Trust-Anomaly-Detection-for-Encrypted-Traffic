"""
LiveTraffic/live_pipeline.py — Live Traffic Processing Pipeline
===============================================================
Zero-Trust Anomaly Detection | University of Peradeniya

Captures live network traffic from a physical switch SPAN/mirror port using
NFStream, extracts 30 DDL features per terminated flow, classifies using the
DDL model + XAI, and logs all decisions.

PREREQUISITES
-------------
  1. Switch mirror port configured (see LiveTraffic/SWITCH_SETUP_GUIDE.md)
  2. Network interface in promiscuous mode:
       sudo ip link set eth1 promisc on
  3. Models trained (or use demo mode):
       python DDLModel/train_ddl_enhanced.py --output models/ddl_30feat.pkl

USAGE
-----
  # Live capture for 5 minutes:
  python LiveTraffic/live_pipeline.py --interface eth1 --duration 300

  # Demo mode (synthetic flows, no real interface needed):
  python LiveTraffic/live_pipeline.py --demo --duration 30
"""

import os
import sys
import time
import json
import signal
import logging
import argparse
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any

import numpy as np

_THIS_DIR    = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_THIS_DIR)
sys.path.insert(0, PROJECT_ROOT)

from DDLModel.ddl_model import DeepDictionaryLearning
from DDLModel.ddl_feature_extractor import DDLFeatureExtractor, DDL_FEATURE_NAMES
from XAIExplainer.explainer import DDLExplainer
from profiling.timing_profiler import StageTimer

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("LivePipeline")

# How often (seconds) to print a running summary to console
SUMMARY_INTERVAL = 30


class LivePipeline:
    """
    Processes live flows from an NFStream capture.

    For each terminated flow:
      1. Extract 30 DDL features using DDLFeatureExtractor.from_nfstream()
      2. Run DDL.predict()
      3. If anomaly → run XAI explanation → log as DROP
      4. If normal   → log as FORWARD

    If no DDL model is provided, logs every flow as FORWARD (passive mode).
    """

    def __init__(self, ddl_model: Optional[DeepDictionaryLearning] = None,
                 enable_shap: bool = True,
                 background_data: Optional[np.ndarray] = None,
                 openflow_host: Optional[str] = None,
                 openflow_port: int = 6633):
        """
        Args:
            ddl_model:       Fitted DDL model (None = passive logging mode).
            enable_shap:     Whether to run SHAP for anomalies.
            background_data: Normal flow feature vectors (n, 30) for SHAP background.
            openflow_host:   Ryu controller host for OpenFlow DROP commands (optional).
            openflow_port:   Ryu controller port.
        """
        self.ddl        = ddl_model
        self.enable_shap = enable_shap
        self.extractor  = DDLFeatureExtractor()
        self.timer      = StageTimer()
        self.of_host    = openflow_host
        self.of_port    = openflow_port
        self._of_sock   = None

        self.explainer = None
        if ddl_model and ddl_model.is_fitted_:
            self.explainer = DDLExplainer(
                ddl_model,
                background_data=background_data,
                feature_names=DDL_FEATURE_NAMES,
            )

        # Stats
        self.stats = {
            "flows_seen":      0,
            "ddl_normal":      0,
            "ddl_anomaly":     0,
            "no_model":        0,
            "errors":          0,
        }
        self.log: list = []
        self._running = True

        # Connect to OpenFlow controller if provided
        if openflow_host:
            self._connect_openflow()

    def _connect_openflow(self):
        """Open TCP socket to the Ryu OpenFlow controller bridge."""
        import socket
        try:
            self._of_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._of_sock.connect((self.of_host, self.of_port))
            logger.info(f"Connected to OpenFlow controller at "
                         f"{self.of_host}:{self.of_port}")
        except Exception as e:
            logger.warning(f"Could not connect to OpenFlow controller: {e}")
            self._of_sock = None

    def _send_openflow_drop(self, flow_id: str, flow_info: dict):
        """Send a DROP command to the Ryu controller for the given 5-tuple."""
        if not self._of_sock:
            return
        try:
            cmd = json.dumps({
                "action": "DROP",
                "flow_id": flow_id,
                "src_ip": flow_info.get("src_ip"),
                "dst_ip": flow_info.get("dst_ip"),
                "src_port": flow_info.get("src_port"),
                "dst_port": flow_info.get("dst_port"),
                "protocol": flow_info.get("protocol"),
                "timeout_s": 60,
            }).encode() + b"\n"
            self._of_sock.sendall(cmd)
        except Exception as e:
            logger.warning(f"OpenFlow DROP send failed: {e}")

    def process_flow(self, flow) -> Dict[str, Any]:
        """
        Process a single NFStream flow object through the DDL pipeline.

        Args:
            flow: nfstream.NFFlow instance with all statistics populated.

        Returns:
            Decision dict with keys:
              flow_id, action (FORWARD/DROP), ddl_score, xai_summary, timing_ms
        """
        self.stats["flows_seen"] += 1
        ts = datetime.now(timezone.utc).isoformat()

        flow_id = (f"{getattr(flow, 'src_ip', 'x')}"
                   f":{getattr(flow, 'src_port', 0)}->"
                   f"{getattr(flow, 'dst_ip', 'x')}"
                   f":{getattr(flow, 'dst_port', 0)}"
                   f"/{getattr(flow, 'protocol', '?')}")

        flow_meta = {
            "src_ip":   str(getattr(flow, "src_ip", "")),
            "dst_ip":   str(getattr(flow, "dst_ip", "")),
            "src_port": int(getattr(flow, "src_port", 0)),
            "dst_port": int(getattr(flow, "dst_port", 0)),
            "protocol": str(getattr(flow, "protocol", "")),
            "duration_ms": float(getattr(flow, "bidirectional_duration_ms", 0)),
            "total_bytes": int(getattr(flow, "bidirectional_bytes", 0)),
        }

        entry = {
            "timestamp": ts,
            "flow_id":   flow_id,
            "flow_meta": flow_meta,
            "action":    "FORWARD",
            "ddl_score": None,
            "threshold": None,
            "xai_summary": None,
            "timing": {},
        }

        if self.ddl is None or not self.ddl.is_fitted_:
            self.stats["no_model"] += 1
            self.log.append(entry)
            return entry

        try:
            # ── Stage: 30-feature extraction ──────────────────────────────
            with self.timer.measure("feat_extract_30"):
                ddl_feats = self.extractor.from_nfstream(flow)

            # ── Stage: DDL forward pass ───────────────────────────────────
            with self.timer.measure("ddl_forward"):
                result = self.ddl.predict(ddl_feats)

            ddl_label = result["labels"]
            ddl_score = float(result["scores"])
            threshold = float(result["threshold"])

            entry["ddl_score"] = round(ddl_score, 4)
            entry["threshold"] = round(threshold, 4)
            entry["timing"]["ddl_ms"] = result.get("predict_ms", 0)

            if ddl_label == "Normal":
                self.stats["ddl_normal"] += 1
                entry["action"] = "FORWARD"
                logger.debug(f"FORWARD  {flow_id}  score={ddl_score:.3f}")

            else:
                self.stats["ddl_anomaly"] += 1
                entry["action"] = "DROP"

                # ── Stage: XAI native explanation ─────────────────────────
                if self.explainer:
                    with self.timer.measure("xai_native"):
                        xai = self.explainer.explain_native(ddl_feats)
                    entry["xai_summary"] = xai.get("interpretation", "")
                    entry["timing"]["xai_native_ms"] = round(
                        self.timer.stats("xai_native").get("mean_ms", 0), 2)

                    if self.enable_shap and self.explainer.shap_explainer:
                        with self.timer.measure("xai_shap"):
                            shap_exp = self.explainer.explain_shap(ddl_feats)
                        if shap_exp:
                            entry["shap_top3"] = [
                                a["feature"] for a in shap_exp["attributions"][:3]
                            ]

                # ── Send DROP to OpenFlow controller ──────────────────────
                self._send_openflow_drop(flow_id, flow_meta)

                logger.info(
                    f"DROP     {flow_id}  score={ddl_score:.3f}  "
                    f"threshold={threshold:.3f}  "
                    f"ratio={ddl_score/threshold:.2f}x"
                )
                if entry["xai_summary"]:
                    logger.info(f"  XAI: {entry['xai_summary'][:120]}...")

        except Exception as e:
            self.stats["errors"] += 1
            entry["error"] = str(e)
            logger.error(f"Error processing flow {flow_id}: {e}")

        self.log.append(entry)
        return entry

    def print_status(self):
        """Print a running summary of pipeline decisions."""
        s      = self.stats
        total  = s["flows_seen"]
        anom   = s["ddl_anomaly"]
        normal = s["ddl_normal"]
        pct    = lambda x: (x / total * 100) if total > 0 else 0.0

        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Pipeline Status:")
        print(f"  Flows seen:       {total}")
        print(f"  DDL normal:       {normal} ({pct(normal):.1f}%) → FORWARD")
        print(f"  DDL anomaly:      {anom}   ({pct(anom):.1f}%) → DROP")
        print(f"  Errors:           {s['errors']}")
        if self.timer._records.get("ddl_forward"):
            print(f"  Avg DDL latency:  {self.timer.stats('ddl_forward')['mean_ms']:.2f}ms")

    def save_log(self, path: str):
        """Save the decision log to a JSON file."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        out = {
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
            "stats":         self.stats,
            "timing_profile": self.timer.to_dict(),
            "decisions":     self.log,
        }
        with open(path, "w") as f:
            json.dump(out, f, indent=2, default=str)
        logger.info(f"Decision log saved to {path}")


def run_live(interface: str, duration: int, pipeline: LivePipeline,
             idle_timeout: int = 15, active_timeout: int = 120,
             log_path: str = "logs/live_pipeline.json"):
    """
    Start NFStream capture on `interface` and feed flows to `pipeline`.

    Args:
        interface:      Network interface name (e.g. "eth1").
        duration:       Capture duration in seconds (0 = unlimited).
        pipeline:       LivePipeline instance.
        idle_timeout:   NFStream idle flow timeout (seconds).
        active_timeout: NFStream active flow timeout (seconds).
        log_path:       Output decision log path.
    """
    try:
        from nfstream import NFStreamer
    except ImportError:
        logger.error("nfstream not installed. Run: pip install nfstream")
        sys.exit(1)

    logger.info(f"Starting live capture on {interface} "
                 f"(idle_timeout={idle_timeout}s, duration={duration or 'unlimited'}s)")

    start_time = time.time()
    last_status = start_time

    # Setup graceful shutdown on Ctrl+C
    def _signal_handler(sig, frame):
        logger.info("Shutdown signal received — finalising...")
        pipeline._running = False

    signal.signal(signal.SIGINT,  _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    streamer = NFStreamer(
        source=interface,
        idle_timeout=idle_timeout,
        active_timeout=active_timeout,
        statistical_analysis=True,
        splt_analysis=10,
        udps=None,
    )

    for flow in streamer:
        if not pipeline._running:
            break
        if duration > 0 and (time.time() - start_time) > duration:
            break

        pipeline.process_flow(flow)

        # Periodic status print
        if time.time() - last_status >= SUMMARY_INTERVAL:
            pipeline.print_status()
            last_status = time.time()

    pipeline.print_status()
    print(pipeline.timer.summary())
    pipeline.save_log(log_path)
    logger.info("Live capture finished.")


def run_demo(duration: int, pipeline: LivePipeline,
             log_path: str = "logs/demo_pipeline.json"):
    """
    Synthetic demo mode: generates fake NFStream-like flow objects.

    Useful for testing without a switch / interface.
    """
    import types

    class _FakeFlow:
        """Minimal fake NFStream flow for demo."""
        def __init__(self, is_attack=False, seed=0):
            rng = np.random.default_rng(seed)
            self.src_ip   = f"10.0.{rng.integers(0,10)}.{rng.integers(1,254)}"
            self.dst_ip   = f"172.16.{rng.integers(0,5)}.{rng.integers(1,100)}"
            self.src_port = int(rng.integers(1024, 60000))
            self.dst_port = int(rng.choice([80, 443, 8080, 22, 53]))
            self.protocol = "TCP"

            if is_attack:
                # SYN-flood signature
                self.src2dst_mean_ps            = float(rng.uniform(40, 60))
                self.src2dst_stddev_ps          = float(rng.uniform(0, 2))
                self.src2dst_min_ps             = 40.0
                self.src2dst_max_ps             = 64.0
                self.dst2src_mean_ps            = 0.0
                self.dst2src_stddev_ps          = 0.0
                self.src2dst_mean_piat_ms       = float(rng.uniform(0.01, 0.5))
                self.src2dst_stddev_piat_ms     = float(rng.uniform(2000, 5000))
                self.src2dst_max_piat_ms        = float(rng.uniform(4000, 8000))
                self.dst2src_mean_piat_ms       = 0.0
                self.dst2src_stddev_piat_ms     = 0.0
                self.dst2src_max_piat_ms        = 0.0
                self.bidirectional_duration_ms  = float(rng.uniform(500, 2000))
                self.bidirectional_bytes        = int(rng.integers(2000, 8000))
                self.src2dst_bytes              = self.bidirectional_bytes
                self.dst2src_bytes              = 0
                self.bidirectional_packets      = int(rng.integers(50, 500))
                self.bidirectional_syn_packets  = int(rng.integers(40, 200))
                self.bidirectional_ack_packets  = 0
                self.bidirectional_fin_packets  = 0
                self.bidirectional_rst_packets  = int(rng.integers(0, 5))
                self.src2dst_psh_packets        = 0
                self.bidirectional_urg_packets  = 0
                self.src2dst_initial_mean_ps    = 64.0
                self.dst2src_initial_mean_ps    = 0.0
            else:
                # Normal HTTPS flow
                self.src2dst_mean_ps            = float(rng.uniform(200, 1200))
                self.src2dst_stddev_ps          = float(rng.uniform(100, 400))
                self.src2dst_min_ps             = float(rng.uniform(40, 100))
                self.src2dst_max_ps             = 1460.0
                self.dst2src_mean_ps            = float(rng.uniform(300, 1400))
                self.dst2src_stddev_ps          = float(rng.uniform(150, 500))
                self.src2dst_mean_piat_ms       = float(rng.uniform(2, 20))
                self.src2dst_stddev_piat_ms     = float(rng.uniform(5, 40))
                self.src2dst_max_piat_ms        = float(rng.uniform(20, 100))
                self.dst2src_mean_piat_ms       = float(rng.uniform(3, 25))
                self.dst2src_stddev_piat_ms     = float(rng.uniform(5, 50))
                self.dst2src_max_piat_ms        = float(rng.uniform(25, 120))
                self.bidirectional_duration_ms  = float(rng.uniform(500, 15000))
                self.bidirectional_bytes        = int(rng.integers(5000, 500000))
                self.src2dst_bytes              = self.bidirectional_bytes // 3
                self.dst2src_bytes              = self.bidirectional_bytes * 2 // 3
                self.bidirectional_packets      = int(rng.integers(20, 200))
                self.bidirectional_syn_packets  = 1
                self.bidirectional_ack_packets  = int(rng.integers(15, 150))
                self.bidirectional_fin_packets  = 1
                self.bidirectional_rst_packets  = 0
                self.src2dst_psh_packets        = int(rng.integers(3, 30))
                self.bidirectional_urg_packets  = 0
                self.src2dst_initial_mean_ps    = 65535.0
                self.dst2src_initial_mean_ps    = 65535.0

    n_flows     = int(duration * 2)   # ~2 flows/second in demo
    attack_rate = 0.20               # 20% attack flows

    logger.info(f"Demo mode: {n_flows} synthetic flows ({attack_rate*100:.0f}% attacks)")

    rng = np.random.default_rng(2025)
    for i in range(n_flows):
        is_attack = rng.random() < attack_rate
        fake_flow = _FakeFlow(is_attack=is_attack, seed=i)
        pipeline.process_flow(fake_flow)
        time.sleep(0.5)   # Simulate 0.5s per flow for a visible demo

        if not pipeline._running:
            break

    pipeline.print_status()
    print(pipeline.timer.summary())
    pipeline.save_log(log_path)


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live Traffic Pipeline")
    parser.add_argument("--interface",      default="eth0",
                        help="Network interface for live capture (default: eth0)")
    parser.add_argument("--duration",       type=int, default=60,
                        help="Capture duration in seconds (0=unlimited, default: 60)")
    parser.add_argument("--ddl_model",      default=None,
                        help="Path to trained DDL model .pkl")
    parser.add_argument("--idle_timeout",   type=int, default=15,
                        help="NFStream idle timeout in seconds (default: 15)")
    parser.add_argument("--active_timeout", type=int, default=120,
                        help="NFStream active timeout in seconds (default: 120)")
    parser.add_argument("--log_path",       default="logs/live_pipeline.json",
                        help="Output decision log path")
    parser.add_argument("--no_shap",        action="store_true",
                        help="Disable SHAP explanations (faster, still gets DDL-native XAI)")
    parser.add_argument("--openflow_host",  default=None,
                        help="Ryu controller host for OpenFlow DROP commands")
    parser.add_argument("--openflow_port",  type=int, default=6633)
    parser.add_argument("--demo",           action="store_true",
                        help="Demo mode: synthetic flows instead of live capture")
    args = parser.parse_args()

    # Load DDL model
    ddl = None
    if args.ddl_model and os.path.exists(args.ddl_model):
        ddl = DeepDictionaryLearning.load(args.ddl_model)
        logger.info(f"DDL model loaded: {args.ddl_model}")
    else:
        logger.warning("No DDL model — running in passive logging mode (FORWARD all flows)")

    pl = LivePipeline(
        ddl_model      = ddl,
        enable_shap    = not args.no_shap,
        openflow_host  = args.openflow_host,
        openflow_port  = args.openflow_port,
    )

    if args.demo:
        run_demo(args.duration or 60, pl, log_path=args.log_path)
    else:
        run_live(
            interface      = args.interface,
            duration       = args.duration,
            pipeline       = pl,
            idle_timeout   = args.idle_timeout,
            active_timeout = args.active_timeout,
            log_path       = args.log_path,
        )
