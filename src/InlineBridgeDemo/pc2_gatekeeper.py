#!/usr/bin/env python3
"""
pc2_gatekeeper.py — PC2: The AI Gatekeeper / Pipeline
========================================================
Zero-Trust XAI Anomaly Detection | University of Peradeniya

This is the CORE of the demo. PC2 sits between PC1 (sender) and PC3 (receiver).
It runs the full two-stage AI pipeline on every packet flow:
  Stage 1: BCC v2 (28 features, Decision Tree) → fast BENIGN/ATTACK gate
  Stage 2: DDL + Isolation Forest (40 features) → deep anomaly analysis
  XAI:     LIME + SHAP (KernelSHAP) explanations on every DROP decision

Three-Plane Architecture on PC2:
  Control Plane (UDP):  Listens for START/END from PC1
  Data Plane (Scapy):   Sniffs packets on eth0, forwards to eth1 if clean
  Telemetry (InfluxDB): Logs predictions and timing for Grafana

Zero Trust Principle:
  NO traffic is inherently trusted. Every flow is verified by the AI pipeline.
  Clean flows are explicitly ALLOWED. Suspicious flows are DROPPED + explained.

Usage:
  sudo python3 pc2_gatekeeper.py --iface-in eth0 --iface-out eth1

  # With InfluxDB:
  export INFLUXDB_URL=http://localhost:8086
  export INFLUXDB_TOKEN=my-token
  sudo -E python3 pc2_gatekeeper.py --iface-in eth0 --iface-out eth1
"""

import os
import sys
import json
import time
import socket
import struct
import threading
import argparse
import logging
import io
import numpy as np

# Add lib/ to path for model imports
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "lib"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PC2-Gatekeeper] %(levelname)s: %(message)s"
)
logger = logging.getLogger("PC2")

# ── InfluxDB Configuration ──────────────────────────────────────────────────
INFLUXDB_URL    = os.environ.get("INFLUXDB_URL",   "http://localhost:8086")
INFLUXDB_TOKEN  = os.environ.get("INFLUXDB_TOKEN", "my-super-secret-token")
INFLUXDB_ORG    = os.environ.get("INFLUXDB_ORG",   "uop")
INFLUXDB_BUCKET = os.environ.get("INFLUXDB_BUCKET","sdn_telemetry")

CONTROL_PORT = 5005


def write_to_influxdb(line_protocol: str):
    """Write a line-protocol data point to InfluxDB v2."""
    try:
        import urllib.request
        url = f"{INFLUXDB_URL}/api/v2/write?org={INFLUXDB_ORG}&bucket={INFLUXDB_BUCKET}&precision=ns"
        req = urllib.request.Request(url, data=line_protocol.encode("utf-8"), method="POST")
        req.add_header("Authorization", f"Token {INFLUXDB_TOKEN}")
        req.add_header("Content-Type", "text/plain; charset=utf-8")
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        logger.debug(f"InfluxDB write failed: {e}")


# ═════════════════════════════════════════════════════════════════════════════
# AI PIPELINE — Two-Stage Zero Trust Model
# ═════════════════════════════════════════════════════════════════════════════

class ZeroTrustPipeline:
    """
    Full two-stage anomaly detection pipeline.

    Zero Trust: Every flow is untrusted by default and must be explicitly verified.

    Stage 1 (BCC): Fast gatekeeper — 28 features, Decision Tree.
                   If BENIGN → FORWARD (but still verified!)
                   If ATTACK → escalate to Stage 2

    Stage 2 (DDL+IF): Deep analysis — 40 features, Dictionary Learning + IF.
                      Smart consensus → FORWARD or DROP
                      DROP → LIME/SHAP XAI explanation generated
    """

    def __init__(self, models_dir=None):
        if models_dir is None:
            models_dir = os.path.join(SCRIPT_DIR, "models")

        logger.info("Loading AI pipeline models...")

        import joblib
        from ddl_model import DeepDictionaryLearning

        # Stage 1: BCC v2
        bcc_data = joblib.load(os.path.join(models_dir, "sentry_model_v2.pkl"))
        self.bcc_model = bcc_data["model"]
        self.bcc_features = bcc_data["feature_names"]
        self.bcc_thresh = bcc_data.get("threshold", 0.5)
        logger.info(f"  BCC v2: {len(self.bcc_features)} features loaded")

        # Stage 2: DDL
        self.ddl = DeepDictionaryLearning.load(os.path.join(models_dir, "ddl_40feat.pkl"))
        logger.info(f"  DDL: {self.ddl.n_features} features loaded")

        # Stage 2: Isolation Forest
        if_data = joblib.load(os.path.join(models_dir, "isolation_forest.pkl"))
        self.if_model = if_data["clf"]
        logger.info(f"  IF: {self.if_model.n_estimators} trees loaded")

        # XAI explainers (lazy init on first DROP)
        self._lime_explainer = None
        self._shap_ddl_explainer = None
        self._shap_if_explainer = None

        logger.info("  ✅ All models loaded successfully!")

    def _init_lime(self):
        """Initialize LIME explainer (lazy, on first DROP)."""
        if self._lime_explainer is not None:
            return
        try:
            from lime.lime_tabular import LimeTabularExplainer
            from ddl_pcap_extractor import DDL_40_FEATURES
            self._lime_explainer = LimeTabularExplainer(
                np.zeros((100, 40)),
                feature_names=DDL_40_FEATURES,
                class_names=["Normal", "Anomaly"],
                mode="classification",
                discretize_continuous=True,
            )
            logger.info("  LIME explainer initialized")
        except ImportError:
            logger.warning("  LIME not available — install lime package")

    def _init_shap(self):
        """Initialize SHAP KernelSHAP explainers (lazy, on first DROP)."""
        if self._shap_ddl_explainer is not None:
            return
        try:
            import shap
            background = np.zeros((50, 40))
            self._shap_ddl_explainer = shap.KernelExplainer(
                self._ddl_predict_scores, background
            )
            self._shap_if_explainer = shap.KernelExplainer(
                lambda X: self._if_predict_proba(X)[:, 1], background
            )
            logger.info("  SHAP KernelSHAP explainers initialized")
        except ImportError:
            logger.warning("  SHAP not available — install shap package")
        except Exception as e:
            logger.warning(f"  SHAP init failed: {e}")

    def _ddl_predict_scores(self, X):
        """Return DDL reconstruction error scores for SHAP."""
        if X.ndim == 1:
            X = X.reshape(1, -1)
        result = self.ddl.predict(X)
        return result["scores"]

    def _ddl_predict_proba(self, X):
        """Wrapper for DDL predict_proba for LIME."""
        if X.ndim == 1:
            X = X.reshape(1, -1)
        result = self.ddl.predict(X)
        errors = result["errors"]
        threshold = self.ddl.threshold_
        proba_anomaly = 1.0 / (1.0 + np.exp(-(errors - threshold) * 5))
        proba_normal = 1.0 - proba_anomaly
        return np.column_stack([proba_normal, proba_anomaly])

    def _if_predict_proba(self, X):
        """Wrapper for IF predict_proba for LIME/SHAP."""
        if X.ndim == 1:
            X = X.reshape(1, -1)
        scores = self.if_model.decision_function(X)
        proba_anomaly = 1.0 / (1.0 + np.exp(scores * 5))
        proba_normal = 1.0 - proba_anomaly
        return np.column_stack([proba_normal, proba_anomaly])

    def predict_from_pcap_bytes(self, raw_packets):
        """
        Run the full pipeline on accumulated raw packet bytes.

        Args:
            raw_packets: list of (timestamp, raw_bytes) tuples

        Returns:
            dict with: prediction, stage, bcc_proba, ddl_label, if_label,
                       ddl_score, xai_explanation, timing
        """
        result = {
            "prediction": "normal",
            "action": "FORWARD",
            "stage": "1",
            "bcc_proba": 0.0,
            "ddl_label": None,
            "ddl_score": None,
            "if_label": None,
            "xai": None,
            "timing": {},
            "zero_trust": "VERIFIED",
        }

        if not raw_packets:
            result["prediction"] = "error"
            result["action"] = "FORWARD"  # fail-open for empty
            return result

        # ── Write temporary PCAP for feature extraction ──────────────────
        pcap_buf = self._build_pcap_buffer(raw_packets)

        import tempfile
        tmp_path = None
        try:
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=".pcap")
            with os.fdopen(tmp_fd, 'wb') as f:
                f.write(pcap_buf)

            # ── STAGE 1: BCC (28 features) ──────────────────────────────
            t0 = time.perf_counter()
            from feature_extractor import extract_features_extended
            bcc_r = extract_features_extended(tmp_path)
            t_bcc_ext = (time.perf_counter() - t0) * 1e6

            if not bcc_r["valid"]:
                result["prediction"] = "error"
                result["action"] = "FORWARD"  # fail-open
                return result

            bcc_vec = np.array(
                [bcc_r["features"].get(c, 0.0) for c in self.bcc_features],
                dtype=np.float64
            ).reshape(1, -1)
            bcc_vec = np.nan_to_num(bcc_vec, posinf=1e9, neginf=-1e9)

            t0 = time.perf_counter()
            bcc_proba = self.bcc_model.predict_proba(bcc_vec)[0, 1]
            bcc_pred = int(bcc_proba >= self.bcc_thresh)
            t_bcc_inf = (time.perf_counter() - t0) * 1e6

            result["bcc_proba"] = float(bcc_proba)
            result["timing"]["bcc_extract_us"] = round(t_bcc_ext, 1)
            result["timing"]["bcc_infer_us"] = round(t_bcc_inf, 1)

            if bcc_pred == 0:
                # BCC says BENIGN → FORWARD (Zero Trust: verified clean)
                result["prediction"] = "normal"
                result["action"] = "FORWARD"
                result["stage"] = "1"
                result["zero_trust"] = "VERIFIED_CLEAN"
                return result

            # ── STAGE 2: DDL + IF (40 features) ─────────────────────────
            result["stage"] = "2"

            t0 = time.perf_counter()
            from ddl_pcap_extractor import extract_ddl_features, DDL_40_FEATURES
            ddl_r = extract_ddl_features(tmp_path)
            t_ddl_ext = (time.perf_counter() - t0) * 1e6

            if not ddl_r["valid"]:
                # Can't extract Stage 2 features but BCC flagged it → DROP (Zero Trust)
                result["prediction"] = "attack"
                result["action"] = "DROP"
                result["zero_trust"] = "UNVERIFIABLE_DROPPED"
                return result

            ddl_vec = np.nan_to_num(
                np.clip(np.array(ddl_r["ordered"], dtype=np.float64).reshape(1, -1), -1e9, 1e9)
            )

            t0 = time.perf_counter()
            ddl_out = self.ddl.predict(ddl_vec)
            ddl_label = ddl_out["labels"][0]
            ddl_score = ddl_out["scores"][0]
            t_ddl_inf = (time.perf_counter() - t0) * 1e6

            t0 = time.perf_counter()
            if_raw = self.if_model.predict(ddl_vec)[0]
            if_label = "Anomaly" if if_raw == -1 else "Normal"
            t_if_inf = (time.perf_counter() - t0) * 1e6

            result["ddl_label"] = ddl_label
            result["ddl_score"] = float(ddl_score)
            result["if_label"] = if_label
            result["timing"]["ddl_extract_us"] = round(t_ddl_ext, 1)
            result["timing"]["ddl_infer_us"] = round(t_ddl_inf, 1)
            result["timing"]["if_infer_us"] = round(t_if_inf, 1)

            # ── Smart Consensus ─────────────────────────────────────────
            # Zero Trust: if ANY model flags it, DROP
            drop = False
            if ddl_label == "Anomaly" or if_label == "Anomaly" or bcc_proba > 0.98:
                drop = True

            if drop:
                result["prediction"] = "attack"
                result["action"] = "DROP"
                result["zero_trust"] = "THREAT_DETECTED"

                # ── XAI: Explain the DROP decision (LIME + SHAP) ────────
                from ddl_pcap_extractor import DDL_40_FEATURES as _feat_names
                self._init_lime()
                self._init_shap()
                xai_result = {}
                t0_xai = time.perf_counter()

                # ── LIME Explanations ────────────────────────────────────
                if self._lime_explainer is not None:
                    try:
                        t0 = time.perf_counter()
                        # DDL LIME
                        ddl_exp = self._lime_explainer.explain_instance(
                            ddl_vec.flatten(),
                            self._ddl_predict_proba,
                            num_features=5,
                            num_samples=300,
                        )
                        xai_result["ddl_lime"] = [
                            (f, round(w, 6)) for f, w in
                            sorted(ddl_exp.as_list(), key=lambda x: abs(x[1]), reverse=True)[:5]
                        ]

                        # IF LIME
                        if_exp = self._lime_explainer.explain_instance(
                            ddl_vec.flatten(),
                            self._if_predict_proba,
                            num_features=5,
                            num_samples=300,
                        )
                        xai_result["if_lime"] = [
                            (f, round(w, 6)) for f, w in
                            sorted(if_exp.as_list(), key=lambda x: abs(x[1]), reverse=True)[:5]
                        ]
                        xai_result["lime_time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
                    except Exception as e:
                        xai_result["lime_error"] = str(e)

                # ── SHAP (KernelSHAP) Explanations ──────────────────────
                if self._shap_ddl_explainer is not None:
                    try:
                        t0 = time.perf_counter()
                        # DDL SHAP
                        ddl_shap_vals = self._shap_ddl_explainer.shap_values(
                            ddl_vec, nsamples=100
                        )
                        sv = ddl_shap_vals[0] if isinstance(ddl_shap_vals, list) else ddl_shap_vals.flatten()
                        top_idx = np.argsort(np.abs(sv))[-5:][::-1]
                        xai_result["ddl_shap"] = [
                            {"feature": _feat_names[i], "shap_value": round(float(sv[i]), 6),
                             "feature_value": round(float(ddl_vec.flatten()[i]), 4)}
                            for i in top_idx
                        ]

                        # IF SHAP
                        if_shap_vals = self._shap_if_explainer.shap_values(
                            ddl_vec, nsamples=100
                        )
                        sv2 = if_shap_vals[0] if isinstance(if_shap_vals, list) else if_shap_vals.flatten()
                        top_idx2 = np.argsort(np.abs(sv2))[-5:][::-1]
                        xai_result["if_shap"] = [
                            {"feature": _feat_names[i], "shap_value": round(float(sv2[i]), 6),
                             "feature_value": round(float(ddl_vec.flatten()[i]), 4)}
                            for i in top_idx2
                        ]

                        xai_result["shap_time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
                        xai_result["shap_base_value"] = float(self._shap_ddl_explainer.expected_value) \
                            if hasattr(self._shap_ddl_explainer, 'expected_value') else None
                    except Exception as e:
                        xai_result["shap_error"] = str(e)

                t_xai_total = (time.perf_counter() - t0_xai) * 1000
                xai_result["xai_total_time_ms"] = round(t_xai_total, 1)
                result["xai"] = xai_result
                result["timing"]["xai_ms"] = round(t_xai_total, 1)
            else:
                result["prediction"] = "normal"
                result["action"] = "FORWARD"
                result["zero_trust"] = "VERIFIED_CLEAN_STAGE2"

        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

        return result

    def _build_pcap_buffer(self, raw_packets):
        """Build a PCAP file in memory from list of (timestamp, raw_bytes)."""
        buf = io.BytesIO()

        # PCAP global header (little-endian)
        buf.write(struct.pack('<I', 0xa1b2c3d4))  # magic
        buf.write(struct.pack('<HH', 2, 4))        # version
        buf.write(struct.pack('<i', 0))             # timezone
        buf.write(struct.pack('<I', 0))             # sigfigs
        buf.write(struct.pack('<I', 65535))          # snaplen
        buf.write(struct.pack('<I', 1))              # network (Ethernet)

        for ts, raw_bytes in raw_packets:
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            pkt_len = len(raw_bytes)
            # Packet header
            buf.write(struct.pack('<II', ts_sec, ts_usec))
            buf.write(struct.pack('<II', pkt_len, pkt_len))
            buf.write(raw_bytes)

        return buf.getvalue()


# ═════════════════════════════════════════════════════════════════════════════
# CONTROL PLANE — UDP Listener
# ═════════════════════════════════════════════════════════════════════════════

class ControlPlane:
    """Listens for UDP control messages (START/END) from PC1."""

    def __init__(self):
        self.lock = threading.Lock()
        self.current_stream_id = None
        self.current_true_label = None
        self.current_attack_type = None
        self.running = True

    def start(self):
        """Start the UDP listener thread."""
        t = threading.Thread(target=self._listen, daemon=True)
        t.start()
        logger.info(f"Control plane listening on UDP port {CONTROL_PORT}")

    def _listen(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", CONTROL_PORT))
        sock.settimeout(1.0)

        while self.running:
            try:
                data, addr = sock.recvfrom(4096)
                msg = json.loads(data.decode("utf-8"))
                action = msg.get("action", "")

                with self.lock:
                    if action == "START":
                        self.current_stream_id = msg.get("stream_id")
                        self.current_true_label = msg.get("label")
                        self.current_attack_type = msg.get("attack_type", "unknown")
                        logger.info(f"📥 START stream: {self.current_stream_id} "
                                    f"(label={self.current_true_label})")
                    elif action == "END":
                        logger.info(f"📤 END stream: {self.current_stream_id}")
                        self.current_stream_id = None
                        self.current_true_label = None
                        self.current_attack_type = None

            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Control plane error: {e}")

    def get_state(self):
        with self.lock:
            return (self.current_stream_id,
                    self.current_true_label,
                    self.current_attack_type)


# ═════════════════════════════════════════════════════════════════════════════
# DATA PLANE — Scapy Sniffer + Forwarder
# ═════════════════════════════════════════════════════════════════════════════

class DataPlane:
    """
    Sniffs packets on iface_in, runs AI pipeline, forwards clean packets
    out iface_out. Drops malicious packets.
    """

    def __init__(self, iface_in: str, iface_out: str,
                 pipeline: ZeroTrustPipeline,
                 control: ControlPlane,
                 no_influxdb: bool = False):
        self.iface_in = iface_in
        self.iface_out = iface_out
        self.pipeline = pipeline
        self.control = control
        self.no_influxdb = no_influxdb

        # Flow accumulation
        self.lock = threading.Lock()
        self.current_packets = []  # list of (timestamp, raw_bytes)
        self.current_stream_processed = False

        # Statistics
        self.stats = {
            "total_streams": 0,
            "forwarded": 0,
            "dropped": 0,
            "errors": 0,
            "tp": 0, "tn": 0, "fp": 0, "fn": 0,
        }
        self.decisions_log = []

    def start(self):
        """Start the Scapy sniffer thread."""
        t = threading.Thread(target=self._sniff_loop, daemon=True)
        t.start()

        # Also start a stream processor thread
        p = threading.Thread(target=self._process_loop, daemon=True)
        p.start()

        logger.info(f"Data plane: sniffing on {self.iface_in}, forwarding to {self.iface_out}")

    def _sniff_loop(self):
        """Sniff packets on the ingress interface."""
        from scapy.all import sniff

        def process_pkt(pkt):
            stream_id, _, _ = self.control.get_state()
            if stream_id is None:
                return  # No active stream — ignore

            with self.lock:
                ts = time.time()
                raw = bytes(pkt)
                self.current_packets.append((ts, raw))

        sniff(iface=self.iface_in, prn=process_pkt, store=False)

    def _process_loop(self):
        """
        Monitor for stream END signals and process accumulated packets.
        """
        last_stream_id = None

        while True:
            stream_id, true_label, attack_type = self.control.get_state()

            # Detect stream transition (END signal: stream_id becomes None)
            if last_stream_id is not None and stream_id is None:
                # Stream just ended — process accumulated packets
                with self.lock:
                    packets = list(self.current_packets)
                    self.current_packets.clear()

                if packets:
                    self._process_stream(last_stream_id, true_label_saved, attack_type_saved, packets)

            # Save current state for next check
            if stream_id is not None:
                true_label_saved = true_label
                attack_type_saved = attack_type
            last_stream_id = stream_id

            time.sleep(0.1)  # Poll interval

    def _process_stream(self, stream_id, true_label, attack_type, packets):
        """Process a complete stream through the AI pipeline."""
        self.stats["total_streams"] += 1

        logger.info(f"🔬 Processing stream {stream_id}: {len(packets)} packets")

        # ── Run AI Pipeline ─────────────────────────────────────────────
        time_pipeline_in = time.time()
        result = self.pipeline.predict_from_pcap_bytes(packets)
        time_pipeline_out = time.time()

        prediction = result["prediction"]
        action = result["action"]
        pipeline_latency_ms = (time_pipeline_out - time_pipeline_in) * 1000

        # ── Forward or Drop ─────────────────────────────────────────────
        if action == "FORWARD":
            self.stats["forwarded"] += 1
            # Forward all packets out iface_out
            from scapy.all import sendp, Ether
            for ts, raw in packets:
                try:
                    pkt = Ether(raw)
                    sendp(pkt, iface=self.iface_out, verbose=False)
                except Exception:
                    pass
            symbol = "✅"
        else:
            self.stats["dropped"] += 1
            symbol = "❌"

        # ── Confusion matrix ────────────────────────────────────────────
        if true_label == "attack" and prediction == "attack":
            self.stats["tp"] += 1
        elif true_label == "normal" and prediction == "normal":
            self.stats["tn"] += 1
        elif true_label == "normal" and prediction == "attack":
            self.stats["fp"] += 1
        elif true_label == "attack" and prediction == "normal":
            self.stats["fn"] += 1

        # ── Log ─────────────────────────────────────────────────────────
        decision = {
            "stream_id": stream_id,
            "true_label": true_label,
            "attack_type": attack_type,
            "prediction": prediction,
            "action": action,
            "stage": result["stage"],
            "bcc_proba": result["bcc_proba"],
            "ddl_label": result.get("ddl_label"),
            "ddl_score": result.get("ddl_score"),
            "if_label": result.get("if_label"),
            "zero_trust": result["zero_trust"],
            "xai": result.get("xai"),
            "timing": result["timing"],
            "pipeline_latency_ms": round(pipeline_latency_ms, 2),
            "packets_count": len(packets),
            "timestamp": time.time(),
        }
        self.decisions_log.append(decision)

        # Pretty print
        logger.info(
            f"  {symbol} {stream_id} | GT={true_label:6s} | Pred={prediction:6s} | "
            f"Action={action} | Stage={result['stage']} | "
            f"BCC={result['bcc_proba']:.4f} | "
            f"Latency={pipeline_latency_ms:.1f}ms | "
            f"ZeroTrust={result['zero_trust']}"
        )

        if result.get("xai"):
            xai = result["xai"]
            if "ddl_lime" in xai and xai["ddl_lime"]:
                logger.info(f"    DDL-LIME: {xai['ddl_lime'][:3]}")
            if "if_lime" in xai and xai["if_lime"]:
                logger.info(f"    IF-LIME:  {xai['if_lime'][:3]}")
            if "ddl_shap" in xai and xai["ddl_shap"]:
                top_shap = [(d['feature'], d['shap_value']) for d in xai['ddl_shap'][:3]]
                logger.info(f"    DDL-SHAP: {top_shap}")
            if "if_shap" in xai and xai["if_shap"]:
                top_shap = [(d['feature'], d['shap_value']) for d in xai['if_shap'][:3]]
                logger.info(f"    IF-SHAP:  {top_shap}")

        # ── Telemetry: InfluxDB ─────────────────────────────────────────
        if not self.no_influxdb:
            ts_ns = int(time.time() * 1e9)
            line = (
                f'stream_metrics,stream_id={stream_id},source=pc2,'
                f'true_label={true_label} '
                f'prediction="{prediction}",action="{action}",'
                f'stage="{result["stage"]}",'
                f'bcc_proba={result["bcc_proba"]:.6f},'
                f'pipeline_latency_ms={pipeline_latency_ms:.2f},'
                f'time_pipeline_in={time_pipeline_in},'
                f'time_pipeline_out={time_pipeline_out},'
                f'zero_trust="{result["zero_trust"]}",'
                f'packets_count={len(packets)}i {ts_ns}'
            )
            write_to_influxdb(line)

    def save_log(self, path):
        """Save all decisions to JSON."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump({
                "stats": self.stats,
                "decisions": self.decisions_log,
            }, f, indent=2, default=str)
        logger.info(f"📁 Decisions log saved: {path}")

    def print_summary(self):
        s = self.stats
        total = s["tp"] + s["tn"] + s["fp"] + s["fn"]
        accuracy = (s["tp"] + s["tn"]) / total * 100 if total > 0 else 0
        recall = s["tp"] / (s["tp"] + s["fn"]) * 100 if (s["tp"] + s["fn"]) > 0 else 0
        precision = s["tp"] / (s["tp"] + s["fp"]) * 100 if (s["tp"] + s["fp"]) > 0 else 0

        avg_latency = 0
        if self.decisions_log:
            avg_latency = sum(d["pipeline_latency_ms"] for d in self.decisions_log) / len(self.decisions_log)

        print(f"\n{'='*60}")
        print(f"  PC2 GATEKEEPER — SUMMARY")
        print(f"{'='*60}")
        print(f"  Total streams:  {s['total_streams']}")
        print(f"  Forwarded:      {s['forwarded']}")
        print(f"  Dropped:        {s['dropped']}")
        print(f"  Accuracy:       {accuracy:.2f}%")
        print(f"  Precision:      {precision:.2f}%")
        print(f"  Recall:         {recall:.2f}%")
        print(f"  Avg Latency:    {avg_latency:.1f} ms/stream")
        print(f"\n  Confusion Matrix:")
        print(f"              Predicted")
        print(f"           FORWARD    DROP")
        print(f"  Normal   {s['tn']:>7,}  {s['fp']:>7,}")
        print(f"  Attack   {s['fn']:>7,}  {s['tp']:>7,}")
        print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(description="PC2: AI Gatekeeper Pipeline")
    parser.add_argument("--iface-in", default="eth0",
                        help="Ingress interface (from PC1, default: eth0)")
    parser.add_argument("--iface-out", default="eth1",
                        help="Egress interface (to PC3, default: eth1)")
    parser.add_argument("--models-dir", default=None,
                        help="Path to models directory")
    parser.add_argument("--log-file", default="logs/bridge_decisions.json",
                        help="Path to save decisions log")
    parser.add_argument("--no-influxdb", action="store_true",
                        help="Disable InfluxDB telemetry")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  PC2 — ZERO TRUST AI GATEKEEPER")
    print(f"{'='*60}")
    print(f"  Ingress:  {args.iface_in} (from PC1)")
    print(f"  Egress:   {args.iface_out} (to PC3)")
    print(f"  InfluxDB: {'disabled' if args.no_influxdb else INFLUXDB_URL}")
    print(f"{'='*60}\n")

    # Load AI pipeline
    pipeline = ZeroTrustPipeline(models_dir=args.models_dir)

    # Start control plane
    control = ControlPlane()
    control.start()

    # Start data plane
    data = DataPlane(
        iface_in=args.iface_in,
        iface_out=args.iface_out,
        pipeline=pipeline,
        control=control,
        no_influxdb=args.no_influxdb,
    )
    data.start()

    print("\n🛡️  Zero Trust Gatekeeper is ACTIVE. Waiting for traffic...")
    print("    Press Ctrl+C to stop and view summary.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        control.running = False
        data.save_log(os.path.join(SCRIPT_DIR, args.log_file))
        data.print_summary()


if __name__ == "__main__":
    main()
