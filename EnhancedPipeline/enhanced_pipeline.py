"""
enhanced_pipeline.py — Main Enhanced Pipeline Orchestrator
===========================================================
Zero-Trust XAI Anomaly Detection | University of Peradeniya
e20420Janith

Architecture:
  Flow flagged by Base Check Classifier (DT)
      ↓
  SDN Buffer (hold packets)
      ↓
  30-feature DDL extraction
      ↓
  DDL reconstruction-error check
  Isolation Forest second-opinion vote
      ↓
  DualXAI (SHAP + LIME + DDL-native)
      ↓
  Decision: FORWARD (release buffer) | DROP (XAI report)

Usage (standalone demo):
    python EnhancedPipeline/enhanced_pipeline.py --demo --n_flows 10

Usage (API mode — called by rest_api.py):
    from EnhancedPipeline.enhanced_pipeline import EnhancedPipeline
    ep = EnhancedPipeline()
    ep.load_models()
    result = ep.process_flow(feature_vector_30)
"""

import os
import sys
import time
import json
import logging
import argparse
import numpy as np
from typing import Optional, Dict, Any, List

# ── Path setup ────────────────────────────────────────────────────────────────
_THIS_DIR    = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_THIS_DIR)
sys.path.insert(0, PROJECT_ROOT)

from EnhancedPipeline.config import CFG
from DDLModel.ddl_model import DeepDictionaryLearning
from DDLModel.ddl_feature_extractor import DDL_FEATURE_NAMES, N_DDL_FEATURES
from EnhancedPipeline.if_second_vote import IsolationForestVoter
from EnhancedPipeline.dual_xai import DualXAIExplainer
from EnhancedPipeline.adaptive_features import AdaptiveFeatureSelector

logging.basicConfig(
    level=getattr(logging, CFG.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("EP.Pipeline")


# ─────────────────────────────────────────────────────────────────────────────

class PipelineStats:
    """Thread-safe lightweight stats tracker."""

    def __init__(self):
        self.total_flows   = 0
        self.drops         = 0
        self.forwards      = 0
        self.ddl_only_drop = 0   # IF agreed → high confidence
        self.if_override   = 0   # DDL said anomaly, IF said normal
        self.latencies_ms  = []  # Per-flow total latency
        self.start_time    = time.time()

    def record(self, action: str, latency_ms: float, confidence: str):
        self.total_flows += 1
        if action == "DROP":
            self.drops += 1
            if confidence == "high":
                self.ddl_only_drop += 1
        elif action == "FORWARD":
            self.forwards += 1
            if confidence == "if_override":
                self.if_override += 1
        self.latencies_ms.append(latency_ms)

    def to_dict(self) -> dict:
        lats = self.latencies_ms or [0]
        uptime = time.time() - self.start_time
        return {
            "total_flows":    self.total_flows,
            "drops":          self.drops,
            "forwards":       self.forwards,
            "drop_rate_pct":  round(100 * self.drops / max(self.total_flows, 1), 1),
            "if_overrides":   self.if_override,
            "mean_latency_ms": round(float(np.mean(lats)), 2),
            "p95_latency_ms":  round(float(np.percentile(lats, 95)), 2),
            "uptime_s":        round(uptime, 1),
        }


# ─────────────────────────────────────────────────────────────────────────────

class EnhancedPipeline:
    """
    Full enhanced pipeline: DDL + Isolation Forest + Dual XAI.

    Parameters
    ----------
    ddl_path : str, optional
        Path to a pre-trained DDL model.  If None, uses CFG.DDL_MODEL_PATH.
    if_path : str, optional
        Path to a pre-trained Isolation Forest.  If None, uses CFG.IF_MODEL_PATH.
    background_data : np.ndarray, optional
        Normal-traffic feature matrix used to initialise SHAP KernelExplainer.
        Shape (N, 30).  Required for SHAP.
    enable_shap : bool
        Enable SHAP explanations (slower, ~100-400 ms per anomaly).
    enable_lime : bool
        Enable LIME explanations (slower, ~200-600 ms per anomaly).
    enable_adaptive : bool
        Enable MI-based adaptive feature selection.
    """

    def __init__(
        self,
        ddl_path: Optional[str] = None,
        if_path: Optional[str] = None,
        background_data: Optional[np.ndarray] = None,
        enable_shap: bool = True,
        enable_lime: bool = True,
        enable_adaptive: bool = True,
    ):
        self.ddl_path   = ddl_path or CFG.DDL_MODEL_PATH
        self.if_path    = if_path  or CFG.IF_MODEL_PATH
        self.enable_shap    = enable_shap
        self.enable_lime    = enable_lime
        self.enable_adaptive = enable_adaptive

        self.ddl: Optional[DeepDictionaryLearning] = None
        self.if_voter: Optional[IsolationForestVoter] = None
        self.xai: Optional[DualXAIExplainer] = None
        self.adaptive: Optional[AdaptiveFeatureSelector] = None
        self.background_data = background_data

        self._is_loaded = False
        self.stats = PipelineStats()

        # In-memory store: flow_id → last explanation (for /explain API)
        self._explanation_store: Dict[str, dict] = {}

    # ─────────────────────────────────────────────────────────────────────────

    def load_models(self, verbose: bool = True) -> "EnhancedPipeline":
        """
        Load DDL and Isolation Forest from disk.

        Raises FileNotFoundError if a model path doesn't exist.
        """
        if not os.path.exists(self.ddl_path):
            raise FileNotFoundError(
                f"DDL model not found at: {self.ddl_path}\n"
                "Run: python DDLModel/train_ddl_enhanced.py --train dataset/TRAIN_Traffic.csv"
            )
        if verbose:
            logger.info(f"Loading DDL model from {self.ddl_path} ...")
        self.ddl = DeepDictionaryLearning.load(self.ddl_path)

        if os.path.exists(self.if_path):
            if verbose:
                logger.info(f"Loading Isolation Forest from {self.if_path} ...")
            self.if_voter = IsolationForestVoter.load(self.if_path)
        else:
            logger.warning(
                f"Isolation Forest model not found at {self.if_path}. "
                "Running DDL-only (no second opinion)."
            )
            self.if_voter = None

        # XAI explainer
        self.xai = DualXAIExplainer(
            ddl_model=self.ddl,
            background_data=self.background_data,
            feature_names=DDL_FEATURE_NAMES,
            enable_shap=self.enable_shap,
            enable_lime=self.enable_lime,
        )

        # Adaptive feature selector
        if self.enable_adaptive:
            self.adaptive = AdaptiveFeatureSelector(
                k=CFG.TOP_K_FEATURES,
                retrain_every=CFG.RETRAIN_EVERY_N,
            )

        self._is_loaded = True
        if verbose:
            logger.info("Enhanced Pipeline ready.")
        return self

    # ─────────────────────────────────────────────────────────────────────────

    def process_flow(
        self,
        features: np.ndarray,
        flow_id: Optional[str] = None,
        run_xai: bool = True,
    ) -> Dict[str, Any]:
        """
        Process a single flagged flow through DDL + IF + XAI.

        Parameters
        ----------
        features : np.ndarray, shape (30,)
            30 DDL features extracted by DDLFeatureExtractor.
        flow_id : str, optional
            Identifier for this flow (used to retrieve explanation later).
        run_xai : bool
            If False, skip SHAP/LIME (fast path for high-throughput mode).

        Returns
        -------
        dict with keys:
            flow_id, action (FORWARD|DROP), confidence, ddl_score,
            ddl_threshold, if_score, explanation (if run_xai), latency_ms
        """
        if not self._is_loaded:
            raise RuntimeError("Call load_models() before process_flow().")

        t0 = time.perf_counter()
        features = np.asarray(features, dtype=np.float64).ravel()
        if features.shape[0] != N_DDL_FEATURES:
            raise ValueError(
                f"Expected {N_DDL_FEATURES} features, got {features.shape[0]}"
            )

        if flow_id is None:
            flow_id = f"flow_{self.stats.total_flows:06d}"

        # ── Stage 1: DDL ─────────────────────────────────────────────────────
        t_ddl_start = time.perf_counter()
        ddl_result  = self.ddl.predict(features)
        ddl_label   = ddl_result["labels"]  # "Normal" | "Anomaly"
        ddl_score   = float(ddl_result["scores"])
        ddl_threshold = float(self.ddl.threshold_)
        t_ddl_ms = (time.perf_counter() - t_ddl_start) * 1000

        # ── Stage 2: Isolation Forest second opinion ──────────────────────────
        t_if_start = time.perf_counter()
        if_label   = "Unknown"
        if_score   = 0.0
        if self.if_voter is not None:
            if_result  = self.if_voter.predict(features)
            if_label   = if_result["label"]    # "Normal" | "Anomaly"
            if_score   = float(if_result["score"])
        t_if_ms = (time.perf_counter() - t_if_start) * 1000

        # ── Stage 3: Voting logic ─────────────────────────────────────────────
        if ddl_label == "Anomaly" and if_label == "Anomaly":
            action     = "DROP"
            confidence = "high"    # Both agree → drop with high confidence
        elif ddl_label == "Anomaly" and if_label == "Normal":
            action     = "FORWARD"
            confidence = "if_override"  # IF overrides DDL → safer to forward
        elif ddl_label == "Normal":
            action     = "FORWARD"
            confidence = "normal"
        else:
            # IF not available — trust DDL alone
            action     = "DROP" if ddl_label == "Anomaly" else "FORWARD"
            confidence = "ddl_only"

        # ── Stage 4: XAI (only for anomalies or when explicitly requested) ───
        explanation: Optional[dict] = None
        t_xai_ms = 0.0
        if run_xai and (action == "DROP" or ddl_label == "Anomaly"):
            t_xai_start = time.perf_counter()
            explanation = self.xai.explain(features, include_shap=self.enable_shap,
                                            include_lime=self.enable_lime)
            t_xai_ms = (time.perf_counter() - t_xai_start) * 1000

        # ── Stage 5: Adaptive feature update ─────────────────────────────────
        if self.adaptive is not None:
            label_int = 1 if action == "DROP" else 0
            self.adaptive.update(features, label_int)

        total_ms = (time.perf_counter() - t0) * 1000
        self.stats.record(action, total_ms, confidence)

        result = {
            "flow_id":      flow_id,
            "action":       action,
            "confidence":   confidence,
            "ddl_label":    ddl_label,
            "ddl_score":    round(ddl_score, 6),
            "ddl_threshold":round(ddl_threshold, 6),
            "if_label":     if_label,
            "if_score":     round(if_score, 6),
            "explanation":  explanation,
            "latency_ms": {
                "ddl":   round(t_ddl_ms, 3),
                "if":    round(t_if_ms, 3),
                "xai":   round(t_xai_ms, 3),
                "total": round(total_ms, 3),
            },
        }

        if explanation:
            self._explanation_store[flow_id] = explanation

        return result

    # ─────────────────────────────────────────────────────────────────────────

    def get_explanation(self, flow_id: str) -> Optional[dict]:
        """Retrieve a stored XAI explanation by flow ID (for /explain API)."""
        return self._explanation_store.get(flow_id)

    def get_stats(self) -> dict:
        return self.stats.to_dict()

    def get_adaptive_stats(self) -> dict:
        if self.adaptive:
            return self.adaptive.stats
        return {}

    # ─────────────────────────────────────────────────────────────────────────

    @classmethod
    def run_demo(
        cls,
        n_flows: int = 10,
        ddl_path: Optional[str] = None,
        if_path: Optional[str] = None,
        enable_shap: bool = False,
        enable_lime: bool = False,
    ) -> None:
        """
        Run demo mode: synthetic normal + attack flows through the pipeline.
        Does NOT require a trained model — uses a freshly fitted DDL on
        synthetic data if no model file exists.
        """
        print("=" * 65)
        print("  ENHANCED PIPELINE — DEMO MODE")
        print("=" * 65)

        # Build/load DDL
        ddl_p  = ddl_path or CFG.DDL_MODEL_PATH
        if_p   = if_path  or CFG.IF_MODEL_PATH

        if os.path.exists(ddl_p):
            ep = cls(ddl_path=ddl_p, if_path=if_p,
                     enable_shap=enable_shap, enable_lime=enable_lime)
        else:
            print("\n[DEMO] No trained model found — fitting on synthetic data ...")
            ep = cls.__new__(cls)
            ep.__init__(ddl_path=ddl_p, if_path=if_p,
                        enable_shap=enable_shap, enable_lime=enable_lime)
            ep._fit_synthetic_demo()
            ep._is_loaded = True  # already set by _fit_synthetic_demo

        if os.path.exists(ddl_p):
            ep.load_models(verbose=True)

        # Generate synthetic flows
        rng = np.random.default_rng(42)
        normal_base   = rng.normal(loc=0.3, scale=0.05, size=(n_flows, N_DDL_FEATURES))
        attack_base   = rng.normal(loc=3.0, scale=1.0,  size=(n_flows, N_DDL_FEATURES))

        print(f"\nProcessing {n_flows} normal + {n_flows} attack flows ...\n")

        for i, feat in enumerate(normal_base):
            r = ep.process_flow(np.clip(feat, 0, None), run_xai=False)
            tag = "✓" if r["action"] == "FORWARD" else "✗"
            print(f"  [{tag}] Normal  flow {i+1:3d} → {r['action']:7s} "
                  f"| DDL score={r['ddl_score']:.4f} | {r['latency_ms']['total']:.1f} ms")

        print()
        for i, feat in enumerate(attack_base):
            r = ep.process_flow(np.clip(feat, 0, None), run_xai=True)
            tag = "✓" if r["action"] == "DROP" else "✗"
            print(f"  [{tag}] Attack  flow {i+1:3d} → {r['action']:7s} "
                  f"| DDL score={r['ddl_score']:.4f} | {r['latency_ms']['total']:.1f} ms")
            if r["explanation"] and r["explanation"].get("summary"):
                for line in r["explanation"]["summary"].split("\n")[:5]:
                    print(f"         {line}")

        print("\n" + "=" * 65)
        print("Pipeline Stats:")
        for k, v in ep.get_stats().items():
            print(f"  {k:25s}: {v}")
        print("=" * 65)

    def _fit_synthetic_demo(self) -> None:
        """Fit DDL + IF on tiny synthetic data for demo-without-model."""
        rng = np.random.default_rng(0)
        X_normal = rng.normal(loc=0.3, scale=0.05, size=(200, N_DDL_FEATURES))
        X_normal = np.clip(X_normal, 0, None)

        self.ddl = DeepDictionaryLearning(
            n_features=N_DDL_FEATURES,
            n_atoms_l1=CFG.DDL_N_ATOMS_L1,
            n_atoms_l2=CFG.DDL_N_ATOMS_L2,
            n_epochs=30,
        )
        self.ddl.fit(X_normal)

        self.if_voter = IsolationForestVoter(
            n_estimators=CFG.IF_N_ESTIMATORS,
            contamination=CFG.IF_CONTAMINATION,
        )
        self.if_voter.fit(X_normal)

        self.xai = DualXAIExplainer(
            ddl_model=self.ddl,
            background_data=X_normal[:50],
            feature_names=DDL_FEATURE_NAMES,
            enable_shap=self.enable_shap,
            enable_lime=self.enable_lime,
        )

        if self.enable_adaptive:
            self.adaptive = AdaptiveFeatureSelector()

        self.stats = PipelineStats()
        self._explanation_store = {}
        logger.info("Synthetic demo models fitted.")


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced Pipeline Demo")
    parser.add_argument("--demo", action="store_true", help="Run demo mode")
    parser.add_argument("--n_flows", type=int, default=10,
                        help="Number of flows per class in demo (default: 10)")
    parser.add_argument("--ddl_path", default=None,
                        help="Override DDL model path")
    parser.add_argument("--if_path", default=None,
                        help="Override Isolation Forest model path")
    parser.add_argument("--shap", action="store_true", help="Enable SHAP explanations")
    parser.add_argument("--lime", action="store_true", help="Enable LIME explanations")
    args = parser.parse_args()

    if args.demo:
        EnhancedPipeline.run_demo(
            n_flows=args.n_flows,
            ddl_path=args.ddl_path,
            if_path=args.if_path,
            enable_shap=args.shap,
            enable_lime=args.lime,
        )
    else:
        print("Use --demo to run demonstration mode.")
        print("For API mode, run: python EnhancedPipeline/rest_api.py --port 5001")
