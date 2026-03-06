"""
profiling/timing_profiler.py — Per-Stage Latency Profiler
==========================================================
Zero-Trust Anomaly Detection | University of Peradeniya

WHAT IT MEASURES
----------------
Provides wall-clock and CPU time for every stage in the pipeline:

  Stage 0 — Feature extraction (15 features, DT input)
  Stage 1 — Base Check Classifier (DT predict)
  Stage 2 — Feature extraction (40 features, DDL input)
  Stage 3 — DDL forward pass (all layers + reconstruction)
  Stage 4 — DDL-native XAI (reconstruction decomposition)
  Stage 5 — SHAP KernelExplainer
  Stage 6 — SDN buffer hold time

OUTPUT
------
Prints a side-by-side table of:
  Stage | Mean (ms) | Median | 95th pct | Min | Max | N calls

And saves a profiling_report.json for later use by latency_benchmark.py.

USAGE
-----
  python -m profiling.timing_profiler --n_samples 200
  python -m profiling.timing_profiler --mode live --interface eth1 --duration 60
"""

import os
import sys
import time
import json
import logging
import argparse
import statistics
from datetime import datetime
from contextlib import contextmanager
from typing import List, Dict, Optional

import numpy as np

logger = logging.getLogger("Profiler")

# ── Stage IDs ─────────────────────────────────────────────────────────────────
STAGES = [
    "feat_extract_15",   # 0
    "base_check_dt",     # 1
    "feat_extract_30",   # 2
    "ddl_forward",       # 3
    "xai_native",        # 4
    "xai_shap",          # 5
    "buffer_hold",       # 6
]

STAGE_LABELS = {
    "feat_extract_15": "Feature Extraction (15 feat, DT)",
    "base_check_dt":   "Base Check Classifier (DT)",
    "feat_extract_30": "Feature Extraction (40-feat DDL)",
    "ddl_forward":     "DDL Forward Pass (all layers)",
    "xai_native":      "XAI DDL-Native (reconstruction)",
    "xai_shap":        "XAI SHAP KernelExplainer",
    "buffer_hold":     "SDN Buffer Hold Time",
}


# ── StageTimer ────────────────────────────────────────────────────────────────

class StageTimer:
    """
    Records per-stage wall-clock latency (milliseconds) across multiple calls.

    Usage:
        timer = StageTimer()
        with timer.measure("ddl_forward"):
            result = ddl.predict(features)
        print(timer.summary())
    """

    def __init__(self):
        self._records: Dict[str, List[float]] = {s: [] for s in STAGES}

    @contextmanager
    def measure(self, stage: str):
        """Context manager: measures the enclosed block and records elapsed ms."""
        if stage not in self._records:
            self._records[stage] = []
        t0 = time.perf_counter()
        try:
            yield
        finally:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            self._records[stage].append(elapsed_ms)

    def record(self, stage: str, elapsed_ms: float):
        """Manually record a pre-measured elapsed time (ms)."""
        if stage not in self._records:
            self._records[stage] = []
        self._records[stage].append(elapsed_ms)

    def stats(self, stage: str) -> Dict:
        """Return statistics dict for a given stage."""
        vals = self._records.get(stage, [])
        if not vals:
            return {
                "n": 0, "mean_ms": 0.0, "median_ms": 0.0,
                "p95_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0,
                "stdev_ms": 0.0,
            }
        sorted_v = sorted(vals)
        p95_idx = int(0.95 * len(sorted_v))
        return {
            "n":         len(vals),
            "mean_ms":   round(statistics.mean(vals), 3),
            "median_ms": round(statistics.median(vals), 3),
            "p95_ms":    round(sorted_v[p95_idx], 3),
            "min_ms":    round(min(vals), 3),
            "max_ms":    round(max(vals), 3),
            "stdev_ms":  round(statistics.stdev(vals) if len(vals) > 1 else 0.0, 3),
        }

    def summary(self) -> str:
        """
        Return a formatted table of per-stage statistics.

        Useful for console output at the end of a benchmark run.
        """
        lines = [
            "",
            "=" * 90,
            "  PIPELINE LATENCY PROFILE",
            "=" * 90,
            f"  {'Stage':<36} {'N':>5}  {'Mean':>8}  {'Median':>8}  {'95th':>8}  {'Min':>8}  {'Max':>8}",
            f"  {'-'*36} {'-'*5}  {'-'*8}  {'-'*8}  {'-'*8}  {'-'*8}  {'-'*8}",
        ]
        for s in STAGES:
            st = self.stats(s)
            if st["n"] == 0:
                continue
            label = STAGE_LABELS.get(s, s)
            lines.append(
                f"  {label:<36} {st['n']:>5}  {st['mean_ms']:>7.2f}ms"
                f"  {st['median_ms']:>7.2f}ms"
                f"  {st['p95_ms']:>7.2f}ms"
                f"  {st['min_ms']:>7.2f}ms"
                f"  {st['max_ms']:>7.2f}ms"
            )

        # Totals
        dt_total   = (self.stats("feat_extract_15")["mean_ms"] +
                      self.stats("base_check_dt")["mean_ms"])
        ddl_total  = (self.stats("feat_extract_30")["mean_ms"] +
                      self.stats("ddl_forward")["mean_ms"] +
                      self.stats("xai_native")["mean_ms"] +
                      self.stats("xai_shap")["mean_ms"])

        lines += [
            f"  {'-'*36} {'-'*5}  {'-'*8}  {'-'*8}  {'-'*8}  {'-'*8}  {'-'*8}",
            f"  {'TOTAL: Normal flow (DT only)':<36} {'':>5}  {dt_total:>7.2f}ms",
            f"  {'TOTAL: Flagged flow (DT+DDL+XAI)':<36} {'':>5}  {dt_total + ddl_total:>7.2f}ms",
            "=" * 90,
            "",
        ]
        return "\n".join(lines)

    def to_dict(self) -> Dict:
        """Serialise all stage statistics to a dict for JSON export."""
        return {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "stages": {s: self.stats(s) for s in STAGES},
        }

    def save_json(self, path: str):
        """Save profiling report as JSON."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info(f"Profiling report saved to {path}")


# ── Synthetic benchmark ───────────────────────────────────────────────────────

def run_synthetic_benchmark(n_samples: int = 200,
                             ddl_model=None,
                             explainer=None,
                             n_features_dt: int = 15,
                             n_features_ddl: int = 30,
                             output_path: str = "profiling/results/profiling_report.json"):
    """
    Run a synthetic benchmark to profile all pipeline stages.

    If no real models are provided, dummy models are used so you can profile
    the calling overhead independently of actual model performance.

    Args:
        n_samples:       Number of synthetic flow samples to process.
        ddl_model:       Fitted DeepDictionaryLearning instance (or None for dummy).
        explainer:       Fitted DDLExplainer instance (or None for dummy).
        n_features_dt:   Number of DT features (default: 15).
        n_features_ddl:  Number of DDL features (default: 30).
        output_path:     Where to save the JSON report.

    Returns:
        StageTimer with all recorded measurements.
    """
    timer = StageTimer()

    # Build dummy DT if not provided
    class _DummyDT:
        def predict(self, X):
            return ["Attack"]
        def predict_proba(self, X):
            return [[0.15, 0.85]]

    class _DummyDDL:
        last_predict_ms = 0.0
        def predict(self, X):
            t0 = time.perf_counter()
            feat = np.array(X, dtype=np.float64)
            if feat.ndim == 1:
                feat = feat.reshape(1, -1)
            # Simulate 2-layer ISTA (50 iterations each, approximate cost)
            D = np.random.randn(n_features_ddl, 64)
            alpha = np.random.randn(len(feat), 64)
            for _ in range(50):
                alpha = np.sign(alpha) * np.maximum(np.abs(alpha) - 0.01, 0)
            elapsed = (time.perf_counter() - t0) * 1000.0
            self.last_predict_ms = elapsed
            return {
                "labels": "Anomaly",
                "scores": 2.5,
                "threshold": 1.0,
                "sparse_codes_l1": alpha[0],
                "sparse_codes_l2": alpha[0],
                "sparse_codes_l3": None,
                "predict_ms": elapsed,
            }
        def get_intermediate_representations(self, X):
            feat = np.array(X, dtype=np.float64)
            n = len(feat) if feat.ndim > 1 else 1
            return {
                "per_feature_error": np.abs(np.random.randn(n_features_ddl)),
                "total_error": 2.5,
                "threshold": 1.0,
                "layer1_active_atoms": 12,
                "layer2_active_atoms": 8,
                "final_reconstruction": np.random.randn(n_features_ddl),
                "decision": "Anomaly",
            }

    class _DummyExplainer:
        def __init__(self):
            self.ddl = _DummyDDL()
            self.shap_explainer = None
        def explain_native(self, features):
            t0 = time.perf_counter()
            ir = self.ddl.get_intermediate_representations(features)
            time.sleep(0.005)  # Simulate 5ms processing
            return {"decision": "Anomaly", "feature_contributions": [], "interpretation": "demo"}
        def explain_shap(self, features, nsamples=100):
            t0 = time.perf_counter()
            time.sleep(0.22)   # Simulate ~220ms SHAP computation
            return {"attributions": [], "interpretation": "demo"}

    dt_model  = _DummyDT()
    ddl       = ddl_model  or _DummyDDL()
    xai       = explainer  or _DummyExplainer()

    rng = np.random.default_rng(42)
    logger.info(f"Running synthetic benchmark: {n_samples} samples")

    for i in range(n_samples):
        # ── Stage 0: 15-feature extraction ──
        with timer.measure("feat_extract_15"):
            dt_feats = rng.normal(0, 1, n_features_dt).tolist()
            time.sleep(0.0008)  # ~0.8ms simulated extraction

        # ── Stage 1: DT base check ──
        with timer.measure("base_check_dt"):
            dt_pred = dt_model.predict([dt_feats])[0]
            dt_conf = max(dt_model.predict_proba([dt_feats])[0])

        if dt_pred == "Normal":
            continue  # Fast path — no further stages

        # ── Stage 2: 30-feature extraction (only for flagged flows) ──
        with timer.measure("feat_extract_30"):
            ddl_feats = rng.normal(0, 1, n_features_ddl)
            time.sleep(0.0014)  # ~1.4ms simulated extraction

        # ── Stage 3: DDL forward pass ──
        with timer.measure("ddl_forward"):
            ddl_result = ddl.predict(ddl_feats)

        # ── Stage 4: DDL-native XAI ──
        with timer.measure("xai_native"):
            _ = xai.explain_native(ddl_feats)

        # ── Stage 5: SHAP ──
        with timer.measure("xai_shap"):
            _ = xai.explain_shap(ddl_feats, nsamples=50)

        # ── Stage 6: Buffer hold ──
        buffer_hold_ms = np.random.uniform(
            timer.stats("ddl_forward")["mean_ms"] or 50,
            (timer.stats("ddl_forward")["mean_ms"] or 50) * 1.1
        )
        timer.record("buffer_hold", buffer_hold_ms)

        if (i + 1) % 50 == 0:
            logger.info(f"  Profiled {i + 1}/{n_samples} samples")

    print(timer.summary())
    timer.save_json(output_path)
    return timer


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(description="Pipeline Latency Profiler")
    parser.add_argument("--n_samples",  type=int, default=200,
                        help="Number of synthetic flows to benchmark (default: 200)")
    parser.add_argument("--output",  default="profiling/results/profiling_report.json",
                        help="Output JSON path")
    args = parser.parse_args()

    timer = run_synthetic_benchmark(
        n_samples=args.n_samples,
        output_path=args.output,
    )
    print(f"\nProfiling report saved to: {args.output}")
