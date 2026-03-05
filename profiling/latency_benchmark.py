"""
profiling/latency_benchmark.py — End-to-End Latency Benchmark
=============================================================
Zero-Trust Anomaly Detection | University of Peradeniya

Runs N synthetic flows through the pipeline profiler and produces:
  - Console summary table (per-stage mean/median/p95)
  - JSON report  →  profiling/results/profiling_report.json
  - CDF plot     →  profiling/results/latency_cdf.png
  - Box plot     →  profiling/results/latency_boxplot.png

USAGE
-----
  python -m profiling.latency_benchmark
  python -m profiling.latency_benchmark --n_flows 500 --output profiling/results/
"""

import os
import sys
import argparse
import logging
import json
import time
import numpy as np

_THIS_DIR   = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_THIS_DIR)
sys.path.insert(0, PROJECT_ROOT)

from profiling.timing_profiler import (
    StageTimer, run_synthetic_benchmark, STAGES, STAGE_LABELS
)

logger = logging.getLogger("Benchmark")

# ── Per-flow end-to-end timing (simulated) ────────────────────────────────────

def _simulate_end2end_latencies(timer: StageTimer, n_flows: int):
    """
    Reconstruct per-flow end-to-end latency from stage records.

    Each normal flow  = feat_extract_15 + base_check_dt
    Each flagged flow = all stages

    Returns two arrays: normal_e2e_ms, flagged_e2e_ms
    """
    rng = np.random.default_rng(0)

    # Draw per-flow samples from each stage's empirical distribution
    def _draw(stage, n):
        recs = timer._records.get(stage, [])
        if not recs:
            return np.zeros(n)
        return rng.choice(recs, size=n, replace=True)

    n_normal  = int(n_flows * 0.80)   # ~80% pass DT
    n_flagged = n_flows - n_normal

    normal_e2e = _draw("feat_extract_15", n_normal) + _draw("base_check_dt", n_normal)
    flagged_e2e = (
        _draw("feat_extract_15", n_flagged) +
        _draw("base_check_dt",   n_flagged) +
        _draw("feat_extract_30", n_flagged) +
        _draw("ddl_forward",     n_flagged) +
        _draw("xai_native",      n_flagged) +
        _draw("xai_shap",        n_flagged)
    )

    return normal_e2e, flagged_e2e


def run_benchmark(n_flows: int = 500, output_dir: str = "profiling/results"):
    """
    Run full latency benchmark and generate all output artefacts.

    Args:
        n_flows:    Number of synthetic flows to simulate.
        output_dir: Directory for output files.
    """
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "profiling_report.json")

    logger.info(f"Starting benchmark: {n_flows} flows")
    timer = run_synthetic_benchmark(
        n_samples=n_flows,
        output_path=report_path,
    )

    # ── Per-flow end-to-end latency ──
    normal_e2e, flagged_e2e = _simulate_end2end_latencies(timer, n_flows)

    # ── Print comparison table ──
    print("\n" + "=" * 70)
    print("  LATENCY COMPARISON: Normal Flow vs. Flagged Flow (DDL+XAI)")
    print("=" * 70)
    print(f"  {'Metric':<25} {'Normal (DT only)':>18} {'Flagged (DT+DDL+XAI)':>22}")
    print(f"  {'-'*25} {'-'*18} {'-'*22}")
    for pct, label in [(50, "Median"), (95, "95th percentile"), (99, "99th percentile")]:
        n_val = float(np.percentile(normal_e2e,  pct))
        f_val = float(np.percentile(flagged_e2e, pct))
        print(f"  {label:<25} {n_val:>17.2f}ms {f_val:>21.2f}ms")
    print(f"  {'Mean':<25} {float(normal_e2e.mean()):>17.2f}ms "
          f"{float(flagged_e2e.mean()):>21.2f}ms")
    print("=" * 70)

    # ── Save latency arrays ──
    lat_path = os.path.join(output_dir, "latency_arrays.json")
    with open(lat_path, "w") as f:
        json.dump({
            "normal_e2e_ms":  normal_e2e.tolist(),
            "flagged_e2e_ms": flagged_e2e.tolist(),
        }, f)

    # ── Generate plots (matplotlib optional) ──
    _try_plot_cdf(normal_e2e, flagged_e2e, output_dir)
    _try_plot_boxplot(timer, output_dir)

    logger.info(f"Benchmark complete. All results in: {output_dir}/")
    return timer


def _try_plot_cdf(normal_e2e, flagged_e2e, output_dir):
    """Plot CDF of end-to-end latency for normal vs. flagged flows."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(9, 5))

        for data, label, color, ls in [
            (normal_e2e,  "Normal flow (DT only)",       "#2196F3", "-"),
            (flagged_e2e, "Flagged flow (DT+DDL+XAI)",  "#F44336", "--"),
        ]:
            sorted_d = np.sort(data)
            cdf = np.arange(1, len(sorted_d) + 1) / len(sorted_d)
            ax.plot(sorted_d, cdf, label=label, color=color, linestyle=ls, linewidth=2)

        ax.set_xlabel("End-to-end latency (ms)", fontsize=13)
        ax.set_ylabel("CDF", fontsize=13)
        ax.set_title("Pipeline End-to-End Latency CDF\n"
                     "Zero-Trust DDL+XAI | University of Peradeniya", fontsize=13)
        ax.legend(fontsize=11)
        ax.grid(True, alpha=0.3)
        ax.set_xlim(left=0)

        # Mark 95th percentile
        for data, color in [(normal_e2e, "#2196F3"), (flagged_e2e, "#F44336")]:
            p95 = float(np.percentile(data, 95))
            ax.axvline(p95, color=color, linestyle=":", alpha=0.5,
                       label=f"p95 = {p95:.1f}ms")

        fig.tight_layout()
        out_path = os.path.join(output_dir, "latency_cdf.png")
        fig.savefig(out_path, dpi=150)
        plt.close(fig)
        logger.info(f"CDF plot saved to: {out_path}")

    except ImportError:
        logger.warning("matplotlib not available — skipping CDF plot")
    except Exception as e:
        logger.warning(f"CDF plot failed: {e}")


def _try_plot_boxplot(timer: StageTimer, output_dir):
    """Plot per-stage latency box plots."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        active_stages = [s for s in STAGES if timer._records.get(s)]
        data   = [timer._records[s] for s in active_stages]
        labels = [STAGE_LABELS[s].replace(" (", "\n(") for s in active_stages]

        fig, ax = plt.subplots(figsize=(12, 6))
        bp = ax.boxplot(data, patch_artist=True, notch=False)

        colors = ["#4CAF50", "#4CAF50", "#FF9800", "#F44336", "#9C27B0", "#9C27B0", "#2196F3"]
        for patch, color in zip(bp["boxes"], colors[:len(bp["boxes"])]):
            patch.set_facecolor(color)
            patch.set_alpha(0.6)

        ax.set_xticks(range(1, len(active_stages) + 1))
        ax.set_xticklabels(labels, fontsize=9)
        ax.set_ylabel("Latency (ms)", fontsize=12)
        ax.set_title("Per-Stage Latency Distribution\n"
                     "Zero-Trust DDL+XAI | University of Peradeniya", fontsize=12)
        ax.grid(True, axis="y", alpha=0.3)
        ax.set_yscale("log")

        from matplotlib.patches import Patch
        legend_items = [
            Patch(facecolor="#4CAF50", alpha=0.6, label="Feature Extraction"),
            Patch(facecolor="#FF9800", alpha=0.6, label="DDL Forward"),
            Patch(facecolor="#F44336", alpha=0.6, label="XAI"),
            Patch(facecolor="#2196F3", alpha=0.6, label="Buffer Hold"),
        ]
        ax.legend(handles=legend_items, fontsize=10, loc="upper left")

        fig.tight_layout()
        out_path = os.path.join(output_dir, "latency_boxplot.png")
        fig.savefig(out_path, dpi=150)
        plt.close(fig)
        logger.info(f"Box plot saved to: {out_path}")

    except ImportError:
        logger.warning("matplotlib not available — skipping box plot")
    except Exception as e:
        logger.warning(f"Box plot failed: {e}")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(description="Pipeline Latency Benchmark")
    parser.add_argument("--n_flows", type=int, default=500,
                        help="Number of synthetic flows (default: 500)")
    parser.add_argument("--output", default="profiling/results",
                        help="Output directory for report + plots")
    args = parser.parse_args()

    run_benchmark(n_flows=args.n_flows, output_dir=args.output)
