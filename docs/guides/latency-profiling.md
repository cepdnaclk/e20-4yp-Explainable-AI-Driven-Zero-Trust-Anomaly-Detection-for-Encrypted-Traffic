# TIMING_GUIDE.md — How to Benchmark and Interpret Pipeline Latency
# Zero-Trust XAI Anomaly Detection | University of Peradeniya
# e20420Janith

# Timing & Latency Benchmarking Guide

This guide explains how to measure per-stage latency for the Zero-Trust
pipeline, interpret the results, and use the numbers effectively in the
research demo.

---

## Why Timing Matters

The two-stage cascade design is only beneficial if:
1. **DT stage** is fast enough not to add noticeable delay for normal flows
2. **DDL+XAI stage** latency is acceptable for anomaly flows held in the SDN buffer
3. The **total overhead** is justified by the reduction in false positives

Timing results provide concrete numbers for these claims.

---

## Running the Benchmark

### Basic Benchmark (500 synthetic flows)

```bash
# From project root:
cd e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate

python -m profiling.latency_benchmark --n_flows 500 --output profiling/results/
```

Output files in `profiling/results/`:
```
latency_cdf.png           ← CDF of per-flow end-to-end latency
per_stage_box.png         ← Box plot of latency per pipeline stage
timing_summary.json       ← Raw numbers (mean, p50, p95, p99, max)
```

### Extended Benchmark (1000 flows, with SHAP enabled)

```bash
python -m profiling.latency_benchmark \
    --n_flows 1000 \
    --enable_shap \
    --output profiling/results/extended/
```

### Live Traffic Profiling (on real captured data)

```bash
python -m profiling.timing_profiler \
    --mode pcap \
    --input /path/to/captured.pcap \
    --output profiling/results/live/
```

---

## Pipeline Stages Measured

| Stage | What it measures |
|-------|-----------------|
| `feat_extract_dt` | 15-feature extraction for Base Check Classifier |
| `dt_decision` | Decision Tree inference time |
| `feat_extract_ddl` | 40-feature extraction (DDL path, triggered for anomalies) |
| `ddl_inference` | DDL reconstruction + error score |
| `if_inference` | Isolation Forest second opinion |
| `xai_native` | DDL native per-feature reconstruction error report |
| `xai_shap` | SHAP KernelExplainer (slowest, high-quality explanation) |
| `xai_lime` | LIME tabular explanation |
| `total` | End-to-end per flow (wall clock) |

---

## Reading the CDF Chart

The CDF (Cumulative Distribution Function) chart shows:

- **X axis**: Latency in milliseconds
- **Y axis**: Fraction of flows completing within that latency (0.0 – 1.0)

**How to interpret:**
- A steep rise early = most flows are fast (good)
- A long tail = a few flows are slow (expected: these are anomaly flows running XAI)
- The **p95 value** (Y=0.95) is the most important number for demo claims

**What good numbers look like (benchmarked on CIC-IDS-2017):**

| Stage | Target Mean | Target p95 |
|-------|-------------|-----------|
| DT feature extract (15) | < 1 ms | < 3 ms |
| DT inference | < 0.5 ms | < 1 ms |
| DDL feature extract (30) | < 2 ms | < 5 ms |
| DDL inference (ISTA) | < 50 ms | < 100 ms |
| IF inference | < 5 ms | < 15 ms |
| DDL-native XAI | < 10 ms | < 20 ms |
| SHAP (100 perturbations) | < 250 ms | < 450 ms |
| **Total — normal flow** | **< 2 ms** | **< 5 ms** |
| **Total — anomaly + XAI** | **< 350 ms** | **< 600 ms** |

> **Demo talking point:** "Normal traffic pays less than 2ms overhead.
> The deep DDL+XAI analysis only runs for flagged flows — and even then,
> the hold time of ~300ms is well within tolerance for a security buffer."

---

## Reading the Per-Stage Box Plot

The box plot shows the distribution for each stage separately:

- **Box**: 25th–75th percentile (the middle 50% of measurements)
- **Whisker**: 5th–95th percentile
- **Dot**: Outliers beyond 95th percentile
- **Median line**: 50th percentile

Stages with wide boxes or long whiskers indicate **variable** latency
(typical for SHAP which varies with input complexity).

---

## Comparing DT vs DDL Latency

The key comparison for research claims:

```
Normal flow path:  Feature extract (15) → DT → FORWARD
                   ~0.8ms                + ~0.3ms = ~1.1ms total

Anomaly flow path: Feature extract (15) → DT → BUFFER → Feature extract (30) → DDL → IF → XAI → Decision
                   ~0.8ms               + ~0.3ms         + ~1.4ms              + ~45ms + ~5ms + ~250ms (SHAP)
                   = ~300ms total (only for anomalies, which are <15% of traffic)
```

This asymmetry is the **core design benefit** of the two-stage cascade.

---

## Pre-Demo: Pre-Generate Timing Charts

Run this the night before the demo so charts are ready:

```bash
cd e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/

python -m profiling.latency_benchmark \
    --n_flows 200 \
    --output profiling/results/demo/ \
    --enable_shap

# Verify PNG files exist:
ls -lh profiling/results/demo/
# Should have: latency_cdf.png, per_stage_box.png, timing_summary.json
```

Then during the demo:
```bash
# Display the charts directly:
eog profiling/results/demo/latency_cdf.png &
eog profiling/results/demo/per_stage_box.png &
```

---

## Saving Raw Timing Data

For paper writeups, save the raw JSON:

```bash
cat profiling/results/demo/timing_summary.json
```

Sample JSON structure:
```json
{
  "n_flows": 200,
  "stages": {
    "feat_extract_dt": {"mean_ms": 0.82, "p50_ms": 0.79, "p95_ms": 1.43, "p99_ms": 2.1},
    "dt_decision":     {"mean_ms": 0.31, "p50_ms": 0.29, "p95_ms": 0.72, "p99_ms": 0.9},
    "ddl_inference":   {"mean_ms": 44.1, "p50_ms": 43.2, "p95_ms": 88.5, "p99_ms": 102.0},
    "xai_shap":        {"mean_ms": 231.0, "p50_ms": 218.0, "p95_ms": 398.0, "p99_ms": 423.0}
  }
}
```

---

## Troubleshooting Timing

| Issue | Likely cause | Fix |
|-------|-------------|-----|
| All times are 0ms | Profiling disabled | Set `ENABLE_PROFILING=True` in `config.py` |
| SHAP time is missing | SHAP not installed | `pip install shap` |
| Times are 10× higher than expected | CPU load from other processes | Close browser tabs, use `taskset -c 0,1` to pin to specific cores |
| PNG files not generated | matplotlib not installed | `pip install matplotlib` |
