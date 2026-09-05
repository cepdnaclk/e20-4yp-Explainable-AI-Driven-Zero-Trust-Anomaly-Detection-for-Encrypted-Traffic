# Documentation Index

Everything written about this project lives under `docs/`. The published
project page (`index.html`, `README.md`, `images/`, `_config.yml`) sits at the
top of this folder; the rest is grouped below.

## Start here

| Document | What it covers |
|---|---|
| [guides/quick-start.md](guides/quick-start.md) | Copy-paste commands to get the pipeline running |
| [guides/reproduction.md](guides/reproduction.md) | Full rebuild from scratch — environment, training, demo |
| [architecture/pipeline.md](architecture/pipeline.md) | How the two-stage pipeline fits together |

## Guides

| Document | What it covers |
|---|---|
| [guides/quick-start.md](guides/quick-start.md) | Shortest path to a running pipeline |
| [guides/reproduction.md](guides/reproduction.md) | Step-by-step reproducibility |
| [guides/testing.md](guides/testing.md) | Testing with real and simulated traffic |
| [guides/live-traffic.md](guides/live-traffic.md) | Every way to feed the pipeline live traffic |
| [guides/inline-bridge.md](guides/inline-bridge.md) | Three-machine inline bridge demo |
| [guides/latency-profiling.md](guides/latency-profiling.md) | Benchmarking and reading per-stage latency |

## Architecture

| Document | What it covers |
|---|---|
| [architecture/pipeline.md](architecture/pipeline.md) | Two-stage SDN pipeline design |
| [architecture/ddl-xai.md](architecture/ddl-xai.md) | DDL, XAI and the SDN buffer in depth |
| [architecture/features.md](architecture/features.md) | Why the DT and DDL feature sets differ |
| [architecture/enhanced-pipeline.md](architecture/enhanced-pipeline.md) | Proposed IF + dual-XAI variant |
| [architecture/basecheck-classifier.md](architecture/basecheck-classifier.md) | Stage-1 classifier structure |

## Setup

| Document | What it covers |
|---|---|
| [setup/gpu.md](setup/gpu.md) | PyTorch + CUDA for GPU DDL training |
| [setup/switch-overview.md](setup/switch-overview.md) | Mirror / SPAN port basics |
| [setup/switch-aruba-2920.md](setup/switch-aruba-2920.md) | Aruba 2920-24G (J9726A) |
| [setup/switch-cisco.md](setup/switch-cisco.md) | Cisco IOS / IOS-XE |
| [setup/switch-hp-procurve.md](setup/switch-hp-procurve.md) | HP ProCurve / ArubaOS-Switch |
| [setup/switch-enhanced-pipeline.md](setup/switch-enhanced-pipeline.md) | Wiring for the enhanced pipeline |

## Reports

| Document | What it covers |
|---|---|
| [reports/training-results.md](reports/training-results.md) | Training and testing numbers |
| [reports/supervisor-summary.md](reports/supervisor-summary.md) | Progress summary for supervisors |
| [reports/ddl-xai-briefing.md](reports/ddl-xai-briefing.md) | DDL + XAI briefing |

## Planning

| Document | What it covers |
|---|---|
| [planning/workplan.md](planning/workplan.md) | Session-by-session workplan |
| [planning/demonstration-plan.md](planning/demonstration-plan.md) | Live demo procedure |

## Docs that stay next to their code

These sit beside the files or artifacts they describe, so they are not moved here:

- `src/*/README.md` — one per package (`DDLModel`, `XAIExplainer`, `SDNBuffer`, `ZeroTrustPipeline`)
- `src/BaseCheckClassifier/sdn/training/documents/` — model plan, dataset distribution, feature reference, evaluation
- `src/BaseCheckClassifier/packet_classifier/` — classification reports next to their JSON output
- `experiments/` — archived experiments, each with its own README
- `dataset/README.md` — how to obtain and prepare the dataset
