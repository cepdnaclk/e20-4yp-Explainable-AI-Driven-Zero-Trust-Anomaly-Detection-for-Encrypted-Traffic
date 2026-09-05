#!/bin/bash
# run_demo.sh — One-Command Full Pipeline Demo
# Zero-Trust XAI Anomaly Detection | University of Peradeniya
#
# Usage:
#   cd e20420Janith/e20-4yp-.../
#   bash FullSDNPipeline/run_demo.sh
#
# This script:
#   1. Activates the venv
#   2. Checks that required models exist
#   3. Runs the SDN pipeline in demo mode OR against real PCAPs

set -e

PROJ_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJ_ROOT"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Zero-Trust XAI Pipeline — Full SDN Demo                ║"
echo "║  University of Peradeniya | e20420Janith                ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Activate venv ─────────────────────────────────────────────
VENV="/scratch1/e20-fyp-xai-anomaly-detection/.venv"
if [ -d "$VENV" ]; then
    source "$VENV/bin/activate"
    echo "✅ Virtual environment activated: $VENV"
else
    echo "⚠️  venv not found at $VENV — using system Python"
fi

echo ""

# ── Check models ──────────────────────────────────────────────
echo "📦 Checking models:"
BCC_OK="❌"
DDL_OK="❌"
IF_OK="❌"

if [ -f "models/sentry_model_v2.pkl" ]; then
    BCC_OK="✅"
fi
if [ -f "models/ddl_40feat.pkl" ]; then
    DDL_OK="✅"
fi
if [ -f "models/isolation_forest.pkl" ]; then
    IF_OK="✅"
fi

echo "   $BCC_OK BCC v2 model:        models/sentry_model_v2.pkl"
echo "   $DDL_OK DDL model:           models/ddl_40feat.pkl"
echo "   $IF_OK Isolation Forest:    models/isolation_forest.pkl"
echo ""

if [ "$DDL_OK" = "❌" ]; then
    echo "⚠️  DDL model not found. Train first with:"
    echo "   apptainer exec --nv /scratch1/.../pytorch_2.4.0-cuda12.4-cudnn9-runtime.sif \\"
    echo "       python DDLModel/train_ddl_enhanced.py \\"
    echo "           --train dataset/TRAIN_Traffic.csv --test dataset/TEST_Traffic.csv \\"
    echo "           --epochs 150 --gpu --batch-size 512"
    echo ""
    echo "Or run in demo mode (no DDL model needed):"
    echo "   python FullSDNPipeline/sdn_pipeline.py --demo"
    echo ""
fi

# ── Choose mode ───────────────────────────────────────────────
MODE="${1:-demo}"

case "$MODE" in
    demo)
        echo "🚀 Running DEMO mode (synthetic flows, no hardware needed)..."
        echo ""
        python FullSDNPipeline/sdn_pipeline.py --demo --n-flows 30
        ;;
    friday)
        echo "🔫 Running Packet Shooter: Friday PCAPs (max speed)..."
        echo ""
        python FullSDNPipeline/packet_shooter.py \
            --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \
            --rate-multiplier 0 --limit 500
        ;;
    tuesday)
        echo "🔫 Running Packet Shooter: Tuesday PCAPs..."
        echo ""
        python FullSDNPipeline/packet_shooter.py \
            --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Tuesday \
            --rate-multiplier 0 --limit 500
        ;;
    realtime)
        echo "🔫 Running Packet Shooter: Friday PCAPs (real-time speed)..."
        echo ""
        python FullSDNPipeline/packet_shooter.py \
            --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \
            --rate-multiplier 1.0 --limit 200
        ;;
    *)
        echo "Usage: bash run_demo.sh [demo|friday|tuesday|realtime]"
        echo ""
        echo "  demo     - Synthetic flows (no models/hardware needed)"
        echo "  friday   - CIC-IDS Friday PCAPs at max speed (500 flows)"
        echo "  tuesday  - CIC-IDS Tuesday PCAPs at max speed (500 flows)"
        echo "  realtime - Friday PCAPs at original timing (200 flows)"
        ;;
esac
