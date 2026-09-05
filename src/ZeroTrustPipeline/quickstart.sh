#!/usr/bin/env bash
# ───────────────────────────────────────────────────
#  Zero-Trust Pipeline — Quick Start
# ───────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_ROOT/.venv"

echo "══════════════════════════════════════════════"
echo "  Zero-Trust Pipeline Quick Start"
echo "══════════════════════════════════════════════"

# ── Detect uv ──
USE_UV=false
if command -v uv &>/dev/null; then
    USE_UV=true
    echo "  (using uv — fast mode)"
fi

# ── Step 1: Virtual environment ──
if [ ! -d "$VENV_DIR" ]; then
    echo "[1/4] Creating virtual environment …"
    if $USE_UV; then
        uv venv "$VENV_DIR" --python 3.12
    else
        python3 -m venv "$VENV_DIR"
    fi
else
    echo "[1/4] Virtual environment exists."
fi

source "$VENV_DIR/bin/activate"

# ── Step 2: Install dependencies ──
echo "[2/4] Installing dependencies …"
if $USE_UV; then
    uv pip install -r "$SCRIPT_DIR/requirements.txt"
else
    pip install --quiet --upgrade pip
    pip install --quiet -r "$SCRIPT_DIR/requirements.txt"
fi

# ── Step 3: Run tests ──
echo "[3/4] Running integration tests …"
cd "$PROJECT_ROOT"
python -m tests.test_pipeline

# ── Step 4: Run demo ──
echo "[4/4] Running pipeline demo …"
python -m ZeroTrustPipeline.run_demo

echo ""
echo "✓ Done! Check ZeroTrustPipeline/pipeline_results.json for detailed output."
