#!/usr/bin/env bash
# ============================================================
#  ZERO-TRUST PIPELINE — QUICK START
# ============================================================
#
#  This script sets up the environment, runs tests, and
#  demonstrates the full pipeline in one go.
#
#  Usage:
#    chmod +x quickstart.sh
#    ./quickstart.sh
#
#  Options:
#    ./quickstart.sh --skip-tests     Skip integration tests
#    ./quickstart.sh --with-shap      Enable SHAP (slower)
#    ./quickstart.sh --help           Show help
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SKIP_TESTS=false
SHAP_FLAG="--no-shap"

for arg in "$@"; do
    case $arg in
        --skip-tests) SKIP_TESTS=true ;;
        --with-shap)  SHAP_FLAG="" ;;
        --help)
            echo "Usage: $0 [--skip-tests] [--with-shap] [--help]"
            echo ""
            echo "  --skip-tests   Skip integration tests"
            echo "  --with-shap    Enable SHAP explanations (slower, more detailed)"
            echo "  --help         Show this help"
            exit 0
            ;;
    esac
done

echo -e "${BLUE}"
echo "============================================================"
echo "  ZERO-TRUST ANOMALY DETECTION PIPELINE"
echo "  Quick Start Setup & Demo"
echo "============================================================"
echo -e "${NC}"

# ─── Step 1: Virtual Environment ───
echo -e "${YELLOW}[1/5] Checking virtual environment...${NC}"
if [ ! -d ".venv" ]; then
    echo "  Creating .venv..."
    python3 -m venv .venv
    echo "  Upgrading pip..."
    .venv/bin/pip install --upgrade pip -q
fi
source .venv/bin/activate
echo -e "${GREEN}  ✓ Virtual environment active ($(.venv/bin/python --version))${NC}"

# ─── Step 2: Dependencies ───
echo -e "${YELLOW}[2/5] Checking dependencies...${NC}"

# Check if key packages are installed
if .venv/bin/python -c "import nfstream, dpkt, shap, sklearn, scapy" 2>/dev/null; then
    echo -e "${GREEN}  ✓ All dependencies already installed${NC}"
else
    echo "  Installing from requirements.txt..."
    .venv/bin/pip install -r requirements.txt -q
    echo -e "${GREEN}  ✓ Dependencies installed${NC}"
fi

# ─── Step 3: Check pcaps ───
echo -e "${YELLOW}[3/5] Checking test data...${NC}"
PCAP_COUNT=$(find . -name "*.pcap" -not -path "./venv/*" -not -path "./.venv/*" | wc -l)
echo "  Found $PCAP_COUNT .pcap files:"
find . -name "*.pcap" -not -path "./venv/*" -not -path "./.venv/*" -exec echo "    - {}" \;

NORMAL_COUNT=$(find ./normal -name "*.pcap" 2>/dev/null | wc -l)
ATTACK_COUNT=$(find ./attack -name "*.pcap" 2>/dev/null | wc -l)
echo -e "${GREEN}  ✓ Benign: $NORMAL_COUNT files, Attack: $ATTACK_COUNT files${NC}"

# ─── Step 4: Integration Tests ───
if [ "$SKIP_TESTS" = false ]; then
    echo -e "${YELLOW}[4/5] Running integration tests...${NC}"
    if .venv/bin/python test_pipeline.py 2>&1 | tail -3; then
        echo -e "${GREEN}  ✓ Tests passed${NC}"
    else
        echo -e "${RED}  ✗ Some tests failed — check output above${NC}"
        echo "  Continuing with demo anyway..."
    fi
else
    echo -e "${YELLOW}[4/5] Skipping tests (--skip-tests flag)${NC}"
fi

# ─── Step 5: Run Demo ───
echo ""
echo -e "${YELLOW}[5/5] Running full pipeline demo...${NC}"
echo ""

.venv/bin/python run_pipeline_demo.py $SHAP_FLAG

echo ""
echo -e "${BLUE}============================================================${NC}"
echo -e "${GREEN}  Quick start complete!${NC}"
echo ""
echo "  Results saved to: pipeline_results.json"
echo "  Documentation:    PIPELINE_GUIDE.md"
echo ""
echo "  Next steps:"
echo "    • Read PIPELINE_GUIDE.md for full documentation"
echo "    • Add more .pcap files to normal/ and attack/ directories"
echo "    • Train DDL on real CIC-IDS-2017 data:"
echo "      python ddl/train_ddl.py --csv /path/to/TRAIN_Traffic.csv \\"
echo "        --output models/ddl_production.pkl"
echo -e "${BLUE}============================================================${NC}"
