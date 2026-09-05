#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# install_dependencies.sh — Automated Setup for Inline Bridge Demo
# ═══════════════════════════════════════════════════════════════════
# Run this on EACH machine (PC1, PC2, PC3) to install all dependencies.
# Different machines need different subsets:
#   PC2 (Gatekeeper): Needs ALL dependencies (AI models + networking)
#   PC1 (Shooter):    Needs scapy only
#   PC3 (Receiver):   Needs scapy only
#
# Usage:
#   bash install_dependencies.sh pc2    # Full install for gatekeeper
#   bash install_dependencies.sh pc1    # Minimal install for shooter
#   bash install_dependencies.sh pc3    # Minimal install for receiver
#   bash install_dependencies.sh all    # Everything for all roles
# ═══════════════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
ROLE="${1:-all}"

echo "═══════════════════════════════════════════════════"
echo "  Inline Bridge Demo — Dependency Installer"
echo "  Role: $ROLE"
echo "═══════════════════════════════════════════════════"

# ── Step 1: Create virtual environment ───────────────────────────
echo ""
echo "[1/5] Creating Python virtual environment..."
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo "  Created: $VENV_DIR"
else
    echo "  Already exists: $VENV_DIR"
fi
source "$VENV_DIR/bin/activate"
pip install --upgrade pip > /dev/null 2>&1

# ── Step 2: Install common dependencies ─────────────────────────
echo "[2/5] Installing common Python packages..."
pip install scapy dpkt numpy 2>&1 | tail -1

# ── Step 3: Install role-specific dependencies ──────────────────
echo "[3/5] Installing $ROLE-specific packages..."

case "$ROLE" in
  pc2|gatekeeper|all)
    echo "  Installing AI/ML packages for Pipeline..."
    pip install scikit-learn joblib scipy lime shap tqdm 2>&1 | tail -3
    echo "  Installing InfluxDB client..."
    pip install influxdb-client 2>&1 | tail -1
    ;;
  pc1|shooter)
    echo "  PC1 only needs scapy (already installed)"
    pip install influxdb-client 2>&1 | tail -1
    ;;
  pc3|receiver)
    echo "  PC3 only needs scapy (already installed)"
    pip install influxdb-client 2>&1 | tail -1
    ;;
  *)
    echo "  Unknown role: $ROLE"
    echo "  Usage: bash install_dependencies.sh {pc1|pc2|pc3|all}"
    exit 1
    ;;
esac

# ── Step 4: Install system packages (Linux) ─────────────────────
echo "[4/5] Checking system packages..."
if command -v apt-get &> /dev/null; then
    echo "  Debian/Ubuntu detected"
    echo "  You may need to install: sudo apt-get install tcpdump iptables"
elif command -v dnf &> /dev/null; then
    echo "  Fedora/RHEL detected"
    echo "  You may need to install: sudo dnf install tcpdump iptables"
elif command -v pacman &> /dev/null; then
    echo "  Arch detected"
    echo "  You may need to install: sudo pacman -S tcpdump iptables"
fi

# ── Step 5: Install InfluxDB v2 + Grafana (optional) ────────────
echo "[5/5] InfluxDB + Grafana setup info..."
if [ "$ROLE" = "all" ] || [ "$ROLE" = "pc2" ] || [ "$ROLE" = "gatekeeper" ]; then
    echo ""
    echo "  ┌─────────────────────────────────────────────────┐"
    echo "  │  InfluxDB v2 Installation (run on PC2):         │"
    echo "  │                                                 │"
    echo "  │  # Download InfluxDB v2                         │"
    echo "  │  wget https://dl.influxdata.com/influxdb/       │"
    echo "  │    releases/influxdb2-2.7.1_linux_amd64.tar.gz  │"
    echo "  │  tar xvzf influxdb2-*.tar.gz                    │"
    echo "  │  sudo cp influxdb2-*/influxd /usr/local/bin/    │"
    echo "  │                                                 │"
    echo "  │  # Start InfluxDB                               │"
    echo "  │  influxd &                                      │"
    echo "  │                                                 │"
    echo "  │  # Open http://localhost:8086 to set up:        │"
    echo "  │  #   Org: uop                                   │"
    echo "  │  #   Bucket: sdn_telemetry                      │"
    echo "  │  #   Copy the API token                         │"
    echo "  │                                                 │"
    echo "  │  # Grafana Installation                         │"
    echo "  │  wget https://dl.grafana.com/oss/release/        │"
    echo "  │    grafana-10.2.3.linux-amd64.tar.gz            │"
    echo "  │  tar xvzf grafana-*.tar.gz                      │"
    echo "  │  ./grafana-*/bin/grafana-server &                │"
    echo "  │                                                 │"
    echo "  │  # Open http://localhost:3000 (admin/admin)     │"
    echo "  │  # Add InfluxDB data source (Flux query)        │"
    echo "  │  # Import dashboard from grafana/ folder        │"
    echo "  └─────────────────────────────────────────────────┘"
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo "  ✅ Installation complete for role: $ROLE"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  Activate the environment:"
echo "    source $VENV_DIR/bin/activate"
echo ""
echo "  Verify:"
echo "    python3 -c 'import scapy; print(\"Scapy OK\")'"
if [ "$ROLE" = "pc2" ] || [ "$ROLE" = "all" ]; then
    echo "    python3 -c 'import joblib; import numpy; print(\"AI deps OK\")'"
    echo "    python3 -c 'import lime; print(\"LIME OK\")'"
fi
echo ""
