#!/bin/bash
#
# build_portable_package.sh
# =========================
# Creates a self-contained portable package of the SDN Pipeline
# that can be copied to any laptop and run locally.
#
# Usage (on the remote server):
#   bash scripts/build_portable_package.sh
#
# Then copy to your laptop:
#   scp -r /tmp/sdn_pipeline_portable user@laptop:~/
#
# On your laptop:
#   cd ~/sdn_pipeline_portable
#   bash setup.sh
#   bash run.sh --interface eth0
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJ="$(dirname "$SCRIPT_DIR")"
SRC="$PROJ/src"
OUT="/tmp/sdn_pipeline_portable"

echo "Building portable SDN pipeline package..."
rm -rf "$OUT"
mkdir -p "$OUT"/{models,DDLModel,sdn/extraction,LiveTraffic,XAIExplainer,profiling,logs}

# ── Models ──
echo "[1/7] Copying models..."
cp "$PROJ/models/sentry_model_v2.pkl"   "$OUT/models/"
cp "$PROJ/models/ddl_40feat.pkl"        "$OUT/models/"
cp "$PROJ/models/isolation_forest.pkl"  "$OUT/models/"

# ── DDL Model code ──
echo "[2/7] Copying DDL model code..."
cp "$SRC/DDLModel/ddl_model.py"          "$OUT/DDLModel/"
cp "$SRC/DDLModel/ddl_pcap_extractor.py" "$OUT/DDLModel/"
cp "$SRC/DDLModel/ddl_feature_extractor.py" "$OUT/DDLModel/" 2>/dev/null || true
touch "$OUT/DDLModel/__init__.py"

# ── BCC extractor (Sandaru's) ──
echo "[3/7] Copying BCC feature extractor..."
cp "$SRC/BaseCheckClassifier/sdn/extraction/feature_extractor.py" "$OUT/sdn/extraction/"
touch "$OUT/sdn/__init__.py"
touch "$OUT/sdn/extraction/__init__.py"

# ── LiveTraffic scripts ──
echo "[4/7] Copying live traffic scripts..."
cp "$SRC/LiveTraffic/live_pipeline.py"       "$OUT/LiveTraffic/"
cp "$SRC/LiveTraffic/openflow_controller.py" "$OUT/LiveTraffic/"
cp "$SRC/LiveTraffic/traffic_generator.py"   "$OUT/LiveTraffic/"
cp "$PROJ/docs/setup/switch-aruba-2920.md" "$OUT/LiveTraffic/"
touch "$OUT/LiveTraffic/__init__.py"

# ── XAI Explainer ──
echo "[5/7] Copying XAI explainer..."
if [ -d "$SRC/XAIExplainer" ]; then
    cp "$SRC/XAIExplainer/"*.py "$OUT/XAIExplainer/" 2>/dev/null || true
fi
touch "$OUT/XAIExplainer/__init__.py"

# ── Profiling ──
echo "[6/7] Copying profiling module..."
if [ -d "$SRC/profiling" ]; then
    cp "$SRC/profiling/"*.py "$OUT/profiling/" 2>/dev/null || true
fi
touch "$OUT/profiling/__init__.py"

# ── Create requirements.txt ──
echo "[7/7] Creating config files..."
cat > "$OUT/requirements.txt" << 'REQS'
numpy>=1.21
scikit-learn>=1.0
joblib>=1.0
nfstream>=6.5
scapy>=2.5
dpkt>=1.9
lime>=0.2
REQS

# ── Create setup.sh ──
cat > "$OUT/setup.sh" << 'SETUP'
#!/bin/bash
# setup.sh — One-time setup for the SDN Pipeline on your laptop
# Run this ONCE after copying the package to your laptop.

set -e
echo "============================================"
echo "  SDN Pipeline — Local Setup"
echo "============================================"

cd "$(dirname "$0")"

# Create virtual environment
if [ ! -d ".venv" ]; then
    echo "[1/3] Creating Python virtual environment..."
    python3 -m venv .venv
else
    echo "[1/3] Virtual environment already exists"
fi

# Activate and install dependencies
echo "[2/3] Installing dependencies..."
source .venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q 2>&1 | tail -3

# Try installing ryu (optional, may fail on Python > 3.10)
echo "[3/3] Installing Ryu OpenFlow controller (optional)..."
pip install ryu -q 2>/dev/null && echo "  ✅ Ryu installed" || echo "  ⚠️  Ryu failed (Python > 3.10?) — port mirroring mode will be used"

echo ""
echo "============================================"
echo "  ✅ Setup complete!"
echo ""
echo "  Activate:  source .venv/bin/activate"
echo "  Run:       bash run.sh --interface <NIC>"
echo "  Guide:     cat LiveTraffic/switch-aruba-2920.md"
echo "============================================"
SETUP
chmod +x "$OUT/setup.sh"

# ── Create run.sh ──
cat > "$OUT/run.sh" << 'RUN'
#!/bin/bash
# run.sh — Start the SDN Pipeline for live traffic capture
#
# Usage:
#   bash run.sh --interface eth0              # Passive capture (port mirroring)
#   bash run.sh --interface eth0 --openflow   # Active OpenFlow mode
#   bash run.sh --demo                        # Demo mode (no hardware)
#
# Prerequisites:
#   1. Run setup.sh first
#   2. Connect Ethernet to switch port 24
#   3. Set static IP: sudo ip addr add 10.0.0.1/24 dev eth0

set -e
cd "$(dirname "$0")"
source .venv/bin/activate

INTERFACE="eth0"
DURATION=300
MODE="live"
OPENFLOW=""
LOG_DIR="logs"

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface|-i) INTERFACE="$2"; shift 2 ;;
        --duration|-d) DURATION="$2"; shift 2 ;;
        --openflow) OPENFLOW="yes"; shift ;;
        --demo) MODE="demo"; shift ;;
        --help|-h)
            echo "Usage: bash run.sh [--interface NIC] [--duration SECS] [--openflow] [--demo]"
            exit 0 ;;
        *) shift ;;
    esac
done

mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "============================================"
echo "  SDN Zero-Trust Pipeline"
echo "============================================"
echo "  Mode:      $MODE"
echo "  Interface: $INTERFACE"
echo "  Duration:  ${DURATION}s"
echo "  OpenFlow:  ${OPENFLOW:-no}"
echo "  Log:       $LOG_DIR/pipeline_${TIMESTAMP}.json"
echo "============================================"

if [ "$MODE" = "demo" ]; then
    echo ""
    echo "Starting demo mode (synthetic flows, no hardware needed)..."
    python LiveTraffic/live_pipeline.py \
        --demo \
        --duration "$DURATION" \
        --ddl_model models/ddl_40feat.pkl \
        --log_path "$LOG_DIR/demo_${TIMESTAMP}.json"
    exit 0
fi

# Set up network interface
echo ""
echo "Setting up $INTERFACE..."
sudo ip link set "$INTERFACE" up 2>/dev/null || true
sudo ip link set "$INTERFACE" promisc on 2>/dev/null || true

# Quick connectivity test
echo "Testing capture on $INTERFACE..."
PKTS=$(sudo timeout 3 tcpdump -i "$INTERFACE" -c 5 -q 2>/dev/null | wc -l || echo "0")
if [ "$PKTS" -gt 0 ]; then
    echo "  ✅ Seeing traffic on $INTERFACE"
else
    echo "  ⚠️  No traffic on $INTERFACE (switch may not be configured yet)"
fi

if [ -n "$OPENFLOW" ]; then
    echo ""
    echo "Starting OpenFlow controller in background..."
    python LiveTraffic/openflow_controller.py --cmd_port 6634 &
    OF_PID=$!
    sleep 2
    echo "  Controller PID: $OF_PID"
    
    echo "Starting pipeline with OpenFlow DROP enforcement..."
    python LiveTraffic/live_pipeline.py \
        --interface "$INTERFACE" \
        --duration "$DURATION" \
        --ddl_model models/ddl_40feat.pkl \
        --openflow_host 127.0.0.1 \
        --openflow_port 6634 \
        --log_path "$LOG_DIR/openflow_${TIMESTAMP}.json"
    
    kill $OF_PID 2>/dev/null
else
    echo ""
    echo "Starting pipeline (passive capture)..."
    sudo python LiveTraffic/live_pipeline.py \
        --interface "$INTERFACE" \
        --duration "$DURATION" \
        --ddl_model models/ddl_40feat.pkl \
        --log_path "$LOG_DIR/pipeline_${TIMESTAMP}.json"
fi

echo ""
echo "============================================"
echo "  Pipeline finished!"
echo "  Results: $LOG_DIR/"
echo "============================================"
RUN
chmod +x "$OUT/run.sh"

# ── Create generate_traffic.sh ──
cat > "$OUT/generate_traffic.sh" << 'TRAFFIC'
#!/bin/bash
# generate_traffic.sh — Generate test traffic on the switch network
#
# Run this from Host A (10.0.0.2) to send traffic through the switch.
#
# Usage:
#   bash generate_traffic.sh normal    # Benign HTTP/DNS traffic
#   bash generate_traffic.sh attack    # SYN flood + port scan
#   bash generate_traffic.sh mixed     # Both simultaneously

set -e
cd "$(dirname "$0")"

MODE="${1:-mixed}"
TARGET="${2:-10.0.0.3}"

echo "Traffic mode: $MODE → Target: $TARGET"

case "$MODE" in
    normal)
        echo "Generating benign traffic..."
        for i in $(seq 1 50); do
            curl -s -m 2 -o /dev/null http://$TARGET/ 2>/dev/null &
            sleep 0.$((RANDOM % 5 + 1))
        done
        wait
        ;;
    attack)
        echo "Generating attack traffic (requires sudo)..."
        # SYN flood for 10 seconds
        echo "  [1/3] SYN flood..."
        sudo timeout 10 hping3 -S --flood -p 80 $TARGET 2>/dev/null &
        sleep 12
        
        # Port scan
        echo "  [2/3] Port scan..."
        sudo nmap -sS -p 1-100 $TARGET 2>/dev/null &
        sleep 15
        
        # Our scapy generator
        echo "  [3/3] Scapy attack flows..."
        source .venv/bin/activate 2>/dev/null || true
        sudo python LiveTraffic/traffic_generator.py --mode attack --count 5 --interface eth0
        ;;
    mixed)
        echo "Generating mixed traffic (benign background + attacks)..."
        # Background benign
        for i in $(seq 1 100); do
            curl -s -m 2 -o /dev/null http://$TARGET/ 2>/dev/null &
            sleep 0.3
        done &
        BENIGN_PID=$!
        
        sleep 10
        echo "  Starting attacks..."
        sudo timeout 15 hping3 -S --flood -p 80 $TARGET 2>/dev/null &
        sleep 20
        sudo nmap -sS -p 1-50 $TARGET 2>/dev/null
        
        kill $BENIGN_PID 2>/dev/null
        ;;
    *)
        echo "Usage: bash generate_traffic.sh [normal|attack|mixed] [target_ip]"
        ;;
esac

echo "Traffic generation complete."
TRAFFIC
chmod +x "$OUT/generate_traffic.sh"

# ── Create README ──
cat > "$OUT/README.md" << 'README'
# SDN Zero-Trust Pipeline — Portable Package

## Quick Start (3 commands)

```bash
# 1. Setup (one-time)
bash setup.sh

# 2. Connect Ethernet to switch Port 24, then:
sudo ip addr add 10.0.0.1/24 dev eth0
sudo ip link set eth0 up

# 3. Run
bash run.sh --interface eth0 --duration 300
```

## Demo (no hardware)
```bash
bash setup.sh
bash run.sh --demo
```

## Files
```
models/                     ← Pre-trained models (DO NOT modify)
  sentry_model_v2.pkl       ← BCC Stage 1 (28 features, Decision Tree)
  ddl_40feat.pkl            ← DDL Stage 2 (40 features, Dictionary Learning)
  isolation_forest.pkl      ← IF Stage 2 (40 features)
DDLModel/                   ← DDL model code + 40-feature extractor
sdn/extraction/             ← Sandaru's 28-feature extractor
LiveTraffic/                ← Pipeline + controller + traffic generator
  live_pipeline.py          ← Main pipeline (NFStream capture → classify)
  openflow_controller.py    ← Ryu OpenFlow 1.3 controller
  traffic_generator.py      ← Scapy-based traffic generator
  switch-aruba-2920.md              ← Full switch setup guide
setup.sh                    ← One-time dependency installer
run.sh                      ← Pipeline launcher
generate_traffic.sh         ← Traffic generator shortcut
```

## Network Topology
```
WiFi ─── SSH to remote server (keeps your connection alive)
eth0 ─── Switch Port 24 (10.0.0.1/24) ← traffic capture

Host A (Port 1, 10.0.0.2) ←→ Switch ←→ Host B (Port 2, 10.0.0.3)
                                ↕
                    SDN Laptop (Port 24, 10.0.0.1)
```
README

# ── Package size ──
echo ""
echo "Package created at: $OUT"
du -sh "$OUT"
du -sh "$OUT/models/"
echo ""
echo "Files:"
find "$OUT" -type f | wc -l
echo ""
echo "To copy to your laptop:"
echo "  scp -r $OUT user@laptop:~/"
echo ""
echo "Or create a tar archive:"
echo "  cd /tmp && tar czf sdn_pipeline_portable.tar.gz sdn_pipeline_portable/"
echo "  scp /tmp/sdn_pipeline_portable.tar.gz user@laptop:~/"
echo ""
echo "Done! ✅"
