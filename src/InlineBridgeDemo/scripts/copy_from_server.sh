#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# copy_from_server.sh — Copy everything needed from the SSH server
# ═══════════════════════════════════════════════════════════════════
# Run this on your LOCAL laptop to download the InlineBridgeDemo
# folder and the PCAP dataset from the department server.
#
# Usage:
#   bash copy_from_server.sh <username>@<server>
#
# Example:
#   bash copy_from_server.sh e20420@10.12.x.x
#   bash copy_from_server.sh e20420@ada.ce.pdn.ac.lk
# ═══════════════════════════════════════════════════════════════════

set -e

if [ -z "$1" ]; then
    echo "Usage: bash copy_from_server.sh <user>@<server>"
    echo "Example: bash copy_from_server.sh e20420@10.12.70.3"
    exit 1
fi

SERVER="$1"
REMOTE_BASE="/scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic"
REMOTE_PCAP="/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled"
LOCAL_DIR="$HOME/InlineBridgeDemo"

echo "═══════════════════════════════════════════════════"
echo "  Copying Inline Bridge Demo from Server"
echo "═══════════════════════════════════════════════════"
echo "  Server: $SERVER"
echo "  Local:  $LOCAL_DIR"
echo ""

# ── Step 1: Copy the InlineBridgeDemo folder ─────────────────────
echo "[1/3] Downloading InlineBridgeDemo folder..."
mkdir -p "$LOCAL_DIR"
scp -r "$SERVER:$REMOTE_BASE/InlineBridgeDemo/" "$LOCAL_DIR/"
echo "  ✅ Demo files downloaded"

# ── Step 2: Copy PCAP dataset (select days) ─────────────────────
echo ""
echo "[2/3] Downloading PCAP dataset..."
echo "  This may take a while depending on your connection."
echo "  The full dataset is ~20GB. We'll download selectively."
echo ""

PCAP_LOCAL="$LOCAL_DIR/pcap_data"
mkdir -p "$PCAP_LOCAL"

# Download just Friday (has DDoS + PortScan — best for demo)
echo "  Downloading Friday PCAPs (most attack types)..."
scp -r "$SERVER:$REMOTE_PCAP/Friday/" "$PCAP_LOCAL/" 2>/dev/null || {
    echo "  Note: Could not copy Friday folder directly."
    echo "  Try: rsync -avz --progress $SERVER:$REMOTE_PCAP/Friday/ $PCAP_LOCAL/Friday/"
}

echo ""
echo "  (Optional) To download all days:"
echo "    scp -r $SERVER:$REMOTE_PCAP/ $PCAP_LOCAL/"
echo ""

# ── Step 3: Verify ──────────────────────────────────────────────
echo "[3/3] Verifying..."
echo ""
echo "  InlineBridgeDemo contents:"
ls -la "$LOCAL_DIR/InlineBridgeDemo/" 2>/dev/null || echo "  (not found)"
echo ""
echo "  Models:"
ls -la "$LOCAL_DIR/InlineBridgeDemo/models/" 2>/dev/null || echo "  (not found)"
echo ""
echo "  PCAP data:"
ls "$PCAP_LOCAL/" 2>/dev/null || echo "  (not found)"
echo ""

echo "═══════════════════════════════════════════════════"
echo "  ✅ Download complete!"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  Next steps:"
echo "  1. cd $LOCAL_DIR/InlineBridgeDemo"
echo "  2. bash install_dependencies.sh pc2"
echo "  3. source .venv/bin/activate"
echo "  4. sudo bash scripts/setup_bridge.sh up"
echo "  5. sudo python3 pc2_gatekeeper.py --iface-in eth0 --iface-out eth1"
echo ""
