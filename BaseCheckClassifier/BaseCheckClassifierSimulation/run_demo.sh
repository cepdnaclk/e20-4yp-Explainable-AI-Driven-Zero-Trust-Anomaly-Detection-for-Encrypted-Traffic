#!/bin/bash

# Activate venv
source .venv/bin/activate

echo "=========================================="
echo "    SENTRY ZERO-LEAK DEMO ORCHESTRATOR    "
echo "=========================================="

# 1. Generate fresh synthetic data
echo "[1] Generating Synthetic Traffic..."
python3 generate_synthetic_pcap.py .
if [ $? -ne 0 ]; then
    echo "[-] Failed to generate traffic."
    exit 1
fi
echo "[+] Created 'synthetic_attack.pcap' and 'synthetic_benign.pcap'"

# 2. Run Controller with these files
# Loop 50 times to give user enough time to see dashboard updates
echo "[2] Running Simulation (Looping 50 times)..."
echo "    Files: synthetic_attack.pcap, synthetic_benign.pcap"
echo "    Check your Dashboard now!"

python3 decision/sentry_controller.py --files synthetic_attack.pcap synthetic_benign.pcap --loop 50

echo "=========================================="
echo "    DEMO COMPLETE    "
echo "=========================================="
