#!/bin/bash
# run_remaining_days.sh

echo "[*] Starting Wednesday classification..."
python3 classify_all_days.py Wednesday > wednesday_progress.log 2>&1

echo "[*] Wednesday complete. Starting Thursday classification..."
python3 classify_all_days.py Thursday > thursday_progress.log 2>&1

echo "[*] All days complete."
