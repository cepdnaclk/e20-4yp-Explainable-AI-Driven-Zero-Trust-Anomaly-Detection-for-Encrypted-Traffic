#!/usr/bin/env python3
"""
packet_shooter.py — PCAP Replay with Real Timing
===================================================
Zero-Trust XAI Anomaly Detection | University of Peradeniya

Reads per-flow PCAPs from the CIC-IDS-2017 Labeled dataset and feeds them
into sdn_pipeline.py with timing that resembles actual traffic patterns.

USAGE:
    # Replay Friday's labeled PCAPs at real speed:
    python FullSDNPipeline/packet_shooter.py \\
        --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \\
        --rate-multiplier 1.0  --limit 500

    # 10x faster for quick testing:
    python FullSDNPipeline/packet_shooter.py \\
        --pcap-dir .../Labeled/Friday --rate-multiplier 10.0

    # Instant (no delays, max speed):
    python FullSDNPipeline/packet_shooter.py \\
        --pcap-dir .../Labeled/Friday --rate-multiplier 0
"""

import os
import sys
import time
import struct
import argparse
import logging
from datetime import datetime, timezone
from typing import List, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_ROOT     = os.path.dirname(SCRIPT_DIR)
PROJECT_ROOT = os.path.dirname(SRC_ROOT)
sys.path.insert(0, SRC_ROOT)
sys.path.insert(0, SCRIPT_DIR)

from sdn_pipeline import FullSDNPipeline

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("PacketShooter")


def get_pcap_first_timestamp(pcap_path: str) -> float:
    """
    Read the timestamp of the first packet from a PCAP file header.
    Returns: Unix timestamp (seconds with microsecond fractional).
    """
    try:
        with open(pcap_path, 'rb') as f:
            # Global header: magic(4) + version(4) + tz(4) + sigfigs(4) + snaplen(4) + network(4) = 24 bytes
            global_header = f.read(24)
            if len(global_header) < 24:
                return 0.0

            magic = struct.unpack('<I', global_header[:4])[0]
            if magic == 0xa1b2c3d4:
                endian = '<'
            elif magic == 0xd4c3b2a1:
                endian = '>'
            else:
                return 0.0  # Not a valid pcap

            # First packet header: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4)
            pkt_header = f.read(16)
            if len(pkt_header) < 16:
                return 0.0
            ts_sec, ts_usec = struct.unpack(endian + 'II', pkt_header[:8])
            return ts_sec + ts_usec / 1_000_000.0
    except Exception:
        return 0.0


def discover_flows(pcap_dir: str, limit: int = 0) -> List[Tuple[str, str, float]]:
    """
    Walk the labeled PCAP directory and discover per-flow PCAPs.

    Returns: List of (pcap_path, ground_truth, first_packet_timestamp)
             sorted by timestamp.
    """
    flows = []
    for root, dirs, files in os.walk(pcap_dir):
        if "packets.pcap" in files:
            folder_name = os.path.basename(root)
            # Parse ground truth from folder name (e.g. Row_123_BENIGN → BENIGN)
            if "_" in folder_name:
                label = folder_name.split("_")[-1]
            else:
                label = "UNKNOWN"
            gt_binary = "BENIGN" if label == "BENIGN" else "ATTACK"

            pcap_path = os.path.join(root, "packets.pcap")
            ts = get_pcap_first_timestamp(pcap_path)
            flows.append((pcap_path, gt_binary, ts))

            if limit > 0 and len(flows) >= limit:
                break

    # Sort by timestamp (replay in chronological order)
    flows.sort(key=lambda x: x[2])
    return flows


def run_shooter(pipeline: FullSDNPipeline, pcap_dir: str,
                rate_multiplier: float = 1.0, limit: int = 0):
    """
    Replay PCAPs with timing from the actual capture timestamps.

    rate_multiplier:
        0   = instant (no delays)
        1.0 = real-time
        2.0 = 2x real-time (half the original delays)
        0.5 = 0.5x (double delays, slow-motion)
    """
    flows = discover_flows(pcap_dir, limit=limit)

    if not flows:
        logger.error(f"No packets.pcap files found in {pcap_dir}")
        return

    benign_count = sum(1 for _, gt, _ in flows if gt == "BENIGN")
    attack_count = len(flows) - benign_count

    print(f"\n🔫 Packet Shooter — Replaying {len(flows)} flows")
    print(f"   Source:    {pcap_dir}")
    print(f"   BENIGN:    {benign_count}")
    print(f"   ATTACK:    {attack_count}")
    if rate_multiplier > 0:
        print(f"   Rate:      {rate_multiplier}x real-time")
    else:
        print(f"   Rate:      MAX SPEED (no timing delays)")
    print()

    prev_ts = flows[0][2] if flows else 0.0
    start_wall = time.time()

    for i, (pcap_path, gt, ts) in enumerate(flows):
        # ── Timing: sleep to simulate real inter-flow gaps ────────────────
        if rate_multiplier > 0 and i > 0 and ts > prev_ts:
            real_delta = ts - prev_ts
            sleep_time = real_delta / rate_multiplier
            # Cap individual sleep to 5 seconds (skip long idle periods)
            sleep_time = min(sleep_time, 5.0)
            if sleep_time > 0.001:
                time.sleep(sleep_time)
        prev_ts = ts

        # ── Process through pipeline ──────────────────────────────────────
        decision = pipeline.process_flow(pcap_path, ground_truth=gt)

        # Log
        symbol = "✅" if decision["action"] == "FORWARD" else "❌"
        ext_us = decision.get("extract_time_us", 0)
        logger.info(
            f"[{i+1:>5d}/{len(flows)}] {symbol} {decision.get('flow_id', '?')[:35]:35s} "
            f"→ {decision['action']:7s} (S{decision.get('stage', '?'):>4s}) "
            f"GT={gt:6s}  extract={ext_us}µs"
        )

        # Print summary every 200 flows
        if (i + 1) % 200 == 0:
            elapsed = time.time() - start_wall
            rate = (i + 1) / elapsed
            print(f"\n  ⏱ Processed {i+1}/{len(flows)} flows in {elapsed:.1f}s "
                  f"({rate:.0f} flows/s)")
            pipeline.print_status()

    elapsed = time.time() - start_wall
    print(f"\n⏱ Finished: {len(flows)} flows in {elapsed:.1f}s "
          f"({len(flows)/elapsed:.0f} flows/sec)")
    pipeline.print_status()
    pipeline.print_confusion_matrix()


def main():
    parser = argparse.ArgumentParser(
        description="Packet Shooter — PCAP Replay with Real Timing"
    )
    parser.add_argument("--pcap-dir", type=str, required=True,
                        help="Directory of labeled PCAPs (CIC-IDS-2017 format)")
    parser.add_argument("--rate-multiplier", type=float, default=1.0,
                        help="Replay speed: 0=instant, 1.0=real-time, 10=10x "
                             "(default: 1.0)")
    parser.add_argument("--limit", type=int, default=0,
                        help="Max flows to process (0=all)")
    parser.add_argument("--bcc-model", type=str, default=None)
    parser.add_argument("--ddl-model", type=str, default=None)
    parser.add_argument("--if-model", type=str, default=None)
    parser.add_argument("--output", type=str,
                        default="logs/packet_shooter_results.json")

    args = parser.parse_args()

    pipeline = FullSDNPipeline(
        bcc_model_path=args.bcc_model,
        ddl_model_path=args.ddl_model,
        if_model_path=args.if_model,
    )

    run_shooter(pipeline, args.pcap_dir,
                rate_multiplier=args.rate_multiplier,
                limit=args.limit)

    pipeline.save_results(args.output)
    print(f"\n📁 Results saved: {args.output}")


if __name__ == "__main__":
    main()
