#!/usr/bin/env python3
"""
pc1_shooter.py — PC1: The Packet Shooter
==========================================
Zero-Trust XAI Anomaly Detection | University of Peradeniya

Three-Plane Architecture:
  Control Plane (UDP):  Sends START/END metadata to PC2 & PC3
  Data Plane (Scapy):   Replays raw PCAP packets on eth0
  Telemetry (InfluxDB): Logs send timestamps for Grafana

PCAP Directory Structure (CIC-IDS-2017):
  Labeled/
    Friday/
      Row_123_BENIGN/packets.pcap
      Row_456_DDoS/packets.pcap
      ...
    Monday/
      ...

Usage:
  sudo python3 pc1_shooter.py --pcap-dir /path/to/Labeled --iface eth0 \
      --pc2-ip 10.0.0.1 --pc3-ip 10.0.1.2 --limit 100

  sudo python3 pc1_shooter.py --pcap-dir /path/to/Labeled --iface eth0 \
      --pc2-ip 10.0.0.1 --pc3-ip 10.0.1.2 --limit 0  # All streams
"""

import os
import sys
import json
import time
import socket
import struct
import argparse
import logging
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PC1-Shooter] %(levelname)s: %(message)s"
)
logger = logging.getLogger("PC1")

# ── InfluxDB Configuration ──────────────────────────────────────────────────
INFLUXDB_URL    = os.environ.get("INFLUXDB_URL",   "http://localhost:8086")
INFLUXDB_TOKEN  = os.environ.get("INFLUXDB_TOKEN", "my-super-secret-token")
INFLUXDB_ORG    = os.environ.get("INFLUXDB_ORG",   "uop")
INFLUXDB_BUCKET = os.environ.get("INFLUXDB_BUCKET","sdn_telemetry")

CONTROL_PORT = 5005  # UDP port for control messages


def write_to_influxdb(line_protocol: str):
    """Write a line-protocol data point to InfluxDB v2."""
    try:
        import urllib.request
        url = f"{INFLUXDB_URL}/api/v2/write?org={INFLUXDB_ORG}&bucket={INFLUXDB_BUCKET}&precision=ns"
        req = urllib.request.Request(url, data=line_protocol.encode("utf-8"), method="POST")
        req.add_header("Authorization", f"Token {INFLUXDB_TOKEN}")
        req.add_header("Content-Type", "text/plain; charset=utf-8")
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        logger.warning(f"InfluxDB write failed: {e}")


def send_udp_control(target_ip: str, message: dict):
    """Send a UDP control message (JSON) to a target."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = json.dumps(message).encode("utf-8")
    sock.sendto(payload, (target_ip, CONTROL_PORT))
    sock.close()


def get_pcap_first_timestamp(pcap_path: str) -> float:
    """Read the timestamp of the first packet from a PCAP file header."""
    try:
        with open(pcap_path, 'rb') as f:
            global_header = f.read(24)
            if len(global_header) < 24:
                return 0.0
            magic = struct.unpack('<I', global_header[:4])[0]
            if magic == 0xa1b2c3d4:
                endian = '<'
            elif magic == 0xd4c3b2a1:
                endian = '>'
            else:
                return 0.0
            pkt_header = f.read(16)
            if len(pkt_header) < 16:
                return 0.0
            ts_sec, ts_usec = struct.unpack(endian + 'II', pkt_header[:8])
            return ts_sec + ts_usec / 1_000_000.0
    except Exception:
        return 0.0


def discover_streams(pcap_dir: str, limit: int = 0):
    """
    Walk the labeled PCAP directory and discover per-flow streams.

    CIC-IDS-2017 structure:
      Labeled/
        Friday/
          Row_123_BENIGN/packets.pcap    → stream_id="Friday_Row_123", label="normal"
          Row_456_DDoS/packets.pcap      → stream_id="Friday_Row_456", label="attack"

    Returns: list of (pcap_path, stream_id, true_label, first_timestamp)
    """
    streams = []
    for day_name in sorted(os.listdir(pcap_dir)):
        day_path = os.path.join(pcap_dir, day_name)
        if not os.path.isdir(day_path):
            continue
        for folder_name in sorted(os.listdir(day_path)):
            folder_path = os.path.join(day_path, folder_name)
            pcap_path = os.path.join(folder_path, "packets.pcap")
            if not os.path.isfile(pcap_path):
                continue

            # Parse stream_id and label from folder name
            # e.g., "Row_123_BENIGN" → stream_id = "Friday_Row_123", label = "normal"
            parts = folder_name.rsplit("_", 1)
            if len(parts) >= 2:
                row_part = parts[0]  # "Row_123"
                label_raw = parts[1]  # "BENIGN", "DDoS", "PortScan", etc.
            else:
                row_part = folder_name
                label_raw = "UNKNOWN"

            stream_id = f"{day_name}_{row_part}"
            true_label = "normal" if label_raw == "BENIGN" else "attack"

            ts = get_pcap_first_timestamp(pcap_path)
            streams.append((pcap_path, stream_id, true_label, label_raw, ts))

            if limit > 0 and len(streams) >= limit:
                return streams

    # Sort by timestamp for chronological replay
    streams.sort(key=lambda x: x[4])
    return streams


def replay_pcap(pcap_path: str, iface: str, inter_pkt_delay: float = 0.001):
    """
    Replay all packets from a PCAP file using Scapy's sendp().

    Args:
        pcap_path: Path to the PCAP file
        iface: Network interface to send on
        inter_pkt_delay: Delay between packets (seconds) to prevent buffer overflow

    Returns:
        (packets_sent, bytes_sent)
    """
    from scapy.all import rdpcap, sendp, Ether

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        logger.warning(f"  Could not read {pcap_path}: {e}")
        return 0, 0

    if not packets:
        return 0, 0

    pkt_count = 0
    byte_count = 0

    for pkt in packets:
        try:
            sendp(pkt, iface=iface, verbose=False)
            pkt_count += 1
            byte_count += len(pkt)
            if inter_pkt_delay > 0:
                time.sleep(inter_pkt_delay)
        except Exception as e:
            logger.warning(f"  Send error: {e}")

    return pkt_count, byte_count


def main():
    parser = argparse.ArgumentParser(description="PC1: Packet Shooter")
    parser.add_argument("--pcap-dir", required=True,
                        help="Path to CIC-IDS-2017 Labeled/ directory")
    parser.add_argument("--iface", default="eth0",
                        help="Network interface to send packets (default: eth0)")
    parser.add_argument("--pc2-ip", required=True,
                        help="IP address of PC2 (Gatekeeper)")
    parser.add_argument("--pc3-ip", required=True,
                        help="IP address of PC3 (Receiver)")
    parser.add_argument("--limit", type=int, default=0,
                        help="Max streams to replay (0=all)")
    parser.add_argument("--inter-pkt-delay", type=float, default=0.001,
                        help="Delay between packets in seconds (default: 0.001)")
    parser.add_argument("--inter-stream-delay", type=float, default=1.0,
                        help="Delay between streams in seconds (default: 1.0)")
    parser.add_argument("--no-influxdb", action="store_true",
                        help="Disable InfluxDB telemetry")
    args = parser.parse_args()

    # ── Discover streams ─────────────────────────────────────────────────
    logger.info(f"Discovering streams in {args.pcap_dir}...")
    streams = discover_streams(args.pcap_dir, limit=args.limit)
    if not streams:
        logger.error("No streams found!")
        sys.exit(1)

    normal_count = sum(1 for _, _, l, _, _ in streams if l == "normal")
    attack_count = len(streams) - normal_count

    print(f"\n{'='*60}")
    print(f"  PC1 — PACKET SHOOTER")
    print(f"{'='*60}")
    print(f"  Streams:    {len(streams)}")
    print(f"  Normal:     {normal_count}")
    print(f"  Attack:     {attack_count}")
    print(f"  Interface:  {args.iface}")
    print(f"  PC2 (Gate): {args.pc2_ip}")
    print(f"  PC3 (Recv): {args.pc3_ip}")
    print(f"{'='*60}\n")

    # ── Replay loop ──────────────────────────────────────────────────────
    total_pkts = 0
    total_bytes = 0
    start_time = time.time()

    for idx, (pcap_path, stream_id, true_label, attack_type, ts) in enumerate(streams):
        logger.info(f"[{idx+1}/{len(streams)}] {stream_id} ({attack_type}) — {true_label.upper()}")

        # ── Control Plane: Send START ────────────────────────────────────
        start_msg = {
            "action": "START",
            "stream_id": stream_id,
            "label": true_label,
            "attack_type": attack_type,
            "stream_index": idx + 1,
            "total_streams": len(streams),
        }
        send_udp_control(args.pc2_ip, start_msg)
        send_udp_control(args.pc3_ip, start_msg)

        # ── Telemetry: Log to InfluxDB ──────────────────────────────────
        time_sent = time.time()
        if not args.no_influxdb:
            ts_ns = int(time_sent * 1e9)
            line = (
                f'stream_metrics,stream_id={stream_id},source=pc1 '
                f'true_label="{true_label}",attack_type="{attack_type}",'
                f'time_sent={time_sent},event="start" {ts_ns}'
            )
            write_to_influxdb(line)

        # ── Data Plane: Wait then send packets ──────────────────────────
        time.sleep(args.inter_stream_delay)

        pkt_count, byte_count = replay_pcap(
            pcap_path, args.iface,
            inter_pkt_delay=args.inter_pkt_delay
        )
        total_pkts += pkt_count
        total_bytes += byte_count

        logger.info(f"  Sent {pkt_count} packets ({byte_count} bytes)")

        # Wait a brief moment for pipeline to finish processing
        time.sleep(0.5)

        # ── Control Plane: Send END ─────────────────────────────────────
        end_msg = {
            "action": "END",
            "stream_id": stream_id,
            "packets_sent": pkt_count,
            "bytes_sent": byte_count,
        }
        send_udp_control(args.pc2_ip, end_msg)
        send_udp_control(args.pc3_ip, end_msg)

        # ── Telemetry: Log completion ───────────────────────────────────
        time_done = time.time()
        if not args.no_influxdb:
            ts_ns = int(time_done * 1e9)
            line = (
                f'stream_metrics,stream_id={stream_id},source=pc1 '
                f'true_label="{true_label}",packets_sent={pkt_count}i,'
                f'bytes_sent={byte_count}i,event="end" {ts_ns}'
            )
            write_to_influxdb(line)

        # Progress
        if (idx + 1) % 10 == 0:
            elapsed = time.time() - start_time
            rate = (idx + 1) / elapsed
            print(f"\n  ⏱ Progress: {idx+1}/{len(streams)} streams "
                  f"({elapsed:.1f}s, {rate:.1f} streams/s)\n")

    # ── Final summary ────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"  SHOOTING COMPLETE")
    print(f"{'='*60}")
    print(f"  Streams:      {len(streams)}")
    print(f"  Packets sent: {total_pkts:,}")
    print(f"  Bytes sent:   {total_bytes:,}")
    print(f"  Duration:     {elapsed:.1f}s")
    print(f"  Rate:         {len(streams)/elapsed:.1f} streams/s")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
