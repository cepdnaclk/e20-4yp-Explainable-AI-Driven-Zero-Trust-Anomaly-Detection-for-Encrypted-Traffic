#!/usr/bin/env python3
"""
pc3_receiver.py — PC3: The Packet Receiver
=============================================
Zero-Trust XAI Anomaly Detection | University of Peradeniya

Listens for packets that have been forwarded through PC2's AI pipeline.
Counts received packets/flows and logs to InfluxDB for Grafana monitoring.

Three-Plane Architecture on PC3:
  Control Plane (UDP):  Listens for START/END from PC1
  Data Plane (Scapy):   Sniffs arriving packets on eth0
  Telemetry (InfluxDB): Logs received timestamps for Grafana

Usage:
  sudo python3 pc3_receiver.py --iface eth0
"""

import os
import sys
import json
import time
import socket
import threading
import argparse
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PC3-Receiver] %(levelname)s: %(message)s"
)
logger = logging.getLogger("PC3")

# ── InfluxDB Configuration ──────────────────────────────────────────────────
INFLUXDB_URL    = os.environ.get("INFLUXDB_URL",   "http://localhost:8086")
INFLUXDB_TOKEN  = os.environ.get("INFLUXDB_TOKEN", "my-super-secret-token")
INFLUXDB_ORG    = os.environ.get("INFLUXDB_ORG",   "uop")
INFLUXDB_BUCKET = os.environ.get("INFLUXDB_BUCKET","sdn_telemetry")

CONTROL_PORT = 5005


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
        logger.debug(f"InfluxDB write failed: {e}")


class ControlPlane:
    """Listens for UDP control messages (START/END) from PC1."""

    def __init__(self):
        self.lock = threading.Lock()
        self.current_stream_id = None
        self.current_true_label = None
        self.running = True
        self.streams_seen = []

    def start(self):
        t = threading.Thread(target=self._listen, daemon=True)
        t.start()
        logger.info(f"Control plane listening on UDP port {CONTROL_PORT}")

    def _listen(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", CONTROL_PORT))
        sock.settimeout(1.0)

        while self.running:
            try:
                data, addr = sock.recvfrom(4096)
                msg = json.loads(data.decode("utf-8"))
                action = msg.get("action", "")

                with self.lock:
                    if action == "START":
                        self.current_stream_id = msg.get("stream_id")
                        self.current_true_label = msg.get("label")
                        logger.info(f"📥 START stream: {self.current_stream_id} "
                                    f"(label={self.current_true_label})")
                    elif action == "END":
                        stream_id = self.current_stream_id
                        logger.info(f"📤 END stream: {stream_id}")
                        self.streams_seen.append(stream_id)
                        self.current_stream_id = None
                        self.current_true_label = None

            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Control plane error: {e}")

    def get_state(self):
        with self.lock:
            return self.current_stream_id, self.current_true_label


class DataPlane:
    """Sniffs arriving packets and counts them per stream."""

    def __init__(self, iface: str, control: ControlPlane, no_influxdb: bool = False):
        self.iface = iface
        self.control = control
        self.no_influxdb = no_influxdb
        self.lock = threading.Lock()

        # Per-stream packet counts
        self.stream_packets = {}  # stream_id → count
        self.total_packets = 0

    def start(self):
        t = threading.Thread(target=self._sniff, daemon=True)
        t.start()
        logger.info(f"Data plane: listening on {self.iface}")

    def _sniff(self):
        from scapy.all import sniff

        def process_pkt(pkt):
            stream_id, true_label = self.control.get_state()
            if stream_id is None:
                return

            with self.lock:
                self.total_packets += 1
                if stream_id not in self.stream_packets:
                    self.stream_packets[stream_id] = 0
                self.stream_packets[stream_id] += 1

            # Log to InfluxDB
            if not self.no_influxdb:
                time_received = time.time()
                ts_ns = int(time_received * 1e9)
                line = (
                    f'stream_metrics,stream_id={stream_id},source=pc3 '
                    f'time_received={time_received},'
                    f'packet_count={self.stream_packets.get(stream_id, 0)}i {ts_ns}'
                )
                write_to_influxdb(line)

        sniff(iface=self.iface, prn=process_pkt, store=False)

    def print_summary(self):
        with self.lock:
            received_streams = len(self.stream_packets)
            total_expected = len(self.control.streams_seen)

        print(f"\n{'='*60}")
        print(f"  PC3 RECEIVER — SUMMARY")
        print(f"{'='*60}")
        print(f"  Total streams expected:  {total_expected}")
        print(f"  Streams with packets:    {received_streams}")
        print(f"  Streams blocked (0 pkts):{total_expected - received_streams}")
        print(f"  Total packets received:  {self.total_packets}")

        if self.stream_packets:
            print(f"\n  Per-stream breakdown:")
            for sid in sorted(self.stream_packets.keys()):
                pkt_count = self.stream_packets[sid]
                print(f"    {sid}: {pkt_count} packets received")

        print(f"{'='*60}\n")

    def save_log(self, path):
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump({
                "total_packets": self.total_packets,
                "streams_received": dict(self.stream_packets),
                "streams_expected": self.control.streams_seen,
            }, f, indent=2)
        logger.info(f"📁 Receiver log saved: {path}")


def main():
    parser = argparse.ArgumentParser(description="PC3: Packet Receiver")
    parser.add_argument("--iface", default="eth0",
                        help="Network interface to listen on (default: eth0)")
    parser.add_argument("--log-file", default="logs/receiver_log.json",
                        help="Path to save receiver log")
    parser.add_argument("--no-influxdb", action="store_true",
                        help="Disable InfluxDB telemetry")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  PC3 — PACKET RECEIVER")
    print(f"{'='*60}")
    print(f"  Interface:  {args.iface}")
    print(f"  InfluxDB:   {'disabled' if args.no_influxdb else INFLUXDB_URL}")
    print(f"{'='*60}\n")

    control = ControlPlane()
    control.start()

    data = DataPlane(
        iface=args.iface,
        control=control,
        no_influxdb=args.no_influxdb,
    )
    data.start()

    print("📡 Receiver is ACTIVE. Waiting for packets...")
    print("   Press Ctrl+C to stop and view summary.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        control.running = False
        data.save_log(os.path.join(os.path.dirname(os.path.abspath(__file__)), args.log_file))
        data.print_summary()


if __name__ == "__main__":
    main()
