"""
traffic_generator.py — Demo Traffic Generator (PCAP + Live Send)
=================================================================
Zero-Trust XAI Anomaly Detection | University of Peradeniya
e20420Janith

Generates demo traffic in three modes:
  --mode normal     → realistic HTTP/DNS/TLS flows
  --mode attack     → SYN flood, port scan, large-flow DDoS
  --mode borderline → crafted to fool DT but pass DDL (valid test case)

Output modes:
  --output /path/to/out.pcap   → save PCAP file (no scapy TX required)
  --interface eth0             → send live on wire (requires root + scapy)
  (both can be combined)

Usage:
    # Save to PCAP (no root needed):
    python LiveTraffic/traffic_generator.py --mode normal --count 20 --output /tmp/normal.pcap

    # Send live on interface (requires sudo):
    sudo python LiveTraffic/traffic_generator.py --mode attack --count 10 --interface eth1

    # Both:
    sudo python LiveTraffic/traffic_generator.py --mode borderline --count 5 \\
         --interface eth1 --output /tmp/borderline.pcap

Requirements:
    pip install scapy
    (For PCAP-only output scapy still needed for packet crafting)
"""

import os
import sys
import time
import random
import logging
import argparse
from typing import List, Optional

logger = logging.getLogger("TrafficGenerator")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

# ── Scapy import ──────────────────────────────────────────────────────────────
try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, Raw, Ether,
        send, sendp, wrpcap,
        RandShort, RandIP, RandMAC,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    logger.error(
        "scapy is not installed.\n"
        "Install: pip install scapy\n"
        "Or (system-wide): sudo pip install scapy"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Packet builders
# ─────────────────────────────────────────────────────────────────────────────

def _rand_ip() -> str:
    return f"10.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"


def build_normal_packets(n_flows: int = 1) -> list:
    """
    Realistic normal HTTP/TLS/DNS flows.
    IAT is moderate, packet sizes vary realistically.
    """
    pkts = []
    for _ in range(n_flows):
        src = _rand_ip()
        dst = "10.0.0.1"
        sport = random.randint(49152, 65535)
        dport = random.choice([80, 443, 53, 22, 8080])
        seq   = random.randint(1000, 9999999)

        # TCP SYN + SYN-ACK + ACK (3-way handshake)
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                    flags="S", seq=seq))
        pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport,
                    flags="SA", seq=seq+100, ack=seq+1))
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                    flags="A", seq=seq+1, ack=seq+101))

        # HTTP GET or TLS ClientHello payload
        payload = b"GET / HTTP/1.1\r\nHost: server.local\r\n\r\n"
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                    flags="PA", seq=seq+1, ack=seq+101) / Raw(load=payload))

        # Response
        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 512\r\n\r\n" + b"A" * 512
        pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport,
                    flags="PA", seq=seq+101, ack=seq+1+len(payload)) / Raw(load=resp))

        # FIN
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA"))
        pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="FA"))

    logger.info(f"Built {len(pkts)} normal packets for {n_flows} flows")
    return pkts


def build_attack_packets(n_flows: int = 1) -> list:
    """
    Attack traffic: SYN flood + port scan bursts.
    High SYN count, tiny IAT, extreme packet rates → high DDL error.
    """
    pkts = []
    for flow_i in range(n_flows):
        attack_type = flow_i % 3

        if attack_type == 0:
            # SYN flood: hundreds of SYNs to same target
            target = "10.0.0.1"
            for _ in range(200):
                src = _rand_ip()
                pkts.append(IP(src=src, dst=target) / TCP(
                    sport=RandShort(), dport=80, flags="S",
                    seq=random.randint(0, 2**32 - 1)
                ))

        elif attack_type == 1:
            # Port scan: sequential port probes
            src  = _rand_ip()
            dst  = "10.0.0.2"
            for port in range(1, 121):
                pkts.append(IP(src=src, dst=dst) / TCP(
                    sport=random.randint(49152, 65535), dport=port,
                    flags="S"
                ))

        else:
            # Large-flow DDoS: huge payload, rapid fire, no handshake
            src = _rand_ip()
            dst = "10.0.0.1"
            for _ in range(50):
                pkts.append(IP(src=src, dst=dst) / UDP(
                    sport=random.randint(1024, 65535), dport=53
                ) / Raw(load=b"\x00" * 1400))

    logger.info(f"Built {len(pkts)} attack packets for {n_flows} attack flows")
    return pkts


def build_borderline_packets(n_flows: int = 1) -> list:
    """
    Borderline flows: shaped to trigger DT anomaly flag (high Fwd Packet
    Length Variance) but look DDL-normal (moderate IAT, regular TCP flags).
    Used to demonstrate the cascade benefit: DT flags → DDL clears.
    """
    pkts = []
    for _ in range(n_flows):
        src   = _rand_ip()
        dst   = "10.0.0.1"
        sport = random.randint(49152, 65535)
        dport = 443
        seq   = random.randint(1000, 9999999)

        # Mixed large/small packets (high variance) but normal IAT
        sizes = [1460, 40, 860, 40, 1200, 40, 600, 40]
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                    flags="S", seq=seq))
        pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport,
                    flags="SA", ack=seq+1))

        for size in sizes:
            pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                        flags="PA") / Raw(load=b"\x17\x03\x03" + b"\x00" * (size - 3)))
            pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport,
                        flags="A"))

        pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="F"))

    logger.info(f"Built {len(pkts)} borderline packets for {n_flows} flows")
    return pkts


# ─────────────────────────────────────────────────────────────────────────────

def generate(
    mode: str,
    count: int = 10,
    output: Optional[str] = None,
    interface: Optional[str] = None,
    inter_packet_s: float = 0.001,
) -> None:
    """
    Main generation function.

    Parameters
    ----------
    mode      : "normal" | "attack" | "borderline"
    count     : number of flows to generate
    output    : path to write PCAP file (None = no file)
    interface : network interface to send live (None = no live send)
    inter_packet_s : delay between live-sent packets (seconds)
    """
    if not SCAPY_OK:
        logger.error("Cannot generate traffic without scapy. Exiting.")
        sys.exit(1)

    builder_map = {
        "normal":     build_normal_packets,
        "attack":     build_attack_packets,
        "borderline": build_borderline_packets,
    }

    if mode not in builder_map:
        raise ValueError(f"Unknown mode '{mode}'. Choose: normal, attack, borderline")

    logger.info(f"Generating {count} {mode} flows ...")
    pkts = builder_map[mode](n_flows=count)

    if output:
        os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
        wrpcap(output, pkts)
        logger.info(f"Saved {len(pkts)} packets → {output}")
        logger.info(f"  View with: wireshark {output}")
        logger.info(f"  Replay with: tcpreplay -i <iface> {output}")

    if interface:
        if os.geteuid() != 0:
            logger.error("Live send requires root (sudo). Exiting.")
            sys.exit(1)
        logger.info(f"Sending {len(pkts)} packets on {interface} ...")
        for i, pkt in enumerate(pkts):
            send(pkt, iface=interface, verbose=False)
            time.sleep(inter_packet_s)
            if (i + 1) % 50 == 0:
                logger.info(f"  Sent {i+1}/{len(pkts)} packets ...")
        logger.info("Done sending.")

    if not output and not interface:
        logger.info(f"Generated {len(pkts)} packets (dry run — no output or interface specified)")
        logger.info("Use --output <path.pcap> or --interface <eth1> to save/send")


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Demo traffic generator for Zero-Trust pipeline"
    )
    parser.add_argument("--mode",   required=True,
                        choices=["normal", "attack", "borderline"],
                        help="Traffic type to generate")
    parser.add_argument("--count",  type=int, default=10,
                        help="Number of flows to generate (default: 10)")
    parser.add_argument("--output", default=None,
                        help="PCAP output file path (e.g. /tmp/demo_normal.pcap)")
    parser.add_argument("--interface", default=None,
                        help="Network interface to send live (e.g. eth1) — requires sudo")
    parser.add_argument("--inter-packet-s", type=float, default=0.001,
                        help="Seconds between live-sent packets (default: 0.001)")
    args = parser.parse_args()

    generate(
        mode=args.mode,
        count=args.count,
        output=args.output,
        interface=args.interface,
        inter_packet_s=args.inter_packet_s,
    )
