# 🔬 28 Feature Reference

**Document:** Feature Set Reference  
**Extractor:** `feature_extractor.py` → `extract_features_extended()`  
**Date:** 2026-03-05

---

## Overview

All 28 features are extracted from **IP and TCP headers only** — no payload inspection,
no decryption required. This makes the approach valid for encrypted traffic (TLS, HTTPS, etc).

Features are derived from:
- `ip.hl` — IP header length (32-bit words)
- `ip.len` — Total IP datagram length
- `tcp.off` — TCP data offset (32-bit words)
- `tcp.win` — TCP receive window size
- `tcp.flags` — TCP flag bitmask (SYN, RST, etc.)
- PCAP `timestamp` — Per-packet capture time (microseconds)

---

## Original 15 Features (CICFlowMeter-compatible)

| # | Feature | Packet Field | Unit | Description |
|---|---------|-------------|------|-------------|
| 1 | `Packet Length Variance` | `ip.len`, `ip.hl`, `tcp.off` | bytes² | Population variance of all TCP payloads (fwd+bwd) |
| 2 | `Fwd Packet Length Max` | same | bytes | Largest TCP payload in forward direction |
| 3 | `Fwd Header Length` | `ip.hl`, `tcp.off` | bytes | Sum of IP+TCP header bytes across all forward packets |
| 4 | `Init_Win_bytes_forward` | `tcp.win` | bytes | TCP window of the very first forward packet (SYN) |
| 5 | `Bwd Header Length` | `ip.hl`, `tcp.off` | bytes | Sum of IP+TCP header bytes across all backward packets |
| 6 | `Total Length of Fwd Packets` | `ip.len`, `ip.hl`, `tcp.off` | bytes | Sum of all forward TCP payloads |
| 7 | `Init_Win_bytes_backward` | `tcp.win` | bytes | TCP window of the very first backward packet |
| 8 | `Bwd Packets/s` | timestamp, count | pkts/s | Backward packet rate: bwd_count / duration_sec |
| 9 | `Flow IAT Min` | timestamp | µs | Minimum inter-arrival time between any consecutive packets (bidirectional) |
| 10 | `Fwd IAT Min` | timestamp | µs | Minimum inter-arrival time between consecutive forward packets only |
| 11 | `Flow Bytes/s` | `ip.len`, timestamp | bytes/s | Total payload throughput: (fwd+bwd bytes) / duration_sec |
| 12 | `Active Min` | timestamp | µs | Minimum active-period duration (gaps > 5s split periods); 0 if flow never idle |
| 13 | `Bwd IAT Total` | timestamp | µs | Sum of all backward inter-arrival times |
| 14 | `Flow IAT Max` | timestamp | µs | Maximum inter-arrival time in the bidirectional flow |
| 15 | `Flow Duration` | timestamp | µs | Last packet timestamp − first packet timestamp |

---

## New 13 Features (Research-backed additions)

Sources: MDPI 2022, ArXiv 2023 encrypted traffic classification, IEEE 2023 anomaly detection

| # | Feature | Packet Field | Unit | Description |
|---|---------|-------------|------|-------------|
| 16 | `Total Fwd Packets` | count | packets | Number of forward packets |
| 17 | `Total Bwd Packets` | count | packets | Number of backward packets |
| 18 | `Fwd Packet Length Mean` | `ip.len`, headers | bytes | Mean TCP payload size in forward direction |
| 19 | `Bwd Packet Length Mean` | `ip.len`, headers | bytes | Mean TCP payload size in backward direction |
| 20 | `Fwd Packet Length Std` | `ip.len`, headers | bytes | Population std of forward TCP payloads |
| 21 | `Bwd Packet Length Max` | `ip.len`, headers | bytes | Largest TCP payload in backward direction |
| 22 | `Flow IAT Mean` | timestamp | µs | Mean inter-arrival time across bidirectional flow |
| 23 | `Flow IAT Std` | timestamp | µs | Std of bidirectional inter-arrival times (bots → very low) |
| 24 | `Fwd IAT Total` | timestamp | µs | Sum of all forward inter-arrival times |
| 25 | `Fwd Packets/s` | timestamp, count | pkts/s | Forward packet rate: fwd_count / duration_sec |
| 26 | `Down/Up Ratio` | `ip.len`, headers | ratio | bwd_payload_bytes / fwd_payload_bytes |
| 27 | `SYN Flag Count` | `tcp.flags` | count | Number of packets with SYN flag set in the flow |
| 28 | `RST Flag Count` | `tcp.flags` | count | Number of packets with RST flag set in the flow |

---

## Why These 28?

| Category | Features | Attack signal |
|----------|----------|--------------|
| Header overhead | Fwd/Bwd Header Length | Unusual options → crafted packets |
| Payload volume | Total Length Fwd, Mean, Max, Std, Variance | Bulk exfil, floods |
| Timing | Duration, IAT Min/Max/Mean/Std/Total, Active Min | Bot regularity, DDoS timing |
| Rates | Fwd/Bwd Packets/s, Flow Bytes/s | Flood magnitude |
| Handshake | Init_Win_forward/backward | OS fingerprint, SYN floods |
| Asymmetry | Down/Up Ratio, Total Fwd/Bwd Packets | Amplification attacks |
| TCP Flags | SYN Count, RST Count | SYN floods, port scans |

All features are computed without decrypting payload — safe for TLS/HTTPS/encrypted SDN traffic.
