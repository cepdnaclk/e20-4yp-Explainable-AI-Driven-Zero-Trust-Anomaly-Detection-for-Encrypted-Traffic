"""
ddl_pcap_extractor.py — 40-Feature PCAP Extractor for DDL + IF
===============================================================
Extracts all 40 features required by the DDL and Isolation Forest models
directly from raw PCAP files using dpkt (IP/TCP headers only).

This is the Stage 2 extractor — runs only on flows flagged by BCC.
BCC uses Sandaru's 28-feature extractor (Stage 1).

Design:
  - BCC (28 features): Always extracted → fast gateway decision
  - DDL+IF (40 features): Extracted separately when BCC flags a flow
  - In SDN: packet data is already buffered at the controller,
    so re-reading for deeper extraction has minimal overhead.

All 40 features are computed from IP/TCP headers — no payload decryption.
"""

import math
import socket
import logging
import dpkt

logger = logging.getLogger("DDLPcapExtractor")

# Activity timeout for Active Min computation (5 seconds in microseconds)
ACTIVITY_TIMEOUT_US = 5_000_000

# The 40 DDL feature names in model order
DDL_40_FEATURES = [
    "fwd_pkt_len_mean", "fwd_pkt_len_std", "fwd_pkt_len_min", "fwd_pkt_len_max",
    "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max",
    "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max",
    "flow_bytes_per_s", "flow_pkts_per_s",
    "fwd_bytes_per_s", "bwd_bytes_per_s",
    "pkt_len_variance", "pkt_len_mean",
    "syn_flag_count", "ack_flag_count", "fin_flag_count",
    "rst_flag_count", "psh_flag_count", "urg_flag_count",
    "total_fwd_bytes", "total_bwd_bytes",
    "flow_duration",
    "init_win_fwd", "init_win_bwd",
    "down_up_ratio",
    "bwd_pkt_len_min", "bwd_pkt_len_max",
    "flow_iat_mean", "flow_iat_std",
    "fwd_iat_total",
    "bwd_iat_min",
    "fwd_pkts_per_s", "bwd_pkts_per_s",
    "fwd_header_len",
    "active_min",
]


def _variance(values):
    """Population variance."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return sum((v - mean) ** 2 for v in values) / n


def _std(values):
    """Population standard deviation."""
    return math.sqrt(_variance(values))


def _mean(values):
    """Mean or 0 if empty."""
    return sum(values) / len(values) if values else 0.0


def _compute_active_min(timestamps_us):
    """CICFlowMeter active/idle period logic. Returns min active period duration."""
    if len(timestamps_us) < 2:
        return 0.0
    active_periods = []
    start = timestamps_us[0]
    end = timestamps_us[0]
    for i in range(1, len(timestamps_us)):
        gap = timestamps_us[i] - timestamps_us[i - 1]
        if gap > ACTIVITY_TIMEOUT_US:
            duration = end - start
            if duration > 0:
                active_periods.append(duration)
            start = timestamps_us[i]
            end = timestamps_us[i]
        else:
            end = timestamps_us[i]
    duration = end - start
    if duration > 0:
        active_periods.append(duration)
    return min(active_periods) if active_periods else 0.0


def extract_ddl_features(pcap_path):
    """
    Extract all 40 DDL features from a PCAP file.

    Uses a single pass through TCP packets with dpkt. All features computed
    from IP/TCP headers and timestamps — no payload decryption needed.

    Args:
        pcap_path: Path to the PCAP file.

    Returns:
        dict with keys:
            "valid" (bool), "features" (dict of 40 values),
            "ordered" (list of 40 values in DDL_40_FEATURES order),
            "flow_id" (str), "error" (str, only if invalid)
    """
    try:
        fwd_src_ip = None
        fwd_src_port = fwd_dst_port = None

        all_ts = []
        fwd_payloads = []
        bwd_payloads = []
        fwd_hdr_sum = 0
        bwd_hdr_sum = 0
        fwd_ts = []
        bwd_ts = []

        init_win_fwd = 0
        init_win_bwd = 0
        got_win_fwd = False
        got_win_bwd = False

        # TCP flag counters
        syn_count = ack_count = fin_count = rst_count = psh_count = urg_count = 0

        with open(pcap_path, 'rb') as f:
            reader = dpkt.pcap.Reader(f)
            for raw_ts, buf in reader:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except Exception:
                    continue
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if ip.p != dpkt.ip.IP_PROTO_TCP:
                    continue
                tcp = ip.data

                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                ts_us = int(raw_ts * 1_000_000)

                ip_hdr = ip.hl * 4
                tcp_hdr = tcp.off * 4
                hdr_bytes = ip_hdr + tcp_hdr
                payload = max(0, ip.len - ip_hdr - tcp_hdr)

                # TCP flags
                flags = tcp.flags
                if flags & dpkt.tcp.TH_SYN: syn_count += 1
                if flags & dpkt.tcp.TH_ACK: ack_count += 1
                if flags & dpkt.tcp.TH_FIN: fin_count += 1
                if flags & dpkt.tcp.TH_RST: rst_count += 1
                if flags & dpkt.tcp.TH_PUSH: psh_count += 1
                if flags & dpkt.tcp.TH_URG: urg_count += 1

                if fwd_src_ip is None:
                    fwd_src_ip = src_ip
                    fwd_src_port = tcp.sport
                    fwd_dst_ip = dst_ip
                    fwd_dst_port = tcp.dport

                all_ts.append(ts_us)
                is_fwd = (src_ip == fwd_src_ip)

                if is_fwd:
                    fwd_payloads.append(payload)
                    fwd_hdr_sum += hdr_bytes
                    fwd_ts.append(ts_us)
                    if not got_win_fwd:
                        init_win_fwd = tcp.win
                        got_win_fwd = True
                else:
                    bwd_payloads.append(payload)
                    bwd_hdr_sum += hdr_bytes
                    bwd_ts.append(ts_us)
                    if not got_win_bwd:
                        init_win_bwd = tcp.win
                        got_win_bwd = True

        if not all_ts:
            return {"valid": False, "error": "No TCP packets", "features": {}}

        # ── Compute all 40 features ──────────────────────────────────────

        # Timing
        flow_dur_us = all_ts[-1] - all_ts[0]
        dur_sec = flow_dur_us / 1_000_000.0

        # Inter-Arrival Times
        flow_iats = [all_ts[i] - all_ts[i-1] for i in range(1, len(all_ts))]
        fwd_iats = [fwd_ts[i] - fwd_ts[i-1] for i in range(1, len(fwd_ts))]
        bwd_iats = [bwd_ts[i] - bwd_ts[i-1] for i in range(1, len(bwd_ts))]

        # Payload sums
        all_payloads = fwd_payloads + bwd_payloads
        fwd_sum = sum(fwd_payloads)
        bwd_sum = sum(bwd_payloads)
        fwd_cnt = len(fwd_payloads)
        bwd_cnt = len(bwd_payloads)
        total_pkts = fwd_cnt + bwd_cnt

        # Rates
        if dur_sec > 0:
            flow_bytes_s = (fwd_sum + bwd_sum) / dur_sec
            flow_pkts_s = total_pkts / dur_sec
            fwd_bytes_s = fwd_sum / dur_sec
            bwd_bytes_s = bwd_sum / dur_sec
            fwd_pkts_s = fwd_cnt / dur_sec
            bwd_pkts_s = bwd_cnt / dur_sec
        else:
            flow_bytes_s = flow_pkts_s = fwd_bytes_s = bwd_bytes_s = 0.0
            fwd_pkts_s = bwd_pkts_s = 0.0

        features = {
            # Forward packet length stats
            "fwd_pkt_len_mean":  _mean(fwd_payloads),
            "fwd_pkt_len_std":   _std(fwd_payloads),
            "fwd_pkt_len_min":   min(fwd_payloads) if fwd_payloads else 0,
            "fwd_pkt_len_max":   max(fwd_payloads) if fwd_payloads else 0,

            # Backward packet length stats
            "bwd_pkt_len_mean":  _mean(bwd_payloads),
            "bwd_pkt_len_std":   _std(bwd_payloads),
            "bwd_pkt_len_min":   min(bwd_payloads) if bwd_payloads else 0,
            "bwd_pkt_len_max":   max(bwd_payloads) if bwd_payloads else 0,

            # Forward IAT stats
            "fwd_iat_mean":      _mean(fwd_iats),
            "fwd_iat_std":       _std(fwd_iats),
            "fwd_iat_max":       max(fwd_iats) if fwd_iats else 0,
            "fwd_iat_total":     sum(fwd_iats) if fwd_iats else 0,

            # Backward IAT stats
            "bwd_iat_mean":      _mean(bwd_iats),
            "bwd_iat_std":       _std(bwd_iats),
            "bwd_iat_max":       max(bwd_iats) if bwd_iats else 0,
            "bwd_iat_min":       min(bwd_iats) if bwd_iats else 0,

            # Flow-level stats
            "flow_bytes_per_s":  flow_bytes_s,
            "flow_pkts_per_s":   flow_pkts_s,
            "fwd_bytes_per_s":   fwd_bytes_s,
            "bwd_bytes_per_s":   bwd_bytes_s,
            "pkt_len_variance":  _variance(all_payloads),
            "pkt_len_mean":      _mean(all_payloads),
            "flow_iat_mean":     _mean(flow_iats),
            "flow_iat_std":      _std(flow_iats),
            "flow_duration":     flow_dur_us,

            # TCP flags
            "syn_flag_count":    syn_count,
            "ack_flag_count":    ack_count,
            "fin_flag_count":    fin_count,
            "rst_flag_count":    rst_count,
            "psh_flag_count":    psh_count,
            "urg_flag_count":    urg_count,

            # Volume
            "total_fwd_bytes":   fwd_sum,
            "total_bwd_bytes":   bwd_sum,

            # TCP window
            "init_win_fwd":      init_win_fwd,
            "init_win_bwd":      init_win_bwd,

            # Ratios
            "down_up_ratio":     (bwd_sum / fwd_sum) if fwd_sum > 0 else 0.0,

            # Rates
            "fwd_pkts_per_s":    fwd_pkts_s,
            "bwd_pkts_per_s":    bwd_pkts_s,

            # Header
            "fwd_header_len":    fwd_hdr_sum,

            # Active period
            "active_min":        _compute_active_min(all_ts),
        }

        flow_id = f"{fwd_src_ip}:{fwd_src_port}->{fwd_dst_ip}:{fwd_dst_port}" if fwd_src_ip else "unknown"

        return {
            "valid": True,
            "features": features,
            "ordered": [features[k] for k in DDL_40_FEATURES],
            "flow_id": flow_id,
        }

    except Exception as e:
        logger.error(f"DDL extraction error for {pcap_path}: {e}")
        return {"valid": False, "error": str(e), "features": {}}


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) > 1:
        result = extract_ddl_features(sys.argv[1])
        print(json.dumps({k: v for k, v in result.items() if k != "ordered"}, indent=2))
