"""
feature_extractor.py — CICFlowMeter-Compatible Feature Extractor
=================================================================
Extracts exactly 15 features from a PCAP file using pure DPKT,
replicating the exact formulas used by CICFlowMeter (Java) to generate
the CIC-IDS-2017 dataset. This ensures extracted features match the
training CSV values so the model can make accurate predictions.

CICFlowMeter Formula Reference (from BasicFlow.java, BasicPacketInfo.java):
  - payloadBytes   = ip.len - ip.hl*4 - tcp.off*4   (pure TCP payload)
  - headerBytes    = ip.hl*4 + tcp.off*4             (IP + TCP headers, incl. options)
  - Total Length of Fwd Packets = sum(fwd TCP payloads)
  - Fwd/Bwd Header Length       = sum(headerBytes) per direction
  - Fwd Packet Length Max       = max(fwd TCP payloads)
  - Packet Length Variance      = variance of ALL packet TCP payloads (bidirectional)
  - Init_Win_bytes_forward      = tcp.win of the very first forward packet
  - Init_Win_bytes_backward     = tcp.win of the very first backward packet
  - Flow Duration               = last_ts - first_ts  (microseconds)
  - Flow IAT Min/Max            = min/max of consecutive bidirectional IATs (microseconds)
  - Fwd IAT Min                 = min of consecutive forward-only IATs
  - Bwd IAT Total               = sum of consecutive backward-only IATs
  - Bwd Packets/s               = bwd_count / (flow_duration_us / 1e6)
  - Flow Bytes/s                = (fwd_bytes+bwd_bytes) / (flow_duration_us / 1e6)
  - Active Min                  = min of active-period durations; 0 if no idle gap > 5s found
"""

import logging
import math
import socket

import dpkt

logger = logging.getLogger("FeatureExtractor")
logger.addHandler(logging.NullHandler())

# CICFlowMeter's activity timeout threshold (microseconds)
# A new idle period is detected when gap between packets > 5 seconds
ACTIVITY_TIMEOUT_US = 5_000_000  # 5 seconds in microseconds

# The 15 features expected by the Sentry model, in order.
REQUIRED_FEATURES = [
    'Packet Length Variance',
    'Fwd Packet Length Max',
    'Fwd Header Length',
    'Init_Win_bytes_forward',
    'Bwd Header Length',
    'Total Length of Fwd Packets',
    'Init_Win_bytes_backward',
    'Bwd Packets/s',
    'Flow IAT Min',
    'Fwd IAT Min',
    'Flow Bytes/s',
    'Active Min',
    'Bwd IAT Total',
    'Flow IAT Max',
    'Flow Duration',
]


def _variance(values):
    """Population variance matching Apache Commons Math SummaryStatistics.getVariance()."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return sum((v - mean) ** 2 for v in values) / n  # population variance (n, not n-1)


def _compute_active_min(all_timestamps_us):
    """
    Replicate CICFlowMeter's updateActiveIdleTime / endActiveIdleTime logic.

    An idle gap is detected when the time between consecutive packets exceeds
    ACTIVITY_TIMEOUT_US (5 seconds). Each contiguous run of packets with
    gaps <= threshold is one 'active period'. Active Min is the minimum
    duration of any active period.

    Returns 0 if there are no idle gaps (flow never went idle), matching
    CICFlowMeter's behaviour when flowActive.getN() == 0.
    """
    if len(all_timestamps_us) < 2:
        return 0.0

    active_periods = []
    start_active = all_timestamps_us[0]
    end_active   = all_timestamps_us[0]

    for i in range(1, len(all_timestamps_us)):
        gap = all_timestamps_us[i] - all_timestamps_us[i - 1]
        if gap > ACTIVITY_TIMEOUT_US:
            # End of an active period
            duration = end_active - start_active
            if duration > 0:
                active_periods.append(duration)
            # Start fresh active period
            start_active = all_timestamps_us[i]
            end_active   = all_timestamps_us[i]
        else:
            end_active = all_timestamps_us[i]

    # Finalise the last active period
    duration = end_active - start_active
    if duration > 0:
        active_periods.append(duration)

    if not active_periods:
        return 0.0
    return min(active_periods)


def extract_features(pcap_path):
    """
    Extract 15 CICFlowMeter-compatible features from a PCAP file.

    Uses a single pass through all TCP packets with DPKT, replicating
    CICFlowMeter's exact calculation methodology from the Java source.

    Args:
        pcap_path (str): Absolute path to the PCAP file.

    Returns:
        dict with keys:
            "valid"           (bool)   – True if extraction succeeded.
            "features"        (dict)   – Feature name → value.
            "ordered_features"(list)   – 15 values in model-required order.
            "flow_id"         (str)    – "src_ip:src_port->dst_ip:dst_port".
            "error"           (str)    – Present only when valid=False.
    """
    try:
        # ------------------------------------------------------------------ #
        # Pass 1: collect per-packet data                                     #
        # ------------------------------------------------------------------ #
        fwd_src_ip   = None   # IP of the forward direction (first packet)
        fwd_src_port = None
        fwd_dst_ip   = None
        fwd_dst_port = None

        # Timestamps (microseconds)
        all_timestamps_us = []

        # Per-direction accumulation
        fwd_payloads    = []   # TCP payload bytes per fwd packet
        bwd_payloads    = []   # TCP payload bytes per bwd packet
        fwd_header_sum  = 0    # Sum of header bytes (IP+TCP) fwd
        bwd_header_sum  = 0    # Sum of header bytes (IP+TCP) bwd
        fwd_timestamps  = []   # Timestamps of fwd packets (us)
        bwd_timestamps  = []   # Timestamps of bwd packets (us)

        init_win_fwd    = 0    # TCP window of first fwd packet
        init_win_bwd    = 0    # TCP window of first bwd packet
        got_win_fwd     = False
        got_win_bwd     = False

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

                src_ip  = socket.inet_ntoa(ip.src)
                dst_ip  = socket.inet_ntoa(ip.dst)
                src_port = tcp.sport
                dst_port = tcp.dport

                # dpkt gives timestamp as a float in seconds; convert to microseconds
                ts_us = int(raw_ts * 1_000_000)

                # CICFlowMeter formula:
                #   ip_header_len   = ip.hl * 4
                #   tcp_header_len  = tcp.off * 4   (data offset = full TCP header incl. options)
                #   header_bytes    = ip_header_len + tcp_header_len
                #   payload_bytes   = ip.len - ip_header_len - tcp_header_len
                ip_hdr_len  = ip.hl * 4
                tcp_hdr_len = tcp.off * 4
                header_bytes  = ip_hdr_len + tcp_hdr_len
                payload_bytes = max(0, ip.len - ip_hdr_len - tcp_hdr_len)

                # Establish flow direction from the very first packet
                if fwd_src_ip is None:
                    fwd_src_ip   = src_ip
                    fwd_src_port = src_port
                    fwd_dst_ip   = dst_ip
                    fwd_dst_port = dst_port

                all_timestamps_us.append(ts_us)

                is_forward = (src_ip == fwd_src_ip)

                if is_forward:
                    fwd_payloads.append(payload_bytes)
                    fwd_header_sum += header_bytes
                    fwd_timestamps.append(ts_us)

                    if not got_win_fwd:
                        init_win_fwd = tcp.win
                        got_win_fwd  = True
                else:
                    bwd_payloads.append(payload_bytes)
                    bwd_header_sum += header_bytes
                    bwd_timestamps.append(ts_us)

                    if not got_win_bwd:
                        init_win_bwd = tcp.win
                        got_win_bwd  = True

        # ------------------------------------------------------------------ #
        # Require at least one packet                                         #
        # ------------------------------------------------------------------ #
        if not all_timestamps_us:
            logger.warning(f"No TCP packets found in {pcap_path}")
            return {"valid": False, "error": "No TCP packets found", "features": {}}

        # ------------------------------------------------------------------ #
        # Pass 2: compute all 15 features from accumulated data               #
        # ------------------------------------------------------------------ #

        # --- Timing ---
        flow_duration_us = all_timestamps_us[-1] - all_timestamps_us[0]
        duration_sec = flow_duration_us / 1_000_000.0

        # Inter-Arrival Times (microseconds), matching CICFlowMeter
        # flowIAT: diff between successive packets in the bidirectional stream
        flow_iats = [
            all_timestamps_us[i] - all_timestamps_us[i - 1]
            for i in range(1, len(all_timestamps_us))
        ]
        # forwardIAT: diff between successive forward packets only
        fwd_iats = [
            fwd_timestamps[i] - fwd_timestamps[i - 1]
            for i in range(1, len(fwd_timestamps))
        ]
        # backwardIAT: diff between successive backward packets only
        bwd_iats = [
            bwd_timestamps[i] - bwd_timestamps[i - 1]
            for i in range(1, len(bwd_timestamps))
        ]

        # --- Packet length stats (TCP payload, bidirectional) ---
        all_payloads = fwd_payloads + bwd_payloads

        pkt_length_variance   = _variance(all_payloads)
        fwd_pkt_length_max    = max(fwd_payloads) if fwd_payloads else 0
        total_len_fwd_packets = sum(fwd_payloads)

        # --- Rates ---
        bwd_count = len(bwd_payloads)
        if duration_sec > 0:
            bwd_pkts_per_sec = bwd_count / duration_sec
            flow_bytes_per_sec = sum(all_payloads) / duration_sec
        else:
            bwd_pkts_per_sec   = 0.0
            flow_bytes_per_sec = 0.0

        # --- IAT summary stats ---
        flow_iat_min = min(flow_iats) if flow_iats else 0
        flow_iat_max = max(flow_iats) if flow_iats else 0
        fwd_iat_min  = min(fwd_iats)  if fwd_iats  else 0
        bwd_iat_total = sum(bwd_iats) if bwd_iats  else 0

        # --- Active Min (CICFlowMeter active/idle period logic) ---
        active_min = _compute_active_min(all_timestamps_us)

        # ------------------------------------------------------------------ #
        # Build feature dict                                                  #
        # ------------------------------------------------------------------ #
        features = {
            'Packet Length Variance':       pkt_length_variance,
            'Fwd Packet Length Max':         fwd_pkt_length_max,
            'Fwd Header Length':             fwd_header_sum,
            'Init_Win_bytes_forward':        init_win_fwd,
            'Bwd Header Length':             bwd_header_sum,
            'Total Length of Fwd Packets':   total_len_fwd_packets,
            'Init_Win_bytes_backward':       init_win_bwd,
            'Bwd Packets/s':                 bwd_pkts_per_sec,
            'Flow IAT Min':                  flow_iat_min,
            'Fwd IAT Min':                   fwd_iat_min,
            'Flow Bytes/s':                  flow_bytes_per_sec,
            'Active Min':                    active_min,
            'Bwd IAT Total':                 bwd_iat_total,
            'Flow IAT Max':                  flow_iat_max,
            'Flow Duration':                 flow_duration_us,
        }

        flow_id = (
            f"{fwd_src_ip}:{fwd_src_port}->{fwd_dst_ip}:{fwd_dst_port}"
            if fwd_src_ip else "unknown"
        )

        return {
            "valid":            True,
            "features":         features,
            "ordered_features": [features[k] for k in REQUIRED_FEATURES],
            "flow_id":          flow_id,
        }

    except Exception as e:
        logger.error(f"Extraction Error for {pcap_path}: {e}")
        return {"valid": False, "error": str(e), "features": {}}



# The 28 features for the extended model (original 15 + 13 new)
EXTENDED_FEATURES = [
    # --- Original 15 ---
    'Packet Length Variance',
    'Fwd Packet Length Max',
    'Fwd Header Length',
    'Init_Win_bytes_forward',
    'Bwd Header Length',
    'Total Length of Fwd Packets',
    'Init_Win_bytes_backward',
    'Bwd Packets/s',
    'Flow IAT Min',
    'Fwd IAT Min',
    'Flow Bytes/s',
    'Active Min',
    'Bwd IAT Total',
    'Flow IAT Max',
    'Flow Duration',
    # --- New 13 ---
    'Total Fwd Packets',
    'Total Bwd Packets',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Mean',
    'Fwd Packet Length Std',
    'Bwd Packet Length Max',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Fwd IAT Total',
    'Fwd Packets/s',
    'Down/Up Ratio',
    'SYN Flag Count',
    'RST Flag Count',
]


def _std(values):
    """Population standard deviation."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return math.sqrt(sum((v - mean) ** 2 for v in values) / n)


def extract_features_extended(pcap_path):
    """
    Extract all 28 features from a PCAP file.

    Returns all original 15 CICFlowMeter-compatible features PLUS 13 new
    research-backed features (packet counts, per-direction stats, IAT statistics,
    TCP flag counts, Down/Up ratio). All features observable from IP/TCP headers
    — no payload decryption required.

    Args:
        pcap_path (str): Absolute path to the PCAP file.

    Returns:
        dict with keys:
            "valid"            (bool)  – True if extraction succeeded.
            "features"         (dict)  – Feature name → value (28 entries).
            "ordered_features" (list)  – 28 values in EXTENDED_FEATURES order.
            "flow_id"          (str)   – "src_ip:src_port->dst_ip:dst_port".
            "error"            (str)   – Present only when valid=False.
    """
    try:
        # ------------------------------------------------------------------ #
        # Pass 1: collect per-packet data                                     #
        # ------------------------------------------------------------------ #
        fwd_src_ip   = None
        fwd_src_port = None
        fwd_dst_ip   = None
        fwd_dst_port = None

        all_timestamps_us = []
        fwd_payloads   = []
        bwd_payloads   = []
        fwd_header_sum = 0
        bwd_header_sum = 0
        fwd_timestamps = []
        bwd_timestamps = []

        init_win_fwd = 0
        init_win_bwd = 0
        got_win_fwd  = False
        got_win_bwd  = False

        syn_count = 0
        rst_count = 0

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

                src_ip   = socket.inet_ntoa(ip.src)
                dst_ip   = socket.inet_ntoa(ip.dst)
                src_port = tcp.sport
                dst_port = tcp.dport
                ts_us    = int(raw_ts * 1_000_000)

                ip_hdr_len    = ip.hl * 4
                tcp_hdr_len   = tcp.off * 4
                header_bytes  = ip_hdr_len + tcp_hdr_len
                payload_bytes = max(0, ip.len - ip_hdr_len - tcp_hdr_len)

                # TCP flags (dpkt stores as integer bitmask)
                flags = tcp.flags
                if flags & dpkt.tcp.TH_SYN:
                    syn_count += 1
                if flags & dpkt.tcp.TH_RST:
                    rst_count += 1

                if fwd_src_ip is None:
                    fwd_src_ip   = src_ip
                    fwd_src_port = src_port
                    fwd_dst_ip   = dst_ip
                    fwd_dst_port = dst_port

                all_timestamps_us.append(ts_us)
                is_forward = (src_ip == fwd_src_ip)

                if is_forward:
                    fwd_payloads.append(payload_bytes)
                    fwd_header_sum += header_bytes
                    fwd_timestamps.append(ts_us)
                    if not got_win_fwd:
                        init_win_fwd = tcp.win
                        got_win_fwd  = True
                else:
                    bwd_payloads.append(payload_bytes)
                    bwd_header_sum += header_bytes
                    bwd_timestamps.append(ts_us)
                    if not got_win_bwd:
                        init_win_bwd = tcp.win
                        got_win_bwd  = True

        if not all_timestamps_us:
            return {"valid": False, "error": "No TCP packets found", "features": {}}

        # ------------------------------------------------------------------ #
        # Pass 2: compute all 28 features                                     #
        # ------------------------------------------------------------------ #

        # Timing
        flow_duration_us = all_timestamps_us[-1] - all_timestamps_us[0]
        duration_sec     = flow_duration_us / 1_000_000.0

        # IATs
        flow_iats = [all_timestamps_us[i] - all_timestamps_us[i-1]
                     for i in range(1, len(all_timestamps_us))]
        fwd_iats  = [fwd_timestamps[i] - fwd_timestamps[i-1]
                     for i in range(1, len(fwd_timestamps))]
        bwd_iats  = [bwd_timestamps[i] - bwd_timestamps[i-1]
                     for i in range(1, len(bwd_timestamps))]

        # Payload stats
        all_payloads = fwd_payloads + bwd_payloads
        fwd_sum = sum(fwd_payloads)
        bwd_sum = sum(bwd_payloads)
        fwd_cnt = len(fwd_payloads)
        bwd_cnt = len(bwd_payloads)

        # Rates
        if duration_sec > 0:
            bwd_pkts_per_sec   = bwd_cnt / duration_sec
            fwd_pkts_per_sec   = fwd_cnt / duration_sec
            flow_bytes_per_sec = sum(all_payloads) / duration_sec
        else:
            bwd_pkts_per_sec   = 0.0
            fwd_pkts_per_sec   = 0.0
            flow_bytes_per_sec = 0.0

        # Down/Up ratio (bwd bytes / fwd bytes)
        down_up_ratio = (bwd_sum / fwd_sum) if fwd_sum > 0 else 0.0

        features = {
            # ---- Original 15 ----
            'Packet Length Variance':      _variance(all_payloads),
            'Fwd Packet Length Max':       max(fwd_payloads) if fwd_payloads else 0,
            'Fwd Header Length':           fwd_header_sum,
            'Init_Win_bytes_forward':      init_win_fwd,
            'Bwd Header Length':           bwd_header_sum,
            'Total Length of Fwd Packets': fwd_sum,
            'Init_Win_bytes_backward':     init_win_bwd,
            'Bwd Packets/s':               bwd_pkts_per_sec,
            'Flow IAT Min':                min(flow_iats) if flow_iats else 0,
            'Fwd IAT Min':                 min(fwd_iats)  if fwd_iats  else 0,
            'Flow Bytes/s':                flow_bytes_per_sec,
            'Active Min':                  _compute_active_min(all_timestamps_us),
            'Bwd IAT Total':               sum(bwd_iats)  if bwd_iats  else 0,
            'Flow IAT Max':                max(flow_iats) if flow_iats else 0,
            'Flow Duration':               flow_duration_us,
            # ---- New 13 ----
            'Total Fwd Packets':           fwd_cnt,
            'Total Bwd Packets':           bwd_cnt,
            'Fwd Packet Length Mean':      (fwd_sum / fwd_cnt) if fwd_cnt > 0 else 0.0,
            'Bwd Packet Length Mean':      (bwd_sum / bwd_cnt) if bwd_cnt > 0 else 0.0,
            'Fwd Packet Length Std':       _std(fwd_payloads),
            'Bwd Packet Length Max':       max(bwd_payloads) if bwd_payloads else 0,
            'Flow IAT Mean':               (sum(flow_iats) / len(flow_iats)) if flow_iats else 0.0,
            'Flow IAT Std':                _std(flow_iats),
            'Fwd IAT Total':               sum(fwd_iats) if fwd_iats else 0,
            'Fwd Packets/s':               fwd_pkts_per_sec,
            'Down/Up Ratio':               down_up_ratio,
            'SYN Flag Count':              syn_count,
            'RST Flag Count':              rst_count,
        }

        flow_id = (
            f"{fwd_src_ip}:{fwd_src_port}->{fwd_dst_ip}:{fwd_dst_port}"
            if fwd_src_ip else "unknown"
        )

        return {
            "valid":            True,
            "features":         features,
            "ordered_features": [features[k] for k in EXTENDED_FEATURES],
            "flow_id":          flow_id,
        }

    except Exception as e:
        logger.error(f"Extended extraction error for {pcap_path}: {e}")
        return {"valid": False, "error": str(e), "features": {}}


if __name__ == "__main__":
    import sys
    import json
    if len(sys.argv) > 1:
        result = extract_features(sys.argv[1])
        print(json.dumps(result, indent=2))
