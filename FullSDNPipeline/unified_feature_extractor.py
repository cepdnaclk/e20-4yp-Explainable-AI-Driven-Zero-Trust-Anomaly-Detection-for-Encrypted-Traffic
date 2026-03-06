"""
unified_feature_extractor.py — Shared Feature Extractor for Both Stages
========================================================================
Zero-Trust XAI Anomaly Detection | University of Peradeniya

Extracts a SUPERSET of features ONCE from raw PCAP data using DPKT.
Both the BCC (28 features) and DDL (40 features) models then take
their required slices from this shared extraction — avoiding double work.

Feature overlap analysis:
  - BCC v2 uses 28 features (15 original + 13 new)
  - DDL uses 40 features (30 original + 10 new)
  - ~22 features overlap; the union = 46 unique features
  - This extractor computes all 46, then provides views for each model.
"""

import logging
import math
import socket
import numpy as np
from typing import Dict, Any, Optional, Tuple

try:
    import dpkt
except ImportError:
    dpkt = None

logger = logging.getLogger("UnifiedExtractor")

# ── Constants ──────────────────────────────────────────────────────────────────
ACTIVITY_TIMEOUT_US = 5_000_000  # 5 seconds (CICFlowMeter standard)

# ── BCC v2 feature order (28) — must match Sandaru's training ────────────────
BCC_V2_FEATURE_NAMES = [
    'Packet Length Variance', 'Fwd Packet Length Max', 'Fwd Header Length',
    'Init_Win_bytes_forward', 'Bwd Header Length',
    'Total Length of Fwd Packets', 'Init_Win_bytes_backward',
    'Bwd Packets/s', 'Flow IAT Min', 'Fwd IAT Min', 'Flow Bytes/s',
    'Active Min', 'Bwd IAT Total', 'Flow IAT Max', 'Flow Duration',
    # New 13:
    'Total Fwd Packets', 'Total Bwd Packets', 'Fwd Packet Length Mean',
    'Bwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Flow IAT Mean', 'Flow IAT Std',
    'Fwd IAT Total', 'Fwd Packets/s', 'Down/Up Ratio',
    'SYN Flag Count', 'RST Flag Count',
]

# ── DDL feature order (40) ────────────────────────────────────────────────────
DDL_FEATURE_NAMES = [
    "fwd_pkt_len_mean", "fwd_pkt_len_std", "fwd_pkt_len_min",
    "fwd_pkt_len_max", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max",
    "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max",
    "flow_bytes_per_s", "flow_pkts_per_s", "fwd_bytes_per_s",
    "bwd_bytes_per_s", "pkt_len_variance", "pkt_len_mean",
    "syn_flag_count", "ack_flag_count", "fin_flag_count",
    "rst_flag_count", "psh_flag_count", "urg_flag_count",
    "total_fwd_bytes", "total_bwd_bytes", "flow_duration",
    "init_win_fwd", "init_win_bwd", "down_up_ratio",
    # New 10:
    "bwd_pkt_len_min", "bwd_pkt_len_max",
    "flow_iat_mean", "flow_iat_std", "fwd_iat_total",
    "bwd_iat_min", "fwd_pkts_per_s", "bwd_pkts_per_s",
    "fwd_header_len", "active_min",
]


def _variance(values):
    """Population variance (n, not n-1)."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return sum((v - mean) ** 2 for v in values) / n


def _std(values):
    """Population standard deviation."""
    return math.sqrt(_variance(values))


def _compute_active_min(all_timestamps_us):
    """CICFlowMeter active/idle period logic — Active Min."""
    if len(all_timestamps_us) < 2:
        return 0.0
    active_periods = []
    start_active = all_timestamps_us[0]
    end_active = all_timestamps_us[0]
    for i in range(1, len(all_timestamps_us)):
        gap = all_timestamps_us[i] - all_timestamps_us[i - 1]
        if gap > ACTIVITY_TIMEOUT_US:
            duration = end_active - start_active
            if duration > 0:
                active_periods.append(duration)
            start_active = all_timestamps_us[i]
            end_active = all_timestamps_us[i]
        else:
            end_active = all_timestamps_us[i]
    duration = end_active - start_active
    if duration > 0:
        active_periods.append(duration)
    return min(active_periods) if active_periods else 0.0


def extract_all_features(pcap_path: str) -> Dict[str, Any]:
    """
    Extract ALL features (superset of BCC-28 + DDL-40) from a PCAP.

    Returns:
        dict:
            "valid"          (bool)   - whether extraction succeeded
            "all_features"   (dict)   - name -> value (full superset)
            "bcc_28"         (list)   - 28 ordered values for BCC v2
            "ddl_40"         (np.ndarray) - 40 values for DDL model
            "flow_id"        (str)   - src:port->dst:port
            "error"          (str)   - only when valid=False
    """
    if dpkt is None:
        return {"valid": False, "error": "dpkt not installed", "all_features": {}}

    try:
        # ── Pass 1: Accumulate per-packet data ────────────────────────────
        fwd_src_ip = fwd_src_port = fwd_dst_ip = fwd_dst_port = None
        all_timestamps_us = []
        fwd_payloads, bwd_payloads = [], []
        fwd_header_sum, bwd_header_sum = 0, 0
        fwd_timestamps, bwd_timestamps = [], []
        init_win_fwd, init_win_bwd = 0, 0
        got_win_fwd, got_win_bwd = False, False
        syn_count = rst_count = ack_count = fin_count = psh_count = urg_count = 0

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
                src_port = tcp.sport
                dst_port = tcp.dport
                ts_us = int(raw_ts * 1_000_000)

                ip_hdr_len = ip.hl * 4
                tcp_hdr_len = tcp.off * 4
                header_bytes = ip_hdr_len + tcp_hdr_len
                payload_bytes = max(0, ip.len - ip_hdr_len - tcp_hdr_len)

                # TCP flags
                flags = tcp.flags
                if flags & dpkt.tcp.TH_SYN: syn_count += 1
                if flags & dpkt.tcp.TH_RST: rst_count += 1
                if flags & dpkt.tcp.TH_ACK: ack_count += 1
                if flags & dpkt.tcp.TH_FIN: fin_count += 1
                if flags & dpkt.tcp.TH_PUSH: psh_count += 1
                if flags & dpkt.tcp.TH_URG: urg_count += 1

                if fwd_src_ip is None:
                    fwd_src_ip, fwd_src_port = src_ip, src_port
                    fwd_dst_ip, fwd_dst_port = dst_ip, dst_port

                all_timestamps_us.append(ts_us)
                is_forward = (src_ip == fwd_src_ip)

                if is_forward:
                    fwd_payloads.append(payload_bytes)
                    fwd_header_sum += header_bytes
                    fwd_timestamps.append(ts_us)
                    if not got_win_fwd:
                        init_win_fwd = tcp.win
                        got_win_fwd = True
                else:
                    bwd_payloads.append(payload_bytes)
                    bwd_header_sum += header_bytes
                    bwd_timestamps.append(ts_us)
                    if not got_win_bwd:
                        init_win_bwd = tcp.win
                        got_win_bwd = True

        if not all_timestamps_us:
            return {"valid": False, "error": "No TCP packets found",
                    "all_features": {}}

        # ── Pass 2: Compute ALL features ──────────────────────────────────
        flow_duration_us = all_timestamps_us[-1] - all_timestamps_us[0]
        duration_sec = flow_duration_us / 1_000_000.0
        all_payloads = fwd_payloads + bwd_payloads
        fwd_sum = sum(fwd_payloads)
        bwd_sum = sum(bwd_payloads)
        fwd_cnt = len(fwd_payloads)
        bwd_cnt = len(bwd_payloads)
        total_pkts = fwd_cnt + bwd_cnt

        # IATs
        flow_iats = [all_timestamps_us[i] - all_timestamps_us[i - 1]
                     for i in range(1, len(all_timestamps_us))]
        fwd_iats = [fwd_timestamps[i] - fwd_timestamps[i - 1]
                    for i in range(1, len(fwd_timestamps))]
        bwd_iats = [bwd_timestamps[i] - bwd_timestamps[i - 1]
                    for i in range(1, len(bwd_timestamps))]

        # Rates
        if duration_sec > 0:
            bwd_pkts_per_sec = bwd_cnt / duration_sec
            fwd_pkts_per_sec = fwd_cnt / duration_sec
            flow_bytes_per_sec = sum(all_payloads) / duration_sec
            flow_pkts_per_sec = total_pkts / duration_sec
            fwd_bytes_per_sec = fwd_sum / duration_sec
            bwd_bytes_per_sec = bwd_sum / duration_sec
        else:
            bwd_pkts_per_sec = fwd_pkts_per_sec = 0.0
            flow_bytes_per_sec = flow_pkts_per_sec = 0.0
            fwd_bytes_per_sec = bwd_bytes_per_sec = 0.0

        down_up_ratio = (bwd_sum / fwd_sum) if fwd_sum > 0 else 0.0

        # Build the full superset dict (all features needed by BCC-28 + DDL-40)
        f = {
            # ── Shared features ──
            'Packet Length Variance':       _variance(all_payloads),
            'Fwd Packet Length Max':        max(fwd_payloads) if fwd_payloads else 0,
            'Fwd Header Length':            fwd_header_sum,
            'Init_Win_bytes_forward':       init_win_fwd,
            'Bwd Header Length':            bwd_header_sum,
            'Total Length of Fwd Packets':  fwd_sum,
            'Init_Win_bytes_backward':      init_win_bwd,
            'Bwd Packets/s':               bwd_pkts_per_sec,
            'Flow IAT Min':                 min(flow_iats) if flow_iats else 0,
            'Fwd IAT Min':                  min(fwd_iats) if fwd_iats else 0,
            'Flow Bytes/s':                 flow_bytes_per_sec,
            'Active Min':                   _compute_active_min(all_timestamps_us),
            'Bwd IAT Total':               sum(bwd_iats) if bwd_iats else 0,
            'Flow IAT Max':                 max(flow_iats) if flow_iats else 0,
            'Flow Duration':                flow_duration_us,
            'Total Fwd Packets':            fwd_cnt,
            'Total Bwd Packets':            bwd_cnt,
            'Fwd Packet Length Mean':       (fwd_sum / fwd_cnt) if fwd_cnt > 0 else 0.0,
            'Bwd Packet Length Mean':       (bwd_sum / bwd_cnt) if bwd_cnt > 0 else 0.0,
            'Fwd Packet Length Std':        _std(fwd_payloads),
            'Bwd Packet Length Max':        max(bwd_payloads) if bwd_payloads else 0,
            'Flow IAT Mean':               (sum(flow_iats) / len(flow_iats)) if flow_iats else 0.0,
            'Flow IAT Std':                _std(flow_iats) if flow_iats else 0.0,
            'Fwd IAT Total':               sum(fwd_iats) if fwd_iats else 0,
            'Fwd Packets/s':               fwd_pkts_per_sec,
            'Down/Up Ratio':               down_up_ratio,
            'SYN Flag Count':              syn_count,
            'RST Flag Count':              rst_count,
            # ── DDL-only features ──
            'Fwd Packet Length Min':        min(fwd_payloads) if fwd_payloads else 0,
            'Bwd Packet Length Std':        _std(bwd_payloads),
            'Fwd IAT Mean':                (sum(fwd_iats) / len(fwd_iats)) if fwd_iats else 0.0,
            'Fwd IAT Std':                 _std(fwd_iats) if fwd_iats else 0.0,
            'Fwd IAT Max':                 max(fwd_iats) if fwd_iats else 0,
            'Bwd IAT Mean':                (sum(bwd_iats) / len(bwd_iats)) if bwd_iats else 0.0,
            'Bwd IAT Std':                 _std(bwd_iats) if bwd_iats else 0.0,
            'Bwd IAT Max':                 max(bwd_iats) if bwd_iats else 0,
            'Flow Packets/s':              flow_pkts_per_sec,
            'Fwd Bytes/s':                 fwd_bytes_per_sec,
            'Bwd Bytes/s':                 bwd_bytes_per_sec,
            'Packet Length Mean':          (sum(all_payloads) / len(all_payloads)) if all_payloads else 0.0,
            'ACK Flag Count':              ack_count,
            'FIN Flag Count':              fin_count,
            'PSH Flag Count':              psh_count,
            'URG Flag Count':              urg_count,
            'Total Length of Bwd Packets':  bwd_sum,
            # ── New DDL-40 features ──
            'Bwd Packet Length Min':        min(bwd_payloads) if bwd_payloads else 0,
            'Bwd IAT Min':                 min(bwd_iats) if bwd_iats else 0,
        }

        flow_id = (f"{fwd_src_ip}:{fwd_src_port}->{fwd_dst_ip}:{fwd_dst_port}"
                   if fwd_src_ip else "unknown")

        # ── Build BCC-28 ordered vector ───────────────────────────────────
        bcc_28 = [f.get(name, 0.0) for name in BCC_V2_FEATURE_NAMES]

        # ── Build DDL-40 vector ───────────────────────────────────────────
        ddl_40 = _build_ddl_40(f)

        return {
            "valid": True,
            "all_features": f,
            "bcc_28": bcc_28,
            "ddl_40": ddl_40,
            "flow_id": flow_id,
        }

    except Exception as e:
        logger.error(f"Extraction error for {pcap_path}: {e}")
        return {"valid": False, "error": str(e), "all_features": {}}


def _build_ddl_40(f: dict) -> np.ndarray:
    """Build the 40-element DDL feature vector from the full dict."""
    g = lambda k: float(f.get(k, 0.0) or 0.0)
    vec = np.zeros(40, dtype=np.float64)

    # Packet size
    vec[0]  = g('Fwd Packet Length Mean')
    vec[1]  = g('Fwd Packet Length Std')
    vec[2]  = g('Fwd Packet Length Min')
    vec[3]  = g('Fwd Packet Length Max')
    vec[4]  = g('Bwd Packet Length Mean')
    vec[5]  = g('Bwd Packet Length Std')

    # IAT (microseconds -> seconds for DDL)
    vec[6]  = g('Fwd IAT Mean') / 1e6
    vec[7]  = g('Fwd IAT Std') / 1e6
    vec[8]  = g('Fwd IAT Max') / 1e6
    vec[9]  = g('Bwd IAT Mean') / 1e6
    vec[10] = g('Bwd IAT Std') / 1e6
    vec[11] = g('Bwd IAT Max') / 1e6

    # Rates
    vec[12] = g('Flow Bytes/s')
    vec[13] = g('Flow Packets/s')
    vec[14] = g('Fwd Bytes/s')
    vec[15] = g('Bwd Bytes/s')

    # Packet variance + mean
    vec[16] = g('Packet Length Variance')
    vec[17] = g('Packet Length Mean')

    # Flags
    vec[18] = g('SYN Flag Count')
    vec[19] = g('ACK Flag Count')
    vec[20] = g('FIN Flag Count')
    vec[21] = g('RST Flag Count')
    vec[22] = g('PSH Flag Count')
    vec[23] = g('URG Flag Count')

    # Totals
    vec[24] = g('Total Length of Fwd Packets')
    vec[25] = g('Total Length of Bwd Packets')
    vec[26] = g('Flow Duration') / 1e6

    # TCP window
    vec[27] = g('Init_Win_bytes_forward')
    vec[28] = g('Init_Win_bytes_backward')

    # Ratio
    fwd = vec[24] + 1e-6
    vec[29] = vec[25] / fwd

    # ── New 10 features (30-39) ──
    vec[30] = g('Bwd Packet Length Min')
    vec[31] = g('Bwd Packet Length Max')
    vec[32] = g('Flow IAT Mean') / 1e6
    vec[33] = g('Flow IAT Std') / 1e6
    vec[34] = g('Fwd IAT Total') / 1e6
    vec[35] = g('Bwd IAT Min') / 1e6
    vec[36] = g('Fwd Packets/s')
    vec[37] = g('Bwd Packets/s')
    vec[38] = g('Fwd Header Length')
    vec[39] = g('Active Min') / 1e6

    vec = np.where(np.isfinite(vec), vec, 0.0)
    vec = np.clip(vec, -1e9, 1e9)
    return vec


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) > 1:
        result = extract_all_features(sys.argv[1])
        if result["valid"]:
            print(f"Flow: {result['flow_id']}")
            print(f"BCC-28: {result['bcc_28']}")
            print(f"DDL-40: {result['ddl_40'].tolist()}")
        else:
            print(f"Error: {result.get('error')}")
    else:
        print("Usage: python unified_feature_extractor.py <pcap_path>")
