"""
ddl_feature_extractor.py — 30-Feature DDL-Specific Extractor
=============================================================
Zero-Trust Anomaly Detection | University of Peradeniya

WHY DIFFERENT FROM DT FEATURES?
---------------------------------
The Base Check Classifier uses 15 lightweight CIC-IDS-2017 features optimised
for fast Decision Tree classification. DDL is a *reconstructive* model that
learns the statistical fingerprint of normal traffic — it benefits from a much
richer, statistically diverse feature set covering:

  - Packet size distributions (fwd + bwd)
  - Inter-arrival time (IAT) statistics (fwd + bwd)
  - TCP flag counts
  - Byte/packet rate statistics
  - Flow-level aggregate features

Design basis:
  Tariyal et al. (2016): DDL paper in Research Papers/ — uses 30+ packet stats
  SHAP paper in Research Papers/: "78 NFStream features → top-30 by MI"
  CIC-IDS-2017/2018: Extended feature lists used by robust IDS implementations

FEATURES (30 total):
  [0]  fwd_pkt_len_mean       — forward packet mean length
  [1]  fwd_pkt_len_std        — forward packet length std dev
  [2]  fwd_pkt_len_min        — forward packet minimum length
  [3]  fwd_pkt_len_max        — forward packet maximum length
  [4]  bwd_pkt_len_mean       — backward packet mean length
  [5]  bwd_pkt_len_std        — backward packet length std dev
  [6]  fwd_iat_mean           — forward inter-arrival mean (s)
  [7]  fwd_iat_std            — forward inter-arrival std dev
  [8]  fwd_iat_max            — forward inter-arrival max (s)
  [9]  bwd_iat_mean           — backward inter-arrival mean (s)
  [10] bwd_iat_std            — backward inter-arrival std dev
  [11] bwd_iat_max            — backward inter-arrival max (s)
  [12] flow_bytes_per_s       — total flow throughput (bytes/s)
  [13] flow_pkts_per_s        — total flow packet rate (pkts/s)
  [14] fwd_bytes_per_s        — forward throughput
  [15] bwd_bytes_per_s        — backward throughput
  [16] pkt_len_variance       — variance across all packet sizes
  [17] pkt_len_mean           — mean across all packet sizes (fwd+bwd)
  [18] syn_flag_count         — number of SYN flags in flow
  [19] ack_flag_count         — number of ACK flags in flow
  [20] fin_flag_count         — number of FIN flags in flow
  [21] rst_flag_count         — number of RST flags in flow
  [22] psh_flag_count         — number of PSH flags (forward)
  [23] urg_flag_count         — number of URG flags
  [24] total_fwd_bytes        — total forward payload bytes
  [25] total_bwd_bytes        — total backward payload bytes
  [26] flow_duration          — total flow duration (s)
  [27] init_win_fwd           — initial TCP window size (forward)
  [28] init_win_bwd           — initial TCP window size (backward)
  [29] down_up_ratio          — download/upload byte ratio
"""

import numpy as np
import logging
from typing import Dict, List, Optional, Union

logger = logging.getLogger("DDL.FeatureExtractor")

# ── Feature registry ──────────────────────────────────────────────────────────

DDL_FEATURE_NAMES: List[str] = [
    "fwd_pkt_len_mean",     # 0
    "fwd_pkt_len_std",      # 1
    "fwd_pkt_len_min",      # 2
    "fwd_pkt_len_max",      # 3
    "bwd_pkt_len_mean",     # 4
    "bwd_pkt_len_std",      # 5
    "fwd_iat_mean",         # 6
    "fwd_iat_std",          # 7
    "fwd_iat_max",          # 8
    "bwd_iat_mean",         # 9
    "bwd_iat_std",          # 10
    "bwd_iat_max",          # 11
    "flow_bytes_per_s",     # 12
    "flow_pkts_per_s",      # 13
    "fwd_bytes_per_s",      # 14
    "bwd_bytes_per_s",      # 15
    "pkt_len_variance",     # 16
    "pkt_len_mean",         # 17
    "syn_flag_count",       # 18
    "ack_flag_count",       # 19
    "fin_flag_count",       # 20
    "rst_flag_count",       # 21
    "psh_flag_count",       # 22
    "urg_flag_count",       # 23
    "total_fwd_bytes",      # 24
    "total_bwd_bytes",      # 25
    "flow_duration",        # 26
    "init_win_fwd",         # 27
    "init_win_bwd",         # 28
    "down_up_ratio",        # 29
]

N_DDL_FEATURES = len(DDL_FEATURE_NAMES)  # 30


# ── Core extractor class ───────────────────────────────────────────────────────

class DDLFeatureExtractor:
    """
    Extracts 30 DDL-specific features from network flow data.

    Accepts input in three modes:
      1. NFStream flow object (online / offline capture)
      2. Dictionary with raw flow statistics (from feature_extractor.py output)
      3. DPKT packet list (manual extraction from pcap)

    All modes return a numpy array of shape (30,) with float64 values.
    Missing or unavailable features are filled with 0.0.
    """

    def from_nfstream(self, flow) -> np.ndarray:
        """
        Extract 30 DDL features from an nfstream NFFlow object.

        NFStream exposes statistical fields per direction that map directly
        to our DDL feature set. Available after nfstream processes a terminated
        or idle-timed-out flow.

        Args:
            flow: nfstream.NFFlow object.

        Returns:
            numpy array (30,).
        """
        feat = np.zeros(N_DDL_FEATURES, dtype=np.float64)

        # ── Packet length stats (fwd = src2dst, bwd = dst2src) ──
        feat[0]  = _safe(flow, "src2dst_mean_ps", 0.0)
        feat[1]  = _safe(flow, "src2dst_stddev_ps", 0.0)
        feat[2]  = _safe(flow, "src2dst_min_ps", 0.0)
        feat[3]  = _safe(flow, "src2dst_max_ps", 0.0)
        feat[4]  = _safe(flow, "dst2src_mean_ps", 0.0)
        feat[5]  = _safe(flow, "dst2src_stddev_ps", 0.0)

        # ── IAT stats ──
        feat[6]  = _safe(flow, "src2dst_mean_piat_ms", 0.0) / 1000.0  # → seconds
        feat[7]  = _safe(flow, "src2dst_stddev_piat_ms", 0.0) / 1000.0
        feat[8]  = _safe(flow, "src2dst_max_piat_ms", 0.0) / 1000.0
        feat[9]  = _safe(flow, "dst2src_mean_piat_ms", 0.0) / 1000.0
        feat[10] = _safe(flow, "dst2src_stddev_piat_ms", 0.0) / 1000.0
        feat[11] = _safe(flow, "dst2src_max_piat_ms", 0.0) / 1000.0

        # ── Byte / packet rates ──
        duration_s = max(_safe(flow, "bidirectional_duration_ms", 1.0) / 1000.0, 1e-6)
        total_bytes = _safe(flow, "bidirectional_bytes", 0.0)
        fwd_bytes   = _safe(flow, "src2dst_bytes", 0.0)
        bwd_bytes   = _safe(flow, "dst2src_bytes", 0.0)
        total_pkts  = max(_safe(flow, "bidirectional_packets", 1.0), 1.0)

        feat[12] = total_bytes / duration_s
        feat[13] = total_pkts / duration_s
        feat[14] = fwd_bytes  / duration_s
        feat[15] = bwd_bytes  / duration_s

        # ── Packet length variance + global mean ──
        all_sizes = []
        if hasattr(flow, "src2dst_ps_histogram") and flow.src2dst_ps_histogram:
            all_sizes.extend(flow.src2dst_ps_histogram)
        if hasattr(flow, "dst2src_ps_histogram") and flow.dst2src_ps_histogram:
            all_sizes.extend(flow.dst2src_ps_histogram)

        if all_sizes:
            feat[16] = float(np.var(all_sizes))
            feat[17] = float(np.mean(all_sizes))
        else:
            feat[16] = 0.0
            feat[17] = (feat[0] + feat[4]) / 2.0

        # ── TCP flag counts ──
        feat[18] = _safe(flow, "bidirectional_syn_packets", 0.0)
        feat[19] = _safe(flow, "bidirectional_ack_packets", 0.0)
        feat[20] = _safe(flow, "bidirectional_fin_packets", 0.0)
        feat[21] = _safe(flow, "bidirectional_rst_packets", 0.0)
        feat[22] = _safe(flow, "src2dst_psh_packets", 0.0)
        feat[23] = _safe(flow, "bidirectional_urg_packets", 0.0)

        # ── Flow totals ──
        feat[24] = fwd_bytes
        feat[25] = bwd_bytes
        feat[26] = duration_s

        # ── TCP window sizes ──
        feat[27] = _safe(flow, "src2dst_initial_mean_ps", 0.0)
        feat[28] = _safe(flow, "dst2src_initial_mean_ps", 0.0)

        # ── Down/Up ratio ──
        feat[29] = bwd_bytes / (fwd_bytes + 1e-6)

        return _sanitize(feat)

    def from_dict(self, raw: dict) -> np.ndarray:
        """
        Extract 30 DDL features from a raw flow statistics dictionary.

        Works with the output format of the BaseCheckClassifier's feature_extractor.py
        (which uses DPKT + NFStream). Missing keys default to 0.0.

        Args:
            raw: dict — keys are feature names, values are floats.

        Returns:
            numpy array (30,).
        """
        feat = np.zeros(N_DDL_FEATURES, dtype=np.float64)
        g = lambda k: float(raw.get(k, 0.0) or 0.0)

        feat[0]  = g("Fwd Packet Length Mean")
        feat[1]  = g("Fwd Packet Length Std")
        feat[2]  = g("Fwd Packet Length Min")
        feat[3]  = g("Fwd Packet Length Max")
        feat[4]  = g("Bwd Packet Length Mean")
        feat[5]  = g("Bwd Packet Length Std")
        feat[6]  = g("Fwd IAT Mean") / 1e6   # μs → s
        feat[7]  = g("Fwd IAT Std")  / 1e6
        feat[8]  = g("Fwd IAT Max")  / 1e6
        feat[9]  = g("Bwd IAT Mean") / 1e6
        feat[10] = g("Bwd IAT Std")  / 1e6
        feat[11] = g("Bwd IAT Max")  / 1e6
        feat[12] = g("Flow Bytes/s")
        feat[13] = g("Flow Packets/s")
        feat[14] = g("Fwd Bytes/Bulk Avg") or g("Total Length of Fwd Packets") / max(g("Flow Duration") / 1e6, 1e-6)
        feat[15] = g("Bwd Bytes/Bulk Avg") or g("Total Length of Bwd Packets") / max(g("Flow Duration") / 1e6, 1e-6)
        feat[16] = g("Packet Length Variance")
        feat[17] = g("Packet Length Mean")
        feat[18] = g("SYN Flag Count")
        feat[19] = g("ACK Flag Count")
        feat[20] = g("FIN Flag Count")
        feat[21] = g("RST Flag Count")
        feat[22] = g("PSH Flag Count")
        feat[23] = g("URG Flag Count")
        feat[24] = g("Total Length of Fwd Packets")
        feat[25] = g("Total Length of Bwd Packets") or g("Total Backward Packets") * g("Bwd Packet Length Mean")
        feat[26] = g("Flow Duration") / 1e6   # μs → s
        feat[27] = g("Init_Win_bytes_forward")
        feat[28] = g("Init_Win_bytes_backward")
        fwd = feat[24] + 1e-6
        feat[29] = feat[25] / fwd

        return _sanitize(feat)

    def from_ordered_list(self, values: list, feature_names: list) -> np.ndarray:
        """
        Build DDL feature vector by matching named features from an ordered list.

        Useful when the upstream extractor returns a parallel (names, values) pair.

        Args:
            values: list of floats — feature values (same order as feature_names).
            feature_names: list of str — names corresponding to values.

        Returns:
            numpy array (30,).
        """
        raw = dict(zip(feature_names, values))
        return self.from_dict(raw)

    def as_named_dict(self, feat_array: np.ndarray) -> Dict[str, float]:
        """Return a feature vector as a named dict for inspection / logging."""
        return {name: float(v) for name, v in zip(DDL_FEATURE_NAMES, feat_array)}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe(obj, attr: str, default: float) -> float:
    """Safely get an attribute from an object, returning default if missing/None."""
    v = getattr(obj, attr, default)
    if v is None or (isinstance(v, float) and (np.isnan(v) or np.isinf(v))):
        return default
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _sanitize(feat: np.ndarray) -> np.ndarray:
    """Replace NaN/Inf with 0.0 and clip to [-1e9, 1e9] for numerical safety."""
    feat = np.where(np.isfinite(feat), feat, 0.0)
    feat = np.clip(feat, -1e9, 1e9)
    return feat.astype(np.float64)


# ── Convenience function ──────────────────────────────────────────────────────

def extract_ddl_features_from_dict(raw_feature_dict: dict) -> np.ndarray:
    """
    Convenience wrapper: raw feature dict → 30-element DDL feature vector.

    Use this in the pipeline when you already have a feature dict from the
    BaseCheckClassifier's extraction layer and want to add the DDL feature vector.

    Example:
        from DDLModel.ddl_feature_extractor import extract_ddl_features_from_dict

        ext_result   = extract_features(pcap_path)          # 15-feat DT extraction
        ddl_feats    = extract_ddl_features_from_dict(ext_result["features"])  # 30-feat DDL
        ddl_result   = ddl.predict(ddl_feats)
    """
    return DDLFeatureExtractor().from_dict(raw_feature_dict)


if __name__ == "__main__":
    import json

    # Quick smoke test
    print("DDL Feature Extractor — smoke test")
    print(f"N_DDL_FEATURES = {N_DDL_FEATURES}")
    print(f"Feature names:  {DDL_FEATURE_NAMES}")

    # Simulate a normal flow dict (similar to CIC-IDS-2017 benign traffic)
    sample_dict = {
        "Fwd Packet Length Mean": 420.0,
        "Fwd Packet Length Std": 180.0,
        "Fwd Packet Length Min": 54.0,
        "Fwd Packet Length Max": 1460.0,
        "Bwd Packet Length Mean": 380.0,
        "Bwd Packet Length Std": 220.0,
        "Fwd IAT Mean": 5000.0, "Fwd IAT Std": 1200.0, "Fwd IAT Max": 25000.0,
        "Bwd IAT Mean": 5500.0, "Bwd IAT Std": 1800.0, "Bwd IAT Max": 30000.0,
        "Flow Bytes/s": 85000.0, "Flow Packets/s": 120.0,
        "Packet Length Variance": 48000.0, "Packet Length Mean": 400.0,
        "SYN Flag Count": 1, "ACK Flag Count": 45, "FIN Flag Count": 1,
        "RST Flag Count": 0, "PSH Flag Count": 12, "URG Flag Count": 0,
        "Total Length of Fwd Packets": 18900.0,
        "Total Length of Bwd Packets": 15200.0,
        "Flow Duration": 1500000.0,   # 1.5 seconds in μs
        "Init_Win_bytes_forward": 65535.0,
        "Init_Win_bytes_backward": 65535.0,
    }

    extractor = DDLFeatureExtractor()
    vec = extractor.from_dict(sample_dict)
    named = extractor.as_named_dict(vec)

    print("\nExtracted 30 DDL features:")
    for name, val in named.items():
        print(f"  {name:30s}: {val:.4f}")
    print(f"\nShape: {vec.shape}, dtype: {vec.dtype}")
    print("Smoke test PASSED.")
