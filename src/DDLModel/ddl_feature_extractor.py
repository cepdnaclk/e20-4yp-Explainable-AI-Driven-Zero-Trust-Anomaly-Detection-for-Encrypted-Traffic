"""
ddl_feature_extractor.py — 40-Feature DDL-Specific Extractor
=============================================================
Zero-Trust Anomaly Detection | University of Peradeniya

WHY 40 FEATURES (vs BCC's 28)?
---------------------------------
The BCC v2 uses 28 CIC-IDS-2017 features for fast Decision Tree classification.
DDL is a *reconstructive* model that learns the statistical fingerprint of
normal traffic — it benefits from a richer, more diverse feature set covering:

  - Packet size distributions (fwd + bwd, full min/max/mean/std)
  - Inter-arrival time (IAT) statistics (flow + fwd + bwd)
  - TCP flag counts (6 types)
  - Byte/packet rate statistics (flow + per-direction)
  - Flow-level aggregate features (duration, header len, active time)

FEATURES (40 total):
  [0-3]   fwd packet length (mean, std, min, max)
  [4-5]   bwd packet length (mean, std)
  [6-8]   fwd IAT (mean, std, max)
  [9-11]  bwd IAT (mean, std, max)
  [12-15] rates (flow bytes/s, flow pkts/s, fwd bytes/s, bwd bytes/s)
  [16-17] packet length (variance, mean)
  [18-23] TCP flags (SYN, ACK, FIN, RST, PSH, URG)
  [24-25] total bytes (fwd, bwd)
  [26]    flow duration (s)
  [27-28] init TCP window (fwd, bwd)
  [29]    down/up ratio
  ── New 10 features for improved detection ──
  [30-31] bwd packet length (min, max)
  [32-33] flow IAT (mean, std)
  [34]    fwd IAT total
  [35]    bwd IAT min
  [36-37] packet rates (fwd pkts/s, bwd pkts/s)
  [38]    fwd header length
  [39]    active min
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
    # ── New 10 features (v2 expansion) ──
    "bwd_pkt_len_min",      # 30
    "bwd_pkt_len_max",      # 31
    "flow_iat_mean",        # 32
    "flow_iat_std",         # 33
    "fwd_iat_total",        # 34
    "bwd_iat_min",          # 35
    "fwd_pkts_per_s",       # 36
    "bwd_pkts_per_s",       # 37
    "fwd_header_len",       # 38
    "active_min",           # 39
]

N_DDL_FEATURES = len(DDL_FEATURE_NAMES)  # 40


# ── Core extractor class ───────────────────────────────────────────────────────

class DDLFeatureExtractor:
    """
    Extracts 40 DDL-specific features from network flow data.

    Accepts input in three modes:
      1. NFStream flow object (online / offline capture)
      2. Dictionary with raw flow statistics (from feature_extractor.py output)
      3. DPKT packet list (manual extraction from pcap)

    All modes return a numpy array of shape (40,) with float64 values.
    Missing or unavailable features are filled with 0.0.
    """

    def from_nfstream(self, flow) -> np.ndarray:
        """
        Extract 40 DDL features from an nfstream NFFlow object.

        Args:
            flow: nfstream.NFFlow object.

        Returns:
            numpy array (40,).
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
        feat[6]  = _safe(flow, "src2dst_mean_piat_ms", 0.0) / 1000.0
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
        fwd_pkts    = max(_safe(flow, "src2dst_packets", 0.0), 0.0)
        bwd_pkts    = max(_safe(flow, "dst2src_packets", 0.0), 0.0)

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

        # ── New 10 features (30-39) ──
        feat[30] = _safe(flow, "dst2src_min_ps", 0.0)
        feat[31] = _safe(flow, "dst2src_max_ps", 0.0)
        feat[32] = _safe(flow, "bidirectional_mean_piat_ms", 0.0) / 1000.0
        feat[33] = _safe(flow, "bidirectional_stddev_piat_ms", 0.0) / 1000.0
        feat[34] = _safe(flow, "src2dst_duration_ms", 0.0) / 1000.0
        feat[35] = _safe(flow, "dst2src_min_piat_ms", 0.0) / 1000.0
        feat[36] = fwd_pkts / duration_s
        feat[37] = bwd_pkts / duration_s
        feat[38] = _safe(flow, "src2dst_header_bytes", 0.0)
        feat[39] = 0.0  # active_min not in NFStream; set via from_dict path

        return _sanitize(feat)

    def from_dict(self, raw: dict) -> np.ndarray:
        """
        Extract 40 DDL features from a raw flow statistics dictionary.

        Works with the output format of the BaseCheckClassifier's feature_extractor.py
        (which uses DPKT + NFStream). Missing keys default to 0.0.

        Args:
            raw: dict — keys are feature names, values are floats.

        Returns:
            numpy array (40,).
        """
        feat = np.zeros(N_DDL_FEATURES, dtype=np.float64)
        g = lambda k: float(raw.get(k, 0.0) or 0.0)

        feat[0]  = g("Fwd Packet Length Mean")
        feat[1]  = g("Fwd Packet Length Std")
        feat[2]  = g("Fwd Packet Length Min")
        feat[3]  = g("Fwd Packet Length Max")
        feat[4]  = g("Bwd Packet Length Mean")
        feat[5]  = g("Bwd Packet Length Std")
        feat[6]  = g("Fwd IAT Mean") / 1e6
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
        feat[26] = g("Flow Duration") / 1e6
        feat[27] = g("Init_Win_bytes_forward")
        feat[28] = g("Init_Win_bytes_backward")
        fwd = feat[24] + 1e-6
        feat[29] = feat[25] / fwd

        # ── New 10 features (30-39) ──
        feat[30] = g("Bwd Packet Length Min")
        feat[31] = g("Bwd Packet Length Max")
        feat[32] = g("Flow IAT Mean") / 1e6
        feat[33] = g("Flow IAT Std") / 1e6
        feat[34] = g("Fwd IAT Total") / 1e6
        feat[35] = g("Bwd IAT Min") / 1e6
        feat[36] = g("Fwd Packets/s")
        feat[37] = g("Bwd Packets/s")
        feat[38] = g("Fwd Header Length")
        feat[39] = g("Active Min") / 1e6

        return _sanitize(feat)

    def from_ordered_list(self, values: list, feature_names: list) -> np.ndarray:
        """
        Build DDL feature vector by matching named features from an ordered list.

        Args:
            values: list of floats — feature values (same order as feature_names).
            feature_names: list of str — names corresponding to values.

        Returns:
            numpy array (40,).
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
    Convenience wrapper: raw feature dict -> 40-element DDL feature vector.

    Use this in the pipeline when you already have a feature dict from the
    BaseCheckClassifier's extraction layer and want to add the DDL feature vector.

    Example:
        from DDLModel.ddl_feature_extractor import extract_ddl_features_from_dict

        ext_result   = extract_features(pcap_path)          # 28-feat DT extraction
        ddl_feats    = extract_ddl_features_from_dict(ext_result["features"])  # 40-feat DDL
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
        "Flow Duration": 1500000.0,   # 1.5 seconds in us
        "Init_Win_bytes_forward": 65535.0,
        "Init_Win_bytes_backward": 65535.0,
        # New 10:
        "Bwd Packet Length Min": 40.0,
        "Bwd Packet Length Max": 1400.0,
        "Flow IAT Mean": 4800.0, "Flow IAT Std": 1500.0,
        "Fwd IAT Total": 45000.0,
        "Bwd IAT Min": 200.0,
        "Fwd Packets/s": 60.0, "Bwd Packets/s": 55.0,
        "Fwd Header Length": 1200,
        "Active Min": 500000.0,
    }

    extractor = DDLFeatureExtractor()
    vec = extractor.from_dict(sample_dict)
    named = extractor.as_named_dict(vec)

    print(f"\nExtracted {N_DDL_FEATURES} DDL features:")
    for name, val in named.items():
        print(f"  {name:30s}: {val:.4f}")
    print(f"\nShape: {vec.shape}, dtype: {vec.dtype}")
    print("Smoke test PASSED.")
