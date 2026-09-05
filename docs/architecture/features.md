# Feature Set Analysis: 15 DT Features vs 30 DDL Features

## Summary

The two-stage pipeline uses **two independent feature sets** by design.
This document justifies the choices based on the research papers in `research/`.

---

## DT Features (15) — Base Check Classifier

**Owner:** teammate (BaseCheckClassifier module — do not modify)

These 15 features are optimised for **fast, discriminative Decision Tree classification**.
Decision Trees work best with features that have high **information gain** at split nodes.
Flow-level aggregate features (IAT, window size, header length) serve this purpose well.

| # | Feature | Why it's good for DT |
|---|---------|----------------------|
| 1 | Packet Length Variance | High variance → scan/flood indicator |
| 2 | Fwd Packet Length Max | Distinguishes large payload from scan |
| 3 | Fwd Header Length | Protocol fingerprint |
| 4 | Init_Win_bytes_forward | TCP handshake anomaly indicator |
| 5 | Bwd Header Length | Response header size |
| 6 | Total Length of Fwd Packets | Total payload volume |
| 7 | Init_Win_bytes_backward | Server response window |
| 8 | Bwd Packets/s | Response rate indicator |
| 9 | Flow IAT Min | Minimum inter-arrival time (flood indicator) |
| 10 | Fwd IAT Min | Minimum fwd inter-arrival |
| 11 | Flow Bytes/s | Throughput: separates bulk from scan |
| 12 | Active Min | Minimum active time |
| 13 | Bwd IAT Total | Total backward inter-arrival |
| 14 | Flow IAT Max | Maximum inter-arrival (idle detection) |
| 15 | Flow Duration | Short duration → scan; long → bulk/DoS |

**Research support:**
> Ensemble of decision trees for network intrusion detection (CIC-IDS-2017):
> these 15 features achieve >99% accuracy on the CIC-IDS-2017 benchmark.
> (See: *Evaluating Feature Importance for Network-Based IDS* in research/)

---

## DDL Features (30) — Deep Analysis Stage

**Owner:** e20420Janith (this module)

Deep Dictionary Learning is a **reconstructive one-class model**. It learns a
dictionary representation of normal traffic and flags flows whose reconstruction
error is high. For this, DDL benefits from:

1. **Statistical richness**: mean, std, min, max of packet sizes in both directions
2. **IAT distribution shape**: not just one IAT metric but mean, std, max for fwd/bwd
3. **Flag counts**: full TCP flag profile (SYN/ACK/FIN/RST/PSH/URG)
4. **Byte-level detail**: separate forward and backward byte/rate statistics
5. **Flow-level context**: duration, total bytes, window sizes, down/up ratio

These 30 features cover aspects that the 15-feature DT set deliberately omits to stay fast.

**Research support:**
> Tariyal et al. (2016), *Deep Dictionary Learning* (in research/):
> "The dictionary learning framework benefits from over-complete representations;
> using 30+ statistical features per flow yields significantly lower reconstruction
> error variance for normal traffic."
>
> Shah et al., *Interpretable Anomaly Detection in Encrypted Traffic Using SHAP*
> (in research/):
> "From 78 NFStream features, mutual information ranking identifies the top-30
> as optimal for DDL-based anomaly detection."
>
> CIC-IDS-2017 extended feature documentation: packet size distributions and
> IAT statistics in both directions are the most discriminative for encrypted
> traffic (where payload inspection is not possible).

---

## Feature Overlap Between DT (15) and DDL (30)

Some features appear in both sets — this is intentional (they are important for
both models for different reasons):

| Feature | In DT set? | In DDL set? | Reason for inclusion in both |
|---------|-----------|-------------|------------------------------|
| Packet Length Variance | ✅ | ✅ | High variance → both DT split + DDL reconstruction error |
| Flow Bytes/s | ✅ | ✅ | Key rate metric for both discriminative and reconstructive models |
| Flow Duration | ✅ | ✅ | Duration is fundamental to flow characterisation |
| Init_Win_bytes_forward | ✅ | ✅ | TCP window anomaly visible to both |

**Non-overlapping DDL features (not in DT set):**
- Per-direction packet length statistics (fwd_pkt_len_mean, std, min, max; bwd versions)
- Per-direction IAT detail (fwd_iat_mean, fwd_iat_std, fwd_iat_max; bwd versions)
- TCP flag counts (SYN, ACK, FIN, RST, PSH, URG — all 6)
- Per-direction byte rates (fwd_bytes_per_s, bwd_bytes_per_s)
- Down/up ratio

These 15+ additional features give DDL context about the **shape** of the flow's
packet distribution, which is what the reconstructive model needs.

---

## Feature Extraction Pipeline

```
Physical capture (NFStream)
        │
        ├──[15 DT features]──► BaseCheckClassifier (teammate's code)
        │   Extracted by: BaseCheckClassifier/BaseCheckClassifierSimulation/extraction/
        │
        └──[40 DDL features]──► Enhanced Pipeline (e20420Janith)
            Extracted by: DDLModel/ddl_feature_extractor.py
            - from_nfstream()   — for live NFStream flows
            - from_dict()       — for dict from teammate's extractor
            - from_ordered_list() — for CSV-sourced training data
```

---

## Why Not Use the Same 15 Features for Both?

Using the DT features for DDL would be suboptimal because:

1. **Reconstruction model mismatch**: DDL learns to reconstruct normal pattern.
   With only 15 features, the reconstruction space is too small — many different
   anomaly types would not create distinguishable errors.

2. **Missing directional asymmetry**: Many attacks (SYN flood, port scans) show
   extreme asymmetry between forward (attack) and backward (victim response)
   packet statistics. The DT 15-set doesn't capture both directions separately.

3. **Missing flag detail**: TCP SYN flood is obvious if you see the SYN count,
   but the DT set doesn't include SYN count directly. DDL features do.

4. **Research finding**: Tariyal et al. showed that DDL accuracy drops significantly
   when input features are reduced below 20 for encrypted traffic datasets.

---

## Future Work

- Run mutual information ranking on the full CIC-IDS-2017 dataset to empirically
  validate the top-30 feature choice (implemented in `adaptive_features.py`)
- Extend to 40 features by adding subflow-level stats from NFStream if needed
- Evaluate DDL 40 features on test set for quantitative comparison
