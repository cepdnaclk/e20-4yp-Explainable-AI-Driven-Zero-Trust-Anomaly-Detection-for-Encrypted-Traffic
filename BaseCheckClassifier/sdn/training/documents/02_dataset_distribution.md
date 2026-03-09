# 📊 Dataset Distribution Report

**Document:** Dataset Class Distribution  
**Source:** `/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/`  
**Date:** 2026-03-05  

---

## Per-Day Breakdown

| Day | Label | Count | Type |
|-----|-------|------:|------|
| Monday | BENIGN | 268,857 | ✅ |
| Tuesday | BENIGN | 51,808 | ✅ |
| Tuesday | FTP-Patator | 2,067 | 🔴 |
| Wednesday | BENIGN | 47,437 | ✅ |
| Wednesday | DoSHulk | 114,787 | 🔴 |
| Wednesday | DoSGoldenEye | 5,390 | 🔴 |
| Wednesday | DoSSlowhttptest | 4,226 | 🔴 |
| Wednesday | DoSslowloris | 3,557 | 🔴 |
| Thursday | BENIGN | 81,199 | ✅ |
| Thursday | WebAttackBruteForce | 401 | 🔴 |
| Thursday | WebAttackXSS | 172 | 🔴 |
| Thursday | Infiltration | 29 | 🔴 |
| Thursday | WebAttackSqlInjection | **2** | ⚠️ |
| Friday | BENIGN | 72,838 | ✅ |
| Friday | PortScan | 24,984 | 🔴 |
| Friday | DDoS | 24,027 | 🔴 |
| Friday | Bot | 226 | 🔴 |

---

## Binary Summary

| Class | Count | % |
|-------|------:|---|
| **BENIGN** | **522,139** | **74.4%** |
| **ATTACK** | **179,868** | **25.6%** |
| **Total** | **702,007** | |

---

## Attack Type Breakdown

| Attack Type | Count | % of Total |
|-------------|------:|------------|
| DoSHulk | 114,787 | 16.35% |
| PortScan | 24,984 | 3.56% |
| DDoS | 24,027 | 3.42% |
| DoSGoldenEye | 5,390 | 0.77% |
| DoSSlowhttptest | 4,226 | 0.60% |
| DoSslowloris | 3,557 | 0.51% |
| FTP-Patator | 2,067 | 0.29% |
| WebAttackBruteForce | 401 | 0.06% |
| Bot | 226 | 0.03% |
| WebAttackXSS | 172 | 0.02% |
| Infiltration | 29 | ~0% |
| WebAttackSqlInjection | 2 | ~0% |

---

## Balancing Decision

Since this is a **binary classifier** (BENIGN vs ATTACK), the attack sub-types do not matter
for training. All attacks collapse into a single ATTACK label.

**Strategy: Undersample BENIGN to match ATTACK count**
```
ATTACK  →  179,868   (keep all)
BENIGN  →  179,868   (undersample from 522,139)
──────────────────────────────
Total   →  359,736   (50% / 50%)
```

No SMOTE needed — 179,868 real attack samples is more than sufficient.
