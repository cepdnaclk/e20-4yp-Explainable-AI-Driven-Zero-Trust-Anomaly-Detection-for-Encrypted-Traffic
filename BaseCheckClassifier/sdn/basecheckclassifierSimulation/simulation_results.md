# 🛡️ SDN Gatekeeper Simulation Results
Created: 2026-03-05 10:26:04

## 📊 Summary Metrics
- **Total Streams Processed:** 523,534
- **Processing Errors:** 178,474
- **Accuracy:** 98.72%
- **Attack Recall (Target >= 99.9%):** **99.964%** 🎯
- **Total Duration:** 0.76 minutes

## ⏱️ Latency (Microseconds)
- **Avg Extraction Time:** 1117.34 µs
- **Avg Inference Time:** 79.82 µs
- **Total Pipeline Latency:** **1197.16 µs** (Target < 1,000 µs ⚡)

## 🧮 Confusion Matrix
| Actual \ Predicted | BENIGN | ATTACK (Forward to DL) |
| :--- | :---: | :---: |
| **BENIGN** | 337,035 (Passed) | 6,630 (False Positive) |
| **ATTACK** | 64 (Leakage!) | 179,805 (Detected) |

---
> **Verdict:** Any leakage (FN > 0) is a potential threat. If leakage is high, decrease the model threshold in `train_model.py`.
