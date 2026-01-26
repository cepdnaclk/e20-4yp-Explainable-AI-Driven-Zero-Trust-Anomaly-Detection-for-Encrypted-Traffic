# Random Forest Anomaly Detection - Performance Report

**Project:** Explainable AI-Driven Zero-Trust Anomaly Detection for Encrypted Traffic
**Date:** 2026-01-18 11:14:59
**Model:** Random Forest Classifier (300 trees, max_depth=15)
**Dataset:** BCCC Darknet (Pseudo-labeled via Ensemble IF+AE)

---

## Executive Summary

This report presents the performance evaluation of a Random Forest classifier trained on **high-confidence pseudo-labeled data**.

### Key Achievements
- ✅ **ROC-AUC: 0.9996**
- ✅ **Recall: 1.0000**
- ✅ **Precision: 0.7451**
- ✅ **F1-Score: 0.8539**
- ✅ **CV Mean: 0.9991 (±0.0003)**

---

## Performance Metrics

| Metric | Value |
|--------|-------|
| Accuracy | 0.9949 |
| Precision | 0.7451 |
| Recall | 1.0000 |
| F1-Score | 0.8539 |
| Specificity | 0.9948 |
| ROC-AUC | 0.9996 |
| Avg Precision | 0.9729 |

---

## Confusion Matrix

|  | Predicted Normal | Predicted Anomaly |
|---|---|---|
| **Actual Normal** | 5006 | 26 |
| **Actual Anomaly** | 0 | 76 |

