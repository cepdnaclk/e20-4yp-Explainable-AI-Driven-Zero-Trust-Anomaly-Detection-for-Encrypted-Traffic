# Random Forest Anomaly Detection - Performance Report

**Project:** Explainable AI-Driven Zero-Trust Anomaly Detection for Encrypted Traffic
**Date:** 2026-02-09 14:20:28
**Model:** Random Forest Classifier (300 trees, max_depth=15)
**Dataset:** BCCC Darknet (Pseudo-labeled via Ensemble IF+AE)

---

## Executive Summary

This report presents the performance evaluation of a Random Forest classifier trained on **high-confidence pseudo-labeled data**.

### Key Achievements
- ✅ **ROC-AUC: 0.9994**
- ✅ **Recall: 0.9865**
- ✅ **Precision: 0.7300**
- ✅ **F1-Score: 0.8391**
- ✅ **CV Mean: 0.9991 (±0.0003)**

---

## Performance Metrics

| Metric | Value |
|--------|-------|
| Accuracy | 0.9945 |
| Precision | 0.7300 |
| Recall | 0.9865 |
| F1-Score | 0.8391 |
| Specificity | 0.9946 |
| ROC-AUC | 0.9994 |
| Avg Precision | 0.9581 |

---

## Confusion Matrix

|  | Predicted Normal | Predicted Anomaly |
|---|---|---|
| **Actual Normal** | 5007 | 27 |
| **Actual Anomaly** | 1 | 73 |

