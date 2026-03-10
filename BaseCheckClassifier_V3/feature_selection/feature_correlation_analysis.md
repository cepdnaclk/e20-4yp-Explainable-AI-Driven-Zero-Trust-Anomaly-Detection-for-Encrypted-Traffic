# Feature Correlation Analysis Report

This report summarizes the linear correlation analysis performed on the `dataset_raw.csv` dataset, evaluating the relationship between each of the 28 extracted features and the target variable (`BENIGN` vs `ATTACK`).

## Objective
To identify and remove features with low correlation to the target label. Removing these features can speed up inference time in the feature extractor without significantly sacrificing model accuracy. 

A threshold of **0.05 absolute correlation** was chosen. Features falling below this threshold were considered weakly correlated and flagged for removal.

## 1. Kept Features (Absolute Correlation $\ge$ 0.05)
These **12 features** show a significant statistical relationship with detecting anomalies.

| Feature | Correlation Score |
| :--- | :--- |
| **Bwd Packet Length Mean** | `0.6669` |
| **Bwd Packet Length Max** | `0.6349` |
| **Packet Length Variance** | `0.6029` |
| **RST Flag Count** | `0.5333` |
| **SYN Flag Count** | `0.3828` |
| **Init_Win_bytes_backward** | `0.3017` |
| **Init_Win_bytes_forward** | `0.1201` |
| **Bwd Packets/s** | `0.1003` |
| **Fwd Packet Length Max** | `-0.0996` |
| **Fwd Packets/s** | `-0.0749` |
| **Fwd Packet Length Std** | `-0.0728` |
| **Flow Duration** | `-0.0524` |

---

## 2. Removed Features (Absolute Correlation < 0.05)
These **16 features** exhibited little to no linear correlation with the target variable and are safe candidates for removal to optimize the `feature_extractor`.

| Feature | Correlation Score |
| :--- | :--- |
| **Fwd Packet Length Mean** | `-0.0496` |
| **Bwd IAT Total** | `-0.0489` |
| **Flow IAT Max** | `-0.0459` |
| **Flow IAT Std** | `-0.0430` |
| **Flow IAT Mean** | `-0.0306` |
| **Active Min** | `-0.0152` |
| **Flow Bytes/s** | `-0.0148` |
| **Fwd Header Length** | `-0.0076` |
| **Total Fwd Packets** | `-0.0076` |
| **Bwd Header Length** | `-0.0071` |
| **Total Bwd Packets** | `-0.0070` |
| **Fwd IAT Min** | `-0.0052` |
| **Total Length of Fwd Packets** | `-0.0050` |
| **Down/Up Ratio** | `0.0048` |
| **Flow IAT Min** | `-0.0030` |
| **Fwd IAT Total** | `0.0028` |

## Summary of Optimization Impact
By dropping the 16 poorly correlated features:
1. The **Sentry Feature Extractor** can be optimized by removing loops and computations relative to Inter-Arrival Times (IAT) and base packet tracking logic.
2. We reduce the memory footprint required for classification from 28 dimensions per flow to **12 dimensions**, speeding up execution dynamically for SDN inference.
