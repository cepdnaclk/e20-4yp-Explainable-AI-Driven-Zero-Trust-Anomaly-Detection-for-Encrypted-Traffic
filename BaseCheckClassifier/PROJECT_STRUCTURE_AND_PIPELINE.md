# Project Structure and Pipeline Documentation

## 1. Project Overview
This project, **Sentry Zero-Leak**, is an AI-driven anomaly detection system for encrypted network traffic. It operates on a **Zero-Trust** principle, inspecting every stream using behavioral metadata (15 extracted features) rather than packet payloads.

---

## 2. File Structure Guide

### `BaseCheckClassifier/` (System Logic)
The core logic for traffic inspection and simulation resides here.

| Directory/File | Purpose |
| :--- | :--- |
| **`BaseCheckClassifierSimulation/`** | The main execution environment for running traffic simulations. |
| ├── `decision/sentry_controller.py` | **Orchestrator**: Runs the simulation loop, manages topology events, and invokes model decisions. |
| ├── `extraction/feature_extractor.py` | **Feature Engine**: Uses DPKT and NFStream to extract 15 specific behavioral features from PCAPs. |
| ├── `encryption/traffic_encryptor.py` | **Simulator**: Injects artificial latency and simulates the overhead of AES-256-GCM encryption. |
| ├── `generate_synthetic_pcap.py` | **Data Generator**: Creates synthetic Benign (HTTP) and Attack (DDoS) PCAPs for testing. |
| ├── `attack/` & `normal/` | Directories containing PCAP files labeled as Attack and Normal respectively. |
| ├── `check_model.py` | Utility to verify if the trained ML model loads correctly. |
| └── `pipeline_description.md` | Internal description of the simulation stages. |
| **`Decision_tree_model_creator/`** | Contains the `DecisionTree.py` script used to train the Sentry model. |
| **`Decision_tree_results/`** | Stores the evaluation results (confusion matrix, metrics) of the trained model. |
| **`CICDataset_filteration_for_DT/`** | Logic for cleaning and selecting the best 15 features from the CIC-IDS-2017 dataset. |

### `CICDataset/` (Data Repository)
The primary storage for raw and processed network traffic data.

| Directory/File | Purpose |
| :--- | :--- |
| **`PCAP/`** | Contains large, raw packet capture files from the CIC-IDS-2017 dataset. |
| **`Machine-Learning-CSV/`** | Contains the flow-level metadata CSV files used for training and testing models. |
| **`packet_classifier/`** | Contains `classify_pcap.py` which matches raw packets to CSV labels to create labeled PCAPs. |
| **`Generated-Labelled-Flow/`** | Output directory for flows that have been successfully labeled and grouped. |
| **`Processed-Data/`** | Interim data stored during the filtration and preparation process. |

---

## 3. The Sentry Pipeline Flow
The system processes network traffic through a sequential pipeline to determine if a stream should be allowed or blocked.

### Stage 1: Traffic Injection & Encryption Sim
- **Action**: A PCAP stream is selected from the source.
- **Simulation**: `traffic_encryptor.py` calculates file-size-based latency and adds a jittered "encryption overhead" (AES-256).
- **Result**: The stream is now logically "encrypted," meaning downstream components must only use header/metadata features.

### Stage 2: Topology Simulation
- **Action**: `sentry_controller.py` simulates the path the packet takes through the virtual network (`Firewall -> Core -> Edge`).
- **Result**: Path events are logged for auditing and analysis.

### Stage 3: Feature Extraction (Zero-Leak)
- **Action**: `feature_extractor.py` performs two passes on the stream.
  1. **DPKT Pass**: Extracts TCP handshake data (Window sizes, Header lengths).
  2. **NFStream Pass**: Extracts statistical flow metrics (IAT, variance, rates).
- **Output**: A vector of **15 Behavioral Features** (e.g., Packet Length Variance, Bwd Packets/s).

### Stage 4: Sentry Model Decision
- **Action**: The 15 features are fed into a pre-trained **Decision Tree Model** (`sentry_zero_leak_v1.pkl`).
- **Logic**:
  - `Prediction == Normal` → **FORWARD** (Traffic allowed to destination).
  - `Prediction == Attack` → **DROP** (Traffic blocked at the edge).

### Stage 5: Logging & Enforcement
- **Action**: Action is enforced, and results are persisted.
- **Logs**:
  - **JSON Log**: Detailed technical metadata for every stream (`simulation_log.json`).
  - **Syslog**: RFC 5424 compliant messages for integration with SIEM/Dashboards.

---

## 4. How to Use the Simulation
1.  **Generate Data**: Run `generate_synthetic_pcap.py` to create test files.
2.  **Run Simulation**: Execute `python decision/sentry_controller.py` from within the `BaseCheckClassifierSimulation` directory.
3.  **View Results**: Monitor `simulation_log.json` or the terminal output for real-time classification decisions.
