# Project Structure and Pipeline Documentation

## 1. Project Overview
This project, **Sentry Zero-Leak**, is an AI-driven anomaly detection system for encrypted network traffic. It operates on a **Zero-Trust** principle, inspecting every stream using behavioral metadata rather than packet payloads.

The system is modularized into a standalone **Encryptor** and an **SDN (Software Defined Network)** component that houses the detection and mitigation logic.

---

## 2. File Structure Guide

### `src/BaseCheckClassifier/` (System Logic)
The core logic for traffic inspection and the SDN simulation environment.

| Directory/File | Purpose |
| :--- | :--- |
| **`encryptor/`** | **Standalone Encryptor**: Simulates traffic encryption outside the SDN. |
| └── `traffic_encryptor.py` | Calculates file-size-based latency and adds AES-256-GCM overhead. |
| **`sdn/`** | **SDN Environment**: Houses all internal network logic and security enforcement. |
| ├── `extraction/feature_extractor.py` | **Feature Engine**: Extracts 15 behavioral features from "encrypted" PCAPs. |
| ├── `decision/sentry_controller.py` | **SDN Controller**: Orchestrates the pipeline and invokes the Decision Tree model. |
| ├── `buffer/` | **SDN Buffer**: Placeholder for the traffic buffering logic. |
| ├── `ddl_xai/` | **DDL + XAI**: Placeholder for Decentralized Deep Learning and Explainable AI components. |
| ├── `attack/` | Contains sample Attack (DDoS/Botnet) PCAP files. |
| └── `normal/` | Contains sample Normal (Benign) PCAP files. |
| **`Decision_tree_model_creator/`** | Training logic for the Sentry Decision Tree model. |
| **`Decision_tree_results/`** | Performance metrics and confusion matrices for the trained model. |
| **`requirements.txt`** | Python dependencies for the project. |

---

## 3. The Sentry Pipeline Flow
The system processes network traffic through a sequential, modular pipeline.

### Stage 1: Traffic Encryption (Outside SDN)
- **Component**: `encryptor/traffic_encryptor.py`
- **Action**: A raw PCAP stream is processed to simulate AES-256 encryption.
- **Result**: Logical "encrypted" metadata is passed to the SDN.

### Stage 2: SDN Entry & Feature Extraction (Zero-Leak)
- **Component**: `sdn/extraction/feature_extractor.py`
- **Action**: The SDN entry point extracts behavioral features (IAT, Packet Length Variance, etc.) without inspecting payloads.
- **Output**: A vector of **15 Behavioral Features**.

### Stage 3: SDN Controller Decision (DT)
- **Component**: `sdn/decision/sentry_controller.py`
- **Action**: The SDN controller feeds features into the pre-trained **Decision Tree Model**.
- **Logic**:
  - `Normal` → **ALLOW** (Proceed to Buffer/Destination).
  - `Attack` → **DROP** (Immediately drop at the edge).

### Stage 4: SDN Buffer & Mitigation
- **Component**: `sdn/buffer/`
- **Action**: Normal traffic is briefly buffered for further analysis or rate-limiting.

### Stage 5: DDL + XAI Analysis
- **Component**: `sdn/ddl_xai/`
- **Action**: Deep Learning analysis and Explainable AI explanation are performed on the traffic to refine decisions and provide insights.

---

## 4. How to Use
1.  **Configure Environment**: Ensure all dependencies from `requirements.txt` are installed.
2.  **Run Simulation**: From the `sdn/` directory, execute:
    ```bash
    python decision/sentry_controller.py
    ```
3.  **Monitor Output**: The controller will log classification decisions (Normal/Attack) and enforcement actions (FORWARD/DROP).
