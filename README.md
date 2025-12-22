# Explainable AI-Driven Zero Trust Anomaly Detection for Encrypted Traffic

This project addresses the modern cybersecurity "blind spot" created by the widespread adoption of encryption protocols (HTTPS/TLS 1.3). While encryption protects privacy, it renders traditional Deep Packet Inspection (DPI) ineffective, allowing adversaries to hide malware and data exfiltration within legitimate-looking data streams.

Our solution integrates **Zero-Trust Architecture (ZTA)**, **Encrypted Traffic Analysis (ETA)**, and **Explainable AI (XAI)** to create a framework that can detect, explain, and block malicious traffic in real-time without decryption.

---

## 🚀 Overview

Traditional perimeter-based security is outdated. This project implements a **"Never Trust, Always Verify"** approach by using Deep Learning to identify malicious patterns in traffic metadata (packet timing, size, and direction). To overcome the "Black Box" problem of AI, we integrate XAI techniques like **SHAP** to provide human-readable rationales for security decisions, ensuring trust in automated policy enforcement.

### Key Features

* **Decryption-Free Detection:** Uses flow-based features (metadata) to identify threats within encrypted tunnels.

* **Explainable Decisions:** Integration of **SHAP** values to explain why a specific flow was flagged as an anomaly.

* **Zero-Trust Integration:** Dynamically updates trust scores and feeds decisions back into Policy Enforcement Points (PEP).

* **Real-time Response:** Aimed at high-bandwidth environments to block or isolate hosts immediately upon detection.



---

## 🛠️ Methodology & Design

The project pipeline follows a structured approach from raw data to automated decision-making:

1. **Data Acquisition:** Utilizes datasets such as **CIC-IDS 2017**.

2. **Feature Extraction:** Focuses on non-encrypted metadata:
* Packet sizes and directions.

* Inter-arrival times.

* TLS handshake parameters (Cipher suites, Client Hello details).

3. **Model Architecture:** A combined model approach using **Deep Dictionary Learning** enhanced with Decision Trees (DT) or Isolation Forests (IF).
4. **XAI Integration:** SHAP engine provides the "reasoning" for every flagged packet in real-time.
5. **Policy Enforcement:** Decisions result in actions such as maintaining/tightening access, step-up authentication, or blocking the host.

---

## 📊 Performance & Evaluation

The system is evaluated against the following metrics:

* **Accuracy Metrics:** F1-score and Precision.
* **Explanation Quality:** Assessing the semantic clarity of AI rationales.
* **Latency & Overhead:** Measuring the impact of continuous verification on system load.
---

## 📅 Project Timeline (2025-2026)

* **Dec 2025:** Data Collection & Preparation and Model Development.
* **Jan 2026:** Testing and XAI Integration.
* **Feb 2026:** Evaluation, Validation, and Deployment.
* **Mar 2026:** Final Documentation and Reporting.
---

## 👥 Research Team

* **Chalaka Perera** (e20288@eng.pdn.ac.lk) 
* **Janith Wanasinghe** (e20420@eng.pdn.ac.lk) 
* **Sandaru Wijewardhana** (e20449@eng.pdn.ac.lk) 
* **Supervisors:** Dr. Suneth Namal Karunarathna & Dr. Upul Jayasinghe 

**Department of Computer Engineering, University of Peradeniya, Sri Lanka.** 

---
