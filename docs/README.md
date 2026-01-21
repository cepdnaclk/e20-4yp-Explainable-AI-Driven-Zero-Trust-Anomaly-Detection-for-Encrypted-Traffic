---
layout: home
permalink: index.html
repository-name: e20-421-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic
title: Explainable AI-Driven Zero-Trust Anomaly Detection for Encrypted Traffic
---

# Explainable AI-Driven Zero-Trust Anomaly Detection for Encrypted Traffic

#### Team

* E/20/288, Chalaka Perera, [e20288@eng.pdn.ac.lk](mailto:e20288@eng.pdn.ac.lk) 

* E/20/420, Janith Wanasinghe, [e20420@eng.pdn.ac.lk](mailto:e20420@eng.pdn.ac.lk) 

* E/20/449, Sandaru Wijewardhana, [e20449@eng.pdn.ac.lk](mailto:e20449@eng.pdn.ac.lk) 



#### Supervisors

* Dr. Suneth Namal Karunarathna, [namal@eng.pdn.ac.lk](mailto:namal@eng.pdn.ac.lk) 

* Dr. Upul Jayasinghe, [upuljm@eng.pdn.ac.lk](mailto:upuljm@eng.pdn.ac.lk) 



#### Table of content

1. [Abstract](https://www.google.com/search?q=%23abstract)
2. [Related works](https://www.google.com/search?q=%23related-works)
3. [Methodology](https://www.google.com/search?q=%23methodology)
4. [Experiment Setup and Implementation](https://www.google.com/search?q=%23experiment-setup-and-implementation)
5. [Results and Analysis](https://www.google.com/search?q=%23results-and-analysis)
6. [Conclusion](https://www.google.com/search?q=%23conclusion)
7. [Publications](https://www.google.com/search?q=%23publications)
8. [Links](https://www.google.com/search?q=%23links)

---

## Abstract

Modern cybersecurity is shifting toward encryption to protect data privacy, but this often blinds traditional Intrusion Detection Systems (IDS) that rely on payload inspection. Concurrently, the rise of cloud computing and remote work has made perimeter-based security obsolete, leading to the adoption of Zero-Trust Architecture (ZTA), which requires continuous verification of every entity. While Deep Learning (DL) models can detect anomalies in encrypted traffic without decryption by analyzing metadata, their "black-box" nature creates a trust deficit that hinders automated policy enforcement. This project proposes a framework integrating Encrypted Traffic Analysis (ETA) with Explainable AI (XAI) using SHAP to provide real-time, human-readable rationales for security decisions.

## Related works

* **Encrypted Traffic Analysis (ETA):** Research shows that flow-based features like packet timing and size can identify malware families with high accuracy. Methods like Convolutional Neural Networks (CNNs) treat traffic as images to capture spatial correlations.

* **Zero-Trust Architecture (ZTA):** Studies emphasize that ZTA must extend beyond identity checks to evaluate connection quality in real-time. However, implementing mutual TLS and continuous authorization introduces significant CPU overhead.

* **Explainable AI (XAI):** Techniques like SHAP and LIME are being adapted to cybersecurity to map AI decisions to frameworks like MITRE ATT&CK.



## Methodology

The proposed framework utilizes a multi-stage pipeline:

1. **Feature Extraction:** Focuses on non-encrypted metadata including packet size, inter-arrival times, and TLS handshake parameters.

2. **Detection Model:** Employs Deep Dictionary Learning enhanced with Decision Trees or Isolation Forests.

3. **XAI Integration:** A SHAP-based engine provides real-time explanations for why a specific flow was flagged.

4. **Policy Enforcement:** Decisions feed back into the ZTA Policy Engine to dynamically adjust access (e.g., throttle, block, or step-up authentication).



## Experiment Setup and Implementation

> ⚠️ **Status: Currently in Progress**

* **Dataset:** Utilizing the CIC-IDS 2017/2018 datasets for training and validation.

* **Environment:** Implementation involves Python-based Deep Learning frameworks and XAI libraries (SHAP).

* **Integration:** Aiming for deployment in simulated environments to measure 10 Gbps+ network compatibility.


## Results and Analysis

> ⏳ **Status: Pending (Expected Feb 2026)**

* Preliminary literature reviews indicate that SHAP can achieve high interpretability accuracy, but computational cost remains a challenge for real-time high-bandwidth networks.



## Conclusion

This project identifies that XAI is the "missing piece" needed to make AI-based detection usable in automated Zero-Trust systems. By bridging the gap between detection, explanation, and automated policy creation, the framework aims to provide a practical solution for securing modern hidden data streams.

## Publications

> 📝 **Note: Documents will be linked as they become available.**

1. Perera, C., Wanasinghe, J., Wijewardhana, S. et al. "Explainable AI-Driven Zero Trust Anomaly Detection for Encrypted Traffic" (2025). (Not Published)



## Links

* [Project Repository](https://www.google.com/search?q=https://github.com/cepdnaclk/e20-421-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic)
* [Project Page](https://www.google.com/search?q=https://cepdnaclk.github.io/e20-421-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic)
* [Department of Computer Engineering](http://www.ce.pdn.ac.lk/)
* [University of Peradeniya](https://eng.pdn.ac.lk/)

---
