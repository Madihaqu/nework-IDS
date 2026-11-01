# 🛡️ Hybrid NIDS: Dual-Engine Network Intrusion Detection System

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red.svg)](https://streamlit.io/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-Machine%20Learning-orange.svg)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An end-to-end, real-time **Hybrid Network Intrusion Detection System (NIDS)** combining **Supervised** and **Unsupervised Machine Learning** algorithms. The system classifies known signature-based attack vectors while dynamically isolating novel, unseen (zero-day) network anomalies through a SOC-style interactive dashboard.

---

## 🚀 Key Features

* **Dual-Engine Fusion Architecture:**
  * **Supervised Engine (Random Forest):** Detects signature-driven known attacks (e.g., DDoS SYN Floods, Stealthy PortScans) with high precision.
  * **Unsupervised Engine (Isolation Forest):** Evaluates anomaly density and flags zero-day threats or abnormal exfiltration behaviors based on outlier scoring.
* **Live Flow Inspector (Sandbox):** An interactive attack simulation module allowing security analysts and evaluators to manually trigger real-world traffic flows and evaluate instant classification results.
* **Real-Time PCAP Stream Ingestor:** Built-in stream simulator processing continuous network packet flows at 10–20 flows/second to demonstrate low-latency pipeline performance.
* **Interactive ML Controls:** Dynamic sidebar controls to adjust Isolation Forest contamination percentages (`IF Sensitivity`) and Random Forest confidence cutoffs on-the-fly.
* **Flexible Ingestion:** Zero-config synthetic dataset fallback generator along with full support for uploading custom CIC-IDS2017 compatible CSV datasets.

---

## 🏗️ System Architecture
