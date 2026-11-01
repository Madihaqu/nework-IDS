# 🛡️ Hybrid NIDS: Dual-Engine Network Intrusion Detection System

[![React](https://img.shields.io/badge/React-19-blue.svg)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-8-646CFF.svg)](https://vitejs.dev/)
[![TailwindCSS](https://img.shields.io/badge/Tailwind-4-38B2AC.svg)](https://tailwindcss.com/)
[![Static Deployment](https://img.shields.io/badge/Deployment-Vercel%20%7C%20GitHub%20Pages-black.svg)](https://vercel.com/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red.svg)](https://streamlit.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An end-to-end, real-time **Hybrid Network Intrusion Detection System (NIDS)** combining **Supervised** and **Unsupervised Machine Learning** algorithms. The system classifies known signature-based attack vectors while dynamically isolating novel, unseen (zero-day) network anomalies through a SOC-style interactive dashboard.

This repository is built as a **100% static web application (React + Vite + Tailwind CSS)** that runs entirely in the user's browser—meaning it deploys directly to **Vercel** or **GitHub Pages** with **zero backend servers and zero build errors**. A complete standalone Python/Streamlit script (`app.py`) is also included.

---

## 🚀 Key Features

* **Dual-Engine Fusion Architecture:**
  * **Supervised Engine (Random Forest):** Detects signature-driven known attacks (e.g., DDoS SYN Floods, Stealthy PortScans) with high precision and confidence scoring.
  * **Unsupervised Engine (Isolation Forest):** Evaluates anomaly density and flags zero-day threats or abnormal exfiltration behaviors based on statistical outlier scoring ($s < 0.0$).
* **Decision Fusion Logic:**
  ```text
  if RF_Confidence(Known_Attack) >= Threshold:
      Output: 'Known Attack' (High-Confidence Signature Match)
  elif RF_Prediction == 'BENIGN':
      if IsolationForest.is_anomaly():
          Output: 'Potential Unknown/Anomalous Attack' (Zero-Day Alert!)
      else:
          Output: 'Normal' (Verified Baseline Profile)
  else:
      if IsolationForest.is_anomaly():
          Output: 'Potential Unknown/Anomalous Attack' (Outlier Escalation)
      else:
          Output: 'Known Attack'
  ```
* **Interactive Live Flow Inspector (Sandbox):** Test attack scenarios (`DDoS SYN Flood`, `Stealthy PortScan`, `Zero-Day Exfiltration`, `Slowloris Keep-Alive Probe`, `Normal HTTPS Session`) with customizable flow timing, packet lengths, and flags.
* **Real-Time PCAP Stream Ingestor:** Built-in stream simulator processing continuous network packet flows at **10–20 flows/second** with live rolling throughput charts.
* **Client-Side CSV Upload & Ingestion:** Full support for uploading custom CIC-IDS2017 schema CSV files via browser `FileReader`, along with a 1-click **Download Sample CSV** generator.
* **SOC Telemetry & Visualizations:**
  * Rolling Traffic Velocity Timeline (Packets/s over time).
  * Decision Breakdown Donut Chart.
  * Isolation Forest Anomaly Score Distribution Histogram with interactive cutoff line ($0.0$).
  * Random Forest Feature Importance Rankings.
  * 2D PCA Cluster Space Representation.
  * Ground Truth vs Decision Confusion Matrix.

---

## 📦 Static Deployment (Vercel & GitHub Pages)

### Option 1: Deploy to Vercel (Instant)
1. Push this repository to GitHub.
2. Go to [vercel.com/new](https://vercel.com/new) and import your repo.
3. Vercel automatically detects the Vite configuration (`npm run build` &rarr; `dist`).
4. Click **Deploy**. Done!

### Option 2: Deploy to GitHub Pages (Automated via GitHub Actions)
A pre-configured GitHub Actions workflow is included in `.github/workflows/deploy.yml`:
1. Push your repository to GitHub.
2. In your GitHub repository, navigate to **Settings** &rarr; **Pages**.
3. Under **Build and deployment** &rarr; **Source**, select **GitHub Actions**.
4. Push a commit or trigger the workflow manually under the **Actions** tab.
5. In ~1 minute, your site will be live at `https://<username>.github.io/<repo-name>/`.

---

## 🛠️ Local Development & Build Commands

```bash
# 1. Install dependencies
npm install

# 2. Run local development server
npm run dev

# 3. Build production static bundle (to /dist)
npm run build

# 4. Preview the exact static production build locally
npm run preview
```

---

## 🐍 Standalone Python / Streamlit Version (Optional)

If you wish to run the prototype locally with Python & Streamlit:

```bash
# 1. Create and activate a virtual environment
python3 -m venv nids-env
source nids-env/bin/activate  # On Windows: nids-env\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch the Streamlit dashboard
streamlit run app.py
```
