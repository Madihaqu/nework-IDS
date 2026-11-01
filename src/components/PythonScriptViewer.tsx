import React, { useState } from 'react';
import { Copy, Check, Download, Terminal, BookOpen, Code, FileText } from 'lucide-react';

const PYTHON_CODE = `"""
================================================================================
HYBRID NETWORK INTRUSION DETECTION SYSTEM (NIDS)
CSE Capstone Project Prototype
================================================================================
Architecture:
  1. Supervised Classification: Random Forest Classifier (for Known Attacks)
  2. Unsupervised Anomaly Detection: Isolation Forest (for Unknown/Zero-Day Attacks)
  3. Decision Fusion Engine: Hierarchical rule-based fusion with confidence thresholding

How to run locally:
  $ pip install -r requirements.txt
  $ streamlit run app.py
================================================================================
"""

import streamlit as st
import pandas as pd
import numpy as np
import time
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import plotly.express as px
import plotly.graph_objects as go
from sklearn.decomposition import PCA

# -----------------------------------------------------------------------------
# 1. PAGE CONFIGURATION & STYLING
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Hybrid NIDS | CSE Capstone",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .metric-card {
        background-color: #1E293B;
        border-radius: 8px;
        padding: 16px;
        border-left: 4px solid #3B82F6;
        margin-bottom: 12px;
    }
    .metric-card h3 {
        margin: 0;
        font-size: 0.85rem;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .metric-card p {
        margin: 4px 0 0 0;
        font-size: 1.8rem;
        font-weight: 700;
        color: #F8FAFC;
    }
    .stAlert {
        border-radius: 6px;
    }
</style>
""", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# 2. DATA PIPELINE WITH FALLBACK SYNTHETIC GENERATOR
# -----------------------------------------------------------------------------
FEATURE_COLS = [
    "flow_duration_ms",
    "total_fwd_packets",
    "total_bwd_packets",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "flow_bytes_per_sec",
    "flow_pkts_per_sec",
    "fwd_iat_mean",
    "bwd_iat_mean",
    "syn_flag_count",
    "ack_flag_count",
    "avg_packet_size"
]

@st.cache_data(show_spinner=False)
def generate_synthetic_cicids_dataset(n_samples: int = 3500, random_seed: int = 42) -> pd.DataFrame:
    """
    Generates a realistic synthetic network flow dataset patterned after CIC-IDS2017.
    Classes generated:
      - BENIGN (~65%): Balanced flows, moderate duration, standard HTTP/HTTPS packet sizes.
      - DDoS (~15%): Massive flow_pkts_per_sec, small packet sizes, skewed Fwd/Bwd packets.
      - PortScan (~12%): Very short duration, 1-2 packets, SYN flags set, 0/low Bwd packets.
      - Unseen_Attack (~8%): Novel anomalies (e.g. DNS exfiltration / covert timing patterns)
                           with out-of-distribution IAT and abnormal payload ratios.
    """
    np.random.seed(random_seed)
    
    n_benign = int(n_samples * 0.65)
    n_ddos = int(n_samples * 0.15)
    n_portscan = int(n_samples * 0.12)
    n_unseen = n_samples - (n_benign + n_ddos + n_portscan)

    records = []

    # 1. BENIGN FLOWS
    for _ in range(n_benign):
        duration = np.random.exponential(scale=1200) + 50
        fwd_pkts = int(np.random.poisson(lam=8) + 1)
        bwd_pkts = int(np.random.poisson(lam=10) + 1)
        fwd_mean = np.random.normal(loc=320, scale=80)
        bwd_mean = np.random.normal(loc=650, scale=120)
        total_bytes = (fwd_pkts * fwd_mean) + (bwd_pkts * bwd_mean)
        
        records.append({
            "flow_duration_ms": max(duration, 10.0),
            "total_fwd_packets": fwd_pkts,
            "total_bwd_packets": bwd_pkts,
            "fwd_pkt_len_mean": max(fwd_mean, 40.0),
            "bwd_pkt_len_mean": max(bwd_mean, 40.0),
            "flow_bytes_per_sec": max((total_bytes / (duration / 1000.0)), 100.0),
            "flow_pkts_per_sec": max(((fwd_pkts + bwd_pkts) / (duration / 1000.0)), 1.0),
            "fwd_iat_mean": np.random.exponential(scale=120) + 10,
            "bwd_iat_mean": np.random.exponential(scale=110) + 10,
            "syn_flag_count": np.random.choice([0, 1], p=[0.7, 0.3]),
            "ack_flag_count": np.random.choice([0, 1], p=[0.1, 0.9]),
            "avg_packet_size": (total_bytes / max(fwd_pkts + bwd_pkts, 1)),
            "true_label": "BENIGN"
        })

    # 2. DDOS (High frequency, overwhelming packet rate, small packets, asymmetric)
    for _ in range(n_ddos):
        duration = np.random.uniform(20, 400)
        fwd_pkts = int(np.random.uniform(150, 600))
        bwd_pkts = int(np.random.choice([0, 1, 2], p=[0.7, 0.2, 0.1]))
        fwd_mean = np.random.uniform(54, 80)
        bwd_mean = 40.0 if bwd_pkts > 0 else 0.0
        total_bytes = (fwd_pkts * fwd_mean) + (bwd_pkts * bwd_mean)

        records.append({
            "flow_duration_ms": duration,
            "total_fwd_packets": fwd_pkts,
            "total_bwd_packets": bwd_pkts,
            "fwd_pkt_len_mean": fwd_mean,
            "bwd_pkt_len_mean": bwd_mean,
            "flow_bytes_per_sec": (total_bytes / (duration / 1000.0)),
            "flow_pkts_per_sec": ((fwd_pkts + bwd_pkts) / (duration / 1000.0)),
            "fwd_iat_mean": np.random.uniform(0.1, 3.0),
            "bwd_iat_mean": 0.0,
            "syn_flag_count": 1,
            "ack_flag_count": 0,
            "avg_packet_size": total_bytes / max(fwd_pkts + bwd_pkts, 1),
            "true_label": "DDoS"
        })

    # 3. PORTSCAN (Extremely fast, 1-2 packets, SYN flags, probe responses)
    for _ in range(n_portscan):
        duration = np.random.uniform(1.0, 15.0)
        fwd_pkts = int(np.random.choice([1, 2, 3], p=[0.8, 0.15, 0.05]))
        bwd_pkts = int(np.random.choice([0, 1], p=[0.85, 0.15]))
        fwd_mean = np.random.uniform(40, 60)
        bwd_mean = 40.0 if bwd_pkts > 0 else 0.0
        total_bytes = (fwd_pkts * fwd_mean) + (bwd_pkts * bwd_mean)

        records.append({
            "flow_duration_ms": duration,
            "total_fwd_packets": fwd_pkts,
            "total_bwd_packets": bwd_pkts,
            "fwd_pkt_len_mean": fwd_mean,
            "bwd_pkt_len_mean": bwd_mean,
            "flow_bytes_per_sec": (total_bytes / (duration / 1000.0)),
            "flow_pkts_per_sec": ((fwd_pkts + bwd_pkts) / (duration / 1000.0)),
            "fwd_iat_mean": np.random.uniform(0.2, 5.0),
            "bwd_iat_mean": 0.0,
            "syn_flag_count": 1,
            "ack_flag_count": 0,
            "avg_packet_size": total_bytes / max(fwd_pkts + bwd_pkts, 1),
            "true_label": "PortScan"
        })

    # 4. UNSEEN / ZERO-DAY ATTACK (Covert exfiltration / weird tunneling)
    for _ in range(n_unseen):
        duration = np.random.uniform(5000, 18000)
        fwd_pkts = int(np.random.uniform(40, 120))
        bwd_pkts = int(np.random.uniform(5, 25))
        fwd_mean = np.random.uniform(1100, 1480)
        bwd_mean = np.random.uniform(60, 90)
        total_bytes = (fwd_pkts * fwd_mean) + (bwd_pkts * bwd_mean)

        records.append({
            "flow_duration_ms": duration,
            "total_fwd_packets": fwd_pkts,
            "total_bwd_packets": bwd_pkts,
            "fwd_pkt_len_mean": fwd_mean,
            "bwd_pkt_len_mean": bwd_mean,
            "flow_bytes_per_sec": (total_bytes / (duration / 1000.0)),
            "flow_pkts_per_sec": ((fwd_pkts + bwd_pkts) / (duration / 1000.0)),
            "fwd_iat_mean": np.random.uniform(350, 900),
            "bwd_iat_mean": np.random.uniform(400, 1200),
            "syn_flag_count": 0,
            "ack_flag_count": 1,
            "avg_packet_size": total_bytes / max(fwd_pkts + bwd_pkts, 1),
            "true_label": "Unseen_Attack"
        })

    df = pd.DataFrame(records).sample(frac=1.0, random_state=random_seed).reset_index(drop=True)
    return df


def load_dataset(uploaded_file, file_path="cicids2017_sample.csv", n_synthetic=3000, seed=42):
    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            st.success("Successfully loaded uploaded CSV dataset!")
            return df, "Uploaded CSV"
        except Exception as e:
            st.warning(f"Failed to parse uploaded CSV: {e}. Falling back to synthetic dataset.")

    try:
        df = pd.read_csv(file_path)
        st.info(f"Loaded dataset from local path: '{file_path}'")
        return df, f"Local CSV ({file_path})"
    except FileNotFoundError:
        df = generate_synthetic_cicids_dataset(n_samples=n_synthetic, random_seed=seed)
        return df, "Synthetic CIC-IDS2017 (Auto-Generated Fallback)"
    except Exception as e:
        st.warning(f"Error reading local file: {e}. Using synthetic fallback.")
        df = generate_synthetic_cicids_dataset(n_samples=n_synthetic, random_seed=seed)
        return df, "Synthetic CIC-IDS2017 (Auto-Generated Fallback)"


# -----------------------------------------------------------------------------
# 3. MODEL TRAINING & DECISION FUSION LOGIC
# -----------------------------------------------------------------------------
def train_hybrid_models(df: pd.DataFrame, if_contamination: float = 0.08, rf_n_estimators: int = 100):
    scaler = StandardScaler()
    
    # Split known vs unknown
    known_mask = df["true_label"].isin(["BENIGN", "DDoS", "PortScan"])
    df_known = df[known_mask].copy()
    
    X_known = df_known[FEATURE_COLS]
    y_known = df_known["true_label"]

    X_train_k, X_val_k, y_train_k, y_val_k = train_test_split(
        X_known, y_known, test_size=0.25, random_state=42, stratify=y_known
    )

    # Scale features
    scaler.fit(X_train_k)
    X_train_k_scaled = scaler.transform(X_train_k)

    # 1. Supervised Model (Random Forest)
    rf_model = RandomForestClassifier(
        n_estimators=rf_n_estimators,
        max_depth=12,
        random_state=42,
        class_weight="balanced"
    )
    rf_model.fit(X_train_k_scaled, y_train_k)

    # 2. Unsupervised Model (Isolation Forest)
    benign_train = X_train_k_scaled[y_train_k == "BENIGN"]
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=if_contamination,
        random_state=42
    )
    iso_forest.fit(benign_train)

    return rf_model, iso_forest, scaler


def run_decision_fusion(
    df_test: pd.DataFrame,
    rf_model: RandomForestClassifier,
    iso_forest: IsolationForest,
    scaler: StandardScaler,
    rf_confidence_threshold: float = 0.70
) -> pd.DataFrame:
    results_df = df_test.copy()
    X_scaled = scaler.transform(df_test[FEATURE_COLS])

    rf_preds = rf_model.predict(X_scaled)
    rf_probas = rf_model.predict_proba(X_scaled)
    rf_classes = list(rf_model.classes_)
    
    if_preds = iso_forest.predict(X_scaled)
    if_scores = iso_forest.decision_function(X_scaled)

    final_decisions = []
    confidence_scores = []
    flagged_reasons = []

    for i in range(len(df_test)):
        pred_label = rf_preds[i]
        class_idx = rf_classes.index(pred_label)
        confidence = rf_probas[i][class_idx]
        is_anomaly = (if_preds[i] == -1)
        score = if_scores[i]

        confidence_scores.append(confidence)

        if pred_label in ["DDoS", "PortScan"] and confidence >= rf_confidence_threshold:
            final_decisions.append("Known Attack")
            flagged_reasons.append(f"Supervised RF: {pred_label} ({confidence:.1%})")
        elif pred_label == "BENIGN":
            if is_anomaly:
                final_decisions.append("Potential Unknown/Anomalous Attack")
                flagged_reasons.append(f"Zero-Day Anomaly (IF Score: {score:.3f})")
            else:
                final_decisions.append("Normal")
                flagged_reasons.append("Verified Normal Traffic")
        else:
            if is_anomaly:
                final_decisions.append("Potential Unknown/Anomalous Attack")
                flagged_reasons.append(f"Uncertain Signature ({confidence:.1%}) + Outlier")
            else:
                final_decisions.append("Known Attack")
                flagged_reasons.append(f"Supervised RF: {pred_label} ({confidence:.1%})")

    results_df["rf_predicted"] = rf_preds
    results_df["rf_confidence"] = confidence_scores
    results_df["if_anomaly"] = if_preds
    results_df["if_score"] = if_scores
    results_df["hybrid_decision"] = final_decisions
    results_df["fusion_reason"] = flagged_reasons

    return results_df


# -----------------------------------------------------------------------------
# 4. STREAMLIT APPLICATION DASHBOARD
# -----------------------------------------------------------------------------
def main():
    st.title("🛡️ Hybrid Network Intrusion Detection System (NIDS)")
    st.markdown(
        "**CSE Capstone Project Prototype** | Dual-Engine Defense: "
        "\`Supervised Classification (Random Forest)\` + \`Unsupervised Anomaly Detection (Isolation Forest)\`"
    )

    st.sidebar.header("⚙️ Configuration & Controls")
    uploaded_file = st.sidebar.file_uploader("Upload Network CSV (Optional)", type=["csv"])
    n_samples = st.sidebar.slider("Synthetic Dataset Size", min_value=1000, max_value=8000, value=3000, step=500)
    data_seed = st.sidebar.number_input("Random Seed", min_value=1, max_value=9999, value=42)

    df_raw, data_source = load_dataset(uploaded_file, file_path="cicids2017_sample.csv", n_synthetic=n_samples, seed=data_seed)
    
    st.sidebar.info(f"Data Source: **{data_source}** ({len(df_raw)} records)")

    if_contamination = st.sidebar.slider(
        "Isolation Forest Contamination", min_value=0.01, max_value=0.25, value=0.08, step=0.01
    )
    rf_confidence_threshold = st.sidebar.slider(
        "RF Attack Confidence Threshold", min_value=0.50, max_value=0.95, value=0.70, step=0.05
    )
    rf_trees = st.sidebar.selectbox("Random Forest Trees", options=[50, 100, 150], index=1)

    with st.spinner("Training Random Forest & Isolation Forest with Decision Fusion..."):
        rf_model, iso_forest, scaler = train_hybrid_models(
            df_raw, if_contamination=if_contamination, rf_n_estimators=rf_trees
        )
        df_results = run_decision_fusion(
            df_raw, rf_model, iso_forest, scaler, rf_confidence_threshold=rf_confidence_threshold
        )

    # Metrics
    total_packets = len(df_results)
    known_attacks = len(df_results[df_results["hybrid_decision"] == "Known Attack"])
    anomalies_flagged = len(df_results[df_results["hybrid_decision"] == "Potential Unknown/Anomalous Attack"])
    normal_flows = len(df_results[df_results["hybrid_decision"] == "Normal"])

    unseen_total = len(df_results[df_results["true_label"] == "Unseen_Attack"])
    unseen_caught = len(df_results[
        (df_results["true_label"] == "Unseen_Attack") & 
        (df_results["hybrid_decision"] == "Potential Unknown/Anomalous Attack")
    ])
    zero_day_capture_rate = (unseen_caught / unseen_total * 100) if unseen_total > 0 else 0.0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Flows", f"{total_packets:,}")
    col2.metric("Known Attacks", f"{known_attacks:,}")
    col3.metric("Anomalies Flagged", f"{anomalies_flagged:,}")
    col4.metric("Zero-Day Capture Rate", f"{zero_day_capture_rate:.1f}%")

    tab1, tab2 = st.tabs(["📊 Analytics", "🚨 Flagged Flows"])
    with tab1:
        st.subheader("Decision Breakdown")
        fig = px.pie(df_results, names="hybrid_decision", color="hybrid_decision",
                     color_discrete_map={"Normal": "#10B981", "Known Attack": "#EF4444", "Potential Unknown/Anomalous Attack": "#F59E0B"})
        st.plotly_chart(fig, use_container_width=True)

    with tab2:
        st.dataframe(df_results[df_results["hybrid_decision"] != "Normal"], use_container_width=True)

if __name__ == "__main__":
    main()
`;

const REQUIREMENTS_TXT = `streamlit>=1.35.0
pandas>=2.0.0
numpy>=1.24.0
scikit-learn>=1.3.0
plotly>=5.18.0
`;

export const PythonScriptViewer: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<'app.py' | 'requirements.txt' | 'guide'>('app.py');
  const [copied, setCopied] = useState<boolean>(false);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header and Download Bar */}
      <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h3 className="font-semibold text-sm text-slate-100 flex items-center gap-2">
            <Code className="w-4 h-4 text-emerald-400" />
            Complete Python Streamlit Script (app.py) & Local Setup
          </h3>
          <p className="text-xs text-slate-400">
            Executable Python script with robust fallback data generator, Random Forest, Isolation Forest, and Streamlit dashboard.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => handleCopy(activeSubTab === 'app.py' ? PYTHON_CODE : REQUIREMENTS_TXT)}
            className="py-1.5 px-3 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-1.5 text-xs font-medium transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? 'Copied to Clipboard!' : 'Copy Code'}
          </button>

          <button
            onClick={() => handleDownload(PYTHON_CODE, 'app.py')}
            className="py-1.5 px-3 rounded bg-blue-600 hover:bg-blue-500 text-white flex items-center gap-1.5 text-xs font-medium transition-colors shadow-lg shadow-blue-600/20"
          >
            <Download className="w-3.5 h-3.5" />
            Download app.py
          </button>

          <button
            onClick={() => handleDownload(REQUIREMENTS_TXT, 'requirements.txt')}
            className="py-1.5 px-3 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-1.5 text-xs font-medium transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-slate-400" />
            Download requirements.txt
          </button>
        </div>
      </div>

      {/* Sub Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveSubTab('app.py')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
            activeSubTab === 'app.py'
              ? 'bg-blue-600/20 text-blue-300 border border-blue-500/40'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
          }`}
        >
          <Code className="w-3.5 h-3.5" />
          app.py (Streamlit Script)
        </button>

        <button
          onClick={() => setActiveSubTab('requirements.txt')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
            activeSubTab === 'requirements.txt'
              ? 'bg-blue-600/20 text-blue-300 border border-blue-500/40'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          requirements.txt
        </button>

        <button
          onClick={() => setActiveSubTab('guide')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
            activeSubTab === 'guide'
              ? 'bg-blue-600/20 text-blue-300 border border-blue-500/40'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          Execution Guide & Capstone Notes
        </button>
      </div>

      {/* Code Display Area */}
      {activeSubTab === 'app.py' && (
        <div className="relative rounded-xl bg-slate-950 border border-slate-800 overflow-hidden">
          <div className="px-4 py-2 bg-slate-900 border-b border-slate-800 flex justify-between items-center text-xs text-slate-400">
            <span className="font-mono text-slate-300">app.py — 420 lines</span>
            <span className="text-[11px]">Python 3.9+ / Streamlit 1.35+</span>
          </div>
          <pre className="p-4 text-xs font-mono text-slate-300 overflow-x-auto max-h-[600px] leading-relaxed">
            {PYTHON_CODE}
          </pre>
        </div>
      )}

      {activeSubTab === 'requirements.txt' && (
        <div className="relative rounded-xl bg-slate-950 border border-slate-800 overflow-hidden">
          <div className="px-4 py-2 bg-slate-900 border-b border-slate-800 text-xs font-mono text-slate-300">
            requirements.txt
          </div>
          <pre className="p-4 text-xs font-mono text-slate-300 leading-relaxed">
            {REQUIREMENTS_TXT}
          </pre>
        </div>
      )}

      {activeSubTab === 'guide' && (
        <div className="space-y-6">
          {/* Quickstart Terminal Card */}
          <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
            <h4 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              How to Run Locally on Your Machine
            </h4>

            <div className="space-y-3 text-xs">
              <div>
                <p className="text-slate-300 font-medium mb-1">1. Create a Python Virtual Environment:</p>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-emerald-400">
                  python3 -m venv nids-env<br />
                  source nids-env/bin/activate  # On Windows: nids-env\Scripts\activate
                </div>
              </div>

              <div>
                <p className="text-slate-300 font-medium mb-1">2. Install Dependencies:</p>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-emerald-400">
                  pip install -r requirements.txt
                </div>
              </div>

              <div>
                <p className="text-slate-300 font-medium mb-1">3. Launch Streamlit Dashboard:</p>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-emerald-400">
                  streamlit run app.py
                </div>
              </div>

              <div className="p-3 rounded bg-blue-950/20 border border-blue-500/30 text-blue-300">
                💡 <strong>Out-of-the-Box Execution:</strong> When you run <code>streamlit run app.py</code>, it checks for <code>cicids2017_sample.csv</code>. If not found, it automatically invokes the realistic synthetic generator so the entire app starts instantly with 3,000 clean records!
              </div>
            </div>
          </div>

          {/* Capstone Defense Presentation Guide */}
          <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
            <h4 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <BookOpen className="w-4 h-4 text-amber-400" />
              CSE Capstone Defense & Presentation Talking Points
            </h4>

            <div className="space-y-3 text-xs text-slate-300">
              <div className="p-3 rounded bg-slate-950 border border-slate-800">
                <strong className="text-slate-100">Why a Hybrid Architecture instead of just Random Forest?</strong>
                <p className="text-slate-400 mt-1">
                  Supervised classifiers like Random Forest or XGBoost rely on labeled historical attack signatures. If an attacker crafts a zero-day exploit or covert tunnel with abnormal payload patterns never seen in training data, the supervised model will falsely classify it as BENIGN. The unsupervised Isolation Forest provides a second tier of protection by flagging any flow that deviates from the normal operational baseline.
                </p>
              </div>

              <div className="p-3 rounded bg-slate-950 border border-slate-800">
                <strong className="text-slate-100">Why not use ONLY Isolation Forest?</strong>
                <p className="text-slate-400 mt-1">
                  Standalone anomaly detection produces high false alarm rates on dynamic enterprise networks and cannot classify the specific attack type (e.g. DDoS vs PortScan). The Hybrid NIDS provides the best of both worlds: known attacks get precise signature labels and automated mitigation rules, while novel anomalies get escalated to human SOC analysts.
                </p>
              </div>

              <div className="p-3 rounded bg-slate-950 border border-slate-800">
                <strong className="text-slate-100">Mathematical Formulation of Decision Fusion:</strong>
                <p className="text-slate-400 mt-1 font-mono text-[11px]">
                  Decision(x) = Known Attack, if RF(x) in (DDoS, PortScan) and Conf(x) &gt;= tau<br />
                  Decision(x) = Unknown Anomaly, if RF(x) == BENIGN and IF_Score(x) &lt; 0.0<br />
                  Decision(x) = Normal, if RF(x) == BENIGN and IF_Score(x) &gt;= 0.0
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
