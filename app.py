"""
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
    # Designed with abnormal stats: very large packet sizes, unusual jitter, high IAT
    for _ in range(n_unseen):
        duration = np.random.uniform(5000, 18000)
        fwd_pkts = int(np.random.uniform(40, 120))
        bwd_pkts = int(np.random.uniform(5, 25))
        fwd_mean = np.random.uniform(1100, 1480) # abnormally high payload chunks
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
            "fwd_iat_mean": np.random.uniform(350, 900), # erratic slow heartbeat
            "bwd_iat_mean": np.random.uniform(400, 1200),
            "syn_flag_count": 0,
            "ack_flag_count": 1,
            "avg_packet_size": total_bytes / max(fwd_pkts + bwd_pkts, 1),
            "true_label": "Unseen_Attack"
        })

    df = pd.DataFrame(records).sample(frac=1.0, random_state=random_seed).reset_index(drop=True)
    return df


def load_dataset(uploaded_file, file_path="cicids2017_sample.csv", n_synthetic=3000, seed=42):
    """
    Robust dataset loading pipeline:
    1. Attempts to read user-uploaded CSV.
    2. Falls back to local CSV file if path exists.
    3. If neither is available or valid, falls back to realistic synthetic generator.
    """
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
    """
    Trains:
      1. Supervised Random Forest: Only trained on KNOWN labels ('BENIGN', 'DDoS', 'PortScan').
         Crucially, 'Unseen_Attack' is excluded from training so it represents true zero-day traffic.
      2. Unsupervised Isolation Forest: Trained on baseline BENIGN traffic to learn the normal baseline envelope.
    """
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
    # Train Isolation Forest on normal/benign traffic to establish the normal operational baseline
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
    """
    Decision Fusion Engine:
    Combines outputs of Supervised Classifier and Unsupervised Anomaly Detector.

    Rules:
      - If RF predicts a known attack (DDoS, PortScan) with confidence >= threshold:
          => Categorized as 'Known Attack'
      - If RF predicts BENIGN:
          - If Isolation Forest flags anomaly (prediction == -1):
              => Categorized as 'Potential Unknown/Anomalous Attack' (Zero-Day threat)
          - If Isolation Forest flags normal (prediction == 1):
              => Categorized as 'Normal'
      - If RF predicts Known Attack but confidence is below threshold AND IF flags anomaly:
          => Categorized as 'Potential Unknown/Anomalous Attack'
      - Else:
          => Follows RF prediction ('Normal' or 'Known Attack')
    """
    results_df = df_test.copy()
    X_scaled = scaler.transform(df_test[FEATURE_COLS])

    # Supervised predictions & probabilities
    rf_preds = rf_model.predict(X_scaled)
    rf_probas = rf_model.predict_proba(X_scaled)
    rf_classes = list(rf_model.classes_)
    
    # Isolation forest anomaly detection
    # -1 = anomaly, 1 = normal
    if_preds = iso_forest.predict(X_scaled)
    # Lower score = more anomalous. Standardized decision_function.
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
            # Low confidence known attack
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
    # Header & Project Info
    st.title("🛡️ Hybrid Network Intrusion Detection System (NIDS)")
    st.markdown(
        "**CSE Capstone Project Prototype** | Dual-Engine Defense: "
        "`Supervised Classification (Random Forest)` + `Unsupervised Anomaly Detection (Isolation Forest)`"
    )
    st.caption("Designed to capture both high-confidence known attacks and novel zero-day threats through Decision Fusion.")

    # Sidebar Controls
    st.sidebar.header("⚙️ Configuration & Controls")
    
    # Dataset Selection
    st.sidebar.subheader("1. Data Ingestion Pipeline")
    uploaded_file = st.sidebar.file_uploader("Upload Network CSV (Optional)", type=["csv"])
    n_samples = st.sidebar.slider("Synthetic Dataset Size", min_value=1000, max_value=8000, value=3000, step=500)
    data_seed = st.sidebar.number_input("Random Seed", min_value=1, max_value=9999, value=42)

    # Load data
    df_raw, data_source = load_dataset(uploaded_file, file_path="cicids2017_sample.csv", n_synthetic=n_samples, seed=data_seed)
    
    st.sidebar.info(f"Data Source: **{data_source}** ({len(df_raw)} records)")

    # Model Hyperparameters
    st.sidebar.subheader("2. Model Hyperparameters")
    if_contamination = st.sidebar.slider(
        "Isolation Forest Contamination (Sensitivity)",
        min_value=0.01,
        max_value=0.25,
        value=0.08,
        step=0.01,
        help="Estimated proportion of anomalies in baseline traffic. Higher = more sensitive."
    )
    
    rf_confidence_threshold = st.sidebar.slider(
        "RF Attack Confidence Threshold",
        min_value=0.50,
        max_value=0.95,
        value=0.70,
        step=0.05,
        help="Confidence cutoff required to accept a known attack classification without anomaly escalation."
    )

    rf_trees = st.sidebar.selectbox("Random Forest Trees (n_estimators)", options=[50, 100, 150], index=1)

    # Run Models Button / Cache
    with st.spinner("Training Random Forest & Isolation Forest with Decision Fusion..."):
        rf_model, iso_forest, scaler = train_hybrid_models(
            df_raw,
            if_contamination=if_contamination,
            rf_n_estimators=rf_trees
        )
        
        # Test the entire dataset through the hybrid fusion pipeline
        df_results = run_decision_fusion(
            df_raw,
            rf_model,
            iso_forest,
            scaler,
            rf_confidence_threshold=rf_confidence_threshold
        )

    # -------------------------------------------------------------------------
    # METRICS SUMMARY CARDS
    # -------------------------------------------------------------------------
    total_packets = len(df_results)
    known_attacks = len(df_results[df_results["hybrid_decision"] == "Known Attack"])
    anomalies_flagged = len(df_results[df_results["hybrid_decision"] == "Potential Unknown/Anomalous Attack"])
    normal_flows = len(df_results[df_results["hybrid_decision"] == "Normal"])

    # Capstone verification metric against Ground Truth (including Unseen)
    unseen_total = len(df_results[df_results["true_label"] == "Unseen_Attack"])
    unseen_caught = len(df_results[
        (df_results["true_label"] == "Unseen_Attack") & 
        (df_results["hybrid_decision"] == "Potential Unknown/Anomalous Attack")
    ])
    zero_day_capture_rate = (unseen_caught / unseen_total * 100) if unseen_total > 0 else 0.0

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""
        <div class="metric-card" style="border-left-color: #3B82F6;">
            <h3>Total Flows Analyzed</h3>
            <p>{total_packets:,}</p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card" style="border-left-color: #EF4444;">
            <h3>Known Attacks Detected</h3>
            <p>{known_attacks:,}</p>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card" style="border-left-color: #F59E0B;">
            <h3>Anomalies Flagged (Zero-Day)</h3>
            <p>{anomalies_flagged:,}</p>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card" style="border-left-color: #10B981;">
            <h3>Zero-Day Capture Rate</h3>
            <p>{zero_day_capture_rate:.1f}%</p>
        </div>
        """, unsafe_allow_html=True)

    # -------------------------------------------------------------------------
    # TABS: DASHBOARD OVERVIEW, CHARTS, AND FLAGGED FLOWS TABLE
    # -------------------------------------------------------------------------
    tab_analytics, tab_table, tab_simulation, tab_report = st.tabs([
        "📊 Detection Analytics",
        "🚨 Malicious & Anomalous Flows",
        "⚡ Live Flow Inspector",
        "📑 Capstone Architecture & Report"
    ])

    # TAB 1: VISUAL ANALYTICS
    with tab_analytics:
        col_c1, col_c2 = st.columns([1, 1])

        with col_c1:
            st.subheader("Decision Breakdown")
            decision_counts = df_results["hybrid_decision"].value_counts().reset_index()
            decision_counts.columns = ["Decision", "Count"]
            
            color_map = {
                "Normal": "#10B981",
                "Known Attack": "#EF4444",
                "Potential Unknown/Anomalous Attack": "#F59E0B"
            }
            
            fig_pie = px.pie(
                decision_counts,
                names="Decision",
                values="Count",
                color="Decision",
                color_discrete_map=color_map,
                hole=0.45,
            )
            fig_pie.update_layout(
                margin=dict(l=10, r=10, t=20, b=20),
                legend=dict(orientation="h", yanchor="bottom", y=-0.2)
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        with col_c2:
            st.subheader("Random Forest Feature Importances")
            importances = pd.DataFrame({
                "Feature": FEATURE_COLS,
                "Importance": rf_model.feature_importances_
            }).sort_values(by="Importance", ascending=True)

            fig_bar = px.bar(
                importances,
                x="Importance",
                y="Feature",
                orientation="h",
                color="Importance",
                color_continuous_scale="Viridis"
            )
            fig_bar.update_layout(margin=dict(l=10, r=10, t=20, b=20))
            st.plotly_chart(fig_bar, use_container_width=True)

        st.markdown("---")
        
        col_c3, col_c4 = st.columns([1, 1])

        with col_c3:
            st.subheader("Isolation Forest Anomaly Scores")
            st.caption("Scores < 0 indicate anomalous / out-of-distribution traffic.")
            fig_hist = px.histogram(
                df_results,
                x="if_score",
                color="hybrid_decision",
                color_discrete_map=color_map,
                nbins=40,
                opacity=0.8,
                labels={"if_score": "Isolation Forest Decision Score"}
            )
            fig_hist.add_vline(x=0.0, line_dash="dash", line_color="red", annotation_text="Anomaly Threshold (0.0)")
            fig_hist.update_layout(margin=dict(l=10, r=10, t=20, b=20), barmode="overlay")
            st.plotly_chart(fig_hist, use_container_width=True)

        with col_c4:
            st.subheader("2D PCA Feature Space Representation")
            st.caption("PCA projection showing clustering of normal vs known vs novel attacks.")
            X_scaled_all = scaler.transform(df_results[FEATURE_COLS])
            pca = PCA(n_components=2)
            coords = pca.fit_transform(X_scaled_all)
            
            df_pca = pd.DataFrame({
                "PCA1": coords[:, 0],
                "PCA2": coords[:, 1],
                "Hybrid Decision": df_results["hybrid_decision"],
                "Ground Truth": df_results["true_label"],
                "Packets/s": df_results["flow_pkts_per_sec"].round(1)
            })

            fig_pca = px.scatter(
                df_pca,
                x="PCA1",
                y="PCA2",
                color="Hybrid Decision",
                color_discrete_map=color_map,
                hover_data=["Ground Truth", "Packets/s"],
                opacity=0.75
            )
            fig_pca.update_layout(margin=dict(l=10, r=10, t=20, b=20))
            st.plotly_chart(fig_pca, use_container_width=True)

    # TAB 2: DATA TABLE OF FLAGGED FLOWS
    with tab_table:
        st.subheader("Flagged Malicious & Anomalous Network Flows")
        st.caption("Filter flows flagged by the Hybrid NIDS for Security Operations Center (SOC) investigation.")

        filter_option = st.radio(
            "Filter Traffic Type:",
            options=["Malicious & Anomalies Only", "Known Attacks Only", "Potential Unknown/Anomalous Only", "All Traffic"],
            horizontal=True
        )

        if filter_option == "Malicious & Anomalies Only":
            display_df = df_results[df_results["hybrid_decision"].isin(["Known Attack", "Potential Unknown/Anomalous Attack"])]
        elif filter_option == "Known Attacks Only":
            display_df = df_results[df_results["hybrid_decision"] == "Known Attack"]
        elif filter_option == "Potential Unknown/Anomalous Only":
            display_df = df_results[df_results["hybrid_decision"] == "Potential Unknown/Anomalous Attack"]
        else:
            display_df = df_results

        # Display columns
        show_cols = [
            "hybrid_decision", "fusion_reason", "rf_predicted", "rf_confidence",
            "if_score", "true_label", "flow_duration_ms", "flow_pkts_per_sec", "avg_packet_size"
        ]
        
        st.dataframe(
            display_df[show_cols].style.format({
                "rf_confidence": "{:.1%}",
                "if_score": "{:.3f}",
                "flow_duration_ms": "{:.1f}",
                "flow_pkts_per_sec": "{:.1f}",
                "avg_packet_size": "{:.1f}"
            }),
            use_container_width=True,
            height=420
        )

        # Export CSV
        csv_data = display_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Export Flagged Incidents (CSV)",
            data=csv_data,
            file_name="hybrid_nids_flagged_flows.csv",
            mime="text/csv"
        )

    # TAB 3: LIVE SINGLE-FLOW INSPECTOR
    with tab_simulation:
        st.subheader("⚡ Live Packet / Flow Inspector")
        st.write("Simulate a live packet flow arriving at the sensor and test the Decision Fusion Engine in real time:")

        col_s1, col_s2, col_s3 = st.columns(3)
        with col_s1:
            test_preset = st.selectbox(
                "Load Attack Preset Scenario:",
                options=["Custom Values", "DDoS SYN Flood", "Stealthy PortScan", "Zero-Day Exfiltration", "Normal HTTPS Session"]
            )

        # Preset logic
        if test_preset == "DDoS SYN Flood":
            p_duration, p_fwd_pkts, p_bwd_pkts = 150.0, 450, 0
            p_fwd_len, p_bwd_len = 64.0, 0.0
            p_syn, p_ack = 1, 0
        elif test_preset == "Stealthy PortScan":
            p_duration, p_fwd_pkts, p_bwd_pkts = 4.0, 1, 0
            p_fwd_len, p_bwd_len = 44.0, 0.0
            p_syn, p_ack = 1, 0
        elif test_preset == "Zero-Day Exfiltration":
            p_duration, p_fwd_pkts, p_bwd_pkts = 12000.0, 85, 12
            p_fwd_len, p_bwd_len = 1420.0, 64.0
            p_syn, p_ack = 0, 1
        elif test_preset == "Normal HTTPS Session":
            p_duration, p_fwd_pkts, p_bwd_pkts = 950.0, 10, 14
            p_fwd_len, p_bwd_len = 340.0, 720.0
            p_syn, p_ack = 0, 1
        else:
            p_duration, p_fwd_pkts, p_bwd_pkts = 800.0, 8, 8
            p_fwd_len, p_bwd_len = 250.0, 400.0
            p_syn, p_ack = 0, 1

        with col_s1:
            in_duration = st.number_input("Flow Duration (ms)", value=float(p_duration), min_value=0.1)
            in_fwd_pkts = st.number_input("Total Fwd Packets", value=int(p_fwd_pkts), min_value=1)
            in_bwd_pkts = st.number_input("Total Bwd Packets", value=int(p_bwd_pkts), min_value=0)
            in_fwd_len = st.number_input("Fwd Pkt Len Mean", value=float(p_fwd_len), min_value=0.0)

        with col_s2:
            in_bwd_len = st.number_input("Bwd Pkt Len Mean", value=float(p_bwd_len), min_value=0.0)
            tot_bytes = (in_fwd_pkts * in_fwd_len) + (in_bwd_pkts * in_bwd_len)
            tot_pkts = in_fwd_pkts + in_bwd_pkts
            computed_bps = tot_bytes / (in_duration / 1000.0)
            computed_pps = tot_pkts / (in_duration / 1000.0)
            
            st.metric("Flow Bytes/sec", f"{computed_bps:,.0f}")
            st.metric("Flow Packets/sec", f"{computed_pps:,.1f}")

        with col_s3:
            in_syn = st.selectbox("SYN Flag", options=[0, 1], index=int(p_syn))
            in_ack = st.selectbox("ACK Flag", options=[0, 1], index=int(p_ack))
            avg_size = tot_bytes / max(tot_pkts, 1)
            st.metric("Avg Packet Size", f"{avg_size:.1f} bytes")

        if st.button("🔍 Analyze Flow with Hybrid NIDS"):
            # Construct feature vector
            custom_flow = pd.DataFrame([{
                "flow_duration_ms": in_duration,
                "total_fwd_packets": in_fwd_pkts,
                "total_bwd_packets": in_bwd_pkts,
                "fwd_pkt_len_mean": in_fwd_len,
                "bwd_pkt_len_mean": in_bwd_len,
                "flow_bytes_per_sec": computed_bps,
                "flow_pkts_per_sec": computed_pps,
                "fwd_iat_mean": in_duration / max(in_fwd_pkts, 1),
                "bwd_iat_mean": (in_duration / max(in_bwd_pkts, 1)) if in_bwd_pkts > 0 else 0.0,
                "syn_flag_count": in_syn,
                "ack_flag_count": in_ack,
                "avg_packet_size": avg_size,
                "true_label": "Live_Probe"
            }])

            flow_res = run_decision_fusion(custom_flow, rf_model, iso_forest, scaler, rf_confidence_threshold)
            decision = flow_res["hybrid_decision"].iloc[0]
            reason = flow_res["fusion_reason"].iloc[0]
            rf_pred = flow_res["rf_predicted"].iloc[0]
            rf_conf = flow_res["rf_confidence"].iloc[0]
            if_s = flow_res["if_score"].iloc[0]

            st.markdown("### Detection Result")
            if decision == "Known Attack":
                st.error(f"🚨 **DECISION: {decision}** | {reason}")
            elif decision == "Potential Unknown/Anomalous Attack":
                st.warning(f"⚠️ **DECISION: {decision}** | {reason}")
            else:
                st.success(f"✅ **DECISION: {decision}** | {reason}")

            st.write(f"- **Supervised Classifier:** Predicted `{rf_pred}` with `{rf_conf:.1%}` confidence")
            st.write(f"- **Anomaly Detector (IF):** Decision score `{if_s:.4f}` (Anomalous if < 0.0)")

    # TAB 4: CAPSTONE REPORT & METHODOLOGY
    with tab_report:
        st.subheader("📑 CSE Capstone Project Documentation")
        st.markdown("""
        ### Problem Statement
        Traditional signature-based Network Intrusion Detection Systems (NIDS) fail against zero-day exploits,
        while standalone unsupervised anomaly detectors suffer from excessive false-positive rates on complex networks.
        
        ### Hybrid Solution Architecture
        This project deploys a **Two-Tier Hybrid Pipeline**:
        1. **Tier 1 (Supervised Classification)**: Random Forest trained on known attack patterns (e.g. DDoS, PortScan)
           delivering rapid, high-confidence detection with verified attack signatures.
        2. **Tier 2 (Unsupervised Anomaly Detection)**: Isolation Forest trained on normal operational baseline traffic.
           It isolates data points by randomly selecting features and splitting values, detecting zero-day anomalies.
        3. **Decision Fusion Logic**:
           ```
           if RF_Confidence(Known_Attack) >= Threshold:
               Output: 'Known Attack' (High Confidence Signature)
           elif RF_Prediction == 'BENIGN':
               if IsolationForest.is_anomaly():
                   Output: 'Potential Unknown/Anomalous Attack' (Zero-Day Alert)
               else:
                   Output: 'Normal'
           else:
               if IsolationForest.is_anomaly():
                   Output: 'Potential Unknown/Anomalous Attack'
               else:
                   Output: 'Known Attack'
           ```
        """)


if __name__ == "__main__":
    main()
