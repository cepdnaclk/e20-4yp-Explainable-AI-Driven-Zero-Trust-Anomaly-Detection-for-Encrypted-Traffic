import streamlit as st
import json
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import time
import os

# Set page config
st.set_page_config(
    page_title="SDN Zero-Trust Sentry",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Paths
STATS_FILE = os.path.join(os.path.dirname(__file__), "live_stats.json")
LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "simulation_log.json")

# Custom CSS for "Hacker" aesthetic
st.markdown("""
<style>
    .stApp {
        background-color: #0E1117;
        color: #00FF41;
        font-family: 'Courier New', Courier, monospace;
    }
    .css-1d391kg {
        background-color: #0E1117;
    }
    h1, h2, h3 {
        color: #00FF41 !important;
        font-family: 'Courier New', Courier, monospace;
    }
    .metric-box {
        border: 1px solid #00FF41;
        padding: 10px;
        border-radius: 5px;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ SDN Zero-Trust Sentry Dashboard")
st.markdown("### >_ System Status: ONLINE | Mode: ENFORCING")

# Placeholder for auto-refresh
placeholder = st.empty()

while True:
    with placeholder.container():
        # 1. Load Data
        try:
            if os.path.exists(STATS_FILE):
                with open(STATS_FILE, 'r') as f:
                    stats = json.load(f)
            else:
                stats = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
            
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, 'r') as f:
                    logs = json.load(f)
            else:
                logs = []
        except Exception as e:
            st.error(f"Error reading data: {e}")
            stats = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
            logs = []

        # 2. Key Metrics
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("🚫 Blocked Attacks (TP)", stats["TP"])
        c2.metric("✅ Safe Traffic (TN)", stats["TN"])
        c3.metric("⚠️ False Alarms (FP)", stats["FP"])
        c4.metric("🚨 Leaks (FN)", stats["FN"])

        col1, col2 = st.columns([1, 2])

        with col1:
            st.subheader("Confusion Matrix")
            if sum(stats.values()) > 0:
                cm = [[stats["TN"], stats["FP"]], [stats["FN"], stats["TP"]]]
                df_cm = pd.DataFrame(cm, index=["Actual Benign", "Actual Attack"], 
                                         columns=["Pred Benign", "Pred Attack"])
                
                fig, ax = plt.subplots(figsize=(4, 3))
                sns.heatmap(df_cm, annot=True, fmt="d", cmap="Greens", ax=ax, cbar=False, 
                            linewidths=1, linecolor='#00FF41', annot_kws={"size": 14})
                # Dark mode styling for plot
                fig.patch.set_facecolor('#0E1117')
                ax.set_facecolor('#0E1117')
                ax.tick_params(colors='white')
                ax.xaxis.label.set_color('white')
                ax.yaxis.label.set_color('white')
                for text in ax.texts:
                    text.set_color('white')
                
                st.pyplot(fig)
            else:
                st.info("Waiting for simulation data...")

        with col2:
            st.subheader("Live Stream Log")
            if logs:
                df_logs = pd.DataFrame(logs)
                # Select interesting columns
                display_cols = ["timestamp", "stream_id", "prediction", "action", "latency_ms"]
                st.dataframe(df_logs[display_cols], height=300, hide_index=True)
                
                # Show latest topology path
                latest = logs[0]
                st.text(f"Latest Topology Path: {' -> '.join(latest.get('topology_path', []))}")
                st.caption(f"Syslog: {latest.get('syslog_entry', 'N/A')}")
            else:
                st.write("No logs yet.")

    time.sleep(2) # Refresh rate
