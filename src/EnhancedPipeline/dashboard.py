"""
dashboard.py — Streamlit Real-Time Monitoring Dashboard
=======================================================
Zero-Trust XAI Anomaly Detection | University of Peradeniya
e20420Janith

Provides a live browser dashboard showing:
  - Pipeline statistics (flows, drops, drop rate)
  - Per-stage latency distribution (CDF chart)
  - Last N XAI explanations for dropped flows
  - Adaptive feature MI rankings

Usage (from project root):
    streamlit run EnhancedPipeline/dashboard.py

Optional: connect to a running REST API (if pipeline is running separately)
    streamlit run EnhancedPipeline/dashboard.py -- --api http://localhost:5001

Requirements:
    pip install streamlit plotly requests
"""

import os
import sys
import time
import json
import argparse
import logging
from collections import deque
from typing import Optional, List, Dict

# ── Path setup ────────────────────────────────────────────────────────────────
_THIS_DIR    = os.path.dirname(os.path.abspath(__file__))
SRC_ROOT     = os.path.dirname(_THIS_DIR)
PROJECT_ROOT = os.path.dirname(SRC_ROOT)
sys.path.insert(0, SRC_ROOT)

try:
    import streamlit as st
    import plotly.graph_objects as go
    import plotly.express as px
    import pandas as pd
    import numpy as np
except ImportError as exc:
    print(f"ERROR: Missing dependency: {exc}")
    print("Install with: pip install streamlit plotly pandas numpy")
    sys.exit(1)

try:
    import requests as http_requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from EnhancedPipeline.config import CFG

logger = logging.getLogger("EP.Dashboard")

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Zero-Trust XAI Pipeline Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .metric-card {
        background: #1e2130;
        border-radius: 8px;
        padding: 16px;
        border-left: 4px solid #4CAF50;
    }
    .metric-card.danger { border-left-color: #f44336; }
    .metric-card.warning { border-left-color: #ff9800; }
    .drop-entry {
        background: #2d1515;
        border-radius: 6px;
        padding: 10px;
        margin: 6px 0;
        font-family: monospace;
        font-size: 12px;
        border-left: 3px solid #f44336;
    }
    .forward-entry {
        background: #152d15;
        border-radius: 6px;
        padding: 10px;
        margin: 6px 0;
        font-family: monospace;
        font-size: 12px;
        border-left: 3px solid #4CAF50;
    }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Session state initialization
# ─────────────────────────────────────────────────────────────────────────────

if "flow_history" not in st.session_state:
    st.session_state.flow_history: deque = deque(maxlen=CFG.DASHBOARD_HISTORY_N)
if "xai_log" not in st.session_state:
    st.session_state.xai_log: List[dict] = []
if "api_url" not in st.session_state:
    st.session_state.api_url: Optional[str] = None

# ─────────────────────────────────────────────────────────────────────────────
# Data fetching helpers
# ─────────────────────────────────────────────────────────────────────────────

def fetch_api_stats(api_url: str) -> Optional[dict]:
    """Fetch pipeline stats from REST API."""
    if not HAS_REQUESTS:
        return None
    try:
        r = http_requests.get(f"{api_url}/status", timeout=2)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def simulate_flow_for_demo() -> dict:
    """Generate a synthetic pipeline result for dashboard demo mode."""
    rng = np.random.default_rng(int(time.time() * 1000) % 2**32)
    is_anomaly = rng.random() < 0.15  # 15% anomaly rate
    latency = rng.exponential(2.0) + 0.5
    return {
        "flow_id":    f"flow_{int(time.time()*1000) % 1000000:07d}",
        "action":     "DROP" if is_anomaly else "FORWARD",
        "confidence": "high" if is_anomaly else "normal",
        "ddl_score":  float(rng.uniform(2.0, 5.0) if is_anomaly else rng.uniform(0.1, 0.8)),
        "ddl_threshold": 1.2,
        "if_label":   "Anomaly" if is_anomaly else "Normal",
        "latency_ms": {
            "ddl": round(latency * 0.6, 2),
            "if":  round(latency * 0.1, 2),
            "xai": round(latency * 0.3 if is_anomaly else 0.0, 2),
            "total": round(latency, 2),
        },
        "timestamp": time.time(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar configuration
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("🛡️ Zero-Trust XAI")
    st.markdown("**Enhanced DDL + XAI Pipeline Monitor**")
    st.divider()

    mode = st.radio("Data Source", ["Demo (Simulated)", "Live API"], index=0)

    if mode == "Live API":
        api_url_input = st.text_input(
            "API URL", value="http://localhost:5001",
            help="URL of the running rest_api.py server"
        )
        st.session_state.api_url = api_url_input
        if HAS_REQUESTS:
            health = None
            try:
                health = http_requests.get(f"{api_url_input}/health", timeout=1).json()
            except Exception:
                pass
            if health and health.get("model_loaded"):
                st.success("🟢 API connected — model loaded")
            else:
                st.error("🔴 Cannot reach API or model not loaded")
        else:
            st.warning("Install `requests` to connect to live API")

    refresh = st.slider(
        "Refresh interval (s)",
        min_value=1, max_value=10, value=CFG.DASHBOARD_REFRESH_SEC
    )
    st.divider()
    st.markdown("### Feature Importance")
    show_adaptive = st.checkbox("Show MI feature ranking", value=True)

# ─────────────────────────────────────────────────────────────────────────────
# Main dashboard layout
# ─────────────────────────────────────────────────────────────────────────────

st.title("🛡️ Zero-Trust XAI Anomaly Detection — Live Dashboard")
st.caption(f"University of Peradeniya | e20420Janith | Refreshing every {refresh}s")

placeholder = st.empty()

while True:
    # Fetch or simulate new data
    if mode == "Demo (Simulated)":
        for _ in range(3):  # Add 3 flows per refresh in demo
            f = simulate_flow_for_demo()
            st.session_state.flow_history.append(f)
            if f["action"] == "DROP":
                st.session_state.xai_log.append(f)
                if len(st.session_state.xai_log) > 20:
                    st.session_state.xai_log.pop(0)
    elif st.session_state.api_url and HAS_REQUESTS:
        api_data = fetch_api_stats(st.session_state.api_url)
        # API-connected mode would update stats here

    history = list(st.session_state.flow_history)

    with placeholder.container():
        # ── Top KPI metrics ───────────────────────────────────────────────────
        kpi1, kpi2, kpi3, kpi4 = st.columns(4)

        total  = len(history)
        drops  = sum(1 for f in history if f["action"] == "DROP")
        fwds   = total - drops
        drop_r = round(100 * drops / max(total, 1), 1)
        lats   = [f["latency_ms"]["total"] for f in history] or [0]
        mean_lat = round(float(np.mean(lats)), 2)

        kpi1.metric("Total Flows", total)
        kpi2.metric("Dropped (Anomaly)", drops,
                    delta=f"{drop_r}% drop rate",
                    delta_color="inverse")
        kpi3.metric("Forwarded (Normal)", fwds)
        kpi4.metric("Mean Latency (ms)", mean_lat)

        st.divider()

        # ── Charts row ────────────────────────────────────────────────────────
        col_left, col_right = st.columns(2)

        with col_left:
            st.subheader("Flow Decision Timeline")
            if history:
                df_hist = pd.DataFrame([
                    {"idx": i, "action": f["action"],
                     "ddl_score": f["ddl_score"],
                     "latency": f["latency_ms"]["total"]}
                    for i, f in enumerate(history[-100:])
                ])
                color_map = {"DROP": "#f44336", "FORWARD": "#4CAF50"}
                fig_time = px.scatter(
                    df_hist, x="idx", y="ddl_score",
                    color="action", color_discrete_map=color_map,
                    labels={"idx": "Flow #", "ddl_score": "DDL Score"},
                    title="DDL Score per Flow (last 100)",
                )
                fig_time.add_hline(y=1.2, line_dash="dash", line_color="orange",
                                   annotation_text="Threshold")
                fig_time.update_layout(height=300, margin=dict(t=40, b=20))
                st.plotly_chart(fig_time, use_container_width=True)
            else:
                st.info("Waiting for flow data ...")

        with col_right:
            st.subheader("Latency Distribution (CDF)")
            if lats and max(lats) > 0:
                sorted_lats = np.sort(lats)
                cdf = np.arange(1, len(sorted_lats)+1) / len(sorted_lats)
                fig_cdf = go.Figure()
                fig_cdf.add_trace(go.Scatter(
                    x=sorted_lats, y=cdf,
                    mode="lines", name="CDF",
                    line=dict(color="#2196F3", width=2),
                ))
                fig_cdf.update_layout(
                    xaxis_title="Latency (ms)", yaxis_title="CDF",
                    height=300, margin=dict(t=40, b=20),
                    title="End-to-End Pipeline Latency CDF",
                )
                st.plotly_chart(fig_cdf, use_container_width=True)

        st.divider()

        # ── Recent anomaly log ────────────────────────────────────────────────
        st.subheader("🚨 Recent Anomaly Events (last 10)")
        recent_drops = [f for f in reversed(history) if f["action"] == "DROP"][:10]
        if recent_drops:
            for entry in recent_drops:
                lms = entry["latency_ms"]
                cls = "drop-entry"
                st.markdown(
                    f'<div class="{cls}">'
                    f'⛔ <b>{entry["flow_id"]}</b> → DROP '
                    f'| DDL={entry["ddl_score"]:.4f} | IF={entry["if_label"]} '
                    f'| confidence={entry["confidence"]}'
                    f'| Latency: DDL={lms["ddl"]}ms  IF={lms["if"]}ms  XAI={lms["xai"]}ms  Total={lms["total"]}ms'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.success("✅ No anomalies detected in recent flows")

    time.sleep(refresh)
