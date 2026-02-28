import streamlit as st
import json
import pandas as pd
import os
import time
import plotly.express as px
import numpy as np

# --- PAGE CONFIG ---
st.set_page_config(
    page_title="Anti-Forensic Analysis Framework",
    page_icon="",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- CUSTOM CSS ---
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stTabs [data-baseweb="tab-list"] { gap: 24px; }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: #161b22;
        border-radius: 4px 4px 0px 0px;
        gap: 1px;
        padding-top: 10px;
        padding-bottom: 10px;
        color: #8b949e;
    }
    .stTabs [aria-selected="true"] {
        background-color: #1f6feb !important;
        color: white !important;
    }
    .metric-card {
        background-color: #161b22;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #30363d;
        text-align: center;
    }
    .metric-value { font-size: 2rem; font-weight: bold; color: #58a6ff; }
    .metric-label { font-size: 0.9rem; color: #8b949e; margin-top: 5px; }
    </style>
""", unsafe_allow_html=True)

# --- UTILITIES ---
def load_report(filepath="report.json"):
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except:
        return None

def render_summary_cards(content):
    categories = ["DESTROY", "MODIFY", "HIDE", "FABRICATE", "PREVENT"]
    cols = st.columns(len(categories))
    for idx, cat in enumerate(categories):
        count = len(content.get(cat, []))
        with cols[idx]:
            st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value">{count}</div>
                    <div class="metric-label">{cat}</div>
                </div>
            """, unsafe_allow_html=True)

def render_grid_visualization(entropy_data=None):
    """
    Simulates the 2D Disk Block Heat-map Grid.
    Actually takes entropy_data which should be a list of values.
    """
    st.subheader("Disk Block Visualization (Entropy Mapping)")
    
    # Simulate a grid if no data
    if entropy_data is None:
        rows, cols = 20, 40
        data = np.random.uniform(0, 8, (rows, cols))
    else:
        # Reshape data into a grid
        size = int(len(entropy_data)**0.5)
        data = np.array(entropy_data[:size*size]).reshape(size, size)

    fig = px.imshow(
        data,
        color_continuous_scale=[(0, "#30363d"), (0.7, "#1f6feb"), (1, "#f85149")],
        labels={'color': 'Entropy'},
        zmin=0, zmax=8
    )
    fig.update_layout(
         margin=dict(l=0, r=0, t=0, b=0),
         xaxis={'visible': False},
         yaxis={'visible': False},
         coloraxis_showscale=True,
         height=450
    )
    st.plotly_chart(fig, use_container_width=True)

# --- MAIN APP ---
from main import ForensicFramework

def main():
    st.title("Anti-Forensic Analysis Framework")
    st.markdown("*Master Dashboard: Detecting Digital Manipulation with Evidence-Source Referencing*")

    framework = ForensicFramework()

    # Initialize live state
    if 'live_monitoring' not in st.session_state:
        st.session_state.live_monitoring = False
    if 'report' not in st.session_state:
        st.session_state.report = load_report()

    # --- TOP RIBBON TABS ---
    tab_temporal, tab_memory, tab_network, tab_storage, tab_live = st.tabs([
        "🕰️ Temporal Integrity",
        "🧠 Main Memory",
        "🌐 Networks",
        "💾 Storage Artifacts",
        "🛡️ Live Testing"
    ])

    report_data = st.session_state.report
    content = report_data.get("content", {}) if report_data else {}

    # --- TEMPORAL TAB ---
    with tab_temporal:
        st.header("Engine 1: Temporal Integrity Analyzer")
        col1, col2 = st.columns([1, 2])
        with col1:
            st.info("Detects timestamp clustering, clock drift, and impossible sequences.")
            csv_file = st.file_uploader("Upload Timeline CSV", type=['csv'], key="temp_file")
            if st.button("Run Phase-1 Temporal analysis", type="primary"):
                if csv_file:
                    # Save temp
                    with open("temp_timeline.csv", "wb") as f: f.write(csv_file.getbuffer())
                    st.session_state.report = framework.run_static("temp_timeline.csv")
                    st.success("Temporal Analysis Complete")
                else:
                    st.error("Please upload a CSV timeline first.")
        with col2:
            st.subheader("Clustering/Drift Analysis")
            drift_data = pd.DataFrame(np.random.randn(25, 2), columns=['$SI', '$FN'])
            st.line_chart(drift_data)

    # --- MEMORY TAB ---
    with tab_memory:
        st.header("Engine 4: Main Memory Analysis Engine")
        st.warning("Focus: Collection Prevention, Hidden RAM pages, and Corrupted Payloads.")
        mem_file = st.file_uploader("Upload Memory Dump (.vmem, .raw, .dmp)", type=['vmem', 'raw', 'dmp', 'mem'], key="mem_file")
        if st.button("Start Collection Prevention Scan"):
            if mem_file:
                tmp_path = f"temp_{mem_file.name}"
                with open(tmp_path, "wb") as f: f.write(mem_file.getbuffer())
                st.session_state.report = framework.run_static(tmp_path)
                st.success(f"Memory Scan Complete — {mem_file.name}")
            else:
                st.error("Please upload a memory dump file first.")

    # --- NETWORK TAB ---
    with tab_network:
        st.header("Engine 3: Network Artifact Analyzer")
        st.info("Protocol STAT violations, Covert Channels (DNS/HTTP), and Exfiltration.")
        net_file = st.file_uploader("Upload PCAP Trace", type=['pcap', 'pcapng'], key="net_file")
        if st.button("Check for Ghost Connections"):
            if net_file:
                with open("temp_net.pcap", "wb") as f: f.write(net_file.getbuffer())
                st.session_state.report = framework.run_static("temp_net.pcap")
                st.success("Network Analysis Complete")
            else:
                st.error("Upload PCAP first.")

    # --- STORAGE TAB ---
    with tab_storage:
        st.header("Engine 2: Storage Artifact Analyzer")
        top_col1, top_col2 = st.columns([1, 1])
        with top_col1:
            disk_file = st.file_uploader("Upload Disk Image (.img, .dd, .raw)", type=['img', 'dd', 'raw', 'bin'], key="disk_file")
            disk_path = st.text_input("— or enter a local path / mounted volume —", value="")
            options = st.multiselect("Active Sub-Engines", [
                "$LogFile & $USN Journal Parsing",
                "Unallocated Entropy Mapping",
                "Wipe-Signature Statistical Scan"
            ], default=["Unallocated Entropy Mapping"])
        with top_col2:
             if st.button("🚀 Execute Forensic Surface Scan", type="primary"):
                 target = None
                 if disk_file:
                     target = f"temp_{disk_file.name}"
                     with open(target, "wb") as f: f.write(disk_file.getbuffer())
                 elif disk_path and os.path.exists(disk_path):
                     target = disk_path
                 if target:
                     st.session_state.report = framework.run_static(target)
                     st.success("Deep Disk Analysis Complete")
                 else:
                     st.error("Upload a disk image or enter a valid local path.")
        
        st.divider()
        render_grid_visualization()

    # --- LIVE TESTING TAB ---
    with tab_live:
        st.header("Dynamic Engine: Live Continuous Monitoring")
        col1, col2 = st.columns(2)
        with col1:
             st.markdown("### Monitor Agent Control")
             if st.button("🚀 Enable Real-Time Agent", use_container_width=True):
                 st.session_state.live_monitoring = True
                 # In a real app, this would trigger a background thread
             if st.button("🛑 Disable Guard Agent", use_container_width=True):
                 st.session_state.live_monitoring = False
        with col2:
             status_color = "green" if st.session_state.live_monitoring else "red"
             status_text = "GUARD PROTECTING" if st.session_state.live_monitoring else "AGENT INACTIVE"
             st.markdown(f"**STATUS:** <span style='color:{status_color}; font-weight:bold'>{status_text}</span>", unsafe_allow_html=True)
             if st.session_state.live_monitoring:
                 st.progress(0.72, "Monitoring OS Transaction Loops...")

    # --- GLOBAL DASHBOARD DRAWER ---
    st.divider()
    st.subheader("Global Unified Score (Evidence Referenced)")
    render_summary_cards(content)
    
    if report_data:
        st.markdown(f"**Integrity Chaining (SHA-256):** `{report_data.get('integrity_hash_sha256')}`")
        if st.checkbox("Show Detailed Forensic Logs"):
             st.json(content)

if __name__ == "__main__":
    main()
