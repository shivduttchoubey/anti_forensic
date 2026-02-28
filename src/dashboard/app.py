import streamlit as st
import json
import pandas as pd
import os
import time

st.set_page_config(page_title="Universal Anti-Forensics Engine", layout="wide")

def load_report(filepath):
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except:
        return None

def main():
    st.title("🛡️ Universal Anti-Forensics Detection Engine")
    
    st.sidebar.header("Configuration")
    report_file = st.sidebar.text_input("Report JSON Path", "report.json")
    auto_refresh = st.sidebar.checkbox("Auto-Refresh (Live Mode)", value=False)
    
    if auto_refresh:
        time.sleep(2)
        st.rerun()

    report_data = load_report(report_file)
    
    if not report_data:
        st.warning(f"Report file '{report_file}' not found or invalid format. Run the engine first.")
        return

    st.subheader("Integrity Check")
    hash_val = report_data.get("integrity_hash_sha256", "N/A")
    st.code(f"SHA-256 Report Chain: {hash_val}", language="text")

    content = report_data.get("content", {})
    categories = ["DESTROY", "MODIFY", "HIDE", "FABRICATE", "PREVENT"]
    
    # Overview Metrics
    cols = st.columns(len(categories))
    for idx, cat in enumerate(categories):
        count = len(content.get(cat, []))
        cols[idx].metric(label=cat, value=count)

    st.markdown("---")
    st.subheader("Anomaly Details")
    
    # Flatten data for dataframe
    flat_data = []
    for cat in categories:
        for item in content.get(cat, []):
            item['category'] = cat
            flat_data.append(item)
            
    if flat_data:
        df = pd.DataFrame(flat_data)
        st.dataframe(df, width='stretch')
        
        st.subheader("Detailed Findings")
        for item in flat_data:
             anomaly_type = item.get('anomaly_type', item.get('description', 'unknown'))
             with st.expander(f"[{item['category']}] {anomaly_type}"):
                 st.write(f"**Anomaly Type:** {anomaly_type}")
                 st.write(f"**Confidence:** {item.get('confidence', 'N/A')}")
                 if 'evidence' in item:
                     st.write(f"**Evidence:**")
                     st.json(item['evidence'])
                 if 'source' in item:
                     st.write(f"**Source:** {item['source']}")
                 if 'reference' in item:
                     st.write(f"**Reference:** {item['reference']}")
    else:
        st.success("No anomalies detected in the current report.")

if __name__ == "__main__":
    main()
