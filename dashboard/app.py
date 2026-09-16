from __future__ import annotations

import time
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from network_monitor.config import DEFAULT_DB_PATH
from network_monitor.database import fetch_dataframe, initialize_database

st.set_page_config(page_title="Network Behavior Monitor", layout="wide")

st.title("Network Behavior Monitor")
st.caption("Dashboard pentru monitorizarea comportamentală a traficului LAN")

with st.sidebar:
    db_path = Path(st.text_input("SQLite database", value=str(DEFAULT_DB_PATH)))
    refresh = st.slider("Auto-refresh interval (sec)", min_value=0, max_value=30, value=5)
    st.write("Setează 0 pentru refresh manual.")
    if st.button("Refresh now"):
        st.cache_data.clear()

initialize_database(db_path)


@st.cache_data(ttl=5)
def load_data(db: str):
    packets = fetch_dataframe(db, "SELECT * FROM packets ORDER BY ts DESC LIMIT 5000")
    features = fetch_dataframe(db, "SELECT * FROM features ORDER BY id DESC LIMIT 1000")
    alerts = fetch_dataframe(db, "SELECT * FROM alerts ORDER BY ts DESC LIMIT 500")
    return packets, features, alerts


packets, features, alerts = load_data(str(db_path))

col1, col2, col3, col4 = st.columns(4)
col1.metric("Pachete stocate", len(packets))
col2.metric("Ferestre analizate", len(features))
col3.metric("Alerte", len(alerts))
if not alerts.empty:
    col4.metric("Ultima severitate", str(alerts.iloc[0]["severity"]))
else:
    col4.metric("Ultima severitate", "N/A")

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("Distribuția protocoalelor")
    if packets.empty:
        st.info("Nu există pachete capturate încă.")
    else:
        proto_counts = packets["protocol"].fillna("UNKNOWN").value_counts().reset_index()
        proto_counts.columns = ["protocol", "count"]
        fig = px.pie(proto_counts, values="count", names="protocol", title="Protocoale observate")
        st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("Top surse după numărul de pachete")
    if packets.empty:
        st.info("Nu există date pentru top IP-uri.")
    else:
        top_src = packets["src_ip"].fillna("unknown").value_counts().head(10).reset_index()
        top_src.columns = ["src_ip", "count"]
        fig = px.bar(top_src, x="src_ip", y="count", title="Top IP-uri sursă")
        st.plotly_chart(fig, use_container_width=True)

st.subheader("Evoluția ferestrelor analizate")
if features.empty:
    st.info("Nu există vectori de caracteristici generați încă.")
else:
    f = features.copy()
    f["window_time"] = pd.to_datetime(f["window_end"], unit="s")
    fig = px.line(
        f.sort_values("window_time"),
        x="window_time",
        y="packets_per_second",
        color="src_ip",
        title="Pachete/secundă pe sursă",
    )
    st.plotly_chart(fig, use_container_width=True)

st.subheader("Alerte recente")
if alerts.empty:
    st.success("Nu există alerte înregistrate.")
else:
    display_alerts = alerts.copy()
    display_alerts["time"] = pd.to_datetime(display_alerts["ts"], unit="s")
    st.dataframe(
        display_alerts[["time", "severity", "alert_type", "src_ip", "dst_ip", "message", "anomaly_score"]],
        use_container_width=True,
        hide_index=True,
    )

st.subheader("Vectori de caracteristici recenți")
if features.empty:
    st.info("Rulează analyzer-ul sau generatorul demo pentru a popula această secțiune.")
else:
    show_cols = [
        "id",
        "src_ip",
        "total_packets",
        "avg_packet_size",
        "unique_dst_ports",
        "unique_dst_ips",
        "packets_per_second",
        "syn_ratio",
        "icmp_ratio",
        "mean_iat",
    ]
    st.dataframe(features[show_cols].head(100), use_container_width=True, hide_index=True)

if refresh > 0:
    time.sleep(refresh)
    st.rerun()
