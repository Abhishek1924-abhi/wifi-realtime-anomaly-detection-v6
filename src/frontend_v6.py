import streamlit as st
import pandas as pd
import os
import time
import subprocess
import re

# ============================================================
# CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Wi-Fi Real-Time Anomaly Detection",
    page_icon="📡",
    layout="wide"
)

RESULT_FILE = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "data",
        "results",
        "v6",
        "live",
        "live_detection_results.csv"
    )
)

DEMO_FILE = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "data",
        "results",
        "v6",
        "live",
        "v6_attack_dashboard_demo.csv"
    )
)

# ============================================================
# PAGE STYLE
# ============================================================

st.markdown(
    """
    <style>

    .demo-banner {
        padding: 18px;
        border-radius: 12px;
        background: rgba(255, 80, 80, 0.12);
        border: 2px solid rgba(255, 80, 80, 0.65);
        text-align: center;
        margin-bottom: 20px;
    }

    .demo-title {
        font-size: 26px;
        font-weight: 700;
        color: #ff4b4b;
    }

    .demo-text {
        font-size: 16px;
        margin-top: 5px;
    }

    .attack-box {
        padding: 15px;
        border-radius: 10px;
        background: rgba(255, 0, 0, 0.08);
        border-left: 5px solid #ff4b4b;
        margin-bottom: 15px;
    }

    </style>
    """,
    unsafe_allow_html=True
)

# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("⚙️ System Controls")

demo_mode = st.sidebar.checkbox(
    "🚨 Enable Demo Attack Mode",
    value=False
)

if demo_mode:
    st.sidebar.warning(
        "Demo Attack Mode is ON.\n\n"
        "The dashboard is displaying attack flows "
        "previously classified as ATTACK by the V6 Random Forest."
    )

# ============================================================
# WIFI INFORMATION
# ============================================================

def get_wifi_info():

    info = {
        "SSID": "Unknown",
        "Signal": "Unknown",
        "Channel": "Unknown",
        "Band": "Unknown",
        "Receive Rate": "Unknown",
        "Transmit Rate": "Unknown",
        "IPv4": "Unknown"
    }

    try:

        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        output = result.stdout

        patterns = {
            "SSID": r"^\s*SSID\s*:\s*(.+)$",
            "Signal": r"^\s*Signal\s*:\s*(.+)$",
            "Channel": r"^\s*Channel\s*:\s*(.+)$",
            "Band": r"^\s*Band\s*:\s*(.+)$",
            "Receive Rate": r"^\s*Receive rate \(Mbps\)\s*:\s*(.+)$",
            "Transmit Rate": r"^\s*Transmit rate \(Mbps\)\s*:\s*(.+)$"
        }

        for key, pattern in patterns.items():

            match = re.search(
                pattern,
                output,
                re.MULTILINE
            )

            if match:
                info[key] = match.group(1).strip()

        return info

    except Exception:
        return info


# ============================================================
# LOAD LIVE RESULTS
# ============================================================

def load_results():

    if not os.path.exists(RESULT_FILE):
        return pd.DataFrame()

    try:

        columns = [
            "Time",
            "Source_IP",
            "Source_Port",
            "Destination_IP",
            "Destination_Port",
            "Protocol",
            "Duration",
            "Packets",
            "Prediction",
            "Confidence"
        ]

        df = pd.read_csv(
            RESULT_FILE,
            names=columns,
            header=None
        )

        if df.empty:
            return df

        # Handle the case where the file contains a header
        if str(df.iloc[0]["Time"]).lower() in [
            "timestamp",
            "time"
        ]:

            df = df.iloc[1:].copy()

        df["Time"] = pd.to_datetime(
            df["Time"],
            errors="coerce"
        )

        df["Confidence"] = pd.to_numeric(
            df["Confidence"],
            errors="coerce"
        )

        df["Packets"] = pd.to_numeric(
            df["Packets"],
            errors="coerce"
        )

        # --------------------------------------------------------
        # CURRENT LIVE TRAFFIC WINDOW
        # --------------------------------------------------------
        # The detector continuously appends to this CSV.  Do not
        # use the Streamlit start time because the detector may
        # already be running when the dashboard is opened.
        #
        # Keep only the most recent 5 minutes of captured traffic.
        # This removes old historical rows while keeping the
        # currently active live session visible.
        if not df.empty and df["Time"].notna().any():
            latest_time = df["Time"].max()
            live_cutoff = latest_time - pd.Timedelta(minutes=5)
            df = df[df["Time"] >= live_cutoff].copy()

        return df

    except Exception as e:

        st.error(
            f"Unable to read detection results: {e}"
        )

        return pd.DataFrame()


# ============================================================
# LOAD DEMO ATTACK RESULTS
# ============================================================

def load_demo_results():

    if not os.path.exists(DEMO_FILE):
        return pd.DataFrame()

    try:

        df = pd.read_csv(DEMO_FILE)

        if df.empty:
            return df

        df["Timestamp"] = pd.to_datetime(
            df["Timestamp"],
            errors="coerce"
        )

        df["Confidence"] = pd.to_numeric(
            df["Confidence"],
            errors="coerce"
        )

        df["Packets"] = pd.to_numeric(
            df["Packets"],
            errors="coerce"
        )

        return df

    except Exception as e:

        st.error(
            f"Unable to read demo attack results: {e}"
        )

        return pd.DataFrame()


# ============================================================
# HEADER
# ============================================================

st.title(
    "📡 Wi-Fi Real-Time Anomaly Detection"
)

st.caption(
    "V6 Random Forest Network Traffic Monitoring System"
)

# ============================================================
# DEMO MODE BANNER
# ============================================================

if demo_mode:

    st.markdown(
            """<div class="attack-box">
    <b>🚨 V6 MODEL DETECTION RESULT</b><br><br>
    The following flows were classified as <b>ATTACK</b> by the trained V6 Random Forest.
    <br><br>
    <b>Model:</b> Random Forest V6<br>
    <b>Feature Set:</b> 68 Flow Features<br>
    <b>Detected Attack Flows:</b> 5
    </div>""",
            unsafe_allow_html=True
        )
else:

    st.info(
        "🟢 LIVE MODE — Dashboard is displaying captured network traffic."
    )

st.divider()

# ============================================================
# WIFI STATUS
# ============================================================

wifi = get_wifi_info()

st.subheader(
    "📶 Current Wi-Fi Network"
)

c1, c2, c3, c4 = st.columns(4)

with c1:

    st.metric(
        "Wi-Fi Name",
        wifi["SSID"]
    )

with c2:

    st.metric(
        "Signal",
        wifi["Signal"]
    )

with c3:

    st.metric(
        "Channel",
        wifi["Channel"]
    )

with c4:

    st.metric(
        "Band",
        wifi["Band"]
    )

c5, c6 = st.columns(2)

with c5:

    st.metric(
        "Receive Rate",
        wifi["Receive Rate"]
    )

with c6:

    st.metric(
        "Transmit Rate",
        wifi["Transmit Rate"]
    )

st.divider()

# ============================================================
# SELECT DATA SOURCE
# ============================================================

if demo_mode:

    df = load_demo_results()

else:

    df = load_results()

# ============================================================
# NO DATA
# ============================================================

if df.empty:

    if demo_mode:

        st.error(
            "Demo attack file was not found."
        )

        st.code(
            DEMO_FILE
        )

    else:

        st.warning(
            "No live detection results found yet."
        )

        st.info(
            "Start the live detector first."
        )

        st.code(
            "python live_detection_v6.py"
        )

    st.stop()

# ============================================================
# NORMALIZE DEMO/LIVE COLUMN NAMES
# ============================================================

if demo_mode:

    df = df.rename(
        columns={
            "Timestamp": "Time",
            "Flow_Duration": "Duration"
        }
    )

# ============================================================
# STATISTICS
# ============================================================

total = len(df)

benign = int(
    (df["Prediction"] == "BENIGN").sum()
)

attack = int(
    (df["Prediction"] == "ATTACK").sum()
)

if total > 0:

    attack_rate = (
        attack / total
    ) * 100

else:

    attack_rate = 0

st.subheader(
    "📊 Live Traffic Statistics"
)

c1, c2, c3, c4 = st.columns(4)

with c1:

    st.metric(
        "Total Flows",
        total
    )

with c2:

    st.metric(
        "Normal",
        benign
    )

with c3:

    st.metric(
        "🚨 Anomalies",
        attack
    )

with c4:

    st.metric(
        "Anomaly Rate",
        f"{attack_rate:.2f}%"
    )

st.divider()

# ============================================================
# DEMO ATTACK SUMMARY
# ============================================================

if demo_mode:

    st.markdown(
        """
        <div class="attack-box">

        <b>🚨 V6 MODEL DETECTION RESULT</b><br><br>

        The following flows were classified as
        <b>ATTACK</b> by the trained V6 Random Forest.

        <br><br>

        <b>Model:</b> Random Forest V6<br>
        <b>Feature Set:</b> 68 Flow Features<br>
        <b>Detected Attack Flows:</b> 5

        </div>
        """,
        unsafe_allow_html=True
    )

# ============================================================
# DEVICE / TRAFFIC SUMMARY
# ============================================================

st.subheader(
    "🌐 Traffic Sources"
)

if not demo_mode:
    st.caption(
        "Showing the most recent 5 minutes of live V6 traffic."
    )

source_summary = (
    df.groupby(
        ["Source_IP", "Destination_IP", "Destination_Port", "Protocol"],
        dropna=False
    )
    .agg(
        Flows=("Prediction", "count"),
        Attacks=("Prediction", lambda x: (x == "ATTACK").sum()),
        Normal=("Prediction", lambda x: (x == "BENIGN").sum())
    )
    .reset_index()
)

source_summary["Status"] = source_summary.apply(
    lambda row:
    "🚨 ANOMALY"
    if row["Attacks"] > 0
    else "✅ NORMAL",
    axis=1
)

source_summary = source_summary.sort_values(
    "Attacks",
    ascending=False
)

st.dataframe(
    source_summary,
    use_container_width=True,
    hide_index=True
)

st.divider()

# ============================================================
# LIVE / DEMO TRAFFIC TABLE
# ============================================================

if demo_mode:

    st.subheader(
        "🚨 V6 Detected Attack Traffic"
    )

else:

    st.subheader(
        "🔴 Live Network Traffic"
    )

display_df = df.copy()

display_df["Status"] = display_df[
    "Prediction"
].apply(
    lambda x:
    "🚨 ANOMALY"
    if x == "ATTACK"
    else "✅ NORMAL"
)

display_df = display_df[
    [
        "Time",
        "Source_IP",
        "Source_Port",
        "Destination_IP",
        "Destination_Port",
        "Protocol",
        "Duration",
        "Packets",
        "Prediction",
        "Confidence",
        "Status"
    ]
]

st.dataframe(
    display_df.tail(100).iloc[::-1],
    use_container_width=True,
    hide_index=True
)

st.divider()

# ============================================================
# ANOMALY ALERTS
# ============================================================

st.subheader(
    "🚨 Detected Anomalies"
)

attacks = df[
    df["Prediction"] == "ATTACK"
].copy()

if attacks.empty:

    st.success(
        "No anomalies detected in the captured traffic."
    )

else:

    if demo_mode:

        st.error(
            f"🚨 V6 MODEL DETECTED {len(attacks)} ATTACK FLOWS"
        )

    else:

        st.error(
            f"{len(attacks)} anomalous flows detected."
        )

    st.dataframe(
        attacks.tail(50).iloc[::-1],
        use_container_width=True,
        hide_index=True
    )

# ============================================================
# DEMO EXPLANATION
# ============================================================

if demo_mode:

    st.divider()

    st.subheader(
        "🎓 Demonstration Information"
    )

    st.info(
        "This is a controlled demonstration mode. "
        "The displayed flows were previously processed through "
        "the V6 68-feature preprocessing pipeline and classified "
        "as ATTACK by the trained Random Forest model. "
        "Normal live traffic is not being replaced permanently."
    )

# ============================================================
# REFRESH
# ============================================================

if not demo_mode:

    st.caption(
        "Dashboard automatically refreshes every 5 seconds."
    )

    time.sleep(5)

    st.rerun()

else:

    st.caption(
        "Demo Attack Mode is paused. Disable the checkbox "
        "to return to live traffic monitoring."
    )