import os
import time
import math
import joblib
import numpy as np
import pandas as pd

from collections import defaultdict
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, conf


# ============================================================
# V6 LIVE WIFI DETECTOR
# ============================================================

print("=" * 70)
print("V6 - LIVE WIFI ATTACK DETECTION")
print("=" * 70)


# ============================================================
# PATHS
# ============================================================

MODEL_PATH = r"..\model\v6\random_forest_v6.pkl"
SCALER_PATH = r"..\model\v6\scaler_v6.pkl"
FEATURE_PATH = r"..\model\v6\features_v6.pkl"

RESULT_DIR = r"..\data\results\v6\live"

os.makedirs(RESULT_DIR, exist_ok=True)

RESULT_FILE = os.path.join(
    RESULT_DIR,
    "live_detection_results.csv"
)


# ============================================================
# SETTINGS
# ============================================================

# Your Intel(R) Wi-Fi 6 AX101 adapter
INTERFACE_NAME = "Wi-Fi"

FLOW_TIMEOUT = 10

PRINT_EVERY_PACKET = False

# Number of packets processed before displaying a summary
SUMMARY_INTERVAL = 20


# ============================================================
# LOAD MODEL
# ============================================================

print("\nLoading V6 model...")

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"V6 model not found:\n{MODEL_PATH}"
    )

model = joblib.load(MODEL_PATH)

print("V6 model loaded successfully.")


# ============================================================
# LOAD SCALER
# ============================================================

print("\nLoading V6 scaler...")

if not os.path.exists(SCALER_PATH):
    raise FileNotFoundError(
        f"V6 scaler not found:\n{SCALER_PATH}"
    )

scaler = joblib.load(SCALER_PATH)

print("V6 scaler loaded successfully.")


# ============================================================
# LOAD FEATURES
# ============================================================

print("\nLoading V6 feature list...")

if not os.path.exists(FEATURE_PATH):
    raise FileNotFoundError(
        f"V6 feature list not found:\n{FEATURE_PATH}"
    )

FEATURES = joblib.load(FEATURE_PATH)

print("Features expected by V6:", len(FEATURES))

if len(FEATURES) != 68:
    raise ValueError(
        f"Expected 68 features, found {len(FEATURES)}"
    )


# ============================================================
# SELECT WIFI INTERFACE
# ============================================================

print("\nSelecting Wi-Fi interface...")

iface = None

for interface in conf.ifaces.values():

    name = getattr(interface, "name", "")

    description = getattr(
        interface,
        "description",
        ""
    )

    if (
        name.lower() == INTERFACE_NAME.lower()
        or
        "Intel(R) Wi-Fi 6 AX101".lower()
        in description.lower()
    ):

        iface = interface
        break


if iface is None:

    print("\nAvailable interfaces:")

    for interface in conf.ifaces.values():

        print(
            "NAME:",
            getattr(interface, "name", ""),
            "| DESCRIPTION:",
            getattr(interface, "description", "")
        )

    raise RuntimeError(
        "Could not find the Wi-Fi interface."
    )


print("Interface:", iface)

print(
    "Interface name:",
    getattr(iface, "name", "")
)

print(
    "Interface description:",
    getattr(iface, "description", "")
)


# ============================================================
# FLOW STORAGE
# ============================================================

flows = {}

packet_counter = 0
flow_counter = 0
prediction_counter = 0

attack_counter = 0
benign_counter = 0


# ============================================================
# CSV INITIALIZATION
# ============================================================

CSV_COLUMNS = [
    "Timestamp",
    "Source_IP",
    "Source_Port",
    "Destination_IP",
    "Destination_Port",
    "Protocol",
    "Flow_Duration",
    "Packets",
    "Prediction",
    "Confidence"
]


if not os.path.exists(RESULT_FILE):

    pd.DataFrame(
        columns=CSV_COLUMNS
    ).to_csv(
        RESULT_FILE,
        index=False
    )


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_mean(values):

    if not values:
        return 0.0

    return float(
        np.mean(values)
    )


def safe_std(values):

    if len(values) <= 1:
        return 0.0

    return float(
        np.std(values)
    )


def safe_max(values):

    if not values:
        return 0.0

    return float(
        np.max(values)
    )


def safe_min(values):

    if not values:
        return 0.0

    return float(
        np.min(values)
    )


def safe_sum(values):

    if not values:
        return 0.0

    return float(
        np.sum(values)
    )


def safe_variance(values):

    if len(values) <= 1:
        return 0.0

    return float(
        np.var(values)
    )


def safe_div(a, b):

    if b == 0:
        return 0.0

    return float(
        a / b
    )


def clean_value(value):

    if value is None:
        return 0.0

    try:

        value = float(value)

        if not math.isfinite(value):
            return 0.0

        return value

    except Exception:

        return 0.0


# ============================================================
# FLOW KEY
# ============================================================

def get_flow_key(packet):

    if IP not in packet:
        return None

    ip = packet[IP]

    src = ip.src
    dst = ip.dst

    protocol = int(ip.proto)

    src_port = 0
    dst_port = 0

    if TCP in packet:

        src_port = int(
            packet[TCP].sport
        )

        dst_port = int(
            packet[TCP].dport
        )

    elif UDP in packet:

        src_port = int(
            packet[UDP].sport
        )

        dst_port = int(
            packet[UDP].dport
        )

    forward = (
        src,
        src_port,
        dst,
        dst_port,
        protocol
    )

    backward = (
        dst,
        dst_port,
        src,
        src_port,
        protocol
    )

    return forward, backward


# ============================================================
# CREATE FLOW
# ============================================================

def create_flow(packet):

    ip = packet[IP]

    src = ip.src
    dst = ip.dst

    protocol = int(ip.proto)

    src_port = 0
    dst_port = 0

    if TCP in packet:

        src_port = int(
            packet[TCP].sport
        )

        dst_port = int(
            packet[TCP].dport
        )

    elif UDP in packet:

        src_port = int(
            packet[UDP].sport
        )

        dst_port = int(
            packet[UDP].dport
        )

    now = time.time()

    packet_length = len(packet)

    flow = {

        "src": src,
        "dst": dst,

        "src_port": src_port,
        "dst_port": dst_port,

        "protocol": protocol,

        "start": now,
        "last": now,

        "forward_lengths": [],
        "backward_lengths": [],

        "forward_times": [],
        "backward_times": [],

        "all_times": [],

        "forward_count": 0,
        "backward_count": 0,

        "forward_bytes": 0,
        "backward_bytes": 0,

        "fwd_psh": 0,

        "fin": 0,
        "syn": 0,
        "rst": 0,
        "psh": 0,
        "ack": 0,
        "urg": 0,
        "ece": 0,

        "fwd_header_lengths": [],
        "bwd_header_lengths": [],

        "init_win_forward": -1,
        "init_win_backward": -1,

        "act_data_pkt_fwd": 0,

        "min_seg_size_forward": 0,

        "active_times": [],
        "idle_times": []
    }

    return flow


# ============================================================
# UPDATE FLOW
# ============================================================

def update_flow(flow, packet, forward=True):

    now = time.time()

    packet_length = len(packet)

    previous_time = flow["last"]

    flow["last"] = now

    flow["all_times"].append(now)

    if forward:

        flow["forward_lengths"].append(
            packet_length
        )

        flow["forward_times"].append(
            now
        )

        flow["forward_count"] += 1

        flow["forward_bytes"] += packet_length

        if packet_length > 0:

            flow["act_data_pkt_fwd"] += 1

        if IP in packet:

            header_length = int(
                packet[IP].ihl * 4
            )

            flow["fwd_header_lengths"].append(
                header_length
            )

            if flow["min_seg_size_forward"] == 0:

                flow["min_seg_size_forward"] = packet_length

            else:

                flow["min_seg_size_forward"] = min(
                    flow["min_seg_size_forward"],
                    packet_length
                )

    else:

        flow["backward_lengths"].append(
            packet_length
        )

        flow["backward_times"].append(
            now
        )

        flow["backward_count"] += 1

        flow["backward_bytes"] += packet_length

        if IP in packet:

            header_length = int(
                packet[IP].ihl * 4
            )

            flow["bwd_header_lengths"].append(
                header_length
            )


    # ========================================================
    # TCP FLAGS
    # ========================================================

    if TCP in packet:

        flags = packet[TCP].flags

        if "F" in flags:
            flow["fin"] += 1

        if "S" in flags:
            flow["syn"] += 1

        if "R" in flags:
            flow["rst"] += 1

        if "P" in flags:

            flow["psh"] += 1

            if forward:

                flow["fwd_psh"] += 1

        if "A" in flags:
            flow["ack"] += 1

        if "U" in flags:
            flow["urg"] += 1

        if "E" in flags:
            flow["ece"] += 1

        if (
            forward
            and
            flow["init_win_forward"] == -1
        ):

            flow["init_win_forward"] = int(
                packet[TCP].window
            )

        if (
            not forward
            and
            flow["init_win_backward"] == -1
        ):

            flow["init_win_backward"] = int(
                packet[TCP].window
            )


# ============================================================
# BUILD 68 FEATURES
# ============================================================

def build_features(flow):

    fwd = flow["forward_lengths"]

    bwd = flow["backward_lengths"]

    all_lengths = fwd + bwd

    fwd_times = flow["forward_times"]

    bwd_times = flow["backward_times"]

    all_times = flow["all_times"]

    start = flow["start"]

    end = flow["last"]

    duration_seconds = max(
        end - start,
        0.000001
    )

    duration_microseconds = (
        duration_seconds * 1_000_000
    )


    # ========================================================
    # IAT
    # ========================================================

    all_iat = []

    if len(all_times) > 1:

        sorted_times = sorted(
            all_times
        )

        for i in range(
            1,
            len(sorted_times)
        ):

            all_iat.append(
                (
                    sorted_times[i]
                    -
                    sorted_times[i - 1]
                )
                * 1_000_000
            )


    fwd_iat = []

    if len(fwd_times) > 1:

        sorted_times = sorted(
            fwd_times
        )

        for i in range(
            1,
            len(sorted_times)
        ):

            fwd_iat.append(
                (
                    sorted_times[i]
                    -
                    sorted_times[i - 1]
                )
                * 1_000_000
            )


    bwd_iat = []

    if len(bwd_times) > 1:

        sorted_times = sorted(
            bwd_times
        )

        for i in range(
            1,
            len(sorted_times)
        ):

            bwd_iat.append(
                (
                    sorted_times[i]
                    -
                    sorted_times[i - 1]
                )
                * 1_000_000
            )


    # ========================================================
    # PACKET RATES
    # ========================================================

    total_packets = (
        flow["forward_count"]
        +
        flow["backward_count"]
    )

    total_bytes = (
        flow["forward_bytes"]
        +
        flow["backward_bytes"]
    )

    flow_bytes_per_second = safe_div(
        total_bytes,
        duration_seconds
    )

    flow_packets_per_second = safe_div(
        total_packets,
        duration_seconds
    )

    fwd_packets_per_second = safe_div(
        flow["forward_count"],
        duration_seconds
    )

    bwd_packets_per_second = safe_div(
        flow["backward_count"],
        duration_seconds
    )


    # ========================================================
    # DOWN / UP RATIO
    # ========================================================

    down_up_ratio = safe_div(
        flow["backward_count"],
        flow["forward_count"]
    )


    # ========================================================
    # HEADER SIZES
    # ========================================================

    fwd_header_length = safe_sum(
        flow["fwd_header_lengths"]
    )

    bwd_header_length = safe_sum(
        flow["bwd_header_lengths"]
    )


    # ========================================================
    # AVERAGE PACKET SIZE
    # ========================================================

    packet_length_mean = safe_mean(
        all_lengths
    )


    # ========================================================
    # 68 FEATURE DICTIONARY
    # ========================================================

    data = {

        "Destination Port":
            flow["dst_port"],

        "Flow Duration":
            duration_microseconds,

        "Total Fwd Packets":
            flow["forward_count"],

        "Total Backward Packets":
            flow["backward_count"],

        "Total Length of Fwd Packets":
            flow["forward_bytes"],

        "Total Length of Bwd Packets":
            flow["backward_bytes"],

        "Fwd Packet Length Max":
            safe_max(fwd),

        "Fwd Packet Length Min":
            safe_min(fwd),

        "Fwd Packet Length Mean":
            safe_mean(fwd),

        "Fwd Packet Length Std":
            safe_std(fwd),

        "Bwd Packet Length Max":
            safe_max(bwd),

        "Bwd Packet Length Min":
            safe_min(bwd),

        "Bwd Packet Length Mean":
            safe_mean(bwd),

        "Bwd Packet Length Std":
            safe_std(bwd),

        "Flow Bytes/s":
            flow_bytes_per_second,

        "Flow Packets/s":
            flow_packets_per_second,

        "Flow IAT Mean":
            safe_mean(all_iat),

        "Flow IAT Std":
            safe_std(all_iat),

        "Flow IAT Max":
            safe_max(all_iat),

        "Flow IAT Min":
            safe_min(all_iat),

        "Fwd IAT Total":
            safe_sum(fwd_iat),

        "Fwd IAT Mean":
            safe_mean(fwd_iat),

        "Fwd IAT Std":
            safe_std(fwd_iat),

        "Fwd IAT Max":
            safe_max(fwd_iat),

        "Fwd IAT Min":
            safe_min(fwd_iat),

        "Bwd IAT Total":
            safe_sum(bwd_iat),

        "Bwd IAT Mean":
            safe_mean(bwd_iat),

        "Bwd IAT Std":
            safe_std(bwd_iat),

        "Bwd IAT Max":
            safe_max(bwd_iat),

        "Bwd IAT Min":
            safe_min(bwd_iat),

        "Fwd PSH Flags":
            flow["fwd_psh"],

        "Fwd Header Length":
            fwd_header_length,

        "Bwd Header Length":
            bwd_header_length,

        "Fwd Packets/s":
            fwd_packets_per_second,

        "Bwd Packets/s":
            bwd_packets_per_second,

        "Min Packet Length":
            safe_min(all_lengths),

        "Max Packet Length":
            safe_max(all_lengths),

        "Packet Length Mean":
            packet_length_mean,

        "Packet Length Std":
            safe_std(all_lengths),

        "Packet Length Variance":
            safe_variance(all_lengths),

        "FIN Flag Count":
            flow["fin"],

        "SYN Flag Count":
            flow["syn"],

        "RST Flag Count":
            flow["rst"],

        "PSH Flag Count":
            flow["psh"],

        "ACK Flag Count":
            flow["ack"],

        "URG Flag Count":
            flow["urg"],

        "ECE Flag Count":
            flow["ece"],

        "Down/Up Ratio":
            down_up_ratio,

        "Average Packet Size":
            packet_length_mean,

        "Avg Fwd Segment Size":
            safe_mean(fwd),

        "Avg Bwd Segment Size":
            safe_mean(bwd),

        "Fwd Header Length.1":
            fwd_header_length,

        "Subflow Fwd Packets":
            flow["forward_count"],

        "Subflow Fwd Bytes":
            flow["forward_bytes"],

        "Subflow Bwd Packets":
            flow["backward_count"],

        "Subflow Bwd Bytes":
            flow["backward_bytes"],

        "Init_Win_bytes_forward":
            flow["init_win_forward"],

        "Init_Win_bytes_backward":
            flow["init_win_backward"],

        "act_data_pkt_fwd":
            flow["act_data_pkt_fwd"],

        "min_seg_size_forward":
            flow["min_seg_size_forward"],

        "Active Mean":
            0.0,

        "Active Std":
            0.0,

        "Active Max":
            0.0,

        "Active Min":
            0.0,

        "Idle Mean":
            0.0,

        "Idle Std":
            0.0,

        "Idle Max":
            0.0,

        "Idle Min":
            0.0
    }


    # ========================================================
    # CLEAN VALUES
    # ========================================================

    for key in data:

        data[key] = clean_value(
            data[key]
        )

    return data


# ============================================================
# PREDICT FLOW
# ============================================================

def predict_flow(flow):

    global prediction_counter
    global attack_counter
    global benign_counter
    global flow_counter


    # ========================================================
    # BUILD FEATURES
    # ========================================================

    features = build_features(
        flow
    )


    # ========================================================
    # CREATE DATAFRAME
    # ========================================================

    row = pd.DataFrame(
        [features],
        columns=FEATURES
    )


    row = row.replace(
        [np.inf, -np.inf],
        np.nan
    )

    row = row.fillna(0)


    # ========================================================
    # SAME LOG TRANSFORMATION USED DURING V6 TRAINING
    # ========================================================

    row = (
        np.sign(row)
        *
        np.log1p(
            np.abs(row)
        )
    )


    # ========================================================
    # SCALE
    # ========================================================

    X_scaled = scaler.transform(
        row
    )


    # ========================================================
    # PREDICTION
    # ========================================================

    prediction = model.predict(
        X_scaled
    )[0]


    probabilities = model.predict_proba(
        X_scaled
    )[0]


    confidence = float(
        np.max(probabilities)
    )


    # ========================================================
    # LABEL
    # ========================================================

    if prediction == 1:

        label = "ATTACK"

        attack_counter += 1

    else:

        label = "BENIGN"

        benign_counter += 1


    prediction_counter += 1

    flow_counter += 1


    # ========================================================
    # TIMESTAMP
    # ========================================================

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    duration = (
        flow["last"]
        -
        flow["start"]
    )


    # ========================================================
    # TERMINAL OUTPUT
    # ========================================================

    print()

    print("-" * 70)

    if label == "ATTACK":

        print(
            "!!! ATTACK DETECTED !!!"
        )

    else:

        print(
            "BENIGN TRAFFIC"
        )


    print(
        "Time       :",
        timestamp
    )


    print(
        "Flow       :",
        flow["src"],
        flow["src_port"],
        "->",
        flow["dst"],
        flow["dst_port"]
    )


    print(
        "Protocol   :",
        flow["protocol"]
    )


    print(
        "Packets    :",
        flow["forward_count"]
        +
        flow["backward_count"]
    )


    print(
        "Duration   :",
        round(
            duration,
            3
        ),
        "seconds"
    )


    print(
        "Prediction :",
        label
    )


    print(
        "Confidence :",
        round(
            confidence,
            4
        )
    )


    # ========================================================
    # SAVE RESULT
    # ========================================================

    result = pd.DataFrame(
        [{
            "Timestamp":
                timestamp,

            "Source_IP":
                flow["src"],

            "Source_Port":
                flow["src_port"],

            "Destination_IP":
                flow["dst"],

            "Destination_Port":
                flow["dst_port"],

            "Protocol":
                flow["protocol"],

            "Flow_Duration":
                duration,

            "Packets":
                flow["forward_count"]
                +
                flow["backward_count"],

            "Prediction":
                label,

            "Confidence":
                confidence
        }]
    )


    result.to_csv(
        RESULT_FILE,
        mode="a",
        header=False,
        index=False
    )


# ============================================================
# PACKET CALLBACK
# ============================================================

def process_packet(packet):

    global packet_counter


    if IP not in packet:
        return


    packet_counter += 1


    flow_keys = get_flow_key(
        packet
    )


    if flow_keys is None:
        return


    forward_key, backward_key = flow_keys


    # ========================================================
    # EXISTING FORWARD FLOW
    # ========================================================

    if forward_key in flows:

        update_flow(
            flows[forward_key],
            packet,
            forward=True
        )

        return


    # ========================================================
    # EXISTING BACKWARD FLOW
    # ========================================================

    if backward_key in flows:

        update_flow(
            flows[backward_key],
            packet,
            forward=False
        )

        return


    # ========================================================
    # NEW FLOW
    # ========================================================

    flow = create_flow(
        packet
    )


    update_flow(
        flow,
        packet,
        forward=True
    )


    flows[forward_key] = flow


    if PRINT_EVERY_PACKET:

        print(
            "New flow:",
            forward_key
        )


# ============================================================
# EXPIRE OLD FLOWS
# ============================================================

def expire_flows():

    now = time.time()

    expired = []


    for key, flow in list(
        flows.items()
    ):

        if (
            now
            -
            flow["last"]
            >=
            FLOW_TIMEOUT
        ):

            expired.append(
                key
            )


    for key in expired:

        flow = flows.pop(
            key
        )


        total_packets = (
            flow["forward_count"]
            +
            flow["backward_count"]
        )


        if total_packets >= 2:

            try:

                predict_flow(
                    flow
                )

            except Exception as e:

                print(
                    "\nPrediction error:",
                    repr(e)
                )


# ============================================================
# SUMMARY
# ============================================================

def print_summary():

    print()

    print("=" * 70)

    print(
        "LIVE DETECTION SUMMARY"
    )

    print(
        "Packets captured :",
        packet_counter
    )

    print(
        "Flows analyzed   :",
        flow_counter
    )

    print(
        "BENIGN           :",
        benign_counter
    )

    print(
        "ATTACK           :",
        attack_counter
    )

    print(
        "Active flows     :",
        len(flows)
    )

    print("=" * 70)


# ============================================================
# MAIN LOOP
# ============================================================

print()

print("=" * 70)

print(
    "LIVE DETECTION STARTED"
)

print("=" * 70)

print()

print(
    "Wi-Fi interface :",
    getattr(
        iface,
        "name",
        ""
    )
)

print(
    "Flow timeout    :",
    FLOW_TIMEOUT,
    "seconds"
)

print(
    "Result file     :",
    RESULT_FILE
)

print()

print(
    "Press CTRL+C to stop."
)

print()


last_summary = time.time()


try:

    while True:

        sniff(
            iface=iface,
            prn=process_packet,
            store=False,
            timeout=1
        )

        expire_flows()


        if (
            time.time()
            -
            last_summary
            >= 10
        ):

            print_summary()

            last_summary = time.time()


except KeyboardInterrupt:

    print()

    print("=" * 70)

    print(
        "STOPPING LIVE DETECTOR"
    )

    print("=" * 70)


    # ========================================================
    # PROCESS REMAINING FLOWS
    # ========================================================

    for key, flow in list(
        flows.items()
    ):

        total_packets = (
            flow["forward_count"]
            +
            flow["backward_count"]
        )


        if total_packets >= 2:

            try:

                predict_flow(
                    flow
                )

            except Exception as e:

                print(
                    "Final flow prediction error:",
                    repr(e)
                )


    flows.clear()


    print_summary()


    print()

    print(
        "Results saved to:"
    )

    print(
        RESULT_FILE
    )

    print()

    print(
        "Live detection stopped."
    )