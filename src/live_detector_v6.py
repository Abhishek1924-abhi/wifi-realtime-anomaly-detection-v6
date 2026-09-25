import os
import time
import socket
import joblib
import numpy as np
import pandas as pd

from collections import defaultdict
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP

print("=" * 70)
print("V6 - LIVE WIFI FLOW ANOMALY DETECTOR")
print("=" * 70)

# ============================================================

# PATHS

# ============================================================

MODEL_PATH = r"..\model\v6\random_forest_v6.pkl"
SCALER_PATH = r"..\model\v6\scaler_v6.pkl"
FEATURE_PATH = r"..\model\v6\features_v6.pkl"

LOG_DIR = r"..\data\results\v6\live"

LOG_PATH = os.path.join(
LOG_DIR,
"live_detection_results.csv"
)

os.makedirs(
LOG_DIR,
exist_ok=True
)

# ============================================================

# NETWORK INTERFACE

# ============================================================

INTERFACE_INDEX = 16

# ============================================================

# FLOW SETTINGS

# ============================================================

FLOW_TIMEOUT = 10
MIN_PACKETS = 2

# ============================================================

# LOAD MODEL

# ============================================================

print("\nLoading V6 model...")

model = joblib.load(
MODEL_PATH
)

print("V6 model loaded successfully.")

print("\nLoading V6 scaler...")

scaler = joblib.load(
SCALER_PATH
)

print("V6 scaler loaded successfully.")

print("\nLoading V6 feature list...")

features = joblib.load(
FEATURE_PATH
)

print(
"Features expected by V6:",
len(features)
)

# ============================================================

# FLOW STORAGE

# ============================================================

flows = {}

# ============================================================

# STATISTICS

# ============================================================

total_flows = 0
benign_flows = 0
attack_flows = 0

# ============================================================

# FLOW KEY

# ============================================================

def get_flow_key(packet):

```
if IP not in packet:
    return None

src = packet[IP].src
dst = packet[IP].dst

protocol = int(packet[IP].proto)

src_port = 0
dst_port = 0

if TCP in packet:
    src_port = int(packet[TCP].sport)
    dst_port = int(packet[TCP].dport)

elif UDP in packet:
    src_port = int(packet[UDP].sport)
    dst_port = int(packet[UDP].dport)

forward = (
    src,
    dst,
    src_port,
    dst_port,
    protocol
)

reverse = (
    dst,
    src,
    dst_port,
    src_port,
    protocol
)

if forward < reverse:
    return forward

return reverse
```

# ============================================================

# CREATE EMPTY FLOW

# ============================================================

def create_flow(packet):

```
src = packet[IP].src
dst = packet[IP].dst

protocol = int(packet[IP].proto)

src_port = 0
dst_port = 0

if TCP in packet:
    src_port = int(packet[TCP].sport)
    dst_port = int(packet[TCP].dport)

elif UDP in packet:
    src_port = int(packet[UDP].sport)
    dst_port = int(packet[UDP].dport)

packet_length = len(packet)

now = time.time()

return {
    "src": src,
    "dst": dst,
    "src_port": src_port,
    "dst_port": dst_port,
    "protocol": protocol,

    "start": now,
    "last": now,

    "forward_packets": 1,
    "backward_packets": 0,

    "forward_bytes": packet_length,
    "backward_bytes": 0,

    "forward_lengths": [
        packet_length
    ],

    "backward_lengths": [],

    "timestamps": [
        now
    ],

    "psh": 0,
    "syn": 0,
    "fin": 0,
    "rst": 0,
    "ack": 0,
    "ece": 0,

    "fwd_psh": 0,

    "fwd_iats": [],
    "bwd_iats": [],

    "last_fwd": now,
    "last_bwd": now
}
```

# ============================================================

# UPDATE FLOW

# ============================================================

def update_flow(flow, packet):

```
now = time.time()

length = len(packet)

flow["last"] = now

src = packet[IP].src

forward = (
    src == flow["src"]
)

if forward:

    previous = flow["last_fwd"]

    flow["forward_packets"] += 1

    flow["forward_bytes"] += length

    flow["forward_lengths"].append(
        length
    )

    flow["fwd_iats"].append(
        max(
            0,
            now - previous
        )
    )

    flow["last_fwd"] = now

else:

    previous = flow["last_bwd"]

    flow["backward_packets"] += 1

    flow["backward_bytes"] += length

    flow["backward_lengths"].append(
        length
    )

    flow["bwd_iats"].append(
        max(
            0,
            now - previous
        )
    )

    flow["last_bwd"] = now

if TCP in packet:

    flags = packet[TCP].flags

    flow["syn"] += int("S" in flags)

    flow["fin"] += int("F" in flags)

    flow["rst"] += int("R" in flags)

    flow["psh"] += int("P" in flags)

    flow["ack"] += int("A" in flags)

    flow["ece"] += int("E" in flags)

    if forward:
        flow["fwd_psh"] += int(
            "P" in flags
        )
```

# ============================================================

# SAFE STATISTICS

# ============================================================

def safe_mean(values):

```
if len(values) == 0:
    return 0.0

return float(
    np.mean(values)
)
```

def safe_std(values):

```
if len(values) <= 1:
    return 0.0

return float(
    np.std(values)
)
```

def safe_min(values):

```
if len(values) == 0:
    return 0.0

return float(
    np.min(values)
)
```

def safe_max(values):

```
if len(values) == 0:
    return 0.0

return float(
    np.max(values)
)
```

# ============================================================

# BUILD CIC-STYLE FEATURES

# ============================================================

def build_features(flow):

```
duration = max(
    flow["last"] - flow["start"],
    0.000001
)

total_packets = (
    flow["forward_packets"]
    +
    flow["backward_packets"]
)

total_bytes = (
    flow["forward_bytes"]
    +
    flow["backward_bytes"]
)

fwd_lengths = flow[
    "forward_lengths"
]

bwd_lengths = flow[
    "backward_lengths"
]

fwd_iats = flow[
    "fwd_iats"
]

bwd_iats = flow[
    "bwd_iats"
]

fwd_min = safe_min(
    fwd_lengths
)

fwd_max = safe_max(
    fwd_lengths
)

fwd_mean = safe_mean(
    fwd_lengths
)

fwd_std = safe_std(
    fwd_lengths
)

bwd_min = safe_min(
    bwd_lengths
)

bwd_max = safe_max(
    bwd_lengths
)

bwd_mean = safe_mean(
    bwd_lengths
)

bwd_std = safe_std(
    bwd_lengths
)

fwd_iat_mean = safe_mean(
    fwd_iats
)

fwd_iat_std = safe_std(
    fwd_iats
)

fwd_iat_min = safe_min(
    fwd_iats
)

fwd_iat_max = safe_max(
    fwd_iats
)

bwd_iat_mean = safe_mean(
    bwd_iats
)

bwd_iat_std = safe_std(
    bwd_iats
)

bwd_iat_min = safe_min(
    bwd_iats
)

bwd_iat_max = safe_max(
    bwd_iats
)

row = {}

row["Destination Port"] = flow["dst_port"]

row["Flow Duration"] = duration

row["Total Fwd Packets"] = flow[
    "forward_packets"
]

row["Total Backward Packets"] = flow[
    "backward_packets"
]

row["Total Length of Fwd Packets"] = flow[
    "forward_bytes"
]

row["Total Length of Bwd Packets"] = flow[
    "backward_bytes"
]

row["Fwd Packet Length Max"] = fwd_max

row["Fwd Packet Length Min"] = fwd_min

row["Fwd Packet Length Mean"] = fwd_mean

row["Fwd Packet Length Std"] = fwd_std

row["Bwd Packet Length Max"] = bwd_max

row["Bwd Packet Length Min"] = bwd_min

row["Bwd Packet Length Mean"] = bwd_mean

row["Bwd Packet Length Std"] = bwd_std

row["Flow Bytes/s"] = (
    total_bytes / duration
)

row["Flow Packets/s"] = (
    total_packets / duration
)

row["Flow IAT Mean"] = duration / max(
    total_packets - 1,
    1
)

row["Fwd IAT Total"] = sum(
    fwd_iats
)

row["Fwd IAT Mean"] = fwd_iat_mean

row["Fwd IAT Std"] = fwd_iat_std

row["Fwd IAT Max"] = fwd_iat_max

row["Fwd IAT Min"] = fwd_iat_min

row["Bwd IAT Total"] = sum(
    bwd_iats
)

row["Bwd IAT Mean"] = bwd_iat_mean

row["Bwd IAT Std"] = bwd_iat_std

row["Bwd IAT Max"] = bwd_iat_max

row["Bwd IAT Min"] = bwd_iat_min

row["Fwd PSH Flags"] = flow[
    "fwd_psh"
]

row["Bwd PSH Flags"] = 0

row["Fwd URG Flags"] = 0

row["Bwd URG Flags"] = 0

row["Fwd Header Length"] = 0

row["Bwd Header Length"] = 0

row["Fwd Packets/s"] = (
    flow["forward_packets"]
    /
    duration
)

row["Bwd Packets/s"] = (
    flow["backward_packets"]
    /
    duration
)

row["Min Packet Length"] = min(
    fwd_min,
    bwd_min
)

row["Max Packet Length"] = max(
    fwd_max,
    bwd_max
)

row["Packet Length Mean"] = safe_mean(
    fwd_lengths + bwd_lengths
)

row["Packet Length Std"] = safe_std(
    fwd_lengths + bwd_lengths
)

row["Packet Length Variance"] = (
    row["Packet Length Std"] ** 2
)

row["FIN Flag Count"] = flow[
    "fin"
]

row["SYN Flag Count"] = flow[
    "syn"
]

row["RST Flag Count"] = flow[
    "rst"
]

row["PSH Flag Count"] = flow[
    "psh"
]

row["ACK Flag Count"] = flow[
    "ack"
]

row["URG Flag Count"] = 0

row["CWE Flag Count"] = 0

row["ECE Flag Count"] = flow[
    "ece"
]

row["Down/Up Ratio"] = (
    flow["backward_packets"]
    /
    max(
        flow["forward_packets"],
        1
    )
)

row["Average Packet Size"] = (
    total_bytes
    /
    max(total_packets, 1)
)

row["Avg Fwd Segment Size"] = fwd_mean

row["Avg Bwd Segment Size"] = bwd_mean

row["Fwd Header Length.1"] = 0

row["Subflow Fwd Packets"] = (
    flow["forward_packets"]
)

row["Subflow Fwd Bytes"] = (
    flow["forward_bytes"]
)

row["Subflow Bwd Packets"] = (
    flow["backward_packets"]
)

row["Subflow Bwd Bytes"] = (
    flow["backward_bytes"]
)

row["Init_Win_bytes_forward"] = 0

row["Init_Win_bytes_backward"] = 0

row["act_data_pkt_fwd"] = (
    flow["forward_packets"]
)

row["min_seg_size_forward"] = fwd_min

row["Active Mean"] = 0

row["Active Std"] = 0

row["Active Max"] = 0

row["Active Min"] = 0

row["Idle Mean"] = 0

row["Idle Std"] = 0

row["Idle Max"] = 0

row["Idle Min"] = 0

row["Total Packets"] = total_packets

row["Total Bytes"] = total_bytes

row["Packets Per Second"] = (
    total_packets / duration
)

row["Bytes Per Second"] = (
    total_bytes / duration
)

row["Bytes Per Packet"] = (
    total_bytes /
    max(total_packets, 1)
)

return row
```

# ============================================================

# PREDICT FLOW

# ============================================================

def predict_flow(flow):

```
global total_flows
global benign_flows
global attack_flows

row = build_features(
    flow
)

frame = pd.DataFrame(
    [row]
)

frame = frame.reindex(
    columns=features,
    fill_value=0
)

frame = frame.replace(
    [np.inf, -np.inf],
    np.nan
)

frame = frame.fillna(0)

values = frame.to_numpy(
    dtype=np.float64
)

values = (
    np.sign(values)
    *
    np.log1p(
        np.abs(values)
    )
)

scaled = scaler.transform(
    values
)

prediction = int(
    model.predict(
        scaled
    )[0]
)

probability = float(
    model.predict_proba(
        scaled
    )[0][1]
)

total_flows += 1

result = "ATTACK"

if prediction == 0:
    result = "BENIGN"
    benign_flows += 1

if prediction == 1:
    attack_flows += 1

timestamp = datetime.now().strftime(
    "%Y-%m-%d %H:%M:%S"
)

confidence = (
    probability
    if prediction == 1
    else 1 - probability
)

print("\n" + "-" * 70)

print(
    "Time        :",
    timestamp
)

print(
    "Source      :",
    flow["src"],
    ":",
    flow["src_port"]
)

print(
    "Destination :",
    flow["dst"],
    ":",
    flow["dst_port"]
)

print(
    "Protocol    :",
    flow["protocol"]
)

print(
    "Packets     :",
    flow["forward_packets"]
    +
    flow["backward_packets"]
)

print(
    "Bytes       :",
    flow["forward_bytes"]
    +
    flow["backward_bytes"]
)

print(
    "Prediction  :",
    result
)

print(
    "Confidence  :",
    f"{confidence * 100:.2f}%"
)

print(
    "Total flows :",
    total_flows
)

print(
    "Benign      :",
    benign_flows
)

print(
    "Attacks     :",
    attack_flows
)

print("-" * 70)

log_row = {
    "Timestamp": timestamp,
    "Source": flow["src"],
    "Source_Port": flow["src_port"],
    "Destination": flow["dst"],
    "Destination_Port": flow["dst_port"],
    "Protocol": flow["protocol"],
    "Packets": (
        flow["forward_packets"]
        +
        flow["backward_packets"]
    ),
    "Bytes": (
        flow["forward_bytes"]
        +
        flow["backward_bytes"]
    ),
    "Prediction": result,
    "Attack_Probability": probability,
    "Confidence": confidence
}

log_df = pd.DataFrame(
    [log_row]
)

log_df.to_csv(
    LOG_PATH,
    mode="a",
    header=not os.path.exists(
        LOG_PATH
    ),
    index=False
)
# ============================================================

# PACKET HANDLER

# ============================================================

def packet_handler(packet):

```
if IP not in packet:
    return

key = get_flow_key(
    packet
)

if key is None:
    return

current_time = time.time()

expired = []

for flow_key, flow in list(
    flows.items()
):

    if (
        current_time
        -
        flow["last"]
        >
        FLOW_TIMEOUT
    ):

        expired.append(
            flow_key
        )

for flow_key in expired:

    flow = flows.pop(
        flow_key
    )

    packet_count = (
        flow["forward_packets"]
        +
        flow["backward_packets"]
    )

    if packet_count >= MIN_PACKETS:

        predict_flow(
            flow
        )

if key not in flows:

    flows[key] = create_flow(
        packet
    )

else:

    update_flow(
        flows[key],
        packet
    )

# ============================================================

# START

# ============================================================

print("\n" + "=" * 70)

print(
"LIVE DETECTION STARTING"
)

print("=" * 70)

print(
"Interface index :",
INTERFACE_INDEX
)

print(
"Flow timeout    :",
FLOW_TIMEOUT,
"seconds"
)

print(
"Minimum packets :",
MIN_PACKETS
)

print(
"\nPress CTRL+C to stop."
)

print(
"\nCapturing live Wi-Fi traffic..."
)

try:

sniff(
    iface=INTERFACE_INDEX,
    prn=packet_handler,
    store=False
)

except KeyboardInterrupt:

print("\n\nStopping live detector...")

for key, flow in list(
    flows.items()
):

    packet_count = (
        flow["forward_packets"]
        +
        flow["backward_packets"]
    )

    if packet_count >= MIN_PACKETS:

        predict_flow(
            flow
        )

print("\nFinal statistics")

print(
    "Total flows :",
    total_flows
)

print(
    "Benign      :",
    benign_flows
)

print(
    "Attacks     :",
    attack_flows
)

print(
    "\nLive results saved to:"
)

print(
    LOG_PATH
)

except Exception as error:

print("\nERROR:")
print(error)
