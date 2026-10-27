# 📡 Real-Time Wi-Fi Network Traffic Anomaly Detection Using Random Forest

## 📌 Overview
This project detects potentially suspicious Wi-Fi network traffic in real time using a **Random Forest machine learning model**. It analyzes captured network traffic, extracts features, and classifies activity as **BENIGN** or **ATTACK**.

## 🎯 Objectives
- 🔍 Monitor available Wi-Fi network traffic.
- 🤖 Apply a Random Forest model to classify network activity.
- 🚨 Identify potentially anomalous traffic.
- 📊 Display detection results through a dashboard.
- 📝 Record detection results for further analysis.

## ⚙️ Technologies Used
- 🐍 Python
- 🌲 Random Forest
- 📦 Scikit-learn
- 📡 Scapy
- 📊 Streamlit
- 🗂️ Pandas

## 🏗️ System Workflow
1. 📥 Capture available network packets.
2. 🔧 Extract traffic features.
3. 🧹 Prepare the features for model input.
4. 🤖 Predict whether the traffic is benign or potentially malicious.
5. 📊 Display and record the detection results.

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/Abhishek1924-abhi/wifi-realtime-anomaly-detection-v6.git
cd wifi-realtime-anomaly-detection-v6
```

### 2. Install dependencies
Activate your virtual environment and install the packages listed in `requirements.txt`, if provided.

### 3. Run the detection system
```bash
python src/live_detection_v6.py
```

### 4. Launch the dashboard
In a separate terminal, run:

```bash
streamlit run src/frontend_v6.py
```

## 📈 Expected Output
- ✅ Benign traffic classifications
- 🚨 Potential attack classifications
- 📊 Dashboard-based monitoring
- 📝 Saved detection results

*Actual results depend on the traffic visible to the capture interface and the model's performance.*

## 🔐 Applications
- 🏠 Home Wi-Fi monitoring
- 🏢 Small-network security monitoring
- 🎓 Cybersecurity education and research
- 🧪 Network anomaly detection experiments

## ⚠️ Limitations
- Detection depends on the packets visible to the selected network interface.
- Encrypted traffic may limit the information available for analysis.
- Predictions may include false positives and false negatives.
- Detection results must be validated against appropriate test data.

## 🔮 Future Enhancements
- 📉 Add precision, recall, F1-score, and false-positive-rate evaluation.
- 📡 Improve live packet capture and feature extraction.
- 📊 Add detection trends and historical analysis to the dashboard.
- ⚡ Optimize prediction speed and resource usage.

## ⚖️ Responsible Use
Use this project only on networks you own or have explicit permission to monitor. It is intended for educational and defensive security purposes.

## 👨‍💻 Author
**Abhishek B S**

## ⭐ Support
If you find this project useful, consider giving the repository a star!
