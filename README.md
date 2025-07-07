# **DDOS Anomaly Detection and Prevention System**

This project implements a robust DDoS (Distributed Denial of Service) anomaly detection and prevention system.
The system combines real-time network traffic analysis, a hybrid detection engine (machine learning and rule-based approaches), an Intrusion Prevention System (IPS) using iptables and extensive detailed monitoring capabilities using Grafana and Prometheus along with instant Telegram alerts and a user-friendly web dashboard.

## **🚀 Features**
i) **Real-time Packet Sniffing**: Efficient capturing of live network traffic is achieved through the use of **Scapy** and **tshark**.

ii) **Hybrid Detection engine**
 
* **Machine Learning (ML) detection**: Utilization of a pre-trained **XGBoost model** to detect advanced and evolving DDoS attacks by analysing network flow statistics.

*  **Rule-Based Detection**: Identification of common DDoS attacks patterns such as **HTTP floods**, **SYN floods**, **ACK floods**, **FIN/RST floods** and **DNS query floods** based on configurable thresholds.

iii) **Intrusion Prevention System**: Automatic blocking of detected malicious IP Addresses using **iptables** rules. IPs can be blocked temporarily for a defined duration or indefinitely marked as malicious.

iv) **Telegram Alerts**: Instant notifications will be sent to a designated Telegram chatbot for critical events such like DDoS detections, IP blocks and unblocks.

v) **Prometheus Metrics** : Exposes a comprehensive set of metrics for real-time monitoring of attack types, packet counts, IPS actions, and application uptime. This data is ideal for integration with visualization tools like Grafana.

vi) **ML Model Training Pipeline** : A dedicated Python script (train.py) is included to preprocess network data (from PCAP and CSV files), extract flow-based features, train an XGBoost classifier, and evaluate its performance. This allows for continuous improvement and adaptation of the ML detection capabilities.

vii) **Web Interface (Dashboard)** : A simple, user-friendly web interface provides a central point to:

* Toggle the detection system on/off.

* View real-time alerts.

* See currently blocked IP addresses.

* Manage IP classifications (false positives or malicious) and manually unblock IPs, all secured with OTP (One-Time Password) verification.
# **⚙️ Technologies Used**
* Python 3.x

* Flask: Web framework for the API and basic UI.

* Scapy: Powerful packet manipulation program for network sniffing and crafting in **api.py**.

* Pyshark: Python wrapper for Tshark, used in train.py to read PCAP files.

* Tshark: Command-line network protocol analyzer (part of Wireshark) used for efficient live packet capture in **api.py**.

* Prometheus: Monitoring system for collecting and storing time series data as metrics.

* Grafana: Data visualization and analytics platform (recommended for dashboarding Prometheus metrics).

* iptables: Linux firewall utility for managing IP packet filter rules, used for blocking.

* scikit-learn & xgboost: Machine learning libraries for model training and prediction.

* joblib: Python library for saving and loading trained ML models and scalers.

* pandas & numpy: Data manipulation and numerical computing for feature extraction and processing.

* flask_cors: Flask extension for handling Cross-Origin Resource Sharing (CORS).

* requests: Python HTTP library for sending Telegram alerts.

* matplotlib & seaborn: Python libraries for data visualization, used in train.py for plotting.

# **🛠️ Setup and Installation**
## **Prerequisites**
Before you begin, ensure you have the following installed on your Linux system (Debian/Ubuntu based commands shown). This project requires root privileges for tshark and iptables.

1. Python 3.x and pip

```sudo apt update

sudo apt install python3 python3-pip
````
2. Tshark (Wireshark)

`sudo apt install tshark`

* **Important**: You might need to configure tshark to allow non-root users to capture packets. Run:

```sudo dpkg-reconfigure wireshark-common
sudo usermod -a -G wireshark $USER
# Log out and log back in for changes to take effect.
```
3. **iptables**

`sudo apt install iptables`

4. **Prometheus & Grafana**: While not strictly part of this project's code, they are essential for monitoring. 
Refer to their official documentation for installation

* [Prometheus Installation guide](https://prometheus.io/docs/prometheus/latest/installation/) 

* [Grafana Installation guide ](https://www.google.com/search?q=https://grafana.com/docs/grafana/latest/setup-and-upgrade/install/)


# **Project Installation** 
1. **Clone the repository** 

```git clone https://github.com/RyanK-04/DDoSAnomalyDetection.git ```

`cd <Directory Path>`

2. **Install Python dependencies**  
Install the required dependencies  

`pip install -r requirements.txt`

**3. Prepare ML Model and Scaler** 
* The api.py expects a trained ML model (ddos_model.joblib) and a scaler (scaler.joblib) in the project root.
* You can train these yourself using the train.py script (see "Training the ML Model" section below) or place your pre-trained files there.
* If these files are not present, the ML detection in api.py will be disabled, and only rule-based detection will be active.

4. **Configure Telegram API**
* Obtain a Telegram Bot Token from BotFather on Telegram.
* Find your Telegram Chat ID (you can send a message to your bot, then open https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates in your browser to find the chat_id).
* Set these as environment variables for security and flexibility. For example, before running api.py:

`export TELEGRAM_TOKEN="YOUR_TELEGRAM_BOT_TOKEN_HERE" `     
`export TELEGRAM_CHAT_ID="YOUR_TELEGRAM_CHAT_ID_HERE"`

* Alternatively, you can directly set them in api.py, but this is less secure for production:

`TELEGRAM_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN_HERE"`   
`TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID_HERE"`

5. **Create a Log Directory**   
The application will create a logs directory in the project root for alert and action logs. Ensure the application has write permissions to this directory.
`mkdir -p logs`

# **🚀 Running the Application**
To run the Flask application:   
`sudo python3 api.py`   
* The application will start on https://localhost:5000/
* Running with sudo is often necessary for tshark to capture packets and for iptables commands to execute.

## **Accessing the Web Interface** 
Open your web browser and navigate to https://localhost:5000/ 

The interface provides controls and status updates:
* **Toggle Detection**: Start or stop the sniffing and analysis threads.
* **Currently Blocked IPs**: Displays IPs that iptables has blocked.
* **Request OTP**: Use this to get an OTP via Telegram to classify an IP as a false positive or permanently malicious.
* **Verify OTP**: Enter the IP and OTP received to confirm the classification or unblock action.
* **Remove IP Classification**: Remove an IP from the false positive or malicious list.
* **Go to Grafana Dashboard**: This is where you would link to your configured Grafana dashboard for full monitoring.

## **Monitoring with Prometheus and Grafana**
The Flask application exposes Prometheus metrics at https://localhost:9090/metrics.
Configure your Prometheus server to scrape this endpoint. An example prometheus.yml snippet:

```# prometheus.yml
scrape_configs:
  - job_name: 'ddos-detector'
    static_configs:
      - targets: ['localhost:9090']
```
After Prometheus collects data, you can import the metrics into Grafana to create custom dashboards. Use the exposed metric names (e.g., malicious_packet_count, alerts_triggered, ips_blocked_total, syn_flood_packets_gauge, etc.) to build insightful visualizations.

# **🧠 Code Explanation**
1. **api.py** - This is the main Flask application that runs the real-time detection, IPS, and exposes the web interface and API endpoints.

**Flask Application Setup and Prometheus Metrics** 
```from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
# ... other imports
from prometheus_flask_exporter import PrometheusMetrics
from prometheus_client import Gauge, Counter

app = Flask(__name__)
CORS(app) # Enables Cross-Origin Resource Sharing
metrics = PrometheusMetrics(app) # Integrates Prometheus metrics collection

# Prometheus metrics definitions (examples):
malicious_packet_count = Gauge('malicious_packet_count', 'Number of packets marked as malicious')
alerts_triggered = Counter('alerts_triggered', 'Number of alerts triggered')
# ... many more metrics for different attack types and IPS actions
```
* Flask(__name__): Initializes the Flask web application
* CORS(app): Essential for web applications where the frontend might be served from a different origin than the backend API
* PrometheusMetrics(app): This library simplifies exposing metrics. It automatically handles basic Flask metrics (like request counts, latency) and allows you to define custom metrics using Gauge (for values that can go up/down) and Counter (for cumulative values that only increase). These metrics are vital for monitoring the system's health and attack patterns.

## **ML Model Loading and Global State** 
````
MODEL_PATH = "filepath to saved model"

SCALER_PATH = "filepath to saved scaler "
try:

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print("ML model and scaler loaded successfully.")
except FileNotFoundError:   
    print(f"Error: ML model or scaler file not found... ML detection disabled.")    
    model = None    
    scaler = None

# Global variables for application state
alerts = [] # List to store detected alert objects      
is_detection_running = False # Boolean flag to control detection threads
otp_store = {} # Stores OTPs issued for IP management (key: IP, value: (type, otp))
false_positives = set() # Set of IPs manually marked as false positives
malicious_ips = set() # Set of IPs manually marked as permanently malicious
blocked_ips = {} # Dictionary of IPs currently blocked by iptables (key: IP, value: unblock_timestamp)
tshark_process_handle = None # Handle for the tshark subprocess
shutdown_event = threading.Event() # Used to signal threads to shut down gracefully
````
* The application attempts to load a pre-trained ML model (ddos_model.joblib) and its corresponding StandardScaler (scaler.joblib). If these files are not found, ML-based detection will be disabled
* A set of global variables manage the application's real-time state, including active alerts, detection status, OTPs, and the lists of recognized false positives, malicious IPs, and currently blocked IPs.

## **Telegram Integration** 
````
TELEGRAM_TOKEN = "TELEGRAM_TOKEN" # Placeholder 

TELEGRAM_CHAT_ID = "TELEGRAM_CHAT_ID" # Placeholder         

LOG_DIR = "logs"

os.makedirs(LOG_DIR, exist_ok=True)

def send_telegram_alert(message):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:

        print("[Telegram] Telegram credentials not set. Skipping alert.")
        return
    # ... (HTTP request to Telegram API)
````
* This section defines the Telegram bot token and chat ID, which should ideally be set as environment variables for security.
* The send_telegram_alert function uses the requests library to send formatted messages to your designated Telegram chat, providing immediate notifications.

## **IPS (iptables) Management** 
````
def add_iptables_rule(ip_address):
    try:
        # Check if rule exists, then add if not
        add_cmd = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP']
        subprocess.run(add_cmd, capture_output=True, text=True, check=True)
        # ... (logging and metric increment)
    except subprocess.CalledProcessError as e:
        # ... (error handling)

def delete_iptables_rule(ip_address):
    try:
        # Check if rule exists, then delete
        del_cmd = ['sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP']
        subprocess.run(del_cmd, capture_output=True, text=True, check=True)
        # ... (logging and metric increment)
    except subprocess.CalledProcessError as e:
        # ... (error handling)
````
* add_iptables_rule adds a rule to the INPUT chain to DROP all incoming traffic from a specified ip_address, effectively blocking it
* delete_iptables_rule removes a previously added DROP rule, unblocking the IP
* Both functions use subprocess.run to execute shell commands with sudo, requiring appropriate permissions for the application

## **Packet Handling and Feature Collection (scapy_packet_handler)**
````
def scapy_packet_handler(pkt):
    global current_window_total_packet_counts, ..., flow_stats

    src_ip = 'N/A'
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src

    if src_ip in blocked_ips and time.time() < blocked_ips[src_ip]:
        return # Drop packets from currently blocked IPs

    try:
        if pkt.haslayer(IP):
            with counts_lock: # Protects shared data from race conditions
                current_window_total_packet_counts[src_ip] += 1
                # Collect flow statistics for ML:
                flow_key = (src_ip, pkt[IP].dst, pkt.highest_layer)
                stats = flow_stats[flow_key]
                stats['packet_count'] += 1
                stats['total_bytes'] += int(pkt.length)
                stats['timestamps'].append(float(pkt.sniff_time.timestamp()))
                stats['protocol'] = pkt.highest_layer

                # Count specific packet types for rule-based detection:
                if pkt.haslayer(TCP):
                    tcp_packets_total.inc()
                    flags = pkt[TCP].flags
                    # ... (SYN, ACK, FIN/RST, HTTP request counts)
                elif pkt.haslayer(UDP):
                    udp_packets_total.inc()
                    # ... (DNS query counts)
                elif pkt.haslayer(ICMP):
                    icmp_packets_total.inc()
    except Exception as e:
        print(f"Error in scapy_packet_handler: {e}")
````
* This function is the heart of the packet processing. It's called for every captured packet
* It filters out packets from already blocked IPs to reduce processing overhead
* It uses counts_lock (a threading.Lock) to ensure thread-safe updates to global dictionaries that store packet counts and flow statistics across different threads
* It aggregates flow statistics (flow_stats) for later ML feature extraction (e.g., packet count, total bytes, timestamps per flow)
* It maintains real-time counts for specific packet types (SYN, ACK, FIN/RST, HTTP requests, DNS queries) per source IP, which are used by the rule-based detection engine

## **Tshark/Scapy Sniffing Thread (tshark_scapy_sniffing_thread)**
````
def tshark_scapy_sniffing_thread(interface_to_sniff):
    global is_detection_running, tshark_process_handle
    try:
        # Command to run tshark as a subprocess, outputting pcap to stdout
        cmd = ['sudo', 'tshark', '-i', interface_to_sniff, '-F', 'pcap', '-w', '-', '-l', '-B', '1']
        tshark_process_handle = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        reader = PcapReader(tshark_process_handle.stdout) # Scapy's PcapReader reads from tshark's stdout
        for pkt in reader:
            if shutdown_event.is_set() or not is_detection_running:
                break # Exit if shutdown signal is received
            if pkt:
                scapy_packet_handler(pkt) # Process each packet
            # ... (Tshark process health check)
    except FileNotFoundError:
        print("Error: 'tshark' command not found.")
        # ... (set shutdown event)
    except Exception as e:
        print(f"Tshark/Scapy sniffing thread error on {interface_to_sniff}: {e}")
        # ... (set shutdown event)
    finally:
        # Ensure tshark process is terminated on exit
        if tshark_process_handle and tshark_process_handle.poll() is None:
            tshark_process_handle.terminate()
            # ... (graceful shutdown / kill)
````
* This function runs in a separate thread and is responsible for continuously capturing network traffic
* It executes tshark as a subprocess, directing its PCAP output to stdout
* PcapReader(tshark_process_handle.stdout) from Scapy is used to read packets directly from tshark's standard output, allowing for efficient live processing without saving temporary files
* Each captured packet is then passed to scapy_packet_handler for feature extraction and counting
* It includes robust error handling and ensures the tshark process is terminated cleanly when the detection system is stopped

## **ML Feature Extraction for Real-time Analysis (extract_ml_features)**
````
def extract_ml_features(flow_stats_subset):
    features = []
    for flow_key, stats in flow_stats_subset.items():
        if len(stats['timestamps']) < 2:
            continue # Need at least 2 timestamps to calculate IAT
        diffs = np.diff(stats['timestamps'])
        flow_duration = stats['timestamps'][-1] - stats['timestamps'][0]
        features.append({
            'Flow Duration': flow_duration,
            'Total Fwd Packets': stats['packet_count'],
            'Total Backward Packets': 0, # Placeholder, depends on specific flow definition
            'Flow Bytes/s': stats['total_bytes'] / max(1e-5, flow_duration),
            'Flow Packets/s': stats['packet_count'] / max(1e-5, flow_duration),
            'Flow IAT Mean': np.mean(diffs),
            'Flow IAT Std': np.std(diffs),
            'Flow IAT Max': np.max(diffs),
            'Flow IAT Min': np.min(diffs)
        })
    return pd.DataFrame(features)
````
* This function takes a subset of flow_stats (typically for a single IP) and transforms them into a Pandas DataFrame, ready for the ML model
* It calculates various flow-based features like flow duration, packet counts, bytes/second, packets/second, and Inter-Arrival Time (IAT) statistics (mean, std, max, min). These are common features used in network intrusion detection
* Note the Total Backward Packets is set to 0, which might imply a simplified flow definition focused on source-initiated traffic

## **Periodic Analysis and Detection Thread (periodic_analysis_thread)**
````
def periodic_analysis_thread(
        total_traffic_threshold=20, syn_flood_threshold=10, # ... other thresholds
        block_duration_minutes=5
):
    global alerts, is_detection_running, blocked_ips, flow_stats
    while is_detection_running and not shutdown_event.is_set():
        time.sleep(5) # Analysis window (e.g., every 5 seconds)
        # ... (IP unblocking logic)

        with counts_lock: # Get a snapshot of current counts and clear for next window
            temp_total_packet_counts = current_window_total_packet_counts.copy()
            # ... (copy other counts and flow_stats, then clear originals)

        # Reset Prometheus gauges for the new window
        syn_flood_packets_gauge.set(0)
        # ... (reset other gauges)

        # ML feature extraction and prediction for each IP
        ml_predictions = {}
        if model is not None and scaler is not None:
            # ... (Iterate through IPs, extract features, scale, and predict)
            if y_pred.any(): # If any prediction is malicious (1)
                ml_predictions[ip] = 1
                ml_malicious_detections.inc() # Increment Prometheus counter

        # Rule-based and ML-based detection logic for each IP
        for ip in all_ips_in_window:
            if ip in false_positives or (ip in blocked_ips and current_time < blocked_ips[ip]):
                continue # Skip processing for known false positives or already blocked IPs

            is_malicious = False
            detection_messages = []
            total_count = temp_total_packet_counts.get(ip, 0)
            if total_count > total_traffic_threshold:
                detection_messages.append(f"High total traffic ({total_count} packets/5s)")
                is_malicious = True
            # ... (Check other rule-based thresholds: SYN, ACK, FIN/RST, HTTP, DNS floods)

            if ip in ml_predictions and ml_predictions[ip] == 1:
                detection_messages.append("ML-based DDoS detection")
                is_malicious = True

            if is_malicious:
                # ... (Append alert, log to file, send Telegram alert)
                total_malicious_in_window += total_count
                if ip not in blocked_ips or current_time >= blocked_ips[ip]:
                    if add_iptables_rule(ip):
                        # Block indefinitely if explicitly marked malicious, else for block_duration_minutes
                        blocked_until = current_time + block_duration_minutes * 60 if ip not in malicious_ips else float('inf')
                        blocked_ips[ip] = blocked_until
                        # ... (Send Telegram block alert)
            else:
                total_benign_in_window += total_count

        malicious_packet_count.set(total_malicious_in_window)
        benign_packet_count.set(total_benign_in_window)
````
* This is another critical thread that runs periodically (every 5 seconds)
* **Automatic Unblocking**: It first checks for and unblocks IPs whose block duration has expired
* **Snapshot and Clear**: It takes a snapshot of the current_window packet counts and flow_stats collected by scapy_packet_handler, then clears them for the next window. This ensures analysis is based on distinct time intervals
* **ML Prediction**: If the ML model is loaded, it extracts features for each active IP in the current window, scales them, and makes predictions
* **Hybrid Detection Logic**: For each IP, it checks both:
  * **Rule-based thresholds**: If any of the traffic counts (total, SYN, ACK, etc.) exceed their defined thresholds
  * **ML prediction**: If the ML model classifies the IP's traffic as malicious
* **Alerting and Blocking**: If an IP is deemed malicious by either method, an alert is generated, logged, a Telegram alert is sent, and the IP is added to iptables for blocking. The block duration is infinite if the IP was marked as manually malicious
* **Prometheus Updates**: malicious_packet_count and benign_packet_count gauges are updated to reflect the overall traffic classification in the window

## **Master Detection Control (detection_real_traffic_master)**
````
def detection_real_traffic_master():
    global is_detection_running, shutdown_event
    print("✅ Master Detection started.")
    interface_to_sniff = "ens33" # Configurable network interface
    shutdown_event.clear() # Clear shutdown signal for a fresh start
    sniff_thread = threading.Thread(target=tshark_scapy_sniffing_thread, args=(interface_to_sniff,))
    sniff_thread.daemon = True # Allows program to exit even if thread is running
    sniff_thread.start()
    analysis_thread = threading.Thread(target=periodic_analysis_thread, args=(50, 20, 20, 20, 10, 30, 5)) # Pass thresholds
    analysis_thread.daemon = True
    analysis_thread.start()
    print(f"Sniffing on interface: {interface_to_sniff}")
````
* This function acts as the orchestrator. When detection is started, it launches two separate daemon threads:
  * One for packet sniffing (tshark_scapy_sniffing_thread)
  * One for periodic analysis and detection (periodic_analysis_thread)
* Daemon threads are useful here because they will automatically terminate when the main program exits

## **Flask API Endpoints**
````
@app.route("/api/alerts")
def get_alerts():
    return jsonify({"alerts": alerts})

@app.route("/api/detection_status")
def detection_status():
    return jsonify({"is_running": is_detection_running, "blocked_ips": {ip: time.ctime(ts) for ip, ts in blocked_ips.items()}})

@app.route("/api/toggle_detection", methods=["POST"])
def toggle_detection():
    global is_detection_running, shutdown_event
    if not is_detection_running:
        is_detection_running = True
        thread = threading.Thread(target=detection_real_traffic_master)
        thread.daemon = True
        thread.start()
        return jsonify({"status": "Detection started"})
    else:
        is_detection_running = False
        shutdown_event.set() # Signal threads to stop
        return jsonify({"status": "Detection stopped"})

@app.route("/api/request_otp_fp", methods=["POST"])
# ... similar for /api/request_otp_malicious
# ... /api/verify_otp
# ... /api/remove_ip
# ... /api/manual_unblock

@app.route('/')
def index():
    return render_template_string('''...html content...''')
````
* **/api/alerts**: Returns a JSON list of all current detection alerts.
* **/api/detection_status**: Provides the current running status of the detection system and a list of currently blocked IPs.
* **/api/toggle_detection (POST)**: Starts or stops the entire detection system by setting the is_detection_running flag and managing the background threads. When stopping, it sets the shutdown_event to gracefully terminate threads.
* **OTP-related endpoints (/api/request_otp_fp, /api/request_otp_malicious, /api/verify_otp, /api/remove_ip, /api/manual_unblock)**: These endpoints handle the secure management of IP addresses. They generate and verify OTPs (sent via Telegram) to confirm actions like marking an IP as a false positive (which also unblocks it if currently blocked), marking an IP as permanently malicious (and blocking it indefinitely), or manually unblocking an IP. This adds a layer of security to critical IPS actions.
* **/**: Serves the main HTML content for the web dashboard, which interacts with these API endpoints via JavaScript.

## **train.py - ML Model Training Pipeline**
This script handles the data preprocessing, feature extraction, model training, and evaluation for the machine learning component of the DDoS detection system.
````
import os
import time
import pandas as pd
import numpy as np
from collections import defaultdict
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from xgboost import XGBClassifier
from joblib import dump
import pyshark
import matplotlib.pyplot as plt
import seaborn as sns

# Configuration paths and parameters
PCAP_PATH = r"filepath" # Path to PCAP file for training data
CSV_PATH = r"filepath" # Path to CSV file (e.g., CICDDoS2019 dataset)
MODEL_PATH = "filepath to the saved model" # Output path for the trained model
SCALER_PATH = "filepath to the saved scaler" # Output path for the trained scaler
TEST_SIZE = 0.8 # Proportion of data for validation/testing
RANDOM_STATE = 42
MAX_PCAP_PACKETS = 5000 # Limit for packets to read from PCAP
````
* **PCAP_PATH, CSV_PATH**: Define the input data sources for training. You'll need to specify actual file paths here. train.py can combine data from both PCAP files (live captures) and pre-labeled CSV datasets (like public DDoS datasets).
* **MODEL_PATH, SCALER_PATH**: Define where the trained XGBoost model and StandardScaler will be saved. These are the .joblib files that api.py will load.
* **TEST_SIZE**: Determines the split ratio for training and validation data.

## **Feature Extraction from PCAP (extract_pcap_features)**
````
def extract_pcap_features(pcap_path, max_packets=5000):
    print(f"Extracting features from PCAP: {pcap_path}")
    cap = pyshark.FileCapture(pcap_path, display_filter="ip") # Use pyshark to read PCAP
    flow_stats = defaultdict(lambda: {
        'packet_count': 0, 'total_bytes': 0, 'timestamps': [], 'protocol': None
    })
    # ... (Loop through packets, extract IP info, populate flow_stats similar to api.py's scapy_packet_handler)
    cap.close()

    features = []
    for flow_key, stats in flow_stats.items():
        if len(stats['timestamps']) < 2:
            continue
        diffs = np.diff(stats['timestamps'])
        flow_duration = stats['timestamps'][-1] - stats['timestamps'][0]
        features.append({
            'Flow Duration': flow_duration,
            'Total Fwd Packets': stats['packet_count'],
            'Total Backward Packets': 0, # Simplified for PCAP extraction
            'Flow Bytes/s': stats['total_bytes'] / max(1e-5, flow_duration),
            'Flow Packets/s': stats['packet_count'] / max(1e-5, flow_duration),
            'Flow IAT Mean': np.mean(diffs),
            'Flow IAT Std': np.std(diffs),
            'Flow IAT Max': np.max(diffs),
            'Flow IAT Min': np.min(diffs),
            'Label': 1 # Assuming packets from this PCAP are DDoS (manual labeling)
        })
    return pd.DataFrame(features)
````
* This function reads a PCAP file using **pyshark.FileCapture** .
* It iterates through packets and extracts flow-based features (similar to api.py), aggregating statistics for each unique flow.
* Note that the Label for features extracted from a PCAP is manually set to 1 (DDoS) here, implying that the provided PCAP_PATH should contain known attack traffic for training.

## **Loading CSV Data (load_csv_data)**
````
def load_csv_data(csv_path):
    print(f"Loading CSV: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.str.strip() # Clean column names
    df = df[df['Label'].isin(['BENIGN', 'DDoS'])] # Filter for relevant labels

    label_map = {'BENIGN': 0, 'DDoS': 1}
    df['Label'] = df['Label'].map(label_map) # Map labels to numerical values (0 for Benign, 1 for DDoS)

    selected_columns = [
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
        'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
        'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Label'
    ]
    return df[selected_columns]
````
* This function loads data from a CSV file (presumably a labeled dataset like CICDDoS2019).
* It preprocesses the data by stripping whitespace from column names, filtering for 'BENIGN' and 'DDoS' labels, and mapping these labels to numerical values (0 and 1).
* It selects a specific set of features that align with those extracted from PCAP files.

## **Model Training (train_model)**
````
def train_model(X_train, y_train, X_val, y_val):
    print("Training XGBoost model...")
    model = XGBClassifier(
        n_estimators=100, max_depth=5, learning_rate=0.1, random_state=RANDOM_STATE, n_jobs=-1
    )
    model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=True)
    return model
````
* This function initializes and trains an XGBoostClassifier, a powerful gradient boosting algorithm known for its performance in classification tasks.
* It fits the model on the X_train (features) and y_train (labels) data. eval_set is used for monitoring performance on a validation set during training.

## **Model Evaluation and Visualization (evaluate_model, plot_confusion, plot_feature_importance)**
````
def plot_confusion(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=["BENIGN", "DDoS"], yticklabels=["BENIGN", "DDoS"])
    plt.title("Confusion Matrix")
    # ... (labels and display)

def plot_feature_importance(model, feature_names):
    importance = model.feature_importances_
    # ... (plotting logic for feature importance)

def evaluate_model(model, X, y_true, feature_names=None):
    print("\nEvaluating Model...")
    y_pred = model.predict(X)

    print("\nMetrics:")
    print(f"- Accuracy:  {accuracy_score(y_true, y_pred):.4f}")
    # ... (Precision, Recall, F1 Score)

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_true, y_pred))
    plot_confusion(y_true, y_pred) # Visualize confusion matrix

    print("\nClassification Report:")
    print(classification_report(y_true, y_pred, target_names=["BENIGN", "DDoS"]))

    if feature_names is not None:
        plot_feature_importance(model, feature_names) # Visualize feature importance
````
* The **evaluate_model** function calculates and prints standard classification metrics (accuracy, precision, recall, F1-score) based on the model's predictions on a test/validation set.
* **plot_confusion** generates a heatmap of the confusion matrix, visually representing true positives, true negatives, false positives, and false negatives. This is crucial for understanding the model's performance on imbalanced datasets.
* **plot_feature_importance** visualizes the importance of each feature in the trained XGBoost model, helping to understand which network flow characteristics contribute most to the detection.

## **Main Training Logic (main function)**
````
def main():
    df_pcap = extract_pcap_features(PCAP_PATH, max_packets=MAX_PCAP_PACKETS)
    df_csv = load_csv_data(CSV_PATH)

    print(f"PCAP samples: {len(df_pcap)}, CSV samples: {len(df_csv)}")
    df = pd.concat([df_pcap, df_csv], ignore_index=True) # Combine datasets

    # Visualize class balance
    plt.figure(figsize=(6, 4))
    df['Label'].value_counts().plot(kind='bar', color=['green', 'red'])
    # ... (plot details)

    X = df.drop('Label', axis=1) # Features
    y = df['Label'] # Labels

    X.replace([np.inf, -np.inf], np.nan, inplace=True) # Handle infinite values
    X.dropna(inplace=True) # Drop rows with NaNs
    y = y.loc[X.index] # Align labels with cleaned features

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train) # Fit and transform training data
    X_val_scaled = scaler.transform(X_val) # Transform validation data
    dump(scaler, SCALER_PATH) # Save the fitted scaler

    model = train_model(X_train_scaled, y_train, X_val_scaled, y_val)
    dump(model, MODEL_PATH) # Save the trained model
    print(f"Model saved to: {MODEL_PATH}")

    evaluate_model(model, X_val_scaled, y_val, feature_names=X.columns)
````
* The main function orchestrates the entire training process:
  * Loads data from both PCAP and CSV sources
  * Concatenates the datasets
  * Visualizes the class distribution (BENIGN vs. DDoS)
  * Handles infinite and NaN values in features
  * Splits the data into training and validation sets using train_test_split with stratify=y to maintain class balance
  * Initializes and fits a StandardScaler on the training data. This is crucial for ML models as it scales features to a common range, preventing features with larger values from dominating. The fitted scaler is saved for use in api.py for real-time inference
  * Calls train_model to train the XGBoost classifier
  * Saves the trained model (ddos_model.joblib) and scaler (scaler.joblib) using joblib.dump
  * Calls evaluate_model to assess the model's performance on the validation set

## **alert.html - Web Interface (Dashboard)**
This is a simple HTML page that serves as the user interface for controlling the DDoS detection system and viewing alerts. It uses JavaScript to interact with the Flask API endpoints.
````
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DDoS Detection Dashboard</title>
    <style> /* ... CSS styles for basic layout and elements ... */ </style>
</head>
<body>
    <h1>DDoS Detection Dashboard</h1>

    <div class="section">
        <button onclick="toggleDetection()">Start/Stop Detection</button>
        <p id="status">Status: Loading...</p>
    </div>

    <div class="section">
        <h2>Detected Alerts</h2>
        <ul id="alerts"></ul>
    </div>

    <div class="section">
        <h2>Mark IP as False Positive</h2>
        <input type="text" id="fp_ip" placeholder="Enter IP">
        <button onclick="requestOtp('fp')">Request OTP</button>
    </div>

    <div class="section">
        <h2>Confirm IP as Malicious</h2>
        <input type="text" id="mal_ip" placeholder="Enter IP">
        <button onclick="requestOtp('malicious')">Request OTP</button>
    </div>

    <div class="section">
        <h2>Verify OTP</h2>
        <input type="text" id="otp_ip" placeholder="Enter IP">
        <input type="text" id="otp_code" placeholder="Enter OTP">
        <button onclick="verifyOtp()">Verify OTP</button>
        <p id="otp_result"></p>
    </div>

    <div class="section">
        <h2>Remove IP Classification</h2>
        <input type="text" id="remove_ip" placeholder="Enter IP">
        <button onclick="removeIp('fp')">Remove False Positive</button>
        <button onclick="removeIp('malicious')">Remove Malicious IP</button>
        <p id="remove_result"></p>
    </div>

    <div class="section">
        <h2>Manual Unblock IP</h2>
        <input type="text" id="manual_unblock_ip" placeholder="Enter IP to unblock">
        <input type="text" id="manual_unblock_otp" placeholder="Enter OTP">
        <button onclick="manualUnblock()">Unblock IP</button>
        <p id="manual_unblock_result"></p>
    </div>

    <hr>
    <h2>Grafana Dashboard Link</h2>
    <p>Click the link below to view the real-time Grafana dashboard:</p>
    <a href="http://your-grafana-ip:3000/d/your_dashboard_id/your-dashboard-name" target="_blank">Go to Grafana Dashboard</a>

    <script>
        // JavaScript functions for API interaction
        function toggleDetection() { /* ... */ }
        function updateStatus() { /* ... */ }
        function loadAlerts() { /* ... */ }
        function requestOtp(type) { /* ... */ }
        function verifyOtp() { /* ... */ }
        function removeIp(type) { /* ... */ }
        function manualUnblock() { /* ... */ }

        // Initial calls and periodic updates
        updateStatus();
        loadAlerts();
        setInterval(loadAlerts, 5000); // Refresh alerts every 5 seconds
        setInterval(updateBlockedIps, 5000); // Refresh blocked IPs every 5 seconds
    </script>
</body>
</html>
````
* **HTML Structure**: Provides input fields, buttons, and display areas for interaction.
* **CSS Styling**: Basic inline styles are provided for a clean, functional layout.
* **JavaScript Logic**:
  * **toggleDetection()**: Sends a POST request to /api/toggle_detection to start or stop the backend detection.
  * **updateStatus()**: Fetches the current detection status from /api/detection_status and updates the UI. It also fetches and displays the list of currently blocked IPs.
  * **loadAlerts()**: Retrieves the latest alerts from /api/alerts and dynamically updates the alerts list on the page.
  * **requestOtp(type)**: Triggers a POST request to /api/request_otp_fp or /api/request_otp_malicious to send an OTP to Telegram for the specified IP.
  * **verifyOtp()**: Sends the IP and entered OTP to /api/verify_otp to confirm a classification.
  * **removeIp(type)**: Sends a request to /api/remove_ip to remove an IP from the false positive or malicious lists.
  * **manualUnblock()**: Sends a request to /api/manual_unblock with an OTP to manually remove an IP from the system's block list.
* **Periodic Updates**: loadAlerts() and updateBlockedIps() are called periodically using setInterval to keep the dashboard real-time.

# **🔒 Security Considerations**
* **Root Privileges**: The system requires sudo for tshark and iptables. Be extremely cautious when running applications with root privileges. Consider running this project within a contained environment (e.g., a dedicated VM or Docker container with fine-grained capabilities) to minimize risk.
* **API Security**: The current web interface uses a simple OTP-based verification. For production environments, consider implementing more robust authentication and authorization mechanisms (e.g., API keys, OAuth, user login systems) to secure the API endpoints.
* **Telegram Token Security**: Never hardcode your Telegram bot token or chat ID directly in the code in a production environment. Use environment variables or a secure configuration management system.
* **iptables Rules**: Ensure you understand the iptables commands being executed. Incorrect rules can block legitimate traffic or expose your system.

# **📄 License**
````
Creative Commons Legal Code

CC0 1.0 Universal

    CREATIVE COMMONS CORPORATION IS NOT A LAW FIRM AND DOES NOT PROVIDE
    LEGAL SERVICES. DISTRIBUTION OF THIS DOCUMENT DOES NOT CREATE AN
    ATTORNEY-CLIENT RELATIONSHIP. CREATIVE COMMONS PROVIDES THIS
    INFORMATION ON AN "AS-IS" BASIS. CREATIVE COMMONS MAKES NO WARRANTIES
    REGARDING THE USE OF THIS DOCUMENT OR THE INFORMATION OR WORKS
    PROVIDED HEREUNDER, AND DISCLAIMS LIABILITY FOR DAMAGES RESULTING FROM
    THE USE OF THIS DOCUMENT OR THE INFORMATION OR WORKS PROVIDED
    HEREUNDER.

Statement of Purpose

The laws of most jurisdictions throughout the world automatically confer
exclusive Copyright and Related Rights (defined below) upon the creator
and subsequent owner(s) (each and all, an "owner") of an original work of
authorship and/or a database (each, a "Work").

Certain owners wish to permanently relinquish those rights to a Work for
the purpose of contributing to a commons of creative, cultural and
scientific works ("Commons") that the public can reliably and without fear
of later claims of infringement build upon, modify, incorporate in other
works, reuse and redistribute as freely as possible in any form whatsoever
and for any purposes, including without limitation commercial purposes.
These owners may contribute to the Commons to promote the ideal of a free
culture and the further production of creative, cultural and scientific
works, or to gain reputation or greater distribution for their Work in
part through the use and efforts of others.

For these and/or other purposes and motivations, and without any
expectation of additional consideration or compensation, the person
associating CC0 with a Work (the "Affirmer"), to the extent that he or she
is an owner of Copyright and Related Rights in the Work, voluntarily
elects to apply CC0 to the Work and publicly distribute the Work under its
terms, with knowledge of his or her Copyright and Related Rights in the
Work and the meaning and intended legal effect of CC0 on those rights.

1. Copyright and Related Rights. A Work made available under CC0 may be
protected by copyright and related or neighboring rights ("Copyright and
Related Rights"). Copyright and Related Rights include, but are not
limited to, the following:

  i. the right to reproduce, adapt, distribute, perform, display,
     communicate, and translate a Work;
 ii. moral rights retained by the original author(s) and/or performer(s);
iii. publicity and privacy rights pertaining to a person's image or
     likeness depicted in a Work;
 iv. rights protecting against unfair competition in regards to a Work,
     subject to the limitations in paragraph 4(a), below;
  v. rights protecting the extraction, dissemination, use and reuse of data
     in a Work;
 vi. database rights (such as those arising under Directive 96/9/EC of the
     European Parliament and of the Council of 11 March 1996 on the legal
     protection of databases, and under any national implementation
     thereof, including any amended or successor version of such
     directive); and
vii. other similar, equivalent or corresponding rights throughout the
     world based on applicable law or treaty, and any national
     implementations thereof.

2. Waiver. To the greatest extent permitted by, but not in contravention
of, applicable law, Affirmer hereby overtly, fully, permanently,
irrevocably and unconditionally waives, abandons, and surrenders all of
Affirmer's Copyright and Related Rights and associated claims and causes
of action, whether now known or unknown (including existing as well as
future claims and causes of action), in the Work (i) in all territories
worldwide, (ii) for the maximum duration provided by applicable law or
treaty (including future time extensions), (iii) in any current or future
medium and for any number of copies, and (iv) for any purpose whatsoever,
including without limitation commercial, advertising or promotional
purposes (the "Waiver"). Affirmer makes the Waiver for the benefit of each
member of the public at large and to the detriment of Affirmer's heirs and
successors, fully intending that such Waiver shall not be subject to
revocation, rescission, cancellation, termination, or any other legal or
equitable action to disrupt the quiet enjoyment of the Work by the public
as contemplated by Affirmer's express Statement of Purpose.

3. Public License Fallback. Should any part of the Waiver for any reason
be judged legally invalid or ineffective under applicable law, then the
Waiver shall be preserved to the maximum extent permitted taking into
account Affirmer's express Statement of Purpose. In addition, to the
extent the Waiver is so judged Affirmer hereby grants to each affected
person a royalty-free, non transferable, non sublicensable, non exclusive,
irrevocable and unconditional license to exercise Affirmer's Copyright and
Related Rights in the Work (i) in all territories worldwide, (ii) for the
maximum duration provided by applicable law or treaty (including future
time extensions), (iii) in any current or future medium and for any number
of copies, and (iv) for any purpose whatsoever, including without
limitation commercial, advertising or promotional purposes (the
"License"). The License shall be deemed effective as of the date CC0 was
applied by Affirmer to the Work. Should any part of the License for any
reason be judged legally invalid or ineffective under applicable law, such
partial invalidity or ineffectiveness shall not invalidate the remainder
of the License, and in such case Affirmer hereby affirms that he or she
will not (i) exercise any of his or her remaining Copyright and Related
Rights in the Work or (ii) assert any associated claims and causes of
action with respect to the Work, in either case contrary to Affirmer's
express Statement of Purpose.

4. Limitations and Disclaimers.

 a. No trademark or patent rights held by Affirmer are waived, abandoned,
    surrendered, licensed or otherwise affected by this document.
 b. Affirmer offers the Work as-is and makes no representations or
    warranties of any kind concerning the Work, express, implied,
    statutory or otherwise, including without limitation warranties of
    title, merchantability, fitness for a particular purpose, non
    infringement, or the absence of latent or other defects, accuracy, or
    the present or absence of errors, whether or not discoverable, all to
    the greatest extent permissible under applicable law.
 c. Affirmer disclaims responsibility for clearing rights of other persons
    that may apply to the Work or any use thereof, including without
    limitation any person's Copyright and Related Rights in the Work.
    Further, Affirmer disclaims responsibility for obtaining any necessary
    consents, permissions or other rights required for any use of the
    Work.
 d. Affirmer understands and acknowledges that Creative Commons is not a
    party to this document and has no duty or obligation with respect to
    this CC0 or use of the Work.
````

