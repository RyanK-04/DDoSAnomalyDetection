from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import threading
import time
import random
import requests
import ssl
import subprocess
import os
from collections import defaultdict
from prometheus_flask_exporter import PrometheusMetrics
from prometheus_client import Gauge, Counter
import atexit
from scapy.all import IP, TCP, UDP, ICMP, Raw, DNS, DNSRR, PcapReader
from scapy.layers.http import HTTPRequest, HTTPResponse
import joblib
import pandas as pd
import numpy as np

app = Flask(__name__)
CORS(app)
metrics = PrometheusMetrics(app)

# Prometheus metrics
malicious_packet_count = Gauge('malicious_packet_count', 'Number of packets marked as malicious')
benign_packet_count = Gauge('benign_packet_count', 'Number of packets below detection threshold')
alerts_triggered = Counter('alerts_triggered', 'Number of alerts triggered')
ips_blocked_total = Counter('ips_blocked_total', 'Total number of IPs blocked by IPS')
ips_unblocked_total = Counter('ips_unblocked_total', 'Total number of IPs unblocked by IPS')
flask_uptime_seconds = Gauge('flask_uptime_seconds', 'Uptime of the Flask app in seconds')
tcp_packets_total = Counter('tcp_packets_total', 'Total number of TCP packets captured')
udp_packets_total = Counter('udp_packets_total', 'Total number of UDP packets captured')
icmp_packets_total = Counter('icmp_packets_total', 'Total number of ICMP packets captured')
syn_flood_packets_gauge = Gauge('syn_flood_packets', 'Number of SYN packets indicating a potential SYN flood')
ack_flood_packets_gauge = Gauge('ack_flood_packets', 'Number of ACK packets indicating a potential ACK flood')
fin_rst_flood_packets_gauge = Gauge('fin_rst_packets', 'Number of FIN/RST packets indicating a potential flood')
http_flood_requests_gauge = Gauge('http_flood_requests', 'Number of HTTP requests indicating a potential HTTP flood')
dns_query_flood_gauge = Gauge('dns_query_flood', 'Number of DNS queries indicating a potential DNS flood')
ml_malicious_detections = Counter('ml_malicious_detections', 'Number of IPs classified as malicious by ML model')

# Load ML model and scaler
MODEL_PATH = "ddos_model.joblib"
SCALER_PATH = "scaler.joblib"
try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print("ML model and scaler loaded successfully.")
except FileNotFoundError:
    print(f"Error: ML model or scaler file not found at {MODEL_PATH} or {SCALER_PATH}. ML detection disabled.")
    model = None
    scaler = None

# Globals
alerts = []
is_detection_running = False
otp_store = {}
false_positives = set()
malicious_ips = set()
blocked_ips = {}
tshark_process_handle = None
shutdown_event = threading.Event()

# Flow statistics for ML feature extraction
flow_stats = defaultdict(lambda: {
    'packet_count': 0,
    'total_bytes': 0,
    'timestamps': [],
    'protocol': None
})

# Packet counts for rule-based detection
current_window_total_packet_counts = defaultdict(int)
current_window_syn_counts = defaultdict(int)
current_window_ack_counts = defaultdict(int)
current_window_fin_rst_counts = defaultdict(int)
current_window_http_request_counts = defaultdict(int)
current_window_dns_query_counts = defaultdict(int)
counts_lock = threading.Lock()

# Telegram details
TELEGRAM_TOKEN = "TELEGRAM_TOKEN"
TELEGRAM_CHAT_ID = "TELEGRAM_CHAT_ID"
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

def send_telegram_alert(message):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[Telegram] Telegram credentials not set. Skipping alert.")
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        data = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }
        response = requests.post(url, data=data)
        response.raise_for_status()
        print(f"[Telegram] Alert sent successfully.")
        alerts_triggered.inc()
    except requests.exceptions.HTTPError as http_err:
        print(f"[Telegram Error] HTTP error occurred: {http_err} - Response: {http_err.response.text}")
    except Exception as e:
        print(f"[Telegram Error] An unexpected error occurred: {e}")

def add_iptables_rule(ip_address):
    try:
        check_cmd = ['sudo', 'iptables', '-C', 'INPUT', '-s', ip_address, '-j', 'DROP']
        result = subprocess.run(check_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[IPS] Rule for {ip_address} already exists.")
            return True
        add_cmd = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP']
        print(f"[IPS] Attempting to block IP: {ip_address} with command: {' '.join(add_cmd)}")
        result = subprocess.run(add_cmd, capture_output=True, text=True, check=True)
        print(f"[IPS] Successfully blocked IP: {ip_address}")
        ips_blocked_total.inc()
        return True
    except subprocess.CalledProcessError as e:
        print(f"[IPS Error] Failed to add iptables rule for {ip_address}: {e.stderr}")
        return False
    except FileNotFoundError:
        print("[IPS Error] 'sudo' or 'iptables' command not found.")
        return False
    except Exception as e:
        print(f"[IPS Error] An unexpected error occurred while blocking {ip_address}: {e}")
        return False

def delete_iptables_rule(ip_address):
    try:
        check_cmd = ['sudo', 'iptables', '-C', 'INPUT', '-s', ip_address, '-j', 'DROP']
        check_result = subprocess.run(check_cmd, capture_output=True, text=True)
        if check_result.returncode != 0:
            print(f"[IPS] No iptables rule found for {ip_address} to delete.")
            return True
        del_cmd = ['sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP']
        print(f"[IPS] Attempting to unblock IP: {ip_address} with command: {' '.join(del_cmd)}")
        result = subprocess.run(del_cmd, capture_output=True, text=True, check=True)
        print(f"[IPS] Successfully unblocked IP: {ip_address}")
        ips_unblocked_total.inc()
        return True
    except subprocess.CalledProcessError as e:
        print(f"[IPS Error] Failed to delete iptables rule for {ip_address}: {e.stderr}")
        return False
    except FileNotFoundError:
        print("[IPS Error] 'sudo' or 'iptables' command not found.")
        return False
    except Exception as e:
        print(f"[IPS Error] An unexpected error occurred while unblocking {ip_address}: {e}")
        return False

def scapy_packet_handler(pkt):
    global current_window_total_packet_counts, current_window_syn_counts, \
        current_window_ack_counts, current_window_fin_rst_counts, \
        current_window_http_request_counts, current_window_dns_query_counts, \
        flow_stats

    src_ip = 'N/A'
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src

    if src_ip in blocked_ips and time.time() < blocked_ips[src_ip]:
        return

    try:
        if pkt.haslayer(IP):
            with counts_lock:
                current_window_total_packet_counts[src_ip] += 1
                flow_key = (src_ip, pkt[IP].dst, pkt.highest_layer)
                stats = flow_stats[flow_key]
                stats['packet_count'] += 1
                stats['total_bytes'] += int(pkt.length)
                stats['timestamps'].append(float(pkt.sniff_time.timestamp()))
                stats['protocol'] = pkt.highest_layer

                if pkt.haslayer(TCP):
                    tcp_packets_total.inc()
                    flags = pkt[TCP].flags
                    if 'S' in flags and not 'A' in flags:
                        current_window_syn_counts[src_ip] += 1
                    elif 'A' in flags and not 'S' in flags:
                        current_window_ack_counts[src_ip] += 1
                    elif 'F' in flags or 'R' in flags:
                        current_window_fin_rst_counts[src_ip] += 1
                    if pkt.haslayer(Raw) and (b"GET " in pkt[Raw].load or b"POST " in pkt[Raw].load):
                        current_window_http_request_counts[src_ip] += 1
                elif pkt.haslayer(UDP):
                    udp_packets_total.inc()
                    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                        current_window_dns_query_counts[src_ip] += 1
                elif pkt.haslayer(ICMP):
                    icmp_packets_total.inc()
    except IndexError:
        pass
    except Exception as e:
        print(f"Error in scapy_packet_handler: {e}")

def tshark_scapy_sniffing_thread(interface_to_sniff):
    global is_detection_running, tshark_process_handle
    try:
        cmd = ['sudo', 'tshark', '-i', interface_to_sniff, '-F', 'pcap', '-w', '-', '-l', '-B', '1']
        tshark_process_handle = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Tshark started sniffing on interface: {interface_to_sniff} with PID {tshark_process_handle.pid}")
        reader = PcapReader(tshark_process_handle.stdout)
        for pkt in reader:
            if shutdown_event.is_set() or not is_detection_running:
                print("Tshark/Scapy sniffing thread received shutdown signal. Exiting.")
                break
            if pkt:
                scapy_packet_handler(pkt)
            if tshark_process_handle.poll() is not None:
                print(f"Tshark process unexpectedly exited with code: {tshark_process_handle.returncode}")
                stderr_output = tshark_process_handle.stderr.read().decode(errors='ignore')
                if stderr_output:
                    print(f"Tshark stderr: {stderr_output}")
                is_detection_running = False
                shutdown_event.set()
                break
    except FileNotFoundError:
        print("Error: 'tshark' command not found.")
        is_detection_running = False
        shutdown_event.set()
    except Exception as e:
        print(f"Tshark/Scapy sniffing thread error on {interface_to_sniff}: {e}")
        is_detection_running = False
        shutdown_event.set()
    finally:
        if tshark_process_handle and tshark_process_handle.poll() is None:
            print("Terminating Tshark process...")
            tshark_process_handle.terminate()
            try:
                tshark_process_handle.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("Tshark process did not terminate gracefully, killing it.")
                tshark_process_handle.kill()
            stderr_output = tshark_process_handle.stderr.read().decode(errors='ignore')
            if stderr_output:
                print(f"Tshark process final stderr: {stderr_output}")
        tshark_process_handle = None
        print("Tshark/Scapy sniffing thread exited.")

def extract_ml_features(flow_stats_subset):
    features = []
    for flow_key, stats in flow_stats_subset.items():
        if len(stats['timestamps']) < 2:
            continue
        diffs = np.diff(stats['timestamps'])
        flow_duration = stats['timestamps'][-1] - stats['timestamps'][0]
        features.append({
            'Flow Duration': flow_duration,
            'Total Fwd Packets': stats['packet_count'],
            'Total Backward Packets': 0,
            'Flow Bytes/s': stats['total_bytes'] / max(1e-5, flow_duration),
            'Flow Packets/s': stats['packet_count'] / max(1e-5, flow_duration),
            'Flow IAT Mean': np.mean(diffs),
            'Flow IAT Std': np.std(diffs),
            'Flow IAT Max': np.max(diffs),
            'Flow IAT Min': np.min(diffs)
        })
    return pd.DataFrame(features)

def periodic_analysis_thread(
        total_traffic_threshold=20,
        syn_flood_threshold=10,
        ack_flood_threshold=10,
        fin_rst_flood_threshold=10,
        http_flood_threshold=5,
        dns_flood_threshold=15,
        block_duration_minutes=5
):
    global alerts, is_detection_running, blocked_ips, flow_stats
    while is_detection_running and not shutdown_event.is_set():
        time.sleep(5)
        if not is_detection_running or shutdown_event.is_set():
            break
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        current_time = time.time()
        ips_to_unblock = [ip for ip, unblock_time in blocked_ips.items() if current_time >= unblock_time]
        for ip in ips_to_unblock:
            if delete_iptables_rule(ip):
                del blocked_ips[ip]
                print(f"[IPS] Auto-unblocked IP: {ip}")
                send_telegram_alert(f"🟢 *IP Unblocked*\nTime: {now}\nIP: `{ip}`\nReason: Block duration expired.")
            else:
                print(f"[IPS] Failed to unblock IP {ip}, keeping it in blocked_ips.")

        with counts_lock:
            temp_total_packet_counts = current_window_total_packet_counts.copy()
            temp_syn_counts = current_window_syn_counts.copy()
            temp_ack_counts = current_window_ack_counts.copy()
            temp_fin_rst_counts = current_window_fin_rst_counts.copy()
            temp_http_request_counts = current_window_http_request_counts.copy()
            temp_dns_query_counts = current_window_dns_query_counts.copy()
            current_window_total_packet_counts.clear()
            current_window_syn_counts.clear()
            current_window_ack_counts.clear()
            current_window_fin_rst_counts.clear()
            current_window_http_request_counts.clear()
            current_window_dns_query_counts.clear()
            temp_flow_stats = flow_stats.copy()
            flow_stats.clear()

        syn_flood_packets_gauge.set(0)
        ack_flood_packets_gauge.set(0)
        fin_rst_flood_packets_gauge.set(0)
        http_flood_requests_gauge.set(0)
        dns_query_flood_gauge.set(0)
        malicious_packet_count.set(0)
        benign_packet_count.set(0)

        total_malicious_in_window = 0
        total_benign_in_window = 0
        all_ips_in_window = set(temp_total_packet_counts.keys()).union(
            temp_syn_counts.keys(),
            temp_ack_counts.keys(),
            temp_fin_rst_counts.keys(),
            temp_http_request_counts.keys(),
            temp_dns_query_counts.keys()
        )

        # ML feature extraction and prediction
        ml_predictions = {}
        if model is not None and scaler is not None:
            ip_flows = defaultdict(list)
            for flow_key, stats in temp_flow_stats.items():
                src_ip = flow_key[0]
                ip_flows[src_ip].append((flow_key, stats))
            for ip in all_ips_in_window:
                if ip in false_positives or (ip in blocked_ips and current_time < blocked_ips[ip]):
                    continue
                flow_stats_subset = {k: v for k, v in temp_flow_stats.items() if k[0] == ip}
                features_df = extract_ml_features(flow_stats_subset)
                if not features_df.empty:
                    X = features_df.drop(columns=[col for col in features_df.columns if col not in [
                        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
                        'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
                        'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min'
                    ]], errors='ignore')
                    X.replace([np.inf, -np.inf], np.nan, inplace=True)
                    X.fillna(0, inplace =True)
                    X_scaled = scaler.transform(X)
                    try:
                        y_pred = model.predict(X_scaled)
                        if y_pred.any():
                            ml_predictions[ip] = 1
                            ml_malicious_detections.inc()
                        else:
                            ml_predictions[ip] = 0

        for ip in all_ips_in_window:
            if ip in false_positives:
                total_benign_in_window += temp_total_packet_counts.get(ip, 0)
                continue
            if ip in blocked_ips and current_time < blocked_ips[ip]:
                total_malicious_in_window += temp_total_packet_counts.get(ip, 0)
                continue

            is_malicious = False
            detection_messages = []
            total_count = temp_total_packet_counts.get(ip, 0)
            if total_count > total_traffic_threshold:
                detection_messages.append(f"High total traffic ({total_count} packets/5s)")
                is_malicious = True
            syn_count = temp_syn_counts.get(ip, 0)
            if syn_count > syn_flood_threshold:
                detection_messages.append(f"SYN Flood ({syn_count} SYN packets/5s)")
                is_malicious = True
            ack_count = temp_ack_counts.get(ip, 0)
            if ack_count > ack_flood_threshold:
                detection_messages.append(f"ACK Flood ({ack_count} ACK packets/5s)")
                is_malicious = True
            fin_rst_count = temp_fin_rst_counts.get(ip, 0)
            if fin_rst_count > fin_rst_flood_threshold:
                detection_messages.append(f"FIN/RST Flood ({fin_rst_count} FIN/RST packets/5s)")
                is_malicious = True
            http_request_count = temp_http_request_counts.get(ip, 0)
            if http_request_count > http_flood_threshold:
                detection_messages.append(f"HTTP Flood ({http_request_count} HTTP requests/5s)")
                is_malicious = True
            dns_query_count = temp_dns_query_counts.get(ip, 0)
            if dns_query_count > dns_flood_threshold:
                detection_messages.append(f"DNS Query Flood ({dns_query_count} DNS queries/5s)")
                is_malicious = True
            if ip in ml_predictions and ml_predictions[ip] == 1:
                detection_messages.append("ML-based DDoS detection")
                is_malicious = True

            if is_malicious:
                alert_message = f"Detected anomalies from {ip}: {', '.join(detection_messages)}"
                alert = {
                    "timestamp": now,
                    "type": "DDoS Anomaly",
                    "message": alert_message,
                    "source_ip": ip
                }
                alerts.append(alert)
                with open(f"{LOG_DIR}/alerts.log", "a") as log_file:
                    log_file.write(f"{now} ALERT: {ip} - {alert_message}\n")
                send_telegram_alert(
                    f"🚨 *DDoS Anomaly Alert*\nTime: {now}\nIP: `{ip}`\nDetails: {', '.join(detection_messages)}"
                )
                total_malicious_in_window += total_count
                if ip not in blocked_ips or current_time >= blocked_ips[ip]:
                    if add_iptables_rule(ip):
                        blocked_until = current_time + block_duration_minutes * 60 if ip not in malicious_ips else float('inf')
                        blocked_ips[ip] = blocked_until
                        print(f"[IPS] IP {ip} blocked until {time.ctime(blocked_until) if blocked_until != float('inf') else 'indefinitely'}")
                        send_telegram_alert(
                            f"⛔ *IP Blocked by IPS*\nTime: {now}\nIP: `{ip}`\nDuration: {'indefinite' if blocked_until == float('inf') else f'{block_duration_minutes} min'}\nReason: Detected as malicious: {', '.join(detection_messages)}"
                        )
                if "SYN Flood" in alert_message:
                    syn_flood_packets_gauge.set(syn_count)
                if "ACK Flood" in alert_message:
                    ack_flood_packets_gauge.set(ack_count)
                if "FIN/RST Flood" in alert_message:
                    fin_rst_flood_packets_gauge.set(fin_rst_count)
                if "HTTP Flood" in alert_message:
                    http_flood_requests_gauge.set(http_request_count)
                if "DNS Query Flood" in alert_message:
                    dns_query_flood_gauge.set(dns_query_count)
            else:
                total_benign_in_window += total_count

        malicious_packet_count.set(total_malicious_in_window)
        benign_packet_count.set(total_benign_in_window)

    print("Periodic analysis thread exited.")

def detection_real_traffic_master():
    global is_detection_running, shutdown_event
    print("✅ Master Detection started.")
    interface_to_sniff = "ens33"
    shutdown_event.clear()
    sniff_thread = threading.Thread(target=tshark_scapy_sniffing_thread, args=(interface_to_sniff,))
    sniff_thread.daemon = True
    sniff_thread.start()
    analysis_thread = threading.Thread(target=periodic_analysis_thread, args=(50, 20, 20, 20, 10, 30, 5))
    analysis_thread.daemon = True
    analysis_thread.start()
    print(f"Sniffing on interface: {interface_to_sniff}")
    print(f"Current false_positives: {list(false_positives)}")

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
        shutdown_event.set()
        return jsonify({"status": "Detection stopped"})

@app.route("/api/request_otp_fp", methods=["POST"])
def request_otp_fp():
    data = request.json
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP is required"}), 400
    otp = str(random.randint(100000, 999999))
    otp_store[ip] = ("fp", otp)
    send_telegram_alert(f"🔐 OTP for False Positive IP `{ip}`: *`{otp}`*")
    print(f"OTP for {ip} (FP): {otp}")
    return jsonify({"message": f"OTP sent for false positive IP {ip}."})

@app.route("/api/request_otp_malicious", methods=["POST"])
def request_otp_malicious():
    data = request.json
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP is required"}), 400
    otp = str(random.randint(100000, 999999))
    otp_store[ip] = ("malicious", otp)
    send_telegram_alert(f"🔐 OTP for Malicious IP `{ip}`: *`{otp}`*")
    print(f"OTP for {ip} (Malicious): {otp}")
    return jsonify({"message": f"OTP sent for malicious IP {ip}."})

@app.route("/api/verify_otp", methods=["POST"])
def verify_otp():
    data = request.json
    ip = data.get("ip")
    otp = data.get("otp")
    if not ip or not otp:
        return jsonify({"error": "IP and OTP required"}), 400
    stored = otp_store.get(ip)
    if stored and stored[1] == otp:
        category = stored[0]
        if category == "fp":
            false_positives.add(ip)
            global alerts
            alerts = [a for a in alerts if a.get("source_ip") != ip]
            if ip in blocked_ips:
                if delete_iptables_rule(ip):
                    del blocked_ips[ip]
                    send_telegram_alert(
                        f"✅ *Manual Unblock*\nTime: {time.strftime('%Y-%m-%d %H:%M:%S')}\nIP: `{ip}`\nReason: Verified as False Positive.")
                else:
                    print(f"Failed to unblock {ip} after marking as FP.")
        elif category == "malicious":
            malicious_ips.add(ip)
            if ip not in blocked_ips:
                if add_iptables_rule(ip):
                    blocked_ips[ip] = float('inf')
                    send_telegram_alert(
                        f"⛔ *IP Blocked Indefinitely*\nTime: {time.strftime('%Y-%m-%d %H:%M:%S')}\nIP: `{ip}`\nReason: Manually verified as Malicious.")
                else:
                    print(f"Failed to block {ip} after marking as malicious.")
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(f"{LOG_DIR}/actions.log", "a") as log_file:
            log_file.write(f"{now} ACTION: IP {ip} verified as {category}.\n")
        del otp_store[ip]
        return jsonify({"message": f"IP {ip} verified and marked as {category}. False positives: {list(false_positives)}"})
    return jsonify({"error": "Invalid OTP"}), 401

@app.route("/api/remove_ip", methods=["POST"])
def remove_ip():
    data = request.json
    ip = data.get("ip")
    ip_type = data.get("type")
    otp = data.get("otp")
    if not ip or not ip_type or not otp:
        return jsonify({"error": "IP, type, and OTP required"}), 400
    stored = otp_store.get(ip)
    if stored and stored[1] == otp:
        del otp_store[ip]
        removed_status = False
        message = ""
        current_time = time.strftime("%Y-%m-%d %H:%M:%S")
        if ip_type == "fp":
            if ip in false_positives:
                false_positives.remove(ip)
                removed_status = True
                message = f"{ip} removed from false positives."
            else:
                message = f"{ip} not found in false positives."
        elif ip_type == "malicious":
            if ip in malicious_ips:
                malicious_ips.remove(ip)
                removed_status = True
                message = f"{ip} removed from malicious IPs."
                if ip in blocked_ips and blocked_ips[ip] == float('inf'):
                    if delete_iptables_rule(ip):
                        del blocked_ips[ip]
                        message += " And unblocked from IPS."
                        send_telegram_alert(
                            f"✅ *Manual Unblock*\nTime: {current_time}\nIP: `{ip}`\nReason: Removed from malicious list.")
                    else:
                        message += " Failed to unblock from IPS."
            else:
                message = f"{ip} not found in malicious IPs."
        else:
            return jsonify({"error": "Invalid type specified for removal."}), 400
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(f"{LOG_DIR}/actions.log", "a") as log_file:
            log_file.write(f"{now} ACTION: {message}.\n")
        if removed_status:
            return jsonify({"message": message})
        else:
            return jsonify({"error": message}), 404
    return jsonify({"error": "Invalid OTP"}), 401

@app.route("/api/manual_unblock", methods=["POST"])
def manual_unblock():
    data = request.json
    ip = data.get("ip")
    otp = data.get("otp")
    if not ip or not otp:
        return jsonify({"error": "IP and OTP required"}), 400
    stored = otp_store.get(ip)
    if stored and stored[1] == otp:
        del otp_store[ip]
        if ip in blocked_ips:
            if delete_iptables_rule(ip):
                del blocked_ips[ip]
                now = time.strftime("%Y-%m-%d %H:%M:%S")
                send_telegram_alert(f"✅ *Manual Unblock*\nTime: {now}\nIP: `{ip}`\nReason: Manual user request.")
                with open(f"{LOG_DIR}/actions.log", "a") as log_file:
                    log_file.write(f"{now} ACTION: IP {ip} manually unblocked.\n")
                return jsonify({"message": f"IP {ip} manually unblocked."})
            else:
                return jsonify({"error": f"Failed to unblock {ip} from iptables."}), 500
        else:
            return jsonify({"error": f"IP {ip} is not currently blocked by the system."}), 404
    return jsonify({"error": "Invalid OTP"}), 401

@app.route('/')
def index():
    html_content = '''
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DDoS Anomaly Detection & Prevention (IPS)</title>
        <style>
            body { font-family: sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }
            h1, h2 { color: #0056b3; }
            hr { border: 0; border-top: 1px solid #ccc; margin: 20px 0; }
            form { background-color: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
            label { display: block; margin-bottom: 5px; font-weight: bold; }
            input[type="text"], select {
                width: calc(100% - 22px);
                padding: 10px;
                margin-bottom: 10px;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
            button {
                background-color: #007bff;
                color: white;
                padding: 10px 15px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 16px;
            }
            button:hover { background-color: #0056b3; }
            #alertsList { list-style-type: none; padding: 0; }
            #alertsList li {
                background-color: #ffe0b2;
                border-left: 5px solid #ff9800;
                margin-bottom: 8px;
                padding: 10px;
                border-radius: 4px;
            }
            #statusMessage {
                margin-top: 10px;
                padding: 10px;
                border-radius: 4px;
                background-color: #e2f0e2;
                border: 1px solid #c8e6cb;
                color: #2e7d32;
            }
            .blocked-ip {
                background-color: #f8d7da;
                border-left: 5px solid #dc3545;
                margin-bottom: 8px;
                padding: 10px;
                border-radius: 4px;
                font-weight: bold;
            }
            .blocked-ip .unblock-btn {
                background-color: #28a745;
                margin-left: 10px;
            }
            .blocked-ip .unblock-btn:hover {
                background-color: #218838;
            }
        </style>
    </head>
    <body>
        <h1>DDoS Anomaly Detection & Prevention (IPS)</h1>
        <p>Click the link below to view the real-time dashboard:</p>
        <a href="Link to Grafana Dashboard" target="_blank">Go to Grafana Dashboard</a>
        <hr>
        <h2>Detection & IPS Control</h2>
        <button id="toggleDetectionBtn">Toggle Detection (Currently: <span id="detectionStatus">Stopped</span>)</button>
        <p id="toggleStatusMessage"></p>
        <hr>
        <h2>Currently Blocked IPs</h2>
        <ul id="blockedIpsList"></ul>
        <p id="unblockStatusMessage"></p>
        <hr>
        <h2>Request OTP for False Positive or Malicious IP</h2>
        <form id="otpForm">
            <label for="ip">IP Address:</label>
            <input type="text" id="ip" name="ip" required><br><br>
            <label for="type">Select Type:</label>
            <select id="type" name="type" required>
                <option value="fp">False Positive (will unblock if currently blocked)</option>
                <option value="malicious">Malicious (will block indefinitely)</option>
            </select><br><br>
            <button type="submit">Request OTP</button>
            <p id="otpStatusMessage"></p>
        </form>
        <hr>
        <h2>Verify OTP</h2>
        <form id="verifyOtpForm">
            <label for="verifyIp">IP Address:</label>
            <input type="text" id="verifyIp" name="verifyIp" required><br><br>
            <label for="verifyOtp">OTP:</label>
            <input type="text" id="verifyOtp" name="verifyOtp" required><br><br>
            <button type="submit">Verify OTP</button>
            <p id="verifyStatusMessage"></p>
        </form>
        <hr>
        <h2>Remove IP from False Positive or Malicious List</h2>
        <form id="removeForm">
            <label for="removeIp">IP Address:</label>
            <input type="text" id="removeIp" name="removeIp" required><br><br>
            <label for="removeType">Select Type:</label>
            <select id="removeType" name="removeType" required>
                <option value="fp">False Positive List</option>
                <option value="malicious">Malicious List (will unblock if permanently blocked)</option>
            </select><br><br>
            <label for="removeOtp">OTP:</label>
            <input type="text" id="removeOtp" name="removeOtp" required><br><br>
            <button type="submit">Remove IP</button>
            <p id="removeStatusMessage"></p>
        </form>
        <hr>
        <h2>Recent Alerts</h2>
        <ul id="alertsList"></ul>
        <script>
            function showMessage(elementId, message, isError = false) {
                const element = document.getElementById(elementId);
                element.textContent = message;
                element.style.backgroundColor = isError ? '#f8d7da' : '#d4edda';
                element.style.color = isError ? '#721c24' : '#155724';
                element.style.borderColor = isError ? '#f5c6cb' : '#c3e6cb';
                element.style.display = 'block';
                setTimeout(() => element.style.display = 'none', 5000);
            }
            async function updateDetectionStatus() {
                try {
                    const response = await fetch("/api/detection_status");
                    const data = await response.json();
                    document.getElementById("detectionStatus").textContent = data.is_running ? "Running" : "Stopped";
                    document.getElementById("toggleDetectionBtn").textContent = data.is_running ? "Stop Detection" : "Start Detection";
                    const blockedIpsList = document.getElementById("blockedIpsList");
                    blockedIpsList.innerHTML = "";
                    for (const ip in data.blocked_ips) {
                        const li = document.createElement("li");
                        const unblockTime = data.blocked_ips[ip];
                        const blockStatus = unblockTime === "Fri Jan 18 05:13:00 2922" ? "Permanently Blocked" : `Blocked until ${unblockTime}`;
                        li.className = "blocked-ip";
                        li.innerHTML = `
                            IP: <strong>${ip}</strong> - ${blockStatus}
                            <button class="unblock-btn" data-ip="${ip}">Unblock</button>
                        `;
                        blockedIpsList.appendChild(li);
                    }
                    document.querySelectorAll('.unblock-btn').forEach(button => {
                        button.onclick = async (event) => {
                            const ipToUnblock = event.target.dataset.ip;
                            const otp = prompt(`Enter OTP for ${ipToUnblock} to unblock:`);
                            if (otp) {
                                try {
                                    const response = await fetch('/api/manual_unblock', {
                                        method: 'POST',
                                        headers: { 'Content-Type': 'application/json' },
                                        body: JSON.stringify({ ip: ipToUnblock, otp: otp })
                                    });
                                    const data = await response.json();
                                    if (response.ok) {
                                        showMessage("unblockStatusMessage", data.message);
                                        updateDetectionStatus();
                                    } else {
                                        showMessage("unblockStatusMessage", data.error, true);
                                    }
                                } catch (error) {
                                    console.error("Error manual unblock:", error);
                                    showMessage("unblockStatusMessage", "Error manually unblocking.", true);
                                }
                            }
                        };
                    });
                } catch (error) {
                    console.error("Error fetching detection status:", error);
                }
            }
            document.getElementById("toggleDetectionBtn").addEventListener("click", async function() {
                try {
                    const response = await fetch("/api/toggle_detection", {
                        method: "POST"
                    });
                    const data = await response.json();
                    showMessage("toggleStatusMessage", data.status);
                    updateDetectionStatus();
                } catch (error) {
                    console.error("Error toggling detection:", error);
                    showMessage("toggleStatusMessage", "Error toggling detection.", true);
                }
            });
            document.getElementById("otpForm").addEventListener("submit", async function(event) {
                event.preventDefault();
                const ip = document.getElementById("ip").value;
                const type = document.getElementById("type").value;
                try {
                    const response = await fetch(`/api/request_otp_${type}`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ ip: ip })
                    });
                    const data = await response.json();
                    if (response.ok) {
                        showMessage("otpStatusMessage", data.message);
                    } else {
                        showMessage("otpStatusMessage", data.error, true);
                    }
                } catch (error) {
                    console.error("Error:", error);
                    showMessage("otpStatusMessage", "Error requesting OTP.", true);
                }
            });
            document.getElementById("verifyOtpForm").addEventListener("submit", async function(event) {
                event.preventDefault();
                const ip = document.getElementById("verifyIp").value;
                const otp = document.getElementById("verifyOtp").value;
                try {
                    const response = await fetch("/api/verify_otp", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ ip: ip, otp: otp })
                    });
                    const data = await response.json();
                    if (response.ok) {
                        showMessage("verifyStatusMessage", data.message);
                        document.getElementById("verifyIp").value = "";
                        document.getElementById("verifyOtp").value = "";
                        updateDetectionStatus();
                    } else {
                        showMessage("verifyStatusMessage", data.error, true);
                    }
                } catch (error) {
                    console.error("Error:", error);
                    showMessage("verifyStatusMessage", "Error verifying OTP.", true);
                }
            });
            document.getElementById("removeForm").addEventListener("submit", async function(event) {
                event.preventDefault();
                const ip = document.getElementById("removeIp").value;
                const type = document.getElementById("removeType").value;
                const otp = document.getElementById("removeOtp").value;
                try {
                    const response = await fetch("/api/remove_ip", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ ip: ip, type: type, otp: otp })
                    });
                    const data = await response.json();
                    if (response.ok) {
                        showMessage("removeStatusMessage", data.message);
                        document.getElementById("removeIp").value = "";
                        document.getElementById("removeOtp").value = "";
                        updateDetectionStatus();
                    } else {
                        showMessage("removeStatusMessage", data.error, true);
                    }
                } catch (error) {
                    console.error("Error:", error);
                    showMessage("removeStatusMessage", "Error removing IP.", true);
                }
            });
            function fetchAlerts() {
                fetch("/api/alerts")
                    .then(response => response.json())
                    .then(data => {
                        const alertsList = document.getElementById("alertsList");
                        alertsList.innerHTML = "";
                        data.alerts.forEach(alert => {
                            const li = document.createElement("li");
                            li.textContent = `${alert.timestamp} - ${alert.type}: ${alert.message} (Source: ${alert.source_ip})`;
                            alertsList.prepend(li);
                        });
                    })
                    .catch(error => {
                        console.error("Error fetching alerts:", error);
                    });
            }
            updateDetectionStatus();
            fetchAlerts();
            setInterval(fetchAlerts, 5000);
            setInterval(updateDetectionStatus, 5000);
        </script>
    </body>
    </html>
    '''
    return render_template_string(html_content)

def on_exit():
    global is_detection_running, shutdown_event, tshark_process_handle
    print("Application is shutting down. Signaling threads...")
    is_detection_running = False
    shutdown_event.set()
    if tshark_process_handle and tshark_process_handle.poll() is None:
        print("Attempting to terminate Tshark process gracefully...")
        tshark_process_handle.terminate()
        try:
            tshark_process_handle.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("Tshark process did not terminate gracefully, killing it.")
            tshark_process_handle.kill()
        tshark_process_handle = None
    print("Clearing all IPs blocked by this IPS instance...")
    ips_to_clear = list(blocked_ips.keys())
    for ip in ips_to_clear:
        if delete_iptables_rule(ip):
            print(f"Removed iptables rule for {ip} on exit.")
        else:
            print(f"Failed to remove iptables rule for {ip} on exit.")
    blocked_ips.clear()
    time.sleep(1)
    print("Shutdown signal sent and cleanup initiated.")

atexit.register(on_exit)

if __name__ == "__main__":
    def uptime_counter():
        start_time = time.time()
        while not shutdown_event.is_set():
            flask_uptime_seconds.set(time.time() - start_time)
            time.sleep(1)
        print("Uptime thread exited.")
    uptime_counter_thread = threading.Thread(target=uptime_counter)
    uptime_counter_thread.daemon = True
    uptime_counter_thread.start()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert_path = r"filepath"
    key_path = r"filepath"
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print(f"Error: SSL certificate or key file not found.")
        exit(1)
    context.load_cert_chain(cert_path, key_path)
    os.makedirs(LOG_DIR, exist_ok=True)
    print("Starting Flask app...")
    try:
        app.run(host="localhost", port=5000, ssl_context=context, debug=False, use_reloader=False)
    except Exception as e:
        print(f"Flask app failed to start: {e}")
        on_exit()
