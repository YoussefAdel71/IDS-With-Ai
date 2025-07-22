from base64 import b64encode
from scapy.all import *
from scapy.layers.inet import TCP, UDP, ICMP, IP
import pandas as pd
import joblib
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import IncrementalPCA
import warnings
import time
from collections import defaultdict
from datetime import datetime
from threading import Lock

# Suppress warnings
warnings.filterwarnings("ignore")

# Initialize lock for thread-safe flow access
flows_lock = Lock()

# Load pre-trained model, scaler, and pca
try:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(BASE_DIR,'Models' ,'random_forest_model_rf2.pkl')
    scaler_path = os.path.join(BASE_DIR, 'Models','scaler.pkl')
    pca_path = os.path.join(BASE_DIR, 'Models','pca.pkl')
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    pca = joblib.load(pca_path)

    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Model, scaler, and PCA loaded successfully")
except Exception as e:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] Loading model/scaler/pca: {e}")
    raise

# Define original columns (70 features)
original_columns = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Fwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

# Flow tracking dictionary
flows = defaultdict(
    lambda: {
        "fwd_packets": 0,
        "bwd_packets": 0,
        "fwd_bytes": 0,
        "bwd_bytes": 0,
        "timestamps": [],
        "lengths": [],
        "start_time": None,
        "flags": defaultdict(int),
        "packets": [],
        "dst_ip": None,
        "dst_port": None,
        "init_win_bytes_forward": 0,
        "init_win_bytes_backward": 0,
        "act_data_pkt_fwd": 0,
        "unique_ports": set(),
    }
)

# Global variables to track statistics
flows_total = 0
threats_total = 0
benign_total = 0
threat_types = set()

def calculate_features(flow_data, offline_mode=False):
    if not flow_data["timestamps"] or flow_data["start_time"] is None:
        return None

    # For offline mode, allow single-packet flows; for live mode, require at least 2 packets
    if not offline_mode and len(flow_data["timestamps"]) < 2:
        return None

    # Convert timestamps to milliseconds since start_time
    timestamps_ms = [
        (t - flow_data["start_time"]).total_seconds() * 1000
        for t in flow_data["timestamps"]
    ]
    if not timestamps_ms or max(timestamps_ms) <= 0:
        return None

    # Handle flow duration for single-packet flows in offline mode
    flow_duration = max(timestamps_ms) - min(timestamps_ms) if len(timestamps_ms) > 1 else 0

    total_fwd_packets = flow_data["fwd_packets"]
    total_bwd_packets = flow_data["bwd_packets"]
    total_fwd_bytes = flow_data["fwd_bytes"]
    total_bwd_bytes = flow_data["bwd_bytes"]

    fwd_lengths = [
        l for l in flow_data["lengths"] if l > 0 and isinstance(l, (int, float))
    ]
    if fwd_lengths:
        fwd_packet_length_max = max(fwd_lengths)
        fwd_packet_length_min = min(fwd_lengths)
        fwd_packet_length_mean = np.mean(fwd_lengths)
        fwd_packet_length_std = np.std(fwd_lengths) if len(fwd_lengths) > 1 else 0
    else:
        fwd_packet_length_max = fwd_packet_length_min = fwd_packet_length_mean = (
            fwd_packet_length_std
        ) = 0

    bwd_lengths = [
        l for l in flow_data["lengths"] if l > 0 and isinstance(l, (int, float))
    ]
    if bwd_lengths:
        bwd_packet_length_max = max(bwd_lengths)
        bwd_packet_length_min = min(bwd_lengths)
        bwd_packet_length_mean = np.mean(bwd_lengths)
        bwd_packet_length_std = np.std(bwd_lengths) if len(bwd_lengths) > 1 else 0
    else:
        bwd_packet_length_max = bwd_packet_length_min = bwd_packet_length_mean = (
            bwd_packet_length_std
        ) = 0

    flow_bytes_per_second = (
        (total_fwd_bytes + total_bwd_bytes) / (flow_duration / 1000)
        if flow_duration > 0
        else 0
    )
    flow_packets_per_second = (
        (total_fwd_packets + total_bwd_packets) / (flow_duration / 1000)
        if flow_duration > 0
        else (total_fwd_packets + total_bwd_packets)  # For single-packet flows
    )

    iat = (
        np.diff(timestamps_ms)
        if timestamps_ms and len(timestamps_ms) > 1
        else np.array([])
    )
    flow_iat_mean = np.mean(iat) if len(iat) > 0 else 0
    flow_iat_std = np.std(iat) if len(iat) > 1 else 0
    flow_iat_max = np.max(iat) if len(iat) > 0 else 0
    flow_iat_min = np.min(iat) if len(iat) > 0 else 0

    fwd_iat = iat[: total_fwd_packets - 1] if total_fwd_packets > 1 else np.array([])
    fwd_iat_total = np.sum(fwd_iat) if len(fwd_iat) > 0 else 0
    fwd_iat_mean = np.mean(fwd_iat) if len(fwd_iat) > 0 else 0
    fwd_iat_std = np.std(fwd_iat) if len(fwd_iat) > 1 else 0
    fwd_iat_max = np.max(fwd_iat) if len(fwd_iat) > 0 else 0
    fwd_iat_min = np.min(fwd_iat) if len(fwd_iat) > 0 else 0

    bwd_iat = (
        iat[total_fwd_packets - 1 :] if total_fwd_packets < len(iat) else np.array([])
    )
    bwd_iat_total = np.sum(bwd_iat) if len(bwd_iat) > 0 else 0
    bwd_iat_mean = np.mean(bwd_iat) if len(bwd_iat) > 0 else 0
    bwd_iat_std = np.std(bwd_iat) if len(bwd_iat) > 1 else 0
    bwd_iat_max = np.max(bwd_iat) if len(bwd_iat) > 0 else 0
    bwd_iat_min = np.min(bwd_iat) if len(bwd_iat) > 0 else 0

    fwd_psh_flags = flow_data["flags"]["PSH"]
    fwd_urg_flags = flow_data["flags"]["U"]
    fwd_header_length = sum(
        20 + (pkt.getlayer(TCP).dataofs * 4 if pkt.haslayer(TCP) else 8)
        for pkt in flow_data["packets"]
        if IP in pkt and pkt[IP].dst == flow_data["dst_ip"]
    )
    bwd_header_length = sum(
        20 + (pkt.getlayer(TCP).dataofs * 4 if pkt.haslayer(TCP) else 8)
        for pkt in flow_data["packets"]
        if IP in pkt and pkt[IP].src == flow_data["dst_ip"]
    )

    fwd_packets_per_second = (
        total_fwd_packets / (flow_duration / 1000) if flow_duration > 0 else total_fwd_packets
    )
    bwd_packets_per_second = (
        total_bwd_packets / (flow_duration / 1000) if flow_duration > 0 else total_bwd_packets
    )

    min_packet_length = min(flow_data["lengths"]) if flow_data["lengths"] else 0
    max_packet_length = max(flow_data["lengths"]) if flow_data["lengths"] else 0
    packet_length_mean = np.mean(flow_data["lengths"]) if flow_data["lengths"] else 0
    packet_length_std = (
        np.std(flow_data["lengths"]) if len(flow_data["lengths"]) > 1 else 0
    )
    packet_length_variance = (
        np.var(flow_data["lengths"]) if len(flow_data["lengths"]) > 1 else 0
    )

    fin_flag_count = flow_data["flags"]["F"]
    syn_flag_count = flow_data["flags"]["S"]
    rst_flag_count = flow_data["flags"]["R"]
    psh_flag_count = flow_data["flags"]["PSH"]
    ack_flag_count = flow_data["flags"]["A"]
    urg_flag_count = flow_data["flags"]["U"]
    cwe_flag_count = flow_data["flags"]["CWE"]
    ece_flag_count = flow_data["flags"]["ECE"]

    down_up_ratio = (
        total_bwd_packets / total_fwd_packets if total_fwd_packets > 0 else 0
    )
    average_packet_size = (
        (total_fwd_bytes + total_bwd_bytes) / (total_fwd_packets + total_bwd_packets)
        if (total_fwd_packets + total_bwd_packets) > 0
        else 0
    )
    avg_fwd_segment_size = (
        total_fwd_bytes / total_fwd_packets if total_fwd_packets > 0 else 0
    )
    avg_bwd_segment_size = (
        total_bwd_bytes / total_bwd_packets if total_bwd_packets > 0 else 0
    )

    subflow_fwd_packets = total_fwd_packets
    subflow_fwd_bytes = total_fwd_bytes
    subflow_bwd_packets = total_bwd_packets
    subflow_bwd_bytes = total_bwd_bytes

    init_win_bytes_forward = flow_data["init_win_bytes_forward"]
    init_win_bytes_backward = flow_data["init_win_bytes_backward"]
    act_data_pkt_fwd = flow_data["act_data_pkt_fwd"]
    min_seg_size_forward = min(fwd_lengths) if fwd_lengths else 0

    # Active and Idle metrics
    active_periods = [t for t in iat if t < 1000]
    idle_periods = [t for t in iat if t >= 1000]
    active_mean = np.mean(active_periods) if active_periods else 0
    active_std = np.std(active_periods) if len(active_periods) > 1 else 0
    active_max = np.max(active_periods) if active_periods else 0
    active_min = np.min(active_periods) if active_periods else 0
    idle_mean = np.mean(idle_periods) if idle_periods else 0
    idle_std = np.std(idle_periods) if len(idle_periods) > 1 else 0
    idle_max = np.max(idle_periods) if idle_periods else 0
    idle_min = np.min(idle_periods) if idle_periods else 0

    feature_dict = {
        "Destination Port": flow_data["dst_port"],
        "Unique Destination Ports": len(flow_data["unique_ports"]),
        "Flow Duration": flow_duration,
        "Total Fwd Packets": total_fwd_packets,
        "Total Backward Packets": total_bwd_packets,
        "Total Length of Fwd Packets": total_fwd_bytes,
        "Total Length of Bwd Packets": total_bwd_bytes,
        "Fwd Packet Length Max": fwd_packet_length_max,
        "Fwd Packet Length Min": fwd_packet_length_min,
        "Fwd Packet Length Mean": fwd_packet_length_mean,
        "Fwd Packet Length Std": fwd_packet_length_std,
        "Bwd Packet Length Max": bwd_packet_length_max,
        "Bwd Packet Length Min": bwd_packet_length_min,
        "Bwd Packet Length Mean": bwd_packet_length_mean,
        "Bwd Packet Length Std": bwd_packet_length_std,
        "Flow Bytes/s": flow_bytes_per_second,
        "Flow Packets/s": flow_packets_per_second,
        "Flow IAT Mean": flow_iat_mean,
        "Flow IAT Std": flow_iat_std,
        "Flow IAT Max": flow_iat_max,
        "Flow IAT Min": flow_iat_min,
        "Fwd IAT Total": fwd_iat_total,
        "Fwd IAT Mean": fwd_iat_mean,
        "Fwd IAT Std": fwd_iat_std,
        "Fwd IAT Max": fwd_iat_max,
        "Fwd IAT Min": fwd_iat_min,
        "Bwd IAT Total": bwd_iat_total,
        "Bwd IAT Mean": bwd_iat_mean,
        "Bwd IAT Std": bwd_iat_std,
        "Bwd IAT Max": bwd_iat_max,
        "Bwd IAT Min": bwd_iat_min,
        "Fwd PSH Flags": fwd_psh_flags,
        "Fwd URG Flags": fwd_urg_flags,
        "Fwd Header Length": fwd_header_length,
        "Bwd Header Length": bwd_header_length,
        "Fwd Packets/s": fwd_packets_per_second,
        "Bwd Packets/s": bwd_packets_per_second,
        "Min Packet Length": min_packet_length,
        "Max Packet Length": max_packet_length,
        "Packet Length Mean": packet_length_mean,
        "Packet Length Std": packet_length_std,
        "Packet Length Variance": packet_length_variance,
        "FIN Flag Count": fin_flag_count,
        "SYN Flag Count": syn_flag_count,
        "RST Flag Count": rst_flag_count,
        "PSH Flag Count": psh_flag_count,
        "ACK Flag Count": ack_flag_count,
        "URG Flag Count": urg_flag_count,
        "CWE Flag Count": cwe_flag_count,
        "ECE Flag Count": ece_flag_count,
        "Down/Up Ratio": down_up_ratio,
        "Average Packet Size": average_packet_size,
        "Avg Fwd Segment Size": avg_fwd_segment_size,
        "Avg Bwd Segment Size": avg_bwd_segment_size,
        "Fwd Header Length.1": fwd_header_length,
        "Subflow Fwd Packets": subflow_fwd_packets,
        "Subflow Fwd Bytes": subflow_fwd_bytes,
        "Subflow Bwd Packets": subflow_bwd_packets,
        "Subflow Bwd Bytes": subflow_bwd_bytes,
        "Init_Win_bytes_forward": init_win_bytes_forward,
        "Init_Win_bytes_backward": init_win_bytes_backward,
        "act_data_pkt_fwd": act_data_pkt_fwd,
        "min_seg_size_forward": min_seg_size_forward,
        "Active Mean": active_mean,
        "Active Std": active_std,
        "Active Max": active_max,
        "Active Min": active_min,
        "Idle Mean": idle_mean,
        "Idle Std": idle_std,
        "Idle Max": idle_max,
        "Idle Min": idle_min,
    }
    return feature_dict

def process_packet(pkt, flow_results, gui_instance=None, offline_mode=False):
    global flows_total, threats_total, benign_total, threat_types
    try:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = pkt[IP].proto
            src_port = pkt[IP].sport if (pkt.haslayer(UDP) or pkt.haslayer(TCP)) else 0
            dst_port = pkt[IP].dport if (pkt.haslayer(UDP) or pkt.haslayer(TCP)) else 0
            # Modified flow_key for offline mode to handle port scans better
            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol) if offline_mode else dst_ip

            with flows_lock:
                flow_data = flows[flow_key]
                flow_data["dst_ip"] = dst_ip
                flow_data["dst_port"] = dst_port
                flow_data["unique_ports"].add(dst_port)

                current_time = pkt.time if offline_mode and hasattr(pkt, 'time') else datetime.now()
                if isinstance(current_time, (int, float)):
                    current_time = datetime.fromtimestamp(current_time)
                elif not isinstance(current_time, datetime):
                    current_time = datetime.now()

                if flow_data["start_time"] is None:
                    flow_data["start_time"] = current_time

                flow_data["timestamps"].append(current_time)
                flow_data["lengths"].append(len(pkt))

                if pkt.haslayer(TCP):
                    flags = pkt[TCP].flags
                    flow_data["flags"]["F"] += 1 if "F" in flags else 0
                    flow_data["flags"]["S"] += 1 if "S" in flags else 0
                    flow_data["flags"]["R"] += 1 if "R" in flags else 0
                    flow_data["flags"]["PSH"] += 1 if "P" in flags else 0
                    flow_data["flags"]["A"] += 1 if "A" in flags else 0
                    flow_data["flags"]["U"] += 1 if "U" in flags else 0
                    flow_data["flags"]["CWE"] += 1 if "C" in flags else 0
                    flow_data["flags"]["ECE"] += 1 if "E" in flags else 0
                    if not flow_data["init_win_bytes_forward"] and pkt[IP].dst == dst_ip:
                        flow_data["init_win_bytes_forward"] = pkt[TCP].window
                    if not flow_data["init_win_bytes_backward"] and pkt[IP].src == dst_ip:
                        flow_data["init_win_bytes_backward"] = pkt[TCP].window
                    if pkt.haslayer(Raw) and pkt[IP].dst == dst_ip:
                        flow_data["act_data_pkt_fwd"] += 1

                if pkt[IP].dst == dst_ip:
                    flow_data["fwd_packets"] += 1
                    flow_data["fwd_bytes"] += len(pkt.payload) if pkt.haslayer(Raw) else 0
                else:
                    flow_data["bwd_packets"] += 1
                    flow_data["bwd_bytes"] += len(pkt.payload) if pkt.haslayer(Raw) else 0
                flow_data["packets"].append(pkt)

                # Process flow for offline mode or after 10 seconds in live mode
                if offline_mode or (current_time - flow_data["start_time"]).total_seconds() >= 10:
                    features = calculate_features(flow_data, offline_mode=offline_mode)
                    if features:
                        df = pd.DataFrame([features])
                        df = df.reindex(columns=original_columns, fill_value=0)
                        X = df[original_columns].values
                        try:
                            X_scaled = scaler.transform(X)
                            X_pca = pca.transform(X_scaled)
                            prediction = model.predict(X_pca)[0]
                            proba = model.predict_proba(X_pca)[0]
                            if prediction == "DoS" and features.get("Unique Destination Ports", 0) > 100:
                                prediction = "PortScan"

                            # Update statistics
                            flows_total += 1
                            if prediction.lower() == "benign":
                                benign_total += 1
                            else:
                                threats_total += 1
                                threat_types.add(prediction)

                            # Prepare probabilities dictionary
                            proba_dict = dict(zip(model.classes_, proba))

                            # Prepare DataFrame for GUI
                            flow_info = {
                                "timestamp": current_time.strftime('%Y-%m-%d %H:%M:%S'),
                                "src_ip": src_ip,
                                "dst_ip": flow_data["dst_ip"],
                                "src_port": src_port,
                                "Dest Port": flow_data["dst_port"],
                                "protocol": protocol,
                                "MultiClass_Prediction": prediction,
                                "probabilities": proba_dict
                            }
                            flow_results.append(pd.DataFrame([flow_info]))
                            if gui_instance:
                                gui_instance.log_text.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Flow {flow_key} processed:")
                                gui_instance.log_text.append(f"    Src IP:   {src_ip}")
                                gui_instance.log_text.append(f"    Dest IP:  {dst_ip}")
                                gui_instance.log_text.append(f"    Protocol: {protocol}")
                                gui_instance.log_text.append(f"    Port:     {dst_port}")
                                gui_instance.log_text.append(f"    Unique Destination Ports: {features.get('Unique Destination Ports', 0)}")
                                gui_instance.log_text.append(f"    Label:    {prediction}")
                                gui_instance.log_text.append(f"    Probabilities: {proba_dict}")
                                gui_instance.log_text.append(f"    SYN Flag Count: {features['SYN Flag Count']}")
                                gui_instance.log_text.append(f"    Flow Packets/s: {features['Flow Packets/s']}")
                                gui_instance.log_text.append(f"    Fwd Packets/s: {features['Fwd Packets/s']}")
                                gui_instance.log_text.append(f"    Down/Up Ratio: {features['Down/Up Ratio']}")
                                gui_instance.log_text.append(f"    Time:     {current_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
                                gui_instance.log_text.append("-" * 30)
                            else:
                                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Flow {flow_key} processed:")
                                print(f"    Src IP:   {src_ip}")
                                print(f"    Dest IP:  {dst_ip}")
                                print(f"    Protocol: {protocol}")
                                print(f"    Port:     {dst_port}")
                                print(f"    Unique Destination Ports: {features.get('Unique Destination Ports', 0)}")
                                print(f"    Label:    {prediction}")
                                print(f"    Probabilities: {proba_dict}")
                                print(f"    SYN Flag Count: {features['SYN Flag Count']}")
                                print(f"    Flow Packets/s: {features['Flow Packets/s']}")
                                print(f"    Fwd Packets/s: {features['Fwd Packets/s']}")
                                print(f"    Down/Up Ratio: {features['Down/Up Ratio']}")
                                print(f"    Time:     {current_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
                                print("-" * 30)

                        except Exception as e:
                            error_msg = f"Prediction error for flow {flow_key}: {e}"
                            if gui_instance:
                                gui_instance.log_text.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] {error_msg}")
                            else:
                                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] {error_msg}")

                    # Reset flow data
                    flows[flow_key] = {
                        "fwd_packets": 0,
                        "bwd_packets": 0,
                        "fwd_bytes": 0,
                        "bwd_bytes": 0,
                        "timestamps": [],
                        "lengths": [],
                        "start_time": current_time,
                        "flags": defaultdict(int),
                        "packets": [],
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "init_win_bytes_forward": 0,
                        "init_win_bytes_backward": 0,
                        "act_data_pkt_fwd": 0,
                        "unique_ports": set(),
                    }

    except Exception as e:
        error_msg = f"Error processing packet: {e}"
        if gui_instance:
            gui_instance.log_text.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] {error_msg}")
        else:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] {error_msg}")

def monitor_traffic(timeout=10, interface="ALL", gui_instance=None):
    global flows_total, threats_total, benign_total, threat_types
    # Reset global counters
    flows_total = 0
    threats_total = 0
    benign_total = 0
    threat_types = set()
    flow_results = []
    empty_df = pd.DataFrame(columns=["timestamp", "src_ip", "dst_ip", "src_port", "Dest Port", "protocol", "MultiClass_Prediction", "probabilities"])
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting monitor_traffic on interface {interface}")

    def packet_callback(pkt):
        if gui_instance and (not gui_instance.monitoring or gui_instance.is_paused):
            return
        process_packet(pkt, flow_results, gui_instance, offline_mode=False)

    try:
        if gui_instance:
            gui_instance.log_text.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [+] Starting packet capture on {interface}")
        else:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Sniffer Started - Analyzing live traffic on {interface}")

        while gui_instance.monitoring if gui_instance else True:
            start_time = time.time()
            try:
                sniff(iface=interface if interface != "ALL" else None, prn=packet_callback, store=0, timeout=timeout)
            except Exception as e:
                error_msg = f"Sniffing error on interface {interface}: {e}"
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] {error_msg}")
                if gui_instance:
                    gui_instance.log_text.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] {error_msg}")
            if flow_results:
                df = pd.concat(flow_results, ignore_index=True)
                yield (df, flows_total, threats_total, benign_total, threat_types)
                flow_results = []
            else:
                yield (empty_df, flows_total, threats_total, benign_total, threat_types)
            if gui_instance and not gui_instance.monitoring:
                break
            if not gui_instance and time.time() - start_time >= timeout:
                break

        if gui_instance:
            gui_instance.log_text.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [+] Packet capture stopped on {interface}")
        else:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Sniffer Stopped")

    except Exception as e:
        error_msg = f"Error in monitor_traffic: {e}"
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] {error_msg}")
        if gui_instance:
            gui_instance.log_text.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] {error_msg}")
        yield (empty_df, flows_total, threats_total, benign_total, threat_types)

def analyze_pcap(pcap_file, gui_instance=None):
    global flows_total, threats_total, benign_total, threat_types
    # Reset global counters
    flows_total = 0
    threats_total = 0
    benign_total = 0
    threat_types = set()
    flow_results = []
    empty_df = pd.DataFrame(columns=["timestamp", "src_ip", "dst_ip", "src_port", "Dest Port", "protocol", "MultiClass_Prediction", "probabilities"])
    
    if gui_instance:
        gui_instance.log_text.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [+] Analyzing PCAP file: {pcap_file}")
    else:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting analyze_pcap on file {pcap_file}")

    try:
        # Read all packets at once
        packets = rdpcap(pcap_file)
        if not packets:
            error_msg = "No packets found in PCAP file"
            if gui_instance:
                gui_instance.log_text.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] {error_msg}")
            else:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] {error_msg}")
            yield (empty_df, flows_total, threats_total, benign_total, threat_types)
            return

        packet_count = 0
        for pkt in packets:
            if gui_instance and not gui_instance.monitoring:
                if gui_instance:
                    gui_instance.log_text.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] Monitoring stopped by user.")
                break
            process_packet(pkt, flow_results, gui_instance, offline_mode=True)
            packet_count += 1
            if packet_count % 100 == 0:  # Log progress every 100 packets
                log_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] Processed {packet_count} packets"
                if gui_instance:
                    gui_instance.log_text.append(log_msg)
                else:
                    print(log_msg)
            
            # Yield flows incrementally for real-time GUI updates
            if flow_results:
                df = pd.concat(flow_results, ignore_index=True)
                log_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] Yielding {len(flow_results)} flow results"
                if gui_instance:
                    gui_instance.log_text.append(log_msg)
                else:
                    print(log_msg)
                yield (df, flows_total, threats_total, benign_total, threat_types)
                flow_results = []

        # Process any remaining flows
        with flows_lock:
            if not flows:
                log_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] No flows collected from PCAP"
                if gui_instance:
                    gui_instance.log_text.append(log_msg)
                else:
                    print(log_msg)
            for flow_key, flow_data in list(flows.items()):
                if flow_data["timestamps"]:
                    log_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] Processing flow {flow_key} with {len(flow_data['timestamps'])} packets"
                    if gui_instance:
                        gui_instance.log_text.append(log_msg)
                    else:
                        print(log_msg)
                    
                    features = calculate_features(flow_data, offline_mode=True)
                    if features:
                        log_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] Features calculated for flow {flow_key}"
                        if gui_instance:
                            gui_instance.log_text.append(log_msg)
                        else:
                            print(log_msg)
                        
                        df = pd.DataFrame([features])
                        df = df.reindex(columns=original_columns, fill_value=0)
                        X = df[original_columns].values
                        try:
                            X_scaled = scaler.transform(X)
                            X_pca = pca.transform(X_scaled)
                            prediction = model.predict(X_pca)[0]
                            proba = model.predict_proba(X_pca)[0]
                            if prediction == "DoS" and features.get("Unique Destination Ports", 0) > 100:
                                prediction = "PortScan"

                            # Update statistics
                            flows_total += 1
                            if prediction.lower() == "benign":
                                benign_total += 1
                            else:
                                threats_total += 1
                                threat_types.add(prediction)

                            # Prepare probabilities dictionary
                            proba_dict = dict(zip(model.classes_, proba))

                            # Prepare DataFrame for GUI
                            src_ip = flow_key[0] if isinstance(flow_key, tuple) else pkt[IP].src if IP in pkt else "Unknown"
                            flow_info = {
                                "timestamp": flow_data["timestamps"][-1].strftime('%Y-%m-%d %H:%M:%S'),
                                "src_ip": src_ip,
                                "dst_ip": flow_data["dst_ip"],
                                "src_port": flow_key[2] if isinstance(flow_key, tuple) else (pkt[IP].sport if (pkt.haslayer(UDP) or pkt.haslayer(TCP)) else 0),
                                "Dest Port": flow_data["dst_port"],
                                "protocol": flow_key[4] if isinstance(flow_key, tuple) else (pkt[IP].proto if IP in pkt else 0),
                                "MultiClass_Prediction": prediction,
                                "probabilities": proba_dict
                            }
                            flow_results.append(pd.DataFrame([flow_info]))
                            if gui_instance:
                                gui_instance.log_text.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Flow {flow_key} processed:")
                                gui_instance.log_text.append(f"    Src IP:   {flow_info['src_ip']}")
                                gui_instance.log_text.append(f"    Dest IP:  {flow_data['dst_ip']}")
                                gui_instance.log_text.append(f"    Protocol: {flow_info['protocol']}")
                                gui_instance.log_text.append(f"    Port:     {flow_data['dst_port']}")
                                gui_instance.log_text.append(f"    Unique Destination Ports: {features.get('Unique Destination Ports', 0)}")
                                gui_instance.log_text.append(f"    Label:    {prediction}")
                                gui_instance.log_text.append(f"    Probabilities: {proba_dict}")
                                gui_instance.log_text.append(f"    SYN Flag Count: {features['SYN Flag Count']}")
                                gui_instance.log_text.append(f"    Flow Packets/s: {features['Flow Packets/s']}")
                                gui_instance.log_text.append(f"    Fwd Packets/s: {features['Fwd Packets/s']}")
                                gui_instance.log_text.append(f"    Down/Up Ratio: {features['Down/Up Ratio']}")
                                gui_instance.log_text.append(f"    Time:     {flow_info['timestamp']}")
                                gui_instance.log_text.append("-" * 30)
                            else:
                                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Flow {flow_key} processed:")
                                print(f"    Src IP:   {flow_info['src_ip']}")
                                print(f"    Dest IP:  {flow_data['dst_ip']}")
                                print(f"    Protocol: {flow_info['protocol']}")
                                print(f"    Port:     {flow_data['dst_port']}")
                                print(f"    Unique Destination Ports: {features.get('Unique Destination Ports', 0)}")
                                print(f"    Label:    {prediction}")
                                print(f"    Probabilities: {proba_dict}")
                                print(f"    SYN Flag Count: {features['SYN Flag Count']}")
                                print(f"    Flow Packets/s: {features['Flow Packets/s']}")
                                print(f"    Fwd Packets/s: {features['Fwd Packets/s']}")
                                print(f"    Down/Up Ratio: {features['Down/Up Ratio']}")
                                print(f"    Time:     {flow_info['timestamp']}")
                                print("-" * 30)

                        except Exception as e:
                            error_msg = f"Prediction error for flow {flow_key}: {e}"
                            if gui_instance:
                                gui_instance.log_text.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] {error_msg}")
                            else:
                                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] {error_msg}")

                    # Clear flow data
                    flows[flow_key] = {
                        "fwd_packets": 0,
                        "bwd_packets": 0,
                        "fwd_bytes": 0,
                        "bwd_bytes": 0,
                        "timestamps": [],
                        "lengths": [],
                        "start_time": None,
                        "flags": defaultdict(int),
                        "packets": [],
                        "dst_ip": None,
                        "dst_port": None,
                        "init_win_bytes_forward": 0,
                        "init_win_bytes_backward": 0,
                        "act_data_pkt_fwd": 0,
                        "unique_ports": set(),
                    }

                # Yield flows incrementally for remaining flows
                if flow_results:
                    df = pd.concat(flow_results, ignore_index=True)
                    log_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] Yielding {len(flow_results)} flow results"
                    if gui_instance:
                        gui_instance.log_text.append(log_msg)
                    else:
                        print(log_msg)
                    yield (df, flows_total, threats_total, benign_total, threat_types)
                    flow_results = []

        if gui_instance:
            gui_instance.log_text.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [+] PCAP analysis completed")
        else:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] PCAP Analysis Completed")

    except Exception as e:
        error_msg = f"Error in analyze_pcap: {e}"
        if gui_instance:
            gui_instance.log_text.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] {error_msg}")
        else:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] {error_msg}")
        yield (empty_df, flows_total, threats_total, benign_total, threat_types)