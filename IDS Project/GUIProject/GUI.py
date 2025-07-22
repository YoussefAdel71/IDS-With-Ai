import sys
import threading
import datetime
from pathlib import Path
import pandas as pd
from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHeaderView, QHBoxLayout, QPushButton,
    QTextEdit, QTableWidget, QTableWidgetItem, QLineEdit, QFileDialog, QFrame, QLabel, QGridLayout, QComboBox, QMessageBox
)
from PySide6.QtGui import QBrush, QColor, QFont
from scapy.all import get_if_list, get_if_addr
from monitor_engine_V2 import monitor_traffic, analyze_pcap
from datetime import timedelta

# Protocol number to name mapping
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
    # Add more protocols as needed
}

class MonitorSignalHandler(QObject):
    update_signal = Signal(object, int, int, int, object)

class SpectraGuardGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SpectraGuard Traffic Monitor")
        self.monitoring = False
        self.is_paused = False
        self.offline_mode = False
        self.monitor_thread = None
        self.signal_handler = MonitorSignalHandler()
        self.signal_handler.update_signal.connect(self.update_ui)
        self.all_flows = pd.DataFrame()
        self.start_time = None
        self.flows_total = 0
        self.threats_total = 0
        self.benign_total = 0
        self.threat_types = set()
        self.setup_ui()

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Control Frame
        control_frame = QFrame()
        control_layout = QHBoxLayout(control_frame)
        control_layout.setSpacing(10)

        interface_label = QLabel("Select Interface:")
        interface_label.setStyleSheet("QLabel { font-size: 12px; }")
        control_layout.addWidget(interface_label)

        self.interface_combo = QComboBox()
        self.interface_combo.setMaximumWidth(300)
        self.interface_combo.setMinimumWidth(200)
        self.interface_combo.setStyleSheet("QComboBox { padding: 5px; border: 1px solid #ccc; border-radius: 5px; font-size: 12px; }")
        self.populate_interfaces()
        control_layout.addWidget(self.interface_combo)

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setMaximumWidth(100)
        self.refresh_button.clicked.connect(self.populate_interfaces)
        self.refresh_button.setStyleSheet("QPushButton { padding: 8px; border-radius: 5px; background-color: #FF9800; color: white; font-size: 12px; } QPushButton:hover { background-color: #F57C00; }")
        control_layout.addWidget(self.refresh_button)

        self.start_button = QPushButton("Start Monitoring")
        self.start_button.setMaximumWidth(150)
        self.start_button.clicked.connect(self.start_monitoring)
        self.start_button.setStyleSheet("QPushButton { padding: 8px; border-radius: 5px; background-color: #4CAF50; color: white; font-size: 12px; } QPushButton:hover { background-color: #45a049; }")
        control_layout.addWidget(self.start_button)

        self.offline_button = QPushButton("Offline Analysis")
        self.offline_button.setMaximumWidth(150)
        self.offline_button.clicked.connect(self.start_offline_analysis)
        self.offline_button.setStyleSheet("QPushButton { padding: 8px; border-radius: 5px; background-color: #0288D1; color: white; font-size: 12px; } QPushButton:hover { background-color: #0277BD; }")
        control_layout.addWidget(self.offline_button)

        self.pause_button = QPushButton("Pause")
        self.pause_button.setMaximumWidth(100)
        self.pause_button.clicked.connect(self.toggle_pause)
        self.pause_button.setEnabled(False)
        self.pause_button.setStyleSheet("QPushButton { padding: 8px; border-radius: 5px; background-color: #FFC107; color: black; font-size: 12px; } QPushButton:hover { background-color: #e0a800; }")
        control_layout.addWidget(self.pause_button)

        self.stop_button = QPushButton("Stop")
        self.stop_button.setMaximumWidth(100)
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("QPushButton { padding: 8px; border-radius: 5px; background-color: #f44336; color: white; font-size: 12px; } QPushButton:hover { background-color: #d32f2f; }")
        control_layout.addWidget(self.stop_button)

        self.export_button = QPushButton("Export")
        self.export_button.setMaximumWidth(100)
        self.export_button.clicked.connect(self.export_packets)
        self.export_button.setEnabled(False)
        self.export_button.setStyleSheet("QPushButton { padding: 8px; border-radius: 5px; background-color: #2196F3; color: white; font-size: 12px; } QPushButton:hover { background-color: #1976D2; }")
        control_layout.addWidget(self.export_button)

        self.clear_button = QPushButton("Clear")
        self.clear_button.setMaximumWidth(100)
        self.clear_button.clicked.connect(self.clear_table)
        self.clear_button.setEnabled(False)
        self.clear_button.setStyleSheet("QPushButton { padding: 8px; border-radius: 5px; background-color: #607D8B; color: white; font-size: 12px; } QPushButton:hover { background-color: #546E7A; }")
        control_layout.addWidget(self.clear_button)

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search (e.g., src_ip:192.168.1.100, protocol:TCP, prediction:PortScan, \"exact match\")")
        self.search_bar.setMinimumWidth(200)
        self.search_bar.textChanged.connect(self.filter_table)
        self.search_bar.setStyleSheet("QLineEdit { padding: 5px; border: 1px solid #ccc; border-radius: 5px; font-size: 12px; }")
        control_layout.addWidget(self.search_bar)

        control_layout.addStretch()
        layout.addWidget(control_frame)

        # Stats Frame
        stats_frame = QFrame()
        stats_layout = QGridLayout(stats_frame)
        self.stats_labels = {}
        stats = ["Flows Extracted", "Threats Detected", "Benign Flows", "Uptime", "Threat Types"]
        for i, stat in enumerate(stats):
            stats_layout.addWidget(QLabel(f"{stat}:"), i, 0)
            self.stats_labels[stat] = QLabel("0")
            stats_layout.addWidget(self.stats_labels[stat], i, 1)
        layout.addWidget(stats_frame)

        # Packet Table
        self.flow_table = QTableWidget()
        self.flow_table.setRowCount(0)
        self.flow_table.setColumnCount(8)
        self.flow_table.setHorizontalHeaderLabels([
            "Timestamp", "Source IP", "Source Port", "Destination IP", "Dest Port",
            "Protocol", "Prediction", "Probabilities"
        ])
        self.flow_table.setWordWrap(True)  # Enable word wrap for table cells
        header = self.flow_table.horizontalHeader()
        header.setStyleSheet("QHeaderView::section { background-color: #CFD8DC; padding: 4px; border: 1px solid #B0BEC5; color: #1A2526; font-weight: bold; }")
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        header.setSectionResizeMode(6, QHeaderView.Stretch)
        header.setSectionResizeMode(7, QHeaderView.Fixed)
        self.flow_table.setColumnWidth(7, 400)  # Wider column for probabilities
        layout.addWidget(self.flow_table)

        # Log Frame
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)

        self.setStyleSheet("""
            QTableWidget {
                border: 1px solid #B0BEC5;
                background-color: #E8ECEF;
                gridline-color: #B0BEC5;
            }
            QTableWidget::item {
                padding: 6px;
                color: #1A2526;
                border: 1px solid #B0BEC5;
            }
            QLineEdit {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 5px;
            }
            QComboBox {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 5px;
            }
            QLabel {
                font-size: 12px;
            }
        """)

    def populate_interfaces(self):
        self.interface_combo.clear()
        interfaces = get_if_list()
        self.interface_combo.addItem("Default (All Interfaces)", "ALL")
        valid_interfaces = []
        for iface in interfaces:
            try:
                ip = get_if_addr(iface)
                display_name = iface
                if ip and ip != "0.0.0.0":
                    display_name = f"{iface} (IP: {ip})"
                if "VMnet8" in iface:
                    display_name = f"{iface} (VMware NAT)"
                elif "VMnet" in iface:
                    display_name = f"{iface} (VMware)"
                elif "Wi-Fi" in iface or "Wireless" in iface or "wlan" in iface.lower():
                    display_name = f"{iface} (Wi-Fi)"
                elif "Ethernet" in iface or "eth" in iface.lower():
                    display_name = f"{iface} (Ethernet)"
                elif "Loopback" in iface or iface == "lo":
                    display_name = f"{iface} (Loopback)"
                self.interface_combo.addItem(display_name, iface)
                valid_interfaces.append(iface)
            except Exception as e:
                self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] Skipping interface {iface}: {e}")
        if not valid_interfaces:
            self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] No valid network interfaces found.")
            self.start_button.setEnabled(False)
        else:
            self.interface_combo.setCurrentIndex(0)

    def show_alert(self, row):
        """Show a popup alert for detected attacks."""
        alert_msg = (
            f"Attack Detected!\n\n"
            f"Timestamp: {row['timestamp']}\n"
            f"Source IP: {row['src_ip']}\n"
            f"Source Port: {row['src_port']}\n"
            f"Destination IP: {row['dst_ip']}\n"
            f"Destination Port: {row.get('Dest Port', '-')}\n"
            f"Protocol: {row['protocol']}\n"
            f"Prediction: {row['MultiClass_Prediction']}\n"
            f"Probabilities: {row['probabilities']}"
        )
        msg_box = QMessageBox()
        msg_box.setWindowTitle("SpectraGuard Alert")
        msg_box.setText(alert_msg)
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.exec()

    def start_monitoring(self):
        if not self.monitoring and not self.offline_mode:
            selected_interface = self.interface_combo.currentData()
            if not selected_interface:
                self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] Please select a valid network interface.")
                return
            self.monitoring = True
            self.offline_mode = False
            self.start_button.setEnabled(False)
            self.offline_button.setEnabled(False)
            self.interface_combo.setEnabled(False)
            self.refresh_button.setEnabled(False)
            self.pause_button.setEnabled(True)
            self.stop_button.setEnabled(True)
            self.log_text.clear()
            self.flow_table.setRowCount(0)
            self.all_flows = pd.DataFrame()
            self.start_time = datetime.datetime.now()
            self.flows_total = 0
            self.threats_total = 0
            self.benign_total = 0
            self.threat_types = set()
            display_text = self.interface_combo.currentText()
            self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [+] SpectraGuard Live Traffic Monitor Started on {display_text}")
            self.monitor_thread = threading.Thread(target=lambda: self.run_monitoring(selected_interface))
            self.monitor_thread.daemon = True
            self.monitor_thread.start()

    def start_offline_analysis(self):
        if not self.monitoring and not self.offline_mode:
            file_name, _ = QFileDialog.getOpenFileName(self, "Select PCAP File", str(Path.home()), "PCAP Files (*.pcap *.pcapng)")
            if not file_name:
                self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] No PCAP file selected.")
                return
            self.monitoring = True
            self.offline_mode = True
            self.start_button.setEnabled(False)
            self.offline_button.setEnabled(False)
            self.interface_combo.setEnabled(False)
            self.refresh_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.log_text.clear()
            self.flow_table.setRowCount(0)
            self.all_flows = pd.DataFrame()
            self.start_time = datetime.datetime.now()
            self.flows_total = 0
            self.threats_total = 0
            self.benign_total = 0
            self.threat_types = set()
            self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [+] SpectraGuard Offline Analysis Started on {file_name}")
            self.monitor_thread = threading.Thread(target=lambda: self.run_offline_analysis(file_name))
            self.monitor_thread.daemon = True
            self.monitor_thread.start()

    def toggle_pause(self):
        if not self.offline_mode:
            self.is_paused = not self.is_paused
            self.pause_button.setText("Resume" if self.is_paused else "Pause")
            self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [*] Monitoring {'paused' if self.is_paused else 'resumed'}")

    def stop_monitoring(self):
        if self.monitoring:
            self.monitoring = False
            self.is_paused = False
            self.offline_mode = False
            self.start_button.setEnabled(True)
            self.offline_button.setEnabled(True)
            self.interface_combo.setEnabled(True)
            self.refresh_button.setEnabled(True)
            self.pause_button.setEnabled(False)
            self.pause_button.setText("Pause")
            self.stop_button.setEnabled(False)
            self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] {'Offline analysis' if self.offline_mode else 'Monitoring'} stopped by user.")

    def run_monitoring(self, interface):
        try:
            for result in monitor_traffic(timeout=10, interface=interface, gui_instance=self):
                if not self.monitoring or self.is_paused:
                    continue
                if result is None:
                    self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] No data received from monitor_traffic")
                    continue
                df, flows_total, threats_total, benign_total, threat_types = result
                if df is None or df.empty:
                    self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] Empty or None DataFrame received, continuing...")
                    continue
                df['timestamp'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.signal_handler.update_signal.emit(
                    df, flows_total, threats_total, benign_total, threat_types
                )
        except Exception as e:
            self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] Error in monitoring: {e}")
            self.stop_monitoring()

    def run_offline_analysis(self, pcap_file):
        try:
            for result in analyze_pcap(pcap_file, gui_instance=self):
                if not self.monitoring:
                    break
                if result is None:
                    self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] No data received from analyze_pcap")
                    continue
                df, flows_total, threats_total, benign_total, threat_types = result
                if df is None or df.empty:
                    self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] Empty or None DataFrame received, continuing...")
                    continue
                df['timestamp'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.signal_handler.update_signal.emit(
                    df, flows_total, threats_total, benign_total, threat_types
                )
            self.stop_monitoring()
        except Exception as e:
            self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] Error in offline analysis: {e}")
            self.stop_monitoring()

    def update_ui(self, df, flows_total, threats_total, benign_total, threat_types):
        self.flows_total = flows_total
        self.threats_total = threats_total
        self.benign_total = benign_total
        self.threat_types = threat_types

        self.stats_labels["Flows Extracted"].setText(str(self.flows_total))
        self.stats_labels["Threats Detected"].setText(str(self.threats_total))
        self.stats_labels["Benign Flows"].setText(str(self.benign_total))
        self.stats_labels["Threat Types"].setText(", ".join(self.threat_types) if self.threat_types else "None")
        if self.start_time:
            uptime = datetime.datetime.now() - self.start_time
            self.stats_labels["Uptime"].setText(str(timedelta(seconds=int(uptime.total_seconds()))))

        summary = (f"[*] Total Flows: {flows_total}\n"
                   f"[*] Threats Detected: {threats_total}\n"
                   f"[*] Benign Flows: {benign_total}\n"
                   f"[*] Threat Types: {', '.join(threat_types) if threat_types else 'None'}\n")
        self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {summary}")

        if df is not None and not df.empty:
            # Convert protocol numbers to names
            df['protocol'] = df['protocol'].apply(
                lambda x: PROTOCOL_MAP.get(int(x), str(x)) if pd.notnull(x) else "Unknown"
            )
            # Format probabilities as a string
            df['probabilities'] = df['probabilities'].apply(
                lambda x: ", ".join([f"{k}: {v*100:.1f}%" for k, v in x.items()]) if isinstance(x, dict) else "Unknown"
            )
            df = df.rename(columns={"Destination Port": "Dest Port"})
            preview_cols = ["timestamp", "src_ip", "src_port", "dst_ip", "Dest Port", "protocol", "MultiClass_Prediction", "probabilities"]
            available_cols = [col for col in preview_cols if col in df.columns or col == "timestamp"]
            missing_cols = [col for col in preview_cols if col not in df.columns and col != "timestamp"]
            if missing_cols:
                self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] Missing expected columns in data: {missing_cols}, using available columns: {available_cols}")

            self.all_flows = pd.concat([self.all_flows, df[available_cols]], ignore_index=True) if not self.all_flows.empty else df[available_cols]
            self.export_button.setEnabled(True)
            self.clear_button.setEnabled(True)

            alerts = df[df["MultiClass_Prediction"].astype(str).str.lower() != "benign"]
            if not alerts.empty:
                alerts = alerts.reset_index(drop=True)
                self.log_text.append(f'<span style="color: red;">[{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}] [!] Detected {len(alerts)} potential threats:</span>')
                alert_cols = [col for col in ["src_ip", "src_port", "dst_ip", "Dest Port", "protocol", "MultiClass_Prediction", "probabilities"] if col in df.columns]
                self.log_text.append(str(alerts[alert_cols]))
                # Show popup for each attack only in live monitoring
                if not self.offline_mode:
                    for _, row in alerts.iterrows():
                        self.show_alert(row)
            else:
                self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [✓] No attacks detected.")

            self.filter_table()

    def filter_table(self):
        self.flow_table.setRowCount(0)
        if self.all_flows.empty:
            self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] No flows available to filter.")
            return

        search_text = self.search_bar.text().strip().lower()
        filtered_df = self.all_flows.copy()

        if not search_text:
            # No search text, show all flows
            pass
        else:
            # Valid columns for field-specific search
            valid_columns = ["timestamp", "src_ip", "src_port", "dst_ip", "Dest Port", "protocol", "MultiClass_Prediction", "probabilities"]
            conditions = []

            # Split search text into terms (space-separated)
            terms = search_text.split()
            for term in terms:
                # Check for field-specific search (e.g., src_ip:192.168.1.100)
                if ":" in term:
                    field, value = term.split(":", 1)
                    if field not in valid_columns:
                        self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] Invalid search field '{field}'. Valid fields: {', '.join(valid_columns)}")
                        continue
                    # Handle exact match (value in quotes)
                    exact_match = False
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                        exact_match = True
                    # Special handling for protocol (match name or number)
                    if field == "protocol":
                        # Try matching protocol name or number
                        protocol_numbers = {v.lower(): k for k, v in PROTOCOL_MAP.items()}
                        if value in protocol_numbers:
                            value = str(protocol_numbers[value])  # Convert protocol name to number
                        elif value.isdigit():
                            value = str(int(value))  # Ensure protocol number is string
                    # Apply filter
                    if exact_match:
                        condition = filtered_df[field].astype(str).str.lower() == value
                    else:
                        condition = filtered_df[field].astype(str).str.lower().str.contains(value, na=False)
                    conditions.append(condition)
                else:
                    # General search across all columns
                    # Handle exact match (term in quotes)
                    value = term
                    exact_match = False
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                        exact_match = True
                    # Special handling for protocol (match name or number)
                    protocol_condition = pd.Series(False, index=filtered_df.index)
                    if term in [v.lower() for v in PROTOCOL_MAP.values()]:
                        protocol_numbers = {v.lower(): k for k, v in PROTOCOL_MAP.items()}
                        protocol_condition = filtered_df["protocol"].astype(str).str.lower() == str(protocol_numbers[term])
                    elif term.isdigit() and int(term) in PROTOCOL_MAP:
                        protocol_condition = filtered_df["protocol"].astype(str).str.lower() == str(term)
                    # General condition across all columns
                    general_condition = (
                        filtered_df["timestamp"].str.lower().str.contains(value, na=False) |
                        filtered_df["src_ip"].str.lower().str.contains(value, na=False) |
                        filtered_df["src_port"].astype(str).str.lower().str.contains(value, na=False) |
                        filtered_df["dst_ip"].str.lower().str.contains(value, na=False) |
                        filtered_df.get("Dest Port", pd.Series(dtype=str)).astype(str).str.lower().str.contains(value, na=False) |
                        filtered_df["protocol"].str.lower().str.contains(value, na=False) |
                        filtered_df["MultiClass_Prediction"].str.lower().str.contains(value, na=False) |
                        filtered_df.get("probabilities", pd.Series(dtype=str)).astype(str).str.lower().str.contains(value, na=False)
                    )
                    if exact_match:
                        general_condition = (
                            filtered_df["timestamp"].str.lower() == value |
                            filtered_df["src_ip"].str.lower() == value |
                            filtered_df["src_port"].astype(str).str.lower() == value |
                            filtered_df["dst_ip"].str.lower() == value |
                            filtered_df.get("Dest Port", pd.Series(dtype=str)).astype(str).str.lower() == value |
                            filtered_df["protocol"].str.lower() == value |
                            filtered_df["MultiClass_Prediction"].str.lower() == value |
                            filtered_df.get("probabilities", pd.Series(dtype=str)).astype(str).str.lower() == value
                        )
                    conditions.append(general_condition | protocol_condition)

            # Combine conditions with AND logic
            if conditions:
                final_condition = conditions[0]
                for condition in conditions[1:]:
                    final_condition = final_condition & condition
                filtered_df = filtered_df[final_condition]

        if filtered_df.empty:
            self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] No flows match search: {search_text}")

        # Update the flow table
        for index, row in filtered_df.iterrows():
            row_position = self.flow_table.rowCount()
            self.flow_table.insertRow(row_position)
            self.flow_table.setItem(row_position, 0, QTableWidgetItem(str(row["timestamp"])))
            self.flow_table.setItem(row_position, 1, QTableWidgetItem(str(row["src_ip"])))
            self.flow_table.setItem(row_position, 2, QTableWidgetItem(str(row["src_port"])))
            self.flow_table.setItem(row_position, 3, QTableWidgetItem(str(row["dst_ip"])))
            self.flow_table.setItem(row_position, 4, QTableWidgetItem(str(row.get("Dest Port", "-"))))
            self.flow_table.setItem(row_position, 5, QTableWidgetItem(str(row["protocol"])))
            prediction_item = QTableWidgetItem(str(row["MultiClass_Prediction"]))
            self.flow_table.setItem(row_position, 6, prediction_item)
            prob_item = QTableWidgetItem(str(row.get("probabilities", "Unknown")))
            prob_item.setFont(QFont("Arial", 9, QFont.Bold))  # Slightly smaller bold font
            prob_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)  # Align left and vertically center
            # Color based on prediction
            if row["MultiClass_Prediction"].lower() == "benign":
                prob_item.setBackground(QBrush(QColor(200, 230, 201)))  # Light green
            else:
                prob_item.setBackground(QBrush(QColor(255, 205, 210)))  # Light red
            self.flow_table.setItem(row_position, 7, prob_item)
            # Adjust row height to fit wrapped text
            self.flow_table.resizeRowToContents(row_position)

    def export_packets(self):
        if self.all_flows.empty:
            self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] No packet data to export.")
            return

        file_name, _ = QFileDialog.getSaveFileName(self, "Export Packet Data", str(Path.home() / "SpectraGuard"), "CSV Files (*.csv)")
        if file_name:
            try:
                export_cols = ["timestamp", "src_ip", "src_port", "dst_ip", "Dest Port", "protocol", "MultiClass_Prediction", "probabilities"]
                export_df = self.all_flows[[col for col in export_cols if col in self.all_flows.columns or col == "timestamp"]]
                export_df.to_csv(file_name, index=False)
                self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [✓] Packet data exported to {file_name}")
            except Exception as e:
                self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [!] Failed to export packet data: {e}")

    def clear_table(self):
        self.all_flows = pd.DataFrame()
        self.flow_table.setRowCount(0)
        self.export_button.setEnabled(False)
        self.clear_button.setEnabled(False)
        self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [*] Packet table cleared.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SpectraGuardGUI()
    window.resize(1200, 800)
    window.show()
    sys.exit(app.exec())