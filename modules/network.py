import sys
import socket
import nmap
import scapy.all as scapy
import netifaces
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QTextEdit, QListWidget, 
                            QHBoxLayout, QLabel, QGroupBox, QComboBox, QLineEdit, 
                            QSplitter, QProgressBar, QMessageBox ,QCheckBox)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont, QTextCursor

def get_local_ip():
    try:
        iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    except Exception as e:
        print("Error getting local IP:", e)
        return "127.0.0.1"

class NetworkScanner(QThread):
    scan_complete = pyqtSignal(list)
    progress_update = pyqtSignal(int)
    
    def __init__(self, scan_method):
        super().__init__()
        self.scan_method = scan_method
        self.running = True

    def run(self):
        active_hosts = []
        try:
            local_ip = get_local_ip()
            ip_base = ".".join(local_ip.split(".")[:-1]) + ".0/24"
            total_hosts = 254
            scanned_hosts = 0

            if self.scan_method == "ARP":
                arp_request = scapy.ARP(pdst=ip_base)
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast / arp_request
                answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
                
                for element in answered_list:
                    if not self.running:
                        return
                    active_hosts.append(element[1].psrc)
                    scanned_hosts += 1
                    self.progress_update.emit(int((scanned_hosts / total_hosts) * 100))

            elif self.scan_method == "ICMP":
                for i in range(1, 255):
                    if not self.running:
                        return
                    ip = f"{'.'.join(local_ip.split('.')[:-1])}.{i}"
                    response = scapy.sr1(scapy.IP(dst=ip)/scapy.ICMP(), timeout=1, verbose=False)
                    if response:
                        active_hosts.append(ip)
                    scanned_hosts += 1
                    self.progress_update.emit(int((scanned_hosts / total_hosts) * 100))

            elif self.scan_method == "Nmap":
                nm = nmap.PortScanner()
                nm.scan(hosts=ip_base, arguments="-sn")
                active_hosts = nm.all_hosts()
                self.progress_update.emit(100)
                
        except Exception as e:
            print("Error scanning network:", e)

        self.scan_complete.emit(active_hosts)

    def stop(self):
        self.running = False

class PortScanner(QThread):
    scan_complete = pyqtSignal(dict)
    progress_update = pyqtSignal(int)
    
    def __init__(self, target_ip, scan_type, port_range, service_scan=False):
        super().__init__()
        self.target_ip = target_ip
        self.scan_type = scan_type
        self.port_range = port_range
        self.service_scan = service_scan
        self.running = True

    def run(self):
        open_ports = {}
        nm = nmap.PortScanner()
        try:
            arguments = f"{self.scan_type} -p {self.port_range}"
            if self.service_scan:
                arguments += " -sV --version-intensity 5"
                
            nm.scan(hosts=self.target_ip, arguments=arguments)

            if self.target_ip in nm.all_hosts():
                for proto in nm[self.target_ip].all_protocols():
                    ports = nm[self.target_ip][proto].keys()
                    total_ports = len(ports)
                    scanned_ports = 0
                    
                    for port in ports:
                        if not self.running:
                            return
                            
                        state = nm[self.target_ip][proto][port]["state"]
                        if state == "open":
                            service = nm[self.target_ip][proto][port].get("name", "Unknown")
                            product = nm[self.target_ip][proto][port].get("product", "")
                            version = nm[self.target_ip][proto][port].get("version", "")
                            extrainfo = nm[self.target_ip][proto][port].get("extrainfo", "")
                            
                            service_info = service
                            if product:
                                service_info += f" ({product}"
                                if version:
                                    service_info += f" {version}"
                                if extrainfo:
                                    service_info += f", {extrainfo}"
                                service_info += ")"
                            
                            open_ports[port] = service_info
                            
                        scanned_ports += 1
                        self.progress_update.emit(int((scanned_ports / total_ports) * 100))

                # OS Detection
                os_info = "Unknown OS"
                if "osmatch" in nm[self.target_ip] and len(nm[self.target_ip]["osmatch"]) > 0:
                    os_info = nm[self.target_ip]["osmatch"][0].get("name", "Unknown OS")
                    os_accuracy = nm[self.target_ip]["osmatch"][0].get("accuracy", "")
                    if os_accuracy:
                        os_info += f" (Accuracy: {os_accuracy}%)"

                open_ports["OS"] = os_info

        except Exception as e:
            print("Error running Nmap:", e)

        self.scan_complete.emit(open_ports)

    def stop(self):
        self.running = False

class NetworkAnalyzer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Advanced Network Analyzer")
        self.setGeometry(100, 100, 900, 700)
        
        # Set main font
        font = QFont()
        font.setPointSize(10)
        self.setFont(font)
        
        # Main layout with splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Network scanning
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # Network scan group
        net_scan_group = QGroupBox("Network Scan")
        net_scan_layout = QVBoxLayout()
        
        # Scan method selection
        method_group = QHBoxLayout()
        method_group.addWidget(QLabel("Scan Method:"))
        self.scan_method_dropdown = QComboBox()
        self.scan_method_dropdown.addItems(["ARP", "ICMP", "Nmap"])
        method_group.addWidget(self.scan_method_dropdown)
        net_scan_layout.addLayout(method_group)
        
        # Scan buttons
        self.scan_button = QPushButton("Start Network Scan")
        self.scan_button.setStyleSheet("background-color: white ; color: black;")
        self.scan_button.clicked.connect(self.scan_network)
        net_scan_layout.addWidget(self.scan_button)
        
        self.stop_net_scan_button = QPushButton("Stop Network Scan")
        self.stop_net_scan_button.setStyleSheet("background-color: white; color: black;")
        self.stop_net_scan_button.clicked.connect(self.stop_network_scan)
        net_scan_layout.addWidget(self.stop_net_scan_button)
        
        # Progress bar
        self.net_progress = QProgressBar()
        self.net_progress.setRange(0, 100)
        net_scan_layout.addWidget(self.net_progress)
        
        # Hosts list
        self.hosts_list = QListWidget()
        self.hosts_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        net_scan_layout.addWidget(QLabel("Discovered Hosts:"))
        net_scan_layout.addWidget(self.hosts_list)
        
        net_scan_group.setLayout(net_scan_layout)
        left_layout.addWidget(net_scan_group)
        
        # Add stretch to push everything up
        left_layout.addStretch()
        
        # Right panel - Port scanning and results
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # Port scan group
        port_scan_group = QGroupBox("Port Scan Options")
        port_scan_layout = QVBoxLayout()
        
        # Scan type selection
        type_group = QHBoxLayout()
        type_group.addWidget(QLabel("Scan Type:"))
        self.scan_type_dropdown = QComboBox()
        self.scan_type_dropdown.addItems(["SYN (Stealth)", "TCP (Connect)", "UDP", "Aggressive", "Version Detection"])
        type_group.addWidget(self.scan_type_dropdown)
        port_scan_layout.addLayout(type_group)
        
        # Protocol selection
        protocol_group = QHBoxLayout()
        protocol_group.addWidget(QLabel("Port Selection:"))
        self.protocol_dropdown = QComboBox()
        self.protocol_dropdown.addItems(["All Ports", "Common Ports", "Common IOT", "Web (80,443)", 
                                        "SSH (22)", "FTP (21)", "MQTT (1883)", "CoAP (5683)", 
                                        "Modbus (502)", "Custom Range"])
        protocol_group.addWidget(self.protocol_dropdown)
        port_scan_layout.addLayout(protocol_group)
        
        # Custom port range
        self.port_range_input = QLineEdit()
        self.port_range_input.setPlaceholderText("Enter port range (e.g., 1-1000 or 22,80,443)")
        self.port_range_input.setEnabled(False)
        port_scan_layout.addWidget(self.port_range_input)
        self.protocol_dropdown.currentTextChanged.connect(self.toggle_port_input)
        
        # Service scan checkbox
        self.service_scan_check = QCheckBox("Enable Service Version Detection")
        self.service_scan_check.setChecked(True)
        port_scan_layout.addWidget(self.service_scan_check)
        
        # Scan buttons
        self.scan_button_host = QPushButton("Start Port Scan")
        self.scan_button_host.setStyleSheet("background-color: white; color: black;")
        self.scan_button_host.clicked.connect(self.scan_ports)
        port_scan_layout.addWidget(self.scan_button_host)
        
        self.stop_port_scan_button = QPushButton("Stop Port Scan")
        self.stop_port_scan_button.setStyleSheet("background-color: white; color: black;")
        self.stop_port_scan_button.clicked.connect(self.stop_port_scan)
        port_scan_layout.addWidget(self.stop_port_scan_button)
        
        # Progress bar
        self.port_progress = QProgressBar()
        self.port_progress.setRange(0, 100)
        port_scan_layout.addWidget(self.port_progress)
        
        port_scan_group.setLayout(port_scan_layout)
        right_layout.addWidget(port_scan_group)
        
        # Results group
        result_group = QGroupBox("Scan Results")
        result_layout = QVBoxLayout()
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setFont(QFont("Courier New", 10))
        result_layout.addWidget(self.result_text)
        
        # Clear button
        clear_button = QPushButton("Clear Results")
        clear_button.clicked.connect(self.clear_results)
        result_layout.addWidget(clear_button)
        
        result_group.setLayout(result_layout)
        right_layout.addWidget(result_group)
        
        # Add panels to splitter
        main_splitter.addWidget(left_panel)
        main_splitter.addWidget(right_panel)
        main_splitter.setStretchFactor(0, 1)
        main_splitter.setStretchFactor(1, 2)
        
        # Main layout
        main_layout = QHBoxLayout(self)
        main_layout.addWidget(main_splitter)
        
        # Initialize scanner references
        self.network_scanner = None
        self.port_scanner = None
        
    def toggle_port_input(self, text):
        self.port_range_input.setEnabled(text == "Custom Range")
        
    def scan_network(self):
        scan_method = self.scan_method_dropdown.currentText()
        
        # Stop previous scan if running
        if self.network_scanner and self.network_scanner.isRunning():
            self.network_scanner.stop()
            self.network_scanner.wait()
        
        self.result_text.append(f"[*] Starting {scan_method} network scan...\n")
        self.hosts_list.clear()
        
        self.network_scanner = NetworkScanner(scan_method)
        self.network_scanner.scan_complete.connect(self.display_hosts)
        self.network_scanner.progress_update.connect(self.net_progress.setValue)
        self.network_scanner.start()
        
    def stop_network_scan(self):
        if self.network_scanner and self.network_scanner.isRunning():
            self.network_scanner.stop()
            self.result_text.append("\n[!] Network scan stopped by user\n")
            
    def display_hosts(self, hosts):
        self.hosts_list.clear()
        for host in sorted(hosts, key=lambda ip: [int(part) for part in ip.split('.')]):
            self.hosts_list.addItem(host)
        self.result_text.append(f"[+] Found {len(hosts)} active hosts\n")
        
    def scan_ports(self):
        selected_items = self.hosts_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Host Selected", "Please select a host from the list first.")
            return
            
        target_ip = selected_items[0].text()
        scan_type = self.scan_type_dropdown.currentText()
        service_scan = self.service_scan_check.isChecked()
        
        # Map scan types to Nmap arguments
        scan_args = {
            "SYN (Stealth)": "-sS",
            "TCP (Connect)": "-sT",
            "UDP": "-sU",
            "Aggressive": "-A",
            "Version Detection": "-sV"
        }
        nmap_arg = scan_args.get(scan_type, "-sS")
        
        # Get port range based on selection
        port_mapping = {
            "All Ports": "1-65535",
            "Common Ports": "21-23,25,53,80,110,139,143,443,445,3389",
            "Common IOT": "1883,5683,502,8883,4840",
            "Web (80,443)": "80,443",
            "SSH (22)": "22",
            "FTP (21)": "21",
            "MQTT (1883)": "1883",
            "CoAP (5683)": "5683",
            "Modbus (502)": "502"
        }
        
        protocol = self.protocol_dropdown.currentText()
        if protocol == "Custom Range":
            port_range = self.port_range_input.text().strip()
            if not port_range:
                QMessageBox.warning(self, "No Port Range", "Please enter a valid port range.")
                return
        else:
            port_range = port_mapping.get(protocol, "1-1000")
        
        # Stop previous scan if running
        if self.port_scanner and self.port_scanner.isRunning():
            self.port_scanner.stop()
            self.port_scanner.wait()
        
        self.result_text.append(f"[*] Scanning {target_ip}...")
        self.result_text.append(f"    Scan Type: {scan_type}")
        self.result_text.append(f"    Ports: {port_range}")
        self.result_text.append(f"    Service Detection: {'Enabled' if service_scan else 'Disabled'}\n")
        
        self.port_scanner = PortScanner(target_ip, nmap_arg, port_range, service_scan)
        self.port_scanner.scan_complete.connect(self.display_ports)
        self.port_scanner.progress_update.connect(self.port_progress.setValue)
        self.port_scanner.start()
        
    def stop_port_scan(self):
        if self.port_scanner and self.port_scanner.isRunning():
            self.port_scanner.stop()
            self.result_text.append("\n[!] Port scan stopped by user\n")
            
    def display_ports(self, ports):
        if not ports:
            self.result_text.append("[-] No open ports found or scan was stopped\n")
            return
            
        self.result_text.append("[+] Scan Results:")
        
        # Display OS information if available
        os_info = ports.pop("OS", None)
        if os_info:
            self.result_text.append(f"    Operating System: {os_info}")
            
        if ports:
            self.result_text.append("\n    Open Ports and Services:")
            for port, service in sorted(ports.items(), key=lambda x: int(x[0])):
                self.result_text.append(f"    {port}/tcp: {service}")
        else:
            self.result_text.append("    No open ports found")
            
        self.result_text.append("\n[+] Scan completed\n")
        
        # Auto-scroll to bottom
        cursor = self.result_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.result_text.setTextCursor(cursor)
        
    def clear_results(self):
        self.result_text.clear()
        
    def closeEvent(self, event):
        # Stop any running scans when closing the application
        if self.network_scanner and self.network_scanner.isRunning():
            self.network_scanner.stop()
            self.network_scanner.wait()
            
        if self.port_scanner and self.port_scanner.isRunning():
            self.port_scanner.stop()
            self.port_scanner.wait()
            
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern style
    
    analyzer = NetworkAnalyzer()
    analyzer.show()
    sys.exit(app.exec())