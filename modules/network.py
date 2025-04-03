import sys
import socket
import nmap
import scapy.all as scapy
import netifaces
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QTextEdit, QListWidget, QHBoxLayout, QLabel, QGroupBox, QComboBox, QLineEdit)
from PyQt6.QtCore import QThread, pyqtSignal

def get_local_ip():
    try:
        iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    except Exception as e:
        print("Error getting local IP:", e)
        return "127.0.0.1"

class NetworkScanner(QThread):
    scan_complete = pyqtSignal(list)

    def __init__(self, scan_method):
        super().__init__()
        self.scan_method = scan_method
        self.running = True  # Add a flag to stop scanning

    def run(self):
        active_hosts = []
        try:
            local_ip = get_local_ip()
            ip_base = ".".join(local_ip.split(".")[:-1]) + ".0/24"

            if self.scan_method == "ARP":
                arp_request = scapy.ARP(pdst=ip_base)
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast / arp_request
                answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
                
                for element in answered_list:
                    if not self.running:  # Check stop flag
                        return
                    active_hosts.append(element[1].psrc)

            elif self.scan_method == "ICMP":
                for i in range(1, 255):
                    if not self.running:  # Check stop flag
                        return
                    ip = f"{'.'.join(local_ip.split('.')[:-1])}.{i}"
                    response = scapy.sr1(scapy.IP(dst=ip)/scapy.ICMP(), timeout=1, verbose=False)
                    if response:
                        active_hosts.append(ip)

            elif self.scan_method == "Nmap":
                nm = nmap.PortScanner()
                nm.scan(hosts=ip_base, arguments="-sn")
                active_hosts = nm.all_hosts()
                
        except Exception as e:
            print("Error scanning network:", e)

        self.scan_complete.emit(active_hosts)

    def stop(self):
        self.running = False  # Set flag to stop scanning


class PortScanner(QThread):
    scan_complete = pyqtSignal(dict)
    
    def __init__(self, target_ip, scan_type, port_range):
        super().__init__()
        self.target_ip = target_ip
        self.scan_type = scan_type
        self.port_range = port_range
        self.running = True  # Allows stopping scan

    def run(self):
        open_ports = {}
        nm = nmap.PortScanner()
        try:
            # Run scan with proper Nmap arguments
            nm.scan(hosts=self.target_ip, arguments=f"{self.scan_type} -p {self.port_range}")

            # Check if the target IP is in the scan result
            if self.target_ip in nm.all_hosts():
                for proto in nm[self.target_ip].all_protocols():
                    for port in nm[self.target_ip][proto].keys():
                        if not self.running:
                            return
                        service = nm[self.target_ip][proto][port].get("name", "Unknown Service")
                        open_ports[port] = f"{service}"

                # OS Detection
                os_info = "Unknown OS"
                if "osmatch" in nm[self.target_ip] and len(nm[self.target_ip]["osmatch"]) > 0:
                    os_info = nm[self.target_ip]["osmatch"][0].get("name", "Unknown OS")

                open_ports["OS"] = os_info  # Store OS info in the dictionary
            else:
                print(f"No results for {self.target_ip}")

        except Exception as e:
            print("Error running Nmap:", e)

        self.scan_complete.emit(open_ports)

    def stop(self):
        self.running = False

class NetworkAnalyzer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Network Analyzer")
        self.setGeometry(100, 100, 700, 500)
        
        main_layout = QHBoxLayout()
        
        left_panel = QVBoxLayout()
        
        self.scan_method_dropdown = QComboBox()
        self.scan_method_dropdown.addItems(["ARP", "ICMP", "Nmap"])
        left_panel.addWidget(QLabel("Scan Method:"))
        left_panel.addWidget(self.scan_method_dropdown)
        
        self.scan_button = QPushButton("Scan Network")
        self.scan_button.clicked.connect(self.scan_network)
        left_panel.addWidget(self.scan_button)

        self.scan_button_host = QPushButton("Scan Selected Host")
        self.stop_host_scan = QPushButton("Stop Scan")
        self.stop_host_scan.clicked.connect(self.stop_scan)
        left_panel.addWidget(self.stop_host_scan)
        
        self.hosts_list = QListWidget()
        left_panel.addWidget(self.hosts_list)
        
        main_layout.addLayout(left_panel,1)
        
        right_panel = QVBoxLayout()
        
        scan_group = QGroupBox("Scan Options")
        scan_layout = QVBoxLayout()
        self.scan_type_dropdown = QComboBox()
        self.scan_type_dropdown.addItems(["SYN" , "TCP" , "UDP" , "Aggressive" , "version"]) #"-sS", "-sT", "-sU", "-A", "-sV"
        scan_layout.addWidget(QLabel("Scan Type:"))
        scan_layout.addWidget(self.scan_type_dropdown)
        
        self.protocol_dropdown = QComboBox()
        self.protocol_dropdown.addItems(["All Ports","Common IOT", "MQTT (1883)", "CoAP (5683)", "Modbus (502)", "Custom Range"])
        scan_layout.addWidget(QLabel("Protocol Scan:"))
        scan_layout.addWidget(self.protocol_dropdown)
        
        self.port_range_input = QLineEdit()
        self.port_range_input.setPlaceholderText("Enter port range (e.g., 1-1000)")
        self.port_range_input.setEnabled(False)
        scan_layout.addWidget(self.port_range_input)
        
        self.protocol_dropdown.currentTextChanged.connect(self.toggle_port_input)
        
        self.scan_button_host.clicked.connect(self.scan_ports)
        scan_layout.addWidget(self.scan_button_host)
        
        scan_group.setLayout(scan_layout)
        right_panel.addWidget(scan_group)
        
        result_group = QGroupBox("Scan Results")
        result_layout = QVBoxLayout()
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        result_layout.addWidget(self.result_text)
        result_group.setLayout(result_layout)
        right_panel.addWidget(result_group)
        
        main_layout.addLayout(right_panel,2)
        self.setLayout(main_layout)
        
    def toggle_port_input(self, text):
        self.port_range_input.setEnabled(text == "Custom Range")
    
    def scan_network(self):
        scan_method = self.scan_method_dropdown.currentText()
        
        # Stop the previous scan if it's running
        if hasattr(self, 'scanner') and self.scanner.isRunning():
            self.scanner.stop()
            self.scanner.wait()  # Ensure the previous scan thread has stopped
        
        self.result_text.append(f"Scanning network using {scan_method}...")
        
        # Start a new scan
        self.scanner = NetworkScanner(scan_method)
        self.scanner.scan_complete.connect(self.display_hosts)
        self.scanner.start()

        
    def display_hosts(self, hosts):
        self.hosts_list.clear()
        for host in hosts:
            self.hosts_list.addItem(host)
        self.result_text.append(f"Found {len(hosts)} active hosts.")
        
    def scan_ports(self):
        selected_items = self.hosts_list.selectedItems()
        if selected_items:
            target_ip = selected_items[0].text()
            scan_type = self.scan_type_dropdown.currentText()

            scanner_type = "-sS"
            if scan_type == "TCP":
                scanner_type = "-sT"
            elif scan_type == "UDP":
                scanner_type = "-sU"
            elif scan_type == "Aggressive":
                scanner_type = "-A"
            elif scan_type == "version":
                scanner_type = "-sV"

            protocol = self.protocol_dropdown.currentText()
            
            port_range = "1-1000"
            if protocol == "MQTT (1883)":
                port_range = "1883"
            elif protocol == "CoAP (5683)":
                port_range = "5683"
            elif protocol == "Modbus (502)":
                port_range = "502"
            elif protocol == "Common IOT":
                port_range = "1883,5683,502"
            elif protocol == "Custom Range":
                port_range = self.port_range_input.text()
            
            self.result_text.append(f"Scanning {target_ip} for {protocol} with scan type: {scan_type} and port range: {port_range}...")
            self.port_scanner = PortScanner(target_ip, scan_type, port_range)
            self.port_scanner.scan_complete.connect(self.display_ports)
            self.port_scanner.start()
        else:
            self.result_text.append("No host selected.")

    def stop_scan(self):
        if hasattr(self, 'scanner') and self.scanner.isRunning():
            self.scanner.stop()
            self.result_text.append("Network scan stopped.")

        
    def display_ports(self, ports):
        self.result_text.append("Open Ports:")
        for port, info in ports.items():
            self.result_text.append(f"Port {port}: {info}")
