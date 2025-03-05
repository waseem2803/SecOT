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
    
    def run(self):
        active_hosts = []
        try:
            local_ip = get_local_ip()
            ip_base = ".".join(local_ip.split(".")[:-1]) + ".1/24"
            
            if self.scan_method == "ARP":
                arp_request = scapy.ARP(pdst=ip_base)
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast / arp_request
                answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
                
                for element in answered_list:
                    active_hosts.append(element[1].psrc)
            else:  # Ping Scan
                for i in range(1, 255):
                    ip = f"{'.'.join(local_ip.split('.')[:-1])}.{i}"
                    print(f"Pinging {ip}...")  # Display each IP being scanned
                    response = scapy.sr1(scapy.IP(dst=ip)/scapy.ICMP(), timeout=1, verbose=False)
                    if response:
                        active_hosts.append(ip)
        except Exception as e:
            print("Error scanning network:", e)
        self.scan_complete.emit(active_hosts)

class PortScanner(QThread):
    scan_complete = pyqtSignal(dict)
    
    def __init__(self, target_ip, scan_type, port_range):
        super().__init__()
        self.target_ip = target_ip
        self.scan_type = scan_type
        self.port_range = port_range
    
    def run(self):
        open_ports = {}
        nm = nmap.PortScanner()
        try:
            nm.scan(self.target_ip, arguments=f"{self.scan_type} -p {self.port_range}")
            for port in nm[self.target_ip]["tcp"]:
                service = nm[self.target_ip]["tcp"][port].get("name", "Unknown")
                os_info = nm[self.target_ip].get("osmatch", [{}])[0].get("name", "Unknown OS")
                open_ports[port] = f"{service} (OS: {os_info})"
        except Exception as e:
            print("Error running Nmap:", e)
        self.scan_complete.emit(open_ports)

class NetworkAnalyzer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Network Analyzer")
        self.setGeometry(100, 100, 700, 500)
        
        main_layout = QHBoxLayout()
        
        # Left Section - Host Selection
        left_panel = QVBoxLayout()
        
        self.scan_method_dropdown = QComboBox()
        self.scan_method_dropdown.addItems(["ARP", "Ping"])
        left_panel.addWidget(QLabel("Scan Method:"))
        left_panel.addWidget(self.scan_method_dropdown)
        
        self.scan_button = QPushButton("Scan Network")
        self.scan_button.clicked.connect(self.scan_network)
        left_panel.addWidget(self.scan_button)
        
        self.hosts_list = QListWidget()
        left_panel.addWidget(self.hosts_list)
        
        main_layout.addLayout(left_panel,1)
        
        # Right Section - Scan Options
        right_panel = QVBoxLayout()
        
        scan_group = QGroupBox("Scan Options")
        scan_layout = QVBoxLayout()
        self.scan_type_dropdown = QComboBox()
        self.scan_type_dropdown.addItems(["-sS", "-sT", "-sU", "-A", "-sV"])  # TCP SYN, TCP Connect, UDP, OS detection, Version detection
        scan_layout.addWidget(QLabel("Scan Type:"))
        scan_layout.addWidget(self.scan_type_dropdown)
        
        self.protocol_dropdown = QComboBox()
        self.protocol_dropdown.addItems(["All Ports", "MQTT (1883)", "CoAP (5683)", "Modbus (502)", "Custom Range"])
        scan_layout.addWidget(QLabel("Protocol Scan:"))
        scan_layout.addWidget(self.protocol_dropdown)
        
        self.port_range_input = QLineEdit()
        self.port_range_input.setPlaceholderText("Enter port range (e.g., 1-1000)")
        self.port_range_input.setEnabled(False)
        scan_layout.addWidget(self.port_range_input)
        
        self.protocol_dropdown.currentTextChanged.connect(self.toggle_port_input)
        
        self.scan_button_host = QPushButton("Scan Selected Host")
        self.scan_button_host.clicked.connect(self.scan_ports)
        scan_layout.addWidget(self.scan_button_host)
        
        scan_group.setLayout(scan_layout)
        right_panel.addWidget(scan_group)
        
        # Results
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
        self.result_text.append(f"Scanning network using {scan_method}...")
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
            protocol = self.protocol_dropdown.currentText()
            
            port_range = "1-1000"
            if protocol == "MQTT (1883)":
                port_range = "1883"
            elif protocol == "CoAP (5683)":
                port_range = "5683"
            elif protocol == "Modbus (502)":
                port_range = "502"
            elif protocol == "Custom Range":
                port_range = self.port_range_input.text()
            
            self.result_text.append(f"Scanning {target_ip} for {protocol} with scan type: {scan_type} and port range: {port_range}...")
            self.port_scanner = PortScanner(target_ip, scan_type, port_range)
            self.port_scanner.scan_complete.connect(self.display_ports)
            self.port_scanner.start()
        else:
            self.result_text.append("No host selected.")
        
    def display_ports(self, ports):
        self.result_text.append("Open Ports:")
        for port, info in ports.items():
            self.result_text.append(f"Port {port}: {info}")