import sys
import socket
import nmap
import scapy.all as scapy
import netifaces
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QTextEdit, QListWidget, QHBoxLayout, QLabel, QGroupBox, QComboBox)
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
    
    def run(self):
        active_hosts = []
        try:
            local_ip = get_local_ip()
            ip_base = ".".join(local_ip.split(".")[:-1]) + ".1/24"
            
            arp_request = scapy.ARP(pdst=ip_base)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            
            for element in answered_list:
                active_hosts.append(element[1].psrc)
        except Exception as e:
            print("Error scanning network:", e)
        self.scan_complete.emit(active_hosts)

class PortScanner(QThread):
    scan_complete = pyqtSignal(dict)
    
    def __init__(self, target_ip, scan_type):
        super().__init__()
        self.target_ip = target_ip
        self.scan_type = scan_type
    
    def run(self):
        open_ports = {}
        nm = nmap.PortScanner()
        try:
            nm.scan(self.target_ip, arguments=self.scan_type)
            for port in nm[self.target_ip]["tcp"]:
                service = nm[self.target_ip]["tcp"][port].get("name", "Unknown")
                open_ports[port] = service
        except Exception as e:
            print("Error running Nmap:", e)
        self.scan_complete.emit(open_ports)

class NetworkAnalyzer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Network Analyzer")
        self.setGeometry(100, 100, 600, 400)
        
        main_layout = QHBoxLayout()
        
        # Left Section - Host Selection
        left_panel = QVBoxLayout()
        self.scan_button = QPushButton("Scan Network")
        self.scan_button.clicked.connect(self.scan_network)
        left_panel.addWidget(self.scan_button)
        
        self.hosts_list = QListWidget()
        left_panel.addWidget(self.hosts_list)
        
        main_layout.addLayout(left_panel)
        
        # Right Section - Host & Port Scan
        right_panel = QVBoxLayout()
        
        host_scan_group = QGroupBox("Host Scan")
        host_scan_layout = QVBoxLayout()
        self.scan_type_dropdown = QComboBox()
        self.scan_type_dropdown.addItems(["-sS -p 1-1000", "-sT -p 1-1000", "-sU -p 1-1000", "-A -p 1-1000"])
        host_scan_layout.addWidget(self.scan_type_dropdown)
        
        self.host_scan_button = QPushButton("Scan Selected Host")
        self.host_scan_button.clicked.connect(self.scan_ports)
        host_scan_layout.addWidget(self.host_scan_button)
        host_scan_group.setLayout(host_scan_layout)
        right_panel.addWidget(host_scan_group)
        
        port_scan_group = QGroupBox("Port Scan")
        port_scan_layout = QVBoxLayout()
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        port_scan_layout.addWidget(self.result_text)
        port_scan_group.setLayout(port_scan_layout)
        right_panel.addWidget(port_scan_group)
        
        main_layout.addLayout(right_panel)
        
        self.setLayout(main_layout)
        
    def scan_network(self):
        self.result_text.append("Scanning network...")
        self.scanner = NetworkScanner()
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
            self.result_text.append(f"Scanning ports for {target_ip} with scan type: {scan_type}...")
            self.port_scanner = PortScanner(target_ip, scan_type)
            self.port_scanner.scan_complete.connect(self.display_ports)
            self.port_scanner.start()
        else:
            self.result_text.append("No host selected.")
        
    def display_ports(self, ports):
        self.result_text.append("Open Ports:")
        for port, service in ports.items():
            self.result_text.append(f"Port {port}: {service}")
