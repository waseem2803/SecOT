import serial
import serial.tools.list_ports
import scapy.all as scapy
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox, 
    QLineEdit, QTextEdit, QTabWidget, QGroupBox, QCheckBox, QSpinBox,
    QFormLayout, QSplitter, QTreeWidget, QTreeWidgetItem, QHeaderView
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont, QColor
import netifaces
from datetime import datetime


#this module is for Debugging the data that's coming out of a iot device , it is essential beacuse from this data we can learn many things about the device , just usual recon,
#it has 2 functionality one is serial monitor and the other is network sniffer (serial monitor prints the debug info same as terminal and network sniffer captures the packets coming in and out of the device)



class IoTDebugMonitor(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("IoT Device Debug & Network Monitor")
        self.setGeometry(100, 100, 1200, 800)
        
        # Main layout
        self.main_layout = QVBoxLayout(self)
        
        # Create tab widget for different functionalities
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        
        # Serial Monitor Tab
        self.setup_serial_tab()
        
        # Network Sniffer Tab
        self.setup_sniffer_tab()
        
        # Status bar
        self.status_label = QLabel("Ready")
        self.main_layout.addWidget(self.status_label)
        
        # Initialize variables
        self.serial_port = None
        self.read_thread = None
        self.sniffer_thread = None
        
    def setup_serial_tab(self):
        """Setup the serial monitor tab"""
        self.serial_tab = QWidget()
        self.tabs.addTab(self.serial_tab, "Serial Monitor")
        
        layout = QVBoxLayout(self.serial_tab)
        
        # Configuration group
        config_group = QGroupBox("Serial Configuration")
        config_layout = QHBoxLayout()
        
        # COM Port selection
        self.com_combo = QComboBox()
        self.refresh_ports()
        config_layout.addWidget(QLabel("COM Port:"))
        config_layout.addWidget(self.com_combo)
        
        # Baud rate selection
        self.baud_combo = QComboBox()
        self.baud_combo.addItems(["9600", "19200", "38400", "57600", "115200", "230400", "460800", "921600"])
        config_layout.addWidget(QLabel("Baud Rate:"))
        config_layout.addWidget(self.baud_combo)
        
        # Buttons
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.connect_serial)
        self.connect_button.setStyleSheet("background-color: #4CAF50; color: white;")
        config_layout.addWidget(self.connect_button)
        
        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.clicked.connect(self.disconnect_serial)
        self.disconnect_button.setEnabled(False)
        self.disconnect_button.setStyleSheet("background-color: #f44336; color: white;")
        config_layout.addWidget(self.disconnect_button)
        
        self.refresh_button = QPushButton("Refresh Ports")
        self.refresh_button.clicked.connect(self.refresh_ports)
        config_layout.addWidget(self.refresh_button)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Splitter for text areas
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Received data area
        self.rx_text = QTextEdit()
        self.rx_text.setReadOnly(True)
        self.rx_text.setFont(QFont("Consolas", 10))
        self.rx_text.setPlaceholderText("Received data will appear here...")
        splitter.addWidget(self.rx_text)
        
        # Send area
        send_group = QGroupBox("Send Data")
        send_layout = QVBoxLayout()
        
        self.tx_text = QLineEdit()
        self.tx_text.setPlaceholderText("Enter data to send...")
        send_layout.addWidget(self.tx_text)
        
        button_layout = QHBoxLayout()
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_data)
        self.send_button.setStyleSheet("background-color: #2196F3; color: white;")
        button_layout.addWidget(self.send_button)
        
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(lambda: self.rx_text.clear())
        button_layout.addWidget(self.clear_button)
        
        send_layout.addLayout(button_layout)
        send_group.setLayout(send_layout)
        splitter.addWidget(send_group)
        
        layout.addWidget(splitter)
        
    def setup_sniffer_tab(self):
        """Setup the network sniffer tab"""
        self.sniffer_tab = QWidget()
        self.tabs.addTab(self.sniffer_tab, "Network Sniffer")
        
        layout = QVBoxLayout(self.sniffer_tab)
        
        # Configuration group
        config_group = QGroupBox("Sniffer Configuration")
        config_layout = QFormLayout()
        
        # Network interface selection
        self.iface_combo = QComboBox()
        self.refresh_interfaces()
        config_layout.addRow("Network Interface:", self.iface_combo)
        
        # Filter options
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("e.g., tcp port 80 or ip host 192.168.1.1")
        config_layout.addRow("BPF Filter:", self.filter_edit)
        
        # Protocol filters
        filter_checkboxes = QHBoxLayout()
        self.tcp_check = QCheckBox("TCP")
        self.tcp_check.setChecked(True)
        filter_checkboxes.addWidget(self.tcp_check)
        
        self.udp_check = QCheckBox("UDP")
        self.udp_check.setChecked(True)
        filter_checkboxes.addWidget(self.udp_check)
        
        self.icmp_check = QCheckBox("ICMP")
        self.icmp_check.setChecked(True)
        filter_checkboxes.addWidget(self.icmp_check)
        
        self.arp_check = QCheckBox("ARP")
        self.arp_check.setChecked(True)
        filter_checkboxes.addWidget(self.arp_check)
        
        config_layout.addRow("Protocol Filters:", filter_checkboxes)
        
        # Packet count
        self.packet_count = QSpinBox()
        self.packet_count.setRange(0, 9999)
        self.packet_count.setValue(100)
        self.packet_count.setSpecialValueText("Unlimited")
        config_layout.addRow("Packet Count:", self.packet_count)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Sniffing")
        self.start_button.clicked.connect(self.start_sniffing)
        self.start_button.setStyleSheet("background-color: #4CAF50; color: white;")
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("Stop Sniffing")
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("background-color: #f44336; color: white;")
        button_layout.addWidget(self.stop_button)
        
        self.clear_sniffer_button = QPushButton("Clear")
        self.clear_sniffer_button.clicked.connect(self.clear_sniffer)
        button_layout.addWidget(self.clear_sniffer_button)
        
        config_layout.addRow(button_layout)
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Packet list and details
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Packet list
        self.packet_list = QTreeWidget()
        self.packet_list.setHeaderLabels(["Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.packet_list.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.packet_list.setSortingEnabled(True)
        self.packet_list.itemSelectionChanged.connect(self.show_packet_details)
        splitter.addWidget(self.packet_list)
        
        # Packet details
        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)
        self.packet_details.setFont(QFont("Consolas", 9))
        splitter.addWidget(self.packet_details)
        
        layout.addWidget(splitter)
        
    def refresh_ports(self):
        """Refresh available serial ports"""
        self.com_combo.clear()
        ports = serial.tools.list_ports.comports()
        for port in ports:
            self.com_combo.addItem(f"{port.device} - {port.description}")
            
    def refresh_interfaces(self):
        """Refresh available network interfaces"""
        self.iface_combo.clear()
        for iface in netifaces.interfaces():
            if iface != 'lo':  # Skip loopback
                self.iface_combo.addItem(iface)
                
    def connect_serial(self):
        """Connect to serial port"""
        com_port = self.com_combo.currentText().split(' - ')[0]
        baud_rate = int(self.baud_combo.currentText())
        
        try:
            self.serial_port = serial.Serial(com_port, baud_rate, timeout=1)
            self.rx_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] Connected to {com_port} @ {baud_rate} baud")
            
            self.read_thread = SerialReadThread(self.serial_port)
            self.read_thread.data_received.connect(self.display_data)
            self.read_thread.start()
            
            self.connect_button.setEnabled(False)
            self.disconnect_button.setEnabled(True)
            self.status_label.setText(f"Connected to {com_port}")
            
        except serial.SerialException as e:
            self.rx_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] Error: {str(e)}")
            
    def disconnect_serial(self):
        """Disconnect from serial port"""
        if self.serial_port and self.serial_port.is_open:
            self.read_thread.stop()
            self.serial_port.close()
            self.rx_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] Disconnected")
            
            self.connect_button.setEnabled(True)
            self.disconnect_button.setEnabled(False)
            self.status_label.setText("Disconnected")
            
    def send_data(self):
        """Send data through serial port"""
        if self.serial_port and self.serial_port.is_open:
            data = self.tx_text.text()
            try:
                self.serial_port.write(data.encode())
                self.rx_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] TX: {data}")
                self.tx_text.clear()
            except Exception as e:
                self.rx_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] Error: {str(e)}")
        else:
            self.rx_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] Error: Not connected to any port")
            
    def display_data(self, data):
        """Display received serial data"""
        self.rx_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] RX: {data}")
        
    def start_sniffing(self):
        """Start network sniffing"""
        iface = self.iface_combo.currentText()
        if not iface:
            self.status_label.setText("Error: No network interface selected")
            return
            
        # Create filter from UI options
        filters = []
        if not self.tcp_check.isChecked():
            filters.append("not tcp")
        if not self.udp_check.isChecked():
            filters.append("not udp")
        if not self.icmp_check.isChecked():
            filters.append("not icmp")
        if not self.arp_check.isChecked():
            filters.append("not arp")
            
        user_filter = self.filter_edit.text().strip()
        if user_filter:
            filters.append(user_filter)
            
        bpf_filter = " and ".join(filters) if filters else None
        
        # Start sniffer thread
        self.sniffer_thread = PacketSnifferThread(
            iface=iface,
            filter=bpf_filter,
            count=self.packet_count.value() if self.packet_count.value() > 0 else None
        )
        self.sniffer_thread.packet_received.connect(self.add_packet)
        self.sniffer_thread.finished.connect(self.sniffing_finished)
        self.sniffer_thread.start()
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status_label.setText(f"Sniffing on {iface}...")
        
    def stop_sniffing(self):
        """Stop network sniffing"""
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_thread.stop()
            
    def sniffing_finished(self):
        """Called when sniffing stops"""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText("Sniffing stopped")
        
    def clear_sniffer(self):
        """Clear sniffer results"""
        self.packet_list.clear()
        self.packet_details.clear()
        
    def add_packet(self, packet):
        """Add a packet to the packet list"""
        try:
            time_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            
            # Get basic packet info
            if packet.haslayer(scapy.IP):
                src = packet[scapy.IP].src
                dst = packet[scapy.IP].dst
                proto = packet[scapy.IP].proto
                length = len(packet)
                
                # Protocol name
                if packet.haslayer(scapy.TCP):
                    proto_name = "TCP"
                    info = f"{packet[scapy.TCP].sport} -> {packet[scapy.TCP].dport}"
                elif packet.haslayer(scapy.UDP):
                    proto_name = "UDP"
                    info = f"{packet[scapy.UDP].sport} -> {packet[scapy.UDP].dport}"
                elif packet.haslayer(scapy.ICMP):
                    proto_name = "ICMP"
                    info = f"type={packet[scapy.ICMP].type}"
                else:
                    proto_name = "IP"
                    info = f"proto={proto}"
                    
            elif packet.haslayer(scapy.ARP):
                src = packet[scapy.ARP].psrc
                dst = packet[scapy.ARP].pdst
                proto_name = "ARP"
                length = len(packet)
                info = f"{'request' if packet[scapy.ARP].op == 1 else 'reply'}"
                
            else:
                src = "Unknown"
                dst = "Unknown"
                proto_name = "Other"
                length = len(packet)
                info = packet.summary()
                
            # Create tree item
            item = QTreeWidgetItem(self.packet_list)
            item.setText(0, time_str)
            item.setText(1, src)
            item.setText(2, dst)
            item.setText(3, proto_name)
            item.setText(4, str(length))
            item.setText(5, info)
            
            # Store full packet data in the item
            item.setData(0, Qt.ItemDataRole.UserRole, packet)
            
            # Auto-scroll to bottom
            self.packet_list.scrollToBottom()
            
        except Exception as e:
            print(f"Error processing packet: {e}")
            
    def show_packet_details(self):
        """Show details of selected packet"""
        selected = self.packet_list.selectedItems()
        if not selected:
            return
            
        packet = selected[0].data(0, Qt.ItemDataRole.UserRole)
        if not packet:
            return
            
        try:
            self.packet_details.clear()
            
            # Basic info
            self.packet_details.append("=== Packet Details ===")
            self.packet_details.append(f"Time: {selected[0].text(0)}")
            self.packet_details.append(f"Source: {selected[0].text(1)}")
            self.packet_details.append(f"Destination: {selected[0].text(2)}")
            self.packet_details.append(f"Protocol: {selected[0].text(3)}")
            self.packet_details.append(f"Length: {selected[0].text(4)} bytes\n")
            
            # Detailed layers
            self.packet_details.append("=== Layers ===")
            for layer in packet.layers():
                self.packet_details.append(f"- {layer.__name__}")
                
            # Hex dump
            self.packet_details.append("\n=== Hex Dump ===")
            hexdump = scapy.hexdump(packet, dump=True)
            self.packet_details.append(hexdump)
            
        except Exception as e:
            self.packet_details.append(f"Error displaying packet: {str(e)}")


class SerialReadThread(QThread):
    """Thread for reading serial data"""
    data_received = pyqtSignal(str)
    
    def __init__(self, serial_port):
        super().__init__()
        self.serial_port = serial_port
        self.running = True
        
    def run(self):
        """Read data from serial port"""
        while self.running and self.serial_port.is_open:
            try:
                if self.serial_port.in_waiting:
                    data = self.serial_port.readline().decode(errors='ignore').strip()
                    if data:
                        self.data_received.emit(data)
            except:
                break
                
    def stop(self):
        """Stop the thread"""
        self.running = False
        self.wait()


class PacketSnifferThread(QThread):
    """Thread for sniffing network packets"""
    packet_received = pyqtSignal(object)  # Emits scapy Packet objects
    
    def __init__(self, iface, filter=None, count=None):
        super().__init__()
        self.iface = iface
        self.filter = filter
        self.count = count
        self.running = True
        
    def run(self):
        """Start sniffing packets"""
        try:
            scapy.sniff(
                iface=self.iface,
                filter=self.filter,
                prn=self.process_packet,
                count=self.count,
                stop_filter=lambda x: not self.running,
                store=False
            )
        except Exception as e:
            print(f"Sniffing error: {e}")
            
    def process_packet(self, packet):
        """Process each sniffed packet"""
        if self.running:
            self.packet_received.emit(packet)
            
    def stop(self):
        """Stop sniffing"""
        self.running = False
        self.wait()


if __name__ == "__main__":
    from PyQt6.QtWidgets import QApplication
    import sys
    
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = IoTDebugMonitor()
    window.show()
    sys.exit(app.exec())