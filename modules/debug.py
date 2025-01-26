import serial
import serial.tools.list_ports
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox, QLineEdit, QTextEdit
)
from PyQt6.QtCore import QThread, pyqtSignal


class SerialMonitorWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        # Main layout for the widget
        self.main_layout = QVBoxLayout(self)

        # Serial configuration layout (top section)
        self.config_layout = QHBoxLayout()
        self.main_layout.addLayout(self.config_layout)

        # COM Port selection
        self.com_label = QLabel("COM Port:")
        self.config_layout.addWidget(self.com_label)

        self.com_combo = QComboBox()
        self.refresh_ports()  # Populate the COM port dropdown
        self.config_layout.addWidget(self.com_combo)

        # Baud rate selection
        self.baud_label = QLabel("Baud Rate:")
        self.config_layout.addWidget(self.baud_label)

        self.baud_combo = QComboBox()
        self.baud_combo.addItems(["9600", "115200", "230400", "921600"])  # Common baud rates
        self.config_layout.addWidget(self.baud_combo)

        # Connect and Disconnect buttons
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.connect_serial)
        self.config_layout.addWidget(self.connect_button)

        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.clicked.connect(self.disconnect_serial)
        self.disconnect_button.setEnabled(False)  # Disable disconnect by default
        self.config_layout.addWidget(self.disconnect_button)

        # Text area to display received serial data
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)  # Make the text area read-only
        self.main_layout.addWidget(self.text_area)

        # Input layout (for sending data)
        self.input_layout = QHBoxLayout()
        self.main_layout.addLayout(self.input_layout)

        self.input_line = QLineEdit()
        self.input_line.setPlaceholderText("Enter data to send...")
        self.input_layout.addWidget(self.input_line)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_data)
        self.input_layout.addWidget(self.send_button)

        # Serial port instance and background thread for reading data
        self.serial_port = None
        self.read_thread = None

    def refresh_ports(self):
        """Refresh the list of available COM ports."""
        self.com_combo.clear()  # Clear existing items
        ports = serial.tools.list_ports.comports()
        for port in ports:
            self.com_combo.addItem(port.device)  # Add detected ports to the dropdown

    def connect_serial(self):
        """Connect to the selected serial port."""
        com_port = self.com_combo.currentText()
        baud_rate = int(self.baud_combo.currentText())
        try:
            # Open serial port
            self.serial_port = serial.Serial(com_port, baud_rate, timeout=1)
            self.text_area.append(f"Connected to {com_port} at {baud_rate} baud.")

            # Start background thread to read data
            self.read_thread = SerialReadThread(self.serial_port)
            self.read_thread.data_received.connect(self.display_data)
            self.read_thread.start()

            # Update button states
            self.connect_button.setEnabled(False)
            self.disconnect_button.setEnabled(True)
        except serial.serialException as e:
            self.text_area.append(f"Error: {str(e)}")

    def disconnect_serial(self):
        """Disconnect from the serial port."""
        if self.serial_port and self.serial_port.is_open:
            # Stop the background thread
            self.read_thread.stop()
            self.serial_port.close()
            self.text_area.append("Disconnected from serial port.")

            # Update button states
            self.connect_button.setEnabled(True)
            self.disconnect_button.setEnabled(False)

    def send_data(self):
        """Send data through the serial port."""
        if self.serial_port and self.serial_port.is_open:
            data = self.input_line.text()
            self.serial_port.write(data.encode())  # Send data
            self.text_area.append(f"Sent: {data}")
            self.input_line.clear()
        else:
            self.text_area.append("Error: Not connected to any serial port.")

    def display_data(self, data):
        """Display received data in the text area."""
        self.text_area.append(f"Received: {data}")


class SerialReadThread(QThread):
    """Thread to read data from the serial port."""
    data_received = pyqtSignal(str)

    def __init__(self, serial_port):
        super().__init__()
        self.serial_port = serial_port
        self.running = True

    def run(self):
        """Continuously read data from the serial port."""
        while self.running:
            if self.serial_port.in_waiting:
                data = self.serial_port.readline().decode(errors='ignore').strip()
                if data:
                    self.data_received.emit(data)

    def stop(self):
        """Stop the thread."""
        self.running = False
        self.wait()
