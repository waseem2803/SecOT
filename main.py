from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QHBoxLayout,
    QVBoxLayout,
    QPushButton,
    QLabel,
    QWidget,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
import sys
from modules import dump,debug,extract_bin,network,hash_crac
from L_config import temp_path_b
import pyfiglet
import os
import sys

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecOT:IoT penetration testing platform")  # Window title
        self.setGeometry(100, 100, 800, 600)  # Initial size

        # Main container widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        # Main layout (Vertical: Navbar + Content)
        self.main_layout = QVBoxLayout()
        self.central_widget.setLayout(self.main_layout)

        # Create the nav bar container
        self.nav_container = QWidget()
        self.nav_container.setStyleSheet("background-color:;")  # Light blue background
        self.nav_bar_layout = QHBoxLayout()
        self.nav_container.setFixedHeight(60)  # Set the height of the nav container
        self.nav_bar_layout.setContentsMargins(10, 10, 10, 10)  # Add padding around the nav bar
        self.nav_container.setLayout(self.nav_bar_layout)
        self.main_layout.addWidget(self.nav_container)

        # Add buttons to the nav bar
        self.create_nav_buttons()
        display_character = pyfiglet.Figlet(font="epic")
        nameapp = QLabel(display_character.renderText("SecOT v1.0"))
        font = QFont("Courier New")  # Common monospace font
        font.setPointSize(10)  # Adjust as needed
        nameapp.setFont(font)
        # Create the function display container
        self.function_window = nameapp  # Initial text
        self.function_window.setAlignment(Qt.AlignmentFlag.AlignCenter)  # Center text
        self.function_window.setStyleSheet(
            """
            background-color: white;  /* White background for the function window */
            font-size: 20px;         /* Font size for content */
            """
        )
        self.main_layout.addWidget(self.function_window)

    def create_nav_buttons(self):
        # Create buttons for each function
        buttons = [
            ("Debugger", self.Debugger),
            ("Dump", self.Dump),
            ("Extract", self.Extract),
            ("Analyze", self.Analyze),
            ("Network Scan", self.scan),
            ("Hash Cracker", self.hashcracker),
        ]

        for name, handler in buttons:
            button = QPushButton(name)
            button.setStyleSheet(
            """
                QPushButton {
                    padding: 10px 20px; 
                    font-size: 14px; 
                    border: 1px solid #ccc; 
                    border-radius: 5px;
                    background-color: white; 
                }
                QPushButton:pressed {
                    background-color: grey; 
                }
                QPushButton:hover {
                    background-color: #f0f0f0;
                }
            """
 
            )
            button.clicked.connect(handler)  # Connect each button to its function
            self.nav_bar_layout.addWidget(button)

    # Functions to update the function window content
    def Debugger(self):
         self.main_layout.removeWidget(self.function_window)
         self.function_window = debug.SerialMonitorWidget()
         self.main_layout.addWidget(self.function_window)

    def Dump(self):
        self.main_layout.removeWidget(self.function_window)
        self.function_window = dump.DumpFirmware()
        self.main_layout.addWidget(self.function_window)

    def Extract(self):
        self.main_layout.removeWidget(self.function_window)
        self.function_window = extract_bin.BinwalkFileExtractor()
        self.main_layout.addWidget(self.function_window)

    def Analyze(self):
        self.main_layout.removeWidget(self.function_window)
        self.function_window = QLabel()
        self.function_window.setText("You are now viewing Function 2")
        self.main_layout.addWidget(self.function_window)

    def scan(self):
        self.main_layout.removeWidget(self.function_window)
        self.function_window = network.NetworkAnalyzer()
        self.main_layout.addWidget(self.function_window)

    def hashcracker(self):
        self.main_layout.removeWidget(self.function_window)
        self.function_window = hash_crac.HashCracker()
        self.main_layout.addWidget(self.function_window)


if __name__ == "__main__":
    # Check if script is running with root privileges
    if os.geteuid() != 0:
        print("Re-running script with sudo...")
        os.execvp("sudo", ["sudo", "/home/mohammed/secOT/SecOT/myenv_l/bin/python"] + sys.argv)
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
