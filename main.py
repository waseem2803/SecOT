from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QHBoxLayout,
    QVBoxLayout,
    QPushButton,
    QLabel,
    QWidget,
    QMessageBox

)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
import sys
from modules import dump,debug,extract_bin,network,hash_crac,file_extract,dependency_scanner,analyze , webapp_scanner
from L_config import temp_path_b
import pyfiglet
import os
import sys
import signal

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecOT:IoT penetration testing platform")  # Window title
        self.setGeometry(100, 100, 1200, 700)  # Initial size

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
        display_character = pyfiglet.Figlet(font='doom')
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
            font-size: 20px;
            color: black;              /* Font size for content */
            """
        )
        self.main_layout.addWidget(self.function_window)

    def create_nav_buttons(self):
        # Create buttons for each function
        buttons = [
            ("Debugger", self.Debugger),
            ("Dump", self.Dump),
            ("Extract", self.Extract),
            #("Analyze", self.Analyze),
           # ("Embedded Files Extractor", self.Embedded_File_Extractor),
            ("Dependency Scanner", self.Dependency_Scanner),
            ("Network Scan", self.scan),
            ("WebApp Scanner", self.WebApp_Scanner),
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
                    background-color: ; 
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
         self.function_window = debug.IoTDebugMonitor()
         self.main_layout.addWidget(self.function_window)

    def Dump(self):
        self.main_layout.removeWidget(self.function_window)
        self.function_window = dump.DumpFirmware()
        self.main_layout.addWidget(self.function_window)
    
    def Dependency_Scanner(self):
        self.main_layout.removeWidget(self.function_window)
        self.function_window = dependency_scanner.DependencyScanner()
        self.main_layout.addWidget(self.function_window)

    def Extract(self):
        self.main_layout.removeWidget(self.function_window)
        self.function_window = extract_bin.BinwalkFileExtractor()
        extractor = extract_bin.BinwalkFileExtractor()
        extractor.send_to_hash_cracker.connect(self.handle_send_to_hash_cracker)
       # extractor.send_to_analyzer.connect(self.handle_send_to_analyzer)
        self.main_layout.addWidget(self.function_window)

    def Analyze(self):
        self.main_layout.removeWidget(self.function_window)
        self.function_window = QLabel()
        self.function_window = analyze.BinaryAnalyzer()
        self.main_layout.addWidget(self.function_window)

    def WebApp_Scanner(self):
        self.main_layout.removeWidget(self.function_window)
        self.function_window = webapp_scanner.WebAppScanner()
        self.main_layout.addWidget(self.function_window)

    def scan(self):
        self.main_layout.removeWidget(self.function_window)
        self.function_window = network.NetworkAnalyzer()
        self.main_layout.addWidget(self.function_window)

    def hashcracker(self):
        # Remove current widget if exists
        if hasattr(self, 'function_window'):
            self.function_window.setParent(None)
            self.function_window.deleteLater()
        
        # Create new hash cracker instance
        self.function_window = hash_crac.HashCracker()
        self.main_layout.addWidget(self.function_window)

    def handle_send_to_hash_cracker(self, file_path):
        """Handle file sent to hash cracker - sends only the path"""
        # Switch to hash cracker tab first
        self.hashcracker()
        
        # Get reference to the hash cracker instance
        hash_cracker = self.function_window
        
        # Check if it has the set_file_path method
        if hasattr(hash_cracker, 'set_file_path'):
            try:
                # Just send the path string
                hash_cracker.set_file_path(file_path)
            except Exception as e:
                QMessageBox.critical(self, "Error", 
                                f"Failed to set file path:\n{str(e)}")
        else:
            QMessageBox.warning(self, "Error", "Hash cracker module doesn't support file path setting")

    def quit_gracefully(sig,frame):
        print("Quitting application...")
        QApplication.quit()

    signal.signal(signal.SIGINT, quit_gracefully)


if __name__ == "__main__":
    # Check if script is running with root privileges
    if os.geteuid() != 0:
        print("Re-running script with sudo...")
        os.execvp("sudo", ["sudo", "/home/mohammed/secOT/SecOT/myenv_l/bin/python"] + sys.argv)
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
