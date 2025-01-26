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
import sys
from modules import extract,debug

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyQt6 Application with Nav Bar and Function Window")
        self.setGeometry(100, 100, 800, 600)  # Initial size

        # Main container widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        # Main layout (Vertical: Navbar + Content)
        self.main_layout = QVBoxLayout()
        self.central_widget.setLayout(self.main_layout)

        # Create the nav bar container
        self.nav_container = QWidget()
        self.nav_container.setStyleSheet("background-color: 232, 236, 238;")  # Light blue background
        self.nav_bar_layout = QHBoxLayout()
        self.nav_container.setFixedHeight(60)  # Set the height of the nav container
        self.nav_bar_layout.setContentsMargins(10, 10, 10, 10)  # Add padding around the nav bar
        self.nav_container.setLayout(self.nav_bar_layout)
        self.main_layout.addWidget(self.nav_container)

        # Add buttons to the nav bar
        self.create_nav_buttons()

        # Create the function display container
        self.function_window = QLabel(""" 
 _____              _____  _____ 
/  ___|            |  _  ||_   _|
\ `--.   ___   ___ | | | |  | |  
 `--. \ / _ \ / __|| | | |  | |  
/\__/ /|  __/| (__ \ \_/ /  | |  
\____/  \___| \___| \___/   \_/  
                                 
                                   """)  # Initial text
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
            ("DEBUGGER", self.Debugger),
            ("DUMP", self.Dump),
            ("EXTRACT", self.Extract),
            ("ANALYZE", self.Analyze),
            ("SCAN", self.scan),
            ("FUZZ", self.fuzz),
        ]

        for name, handler in buttons:
            button = QPushButton(name)
            button.setStyleSheet(
                """
                padding: 10px 20px; 
                font-size: 14px; 
                border: 1px solid #ccc; 
                border-radius: 5px;
                background-color: white; 
                """
            )
            button.clicked.connect(handler)  # Connect each button to its function
            self.nav_bar_layout.addWidget(button)

    # Functions to update the function window content
    def Debugger(self):
         self.main_layout.removeWidget(self.function_window)
         widget = debug.SerialMonitorWidget()
         self.main_layout.addWidget(widget)

    def Dump(self):
        self.function_window.setText("You are now viewing Function 1")

    def Extract(self):
        self.function_window.setText("You are now viewing Function 2")

    def Analyze(self):
        self.function_window.setText("You are now viewing Function 3")

    def scan(self):
        self.function_window.setText("You are now viewing Function 4")

    def fuzz(self):
        self.function_window.setText("You are now viewing Function 5")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
