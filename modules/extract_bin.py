import os
import subprocess
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTreeWidget, QTreeWidgetItem, QTextEdit, QPushButton, QFileDialog,
    QLabel, QMessageBox, QCheckBox, QComboBox, QSplitter, QMenu
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QAction, QFont
from pathlib import Path
import magic
from L_config import temp_path_b

class BinwalkFileExtractor(QMainWindow):
    send_to_hash_cracker = pyqtSignal(str)
    send_to_analyzer = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Binwalk File Extractor")
        self.setGeometry(200, 200, 1000, 700)
        self.setup_ui()
        self.extracted_dir = None

    def setup_ui(self):
        """Initialize and configure the UI components"""
        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Splitter for the main content
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel - controls and file tree
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)

        # File operations
        file_buttons = QHBoxLayout()
        self.load_button = QPushButton("Load Binary File")
        self.load_button.clicked.connect(self.load_binary_file)
        file_buttons.addWidget(self.load_button)

        self.select_dir_button = QPushButton("Open Extracted")
        self.select_dir_button.clicked.connect(self.select_directory)
        file_buttons.addWidget(self.select_dir_button)
        left_layout.addLayout(file_buttons)

        # Extraction options
        self.magic_bytes_checkbox = QCheckBox("Use Magic Bytes for Extraction")
        self.magic_bytes_checkbox.stateChanged.connect(self.toggle_fs_dropdown)
        left_layout.addWidget(self.magic_bytes_checkbox)

        self.fs_type_dropdown = QComboBox()
        self.fs_type_dropdown.addItems(["SquashFS", "Ext", "JFFS2", "UBIFS", "CramFS"])
        self.fs_type_dropdown.setEnabled(False)
        left_layout.addWidget(self.fs_type_dropdown)

        # File tree
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(["Extracted Files"])
        self.file_tree.itemClicked.connect(self.display_file_content)
        self.file_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_tree.customContextMenuRequested.connect(self.show_context_menu)
        left_layout.addWidget(self.file_tree)

        # Scan button
        self.binwalk_button = QPushButton("Scan Binary File")
        self.binwalk_button.clicked.connect(self.scan_binary_file)
        left_layout.addWidget(self.binwalk_button)

        # Status label
        self.status_label = QLabel("Status: Ready")
        left_layout.addWidget(self.status_label)

        # Right panel - file content and scan results
        right_panel = QSplitter(Qt.Orientation.Vertical)

        # File content viewer
        self.file_viewer = QTextEdit()
        self.file_viewer.setReadOnly(True)
        self.file_viewer.setFont(QFont("Courier New", 10))
        right_panel.addWidget(self.file_viewer)

        # Binwalk scan output
        self.scan_output = QTextEdit()
        self.scan_output.setReadOnly(True)
        self.scan_output.setFont(QFont("Courier New", 10))
        right_panel.addWidget(self.scan_output)

        # Add panels to splitter
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([300, 700])

        # Add to main layout
        main_layout.addWidget(splitter)

    def scan_binary_file(self):
        """Scan the binary file with binwalk and display results"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Binary File", "", "All Files (*)"
        )
        if not file_path:
            return

        try:
            result = subprocess.run(
                ["binwalk", file_path],
                capture_output=True,
                text=True,
                check=True
            )
            self.scan_output.setText(result.stdout)
            self.status_label.setText("Status: Scan completed successfully")
        except subprocess.CalledProcessError as e:
            self.scan_output.setText(f"Error running binwalk:\n{e.stderr}")
            self.status_label.setText("Status: Scan failed")
        except FileNotFoundError:
            QMessageBox.critical(self, "Error", "Binwalk is not installed or not found in PATH.")
            self.status_label.setText("Status: Binwalk not found")

    def load_binary_file(self):
        """Load and extract a binary file using binwalk"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Binary File", "", "All Files (*)"
        )
        if not file_path:
            return

        command = ["sudo", "binwalk", "-e", "--run-as=root", "--directory", temp_path_b]
        
        if self.magic_bytes_checkbox.isChecked():
            fs_type = self.fs_type_dropdown.currentText()
            command.extend(["-D", f"'{fs_type.lower()}:{fs_type} filesystem'"])

        command.append(file_path)

        self.status_label.setText("Status: Extracting...")
        QApplication.processEvents()

        try:
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
            base_name = os.path.basename(file_path)
            self.extracted_dir = os.path.join(temp_path_b, f"_{base_name}.extracted")

            if os.path.exists(self.extracted_dir):
                self.populate_file_tree()
                self.status_label.setText("Status: Extraction complete")
            else:
                QMessageBox.warning(self, "Warning", "No files were extracted")
                self.status_label.setText("Status: No files extracted")
        except subprocess.CalledProcessError:
            QMessageBox.critical(self, "Error", "Failed to extract binary file")
            self.status_label.setText("Status: Extraction failed")

    def toggle_fs_dropdown(self):
        """Toggle the filesystem type dropdown based on checkbox state"""
        self.fs_type_dropdown.setEnabled(self.magic_bytes_checkbox.isChecked())

    def select_directory(self):
        """Select an already extracted directory"""
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.extracted_dir = directory
            self.populate_file_tree()
            self.status_label.setText(f"Status: Loaded {os.path.basename(directory)}")

    def populate_file_tree(self):
        """Populate the file tree with the contents of the extracted directory"""
        self.file_tree.clear()

        def add_items(parent_item, directory):
            try:
                for entry in sorted(os.listdir(directory)):
                    entry_path = os.path.join(directory, entry)
                    item = QTreeWidgetItem([entry])
                    item.setData(0, Qt.ItemDataRole.UserRole, entry_path)
                    
                    if os.path.isdir(entry_path):
                        add_items(item, entry_path)
                    
                    parent_item.addChild(item)
            except PermissionError as e:
                print(f"Permission error reading directory: {e}")

        if self.extracted_dir and os.path.exists(self.extracted_dir):
            root_item = QTreeWidgetItem([os.path.basename(self.extracted_dir)])
            root_item.setData(0, Qt.ItemDataRole.UserRole, self.extracted_dir)
            self.file_tree.addTopLevelItem(root_item)
            add_items(root_item, self.extracted_dir)
            self.file_tree.expandItem(root_item)

    def display_file_content(self, item):
        """Display the content of the selected file"""
        file_path = item.data(0, Qt.ItemDataRole.UserRole)
        if not file_path:
            return

        self.file_viewer.clear()

        if os.path.isdir(file_path):
            self.file_viewer.setText(f"Directory: {file_path}")
            return

        try:
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)

            if "text" in file_type or "ascii" in file_type:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    self.file_viewer.setText(f.read())
            else:
                with open(file_path, "rb") as f:
                    # Display first 1KB of binary files in hex
                    self.file_viewer.setText(f.read(1024).hex(' ', 1))
        except Exception as e:
            self.file_viewer.setText(f"Error reading file: {str(e)}")

    def show_context_menu(self, position):
        """Show context menu for file operations"""
        item = self.file_tree.itemAt(position)
        if not item:
            return

        file_path = item.data(0, Qt.ItemDataRole.UserRole)
        if not file_path or not os.path.isfile(file_path):
            return

        menu = QMenu(self)
        
        hash_action = QAction("Send to Hash Cracker", self)
        hash_action.triggered.connect(lambda: self.send_to_hash_cracker.emit(file_path))
        menu.addAction(hash_action)
        
        analyze_action = QAction("Send to Analyzer", self)
        analyze_action.triggered.connect(lambda: self.send_to_analyzer.emit(file_path))
        menu.addAction(analyze_action)
        
        menu.exec(self.file_tree.viewport().mapToGlobal(position))

if __name__ == "__main__":
    app = QApplication([])
    window = BinwalkFileExtractor()
    window.show()
    app.exec()