import os
import subprocess
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTreeWidget, QTreeWidgetItem, QTextEdit, QPushButton, QFileDialog, QLabel, QMessageBox, QCheckBox, QComboBox , QSizePolicy
)
from PyQt6.QtCore import Qt
from pathlib import Path
import magic
from L_config import temp_path_b

class BinwalkFileExtractor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Binwalk File Extractor")
        self.setGeometry(200, 200, 800, 600)

        # Layouts
        main_layout = QVBoxLayout()
        top_layout = QHBoxLayout()
        left_layout = QVBoxLayout()
        right_layout = QVBoxLayout()
        bottom_layout = QHBoxLayout()

        # File Tree Widget
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderHidden(True)
        self.file_tree.itemClicked.connect(self.display_file_content)
        self.file_tree.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
    
        # File Content Viewer
        self.file_viewer = QTextEdit()
        self.file_viewer.setReadOnly(True)

        # Load Binary Button
        self.load_button = QPushButton("Load Binary File")
        self.load_button.clicked.connect(self.load_binary_file)

        # Select Directory Button
        self.select_dir_button = QPushButton("Select Directory")
        self.select_dir_button.clicked.connect(self.select_directory)

        #scan button
        self.binwalk_button = QPushButton("Scan Binary File")
        # Magic Bytes Extraction Checkbox
        self.magic_bytes_checkbox = QCheckBox("Use Magic Bytes for Extraction")
        self.magic_bytes_checkbox.stateChanged.connect(self.toggle_fs_dropdown)

        # Filesystem Type Dropdown
        self.fs_type_dropdown = QComboBox()
        self.fs_type_dropdown.addItems(["SquashFS", "Ext", "JFFS2", "UBIFS"])
        self.fs_type_dropdown.setEnabled(False)

        #binwalk file scan
       
        self.file_scan = QTextEdit()
        self.file_scan.setReadOnly(True)
        self.binwalk_button.clicked.connect(self.read_binwalk)
        # Status Label
        self.status_label = QLabel("Status: Ready")

        # Arrange layouts
        left_layout.addWidget(self.load_button)
        left_layout.addWidget(self.select_dir_button)
        left_layout.addWidget(self.magic_bytes_checkbox)
        left_layout.addWidget(self.fs_type_dropdown)
        left_layout.addWidget(self.file_tree)
        left_layout.addWidget(self.status_label)
        left_layout.addWidget(self.binwalk_button)
        
        right_layout.addWidget(self.file_viewer)

        bottom_layout.addWidget(self.file_scan)
        

        top_layout.addLayout(left_layout, 1)
        top_layout.addLayout(right_layout, 3)
        main_layout.addLayout(top_layout)
        main_layout.addLayout(bottom_layout)

        self.setLayout(main_layout)

        # Instance variables
        self.extracted_dir = None

    def read_binwalk(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Binary File", "", "All Files (*)")
        if not file_path:
            return  # Exit if no file is selected
        
        try:
            scan_result = subprocess.run(["binwalk", file_path ], capture_output=True, text=True, check=True)
            self.file_scan.setText(scan_result.stdout)  # Display the output in the QTextEdit
        except subprocess.CalledProcessError as e:
            self.file_scan.setText(f"Error running binwalk:\n{e}")

    def toggle_fs_dropdown(self):
        self.fs_type_dropdown.setEnabled(self.magic_bytes_checkbox.isChecked())

    def load_binary_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Binary File", "", "All Files (*)")
        if not file_path:
            return

        magic_bytes_option = ""
        if self.magic_bytes_checkbox.isChecked():
            fs_type = self.fs_type_dropdown.currentText()
            magic_bytes_option = self.get_magic_bytes_option(fs_type)
        
        self.status_label.setText("Status: Extracting...")
        QApplication.processEvents()
        try:
            subprocess.run(["sudo","binwalk", "-e", "--run-as=root","--directory", temp_path_b, file_path], check=True , stdout=subprocess.DEVNULL)
        except FileNotFoundError:
            QMessageBox.critical(self, "Error", "Binwalk is not installed or not found in PATH.")
            self.status_label.setText("Status: Binwalk not found.")
            return
        except subprocess.CalledProcessError:
            QMessageBox.critical(self, "Error", "Failed to extract binary file.")
            self.status_label.setText("Status: Extraction failed.")
            return

        base_name = os.path.basename(file_path)
        self.extracted_dir = os.path.join(temp_path_b, f"_{base_name}.extracted")

        if not os.path.exists(self.extracted_dir):
            QMessageBox.warning(self, "Warning", "No files were extracted.")
            self.status_label.setText("Status: No files extracted.")
            return

        self.populate_file_tree()
        self.status_label.setText("Status: Extraction complete.")

    def get_magic_bytes_option(self, fs_type):
        fs_options = {
            "SquashFS": "-D 'squashfs'",
            "Ext": "-D 'ext'",
            "JFFS2": "-D 'jffs2'",
            "UBIFS": "-D 'ubifs'",
        }
        return fs_options.get(fs_type, "")

    def select_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.extracted_dir = directory
            self.populate_file_tree()

    def populate_file_tree(self):
        self.file_tree.clear()

        def add_items(parent_item, directory):
            for entry in os.listdir(directory):
                entry_path = os.path.join(directory, entry)
                item = QTreeWidgetItem([entry])
                parent_item.addChild(item)
                if os.path.isdir(entry_path):
                    add_items(item, entry_path)

        if self.extracted_dir:
            root_item = QTreeWidgetItem([os.path.basename(self.extracted_dir)])
            self.file_tree.addTopLevelItem(root_item)
            add_items(root_item, self.extracted_dir)

    def display_file_content(self, item):
        if not self.extracted_dir:
            self.file_viewer.setText("Error: No extraction directory set")
            return

        # Get path parts from tree item
        item_path_parts = self.get_item_path(item)
        if not item_path_parts:
            self.file_viewer.setText("Error: Invalid item path")
            return

        # Convert to Path objects
        extracted_dir = Path(self.extracted_dir).resolve()
        item_path = Path(*item_path_parts)

        # Debug output
        print(f"[DEBUG 1] Extracted dir: {extracted_dir}")
        print(f"[DEBUG 2] Raw item path: {item_path}")

        # SPECIAL FIX: Remove extracted_dir name if it appears at start of item_path
        extracted_dir_name = extracted_dir.name
        if item_path.parts and item_path.parts[0] == extracted_dir_name:
            item_path = Path(*item_path.parts[1:])  # Remove first component
            print(f"[DEBUG 3] Fixed item path: {item_path}")

        # Construct final path
        file_path = extracted_dir / item_path
        file_path = file_path.resolve()

        # Debug output
        print(f"[DEBUG 4] Final file path: {file_path}")

        # Handle file display
        self.file_viewer.clear()

        if file_path.is_dir():
            self.file_viewer.setText(f"[Directory] {file_path}")
            return

        if not file_path.exists():
            self.file_viewer.setText(f"File not found: {file_path}")
            return

        try:
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(str(file_path))

            if "text" in file_type or "ascii" in file_type:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    self.file_viewer.setText(f.read())
            else:
                with open(file_path, "rb") as f:
                    self.file_viewer.setText(f.read(256).hex())
        except Exception as e:
            self.file_viewer.setText(f"Error reading file: {str(e)}")
                    
    def get_item_path(self, item):
        path = []
        while item is not None:
            path.insert(0, item.text(0))
            item = item.parent()
            print(path)
        return path

if __name__ == "__main__":
    import sys

    app = QApplication(sys.argv)
    window = BinwalkFileExtractor()
    window.show()
    sys.exit(app.exec())