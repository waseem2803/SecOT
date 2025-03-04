import os
import subprocess
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTreeWidget, QTreeWidgetItem, QTextEdit, QPushButton, QFileDialog, QLabel, QMessageBox, QCheckBox, QComboBox
)
from PyQt6.QtCore import Qt
from pathlib import Path

class BinwalkFileExtractor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Binwalk File Extractor")
        self.setGeometry(200, 200, 800, 600)

        # Layouts
        main_layout = QHBoxLayout()
        left_layout = QVBoxLayout()
        right_layout = QVBoxLayout()

        # File Tree Widget
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderHidden(True)
        self.file_tree.itemClicked.connect(self.display_file_content)

        # File Content Viewer
        self.file_viewer = QTextEdit()
        self.file_viewer.setReadOnly(True)

        # Load Binary Button
        self.load_button = QPushButton("Load Binary File")
        self.load_button.clicked.connect(self.load_binary_file)

        # Select Directory Button
        self.select_dir_button = QPushButton("Select Directory")
        self.select_dir_button.clicked.connect(self.select_directory)

        # Magic Bytes Extraction Checkbox
        self.magic_bytes_checkbox = QCheckBox("Use Magic Bytes for Extraction")
        self.magic_bytes_checkbox.stateChanged.connect(self.toggle_fs_dropdown)

        # Filesystem Type Dropdown
        self.fs_type_dropdown = QComboBox()
        self.fs_type_dropdown.addItems(["SquashFS", "Ext", "JFFS2", "UBIFS"])
        self.fs_type_dropdown.setEnabled(False)

        # Status Label
        self.status_label = QLabel("Status: Ready")

        # Arrange layouts
        left_layout.addWidget(self.load_button)
        left_layout.addWidget(self.select_dir_button)
        left_layout.addWidget(self.magic_bytes_checkbox)
        left_layout.addWidget(self.fs_type_dropdown)
        left_layout.addWidget(self.file_tree)
        left_layout.addWidget(self.status_label)

        right_layout.addWidget(self.file_viewer)

        main_layout.addLayout(left_layout, 1)
        main_layout.addLayout(right_layout, 3)

        self.setLayout(main_layout)

        # Instance variables
        self.extracted_dir = None

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
            subprocess.run(["binwalk", "--extract"] + (magic_bytes_option.split() if magic_bytes_option else []) + [file_path], check=True)
        except FileNotFoundError:
            QMessageBox.critical(self, "Error", "Binwalk is not installed or not found in PATH.")
            self.status_label.setText("Status: Binwalk not found.")
            return
        except subprocess.CalledProcessError:
            QMessageBox.critical(self, "Error", "Failed to extract binary file.")
            self.status_label.setText("Status: Extraction failed.")
            return

        base_name = os.path.basename(file_path)
        self.extracted_dir = os.path.join(os.getcwd(), f"_{base_name}.extracted")

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
            return

        b_path = Path(self.extracted_dir)
        relative_path = Path(*self.get_item_path(item))
        
        if relative_path.parts[0] == b_path.name:
            relative_path = relative_path.relative_to(relative_path.parts[0])

        file_path = b_path / relative_path  
        
        if os.path.isdir(file_path):
            return  

        if not os.path.exists(file_path):
            self.file_viewer.setText(f"File not found: {file_path}")
            return

        try:
            with open(file_path, "r", errors="ignore") as file:
                content = file.read()
                self.file_viewer.setText(content)
        except Exception as e:
            self.file_viewer.setText(f"Failed to read file: {e}")

    def get_item_path(self, item):
        path = []
        while item is not None:
            path.insert(0, item.text(0))
            item = item.parent()
        return path

if __name__ == "__main__":
    import sys

    app = QApplication(sys.argv)
    window = BinwalkFileExtractor()
    window.show()
    sys.exit(app.exec())