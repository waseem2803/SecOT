import os
import subprocess
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTreeWidget, QTreeWidgetItem, QTextEdit, QPushButton, QFileDialog, QLabel, QMessageBox, QSplitter
)
from PyQt6.QtCore import Qt, QStringListModel
from pathlib import Path
import datetime


def find_magic_offsets(file_path, magic_dict):
    """Scans the firmware for known file signatures and returns offsets."""
    offsets = []
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            for magic, ext in magic_dict.items():
                offset = data.find(magic)
                while offset != -1:
                    offsets.append((offset, ext))
                    offset = data.find(magic, offset + 1)
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
    except Exception as e:
        print(f"Unexpected error while reading the file: {e}")
    return offsets


def extract_files(file_path, offsets, output_dir):
    """Extracts files from the firmware based on identified offsets."""
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
        except Exception as e:
            print(f"Error creating output directory: {e}")
            return []

    extracted_files = []
    try:
        with open(file_path, 'rb') as f:
            for i, (offset, ext) in enumerate(offsets):
                f.seek(offset)
                data = f.read(1024 * 1024)  # Read 1MB for initial extraction
                output_file = os.path.join(output_dir, f'extracted_{i}.{ext}')
                with open(output_file, 'wb') as out:
                    out.write(data)
                extracted_files.append(output_file)
    except Exception as e:
        print(f"Unexpected error while extracting files: {e}")

    return extracted_files


def extract_filesystem(file_path, output_dir):
    """Extracts and processes known file systems from firmware."""
    magic_fs = {
        b'hsqs': 'squashfs',  # SquashFS
        b'0x28cd3d45': 'cramfs',  # CramFS
        b'JFFS2': 'jffs2',  # JFFS2
        b'UBI#': 'ubifs',  # UBIFS
    }
    offsets = find_magic_offsets(file_path, magic_fs)
    if not offsets:
        print("No known filesystems found.")
        return []
    
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
        except Exception as e:
            print(f"Error creating output directory: {e}")
            return []

    extracted_fs_paths = []
    try:
        with open(file_path, 'rb') as f:
            for i, (offset, fs_type) in enumerate(offsets):
                f.seek(offset)
                data = f.read(10 * 1024 * 1024)  # Read 10MB for extraction
                output_file = os.path.join(output_dir, f'filesystem_{i}.{fs_type}')
                with open(output_file, 'wb') as out:
                    out.write(data)
                extracted_fs_paths.append((output_file, fs_type))
                print(f"Extracted filesystem: {output_file}")
    except Exception as e:
        print(f"Unexpected error while extracting filesystems: {e}")

    for fs_path, fs_type in extracted_fs_paths:
        extract_rootfs(fs_path, fs_type, output_dir)


def extract_rootfs(fs_path, fs_type, output_dir):
    """Extracts root filesystem from recognized file systems."""
    fs_extractors = {
        'squashfs': ["unsquashfs", "-d", os.path.join(output_dir, "rootfs"), fs_path],
        'cramfs': ["cramfsck", "-x", os.path.join(output_dir, "rootfs"), fs_path],
        'jffs2': ["jefferson", fs_path, "-d", os.path.join(output_dir, "rootfs")],
        'ubifs': ["ubi_extract", "-d", os.path.join(output_dir, "rootfs"), fs_path],
    }
    
    if fs_type in fs_extractors:
        try:
            subprocess.run(fs_extractors[fs_type], check=True)
            print(f"Successfully extracted rootfs from {fs_type} filesystem.")
        except subprocess.CalledProcessError as e:
            print(f"Error during {fs_type} extraction: {e}")
        except Exception as e:
            print(f"Failed to extract rootfs from {fs_type}: {e}")
    else:
        print(f"No extractor available for {fs_type}.")


def main(firmware_path, output_dir):
    """Main function to scan and extract files and file systems from firmware."""
    magic_dict = {
        b'PK\x03\x04': 'zip',  # ZIP file
        b'7z\xBC\xAF\x27\x1C': '7z',  # 7z archive
        b'\x1F\x8B': 'gz',  # Gzip file
        b'BZh': 'bz2',  # Bzip2 file
        b'Rar!': 'rar',  # RAR archive
        b'\x89PNG\x0D\x0A\x1A\x0A': 'png',  # PNG image
        b'GIF89a': 'gif',  # GIF image
        b'GIF87a': 'gif',  # GIF image
        b'\xFF\xD8\xFF': 'jpg',  # JPEG image
        b'\x7FELF': 'elf',  # ELF executable
    }

    extracted_files = []
    try:
        offsets = find_magic_offsets(firmware_path, magic_dict)
        if offsets:
            extracted_files.extend(extract_files(firmware_path, offsets, output_dir))
        else:
            print("No known embedded files found.")
        
        extracted_files.extend(extract_filesystem(firmware_path, output_dir))
    except Exception as e:
        print(f"Error processing firmware: {e}")
    
    return extracted_files

class EmbeddedFileExtractor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Embedded Files Extractor")
        self.setGeometry(200, 200, 800, 600)

        # Layouts
        main_layout = QVBoxLayout()
        splitter = QSplitter(Qt.Orientation.Vertical)
        top_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left layout
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_widget.setLayout(left_layout)

        # Right layout
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_widget.setLayout(right_layout)

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

        # Status Label
        

        # Terminal Output
        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setStyleSheet("background-color: black; color: white; font-family: Consolas;")
        
        
        # Arrange layouts
        left_layout.addWidget(self.load_button)
        left_layout.addWidget(self.select_dir_button)
        left_layout.addWidget(self.file_tree)
        

        right_layout.addWidget(self.file_viewer)

        top_splitter.addWidget(left_widget)
        top_splitter.addWidget(right_widget)

        splitter.addWidget(top_splitter)
        splitter.addWidget(self.terminal_output)

        main_layout.addWidget(splitter)
        self.setLayout(main_layout)

        # Instance variables
        self.extracted_dir = None

    def load_binary_file(self):
        # Select binary file
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Binary File", "", "All Files (*)")
        if file_path:
            self.terminal_output.append(f"[{datetime.datetime.now()}] {Path(file_path).name} File is Loaded")
            self.extract_firmware(file_path)

    def extract_firmware(self, firmware_path):
        output_dir = f"{firmware_path}_extracted"
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except Exception as e:
                print(f"Error creating output directory: {e}")
                return

        # Extract the firmware
        self.extracted_files = main(firmware_path, output_dir)

        # Set the extracted directory to the output directory
        self.extracted_dir = output_dir

        # Populate the file tree with the files in the extracted directory
        self.populate_file_tree()

        # Show extraction completed in terminal
        self.terminal_output.append(f"[{datetime.datetime.now()}] Extraction Completed")
        
    def select_directory(self):
        # Select a directory
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
        print(self.extracted_dir)
        b_path = Path(self.extracted_dir)
        relative_path = Path(*self.get_item_path(item))
        # Debug: Print the relative path
        print(f"Relative path: {relative_path}")
        #file_path = relative_path.resolve()
        if relative_path.parts[0] == b_path.name:
            relative_path = relative_path.relative_to(relative_path.parts[0])

        file_path = b_path / relative_path  # Join after fixing the duplication
        print(file_path) 
        # Debug: Print the file path
        print(f"Resolved file path: {file_path}")

        if os.path.isdir(file_path):
            print("Read as directory")
            return  # Ignore directories

        if not os.path.exists(file_path):
            self.file_viewer.setText(f"File not found: {file_path}")
            return

        try:
            with open(file_path, "r", errors="ignore") as file:
                content = file.read()
                print(content)
                self.file_viewer.setText(content)
        except Exception as e:
            print("Error in reading")
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
    window = EmbeddedFileExtractor()
    window.show()
    sys.exit(app.exec())