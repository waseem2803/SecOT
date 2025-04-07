import sys
import hashlib
import os
import subprocess
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, 
    QFileDialog, QComboBox, QLineEdit, QHBoxLayout, QMessageBox, 
    QCheckBox, QGroupBox
)
from PyQt6.QtCore import QProcess, pyqtSignal, Qt


#this module is used to compute and crack hashes using various algorithms and tools  uses john the ripper and hashcat and also python for simple agorthims , we can use our custom wordlist or the default wordlist and can add wordlist in the /wordlist directory

class HashCracker(QWidget):
    compute_hash_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Hash Cracker")
        self.setMinimumSize(600, 600)  # More compact size
        
        main_layout = QVBoxLayout()
        
        # Input Section
        input_group = QGroupBox("Input Options")
        input_layout = QVBoxLayout()
        
        # Text Input
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Enter text to hash or paste hash to crack here...")
        self.text_input.setMaximumHeight(100)
        input_layout.addWidget(self.text_input)
        
        # File Input Section
        file_layout = QHBoxLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Or select a file...")
        file_layout.addWidget(self.file_path_input)
        
        self.select_file_button = QPushButton("Browse")
        self.select_file_button.setFixedWidth(100)  # Compact button
        self.select_file_button.clicked.connect(self.select_file)
        file_layout.addWidget(self.select_file_button)
        input_layout.addLayout(file_layout)
        
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)
        
        # Hash Configuration Section
        config_group = QGroupBox("Hash Configuration")
        config_layout = QVBoxLayout()
        
        # Hash Algorithm
        hash_algo_layout = QHBoxLayout()
        hash_algo_layout.addWidget(QLabel("Hash Algorithm:"))
        self.hash_algorithm_dropdown = QComboBox()
        self.hash_algorithm_dropdown.addItems([
            "MD5", "SHA-1", "SHA-256", "SHA-512",
            "NTLM", "LM", "Unix Crypt", "John the Ripper"
        ])
        hash_algo_layout.addWidget(self.hash_algorithm_dropdown)
        config_layout.addLayout(hash_algo_layout)
        
        # Cracking Tool
        tool_layout = QHBoxLayout()
        tool_layout.addWidget(QLabel("Cracking Tool:"))
        self.tool_dropdown = QComboBox()
        self.tool_dropdown.addItems(["hashcat", "John the Ripper", "Built-in Python"])
        tool_layout.addWidget(self.tool_dropdown)
        config_layout.addLayout(tool_layout)
        
        # Options
        options_layout = QHBoxLayout()
        self.mask_checkbox = QCheckBox("Mask Attack")
        self.bruteforce_checkbox = QCheckBox("Bruteforce")
        options_layout.addWidget(self.mask_checkbox)
        options_layout.addWidget(self.bruteforce_checkbox)
        options_layout.addStretch()
        config_layout.addLayout(options_layout)
        
        config_group.setLayout(config_layout)
        main_layout.addWidget(config_group)
        
        # Wordlist Section
        wordlist_group = QGroupBox("Wordlist Options")
        wordlist_layout = QHBoxLayout()
        self.wordlist_input = QLineEdit()
        self.wordlist_input.setPlaceholderText("Select wordlist (optional)")
        wordlist_layout.addWidget(self.wordlist_input)
        
        self.wordlist_button = QPushButton("Browse")
        self.wordlist_button.setFixedWidth(100)  # Compact button
        self.wordlist_button.clicked.connect(self.choose_wordlist)
        wordlist_layout.addWidget(self.wordlist_button)
        wordlist_group.setLayout(wordlist_layout)
        main_layout.addWidget(wordlist_group)
        
        # Action Buttons
        button_layout = QHBoxLayout()
        
        self.compute_button = QPushButton("Compute Hash")
        self.compute_button.setFixedWidth(120)  # Compact button
        self.compute_button.clicked.connect(self.compute_hash)
        button_layout.addWidget(self.compute_button)
        
        self.crack_button = QPushButton("Crack Hash")
        self.crack_button.setFixedWidth(120)  # Compact button
        self.crack_button.clicked.connect(self.crack_hash)
        button_layout.addWidget(self.crack_button)
        
        button_layout.addStretch()
        main_layout.addLayout(button_layout)
        
        # Output Section
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        output_layout.addWidget(self.output_text)
        output_group.setLayout(output_layout)
        main_layout.addWidget(output_group)
        
        self.setLayout(main_layout)
        
        # Initialize variables
        self.file_path = None
        self.wordlist_path = None
        
        # Process for running external tools
        self.process = QProcess()
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.finished.connect(self.process_finished)

    def set_file_path(self, file_path):
        """Set file path from external source"""
        if not isinstance(file_path, str):
            return
            
        self.file_path = file_path
        self.file_path_input.setText(file_path)
        self.text_input.clear()  # Clear text input when file is selected
        
        # Auto-compute if small file
        try:
            if os.path.exists(file_path) and os.path.getsize(file_path) < 10 * 1024 * 1024:
                self.compute_hash()
        except Exception as e:
            self.output_text.append(f"Error: {str(e)}")

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.set_file_path(file_path)

    def choose_wordlist(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist")
        if file_path:
            self.wordlist_path = file_path
            self.wordlist_input.setText(file_path)

    def compute_hash(self):
        """Compute hash from either text or file input"""
        input_text = self.text_input.toPlainText().strip()
        
        if input_text:
            # Compute hash from text input
            try:
                algo = self.hash_algorithm_dropdown.currentText().lower().replace("-", "")
                if algo == "john the ripper":
                    self.output_text.append("John the Ripper requires file input")
                    return
                    
                hasher = getattr(hashlib, algo)()
                hasher.update(input_text.encode())
                computed_hash = hasher.hexdigest()
                self.output_text.append(f"Computed {algo.upper()} hash of text input:\n{computed_hash}")
            except Exception as e:
                self.output_text.append(f"Error computing hash: {str(e)}")
        elif self.file_path:
            # Compute hash from file
            try:
                algo = self.hash_algorithm_dropdown.currentText().lower().replace("-", "")
                if algo == "john the ripper":
                    self.output_text.append("Please use John the Ripper directly on the file.")
                    return
                    
                hasher = getattr(hashlib, algo)()
                with open(self.file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hasher.update(chunk)
                        
                computed_hash = hasher.hexdigest()
                self.output_text.append(f"Computed {algo.upper()} hash of file:\n{computed_hash}")
            except Exception as e:
                self.output_text.append(f"Error computing hash: {str(e)}")
        else:
            QMessageBox.warning(self, "Warning", "No input provided - enter text or select a file")

    def crack_hash(self):
        target_hash = self.hash_input.text().strip()
        algo = self.hash_algorithm_dropdown.currentText()
        tool = self.tool_dropdown.currentText()
        
        if not target_hash and not self.file_path:
            QMessageBox.warning(self, "Warning", "Please provide a hash or select a file first.")
            return
        
        if tool == "John the Ripper" and not self.file_path:
            QMessageBox.warning(self, "Warning", "John the Ripper requires a file input.")
            return
        
        self.output_text.clear()
        
        if tool == "Built-in Python":
            self.crack_with_python(target_hash, algo)
        elif tool == "hashcat":
            self.run_hashcat(target_hash, algo)
        elif tool == "John the Ripper":
            self.run_john()

    def crack_with_python(self, target_hash, algo):
        if not self.wordlist_path:
            QMessageBox.warning(self, "Warning", "Please select a wordlist first.")
            return
        
        try:
            algo = algo.lower().replace("-", "")
            hasher = getattr(hashlib, algo)
            
            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as wordlist:
                for word in wordlist:
                    word = word.strip()
                    if hasher(word.encode()).hexdigest() == target_hash:
                        self.output_text.append(f"Password found: {word}")
                        return
                
            self.output_text.append("Password not found in wordlist.")
        except Exception as e:
            self.output_text.append(f"Error: {str(e)}")

    def run_hashcat(self, target_hash, algo):
        if not self.wordlist_path:
            QMessageBox.warning(self, "Warning", "Please select a wordlist first.")
            return
        
        hash_type = {
            "MD5": 0,
            "SHA-1": 100,
            "SHA-256": 1400,
            "SHA-512": 1700,
            "NTLM": 1000,
            "LM": 3000
        }.get(algo, 0)
        
        if hash_type == 0:
            QMessageBox.warning(self, "Warning", f"Unsupported hash type {algo} for hashcat")
            return
        
        cmd = [
            "hashcat",
            "-m", str(hash_type),
            "-a", "0",
            target_hash,
            self.wordlist_path
        ]
        
        self.output_text.append(f"Running hashcat: {' '.join(cmd)}")
        self.process.start("hashcat", cmd)

    def run_john(self):
        if not self.file_path:
            QMessageBox.warning(self, "Warning", "Please select a file first.")
            return
        
        cmd = ["john", self.file_path]
        
        if self.wordlist_path:
            cmd.extend(["--wordlist", self.wordlist_path])
        
        if self.mask_checkbox.isChecked():
            cmd.append("--mask")
        
        self.output_text.append(f"Running John the Ripper: {' '.join(cmd)}")
        self.process.start("john", cmd)

    def handle_stdout(self):
        data = self.process.readAllStandardOutput()
        stdout = bytes(data).decode("utf8")
        self.output_text.append(stdout)

    def handle_stderr(self):
        data = self.process.readAllStandardError()
        stderr = bytes(data).decode("utf8")
        self.output_text.append(f"Error: {stderr}")

    def process_finished(self, exit_code, exit_status):
        self.output_text.append(f"\nProcess finished with exit code {exit_code}")
        if exit_code == 0:
            self.output_text.append("Cracking completed successfully!")
            
            if self.tool_dropdown.currentText() == "John the Ripper":
                self.show_john_results()

    def show_john_results(self):
        if not self.file_path:
            return
        
        try:
            result = subprocess.run(
                ["john", "--show", self.file_path],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                self.output_text.append("\nJohn the Ripper results:")
                self.output_text.append(result.stdout)
            else:
                self.output_text.append("\nNo passwords recovered by John the Ripper")
        except Exception as e:
            self.output_text.append(f"Error getting John results: {str(e)}")

if __name__ == "__main__":
    from PyQt6.QtWidgets import QApplication
    app = QApplication(sys.argv)
    widget = HashCracker()
    widget.show()
    sys.exit(app.exec())