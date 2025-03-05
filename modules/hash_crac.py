import sys
import hashlib
import itertools
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QFileDialog, QComboBox, QLineEdit, QHBoxLayout
)

class HashCracker(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Hash Cracker")
        self.setGeometry(100, 100, 600, 400)
        
        layout = QVBoxLayout()
        
        self.file_label = QLabel("Select File:")
        layout.addWidget(self.file_label)
        
        self.select_file_button = QPushButton("Choose File")
        self.select_file_button.clicked.connect(self.select_file)
        layout.addWidget(self.select_file_button)
        
        self.hash_algorithm_label = QLabel("Select Hash Algorithm:")
        layout.addWidget(self.hash_algorithm_label)
        
        self.hash_algorithm_dropdown = QComboBox()
        self.hash_algorithm_dropdown.addItems(["MD5", "SHA-1", "SHA-256"])
        layout.addWidget(self.hash_algorithm_dropdown)
        
        self.hash_label = QLabel("Computed/Provided Hash:")
        layout.addWidget(self.hash_label)
        
        self.hash_input = QLineEdit()
        layout.addWidget(self.hash_input)
        
        self.hash_output = QTextEdit()
        self.hash_output.setReadOnly(True)
        layout.addWidget(self.hash_output)
        
        self.wordlist_button = QPushButton("Choose Wordlist")
        self.wordlist_button.clicked.connect(self.choose_wordlist)
        layout.addWidget(self.wordlist_button)
        
        self.crack_button = QPushButton("Crack Hash")
        self.crack_button.clicked.connect(self.crack_hash)
        layout.addWidget(self.crack_button)
        
        self.result_label = QLabel("Cracking Result:")
        layout.addWidget(self.result_label)
        
        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)
        layout.addWidget(self.result_output)
        
        self.setLayout(layout)
        self.file_path = None
        self.wordlist_path = None
    
    def select_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path = file_path
            self.compute_hash()
    
    def compute_hash(self):
        if not self.file_path:
            return
        algo = self.hash_algorithm_dropdown.currentText().lower().replace("-", "")
        hasher = getattr(hashlib, algo)()
        try:
            with open(self.file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            self.hash_output.setText(hasher.hexdigest())
            self.hash_input.setText(hasher.hexdigest())
        except Exception as e:
            self.hash_output.setText(f"Error: {e}")
    
    def choose_wordlist(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Select Wordlist")
        if file_path:
            self.wordlist_path = file_path
    
    def crack_hash(self):
        target_hash = self.hash_input.text().strip() or self.hash_output.toPlainText().strip()
        if not self.wordlist_path or not target_hash:
            self.result_output.setText("Please select a wordlist and provide a hash first.")
            return
        
        algo = self.hash_algorithm_dropdown.currentText().lower().replace("-", "")
        hasher = getattr(hashlib, algo)
        
        try:
            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as wordlist:
                for word in wordlist:
                    word = word.strip()
                    if hasher(word.encode()).hexdigest() == target_hash:
                        self.result_output.setText(f"Password Found: {word}")
                        return
            self.result_output.setText("Password not found in wordlist.")
        except Exception as e:
            self.result_output.setText(f"Error: {e}")
        
if __name__ == "__main__":
    from PyQt6.QtWidgets import QApplication
    app = QApplication(sys.argv)
    widget = HashCrackerWidget()
    widget.show()
    sys.exit(app.exec())
