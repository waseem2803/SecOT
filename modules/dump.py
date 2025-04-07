import sys
import subprocess
from PyQt6.QtWidgets import (
    QApplication, QVBoxLayout, QLabel, QComboBox, QPushButton, 
    QWidget, QMessageBox, QTextEdit, QGroupBox, QHBoxLayout,
    QFileDialog, QLineEdit, QTabWidget ,QCheckBox ,QProgressBar
)
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QFont


#this module is used to dump firmware from IoT devices using different methods , one dumps the firmware using a debugger interface (like JTAG or SWD) and the other uses flashrom to read the firmware from SPI or NAND flash chips.
# uart dumping is what we are gonna show in review

class FirmwareDumpThread(QThread):
    log_signal = pyqtSignal(str)
    result_signal = pyqtSignal(bool, str)
    progress_signal = pyqtSignal(int)

    def __init__(self, mode, params, parent=None):
        super().__init__(parent)
        self.mode = mode  # 'debugger' or 'flashrom'
        self.params = params
        self.running = True

    def run(self):
        if self.mode == "debugger":
            self.run_debugger_dump()
        elif self.mode == "flashrom":
            self.run_flashrom_dump()

    def run_debugger_dump(self):
        """Dump firmware using debug interfaces (JTAG/SWD/UART)"""
        board = self.params['board']
        interface = self.params['interface']
        extractor = self.params['extractor']

        commands = {
            "BCM2835 (Raspberry Pi 1)": {
                "UART": "openocd -f bcm2835_uart.cfg -c 'dump_image firmware.bin 0x00000000 0x100000'",
                "JTAG": "openocd -f bcm2835_jtag.cfg -c 'dump_image firmware.bin 0x00000000 0x100000'",
                "SWD": "openocd -f bcm2835_swd.cfg -c 'dump_image firmware.bin 0x00000000 0x100000'"
            },
            # ... (other board definitions remain the same)
        }

        try:
            if extractor == "PyOCD" and interface not in ["SWD", "PyOCD"]:
                self.result_signal.emit(False, "PyOCD is not compatible with selected interface.")
                return

            command = commands[board][interface]
            self.execute_command(command)

        except KeyError:
            self.result_signal.emit(False, f"Configuration for {board} with {interface} not found.")
        except Exception as e:
            self.result_signal.emit(False, f"An error occurred: {str(e)}")

    def run_flashrom_dump(self):
        """Dump firmware using flashrom"""
        programmer = self.params['programmer']
        flash_chip = self.params['flash_chip']
        output_file = self.params['output_file']
        verify = self.params['verify']
        force = self.params['force']

        try:
            # Build flashrom command
            cmd = ["flashrom", "-p", programmer, "-r", output_file]
            
            if flash_chip:
                cmd.extend(["-c", flash_chip])
            if verify:
                cmd.append("-V")
            if force:
                cmd.append("--force")
            
            self.log_signal.emit(f"Executing: {' '.join(cmd)}")
            self.execute_command(cmd)

        except Exception as e:
            self.result_signal.emit(False, f"Flashrom error: {str(e)}")

    def execute_command(self, command):
        """Execute a system command and handle output"""
        process = subprocess.Popen(
            command if isinstance(command, list) else command,
            shell=not isinstance(command, list),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        while self.running:
            line = process.stdout.readline()
            if not line:
                break
            self.log_signal.emit(line.strip())
            # Simple progress detection (can be improved)
            if "%" in line:
                try:
                    progress = int(line.split("%")[0].split()[-1])
                    self.progress_signal.emit(progress)
                except:
                    pass

        process.wait()
        if not self.running:
            self.result_signal.emit(False, "Operation cancelled by user")
        elif process.returncode == 0:
            self.result_signal.emit(True, "Operation completed successfully")
        else:
            self.result_signal.emit(False, f"Operation failed with code {process.returncode}")

    def stop(self):
        """Stop the running operation"""
        self.running = False
        self.wait()

class DumpFirmware(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.thread = None

    def init_ui(self):
        self.setWindowTitle("IoT Firmware Extraction Tool")
        self.setGeometry(100, 100, 800, 600)
        self.setFont(QFont('Arial', 10))

        # Main layout with tabs
        layout = QVBoxLayout()
        self.tabs = QTabWidget()
        
        # Debugger Tab
        self.setup_debugger_tab()
        
        # Flashrom Tab
        self.setup_flashrom_tab()
        
        # Add tabs
        self.tabs.addTab(self.debugger_tab, "Debugger Interface")
        self.tabs.addTab(self.flashrom_tab, "Flashrom (SPI/NAND)")
        
        # Common elements
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setFont(QFont('Courier New', 9))
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        
        # Stop button
        self.stop_button = QPushButton("Stop Operation")
        self.stop_button.setStyleSheet("background-color: #f44336; color: white;")
        self.stop_button.clicked.connect(self.stop_operation)
        self.stop_button.setEnabled(False)
        
        # Add to layout
        layout.addWidget(self.tabs)
        layout.addWidget(QLabel("Operation Log:"))
        layout.addWidget(self.log_area)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.stop_button)
        
        self.setLayout(layout)

    def setup_debugger_tab(self):
        """Setup the debugger interface tab"""
        self.debugger_tab = QWidget()
        layout = QVBoxLayout()
        
        # Board selection
        board_group = QGroupBox("Target Board")
        board_layout = QHBoxLayout()
        self.board_combo = QComboBox()
        self.board_combo.addItems([
            "BCM2835 (Raspberry Pi 1)",
            "BCM2836 (Raspberry Pi 2)",
            "ESP32",
            "STM32F4",
            "Generic ARM Cortex-M4",
            "Generic ARM Cortex-M3"
        ])
        board_layout.addWidget(QLabel("Board:"))
        board_layout.addWidget(self.board_combo)
        board_group.setLayout(board_layout)
        
        # Interface selection
        interface_group = QGroupBox("Debug Interface")
        interface_layout = QHBoxLayout()
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(["UART", "JTAG", "SWD"])
        interface_layout.addWidget(QLabel("Interface:"))
        interface_layout.addWidget(self.interface_combo)
        interface_group.setLayout(interface_layout)
        
        # Extractor selection
        extractor_group = QGroupBox("Extraction Tool")
        extractor_layout = QHBoxLayout()
        self.extractor_combo = QComboBox()
        self.extractor_combo.addItems(["OpenOCD", "PyOCD"])
        extractor_layout.addWidget(QLabel("Tool:"))
        extractor_layout.addWidget(self.extractor_combo)
        extractor_group.setLayout(extractor_layout)
        
        # Start button
        self.debugger_button = QPushButton("Dump via Debug Interface")
        self.debugger_button.setStyleSheet("background-color: #4CAF50; color: white;")
        self.debugger_button.clicked.connect(self.start_debugger_dump)
        
        # Add to layout
        layout.addWidget(board_group)
        layout.addWidget(interface_group)
        layout.addWidget(extractor_group)
        layout.addWidget(self.debugger_button)
        layout.addStretch()
        
        self.debugger_tab.setLayout(layout)

    def setup_flashrom_tab(self):
        """Setup the flashrom interface tab"""
        self.flashrom_tab = QWidget()
        layout = QVBoxLayout()
        
        # Programmer selection
        programmer_group = QGroupBox("Flash Programmer")
        programmer_layout = QHBoxLayout()
        self.programmer_combo = QComboBox()
        self.programmer_combo.addItems([
            "linux_spi:dev=/dev/spidevX.Y",
            "ch341a_spi",  # Common cheap USB SPI programmer
            "dediprog",     # Dediprog programmer
            "raiden_debug", # Raiden Debugger
            "pony_spi",     # PonyProg compatible
            "buspirate_spi" # Bus Pirate
        ])
        self.programmer_combo.setEditable(True)
        programmer_layout.addWidget(QLabel("Programmer:"))
        programmer_layout.addWidget(self.programmer_combo)
        programmer_group.setLayout(programmer_layout)
        
        # Flash chip selection
        chip_group = QGroupBox("Flash Chip (Optional)")
        chip_layout = QHBoxLayout()
        self.chip_combo = QComboBox()
        self.chip_combo.addItems([
            "",
            "MX25L1605",  # Common 16Mbit SPI NOR
            "W25Q128",    # Winbond 128Mbit
            "S25FL128S",  # Spansion 128Mbit
            "GD25Q64",    # GigaDevice 64Mbit
            "EN25QH32"    # Eon 32Mbit
        ])
        self.chip_combo.setEditable(True)
        chip_layout.addWidget(QLabel("Chip:"))
        chip_layout.addWidget(self.chip_combo)
        chip_group.setLayout(chip_layout)
        
        # Output file selection
        file_group = QGroupBox("Output File")
        file_layout = QHBoxLayout()
        self.file_edit = QLineEdit()
        self.file_edit.setPlaceholderText("Select output file...")
        self.file_button = QPushButton("Browse...")
        self.file_button.clicked.connect(self.select_output_file)
        file_layout.addWidget(self.file_edit)
        file_layout.addWidget(self.file_button)
        file_group.setLayout(file_layout)
        
        # Options
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()
        self.verify_check = QCheckBox("Verify after read")
        self.verify_check.setChecked(True)
        self.force_check = QCheckBox("Force operation (dangerous)")
        options_layout.addWidget(self.verify_check)
        options_layout.addWidget(self.force_check)
        options_group.setLayout(options_layout)
        
        # Start button
        self.flashrom_button = QPushButton("Dump via Flashrom")
        self.flashrom_button.setStyleSheet("background-color: #2196F3; color: white;")
        self.flashrom_button.clicked.connect(self.start_flashrom_dump)
        
        # Add to layout
        layout.addWidget(programmer_group)
        layout.addWidget(chip_group)
        layout.addWidget(file_group)
        layout.addWidget(options_group)
        layout.addWidget(self.flashrom_button)
        layout.addStretch()
        
        self.flashrom_tab.setLayout(layout)

    def select_output_file(self):
        """Select output file for flashrom dump"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Firmware Dump", "", "Binary Files (*.bin);;All Files (*)"
        )
        if filename:
            self.file_edit.setText(filename)

    def start_debugger_dump(self):
        """Start debugger-based firmware dump"""
        params = {
            'board': self.board_combo.currentText(),
            'interface': self.interface_combo.currentText(),
            'extractor': self.extractor_combo.currentText()
        }
        self.start_operation("debugger", params)

    def start_flashrom_dump(self):
        """Start flashrom-based firmware dump"""
        if not self.file_edit.text():
            QMessageBox.warning(self, "Error", "Please select an output file")
            return
            
        params = {
            'programmer': self.programmer_combo.currentText(),
            'flash_chip': self.chip_combo.currentText() if self.chip_combo.currentText() else None,
            'output_file': self.file_edit.text(),
            'verify': self.verify_check.isChecked(),
            'force': self.force_check.isChecked()
        }
        self.start_operation("flashrom", params)

    def start_operation(self, mode, params):
        """Start a dump operation"""
        self.log_area.clear()
        self.progress_bar.setValue(0)
        self.stop_button.setEnabled(True)
        
        # Disable relevant buttons
        if mode == "debugger":
            self.debugger_button.setEnabled(False)
        else:
            self.flashrom_button.setEnabled(False)
        
        self.thread = FirmwareDumpThread(mode, params)
        self.thread.log_signal.connect(self.log_area.append)
        self.thread.result_signal.connect(self.operation_finished)
        self.thread.progress_signal.connect(self.progress_bar.setValue)
        self.thread.start()

    def stop_operation(self):
        """Stop the current operation"""
        if self.thread and self.thread.isRunning():
            self.thread.stop()
            self.stop_button.setEnabled(False)

    def operation_finished(self, success, message):
        """Handle operation completion"""
        self.stop_button.setEnabled(False)
        self.debugger_button.setEnabled(True)
        self.flashrom_button.setEnabled(True)
        
        if success:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.critical(self, "Error", message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DumpFirmware()
    window.show()
    sys.exit(app.exec())