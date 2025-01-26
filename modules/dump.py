import sys
from PyQt6.QtWidgets import (
    QApplication, QVBoxLayout, QLabel, QComboBox, QPushButton, QWidget, QMessageBox, QTextEdit
)
from PyQt6.QtCore import QThread, pyqtSignal
import subprocess


class FirmwareDumpThread(QThread):
    log_signal = pyqtSignal(str)
    result_signal = pyqtSignal(bool, str)

    def __init__(self, board, interface, extractor, parent=None):
        super().__init__(parent)
        self.board = board
        self.interface = interface
        self.extractor = extractor

    def run(self):
        commands = {
            "BCM2835 (Raspberry Pi 1)": {
                "UART": "openocd -f bcm2835_uart.cfg -c 'dump_image firmware.bin 0x00000000 0x100000'",
                "JTAG": "openocd -f bcm2835_jtag.cfg -c 'dump_image firmware.bin 0x00000000 0x100000'",
                "SWD": "openocd -f bcm2835_swd.cfg -c 'dump_image firmware.bin 0x00000000 0x100000'"
            },
            "BCM2836 (Raspberry Pi 2)": {
                "UART": "openocd -f bcm2836_uart.cfg -c 'dump_image firmware.bin 0x00000000 0x100000'",
                "JTAG": "openocd -f bcm2836_jtag.cfg -c 'dump_image firmware.bin 0x00000000 0x100000'",
                "SWD": "openocd -f bcm2836_swd.cfg -c 'dump_image firmware.bin 0x00000000 0x100000'"
            },
            "ESP32": {
                "UART": "python -mesptool --port com3 read_flash 0x00000 0x400000 firmware.bin",
                "JTAG": "openocd -f esp32_jtag.cfg -c 'dump_image firmware.bin 0x00000000 0x400000'",
                "SWD": "openocd -f esp32_swd.cfg -c 'dump_image firmware.bin 0x00000000 0x400000'"
            },
            "STM32F4": {
                "UART": "openocd -f stm32f4_uart.cfg -c 'dump_image firmware.bin 0x08000000 0x100000'",
                "JTAG": "openocd -f stm32f4_jtag.cfg -c 'dump_image firmware.bin 0x08000000 0x100000'",
                "SWD": "openocd -f stm32f4_swd.cfg -c 'dump_image firmware.bin 0x08000000 0x100000'"
            },
            "Generic ARM Cortex-M4": {
                "UART": "openocd -f cortex_m4_uart.cfg -c 'dump_image firmware.bin 0x08000000 0x100000'",
                "JTAG": "openocd -f cortex_m4_jtag.cfg -c 'dump_image firmware.bin 0x08000000 0x100000'",
                "SWD": "openocd -f cortex_m4_swd.cfg -c 'dump_image firmware.bin 0x08000000 0x100000'",
                "PyOCD": "pyocd cmd -c 'read memory 0x08000000 0x100000 firmware.bin'"
            },
            "Generic ARM Cortex-M3": {
                "UART": "openocd -f cortex_m3_uart.cfg -c 'dump_image firmware.bin 0x08000000 0x100000'",
                "JTAG": "openocd -f cortex_m3_jtag.cfg -c 'dump_image firmware.bin 0x08000000 0x100000'",
                "SWD": "openocd -f cortex_m3_swd.cfg -c 'dump_image firmware.bin 0x08000000 0x100000'",
                "PyOCD": "pyocd cmd -c 'read memory 0x08000000 0x100000 firmware.bin'"
            }
        }

        try:
            if self.extractor == "PyOCD" and self.interface not in ["SWD", "PyOCD"]:
                self.result_signal.emit(False, "PyOCD is not compatible with selected interface.")
                return

            command = commands[self.board][self.interface]

            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            for line in process.stdout:
                self.log_signal.emit(line.strip())

            process.wait()

            if process.returncode == 0:
                self.result_signal.emit(True, "Firmware dumped successfully.")
            else:
                self.result_signal.emit(False, "Firmware dump failed.")

        except KeyError:
            self.result_signal.emit(False, f"Configuration for {self.board} with {self.interface} not found.")
        except Exception as e:
            self.result_signal.emit(False, f"An error occurred: {str(e)}")


class DumpFirmware(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Board Debugger Selector")
        self.setGeometry(100, 100, 600, 400)

        # Layout
        layout = QVBoxLayout()

        # Board selection
        self.board_label = QLabel("Select a Board:")
        self.board_combo = QComboBox()
        self.board_combo.setFixedWidth(300)
        self.board_combo.addItems([
            "BCM2835 (Raspberry Pi 1)",
            "BCM2836 (Raspberry Pi 2)",
            "ESP32",
            "STM32F4",
            "Generic ARM Cortex-M4",
            "Generic ARM Cortex-M3"
        ])

        # Interface selection
        self.interface_label = QLabel("Select an Interface:")
        self.interface_combo = QComboBox()
        self.interface_combo.setFixedWidth(300)
        self.interface_combo.addItems(["UART", "JTAG", "SWD"])

        # Extractor selection
        self.extractor_label = QLabel("Select an Extractor:")
        self.extractor_combo = QComboBox()
        self.extractor_combo.setFixedWidth(300)
        self.extractor_combo.addItems(["OpenOCD", "PyOCD"])

        # Log area
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)

        # Submit button
        self.submit_button = QPushButton("Dump Firmware")
        self.submit_button.setFixedWidth(300)
        self.submit_button.clicked.connect(self.submit_selection)

        # Add widgets to layout
        layout.addWidget(self.board_label)
        layout.addWidget(self.board_combo)
        layout.addWidget(self.interface_label)
        layout.addWidget(self.interface_combo)
        layout.addWidget(self.extractor_label)
        layout.addWidget(self.extractor_combo)
        layout.addWidget(self.submit_button)
        layout.addWidget(QLabel("Logs:"))
        layout.addWidget(self.log_area)

        self.setLayout(layout)

    def submit_selection(self):
        board = self.board_combo.currentText()
        interface = self.interface_combo.currentText()
        extractor = self.extractor_combo.currentText()

        self.log_area.clear()

        self.thread = FirmwareDumpThread(board, interface, extractor)
        self.thread.log_signal.connect(self.log_area.append)
        self.thread.result_signal.connect(self.handle_result)
        self.thread.start()

    def handle_result(self, success, message):
        if success:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.critical(self, "Error", message)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    selector = DumpFirmware()
    selector.show()
    sys.exit(app.exec())
