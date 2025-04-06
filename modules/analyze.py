import os
import subprocess
import pefile
import lief
import magic
import re
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QTextEdit, QPushButton, QTreeWidget, QTreeWidgetItem,
    QLabel, QSplitter, QTableWidget, QTableWidgetItem,
    QHeaderView, QComboBox, QProgressBar, QSizePolicy,
    QFileDialog, QMessageBox, QFrame
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QTextCursor

class AnalysisThread(QThread):
    update_signal = pyqtSignal(dict)
    progress_signal = pyqtSignal(int)

    def __init__(self, analysis_func, file_path):
        super().__init__()
        self.analysis_func = analysis_func
        self.file_path = file_path

    def run(self):
        try:
            result = self.analysis_func(self.file_path)
            self.update_signal.emit(result)
        except Exception as e:
            self.update_signal.emit({"Error": str(e)})
        finally:
            self.progress_signal.emit(100)

class BinaryAnalyzer(QWidget):
    analysis_complete = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_file = None
        self.file_info = {}
        self.setup_ui()
        self.setup_styles()

    def setup_ui(self):
        """Initialize the widget UI with compact controls"""
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(2, 2, 2, 2)
        main_layout.setSpacing(4)

        # Compact control panel
        control_frame = QFrame()
        control_frame.setFrameShape(QFrame.Shape.StyledPanel)
        control_layout = QHBoxLayout(control_frame)
        control_layout.setContentsMargins(4, 4, 4, 4)
        control_layout.setSpacing(6)

        # Load button with icon
        self.load_button = QPushButton("Load")
        self.load_button.setFixedWidth(60)
        self.load_button.clicked.connect(self.load_binary)
        control_layout.addWidget(self.load_button)

        # File type combo
        self.file_type_combo = QComboBox()
        self.file_type_combo.setFixedWidth(100)
        self.file_type_combo.addItems(["Auto", "PE", "ELF", "Mach-O", "Raw"])
        control_layout.addWidget(QLabel("Type:"))
        control_layout.addWidget(self.file_type_combo)

        # Status label with elide
        self.status_label = QLabel("No file loaded")
        self.status_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.status_label.setMinimumWidth(100)
        control_layout.addWidget(self.status_label)
        
        # Compact progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setFixedWidth(80)
        self.progress_bar.setVisible(False)
        control_layout.addWidget(self.progress_bar)
        
        main_layout.addWidget(control_frame)

        # Main content area
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(2)

        # Analysis functions panel (compact)
        self.analysis_funcs = QTreeWidget()
        self.analysis_funcs.setHeaderHidden(True)
        self.analysis_funcs.setMinimumWidth(150)
        self.analysis_funcs.setMaximumWidth(180)
        self.setup_analysis_functions()
        splitter.addWidget(self.analysis_funcs)

        # Results panel
        self.results_tabs = QTabWidget()
        self.results_tabs.setDocumentMode(True)
        self.setup_results_tabs()
        splitter.addWidget(self.results_tabs)

        splitter.setSizes([160, 640])
        main_layout.addWidget(splitter)

    def setup_styles(self):
        """Apply compact styling"""
        self.setStyleSheet("""
            QWidget {
                background-color: #f5f5f5;
                font-size: 11px;
            }
            QFrame {
                background-color: #e0e0e0;
                border-radius: 3px;
            }
            QPushButton {
                background-color: #e0e0e0;
                border: 1px solid #aaa;
                padding: 2px 5px;
                border-radius: 3px;
                min-width: 50px;
            }
            QPushButton:hover {
                background-color: #d0d0d0;
            }
            QTreeWidget {
                border: 1px solid #ccc;
                background-color: white;
                font-size: 10px;
            }
            QTabWidget::pane {
                border: 1px solid #ccc;
                margin: 0px;
            }
            QTabBar::tab {
                padding: 3px 6px;
                font-size: 10px;
            }
            QTableWidget {
                border: 1px solid #ccc;
                background-color: white;
                font-family: 'Courier New';
                font-size: 10px;
            }
            QTextEdit {
                border: 1px solid #ccc;
                background-color: white;
                font-family: 'Courier New';
                font-size: 10px;
            }
            QProgressBar {
                border: 1px solid #aaa;
                border-radius: 3px;
                text-align: center;
                padding: 1px;
                font-size: 10px;
                height: 16px;
            }
            QProgressBar::chunk {
                background-color: #5b9bd5;
            }
            QComboBox {
                padding: 1px;
            }
        """)

    def setup_results_tabs(self):
        """Set up compact results tabs"""
        # File info tab
        self.file_info_table = QTableWidget()
        self.file_info_table.setColumnCount(2)
        self.file_info_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.file_info_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.results_tabs.addTab(self.file_info_table, "Info")

        # Hex view tab
        self.hex_view = QTextEdit()
        self.hex_view.setFont(QFont("Courier New", 9))
        self.hex_view.setReadOnly(True)
        self.results_tabs.addTab(self.hex_view, "Hex")

        # Strings tab
        self.strings_table = QTableWidget()
        self.strings_table.setColumnCount(2)
        self.strings_table.setHorizontalHeaderLabels(["Offset", "String"])
        self.strings_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.results_tabs.addTab(self.strings_table, "Strings")

        # Memory map tab
        self.memory_map_table = QTableWidget()
        self.memory_map_table.setColumnCount(4)
        self.memory_map_table.setHorizontalHeaderLabels(["Name", "VA", "Size", "Flags"])
        self.memory_map_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.results_tabs.addTab(self.memory_map_table, "Memory")

        # Analysis output tab
        self.analysis_output = QTextEdit()
        self.analysis_output.setFont(QFont("Courier New", 9))
        self.analysis_output.setReadOnly(True)
        self.results_tabs.addTab(self.analysis_output, "Details")

    def setup_analysis_functions(self):
        """Compact analysis functions tree"""
        root = QTreeWidgetItem(self.analysis_funcs, ["Analysis"])
        
        # Basic analysis
        basic_item = QTreeWidgetItem(root, ["Basic"])
        QTreeWidgetItem(basic_item, ["File Info"])
        QTreeWidgetItem(basic_item, ["Strings"])
        QTreeWidgetItem(basic_item, ["Hex"])
        
        # PE Analysis
        pe_item = QTreeWidgetItem(root, ["PE"])
        QTreeWidgetItem(pe_item, ["Headers"])
        QTreeWidgetItem(pe_item, ["Sections"])
        QTreeWidgetItem(pe_item, ["Memory"])
        
        # ELF Analysis
        elf_item = QTreeWidgetItem(root, ["ELF"])
        QTreeWidgetItem(elf_item, ["Headers"])
        QTreeWidgetItem(elf_item, ["Memory"])
        
        self.analysis_funcs.expandAll()
        self.analysis_funcs.itemClicked.connect(self.run_analysis)

    def load_binary(self, file_path=None):
        """Compact file loading"""
        if not file_path:
            file_path, _ = QFileDialog.getOpenFileName(
                self, 
                "Select Binary", 
                "", 
                "Binaries (*.exe *.dll *.elf *.so *.bin *.sys *.o);;All Files (*)"
            )
            if not file_path:
                return

        self.current_file = file_path
        short_name = os.path.basename(file_path)
        if len(short_name) > 20:
            short_name = f"{short_name[:15]}...{short_name[-5:]}"
        self.status_label.setText(short_name)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        self.analysis_thread = AnalysisThread(self.analyze_file, file_path)
        self.analysis_thread.update_signal.connect(self.display_file_info)
        self.analysis_thread.progress_signal.connect(self.update_progress)
        self.analysis_thread.start()

    def analyze_file(self, file_path):
        """Collect comprehensive file information"""
        file_info = {}
        file_info['Path'] = file_path
        file_info['Name'] = os.path.basename(file_path)
        file_info['Size'] = f"{os.path.getsize(file_path):,} bytes"
        
        # File type detection
        mime = magic.Magic()
        file_info['Type'] = mime.from_file(file_path)
        
        # Try to parse with PE and ELF parsers
        try:
            pe = pefile.PE(file_path)
            file_info['Format'] = "PE (Portable Executable)"
            file_info['Architecture'] = pe.FILE_HEADER.Machine
            file_info['Entry Point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            pe.close()
        except:
            try:
                binary = lief.parse(file_path)
                if binary and binary.format == lief.EXE_FORMATS.ELF:
                    file_info['Format'] = "ELF (Executable and Linkable Format)"
                    file_info['Architecture'] = binary.header.machine_type.name
                    file_info['Entry Point'] = hex(binary.entrypoint)
            except:
                file_info['Format'] = "Unknown/Not PE or ELF"
        
        return file_info

    def display_file_info(self, file_info):
        """Display file information in the table"""
        self.file_info = file_info
        self.file_info_table.setRowCount(len(file_info))
        
        for row, (key, value) in enumerate(file_info.items()):
            self.file_info_table.setItem(row, 0, QTableWidgetItem(key))
            self.file_info_table.setItem(row, 1, QTableWidgetItem(str(value)))
        
        self.progress_bar.setVisible(False)
        self.analysis_complete.emit(file_info)
        
        # Auto-select appropriate analysis based on file type
        if "PE" in file_info.get('Format', ''):
            self.file_type_combo.setCurrentText("PE")
        elif "ELF" in file_info.get('Format', ''):
            self.file_type_combo.setCurrentText("ELF")

    def update_progress(self, value):
        """Update progress bar"""
        self.progress_bar.setValue(value)
        if value == 100:
            self.progress_bar.setVisible(False)

    def run_analysis(self, item, column):
        """Run the selected analysis function"""
        if not self.current_file or item.childCount() > 0:
            return  # Skip category items

        analysis_type = item.text(column)
        self.status_label.setText(f"Running {analysis_type}...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        if analysis_type == "File Info":
            self.display_file_info(self.file_info)
            self.progress_bar.setVisible(False)
        elif analysis_type == "Strings":
            self.run_strings_analysis()
        elif analysis_type == "Hex":
            self.run_hex_dump()
        elif analysis_type == "Headers" and "PE" in item.parent().text(0):
            self.analyze_pe_headers()
        elif analysis_type == "Sections" and "PE" in item.parent().text(0):
            self.analyze_pe_sections()
        elif analysis_type == "Memory" and "PE" in item.parent().text(0):
            self.analyze_pe_memory_layout()
        elif analysis_type == "Headers" and "ELF" in item.parent().text(0):
            self.analyze_elf_headers()
        elif analysis_type == "Memory" and "ELF" in item.parent().text(0):
            self.analyze_elf_memory_layout()
        else:
            self.analysis_output.setText(f"Analysis '{analysis_type}' not implemented")
            self.progress_bar.setVisible(False)

    def run_strings_analysis(self):
        """Run strings analysis in background thread"""
        self.analysis_thread = AnalysisThread(self.extract_strings, self.current_file)
        self.analysis_thread.update_signal.connect(self.display_strings)
        self.analysis_thread.progress_signal.connect(self.update_progress)
        self.analysis_thread.start()

    def extract_strings(self, file_path):
        """Extract strings from the binary"""
        try:
            # First try using system 'strings' command
            try:
                result = subprocess.run(
                    ["strings", file_path],
                    capture_output=True,
                    text=True,
                    check=True
                )
                return result.stdout
            except:
                # Fallback to manual string extraction
                with open(file_path, 'rb') as f:
                    data = f.read()
                
                strings = []
                current_string = bytearray()
                for byte in data:
                    if 32 <= byte <= 126:  # Printable ASCII
                        current_string.append(byte)
                    else:
                        if len(current_string) >= 4:  # Minimum string length
                            strings.append(current_string.decode('ascii'))
                        current_string = bytearray()
                
                return "\n".join(strings)
        except Exception as e:
            return f"Error extracting strings: {str(e)}"

    def display_strings(self, strings):
        """Display extracted strings in the table"""
        if strings.startswith("Error:"):
            self.analysis_output.setText(strings)
            self.progress_bar.setVisible(False)
            return
        
        string_list = strings.split('\n')
        self.strings_table.setRowCount(len(string_list))
        
        with open(self.current_file, 'rb') as f:
            data = f.read()
        
        for row, string in enumerate(string_list):
            # Find all occurrences of this string in the binary
            offsets = [hex(m.start()) for m in re.finditer(re.escape(string), data.decode('latin-1'))]
            offset_str = ", ".join(offsets) if offsets else "N/A"
            
            self.strings_table.setItem(row, 0, QTableWidgetItem(offset_str))
            self.strings_table.setItem(row, 1, QTableWidgetItem(string))
        
        self.results_tabs.setCurrentWidget(self.strings_table)
        self.progress_bar.setVisible(False)

    def run_hex_dump(self):
        """Run hex dump in background thread"""
        self.analysis_thread = AnalysisThread(self.generate_hex_dump, self.current_file)
        self.analysis_thread.update_signal.connect(self.display_hex_dump)
        self.analysis_thread.progress_signal.connect(self.update_progress)
        self.analysis_thread.start()

    def generate_hex_dump(self, file_path):
        """Generate a hex dump of the file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(4096)  # First 4KB for performance
            
            hex_dump = ""
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_str = ' '.join(f"{b:02x}" for b in chunk)
                ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                hex_dump += f"{i:08x}: {hex_str.ljust(47)}  {ascii_str}\n"
            
            return hex_dump
        except Exception as e:
            return f"Error generating hex dump: {str(e)}"

    def display_hex_dump(self, hex_dump):
        """Display hex dump in the hex view"""
        if hex_dump.startswith("Error:"):
            self.analysis_output.setText(hex_dump)
        else:
            self.hex_view.setText(hex_dump)
            self.results_tabs.setCurrentWidget(self.hex_view)
        
        self.progress_bar.setVisible(False)

    def analyze_pe_headers(self):
        """Analyze PE headers for Windows binaries"""
        try:
            pe = pefile.PE(self.current_file)
            info = "PE Header Information:\n\n"
            
            # DOS Header
            info += "DOS Header:\n"
            info += f"  Magic: {hex(pe.DOS_HEADER.e_magic)}\n"
            info += f"  PE Header Offset: {hex(pe.DOS_HEADER.e_lfanew)}\n\n"
            
            # NT Headers
            info += "NT Headers:\n"
            info += f"  Signature: {hex(pe.NT_HEADERS.Signature)}\n"
            info += f"  Machine: {hex(pe.FILE_HEADER.Machine)} ({pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine]})\n"
            info += f"  NumberOfSections: {pe.FILE_HEADER.NumberOfSections}\n"
            info += f"  Characteristics: {hex(pe.FILE_HEADER.Characteristics)}\n\n"
            
            # Optional Header
            info += "Optional Header:\n"
            info += f"  Magic: {hex(pe.OPTIONAL_HEADER.Magic)}\n"
            info += f"  EntryPoint: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}\n"
            info += f"  ImageBase: {hex(pe.OPTIONAL_HEADER.ImageBase)}\n"
            info += f"  SectionAlignment: {hex(pe.OPTIONAL_HEADER.SectionAlignment)}\n"
            info += f"  FileAlignment: {hex(pe.OPTIONAL_HEADER.FileAlignment)}\n"
            
            self.analysis_output.setText(info)
            pe.close()
        except Exception as e:
            self.analysis_output.setText(f"Error analyzing PE headers: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)

    def analyze_pe_sections(self):
        """Analyze PE sections for Windows binaries"""
        try:
            pe = pefile.PE(self.current_file)
            info = "PE Section Information:\n\n"
            
            for section in pe.sections:
                info += f"Section: {section.Name.decode().strip()}\n"
                info += f"  Virtual Address: {hex(section.VirtualAddress)}\n"
                info += f"  Virtual Size: {hex(section.Misc_VirtualSize)}\n"
                info += f"  Raw Size: {hex(section.SizeOfRawData)}\n"
                info += f"  Characteristics: {hex(section.Characteristics)}\n\n"
            
            self.analysis_output.setText(info)
            pe.close()
        except Exception as e:
            self.analysis_output.setText(f"Error analyzing PE sections: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)

    def analyze_pe_memory_layout(self):
        """Analyze PE memory layout"""
        try:
            pe = pefile.PE(self.current_file)
            self.memory_map_table.setRowCount(len(pe.sections))
            
            for row, section in enumerate(pe.sections):
                self.memory_map_table.setItem(row, 0, QTableWidgetItem(section.Name.decode().strip()))
                self.memory_map_table.setItem(row, 1, QTableWidgetItem(hex(section.VirtualAddress)))
                self.memory_map_table.setItem(row, 2, QTableWidgetItem(hex(section.Misc_VirtualSize)))
                
                # Format characteristics
                chars = []
                for flag in pefile.SECTION_CHARACTERISTICS.__members__:
                    if section.Characteristics & pefile.SECTION_CHARACTERISTICS[flag]:
                        chars.append(flag)
                
                self.memory_map_table.setItem(row, 3, QTableWidgetItem(", ".join(chars)))
            
            pe.close()
            self.results_tabs.setCurrentWidget(self.memory_map_table)
        except Exception as e:
            self.analysis_output.setText(f"Error analyzing PE memory layout: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)

    def analyze_elf_headers(self):
        """Analyze ELF headers for Linux binaries"""
        try:
            binary = lief.parse(self.current_file)
            if not binary:
                raise Exception("Failed to parse ELF file")
            
            info = "ELF Header Information:\n\n"
            info += f"Type: {binary.header.file_type.name}\n"
            info += f"Machine: {binary.header.machine_type.name}\n"
            info += f"Entry Point: 0x{binary.entrypoint: x}\n"
            info += f"Number of Sections: {len(binary.sections)}\n"
            info += f"Number of Segments: {len(binary.segments)}\n"
            
            self.analysis_output.setText(info)
        except Exception as e:
            self.analysis_output.setText(f"Error analyzing ELF headers: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)

    def analyze_elf_memory_layout(self):
        """Analyze ELF memory layout"""
        try:
            binary = lief.parse(self.current_file)
            if not binary:
                raise Exception("Failed to parse ELF file")
            
            # Combine sections and segments for complete memory map
            self.memory_map_table.setRowCount(len(binary.sections) + len(binary.segments))
            row = 0
            
            # Add sections
            for section in binary.sections:
                self.memory_map_table.setItem(row, 0, QTableWidgetItem(section.name))
                self.memory_map_table.setItem(row, 1, QTableWidgetItem(hex(section.virtual_address)))
                self.memory_map_table.setItem(row, 2, QTableWidgetItem(hex(section.size)))
                self.memory_map_table.setItem(row, 3, QTableWidgetItem(str(section.type)))
                row += 1
            
            # Add segments
            for segment in binary.segments:
                self.memory_map_table.setItem(row, 0, QTableWidgetItem(segment.type.name))
                self.memory_map_table.setItem(row, 1, QTableWidgetItem(hex(segment.virtual_address)))
                self.memory_map_table.setItem(row, 2, QTableWidgetItem(hex(segment.physical_size)))
                flags = []
                if segment.has(lief.ELF.SEGMENT_FLAGS.R): flags.append("R")
                if segment.has(lief.ELF.SEGMENT_FLAGS.W): flags.append("W")
                if segment.has(lief.ELF.SEGMENT_FLAGS.X): flags.append("X")
                self.memory_map_table.setItem(row, 3, QTableWidgetItem(''.join(flags)))
                row += 1
            
            self.results_tabs.setCurrentWidget(self.memory_map_table)
        except Exception as e:
            self.analysis_output.setText(f"Error analyzing ELF memory layout: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)