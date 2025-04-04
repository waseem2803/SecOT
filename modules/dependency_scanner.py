import sys
import os
import json
import requests
import subprocess
import re
import time
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QFileDialog, QTextEdit, QLabel, QListWidget, QListWidgetItem, QSplitter
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from bs4 import BeautifulSoup
from datetime import datetime

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VULNERABILITIES_FILE = "vulnerabilities.json"
INVALID_DEPENDENCIES = {"modules", "linker", "enabled", "using", "return", "default", "support", "section", "library", "for", "the", "version", "since", "data", "ethernet", "wifi", "usb", "license", "scanner", "long", "allowing", "src_ip", "dest_ip", "display", "smartcols", "linu", "uuid", "blkid", "license-", "gnu", "cpe", "ieee"}

def ensure_json_file():
    """Ensures `vulnerabilities.json` exists and is valid."""
    if not os.path.exists(VULNERABILITIES_FILE) or os.stat(VULNERABILITIES_FILE).st_size == 0:
        with open(VULNERABILITIES_FILE, "w") as f:
            json.dump([], f)

    try:
        with open(VULNERABILITIES_FILE, "r") as f:
            json.load(f)
    except json.JSONDecodeError:
        print("⚠️ Corrupt JSON file detected! Resetting vulnerabilities.json...")
        with open(VULNERABILITIES_FILE, "w") as f:
            json.dump([], f)

def fetch_cves_from_nvd(cpe_string, max_retries=3):
    """Fetches CVEs for a given CPE string from NVD API."""
    url = f"{NVD_API_URL}?cpeName={cpe_string}"

    attempts = 0
    while attempts < max_retries:
        print(f"🔹 Querying CVEs: {url} (Attempt {attempts + 1})")
        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()

            cve_list = []
            if "vulnerabilities" in data:
                for vuln in data["vulnerabilities"]:
                    cve_data = vuln["cve"]
                    cve_id = cve_data["id"]
                    description = next((desc["value"] for desc in cve_data["descriptions"] if desc["lang"] == "en"), "No description available")
                    severity = cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                    references = [ref["url"] for ref in cve_data.get("references", [])]

                    cve_list.append({
                        "CVE_ID": cve_id,
                        "description": description,
                        "severity": severity,
                        "references": references
                    })

            return cve_list  # ✅ Successful response

        except requests.exceptions.RequestException as e:
            print(f"⚠️ Error fetching CVEs: {e}")
            attempts += 1
            if attempts < max_retries:
                print(f"{datetime.now()} - Retrying in 30 seconds...")
                time.sleep(30)
            else:
                print(f"❌ Skipping CVE check after {max_retries} failed attempts.")

    return []

def fetch_vendor_from_nvd(product_name):
    """Fetches vendor for a product from NVD and returns vendor name."""
    url = f"https://nvd.nist.gov/products/cpe/search/results?namingFormat=2.3&keyword={product_name}"
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        # Find all CPE links in the search results
        cpe_links = soup.select("tbody#cpeSearchResultTBody a[data-testid^='cpe-detail-link']")
        vendors = []

        # Extract vendors from CPE strings
        for link in cpe_links:
            cpe_string = link.text.strip()
            cpe_parts = cpe_string.split(":")
            if len(cpe_parts) > 3:
                vendors.append(cpe_parts[3])  # Vendor name is the 3rd element in CPE format

        if not vendors:
            print(f"❌ No vendor found for {product_name}. Skipping...")
            return None  # Skip product if no vendor found

        return vendors[0], vendors  # Return first vendor + full vendor list

    except requests.exceptions.RequestException as e:
        print(f"⚠️ Error fetching vendor for {product_name}: {e}")
        return None, []

def analyze_dependency(dep, analyzer):
    """Analyzes a single dependency, fetching vulnerabilities."""
    if analyzer.stop_scan:
        return

    product_name = dep["dependency"]
    version = dep["version"]
    vendor_info = fetch_vendor_from_nvd(product_name)
    if vendor_info is None:
        return  # ✅ Skip this dependency if no vendor is found

    vendor, all_vendors = vendor_info

    if not vendor:
        return

    cve_results = []
    cpe1 = f"cpe:2.3:a:{vendor}:{product_name}:{version}"
    cpe2 = f"cpe:2.3:a:{product_name}:{product_name}:{version}"

    print(f"🔍 Scanning CVEs for: {cpe1}")
    cve_results.extend(fetch_cves_from_nvd(cpe1))

    if product_name.lower() in [v.lower() for v in all_vendors]:
        print(f"🔍 Also scanning CVEs for: {cpe2}")
        cve_results.extend(fetch_cves_from_nvd(cpe2))

    if cve_results:
        with open(VULNERABILITIES_FILE, "r+") as f:
            data = json.load(f)
            data.append({
                "dependency": product_name,
                "version": version,
                "vulnerabilities": cve_results
            })
            f.seek(0)
            json.dump(data, f, indent=4)
        
        analyzer.log_signal.emit(f"[{datetime.now()}] ⚠️ CVEs found for {product_name} {version}")
        analyzer.update_vulnerabilities_signal.emit()

def find_kernel_image(firmware_path):
    """Search for `kernel.img` in extracted firmware."""
    print("🔍 Searching for kernel.img...")
    for root, _, files in os.walk(firmware_path):
        for file in files:
            if "kernel" in file.lower() and file.endswith(".img"):
                kernel_path = os.path.join(root, file)
                print(f"✅ Found Kernel Image: {kernel_path}")
                return kernel_path
    print("❌ No kernel image found.")
    return None

def extract_kernel_version(kernel_file):
    """Extracts the Linux kernel version from `kernel.img`."""
    if not kernel_file:
        return None

    try:
        output = subprocess.check_output(["strings", kernel_file], text=True, errors="ignore")
        match = re.search(r"Linux version (\d+\.\d+\.\d+)", output)
        if match:
            print(f"✅ Detected Kernel Version: {match.group(1)}")
            return match.group(1)
    except Exception as e:
        print(f"⚠️ Error extracting kernel version: {e}")

    return None

def analyze_kernel(firmware_path, analyzer):
    """Finds and analyzes kernel vulnerabilities."""
    if analyzer.stop_scan:
        return

    kernel_file = find_kernel_image(firmware_path)
    kernel_version = extract_kernel_version(kernel_file)

    if not kernel_version:
        return

    cpe_string = f"cpe:2.3:o:linux:linux_kernel:{kernel_version}"
    kernel_cves = fetch_cves_from_nvd(cpe_string)

    if kernel_cves:
        with open(VULNERABILITIES_FILE, "r+") as f:
            data = json.load(f)
            data.append({
                "dependency": "Linux Kernel",
                "version": kernel_version,
                "vulnerabilities": kernel_cves
            })
            f.seek(0)
            json.dump(data, f, indent=4)
        
        analyzer.log_signal.emit(f"⚠️ CVEs found for Linux Kernel {kernel_version}")
        analyzer.update_vulnerabilities_signal.emit()

def scan_binaries_for_versions(firmware_dir, analyzer):
    """Scans binaries for dependency versions (e.g., busybox 1.36.1)."""
    extracted_info = []
    seen_dependencies = set()

    for root, _, files in os.walk(firmware_dir):
        if analyzer.stop_scan:
            break
        for file in files:
            if analyzer.stop_scan:
                break
            bin_path = os.path.join(root, file)

            try:
                output = subprocess.check_output(["strings", bin_path], text=True, errors="ignore")
                matches = re.findall(r'([a-zA-Z0-9\-_]+)\s*v?(\S+)', output)

                for name, version in matches:
                    if analyzer.stop_scan:
                        break
                    if name.isdigit() or len(name) < 3 or name.lower() in INVALID_DEPENDENCIES:
                        continue

                    clean_version = re.match(r"(\d+\.\d+(?:\.\d+)?)", version)
                    if not clean_version:
                        continue

                    dep_key = f"{name}:{clean_version.group(1)}"
                    if dep_key not in seen_dependencies:
                        extracted_info.append({
                            "dependency": name,
                            "version": clean_version.group(1),
                            "path": bin_path
                        })
                        seen_dependencies.add(dep_key)

            except Exception:
                pass  

    return extracted_info

class AnalysisThread(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()
    update_vulnerabilities_signal = pyqtSignal()

    def __init__(self, firmware_path):
        super().__init__()
        self.firmware_path = firmware_path
        self.stop_scan = False

    def run(self):
        self.log_signal.emit(f"[{datetime.now()}] Starting Dependency CVE Scan\nIt will take some time...\nGo grab a coffee hacker ☕️\n")
        
        ensure_json_file()

        analyze_kernel(self.firmware_path, self)

        dependencies = scan_binaries_for_versions(self.firmware_path, self)
        for dep in dependencies:
            if self.stop_scan:
                self.log_signal.emit(f"[{datetime.now()}] Scan Stopped")
                break
            analyze_dependency(dep, self)

        self.log_signal.emit(f"[{datetime.now()}] Scan Completed")
        self.finished_signal.emit()

    def stop(self):
        self.stop_scan = True

class DependencyScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.firmware_path = ""
        self.analysis_thread = None

    def initUI(self):
        main_layout = QVBoxLayout()
        
        # Top layout for buttons
        top_layout = QHBoxLayout()
        
        self.selectButton = QPushButton("Select Folder")
        self.selectButton.clicked.connect(self.selectFirmwarePath)
        top_layout.addWidget(self.selectButton)
        
        self.runButton = QPushButton("Start Scan")
        self.runButton.clicked.connect(self.start_analysis_thread)
        self.runButton.setEnabled(False)
        top_layout.addWidget(self.runButton)
        
        self.stopButton = QPushButton("Stop Scan")
        self.stopButton.clicked.connect(self.stop_scan_analysis)
        self.stopButton.setEnabled(False)
        top_layout.addWidget(self.stopButton)
        
        main_layout.addLayout(top_layout)
        
        # Splitter for dependency list and CVE details
        vertical_splitter = QSplitter(Qt.Orientation.Vertical)
        horizontal_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Widget A - List of vulnerable dependencies
        widget_a = QWidget()
        layout_a = QVBoxLayout()
        label_a = QLabel("Vulnerable Dependencies")
        self.dependencyList = QListWidget()
        self.dependencyList.itemClicked.connect(self.display_cve_details)
        layout_a.addWidget(label_a)
        layout_a.addWidget(self.dependencyList)
        widget_a.setLayout(layout_a)
        horizontal_splitter.addWidget(widget_a)
        
        # Widget B - Details of CVE
        widget_b = QWidget()
        layout_b = QVBoxLayout()
        label_b = QLabel("CVE Details")
        self.cveDetails = QTextEdit()
        self.cveDetails.setReadOnly(True)
        layout_b.addWidget(label_b)
        layout_b.addWidget(self.cveDetails)
        widget_b.setLayout(layout_b)
        horizontal_splitter.addWidget(widget_b)
        
        vertical_splitter.addWidget(horizontal_splitter)
        
        # Widget C - Logs
        widget_c = QWidget()
        layout_c = QVBoxLayout()        
        self.outputText = QTextEdit()
        self.outputText.setReadOnly(True)
        layout_c.addWidget(self.outputText)
        widget_c.setLayout(layout_c)
        widget_c.setStyleSheet("background-color: black; color: white; font-family: Consolas;")
        vertical_splitter.addWidget(widget_c)
        
        main_layout.addWidget(vertical_splitter)
        
        self.setLayout(main_layout)
        self.setWindowTitle("Dependency Scanner")
        self.setGeometry(100, 100, 800, 600)
    
    def log(self, message):
        self.outputText.append(message)
        QApplication.processEvents()

    def selectFirmwarePath(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Firmware File System")
        if folder:
            self.firmware_path = folder
            self.log(f"Selected Directory: {folder}")
            self.runButton.setEnabled(True)
        
    def stop_scan_analysis(self):
        if self.analysis_thread:
            self.analysis_thread.stop()
            self.log(f"[{datetime.now()}] Stopping scan...")

    def start_analysis_thread(self):
        self.analysis_thread = AnalysisThread(self.firmware_path)
        self.analysis_thread.log_signal.connect(self.log)
        self.analysis_thread.finished_signal.connect(self.on_analysis_finished)
        self.analysis_thread.update_vulnerabilities_signal.connect(self.load_vulnerabilities)
        self.analysis_thread.start()
        self.runButton.setEnabled(False)
        self.stopButton.setEnabled(True)

    def on_analysis_finished(self):
        self.stopButton.setEnabled(False)
        self.runButton.setEnabled(True)

    def load_vulnerabilities(self):
        self.dependencyList.clear()
        try:
            with open(VULNERABILITIES_FILE, "r") as f:
                vulnerabilities = json.load(f)
                for entry in vulnerabilities:
                    if "dependency" in entry:
                        item = QListWidgetItem(f"{entry['dependency']} {entry['version']}")
                        item.setData(1, entry)
                        self.dependencyList.addItem(item)
        except Exception as e:
            self.log(f"Error loading vulnerabilities: {e}")

    def display_cve_details(self, item):
        entry = item.data(1)
        cve_details = ""
        for cve in entry["vulnerabilities"]:
            severity_color = {
                "LOW": "green",
                "MEDIUM": "orange",
                "HIGH": "red",
                "CRITICAL": "darkred"
            }.get(cve["severity"], "grey")
            cve_details += f"<p><b style='color:{severity_color}'>{cve['CVE_ID']}</b>: {cve['description']}<br>Severity: {cve['severity']}<br>References: {', '.join(cve['references'])}</p>"
        self.cveDetails.setHtml(cve_details)

if __name__ == "__main__":
    
    import sys
    app = QApplication(sys.argv)
    window = DependencyScanner()
    window.show()
    sys.exit(app.exec())