from concurrent.futures import ThreadPoolExecutor
from pwn import *
from termcolor import *
import socket
import sys
import os
import subprocess
from PyQt6 import QtWidgets, QtGui, QtCore
from datetime import datetime
import requests
import json


class WebAppScanner(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        
        self.root_dir = "/home/kali/secot/SecOT"
        self.base_dir = f"{self.root_dir}/webappscan"
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.check_and_install_tools()

    def initUI(self):
        self.setWindowTitle('WebApp Scanner')
        self.setGeometry(100, 100, 1200, 800)

        main_layout = QtWidgets.QVBoxLayout()

        # URL input and OK button
        url_layout = QtWidgets.QHBoxLayout()
        self.urlInput = QtWidgets.QLineEdit(self)
        self.urlInput.setPlaceholderText("Enter URL")
        url_layout.addWidget(self.urlInput)

        self.checkUrlBtn = QtWidgets.QPushButton("OK", self)
        self.checkUrlBtn.clicked.connect(self.check_url)
        url_layout.addWidget(self.checkUrlBtn)

        main_layout.addLayout(url_layout)

        # Splitter for Directory, Crawl, and Vulnerabilities widgets
        scan_splitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)

        dir_layout = QtWidgets.QVBoxLayout()
        self.startDirEnumBtn = QtWidgets.QPushButton("Start Directory Enumeration", self)
        self.startDirEnumBtn.clicked.connect(self.start_dir_enum)
        self.startDirEnumBtn.setEnabled(False)
        dir_layout.addWidget(self.startDirEnumBtn)

        self.dirLister = QtWidgets.QListWidget(self)
        dir_layout.addWidget(self.dirLister)

        dir_widget = QtWidgets.QWidget()
        dir_widget.setLayout(dir_layout)
        scan_splitter.addWidget(dir_widget)

        crawl_layout = QtWidgets.QVBoxLayout()
        self.startCrawlingBtn = QtWidgets.QPushButton("Start Crawling", self)
        self.startCrawlingBtn.clicked.connect(self.start_crawling)
        self.startCrawlingBtn.setEnabled(False)
        crawl_layout.addWidget(self.startCrawlingBtn)

        self.crawlLister = QtWidgets.QListWidget(self)
        crawl_layout.addWidget(self.crawlLister)

        crawl_widget = QtWidgets.QWidget()
        crawl_widget.setLayout(crawl_layout)
        scan_splitter.addWidget(crawl_widget)

        vuln_layout = QtWidgets.QVBoxLayout()
        self.findVulnsBtn = QtWidgets.QPushButton("Find Vulnerabilities", self)
        self.findVulnsBtn.clicked.connect(self.start_wapiti_scan)
        self.findVulnsBtn.setEnabled(False)
        vuln_layout.addWidget(self.findVulnsBtn)

        self.vulnLister = QtWidgets.QTreeWidget(self)
        self.vulnLister.setHeaderLabel("Vulnerabilities")
        self.vulnLister.itemClicked.connect(self.toggle_vuln_details)
        vuln_layout.addWidget(self.vulnLister)

        vuln_widget = QtWidgets.QWidget()
        vuln_widget.setLayout(vuln_layout)
        scan_splitter.addWidget(vuln_widget)

        # Splitter for scan_splitter and logDisplay
        main_splitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)
        main_splitter.addWidget(scan_splitter)

        self.logDisplay = QtWidgets.QTextEdit(self)
        self.logDisplay.setReadOnly(True)
        main_splitter.addWidget(self.logDisplay)

        main_layout.addWidget(main_splitter)

        self.setLayout(main_layout)

    def log(self, message):
        self.logDisplay.append(message)

    def check_url(self):
        url = self.urlInput.text().strip().lower()
        if url == "":
            self.log(f"[{datetime.now()}] ❌ Invalid URL")
            self.set_buttons_enabled(False)
        else:
            try:
                response = requests.get(url, verify=False)
                if response.status_code == 200:
                    self.log(f"[{datetime.now()}] ✔️ {url} is reachable")
                    scope_file = os.path.join(self.base_dir, 'scope.txt')
                    os.makedirs(os.path.dirname(scope_file), exist_ok=True)
                    with open(scope_file, "w") as output_file:
                        output_file.write(url)
                        self.log(f"[{datetime.now()}] ✔️ {url} added to scope")
                        self.set_buttons_enabled(True)
                else:
                    self.log(f"[{datetime.now()}] ❌ {url} returned status code {response.status_code}")
                    self.set_buttons_enabled(False)
            except requests.RequestException as e:
                self.log(f"[{datetime.now()}] ❌ Error connecting to {url}: {e}")
                self.set_buttons_enabled(False)

    def set_buttons_enabled(self, enabled):
        self.startDirEnumBtn.setEnabled(enabled)
        self.startCrawlingBtn.setEnabled(enabled)
        self.findVulnsBtn.setEnabled(enabled)

    def start_crawling(self):
        self.log(f"[{datetime.now()}] Crawling started")
        future = self.executor.submit(self.gau)
        future.add_done_callback(lambda _: self.executor.submit(self.list_files))
        future.add_done_callback(lambda _: self.log(f"[{datetime.now()}] Crawling finished"))

    def start_dir_enum(self):
        self.log(f"[{datetime.now()}] Directory enumeration started")
        future = self.executor.submit(self.dirsearch)
        future.add_done_callback(lambda _: self.executor.submit(self.list_files))
        future.add_done_callback(lambda _: self.log(f"[{datetime.now()}] Directory enumeration finished"))

    def find_vulnerabilities(self):
        self.log(f"[{datetime.now()}] Started Finding Vulnerabilities")
        future = self.executor.submit(self.gf)
        future.add_done_callback(lambda _: self.executor.submit(self.list_files))
        future.add_done_callback(lambda _: self.log(f"[{datetime.now()}] Finished Finding Vulnerabilties"))

    def stop_scan(self):
        self.log(f"[{datetime.now()}] Scan stopped")

    def run_dirsearch(self):
        dirsearch_cmd = f'python3 tools/dirsearch/dirsearch.py -l {os.path.join(self.base_dir, "scope.txt")} -e php,asp,aspx,net,js,cs,php2,php3,php4,php5,php6,php7,jsp,java,python,yaml,yml,config,conf,htaccess,htpasswd,shtml -o {os.path.join(self.base_dir, "dir_enum.txt")}'
        try:
            subprocess.run(dirsearch_cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            self.log(f"[{datetime.now()}] Error running Dirsearch: {e}")

    def dirsearch(self):
        self.run_dirsearch()

    def run_gau(self):
        gau_cmd = f'cat {os.path.join(self.base_dir, "scope.txt")} | gau | sort -u >> {os.path.join(self.base_dir, "gau.txt")}'
        with open(os.devnull, 'w') as null_file:
            try:
                subprocess.run(gau_cmd, shell=True, check=True, stdout=null_file, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                self.log(f"[{datetime.now()}] Error running Gau: {e}")

    def gau(self):
        self.run_gau()

    def run_wapiti(self):
        url = self.urlInput.text().strip().lower()
        if url == "":
            self.log(f"[{datetime.now()}] ❌ Invalid URL")
            return

        wapiti_cmd = f'wapiti -u {url} -o {os.path.join(self.base_dir, "webapp.json")} -f json'
        try:
            subprocess.run(wapiti_cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.log(f"[{datetime.now()}] ✔️ Wapiti scan completed")
        except subprocess.CalledProcessError as e:
            self.log(f"[{datetime.now()}] Error running Wapiti: {e}")

    def start_wapiti_scan(self):
        self.log(f"[{datetime.now()}] Wapiti scan started")
        future = self.executor.submit(self.run_wapiti)
        future.add_done_callback(lambda _: self.executor.submit(self.list_files))
        future.add_done_callback(lambda _: self.log(f"[{datetime.now()}] Wapiti scan finished"))
        future.add_done_callback(lambda _: self.executor.submit(self.view_json_report))

    def extract_urls_from_file(file_path):
        urls = []
        with open(file_path, 'r') as file:
            for line in file:
                match = re.search(r'http[s]?://\S+', line)
                if match:
                    urls.append(match.group(0))
        return urls

    def is_tool_installed(self, command):
        try:
            subprocess.run([command, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except FileNotFoundError:
            return False

    def install_tool(self, tool):
        install_commands = {
            "dirsearch": "git clone https://github.com/maurosoria/dirsearch.git tools/dirsearch; cd tools/dirsearch; pip3 install -r requirements.txt --break-system-packages",
            "gau": "go install -v github.com/lc/gau@latest",
            "wapiti": "sudo apt install wapiti"
        }

        if tool in install_commands:
            try:
                subprocess.run(install_commands[tool], shell=True, check=True)
                self.log(f"[{datetime.now()}] {tool} installed successfully.")
            except subprocess.CalledProcessError as e:
                self.log(f"[{datetime.now()}] Error installing {tool}: {e}")

    def check_and_install_tools(self):
        tools = {
            "dirsearch": "dirsearch",
            "gau": "gau",
            "wapiti": "wapiti"
        }

        for tool, command in tools.items():
            if not self.is_tool_installed(command):
                self.log(f"[{datetime.now()}] {tool} is not installed. Installing...")
                self.install_tool(tool)
            else:
                self.log(f"[{datetime.now()}] {tool} is already installed.")

    def view_json_report(self):
        json_file_path = os.path.join(self.base_dir, 'webapp.json')
        if os.path.exists(json_file_path):
            with open(json_file_path, 'r') as file:
                json_data = json.load(file)
                self.display_vulnerabilities(json_data)
        else:
            self.log(f"[{datetime.now()}] ❌ JSON report not found")

    def display_vulnerabilities(self, json_data):
        self.vulnLister.clear()
        vulnerabilities = json_data.get("vulnerabilities", {})
        for vuln_type, vuln_list in vulnerabilities.items():
            if vuln_list:
                vuln_item = QtWidgets.QTreeWidgetItem([vuln_type])
                vuln_item.setData(0, QtCore.Qt.ItemDataRole.UserRole, vuln_list)
                self.vulnLister.addTopLevelItem(vuln_item)

    def toggle_vuln_details(self, item, column):
        vuln_list = item.data(0, QtCore.Qt.ItemDataRole.UserRole)
        if item.childCount() == 0:
            for vuln in vuln_list:
                details = f"Method: {vuln['method']}\nPath: {vuln['path']}\nInfo: {vuln['info']}\nLevel: {vuln['level']}\nParameter: {vuln['parameter']}\nHTTP Request: {vuln['http_request']}\nCurl Command: {vuln['curl_command']}"
                vuln_detail_item = QtWidgets.QTreeWidgetItem([details])
                item.addChild(vuln_detail_item)
        else:
            item.takeChildren()

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    scanner = WebAppScanner()
    scanner.show()
    sys.exit(app.exec())