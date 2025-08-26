# MalduarkAnaly

**Author:** Hygark

MalduarkAnaly.py - Malware Analysis Tool in Isolated Environment  
Copyright (c) 2025 Hygark  
Licensed under the MIT License. See the LICENSE file for details.  


---

## Features

* **Static Analysis:** Extracts metadata from PE files, Office documents, PDFs, JARs, APKs, and calculates hashes (MD5, SHA256).

* **Script Analysis:** Detects malicious patterns in Python (e.g., eval, exec) and PowerShell (e.g., Invoke-Expression).

* **Document Analysis:** Identifies suspicious VBA macros in .doc/.docx and JavaScript in PDFs.

* **APK/JAR Analysis:** Checks suspicious permissions in APKs and classes in JARs.

* **Dynamic Analysis:** Monitors CPU, memory, and system calls in real time.

* **Network Monitoring:** Detects connections to suspicious IPs using Scapy.

* **Obfuscation Detection:** Identifies base64, compressed code, and non-ASCII characters.

* **Behavior Analysis with ML:** Uses Isolation Forest to detect anomalies in dynamic metrics.

* **Sandbox Integration:**

  * **VirusTotal:** Checks hashes against the API.
  * **Cuckoo Sandbox:** Analysis in a virtualized environment.
  * **Hybrid Analysis:** Detailed threat analysis.
  * **Joe Sandbox:** Advanced behavior reports.

* **Reports:** Export in JSON, CSV, PDF, and HTML with interactive charts.

* **Logs:** Supports file logs, webhook, and Syslog (Splunk/ELK).

* **GUI:** Tkinter interface with Settings, Dashboard (CPU/memory charts), Results, and Reports.

* **Compatibility:** Windows and Linux, with automatic adaptation of commands and interfaces.

---

## Requirements

* **Python:** 3.11 or higher.

* **Python Dependencies:**

  ```bash
  pip install pefile psutil scapy requests reportlab matplotlib tkinterweb python-docx pdfid sklearn numpy
  ```

* **External Dependencies:**

  * **VirusTotal API:** Obtain a key at virustotal.com.
  * **Cuckoo Sandbox:** Configure at cuckoosandbox.org (e.g., [http://localhost:8090](http://localhost:8090)).
  * **Hybrid Analysis API:** Obtain a key at hybrid-analysis.com.
  * **Joe Sandbox API:** Obtain a key at joesandbox.com.
  * **Network Interface:** Configured (e.g., eth0 on Linux, Ethernet on Windows).

* **Operating System:** Windows/Linux (VM isolation recommended).

* **Permissions:** Dynamic and network analysis may require administrator privileges.

* **Security Warning:** Run only in isolated environments to avoid damage from real malware.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/hygark/MalduarkAnaly.git
cd MalduarkAnaly
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Configure API keys (VirusTotal, Cuckoo, Hybrid Analysis, Joe Sandbox) in the script or via GUI.

Install and configure **Cuckoo Sandbox**:

* Follow the instructions at cuckoosandbox.org.
* Make sure the API is accessible (e.g., [http://localhost:8090](http://localhost:8090)).

Create directories for logs and reports:

```bash
mkdir logs reports
```

---

## Usage

Run the script:

```bash
python3 MalduarkAnaly.py
```

In the GUI:

* **Settings:** Select the file (.exe, .dll, .py, .ps1, .doc, .docx, .pdf, .jar, .apk), configure monitoring duration, network interface, API keys, and export options.
* **Dashboard:** View real-time CPU and memory charts.
* **Results:** See details of static, dynamic, network, sandbox, script, obfuscation, and ML analysis.
* **Reports:** Export in JSON, CSV, PDF, or interactive HTML.
* **Buttons:** Start/stop analysis, save settings, view charts, or export reports.

Configure logs (file, webhook, Syslog) as needed.

---

## Example Configuration

```python
Settings = {
    'FilePath': 'sample.exe',
    'MonitorDuration': 30,
    'VirusTotalApiKey': 'your_virustotal_api_key',
    'CuckooApiUrl': 'http://localhost:8090',
    'CuckooApiKey': 'your_cuckoo_api_key',
    'HybridAnalysisApiKey': 'your_hybrid_api_key',
    'JoeSandboxApiKey': 'your_joe_api_key',
    'LogFile': 'logs/malduark_analy.log',
    'ReportDir': 'reports/',
    'NetworkInterface': 'eth0' if platform.system() != 'Windows' else 'Ethernet',
    'ExportJSON': True,
    'ExportCSV': True,
    'ExportPDF': True,
    'ExportHTML': True,
}
```

---

## Legal Compliance

* **Notice:** This tool is intended exclusively for malware analysis in isolated environments with explicit authorization.
  Using it on unauthorized systems or with real malware outside a controlled environment may violate laws such as LGPD (Brazil) or GDPR internationally.
* **Responsibility:** The author (Hygark) is not responsible for any misuse of the tool. Run only in isolated virtual machines and obtain permissions before performing analyses.

---

## Contributions

Contributions are welcome! Submit pull requests or open issues on the GitHub repository.

---

## License

MIT License. See the LICENSE file for more details.

---

## Contact

For questions or suggestions, contact Hygark via GitHub.
