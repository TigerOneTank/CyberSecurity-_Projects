# 🛡️ USB-Sentinel

> **Automated USB & Removable Media Threat Defense & Forensic Scanner**  
> *Developed by [DuckWater (@TigerOneTank)](https://github.com/TigerOneTank)*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)](https://microsoft.com)
[![Security](https://img.shields.io/badge/Threat%20Model-MITRE%20ATT%26CK-red)](https://attack.mitre.org/)
[![Engine](https://img.shields.io/badge/AV%20Engine-Microsoft%20Defender%20CLI-success)](#windows-defender-integration)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Standard%20Lib)-brightgreen)](#prerequisites)

---

## 📌 Overview

Removable USB media remains one of the primary vectors for initial access, air-gapped network traversal, and stealthy worm propagation (as seen in historic campaigns like **Stuxnet**, **Conficker**, and modern **Raspberry Robin**).

**USB-Sentinel** is an automated endpoint security tool engineered to monitor Windows systems for external drive insertion events in real time. The moment a USB flash drive, external SSD, or SD card is mounted, USB-Sentinel dispatches an automated, multi-layered forensic inspection, isolates weaponized payloads into a secure quarantine vault, triggers desktop alerts, and compiles comprehensive JSON and HTML incident reports.

---

## ⚡ Key Features

- **Automated Event Detection**: Monitors storage bus insertion events in real time using native Win32 APIs (`kernel32.GetLogicalDrives` and `GetDriveTypeW`) without polling third-party drivers.
- **Zero External Dependencies**: Engineered entirely with standard Python 3 and native OS libraries (`ctypes`, `subprocess`, `hashlib`, `stat`). Runs instantly on any modern Windows system with `py main.py`.
- **Multi-Layered Threat Heuristics**:
  - **Autorun Worm Neutralization**: Flags execution directives in `autorun.inf` attempting to spawn binaries or scripts.
  - **Double-Extension Masquerading**: Detects spoofed files (e.g., `invoice.pdf.exe`, `photo.jpg.vbs`, `bonus.docx.bat`).
  - **Weaponized LNK Shortcut Analysis**: Inspects shortcut files for concealed commands invoking `powershell.exe`, `cmd.exe`, `wscript`, `cscript`, `mshta`, or `certutil`.
  - **Hidden & System Executable Detection**: Detects files masquerading as system files with `HIDDEN` or `SYSTEM` attributes enabled.
- **Signature & Threat Intelligence Matching**:
  - Validates files against EICAR standard anti-virus test signatures.
  - Computes cryptographic hashes (SHA-256 and MD5) against known threat indicators.
- **Microsoft Defender Integration**: Seamlessly interfaces with Microsoft Defender's CLI engine (`MpCmdRun.exe`) to perform in-depth custom drive scans.
- **Isolated Quarantine Vault**: Defangs malicious files, strips execute permissions, renames files with a `.quarantined` extension, moves them to a secure directory, and records cryptographic metadata. Includes 1-click restore functionality.
- **Interactive Cyber Reporting**: Generates forensic JSON logs and a dark-mode, responsive HTML report complete with severity badges and MITRE ATT&CK mappings.

---

## 🎯 MITRE ATT&CK® Alignment

| Technique ID | Technique Name | Detection Mechanism in USB-Sentinel |
| :--- | :--- | :--- |
| **[T1091](https://attack.mitre.org/techniques/T1091/)** | **Replication Through Removable Media** | Scans and validates root `autorun.inf` execution directives and hidden root droppers. |
| **[T1204.002](https://attack.mitre.org/techniques/T1204/002/)** | **User Execution: Malicious File** | Flags disguised double extensions (`.pdf.exe`, `.jpg.scr`) designed to deceive users. |
| **[T1059](https://attack.mitre.org/techniques/T1059/)** | **Command & Scripting Interpreter** | Scans `.lnk` shortcuts for embedded PowerShell, CMD, or WScript dropper commands. |
| **[T1564.001](https://attack.mitre.org/techniques/T1564/001/)** | **Hidden Files and Directories** | Evaluates Windows filesystem attributes for hidden executable binaries. |

---

## 📂 Project Architecture

```
usb-sentinel/
├── usb_sentinel/
│   ├── __init__.py         # Package metadata
│   ├── config.py           # Configuration loader & default schema
│   ├── detector.py         # Win32 removable drive detection & event watcher
│   ├── scanner.py          # Multi-engine heuristic & signature inspector
│   ├── quarantine.py       # Secure defanging vault and restoration manager
│   ├── notifier.py         # Windows toast notifications & audible alerts
│   └── reporter.py         # JSON and HTML forensic report generator
├── tests/
│   └── test_scanner.py     # Automated unit test suite
├── quarantine/             # Storage vault for isolated threats (.quarantined)
├── reports/                # Output directory for HTML and JSON reports
├── config.json             # User-configurable parameters
├── main.py                 # CLI controller
├── README.md               # Documentation
└── .gitignore
```

---

## 🚀 Quickstart & Usage

### 1. Requirements
- **Windows 10 / 11** or **Windows Server**
- **Python 3.10+** (verified on Python 3.13)
- No `pip install` required!

### 2. Run the Real-Time Insertion Watcher
Keep USB-Sentinel running in your terminal. When you plug in any USB drive, it automatically detects the drive and scans it:
```powershell
py main.py --watch
```

To automatically isolate and quarantine threats upon detection, enable the auto-quarantine flag:
```powershell
py main.py --watch --auto-quarantine
```

### 3. Immediate On-Demand Scan
Scan an already connected drive or folder:
```powershell
py main.py --scan E:\
```

### 4. Safe Simulation Test
Run a safe test inside an isolated temporary directory using the standardized EICAR test string and simulated heuristic samples:
```powershell
py main.py --test-sim
```

To test automated isolation during simulation:
```powershell
py main.py --test-sim --auto-quarantine
```

### 5. Quarantine Management
View all files stored in the quarantine vault:
```powershell
py main.py --quarantine-list
```

Restore a file from quarantine if confirmed safe:
```powershell
py main.py --restore <VAULT_FILENAME>
```

---

## ⚙️ Configuration (`config.json`)

Tweak scanner behavior directly in `config.json`:

```json
{
    "poll_interval_seconds": 2,
    "auto_quarantine": false,
    "quarantine_dir": "quarantine",
    "reports_dir": "reports",
    "enable_defender_scan": true,
    "defender_path": "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
    "enable_desktop_notifications": true,
    "enable_audio_alert": true,
    "max_file_size_mb": 100,
    "suspicious_extensions": [
        ".exe", ".scr", ".vbs", ".bat", ".cmd", 
        ".ps1", ".hta", ".pif", ".jar", ".com", ".wsf", ".lnk"
    ],
    "double_extension_targets": [
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", 
        ".jpg", ".jpeg", ".png", ".txt", ".mp4", ".zip", ".rar"
    ]
}
```

---

## 🧪 Automated Testing

Run the built-in test suite to verify detection logic, file parsing, quarantine mechanics, and report rendering:

```powershell
py -m unittest discover -s tests -p "test_*.py" -v
```

Output:
```
test_autorun_detection ... ok
test_clean_directory ... ok
test_double_extension_detection ... ok
test_eicar_signature_detection ... ok
test_quarantine_isolation_and_restore ... ok
test_reporter_generation ... ok

Ran 6 tests in 0.032s
OK
```

---

## 📊 Sample Forensic Report

When a scan finishes, USB-Sentinel generates both:
1. **Machine-readable JSON**: `reports/scan_report_<timestamp>.json`
2. **Interactive HTML Dashboard**: `reports/scan_report_<timestamp>.html`

```
========================================================
SCAN SUMMARY REPORT
========================================================
Target Scanned   : E:\
Files Inspected  : 142
Threats Detected : 2
Scan Duration    : 0.34 seconds

[!] DETECTED THREAT DETAILS:
  1. [QUARANTINED] USB.AutoRun.WormVector (CRITICAL)
     Path : E:\autorun.inf
     MITRE: T1091 - Replication via Removable Media
  2. [QUARANTINED] Heuristic.DoubleExtension.Spoof (CRITICAL)
     Path : E:\urgent_tax_form.pdf.exe
     MITRE: T1204.002 - Malicious File / Masquerading

[+] JSON Report : reports/scan_report_20260904_131911.json
[+] HTML Report : reports/scan_report_20260904_131911.html
========================================================
```

---

## 🔒 Security & Safe Handling

- **Non-Destructive Quarantine**: Quarantined files are defanged, permissions set to read-only, and preserved with complete SHA-256 metadata so they can be securely analyzed or reversed.
- **Safe Sandboxing**: The simulation mode operates in an ephemeral `%TEMP%` directory and automatically tears down its temporary files upon completion.

---

## 👤 Author

**DuckWater** ([@TigerOneTank](https://github.com/TigerOneTank))  
*Portfolio Repository: [CyberSecurity-_Projects](https://github.com/TigerOneTank/CyberSecurity-_Projects)*
