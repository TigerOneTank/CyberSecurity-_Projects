# 🛡️ Cybersecurity Projects & Research Lab

> A curated collection of security tools, incident response scripts, defensive utilities, and forensic tools built by **DuckWater** ([@TigerOneTank](https://github.com/TigerOneTank)).

[![GitHub Profile](https://img.shields.io/badge/GitHub-TigerOneTank-181717?logo=github&logoColor=white)](https://github.com/TigerOneTank)
[![Focus](https://img.shields.io/badge/Focus-Threat%20Hunting%20%7C%20Endpoint%20Defense%20%7C%20Forensics-red)](#featured-projects)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## 🚀 Featured Projects

| Project | Category | Tech Stack | Status | Documentation |
| :--- | :--- | :--- | :--- | :--- |
| **[USB-Sentinel](./usb-sentinel)** | Endpoint Defense / Forensics | Python 3, Win32 API, Windows Defender CLI | Ready | [View Project README](./usb-sentinel/README.md) |

---

### 1. [USB-Sentinel](./usb-sentinel) — Automated USB & External Drive Malware Defense
An automated endpoint scanner that listens for external drive insertion events in real time, scans mounted media for worm droppers and weaponized files, integrates with the Microsoft Defender CLI, isolates threats into a secure quarantine vault, and compiles interactive forensic reports.

- **MITRE ATT&CK® Techniques**:
  - `T1091` (Replication Through Removable Media)
  - `T1204.002` (User Execution: Malicious File / Double Extensions)
  - `T1059` (Command and Scripting Interpreter / Weaponized LNK Shortcuts)
  - `T1564.001` (Hidden Files and Directories)
- **Key Capabilities**:
  - Zero third-party dependencies (runs out-of-the-box on standard Python 3.10+)
  - Real-time drive arrival listener (`py main.py --watch`)
  - Multi-engine heuristics (`autorun.inf`, spoofed `.pdf.exe`, weaponized `.lnk`, EICAR signatures)
  - Microsoft Defender engine CLI integration (`MpCmdRun.exe`)
  - Defanged quarantine isolation vault with metadata tracking
  - Automated HTML & JSON forensic report generation with dark cyber theme

👉 **[Explore USB-Sentinel](./usb-sentinel)**

---

## 🗺️ Cybersecurity Engineering Roadmap

- [x] **Project 1**: Automated External Drive Malware & Heuristic Scanner (`USB-Sentinel`)
- [ ] **Project 2**: Real-Time Network Packet Analyzer & Port Scanner
- [ ] **Project 3**: SIEM Threat Detection Rules & Wazuh/Splunk Ingestion Pipeline
- [ ] **Project 4**: Vulnerability Assessment & Automated Web Recon Tool

---

## 📬 Contact & Links

- **GitHub**: [@TigerOneTank](https://github.com/TigerOneTank)
- **Repository**: [TigerOneTank/CyberSecurity-_Projects](https://github.com/TigerOneTank/CyberSecurity-_Projects)
