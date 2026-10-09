# 🛡️ Cybersecurity Engineering Portfolio & Research Lab

> A curated collection of production-grade security tools, defensive utilities, network analyzers, and incident response software built by **DuckWater** ([@TigerOneTank](https://github.com/TigerOneTank)).

[![GitHub Profile](https://img.shields.io/badge/GitHub-TigerOneTank-181717?logo=github&logoColor=white)](https://github.com/TigerOneTank)
[![Focus](https://img.shields.io/badge/Focus-Host%20Defense%20%7C%20Network%20Security%20%7C%20Forensics-red)](#-portfolio-projects-directory)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Libraries-blue)](#-standardized-project-structure)

---

## 🗂️ Portfolio Projects Directory

A structured index of all security projects in this repository:

| # | Project | Domain | Key Technologies | MITRE ATT&CK® Coverage | Status | Documentation | Quick Run Command |
| :-: | :--- | :--- | :--- | :--- | :-: | :--- | :--- |
| **01** | **[USB-Sentinel](./usb-sentinel)** | Host & Endpoint Security | Python 3, Win32 API, Defender CLI | `T1091`, `T1204.002`, `T1059`, `T1564.001` | 🟢 Ready | [Project Docs &rarr;](./usb-sentinel/README.md) | `cd usb-sentinel; py main.py --test-sim` |
| **02** | **[Net-Sentry](./net-sentry)** | Network Security & NIDS | Python 3, Binary Dissection (`struct`), PCAP | `T1046`, `T1557.002`, `T1498`, `T1071.004`, `T1552` | 🟢 Ready | [Project Docs &rarr;](./net-sentry/README.md) | `cd net-sentry; py main.py --simulate` |

---

## 🔍 Featured Projects Breakdown

### 1. [USB-Sentinel](./usb-sentinel) — Automated Removable Media Malware Defense
An automated endpoint security tool that listens for external storage drive insertion events in real time, scans mounted media for malware vectors and droppers, integrates with the Microsoft Defender CLI, isolates threats into a safe quarantine vault, and compiles interactive forensic reports.

- **Specialization**: Host & Endpoint Defense, Digital Forensics, Heuristic Analysis
- **Key Capabilities**:
  - Real-time drive insertion event listener (`--watch`) using native Windows Win32 APIs (`kernel32.GetLogicalDrives`).
  - Heuristic analysis for `autorun.inf` worms, spoofed double extensions (`.pdf.exe`), weaponized `.lnk` shortcuts, and hidden executables.
  - Native Windows Defender CLI integration (`MpCmdRun.exe`).
  - Isolated quarantine vault with defanging and metadata tracking.
  - Safe sandboxed simulation mode (`--test-sim`).
- **Quickstart**:
  ```powershell
  cd usb-sentinel
  py main.py --test-sim --auto-quarantine
  ```
👉 **[Read Complete USB-Sentinel Documentation &rarr;](./usb-sentinel/README.md)**

---

### 2. [Net-Sentry](./net-sentry) — Network Intrusion Detection System & Protocol Analyzer
A low-level Network Intrusion Detection System (NIDS) and deep packet analyzer engineered in pure Python 3 without heavy third-party wrappers like Scapy. It dissects raw network frames down to the bit and byte level using Python's standard `struct` module (RFC 791, 793, 768, 826, 1035), detects real-time network attacks, and logs threat captures to Wireshark-compatible `.pcap` files.

- **Specialization**: Network Security, Protocol Engineering, Intrusion Detection, Traffic Analysis
- **Key Capabilities**:
  - Low-level packet dissection (Ethernet II, IPv4, TCP with flag bitmasks, UDP, ARP, DNS, HTTP).
  - Stateful detection for **Port Scans** (SYN sweeps, NULL, FIN, XMAS scans), **ARP Cache Poisoning (MitM)**, **SYN Flood DoS**, **DNS Tunneling** (via Shannon Entropy scoring), and **Cleartext Credential Leakage**.
  - Wireshark-compatible `.pcap` file exporter built with standard Python file I/O.
  - Built-in safe attack traffic synthesizer (`--simulate`).
- **Quickstart**:
  ```powershell
  cd net-sentry
  py main.py --simulate
  ```
👉 **[Read Complete Net-Sentry Documentation &rarr;](./net-sentry/README.md)**

---

## 📐 Standardized Project Structure

Every project in this repository follows a clean, consistent open-source architecture designed for reproducibility:

```
CyberSecurity-_Projects/
├── README.md                   # Global portfolio hub & index (this file)
├── .gitignore                  # Global git exclusions
│
├── usb-sentinel/               # Project 01: Endpoint Security
│   ├── usb_sentinel/           # Source module package
│   ├── tests/                  # Automated unit test suite
│   ├── config.json             # Tunable settings
│   ├── main.py                 # CLI controller
│   ├── README.md               # Detailed project documentation
│   └── reports/                # Forensic reports directory
│
└── net-sentry/                 # Project 02: Network Security
    ├── net_sentry/             # Source module package
    ├── tests/                  # Automated unit test suite
    ├── config.json             # Tunable settings
    ├── main.py                 # CLI controller
    ├── README.md               # Detailed project documentation
    ├── captures/               # Wireshark .pcap captures
    └── reports/                # Forensic reports directory
```

---

## 🗺️ Academic & Industry Roadmap

- [x] **Project 1 (Endpoint Defense)**: Automated External Drive Malware & Heuristic Scanner (`USB-Sentinel`)
- [x] **Project 2 (Network Security)**: Network Intrusion Detection System & Protocol Analyzer (`Net-Sentry`)
- [ ] **Project 3 (Application Security)**: Automated Web Vulnerability & Security Header Scanner (Mini-DAST)
- [ ] **Project 4 (Applied Cryptography)**: Zero-Knowledge CLI Secret Vault & Password Manager

---

## 👤 Author & Contact

**DuckWater** ([@TigerOneTank](https://github.com/TigerOneTank))  
*Portfolio Repository: [TigerOneTank/CyberSecurity-_Projects](https://github.com/TigerOneTank/CyberSecurity-_Projects)*
