# 📡 Net-Sentry

> **Network Intrusion Detection System (NIDS) & Low-Level Binary Packet Analyzer**  
> *Developed by [DuckWater (@TigerOneTank)](https://github.com/TigerOneTank)*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?logo=linux&logoColor=white)](https://github.com/TigerOneTank/CyberSecurity-_Projects)
[![Security](https://img.shields.io/badge/Threat%20Model-MITRE%20ATT%26CK-red)](https://attack.mitre.org/)
[![Format](https://img.shields.io/badge/Capture-Wireshark%20PCAP%20(RFC)-success?logo=wireshark&logoColor=white)](#wireshark-compatible-pcap-export)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Standard%20Lib)-brightgreen)](#prerequisites)

---

## 📌 Overview

**Net-Sentry** is an educational, zero-dependency Network Intrusion Detection System (NIDS) and deep packet analyzer written in pure Python 3. Rather than relying on third-party abstractions like Scapy, Net-Sentry dissects raw network frames down to the bit and byte level using Python's standard `struct` module—demonstrating a low-level understanding of fundamental networking RFCs and protocol headers.

It monitors network traffic, detects common network-layer and application-layer attacks mapped to the **MITRE ATT&CK®** framework, records flagged threat traffic into Wireshark-compatible `.pcap` files, and generates dark-mode HTML forensic reports.

---

## ⚡ Core Capabilities

- **Zero External Dependencies**: Built entirely with Python 3 standard libraries (`struct`, `socket`, `math`, `time`). Runs out of the box with `py main.py`.
- **Low-Level Protocol Dissection**:
  - **Ethernet II** (14-byte frames, MAC addressing, EtherType resolution)
  - **Address Resolution Protocol (ARP)** (RFC 826, Hardware/Protocol types, Opcodes)
  - **IPv4** (RFC 791, IHL calculation, TTL, Flags, Protocol demuxing)
  - **Transmission Control Protocol (TCP)** (RFC 793, Seq/Ack tracking, Flag bitmask decoding: URG, ACK, PSH, RST, SYN, FIN)
  - **User Datagram Protocol (UDP)** (RFC 768, 8-byte datagram headers)
  - **Domain Name System (DNS)** (RFC 1035, QNAME extraction & subdomain parsing)
  - **Hypertext Transfer Protocol (HTTP)** (Methods, URIs, Request Headers, Form Payloads)
- **Wireshark-Compatible PCAP Generation**: Writes valid standard libpcap files (`0xa1b2c3d4` magic header) so flagged malicious packets can be analyzed directly in Wireshark.
- **Safe Built-In Attack Simulation**: Synthesizes realistic raw packet streams for all 5 threat vectors so professors, evaluators, and recruiters can test detection logic safely without live network access or elevated root privileges.

---

## 🎯 MITRE ATT&CK® Threat Rules

| Attack Vector | MITRE ATT&CK® | Detection Technique in Net-Sentry |
| :--- | :--- | :--- |
| **Port Scanning (Stealth & Sweep)** | **[T1046](https://attack.mitre.org/techniques/T1046/)** | Tracks sliding-window connection attempts (>15 ports in 5s). Detects abnormal TCP flag combinations (SYN sweeps, NULL scans, FIN scans, and XMAS scans: FIN+PSH+URG). |
| **ARP Poisoning / Spoofing (MitM)** | **[T1557.002](https://attack.mitre.org/techniques/T1557/002/)** | Maintains a dynamic IP-to-MAC state table. Detects duplicate MAC claims, sudden hardware address remappings, and unsolicited gratuitous ARP replies. |
| **SYN Flood Denial of Service** | **[T1498](https://attack.mitre.org/techniques/T1498/)** | Tracks half-open TCP connections and flags anomalous ratios of unanswered SYN packets exceeding configurable rate limits. |
| **DNS Tunneling & Data Exfiltration** | **[T1071.004](https://attack.mitre.org/techniques/T1071/004/)** | Analyzes DNS query structures, flags abnormally long query strings (>45 chars), and calculates **Shannon Entropy** (>3.8 bits/char) to flag base64/hex data exfiltration. |
| **Cleartext Credential Exposure** | **[T1552](https://attack.mitre.org/techniques/T1552/)** | Inspects unencrypted HTTP POST bodies, Basic Auth headers (`Authorization: Basic`), and FTP/Telnet streams for exposed passwords and usernames. |

---

## 📐 Network Protocol Breakdown

Net-Sentry unpacks network packets directly using binary struct patterns:

```
+-----------------------------------------------------------+
|               Ethernet II Frame Header (14 bytes)         |
|   Destination MAC (6B) | Source MAC (6B) | EtherType (2B) |
+-----------------------------------------------------------+
                              |
       +----------------------+----------------------+
       | EtherType = 0x0800                          | EtherType = 0x0806
       v                                             v
+-------------------------------+             +-----------------------+
|      IPv4 Header (20 bytes)   |             |   ARP Packet (28B)    |
| Version, IHL, TTL, Protocol   |             | Opcode, Sender/Target |
+-------------------------------+             | MAC & IP addresses    |
       |               |                      +-----------------------+
       | Proto=6 (TCP) | Proto=17 (UDP)
       v               v
+-------------+ +-------------+
| TCP Segment | | UDP Datagram|
| Flags, Ports| | Ports, Len  |
+-------------+ +-------------+
```

---

## 📂 Project Architecture

```
net-sentry/
├── net_sentry/
│   ├── __init__.py         # Package metadata
│   ├── config.py           # Configuration loader
│   ├── parser.py           # Binary packet dissector (struct unpack)
│   ├── detector.py         # Threat rules & Shannon entropy engine
│   ├── engine.py           # Capture engine & PCAP reader/writer
│   ├── pcap_writer.py      # Standard RFC libpcap file generator
│   ├── simulator.py        # Raw packet synthesizer for attack streams
│   └── reporter.py         # JSON and HTML report renderer
├── tests/
│   └── test_nids.py        # Automated unit test suite
├── captures/               # Storage directory for captured .pcap files
├── reports/                # Output directory for HTML and JSON logs
├── config.json             # User-configurable detection thresholds
├── main.py                 # CLI controller
├── README.md               # Documentation
└── .gitignore
```

---

## 🚀 Quickstart & Usage

### 1. Run the Safe Attack Traffic Simulator
Synthesizes a realistic stream of benign web traffic and 5 distinct network attacks:
```powershell
py main.py --simulate
```

### 2. Ingest an Offline Wireshark PCAP File
Analyze existing network captures for intrusion patterns:
```powershell
py main.py --pcap captures/alerts_sample.pcap
```

### 3. Run Live Packet Capture (Windows)
Run live network inspection on your local interface (*Note: Requires running PowerShell as Administrator on Windows*):
```powershell
py main.py --live
```

---

## 🧪 Automated Testing

Run the unit test suite to verify binary unpacking, entropy calculation, and threat detection rules:

```powershell
py -m unittest discover -s tests -p "test_*.py" -v
```

Output:
```
test_arp_cache_poisoning_detection ... ok
test_dns_tunneling_detection ... ok
test_pcap_writer ... ok
test_port_scan_sweep_detection ... ok
test_shannon_entropy ... ok
test_stealth_null_scan_detection ... ok
test_stealth_xmas_scan_detection ... ok

Ran 7 tests in 0.009s
OK
```

---

## 📊 Sample Detection Telemetry

```
🚨 [HIGH] STEALTH_SCAN_TCP_XMAS
   Severity : HIGH
   MITRE    : T1046 - Network Service Discovery: XMAS Scan
   Flow     : 10.0.0.99:54321 -> 192.168.1.10:445
   Details  : TCP packet with URG+PSH+FIN flags set (nmap -sX stealth probe)

🚨 [CRITICAL] ARP_CACHE_POISONING_ATTACK
   Severity : CRITICAL
   MITRE    : T1557.002 - Adversary-in-the-Middle: ARP Poisoning
   Flow     : 192.168.1.1 (de:ad:be:ef:66:66) -> 192.168.1.10 (ff:ff:ff:ff:ff:ff)
   Details  : IP 192.168.1.1 re-assigned from 00:aa:bb:cc:dd:ee to de:ad:be:ef:66:66

🚨 [CRITICAL] DNS_TUNNELING_EXFILTRATION
   Severity : CRITICAL
   MITRE    : T1071.004 - Application Layer Protocol: DNS Tunneling
   Flow     : 192.168.1.45 -> 8.8.8.8
   Details  : Suspicious high-entropy DNS query indicative of base64/hex C2 exfiltration
```

---

## 👤 Author

**DuckWater** ([@TigerOneTank](https://github.com/TigerOneTank))  
*Portfolio Repository: [CyberSecurity-_Projects](https://github.com/TigerOneTank/CyberSecurity-_Projects)*
