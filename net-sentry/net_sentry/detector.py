import time
import math
import re
import base64
from collections import defaultdict

def calculate_shannon_entropy(data_str):
    """Calculates the Shannon Entropy (information density in bits/char) of a string."""
    if not data_str:
        return 0.0
    entropy = 0.0
    length = len(data_str)
    counts = defaultdict(int)
    for char in data_str:
        counts[char] += 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

class ThreatAlert:
    def __init__(self, rule_name, severity, mitre_id, description, src, dest, details=None):
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.rule_name = rule_name
        self.severity = severity  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
        self.mitre_id = mitre_id
        self.description = description
        self.src = src
        self.dest = dest
        self.details = details or {}

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "mitre_id": self.mitre_id,
            "description": self.description,
            "src": self.src,
            "dest": self.dest,
            "details": self.details
        }

class NetworkDetector:
    """Stateful threat detection engine mapping network anomalies to MITRE ATT&CK."""

    def __init__(self, config=None):
        self.config = config or {}
        self.port_scan_threshold = self.config.get("port_scan_threshold_ports", 15)
        self.port_scan_window = self.config.get("port_scan_window_seconds", 5.0)
        self.syn_flood_threshold = self.config.get("syn_flood_threshold_packets", 40)
        self.dns_entropy_threshold = self.config.get("dns_entropy_threshold", 3.8)
        self.dns_length_threshold = self.config.get("dns_length_threshold", 45)

        # State tracking tables
        self.arp_table = {}  # { ip: mac }
        self.port_scan_tracker = defaultdict(list)  # { src_ip: [(timestamp, port)] }
        self.syn_flood_tracker = defaultdict(list)  # { src_ip: [timestamp] }
        self.alerts = []

    def evaluate_arp(self, arp_pkt):
        """Detects ARP Poisoning / Man-in-the-Middle spoofing (MITRE T1557.002)."""
        src_ip = arp_pkt["src_ip"]
        src_mac = arp_pkt["src_mac"]

        # Ignore invalid/zero broadcast addresses
        if src_ip in ("0.0.0.0", "255.255.255.255") or src_mac == "00:00:00:00:00:00":
            return None

        # Check for IP-MAC mapping conflict
        if src_ip in self.arp_table:
            known_mac = self.arp_table[src_ip]
            if known_mac.lower() != src_mac.lower():
                alert = ThreatAlert(
                    rule_name="ARP_CACHE_POISONING_ATTACK",
                    severity="CRITICAL",
                    mitre_id="T1557.002 - Adversary-in-the-Middle: ARP Poisoning",
                    description=f"IP {src_ip} re-assigned from {known_mac} to {src_mac} (unsolicited MAC conflict)",
                    src=f"{src_ip} ({src_mac})",
                    dest=f"{arp_pkt['dest_ip']} ({arp_pkt['dest_mac']})",
                    details={"original_mac": known_mac, "spoofed_mac": src_mac}
                )
                self.alerts.append(alert)
                return alert
        else:
            self.arp_table[src_ip] = src_mac

        return None

    def evaluate_tcp(self, ip_pkt, tcp_pkt):
        """Detects stealth scans, rapid port sweeps, and SYN flood attacks (MITRE T1046, T1498)."""
        src_ip = ip_pkt["src_ip"]
        dest_ip = ip_pkt["dest_ip"]
        dest_port = tcp_pkt["dest_port"]
        now = time.time()

        # 1. Stealth Scans: NULL, FIN, XMAS
        if tcp_pkt.get("is_null_scan"):
            alert = ThreatAlert(
                rule_name="STEALTH_SCAN_TCP_NULL",
                severity="HIGH",
                mitre_id="T1046 - Network Service Discovery: NULL Scan",
                description="TCP packet with zero flags set (nmap -sN stealth probe)",
                src=f"{src_ip}:{tcp_pkt['src_port']}",
                dest=f"{dest_ip}:{dest_port}"
            )
            self.alerts.append(alert)
            return alert

        if tcp_pkt.get("is_xmas_scan"):
            alert = ThreatAlert(
                rule_name="STEALTH_SCAN_TCP_XMAS",
                severity="HIGH",
                mitre_id="T1046 - Network Service Discovery: XMAS Scan",
                description="TCP packet with URG+PSH+FIN flags set (nmap -sX stealth probe)",
                src=f"{src_ip}:{tcp_pkt['src_port']}",
                dest=f"{dest_ip}:{dest_port}"
            )
            self.alerts.append(alert)
            return alert

        if tcp_pkt.get("is_fin_scan"):
            alert = ThreatAlert(
                rule_name="STEALTH_SCAN_TCP_FIN",
                severity="HIGH",
                mitre_id="T1046 - Network Service Discovery: FIN Scan",
                description="TCP packet with solitary FIN flag set (nmap -sF stealth probe)",
                src=f"{src_ip}:{tcp_pkt['src_port']}",
                dest=f"{dest_ip}:{dest_port}"
            )
            self.alerts.append(alert)
            return alert

        # 2. Port Sweep Detection (SYN packets across distinct ports)
        if tcp_pkt.get("is_syn_only"):
            # Clean expired records
            cutoff = now - self.port_scan_window
            self.port_scan_tracker[src_ip] = [
                (t, p) for (t, p) in self.port_scan_tracker[src_ip] if t >= cutoff
            ]
            self.port_scan_tracker[src_ip].append((now, dest_port))

            unique_ports = {p for (_, p) in self.port_scan_tracker[src_ip]}
            if len(unique_ports) >= self.port_scan_threshold:
                alert = ThreatAlert(
                    rule_name="PORT_SCAN_RECON_SWEEP",
                    severity="HIGH",
                    mitre_id="T1046 - Network Service Discovery: Port Scan",
                    description=f"Source probed {len(unique_ports)} distinct ports within {self.port_scan_window}s",
                    src=f"{src_ip}",
                    dest=f"{dest_ip}",
                    details={"scanned_ports_sample": list(unique_ports)[:10], "total_ports": len(unique_ports)}
                )
                self.alerts.append(alert)
                # Reset tracker after alerting to prevent alert storms
                self.port_scan_tracker[src_ip].clear()
                return alert

            # 3. SYN Flood DoS Detection
            flood_cutoff = now - 1.0  # 1-second burst window
            self.syn_flood_tracker[src_ip] = [t for t in self.syn_flood_tracker[src_ip] if t >= flood_cutoff]
            self.syn_flood_tracker[src_ip].append(now)

            if len(self.syn_flood_tracker[src_ip]) >= self.syn_flood_threshold:
                alert = ThreatAlert(
                    rule_name="SYN_FLOOD_DOS_ATTACK",
                    severity="CRITICAL",
                    mitre_id="T1498 - Network Denial of Service: Direct Flood",
                    description=f"High-frequency SYN packet flood: {len(self.syn_flood_tracker[src_ip])} pkts/sec",
                    src=f"{src_ip}",
                    dest=f"{dest_ip}:{dest_port}"
                )
                self.alerts.append(alert)
                self.syn_flood_tracker[src_ip].clear()
                return alert

        return None

    def evaluate_dns(self, ip_pkt, domain_name):
        """Detects DNS Tunneling and data exfiltration channels (MITRE T1071.004)."""
        if not domain_name:
            return None

        entropy = calculate_shannon_entropy(domain_name)
        length = len(domain_name)

        if length >= self.dns_length_threshold and entropy >= self.dns_entropy_threshold:
            alert = ThreatAlert(
                rule_name="DNS_TUNNELING_EXFILTRATION",
                severity="CRITICAL",
                mitre_id="T1071.004 - Application Layer Protocol: DNS Tunneling",
                description=f"Suspicious high-entropy DNS query indicative of base64/hex C2 exfiltration",
                src=ip_pkt["src_ip"],
                dest=ip_pkt["dest_ip"],
                details={"query": domain_name, "length": length, "shannon_entropy": entropy}
            )
            self.alerts.append(alert)
            return alert

        return None

    def evaluate_http(self, ip_pkt, http_data):
        """Detects cleartext credentials over unencrypted protocols (MITRE T1552)."""
        if not http_data:
            return None

        # Check Authorization header (Basic Auth)
        auth_hdr = http_data.get("headers", {}).get("authorization", "")
        if "basic " in auth_hdr.lower():
            try:
                encoded = auth_hdr.split()[1]
                decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
                alert = ThreatAlert(
                    rule_name="CLEARTEXT_BASIC_AUTH_CREDENTIALS",
                    severity="HIGH",
                    mitre_id="T1552 - Unsecured Credentials",
                    description="Cleartext HTTP Basic Authentication header detected in transit",
                    src=ip_pkt["src_ip"],
                    dest=ip_pkt["dest_ip"],
                    details={"leaked_credentials_sample": decoded.split(":")[0] + ":******"}
                )
                self.alerts.append(alert)
                return alert
            except Exception:
                pass

        # Check Form Body for login passwords
        body = http_data.get("body", "")
        cred_patterns = [r"password=([^&]+)", r"passwd=([^&]+)", r"pwd=([^&]+)", r"secret=([^&]+)"]
        for pat in cred_patterns:
            if re.search(pat, body, re.IGNORECASE):
                alert = ThreatAlert(
                    rule_name="CLEARTEXT_PASSWORD_TRANSMISSION",
                    severity="HIGH",
                    mitre_id="T1552 - Unsecured Credentials",
                    description="Unencrypted password submission detected in HTTP payload",
                    src=ip_pkt["src_ip"],
                    dest=ip_pkt["dest_ip"],
                    details={"endpoint": http_data.get("uri", "/"), "method": http_data.get("method")}
                )
                self.alerts.append(alert)
                return alert

        return None
