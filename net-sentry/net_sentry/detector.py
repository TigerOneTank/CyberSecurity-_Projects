import time
import math
import re
import base64
from collections import defaultdict

def calculate_shannon_entropy(data_str):
    if not data_str:
        return 0.0
    n = len(data_str)
    freqs = defaultdict(int)
    for ch in data_str:
        freqs[ch] += 1
    return round(-sum((c / n) * math.log2(c / n) for c in freqs.values()), 3)

class ThreatAlert:
    def __init__(self, rule_name, severity, mitre_id, description, src, dest, details=None):
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.rule_name = rule_name
        self.severity = severity
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
    def __init__(self, cfg=None):
        self.cfg = cfg or {}
        self.scan_threshold = self.cfg.get("port_scan_threshold_ports", 15)
        self.scan_window = self.cfg.get("port_scan_window_seconds", 5.0)
        self.flood_threshold = self.cfg.get("syn_flood_threshold_packets", 40)
        self.dns_entropy_cut = self.cfg.get("dns_entropy_threshold", 3.8)
        self.dns_len_cut = self.cfg.get("dns_length_threshold", 45)

        self.arp_table = {}
        self.scan_history = defaultdict(list)
        self.syn_history = defaultdict(list)
        self.alerts = []

    def evaluate_arp(self, arp_pkt):
        src_ip = arp_pkt["src_ip"]
        src_mac = arp_pkt["src_mac"]

        if src_ip in ("0.0.0.0", "255.255.255.255") or src_mac == "00:00:00:00:00:00":
            return None

        cached_mac = self.arp_table.get(src_ip)
        if cached_mac and cached_mac.lower() != src_mac.lower():
            alert = ThreatAlert(
                rule_name="ARP_CACHE_POISONING_ATTACK",
                severity="CRITICAL",
                mitre_id="T1557.002 - Adversary-in-the-Middle: ARP Poisoning",
                description=f"IP {src_ip} re-assigned from {cached_mac} to {src_mac} (unsolicited MAC conflict)",
                src=f"{src_ip} ({src_mac})",
                dest=f"{arp_pkt['dest_ip']} ({arp_pkt['dest_mac']})",
                details={"original_mac": cached_mac, "spoofed_mac": src_mac}
            )
            self.alerts.append(alert)
            return alert

        self.arp_table[src_ip] = src_mac
        return None

    def evaluate_tcp(self, ip_pkt, tcp_pkt):
        src_ip = ip_pkt["src_ip"]
        dst_ip = ip_pkt["dest_ip"]
        dst_port = tcp_pkt["dest_port"]
        now = time.time()

        # Stealth probe scans
        if tcp_pkt.get("is_null_scan"):
            alert = ThreatAlert(
                rule_name="STEALTH_SCAN_TCP_NULL",
                severity="HIGH",
                mitre_id="T1046 - Network Service Discovery: NULL Scan",
                description="TCP packet with zero flags set (nmap -sN stealth probe)",
                src=f"{src_ip}:{tcp_pkt['src_port']}",
                dest=f"{dst_ip}:{dst_port}"
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
                dest=f"{dst_ip}:{dst_port}"
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
                dest=f"{dst_ip}:{dst_port}"
            )
            self.alerts.append(alert)
            return alert

        if not tcp_pkt.get("is_syn_only"):
            return None

        # Sweep tracking
        cutoff = now - self.scan_window
        self.scan_history[src_ip] = [pt for pt in self.scan_history[src_ip] if pt[0] >= cutoff]
        self.scan_history[src_ip].append((now, dst_port))

        probed = {pt[1] for pt in self.scan_history[src_ip]}
        if len(probed) >= self.scan_threshold:
            alert = ThreatAlert(
                rule_name="PORT_SCAN_RECON_SWEEP",
                severity="HIGH",
                mitre_id="T1046 - Network Service Discovery: Port Scan",
                description=f"Source probed {len(probed)} distinct ports within {self.scan_window}s",
                src=src_ip,
                dest=dst_ip,
                details={"scanned_ports_sample": list(probed)[:10], "total_ports": len(probed)}
            )
            self.alerts.append(alert)
            self.scan_history[src_ip].clear()
            return alert

        # Flood tracking (1s sliding window)
        flood_cut = now - 1.0
        self.syn_history[src_ip] = [t for t in self.syn_history[src_ip] if t >= flood_cut]
        self.syn_history[src_ip].append(now)

        if len(self.syn_history[src_ip]) >= self.flood_threshold:
            alert = ThreatAlert(
                rule_name="SYN_FLOOD_DOS_ATTACK",
                severity="CRITICAL",
                mitre_id="T1498 - Network Denial of Service: Direct Flood",
                description=f"High-frequency SYN packet flood: {len(self.syn_history[src_ip])} pkts/sec",
                src=src_ip,
                dest=f"{dst_ip}:{dst_port}"
            )
            self.alerts.append(alert)
            self.syn_history[src_ip].clear()
            return alert

        return None

    def evaluate_dns(self, ip_pkt, domain_str):
        if not domain_str:
            return None

        h = calculate_shannon_entropy(domain_str)
        length = len(domain_str)

        if length >= self.dns_len_cut and h >= self.dns_entropy_cut:
            alert = ThreatAlert(
                rule_name="DNS_TUNNELING_EXFILTRATION",
                severity="CRITICAL",
                mitre_id="T1071.004 - Application Layer Protocol: DNS Tunneling",
                description="Suspicious high-entropy DNS query indicative of base64/hex C2 exfiltration",
                src=ip_pkt["src_ip"],
                dest=ip_pkt["dest_ip"],
                details={"query": domain_str, "length": length, "shannon_entropy": h}
            )
            self.alerts.append(alert)
            return alert

        return None

    def evaluate_http(self, ip_pkt, http_obj):
        if not http_obj:
            return None

        auth = http_obj.get("headers", {}).get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                raw_b64 = auth.split(None, 1)[1]
                clear = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")
                user_part = clear.split(":", 1)[0]
                alert = ThreatAlert(
                    rule_name="CLEARTEXT_BASIC_AUTH_CREDENTIALS",
                    severity="HIGH",
                    mitre_id="T1552 - Unsecured Credentials",
                    description="Cleartext HTTP Basic Authentication header detected in transit",
                    src=ip_pkt["src_ip"],
                    dest=ip_pkt["dest_ip"],
                    details={"leaked_credentials_sample": f"{user_part}:******"}
                )
                self.alerts.append(alert)
                return alert
            except Exception:
                pass

        body = http_obj.get("body", "")
        pass_regex = (r"password=([^&]+)", r"passwd=([^&]+)", r"pwd=([^&]+)", r"secret=([^&]+)")
        if any(re.search(pat, body, re.IGNORECASE) for pat in pass_regex):
            alert = ThreatAlert(
                rule_name="CLEARTEXT_PASSWORD_TRANSMISSION",
                severity="HIGH",
                mitre_id="T1552 - Unsecured Credentials",
                description="Unencrypted password submission detected in HTTP payload",
                src=ip_pkt["src_ip"],
                dest=ip_pkt["dest_ip"],
                details={"endpoint": http_obj.get("uri", "/"), "method": http_obj.get("method")}
            )
            self.alerts.append(alert)
            return alert

        return None
