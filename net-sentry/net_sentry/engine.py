import sys
import os
import time
import socket
import struct
from .parser import PacketParser
from .detector import NetworkDetector
from .pcap_writer import PcapWriter
from .reporter import NidsReporter

# Ensure UTF-8 output on Windows
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

class NidsEngine:
    """Core Network Intrusion Detection Engine orchestrating dissection and rule evaluation."""

    def __init__(self, config=None):
        self.config = config or {}
        self.detector = NetworkDetector(self.config)
        self.reporter = NidsReporter(self.config.get("reports_dir", "reports"))
        
        # Setup PCAP capture file
        pcap_dir = self.config.get("pcap_capture_dir", "captures")
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.pcap_path = os.path.join(pcap_dir, f"alerts_{timestamp}.pcap")
        self.pcap_writer = PcapWriter(self.pcap_path) if self.config.get("enable_pcap_dump", True) else None

        self.stats = {
            "total_packets": 0,
            "arp": 0,
            "ipv4": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "other": 0,
            "alerts_count": 0
        }

    def process_packet(self, raw_bytes):
        """Dissects an incoming raw Ethernet packet and applies detection rules."""
        self.stats["total_packets"] += 1
        eth = PacketParser.parse_ethernet(raw_bytes)
        if not eth:
            self.stats["other"] += 1
            return None

        alert = None

        # 1. ARP Inspection
        if eth["eth_type"] == 0x0806:
            self.stats["arp"] += 1
            arp = PacketParser.parse_arp(eth["payload"])
            if arp:
                alert = self.detector.evaluate_arp(arp)

        # 2. IPv4 Inspection
        elif eth["eth_type"] == 0x0800:
            self.stats["ipv4"] += 1
            ip = PacketParser.parse_ipv4(eth["payload"])
            if ip:
                proto = ip["protocol"]

                # TCP
                if proto == 6:
                    self.stats["tcp"] += 1
                    tcp = PacketParser.parse_tcp(ip["payload"])
                    if tcp:
                        alert = self.detector.evaluate_tcp(ip, tcp)
                        # Check for HTTP payload on common web ports or payload presence
                        if tcp["payload"] and (tcp["dest_port"] in (80, 8080, 8000) or tcp["src_port"] in (80, 8080, 8000)):
                            http = PacketParser.parse_http(tcp["payload"])
                            if http:
                                http_alert = self.detector.evaluate_http(ip, http)
                                if http_alert:
                                    alert = http_alert

                # UDP
                elif proto == 17:
                    self.stats["udp"] += 1
                    udp = PacketParser.parse_udp(ip["payload"])
                    if udp:
                        # DNS inspection
                        if udp["dest_port"] == 53 or udp["src_port"] == 53:
                            domain = PacketParser.parse_dns_query(udp["payload"])
                            if domain:
                                alert = self.detector.evaluate_dns(ip, domain)

                # ICMP
                elif proto == 1:
                    self.stats["icmp"] += 1
                else:
                    self.stats["other"] += 1

        if alert:
            self.stats["alerts_count"] += 1
            self._print_alert(alert)
            if self.pcap_writer:
                self.pcap_writer.write_packet(raw_bytes)

        return alert

    def _print_alert(self, alert):
        sev = alert.severity
        color_tag = "[CRITICAL]" if sev == "CRITICAL" else "[HIGH]"
        print(f"\n🚨 {color_tag} {alert.rule_name}")
        print(f"   Severity : {alert.severity}")
        print(f"   MITRE    : {alert.mitre_id}")
        print(f"   Flow     : {alert.src} -> {alert.dest}")
        print(f"   Details  : {alert.description}")

    def analyze_pcap(self, pcap_path):
        """Reads and analyzes an offline .pcap capture file packet-by-packet."""
        if not os.path.exists(pcap_path):
            print(f"[x] Error: PCAP file not found: {pcap_path}")
            return None

        print(f"[*] Analyzing offline PCAP: {pcap_path}")
        with open(pcap_path, "rb") as f:
            global_header = f.read(24)
            if len(global_header) < 24:
                print("[x] Invalid PCAP file header.")
                return None

            magic = struct.unpack("!I", global_header[:4])[0]
            # Standard PCAPs: 0xa1b2c3d4 or 0xd4c3b2a1
            endian = ">" if magic == 0xa1b2c3d4 else "<"

            while True:
                header_data = f.read(16)
                if len(header_data) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", header_data)
                packet_data = f.read(incl_len)
                if len(packet_data) < incl_len:
                    break
                self.process_packet(packet_data)

        return self.finalize_session("OFFLINE_PCAP")

    def run_live(self, host_ip=None, packet_limit=None):
        """Runs live packet capture on Windows using raw socket (requires administrator)."""
        if sys.platform != "win32":
            print("[!] Live raw socket capture in this script is optimized for Windows.")
            return None

        target_host = host_ip or socket.gethostbyname(socket.gethostname())
        print(f"[*] Binding raw socket to host IP: {target_host}")

        try:
            # Create raw socket (IPv4)
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((target_host, 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Enable promiscuous mode via Windows IOCTL
            # SIO_RCVALL = 0x98000001
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            print(f"[*] Sniffing active on {target_host}. Press Ctrl+C to terminate...")

            count = 0
            while True:
                raw_data = sniffer.recvfrom(65535)[0]
                # Windows raw IP socket receives IP packet without Ethernet frame,
                # so synthesize dummy Ethernet frame for uniform pipeline
                dummy_eth = b"\x00\x11\x22\x33\x44\x55\xaa\xbb\xcc\xdd\xee\xff\x08\x00" + raw_data
                self.process_packet(dummy_eth)
                count += 1
                if packet_limit and count >= packet_limit:
                    break
        except PermissionError:
            print("[x] Permission Error: Live raw socket capture on Windows requires running the terminal as Administrator.")
            print("    Recommendation: Run safe attack simulation with: py main.py --simulate")
        except KeyboardInterrupt:
            print("\n[*] Stopping live sniffer...")
        finally:
            try:
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                sniffer.close()
            except Exception:
                pass

        return self.finalize_session("LIVE_SNIFFER")

    def finalize_session(self, mode="SIMULATION"):
        """Compiles session statistics and exports JSON and HTML reports."""
        if self.pcap_writer:
            self.pcap_writer.close()

        alerts_dicts = [a.to_dict() for a in self.detector.alerts]
        summary = {
            "mode": mode,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "packets_analyzed": self.stats["total_packets"],
            "protocol_breakdown": {
                "TCP": self.stats["tcp"],
                "UDP": self.stats["udp"],
                "ARP": self.stats["arp"],
                "ICMP": self.stats["icmp"],
                "Other": self.stats["other"]
            },
            "alerts_count": len(alerts_dicts),
            "alerts": alerts_dicts,
            "pcap_file": self.pcap_path if self.pcap_writer else None
        }

        json_path, html_path = self.reporter.generate_reports(summary)
        summary["json_report"] = json_path
        summary["html_report"] = html_path

        self._print_summary(summary)
        return summary

    def _print_summary(self, summary):
        print("\n" + "=" * 60)
        print("📊 NET-SENTRY: NIDS TELEMETRY SUMMARY")
        print("=" * 60)
        print(f"Session Mode       : {summary['mode']}")
        print(f"Packets Analyzed   : {summary['packets_analyzed']}")
        print(f"Protocol Breakdown : TCP={self.stats['tcp']}, UDP={self.stats['udp']}, ARP={self.stats['arp']}, ICMP={self.stats['icmp']}")
        print(f"Threat Alerts      : {summary['alerts_count']}")
        if summary.get("pcap_file"):
            print(f"Captured PCAP      : {summary['pcap_file']}")
        print(f"JSON Report        : {summary['json_report']}")
        print(f"HTML Report        : {summary['html_report']}")
        print("=" * 60 + "\n")
