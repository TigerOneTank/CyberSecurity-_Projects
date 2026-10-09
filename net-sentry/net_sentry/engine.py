import sys
import os
import time
import socket
import struct
from .parser import PacketParser
from .detector import NetworkDetector
from .pcap_writer import PcapWriter
from .reporter import NidsReporter

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

class NidsEngine:
    def __init__(self, cfg=None):
        self.cfg = cfg or {}
        self.detector = NetworkDetector(self.cfg)
        self.reporter = NidsReporter(self.cfg.get("reports_dir", "reports"))
        
        pcap_dir = self.cfg.get("pcap_capture_dir", "captures")
        stamp = time.strftime("%Y%m%d_%H%M%S")
        self.pcap_path = os.path.join(pcap_dir, f"alerts_{stamp}.pcap")
        self.pcap_sink = PcapWriter(self.pcap_path) if self.cfg.get("enable_pcap_dump", True) else None

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

    def process_packet(self, raw):
        self.stats["total_packets"] += 1
        eth = PacketParser.parse_ethernet(raw)
        if not eth:
            self.stats["other"] += 1
            return None

        alert = None

        if eth["eth_type"] == 0x0806:
            self.stats["arp"] += 1
            if (arp := PacketParser.parse_arp(eth["payload"])):
                alert = self.detector.evaluate_arp(arp)

        elif eth["eth_type"] == 0x0800:
            self.stats["ipv4"] += 1
            if (ip := PacketParser.parse_ipv4(eth["payload"])):
                proto = ip["protocol"]

                if proto == 6:
                    self.stats["tcp"] += 1
                    if (tcp := PacketParser.parse_tcp(ip["payload"])):
                        alert = self.detector.evaluate_tcp(ip, tcp)
                        # Check web payloads for credential leaks
                        if tcp["payload"] and {tcp["dest_port"], tcp["src_port"]} & {80, 8080, 8000}:
                            if (http := PacketParser.parse_http(tcp["payload"])):
                                alert = self.detector.evaluate_http(ip, http) or alert

                elif proto == 17:
                    self.stats["udp"] += 1
                    if (udp := PacketParser.parse_udp(ip["payload"])):
                        if 53 in (udp["dest_port"], udp["src_port"]):
                            if (q := PacketParser.parse_dns_query(udp["payload"])):
                                alert = self.detector.evaluate_dns(ip, q)

                elif proto == 1:
                    self.stats["icmp"] += 1
                else:
                    self.stats["other"] += 1

        if alert:
            self.stats["alerts_count"] += 1
            self._display_alert(alert)
            if self.pcap_sink:
                self.pcap_sink.write_packet(raw)

        return alert

    def _display_alert(self, alert):
        sev_tag = "[CRITICAL]" if alert.severity == "CRITICAL" else "[HIGH]"
        print(f"\n🚨 {sev_tag} {alert.rule_name}")
        print(f"   Severity : {alert.severity}")
        print(f"   MITRE    : {alert.mitre_id}")
        print(f"   Flow     : {alert.src} -> {alert.dest}")
        print(f"   Details  : {alert.description}")

    def analyze_pcap(self, pcap_path):
        if not os.path.exists(pcap_path):
            print(f"[x] PCAP not found: {pcap_path}")
            return None

        print(f"[*] Parsing PCAP stream from {pcap_path}...")
        with open(pcap_path, "rb") as fh:
            hdr = fh.read(24)
            if len(hdr) < 24:
                return None

            magic = struct.unpack("!I", hdr[:4])[0]
            endian = ">" if magic == 0xa1b2c3d4 else "<"

            while rec_hdr := fh.read(16):
                if len(rec_hdr) < 16:
                    break
                _, _, cap_len, _ = struct.unpack(f"{endian}IIII", rec_hdr)
                frame = fh.read(cap_len)
                if len(frame) < cap_len:
                    break
                self.process_packet(frame)

        return self.finalize_session("OFFLINE_PCAP")

    def run_live(self, bind_ip=None, max_pkts=None):
        if sys.platform != "win32":
            print("[!] Win32 raw socket IOCTLs required for live mode.")
            return None

        host = bind_ip or socket.gethostbyname(socket.gethostname())
        print(f"[*] Attaching raw socket on {host}...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((host, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Promiscuous mode IOCTL
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            print(f"[*] Sniffing active. Press Ctrl+C to halt.")

            seen = 0
            while True:
                buf = sock.recvfrom(65535)[0]
                # Synthesize a dummy Ethernet header for uniform downstream processing
                synth_frame = b"\x00\x11\x22\x33\x44\x55\xaa\xbb\xcc\xdd\xee\xff\x08\x00" + buf
                self.process_packet(synth_frame)
                seen += 1
                if max_pkts and seen >= max_pkts:
                    break
        except PermissionError:
            print("[x] Permission denied: Live packet capture on Windows requires an elevated terminal (Run as Administrator).")
            print("    Run safe simulated telemetry instead:  py main.py --simulate")
        except KeyboardInterrupt:
            print("\n[*] Sniffing halted.")
        finally:
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                sock.close()
            except Exception:
                pass

        return self.finalize_session("LIVE_SNIFFER")

    def finalize_session(self, label="SIMULATION"):
        if self.pcap_sink:
            self.pcap_sink.close()

        records = [a.to_dict() for a in self.detector.alerts]
        summary = {
            "mode": label,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "packets_analyzed": self.stats["total_packets"],
            "protocol_breakdown": {
                "TCP": self.stats["tcp"],
                "UDP": self.stats["udp"],
                "ARP": self.stats["arp"],
                "ICMP": self.stats["icmp"],
                "Other": self.stats["other"]
            },
            "alerts_count": len(records),
            "alerts": records,
            "pcap_file": self.pcap_path if self.pcap_sink else None
        }

        json_out, html_out = self.reporter.generate_reports(summary)
        summary["json_report"] = json_out
        summary["html_report"] = html_out

        self._print_stats(summary)
        return summary

    def _print_stats(self, summary):
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
