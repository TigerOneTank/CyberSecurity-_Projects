import sys
import os
import argparse
from net_sentry.config import Config
from net_sentry.engine import NidsEngine
from net_sentry.simulator import TrafficSimulator

BANNER = r"""
  _   _ ______ _______       _____ ______ _   _ _______ _______     __
 | \ | |  ____|__   __|     / ____|  ____| \ | |__   __|  __ \ \   / /
 |  \| | |__     | |  _____| (___ | |__  |  \| |  | |  | |__) \ \_/ / 
 | . ` |  __|    | | |______\___ \|  __| | . ` |  | |  |  _  / \   /  
 | |\  | |____   | |        ____) | |____| |\  |  | |  | | \ \  | |   
 |_| \_|______|  |_|       |_____/|______|_| \_|  |_|  |_|  \_\ |_|   
         Network Intrusion Detection System & Deep Packet Inspector
                      Author: DuckWater (@TigerOneTank)
"""

def print_banner():
    print(BANNER)

def run_simulation(config):
    print_banner()
    print("[*] INITIATING SAFE NETWORK ATTACK TRAFFIC SIMULATION...")
    packets = TrafficSimulator.generate_attack_stream()
    print(f"[+] Synthesized {len(packets)} raw network packets covering 5 threat vectors:")
    print("    1. Benign Web Browsing Traffic (baseline)")
    print("    2. Stealth TCP XMAS Port Scan (nmap -sX)")
    print("    3. Multi-Port Reconnaissance Sweep (TCP SYN sweep)")
    print("    4. ARP Cache Poisoning / MitM Gateway Claim")
    print("    5. High-Frequency SYN Flood Denial of Service")
    print("    6. DNS Tunneling & Base64 Data Exfiltration")
    print("    7. Cleartext HTTP Credential Leakage")

    print("\n[*] Processing packets through Net-Sentry dissection pipeline...")
    engine = NidsEngine(config.data)
    for pkt in packets:
        engine.process_packet(pkt["bytes"])

    engine.finalize_session(mode="SIMULATED_ATTACK_STREAM")

def main():
    parser = argparse.ArgumentParser(
        description="Net-Sentry: Network Intrusion Detection System (NIDS) & Protocol Dissector"
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Run safe simulated attack stream (Port scans, ARP spoofing, SYN flood, DNS tunneling)"
    )
    parser.add_argument(
        "--pcap",
        metavar="FILE.PCAP",
        type=str,
        help="Analyze an offline Wireshark .pcap packet capture file"
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Run live raw packet sniffer on local interface (Requires Admin on Windows)"
    )
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Host IP to bind live sniffer to (default: local IP)"
    )

    args = parser.parse_args()
    config = Config()

    if args.simulate:
        run_simulation(config)
    elif args.pcap:
        print_banner()
        engine = NidsEngine(config.data)
        engine.analyze_pcap(args.pcap)
    elif args.live:
        print_banner()
        engine = NidsEngine(config.data)
        engine.run_live(host_ip=args.host)
    else:
        print_banner()
        parser.print_help()
        print("\nTip: To run a safe intrusion detection test right now, run:  py main.py --simulate")

if __name__ == "__main__":
    main()
