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

def launch_sim(cfg):
    print(BANNER)
    print("[*] Generating synthetic raw attack sequence...")
    stream = TrafficSimulator.generate_attack_stream()
    print(f"[+] Dispatched {len(stream)} frames across 5 threat scenarios.")

    engine = NidsEngine(cfg.data)
    for frame in stream:
        engine.process_packet(frame["bytes"])

    engine.finalize_session(label="SIMULATED_ATTACK_STREAM")

def main():
    cli = argparse.ArgumentParser(
        description="Net-Sentry: Network Intrusion Detection System (NIDS) & Protocol Dissector"
    )
    cli.add_argument("--simulate", action="store_true", help="Run simulated attack stream")
    cli.add_argument("--pcap", metavar="FILE.PCAP", type=str, help="Ingest offline libpcap file")
    cli.add_argument("--live", action="store_true", help="Start live raw packet sniffer (Admin required)")
    cli.add_argument("--host", type=str, default=None, help="Host IP override for live capture")

    args = cli.parse_args()
    cfg = Config()

    if args.simulate:
        launch_sim(cfg)
    elif args.pcap:
        print(BANNER)
        NidsEngine(cfg.data).analyze_pcap(args.pcap)
    elif args.live:
        print(BANNER)
        NidsEngine(cfg.data).run_live(bind_ip=args.host)
    else:
        print(BANNER)
        cli.print_help()

if __name__ == "__main__":
    main()
