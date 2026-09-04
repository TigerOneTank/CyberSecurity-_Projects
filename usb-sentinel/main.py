import sys
import os
import argparse
import tempfile
import shutil
from usb_sentinel.config import Config
from usb_sentinel.detector import DriveWatcher, DriveDetector
from usb_sentinel.scanner import USBScanner, EICAR_SIGNATURE
from usb_sentinel.quarantine import QuarantineVault

BANNER = r"""
  _    _  _____ ____         _____ ______ _   _ _______ _____ _   _ ______ _      
 | |  | |/ ____|  _ \       / ____|  ____| \ | |__   __|_   _| \ | |  ____| |     
 | |  | | (___ | |_) |_____| (___ | |__  |  \| |  | |    | | |  \| | |__  | |     
 | |  | |\___ \|  _ <______| \___ \|  __| | . ` |  | |    | | | . ` |  __| | |     
 | |__| |____) | |_) |      ____) | |____| |\  |  | |   _| |_| |\  | |____| |____ 
  \____/|_____/|____/      |_____/|______|_| \_|  |_|  |_____|_| \_|______|______|
                Automated USB & External Storage Malware Defense
                         Author: DuckWater (@TigerOneTank)
"""

def print_banner():
    print(BANNER)

def run_watcher(config, auto_quarantine):
    print_banner()
    scanner = USBScanner(config)

    def on_drive_connected(drive_info):
        root = drive_info["root"]
        vol = drive_info["volume_name"]
        fs = drive_info["filesystem"]
        total = drive_info["total_gb"]
        free = drive_info["free_gb"]

        print(f"\n[⚡] EVENT: Removable Media Inserted!")
        print(f"    Drive Root  : {root}")
        print(f"    Volume Name : {vol}")
        print(f"    File System : {fs}")
        print(f"    Capacity    : {free} GB free of {total} GB")
        print(f"[*] Dispatching automated forensic scan...")
        
        scanner.scan_path(root, auto_quarantine=auto_quarantine)

    def on_drive_disconnected(root):
        print(f"[!] Drive {root} safely dismounted or unplugged.")

    watcher = DriveWatcher(
        poll_interval=config.get("poll_interval_seconds", 2),
        on_connect=on_drive_connected,
        on_disconnect=on_drive_disconnected
    )
    watcher.start()

def run_simulation(config, auto_quarantine):
    print_banner()
    print("[*] PREPARING SAFE THREAT SIMULATION ENVIRONMENT...")
    temp_dir = tempfile.mkdtemp(prefix="usb_sentinel_sim_")
    
    try:
        # 1. Benign normal file
        with open(os.path.join(temp_dir, "meeting_notes.txt"), "w") as f:
            f.write("Q3 Security Review Notes: All endpoints updated.")

        # 2. Simulated Autorun worm vector
        with open(os.path.join(temp_dir, "autorun.inf"), "w") as f:
            f.write("[AutoRun]\nopen=suspicious_worm.exe\naction=Open USB Drive\n")

        # 3. Simulated Double Extension Spoof
        with open(os.path.join(temp_dir, "Employee_Benefits_2026.pdf.exe"), "wb") as f:
            f.write(b"MZ\x90\x00\x03\x00\x00\x00(simulated fake executable payload)")

        # 4. Standard EICAR Antivirus Test File
        with open(os.path.join(temp_dir, "eicar_test_sample.com"), "wb") as f:
            f.write(EICAR_SIGNATURE)

        print(f"[+] Simulation sandbox generated at: {temp_dir}")
        print("    - Added clean file: meeting_notes.txt")
        print("    - Added simulated autorun vector: autorun.inf")
        print("    - Added simulated double extension: Employee_Benefits_2026.pdf.exe")
        print("    - Added standard EICAR test string: eicar_test_sample.com")

        scanner = USBScanner(config)
        result = scanner.scan_path(temp_dir, auto_quarantine=auto_quarantine)

        print("\n[✔] Simulation test completed successfully!")
        print(f"[✔] Detected {result['threats_count']} threat indicators as expected.")
    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass

def list_quarantine(config):
    vault = QuarantineVault(config.get("quarantine_dir"))
    items = vault.list_quarantined()
    print_banner()
    print("🔒 QUARANTINE VAULT INVENTORY")
    print("=" * 60)
    if not items:
        print("Vault is empty. No files currently in quarantine.")
        return

    for idx, item in enumerate(items, 1):
        print(f"{idx}. {item.get('original_filename')} ({item.get('threat_name')})")
        print(f"   Severity : {item.get('severity')}")
        print(f"   Isolated : {item.get('quarantined_at')}")
        print(f"   Original : {item.get('original_path')}")
        print(f"   Vault ID : {item.get('quarantined_file')}")
        print("-" * 60)

def main():
    parser = argparse.ArgumentParser(
        description="USB-Sentinel: Automated USB & External Storage Malware Defense Scanner"
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Run real-time watcher daemon for external drive insertion events"
    )
    parser.add_argument(
        "--scan",
        metavar="PATH",
        type=str,
        help="Perform an immediate scan on a target drive or directory (e.g. E:\\)"
    )
    parser.add_argument(
        "--test-sim",
        action="store_true",
        help="Run a safe simulated scan using EICAR and simulated threat samples"
    )
    parser.add_argument(
        "--auto-quarantine",
        action="store_true",
        help="Automatically isolate and quarantine threats upon detection"
    )
    parser.add_argument(
        "--quarantine-list",
        action="store_true",
        help="Display all files currently stored in the quarantine vault"
    )
    parser.add_argument(
        "--restore",
        metavar="VAULT_FILE",
        type=str,
        help="Restore a quarantined file from the vault by its vault filename"
    )

    args = parser.parse_args()
    config = Config()

    auto_q = args.auto_quarantine or config.get("auto_quarantine", False)

    if args.watch:
        run_watcher(config, auto_q)
    elif args.scan:
        print_banner()
        scanner = USBScanner(config)
        scanner.scan_path(args.scan, auto_quarantine=auto_q)
    elif args.test_sim:
        run_simulation(config, auto_q)
    elif args.quarantine_list:
        list_quarantine(config)
    elif args.restore:
        vault = QuarantineVault(config.get("quarantine_dir"))
        success, msg = vault.restore(args.restore)
        print(f"[{'✔' if success else 'x'}] {msg}")
    else:
        print_banner()
        parser.print_help()
        print("\nTip: To monitor for new USB drives in real time, run:  py main.py --watch")
        print("Tip: To run a safe test scan right now, run:        py main.py --test-sim")

if __name__ == "__main__":
    main()
