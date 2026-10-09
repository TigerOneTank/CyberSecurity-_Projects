import sys
import os
import argparse
import tempfile
import shutil
from usb_sentinel.config import Config
from usb_sentinel.detector import DriveWatcher
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

def launch_watcher(cfg, auto_isolate):
    print(BANNER)
    scanner = USBScanner(cfg)

    def _drive_added(drive):
        root = drive["root"]
        print(f"\n[⚡] INSERTION: {root} ({drive['volume_name']}) - {drive['filesystem']}")
        print(f"[*] Capacity : {drive['free_gb']} GB free of {drive['total_gb']} GB")
        print(f"[*] Initiating triage sweep on {root}...")
        scanner.scan_path(root, auto_quarantine=auto_isolate)

    def _drive_removed(root):
        print(f"[!] Dismounted device: {root}")

    watcher = DriveWatcher(
        poll_interval=cfg.get("poll_interval_seconds", 2),
        on_connect=_drive_added,
        on_disconnect=_drive_removed
    )
    watcher.start()

def launch_simulation(cfg, auto_isolate):
    print(BANNER)
    print("[*] Staging mock infected drive environment in %TEMP%...")
    sandbox = tempfile.mkdtemp(prefix="sentinel_mock_")
    
    try:
        # Legitimate benign sample
        with open(os.path.join(sandbox, "meeting_notes.txt"), "w") as fh:
            fh.write("Weekly SOC sync notes: all endpoints patched.")

        # Autorun worm sample
        with open(os.path.join(sandbox, "autorun.inf"), "w") as fh:
            fh.write("[AutoRun]\nopen=drop_payload.exe\naction=Launch USB Drive\n")

        # Double extension spoof sample
        with open(os.path.join(sandbox, "Quarterly_Bonus_2026.pdf.exe"), "wb") as fh:
            fh.write(b"MZ\x90\x00\x03\x00\x00\x00mock_binary_data")

        # Standard EICAR test string
        with open(os.path.join(sandbox, "eicar_test_sample.com"), "wb") as fh:
            fh.write(EICAR_SIGNATURE)

        print(f"[+] Sandbox ready at: {sandbox}")
        print("    - Added clean baseline : meeting_notes.txt")
        print("    - Added autorun vector  : autorun.inf")
        print("    - Added disguised binary: Quarterly_Bonus_2026.pdf.exe")
        print("    - Added EICAR test file : eicar_test_sample.com")

        scanner = USBScanner(cfg)
        res = scanner.scan_path(sandbox, auto_quarantine=auto_isolate)

        print("\n[✔] Simulation run finished.")
        print(f"[✔] Captured {res['threats_count']} threat indicators.")
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)

def show_quarantine(cfg):
    vault = QuarantineVault(cfg.get("quarantine_dir"))
    records = vault.list_quarantined()
    print(BANNER)
    print("🔒 QUARANTINE VAULT INVENTORY")
    print("=" * 60)
    if not records:
        print("Vault is clean. Zero quarantined items on record.")
        return

    for i, item in enumerate(records, 1):
        print(f"{i}. {item.get('original_filename')} [{item.get('threat_name')}]")
        print(f"   Severity : {item.get('severity')}")
        print(f"   Isolated : {item.get('quarantined_at')}")
        print(f"   Original : {item.get('original_path')}")
        print(f"   Vault ID : {item.get('quarantined_file')}")
        print("-" * 60)

def main():
    cli = argparse.ArgumentParser(
        description="USB-Sentinel: Automated USB & Removable Media Threat Defense"
    )
    cli.add_argument("--watch", action="store_true", help="Launch background insertion watcher")
    cli.add_argument("--scan", metavar="TARGET", type=str, help="Scan specific drive/folder path")
    cli.add_argument("--test-sim", action="store_true", help="Run safe sandbox simulation with EICAR")
    cli.add_argument("--auto-quarantine", action="store_true", help="Automatically isolate detected files")
    cli.add_argument("--quarantine-list", action="store_true", help="Print quarantine inventory")
    cli.add_argument("--restore", metavar="VAULT_FILE", type=str, help="Restore isolated file by vault ID")

    args = cli.parse_args()
    cfg = Config()
    auto_q = args.auto_quarantine or cfg.get("auto_quarantine", False)

    if args.watch:
        launch_watcher(cfg, auto_q)
    elif args.scan:
        print(BANNER)
        USBScanner(cfg).scan_path(args.scan, auto_quarantine=auto_q)
    elif args.test_sim:
        launch_simulation(cfg, auto_q)
    elif args.quarantine_list:
        show_quarantine(cfg)
    elif args.restore:
        ok, msg = QuarantineVault(cfg.get("quarantine_dir")).restore(args.restore)
        print(f"[{'✔' if ok else 'x'}] {msg}")
    else:
        print(BANNER)
        cli.print_help()

if __name__ == "__main__":
    main()
