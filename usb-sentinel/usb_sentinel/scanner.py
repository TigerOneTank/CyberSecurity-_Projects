import os
import sys
import re
import time
import hashlib
import subprocess
from .config import Config
from .quarantine import QuarantineVault
from .notifier import Notifier
from .reporter import ScanReporter

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Official EICAR standard test signature
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

class ThreatCategory:
    AUTORUN_WORM = "AUTORUN_WORM"
    DOUBLE_EXTENSION = "DOUBLE_EXTENSION"
    SUSPICIOUS_SHORTCUT = "SUSPICIOUS_SHORTCUT"
    HIDDEN_EXECUTABLE = "HIDDEN_EXECUTABLE"
    EICAR_TEST = "EICAR_TEST_SIGNATURE"
    HASH_MATCH = "KNOWN_MALWARE_HASH"
    DEFENDER_DETECTION = "WINDOWS_DEFENDER_DETECTION"

class USBScanner:
    def __init__(self, cfg=None):
        self.cfg = cfg or Config()
        self.vault = QuarantineVault(self.cfg.get("quarantine_dir"))
        self.reporter = ScanReporter(self.cfg.get("reports_dir"))
        self.bad_exts = {ext.lower() for ext in self.cfg.get("suspicious_extensions")}
        self.doc_exts = {ext.lower() for ext in self.cfg.get("double_extension_targets")}
        self.hash_db = self.cfg.get("known_malicious_hashes", {})

    def scan_path(self, target, auto_quarantine=None):
        auto_isolate = self.cfg.get("auto_quarantine", False) if auto_quarantine is None else auto_quarantine
        target_abs = os.path.abspath(target)
        t0 = time.time()

        print("\n" + "=" * 56)
        print("[+] USB-SENTINEL: STARTING FORENSIC SCAN")
        print(f"[*] Target: {target_abs}")
        print(f"[*] Auto-Quarantine: {'ENABLED' if auto_isolate else 'DISABLED (Alert Only)'}")
        print("=" * 56 + "\n")

        findings = []
        inspected = 0

        # Check drive root for autorun vectors
        if (autorun_hit := self._inspect_autorun(target_abs)):
            findings.append(autorun_hit)

        # File tree traversal
        for dirpath, _, filenames in os.walk(target_abs):
            for fname in filenames:
                full_path = os.path.join(dirpath, fname)
                inspected += 1
                hits = self._inspect_file(full_path, fname)
                if hits:
                    findings.extend(hits)

        # Optional Windows Defender engine query
        if self.cfg.get("enable_defender_scan", True):
            findings.extend(self._run_defender(target_abs))

        # Deduplicate multiple hits on the same file
        deduped = []
        seen_keys = set()
        for threat in findings:
            key = (threat.get("file_path"), threat.get("threat_name"))
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(threat)

        # Handle file containment
        if auto_isolate:
            for threat in deduped:
                fp = threat.get("file_path")
                if not (fp and os.path.exists(fp)):
                    continue
                ok, vault_path = self.vault.isolate(fp, threat)
                if ok:
                    threat["quarantined"] = True
                    print(f"[!] QUARANTINED: {fp} -> {vault_path}")
                else:
                    print(f"[x] Isolation failed for {fp}: {vault_path}")

        elapsed = round(time.time() - t0, 2)
        summary = {
            "target": target_abs,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "files_scanned": inspected,
            "threats_count": len(deduped),
            "threats": deduped,
            "duration_seconds": elapsed,
            "auto_quarantine": auto_isolate
        }

        json_out, html_out = self.reporter.generate_reports(summary)

        if deduped:
            if self.cfg.get("enable_audio_alert", True):
                Notifier.play_alert("CRITICAL")
            if self.cfg.get("enable_desktop_notifications", True):
                Notifier.show_desktop_notification(
                    "USB-Sentinel Threat Alert!",
                    f"{len(deduped)} security threat(s) detected on {target_abs}",
                    is_alert=True
                )
        else:
            if self.cfg.get("enable_desktop_notifications", True):
                Notifier.show_desktop_notification(
                    "USB-Sentinel: Clean",
                    f"Scanned {inspected} files on {target_abs}. No threats detected.",
                    is_alert=False
                )

        self._print_summary(summary, json_out, html_out)
        return summary

    def _inspect_autorun(self, drive_root):
        inf_path = os.path.join(drive_root, "autorun.inf")
        if not os.path.exists(inf_path):
            return None

        try:
            with open(inf_path, "r", errors="ignore") as fh:
                raw = fh.read()

            patterns = (r"open\s*=", r"shellexecute\s*=", r"shell\\.+command\s*=")
            if any(re.search(pat, raw, re.IGNORECASE) for pat in patterns):
                return {
                    "file_path": inf_path,
                    "threat_name": "USB.AutoRun.WormVector",
                    "threat_type": ThreatCategory.AUTORUN_WORM,
                    "severity": "CRITICAL",
                    "mitre_attack": "T1091 - Replication via Removable Media",
                    "description": "Suspicious execution directive in autorun.inf commonly used by USB worms.",
                    "sha256": self._hash_file(inf_path),
                    "quarantined": False
                }
        except OSError:
            pass
        return None

    def _inspect_file(self, fpath, fname):
        hits = []
        name_lower = fname.lower()
        _, ext = os.path.splitext(name_lower)

        # Flag disguised double extensions (e.g. invoice.pdf.exe)
        parts = name_lower.split(".")
        if len(parts) >= 3:
            penultimate = f".{parts[-2]}"
            tail = f".{parts[-1]}"
            if tail in self.bad_exts and penultimate in self.doc_exts:
                hits.append({
                    "file_path": fpath,
                    "threat_name": "Heuristic.DoubleExtension.Spoof",
                    "threat_type": ThreatCategory.DOUBLE_EXTENSION,
                    "severity": "CRITICAL",
                    "mitre_attack": "T1204.002 - Malicious File / Masquerading",
                    "description": f"File uses spoofed double extension ({penultimate}{tail}) to disguise executable payload.",
                    "sha256": self._hash_file(fpath),
                    "quarantined": False
                })

        # Scan shortcuts for dropper one-liners
        if ext == ".lnk":
            try:
                with open(fpath, "rb") as fh:
                    chunk = fh.read(4096).decode("ascii", errors="ignore").lower()
                dropper_bins = ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "certutil", "bitsadmin")
                if any(bin_name in chunk for bin_name in dropper_bins):
                    hits.append({
                        "file_path": fpath,
                        "threat_name": "USB.WeaponizedShortcut.LNK",
                        "threat_type": ThreatCategory.SUSPICIOUS_SHORTCUT,
                        "severity": "HIGH",
                        "mitre_attack": "T1059 - Command & Scripting Interpreter",
                        "description": "LNK shortcut invokes command shells or scripting interpreters commonly used in USB dropper worms.",
                        "sha256": self._hash_file(fpath),
                        "quarantined": False
                    })
            except OSError:
                pass

        # Executables hidden via filesystem attributes
        if sys.platform == "win32" and ext in self.bad_exts:
            try:
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(fpath)
                if attrs != -1 and (attrs & 0x02 or attrs & 0x04):
                    hits.append({
                        "file_path": fpath,
                        "threat_name": "Heuristic.HiddenExecutable",
                        "threat_type": ThreatCategory.HIDDEN_EXECUTABLE,
                        "severity": "HIGH",
                        "mitre_attack": "T1564.001 - Hidden Files & Directories",
                        "description": "Executable file has HIDDEN or SYSTEM filesystem attributes enabled.",
                        "sha256": self._hash_file(fpath),
                        "quarantined": False
                    })
            except Exception:
                pass

        # Hash and EICAR signature validation
        try:
            sz_mb = os.path.getsize(fpath) / (1024 * 1024)
            if sz_mb <= self.cfg.get("max_file_size_mb", 100):
                with open(fpath, "rb") as fh:
                    head = fh.read(512)
                if EICAR_SIGNATURE in head or head.startswith(b"X5O!P%@AP[4\\PZX54"):
                    hits.append({
                        "file_path": fpath,
                        "threat_name": "EICAR.Standard.AV.TestFile",
                        "threat_type": ThreatCategory.EICAR_TEST,
                        "severity": "HIGH",
                        "mitre_attack": "Test.Validation",
                        "description": "Standard Antivirus Test File signature detected.",
                        "sha256": self._hash_file(fpath),
                        "quarantined": False
                    })

                sha, md5 = self._compute_hashes(fpath)
                match = self.hash_db.get(sha) or self.hash_db.get(md5)
                if match:
                    hits.append({
                        "file_path": fpath,
                        "threat_name": f"Malware.HashMatch: {match}",
                        "threat_type": ThreatCategory.HASH_MATCH,
                        "severity": "CRITICAL",
                        "mitre_attack": "T1204.002 - Known Malicious Payload",
                        "description": f"File hash matched threat intelligence database: {match}",
                        "sha256": sha,
                        "quarantined": False
                    })
        except OSError:
            pass

        return hits

    def _run_defender(self, target_dir):
        def_bin = self.cfg.get("defender_path", r"C:\Program Files\Windows Defender\MpCmdRun.exe")
        if not os.path.exists(def_bin):
            return []

        threats = []
        try:
            print("[*] Running Windows Defender engine scan...")
            cmd = [def_bin, "-Scan", "-ScanType", "3", "-File", target_dir, "-DisableRemediation"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            # Defender returns code 2 on threat hit
            if proc.returncode == 2 or "threat" in proc.stdout.lower():
                for line in proc.stdout.splitlines():
                    cleaned = line.strip()
                    if "threat" in cleaned.lower() or "file:" in cleaned.lower():
                        threats.append({
                            "file_path": target_dir,
                            "threat_name": f"WinDefender: {cleaned}",
                            "threat_type": ThreatCategory.DEFENDER_DETECTION,
                            "severity": "CRITICAL",
                            "mitre_attack": "AV.MicrosoftDefender",
                            "description": f"Windows Defender reported: {cleaned}",
                            "sha256": "N/A",
                            "quarantined": False
                        })
        except Exception as err:
            print(f"[!] Defender engine scan aborted: {err}")

        return threats

    def _hash_file(self, fpath):
        try:
            h = hashlib.sha256()
            with open(fpath, "rb") as fh:
                while chunk := fh.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return "N/A"

    def _compute_hashes(self, fpath):
        try:
            s = hashlib.sha256()
            m = hashlib.md5()
            with open(fpath, "rb") as fh:
                while chunk := fh.read(65536):
                    s.update(chunk)
                    m.update(chunk)
            return s.hexdigest(), m.hexdigest()
        except OSError:
            return "N/A", "N/A"

    def _print_summary(self, res, json_path, html_path):
        print("\n" + "=" * 56)
        print("SCAN SUMMARY REPORT")
        print("=" * 56)
        print(f"Target Scanned   : {res['target']}")
        print(f"Files Inspected  : {res['files_scanned']}")
        print(f"Threats Detected : {res['threats_count']}")
        print(f"Scan Duration    : {res['duration_seconds']} seconds")

        if res["threats"]:
            print("\n[!] DETECTED THREAT DETAILS:")
            for idx, threat in enumerate(res["threats"], 1):
                status = "[QUARANTINED]" if threat.get("quarantined") else "[DETECTED]"
                print(f"  {idx}. {status} {threat['threat_name']} ({threat['severity']})")
                print(f"     Path : {threat['file_path']}")
                print(f"     MITRE: {threat.get('mitre_attack', 'N/A')}")
        else:
            print("\n[+] DRIVE VERIFIED CLEAN. No indicators of compromise found.")

        print(f"\n[+] JSON Report : {json_path}")
        print(f"[+] HTML Report : {html_path}")
        print("=" * 56 + "\n")
