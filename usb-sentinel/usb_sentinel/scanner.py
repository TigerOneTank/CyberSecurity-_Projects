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

# Ensure UTF-8 output without crashing on cp1252 consoles
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# EICAR Standard Antivirus Test signature pattern
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
    """Multi-layered cybersecurity scanner for external & removable storage media."""

    def __init__(self, config=None):
        self.config = config or Config()
        self.quarantine_vault = QuarantineVault(self.config.get("quarantine_dir"))
        self.reporter = ScanReporter(self.config.get("reports_dir"))
        self.suspicious_exts = set(ext.lower() for ext in self.config.get("suspicious_extensions"))
        self.double_ext_targets = set(ext.lower() for ext in self.config.get("double_extension_targets"))
        self.known_hashes = self.config.get("known_malicious_hashes", {})

    def scan_path(self, target_path, auto_quarantine=None):
        """Performs a comprehensive security scan of a target drive or directory."""
        if auto_quarantine is None:
            auto_quarantine = self.config.get("auto_quarantine", False)

        target_path = os.path.abspath(target_path)
        start_time = time.time()
        
        print("\n========================================================")
        print("[+] USB-SENTINEL: STARTING FORENSIC SCAN")
        print(f"[*] Target: {target_path}")
        print(f"[*] Auto-Quarantine: {'ENABLED' if auto_quarantine else 'DISABLED (Alert Only)'}")
        print("========================================================\n")

        threats = []
        files_scanned = 0

        # Layer 1: Check for root autorun.inf worm vector (MITRE ATT&CK T1091)
        autorun_threat = self._inspect_autorun(target_path)
        if autorun_threat:
            threats.append(autorun_threat)

        # Layer 2: Recursive file tree inspection (Heuristics & Signatures)
        for root, dirs, files in os.walk(target_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                files_scanned += 1
                
                # Check for threats on this file
                detected = self._inspect_file(file_path, filename)
                if detected:
                    threats.extend(detected)

        # Layer 3: Windows Defender Engine Scan (if available and enabled)
        if self.config.get("enable_defender_scan", True):
            defender_threats = self._run_defender_scan(target_path)
            threats.extend(defender_threats)

        # Remove duplicate detections for the same file
        deduped_threats = self._deduplicate_threats(threats)

        # Handle Quarantine
        if auto_quarantine:
            for threat in deduped_threats:
                if threat.get("file_path") and os.path.exists(threat["file_path"]):
                    success, msg = self.quarantine_vault.isolate(threat["file_path"], threat)
                    if success:
                        threat["quarantined"] = True
                        print(f"[!] QUARANTINED: {threat['file_path']} -> {msg}")
                    else:
                        print(f"[x] Failed to quarantine {threat['file_path']}: {msg}")

        duration = round(time.time() - start_time, 2)

        # Build scan result
        scan_result = {
            "target": target_path,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "files_scanned": files_scanned,
            "threats_count": len(deduped_threats),
            "threats": deduped_threats,
            "duration_seconds": duration,
            "auto_quarantine": auto_quarantine
        }

        # Generate Reports
        json_report, html_report = self.reporter.generate_reports(scan_result)

        # Alerting
        if deduped_threats:
            if self.config.get("enable_audio_alert", True):
                Notifier.play_alert("CRITICAL")
            if self.config.get("enable_desktop_notifications", True):
                Notifier.show_desktop_notification(
                    "USB-Sentinel Threat Alert!",
                    f"Found {len(deduped_threats)} threat(s) on {target_path}!",
                    is_threat=True
                )
        else:
            if self.config.get("enable_desktop_notifications", True):
                Notifier.show_desktop_notification(
                    "USB-Sentinel: Drive Clean",
                    f"Scanned {files_scanned} files on {target_path}. No threats found.",
                    is_threat=False
                )

        self._print_summary(scan_result, json_report, html_report)
        return scan_result

    def _inspect_autorun(self, drive_root):
        """Analyzes autorun.inf files for worm propagation directives (MITRE T1091)."""
        autorun_path = os.path.join(drive_root, "autorun.inf")
        if not os.path.exists(autorun_path):
            return None

        try:
            with open(autorun_path, "r", errors="ignore") as f:
                content = f.read()

            suspicious_patterns = [r"open\s*=", r"shellexecute\s*=", r"shell\\.+command\s*="]
            for pattern in suspicious_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    sha256 = self._compute_hash(autorun_path)
                    return {
                        "file_path": autorun_path,
                        "threat_name": "USB.AutoRun.WormVector",
                        "threat_type": ThreatCategory.AUTORUN_WORM,
                        "severity": "CRITICAL",
                        "mitre_attack": "T1091 - Replication via Removable Media",
                        "description": "Suspicious execution directive in autorun.inf commonly used by USB worms.",
                        "sha256": sha256,
                        "quarantined": False
                    }
        except Exception:
            pass
        return None

    def _inspect_file(self, file_path, filename):
        """Evaluates heuristics, double extensions, weaponized shortcuts, and file hashes."""
        threats = []
        lower_name = filename.lower()
        _, ext = os.path.splitext(lower_name)

        # 1. Double Extension Detection (e.g. invoice.pdf.exe) (MITRE T1204.002)
        parts = lower_name.split(".")
        if len(parts) >= 3:
            second_last = "." + parts[-2]
            last_ext = "." + parts[-1]
            if last_ext in self.suspicious_exts and second_last in self.double_ext_targets:
                sha = self._compute_hash(file_path)
                threats.append({
                    "file_path": file_path,
                    "threat_name": "Heuristic.DoubleExtension.Spoof",
                    "threat_type": ThreatCategory.DOUBLE_EXTENSION,
                    "severity": "CRITICAL",
                    "mitre_attack": "T1204.002 - Malicious File / Masquerading",
                    "description": f"File uses spoofed double extension ({second_last}{last_ext}) to disguise executable payload.",
                    "sha256": sha,
                    "quarantined": False
                })

        # 2. Weaponized Shortcut Analysis (.lnk files) (MITRE T1059 / T1204)
        if ext == ".lnk":
            try:
                with open(file_path, "rb") as f:
                    sample = f.read(4096)
                sample_str = sample.decode("ascii", errors="ignore").lower()
                cmd_indicators = ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "certutil", "bitsadmin"]
                if any(ind in sample_str for ind in cmd_indicators):
                    sha = self._compute_hash(file_path)
                    threats.append({
                        "file_path": file_path,
                        "threat_name": "USB.WeaponizedShortcut.LNK",
                        "threat_type": ThreatCategory.SUSPICIOUS_SHORTCUT,
                        "severity": "HIGH",
                        "mitre_attack": "T1059 - Command & Scripting Interpreter",
                        "description": "LNK shortcut invokes command shells or scripting interpreters commonly used in USB dropper worms.",
                        "sha256": sha,
                        "quarantined": False
                    })
            except Exception:
                pass

        # 3. Hidden Executable Attribute Check
        if sys.platform == "win32" and ext in self.suspicious_exts:
            try:
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
                # FILE_ATTRIBUTE_HIDDEN = 0x2, FILE_ATTRIBUTE_SYSTEM = 0x4
                if attrs != -1 and (attrs & 0x2 or attrs & 0x4):
                    sha = self._compute_hash(file_path)
                    threats.append({
                        "file_path": file_path,
                        "threat_name": "Heuristic.HiddenExecutable",
                        "threat_type": ThreatCategory.HIDDEN_EXECUTABLE,
                        "severity": "HIGH",
                        "mitre_attack": "T1564.001 - Hidden Files & Directories",
                        "description": "Executable file has HIDDEN or SYSTEM filesystem attributes enabled.",
                        "sha256": sha,
                        "quarantined": False
                    })
            except Exception:
                pass

        # 4. Hash & EICAR Signature Check
        try:
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            max_size = self.config.get("max_file_size_mb", 100)

            if file_size_mb <= max_size:
                # EICAR Check
                with open(file_path, "rb") as f:
                    file_bytes = f.read(512)
                    if EICAR_SIGNATURE in file_bytes or file_bytes.startswith(b"X5O!P%@AP[4\\PZX54"):
                        sha = self._compute_hash(file_path)
                        threats.append({
                            "file_path": file_path,
                            "threat_name": "EICAR.Standard.AV.TestFile",
                            "threat_type": ThreatCategory.EICAR_TEST,
                            "severity": "HIGH",
                            "mitre_attack": "Test.Validation",
                            "description": "Standard Antivirus Test File signature detected.",
                            "sha256": sha,
                            "quarantined": False
                        })

                # Known Hash Blacklist Check
                sha256, md5 = self._compute_both_hashes(file_path)
                if sha256 in self.known_hashes or md5 in self.known_hashes:
                    matched_name = self.known_hashes.get(sha256) or self.known_hashes.get(md5)
                    threats.append({
                        "file_path": file_path,
                        "threat_name": f"Malware.HashMatch: {matched_name}",
                        "threat_type": ThreatCategory.HASH_MATCH,
                        "severity": "CRITICAL",
                        "mitre_attack": "T1204.002 - Known Malicious Payload",
                        "description": f"File hash matched threat intelligence database: {matched_name}",
                        "sha256": sha256,
                        "quarantined": False
                    })
        except Exception:
            pass

        return threats

    def _run_defender_scan(self, target_path):
        """Invokes Microsoft Defender CLI engine if installed on Windows."""
        defender_path = self.config.get("defender_path", r"C:\Program Files\Windows Defender\MpCmdRun.exe")
        if not os.path.exists(defender_path):
            return []

        threats = []
        try:
            print("[*] Running Windows Defender engine scan...")
            cmd = [defender_path, "-Scan", "-ScanType", "3", "-File", target_path, "-DisableRemediation"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            # Returncode 2 indicates Defender found a threat
            if result.returncode == 2 or "threat" in result.stdout.lower():
                # Parse stdout for threat detections
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if "threat" in line.lower() or "file:" in line.lower():
                        threats.append({
                            "file_path": target_path,
                            "threat_name": f"WinDefender: {line}",
                            "threat_type": ThreatCategory.DEFENDER_DETECTION,
                            "severity": "CRITICAL",
                            "mitre_attack": "AV.MicrosoftDefender",
                            "description": f"Windows Defender reported: {line}",
                            "sha256": "N/A",
                            "quarantined": False
                        })
        except Exception as e:
            print(f"[!] Warning: Windows Defender scan failed or timed out: {e}")

        return threats

    def _compute_hash(self, file_path):
        try:
            hasher = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return "N/A"

    def _compute_both_hashes(self, file_path):
        try:
            sha = hashlib.sha256()
            md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha.update(chunk)
                    md5.update(chunk)
            return sha.hexdigest(), md5.hexdigest()
        except Exception:
            return "N/A", "N/A"

    def _deduplicate_threats(self, threats):
        unique = {}
        for t in threats:
            key = (t.get("file_path"), t.get("threat_name"))
            if key not in unique:
                unique[key] = t
        return list(unique.values())

    def _print_summary(self, result, json_path, html_path):
        print("\n" + "=" * 56)
        print("SCAN SUMMARY REPORT")
        print("=" * 56)
        print(f"Target Scanned   : {result['target']}")
        print(f"Files Inspected  : {result['files_scanned']}")
        print(f"Threats Detected : {result['threats_count']}")
        print(f"Scan Duration    : {result['duration_seconds']} seconds")

        if result["threats"]:
            print("\n[!] DETECTED THREAT DETAILS:")
            for i, t in enumerate(result["threats"], 1):
                status = "[QUARANTINED]" if t.get("quarantined") else "[DETECTED]"
                print(f"  {i}. {status} {t['threat_name']} ({t['severity']})")
                print(f"     Path : {t['file_path']}")
                print(f"     MITRE: {t.get('mitre_attack', 'N/A')}")
        else:
            print("\n[+] DRIVE VERIFIED CLEAN. No indicators of compromise found.")

        print(f"\n[+] JSON Report : {json_path}")
        print(f"[+] HTML Report : {html_path}")
        print("=" * 56 + "\n")
