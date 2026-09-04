import os
import sys
import tempfile
import shutil
import unittest

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from usb_sentinel.config import Config
from usb_sentinel.scanner import USBScanner, EICAR_SIGNATURE, ThreatCategory
from usb_sentinel.quarantine import QuarantineVault
from usb_sentinel.reporter import ScanReporter

class TestUSBSentinel(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="usb_test_")
        self.vault_dir = os.path.join(self.test_dir, "vault")
        self.reports_dir = os.path.join(self.test_dir, "reports")
        self.scan_target = os.path.join(self.test_dir, "target")
        os.makedirs(self.scan_target, exist_ok=True)

        self.config = Config()
        self.config.data["quarantine_dir"] = self.vault_dir
        self.config.data["reports_dir"] = self.reports_dir
        self.config.data["enable_defender_scan"] = False  # Disable in unit tests for speed and determinism
        self.config.data["enable_desktop_notifications"] = False
        self.config.data["enable_audio_alert"] = False

        self.scanner = USBScanner(self.config)

    def tearDown(self):
        try:
            shutil.rmtree(self.test_dir, ignore_errors=True)
        except Exception:
            pass

    def test_clean_directory(self):
        """Verifies that legitimate files are not falsely flagged."""
        clean_file = os.path.join(self.scan_target, "readme.txt")
        with open(clean_file, "w") as f:
            f.write("Legitimate documentation file.")

        result = self.scanner.scan_path(self.scan_target)
        self.assertEqual(result["threats_count"], 0)
        self.assertEqual(result["files_scanned"], 1)

    def test_autorun_detection(self):
        """Verifies detection of malicious autorun.inf execution directives."""
        autorun_file = os.path.join(self.scan_target, "autorun.inf")
        with open(autorun_file, "w") as f:
            f.write("[AutoRun]\nopen=worm.exe\nicon=drive.ico\n")

        result = self.scanner.scan_path(self.scan_target)
        self.assertGreaterEqual(result["threats_count"], 1)
        threat_types = [t["threat_type"] for t in result["threats"]]
        self.assertIn(ThreatCategory.AUTORUN_WORM, threat_types)

    def test_double_extension_detection(self):
        """Verifies detection of masquerading double extensions."""
        spoofed_file = os.path.join(self.scan_target, "Quarterly_Bonus.pdf.exe")
        with open(spoofed_file, "wb") as f:
            f.write(b"MZfakebinarycontent")

        result = self.scanner.scan_path(self.scan_target)
        self.assertGreaterEqual(result["threats_count"], 1)
        threat_types = [t["threat_type"] for t in result["threats"]]
        self.assertIn(ThreatCategory.DOUBLE_EXTENSION, threat_types)

    def test_eicar_signature_detection(self):
        """Verifies detection of EICAR standard antivirus test signature."""
        eicar_file = os.path.join(self.scan_target, "test_eicar.com")
        with open(eicar_file, "wb") as f:
            f.write(EICAR_SIGNATURE)

        result = self.scanner.scan_path(self.scan_target)
        self.assertGreaterEqual(result["threats_count"], 1)
        threat_types = [t["threat_type"] for t in result["threats"]]
        self.assertIn(ThreatCategory.EICAR_TEST, threat_types)

    def test_quarantine_isolation_and_restore(self):
        """Verifies quarantine isolation and restoration workflow."""
        sample_threat = os.path.join(self.scan_target, "invoice.pdf.vbs")
        with open(sample_threat, "w") as f:
            f.write("Wscript.Echo 'Simulated malicious payload'")

        vault = QuarantineVault(self.vault_dir)
        threat_info = {
            "threat_name": "Test.Script.Threat",
            "threat_type": "VBS_DROPPER",
            "severity": "HIGH",
            "sha256": "abcdef1234567890abcdef1234567890"
        }

        # Isolate
        success, vault_path = vault.isolate(sample_threat, threat_info)
        self.assertTrue(success)
        self.assertFalse(os.path.exists(sample_threat))
        self.assertTrue(os.path.exists(vault_path))

        # Check inventory
        items = vault.list_quarantined()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["original_filename"], "invoice.pdf.vbs")

        # Restore
        quarantined_name = os.path.basename(vault_path)
        restored, msg = vault.restore(quarantined_name)
        self.assertTrue(restored)
        self.assertTrue(os.path.exists(sample_threat))

    def test_reporter_generation(self):
        """Verifies JSON and HTML report file creation."""
        reporter = ScanReporter(self.reports_dir)
        mock_result = {
            "target": self.scan_target,
            "timestamp": "2026-09-04 12:00:00",
            "files_scanned": 10,
            "threats_count": 0,
            "threats": [],
            "duration_seconds": 0.42
        }
        json_file, html_file = reporter.generate_reports(mock_result)
        self.assertTrue(os.path.exists(json_file))
        self.assertTrue(os.path.exists(html_file))
        with open(html_file, "r", encoding="utf-8") as f:
            html_text = f.read()
            self.assertIn("USB-Sentinel Forensic Scan Report", html_text)

if __name__ == "__main__":
    unittest.main()
