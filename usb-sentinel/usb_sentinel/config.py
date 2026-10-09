import os
import json

DEFAULTS = {
    "poll_interval_seconds": 2,
    "auto_quarantine": False,
    "quarantine_dir": "quarantine",
    "reports_dir": "reports",
    "enable_defender_scan": True,
    "defender_path": r"C:\Program Files\Windows Defender\MpCmdRun.exe",
    "enable_desktop_notifications": True,
    "enable_audio_alert": True,
    "max_file_size_mb": 100,
    "suspicious_extensions": [
        ".exe", ".scr", ".vbs", ".bat", ".cmd", 
        ".ps1", ".hta", ".pif", ".jar", ".com", ".wsf", ".lnk"
    ],
    "double_extension_targets": [
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", 
        ".jpg", ".jpeg", ".png", ".txt", ".mp4", ".zip", ".rar"
    ],
    "known_malicious_hashes": {
        "44d88612fea8a8f36de82e1278abb02f": "EICAR-Standard-AV-Test (MD5)",
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Standard-AV-Test (SHA-256)"
    }
}

class Config:
    def __init__(self, cfg_path="config.json"):
        self.cfg_path = cfg_path
        self.data = dict(DEFAULTS)
        self.reload()

    def reload(self):
        if not os.path.exists(self.cfg_path):
            return
        try:
            with open(self.cfg_path, "r", encoding="utf-8-sig") as fh:
                self.data.update(json.load(fh))
        except (json.JSONDecodeError, OSError) as err:
            print(f"[!] bad config ({self.cfg_path}): {err}, falling back to defaults")

    def get(self, key, fallback=None):
        return self.data.get(key, fallback if fallback is not None else DEFAULTS.get(key))

    def save(self):
        with open(self.cfg_path, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=4)
