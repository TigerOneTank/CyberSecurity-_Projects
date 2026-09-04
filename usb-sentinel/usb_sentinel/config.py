import os
import json

DEFAULT_CONFIG = {
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
    def __init__(self, config_file="config.json"):
        self.config_file = config_file
        self.data = DEFAULT_CONFIG.copy()
        self.load()

    def load(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8-sig") as f:
                    user_data = json.load(f)
                    self.data.update(user_data)
            except Exception as e:
                print(f"[!] Warning: Could not load {self.config_file}: {e}. Using defaults.")

    def get(self, key, default=None):
        return self.data.get(key, default if default is not None else DEFAULT_CONFIG.get(key))

    def save(self):
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=4)
        except Exception as e:
            print(f"[!] Warning: Could not save {self.config_file}: {e}")
