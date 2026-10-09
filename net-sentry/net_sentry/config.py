import os
import json

DEFAULT_CONFIG = {
    "port_scan_threshold_ports": 15,
    "port_scan_window_seconds": 5.0,
    "syn_flood_threshold_packets": 40,
    "dns_entropy_threshold": 3.8,
    "dns_length_threshold": 45,
    "pcap_capture_dir": "captures",
    "reports_dir": "reports",
    "enable_pcap_dump": True,
    "enable_audio_alert": True,
    "enable_desktop_notifications": True
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
