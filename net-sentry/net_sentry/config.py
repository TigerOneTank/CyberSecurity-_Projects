import os
import json

DEFAULTS = {
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
    def __init__(self, path="config.json"):
        self.path = path
        self.data = dict(DEFAULTS)
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8-sig") as fh:
                self.data.update(json.load(fh))
        except (json.JSONDecodeError, OSError) as err:
            print(f"[!] Warning: failed reading {self.path} ({err}), using defaults")

    def get(self, key, fallback=None):
        return self.data.get(key, fallback if fallback is not None else DEFAULTS.get(key))
