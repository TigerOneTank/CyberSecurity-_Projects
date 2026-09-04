import sys
import os
import time
import shutil

DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6

class DriveDetector:
    """Detects connected removable drives and monitors drive insertion events."""
    
    @staticmethod
    def get_drive_details(drive_root):
        """Retrieves volume label, filesystem type, and storage capacity."""
        details = {
            "root": drive_root,
            "volume_name": "Removable Disk",
            "filesystem": "Unknown",
            "total_bytes": 0,
            "free_bytes": 0,
            "total_gb": 0.0,
            "free_gb": 0.0
        }

        if sys.platform == "win32":
            try:
                import ctypes
                vol_buf = ctypes.create_unicode_buffer(261)
                fs_buf = ctypes.create_unicode_buffer(261)
                serial = ctypes.c_ulong()
                max_len = ctypes.c_ulong()
                flags = ctypes.c_ulong()

                res = ctypes.windll.kernel32.GetVolumeInformationW(
                    ctypes.c_wchar_p(drive_root),
                    vol_buf,
                    ctypes.sizeof(vol_buf),
                    ctypes.byref(serial),
                    ctypes.byref(max_len),
                    ctypes.byref(flags),
                    fs_buf,
                    ctypes.sizeof(fs_buf)
                )
                if res:
                    details["volume_name"] = vol_buf.value or "Removable Disk"
                    details["filesystem"] = fs_buf.value or "Unknown"
            except Exception:
                pass

        try:
            usage = shutil.disk_usage(drive_root)
            details["total_bytes"] = usage.total
            details["free_bytes"] = usage.free
            details["total_gb"] = round(usage.total / (1024 ** 3), 2)
            details["free_gb"] = round(usage.free / (1024 ** 3), 2)
        except Exception:
            pass

        return details

    @classmethod
    def get_removable_drives(cls):
        """Returns a list of drive details for all currently mounted removable drives."""
        removable = []
        if sys.platform != "win32":
            return removable

        import ctypes
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                drive_letter = chr(65 + i)
                drive_root = f"{drive_letter}:\\"
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_root)
                if drive_type == DRIVE_REMOVABLE:
                    removable.append(cls.get_drive_details(drive_root))
        return removable


class DriveWatcher:
    """Watches for insertion or removal of removable drives in real time."""
    
    def __init__(self, poll_interval=2, on_connect=None, on_disconnect=None):
        self.poll_interval = poll_interval
        self.on_connect = on_connect
        self.on_disconnect = on_disconnect
        self._running = False
        self._known_drives = set()

    def start(self):
        """Starts polling loop in foreground (blocking)."""
        self._running = True
        # Initialize with currently existing removable drives
        initial_drives = DriveDetector.get_removable_drives()
        self._known_drives = {d["root"] for d in initial_drives}

        print(f"[*] USB-Sentinel Watcher active (Polling every {self.poll_interval}s).")
        if self._known_drives:
            print(f"[*] Currently attached removable drive(s): {', '.join(self._known_drives)}")
        else:
            print("[*] Waiting for USB / External drive connection...")

        try:
            while self._running:
                time.sleep(self.poll_interval)
                current_drives = DriveDetector.get_removable_drives()
                current_roots = {d["root"]: d for d in current_drives}
                current_set = set(current_roots.keys())

                # New drive connected
                new_roots = current_set - self._known_drives
                for root in new_roots:
                    drive_info = current_roots[root]
                    print(f"\n[+] NEW DRIVE DETECTED: {root} ({drive_info['volume_name']})")
                    if self.on_connect:
                        self.on_connect(drive_info)

                # Drive disconnected
                removed_roots = self._known_drives - current_set
                for root in removed_roots:
                    print(f"\n[-] DRIVE REMOVED: {root}")
                    if self.on_disconnect:
                        self.on_disconnect(root)

                self._known_drives = current_set
        except KeyboardInterrupt:
            print("\n[*] Stopping drive watcher...")
            self.stop()

    def stop(self):
        self._running = False
