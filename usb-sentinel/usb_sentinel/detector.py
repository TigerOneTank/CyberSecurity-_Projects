import sys
import os
import time
import shutil

DRIVE_REMOVABLE = 2

class DriveDetector:
    @staticmethod
    def get_drive_details(root):
        info = {
            "root": root,
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

                ok = ctypes.windll.kernel32.GetVolumeInformationW(
                    ctypes.c_wchar_p(root),
                    vol_buf,
                    ctypes.sizeof(vol_buf),
                    ctypes.byref(serial),
                    ctypes.byref(max_len),
                    ctypes.byref(flags),
                    fs_buf,
                    ctypes.sizeof(fs_buf)
                )
                if ok:
                    info["volume_name"] = vol_buf.value or "Removable Disk"
                    info["filesystem"] = fs_buf.value or "Unknown"
            except Exception:
                pass

        try:
            usage = shutil.disk_usage(root)
            info["total_bytes"] = usage.total
            info["free_bytes"] = usage.free
            info["total_gb"] = round(usage.total / (1024 ** 3), 2)
            info["free_gb"] = round(usage.free / (1024 ** 3), 2)
        except OSError:
            pass

        return info

    @classmethod
    def get_removable_drives(cls):
        if sys.platform != "win32":
            return []

        import ctypes
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        active = []
        for bit in range(26):
            if not (mask & (1 << bit)):
                continue
            root = f"{chr(65 + bit)}:\\"
            if ctypes.windll.kernel32.GetDriveTypeW(root) == DRIVE_REMOVABLE:
                active.append(cls.get_drive_details(root))
        return active


class DriveWatcher:
    def __init__(self, poll_interval=2, on_connect=None, on_disconnect=None):
        self.interval = poll_interval
        self.on_connect = on_connect
        self.on_disconnect = on_disconnect
        self._alive = False
        self._seen = set()

    def start(self):
        self._alive = True
        self._seen = {d["root"] for d in DriveDetector.get_removable_drives()}

        print(f"[*] USB-Sentinel watcher armed ({self.interval}s poll).")
        if self._seen:
            print(f"[*] Mounted removable drives: {', '.join(sorted(self._seen))}")
        else:
            print("[*] Standing by for media insertion...")

        try:
            while self._alive:
                time.sleep(self.interval)
                mounted = {d["root"]: d for d in DriveDetector.get_removable_drives()}
                current_roots = set(mounted.keys())

                for added in (current_roots - self._seen):
                    entry = mounted[added]
                    print(f"\n[+] MEDIA ATTACHED: {added} ({entry['volume_name']})")
                    if self.on_connect:
                        self.on_connect(entry)

                for dropped in (self._seen - current_roots):
                    print(f"\n[-] MEDIA EJECTED: {dropped}")
                    if self.on_disconnect:
                        self.on_disconnect(dropped)

                self._seen = current_roots
        except KeyboardInterrupt:
            print("\n[*] Watcher terminated by user.")
            self.stop()

    def stop(self):
        self._alive = False
