import os
import shutil
import json
import time
import stat

class QuarantineVault:
    def __init__(self, target_dir="quarantine"):
        self.vault_path = os.path.abspath(target_dir)
        os.makedirs(self.vault_path, exist_ok=True)

    def isolate(self, fpath, threat):
        if not os.path.exists(fpath):
            return False, "Target file missing on disk"

        try:
            name = os.path.basename(fpath)
            digest = threat.get("sha256", "nohash")[:12]
            epoch = int(time.time())
            quarantined_name = f"{epoch}_{digest}_{name}.quarantined"
            dest = os.path.join(self.vault_path, quarantined_name)
            meta_dest = dest + ".meta.json"

            file_size = os.path.getsize(fpath)
            shutil.move(fpath, dest)

            # Strip write/exec bits so it cannot be launched by accident
            try:
                os.chmod(dest, stat.S_IREAD)
            except OSError:
                pass

            manifest = {
                "original_path": fpath,
                "original_filename": name,
                "quarantined_file": quarantined_name,
                "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "threat_name": threat.get("threat_name", "Generic.Threat"),
                "threat_type": threat.get("threat_type", "GENERIC"),
                "severity": threat.get("severity", "HIGH"),
                "sha256": threat.get("sha256", ""),
                "size_bytes": file_size
            }

            with open(meta_dest, "w", encoding="utf-8") as fh:
                json.dump(manifest, fh, indent=4)

            return True, dest
        except Exception as err:
            return False, str(err)

    def list_quarantined(self):
        if not os.path.exists(self.vault_path):
            return []

        entries = []
        for item in os.listdir(self.vault_path):
            if not item.endswith(".meta.json"):
                continue
            meta_file = os.path.join(self.vault_path, item)
            try:
                with open(meta_file, "r", encoding="utf-8") as fh:
                    entries.append(json.load(fh))
            except (json.JSONDecodeError, OSError):
                continue
        return entries

    def restore(self, quarantined_name, custom_dest=None):
        meta_file = os.path.join(self.vault_path, quarantined_name + ".meta.json")
        vault_file = os.path.join(self.vault_path, quarantined_name)

        if not (os.path.exists(vault_file) and os.path.exists(meta_file)):
            return False, "Target archive or manifest missing from vault"

        try:
            with open(meta_file, "r", encoding="utf-8") as fh:
                manifest = json.load(fh)

            restore_target = custom_dest or manifest.get("original_path")
            parent = os.path.dirname(restore_target)
            if parent:
                os.makedirs(parent, exist_ok=True)

            os.chmod(vault_file, stat.S_IWRITE | stat.S_IREAD)
            shutil.move(vault_file, restore_target)
            os.remove(meta_file)
            return True, f"Restored -> {restore_target}"
        except Exception as err:
            return False, f"Restore failed: {err}"
