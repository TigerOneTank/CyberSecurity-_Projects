import os
import shutil
import json
import time
import stat

class QuarantineVault:
    """Safely isolates and neutralizes detected malware from external drives."""
    
    def __init__(self, vault_dir="quarantine"):
        self.vault_dir = os.path.abspath(vault_dir)
        os.makedirs(self.vault_dir, exist_ok=True)

    def isolate(self, file_path, threat_info):
        """
        Moves the target file to the vault, renames it with .quarantined,
        sets read-only permission, and saves forensic metadata.
        """
        if not os.path.exists(file_path):
            return False, "File does not exist or was already removed."

        try:
            filename = os.path.basename(file_path)
            sha = threat_info.get("sha256", "nohash")[:12]
            timestamp = int(time.time())
            quarantined_name = f"{timestamp}_{sha}_{filename}.quarantined"
            target_vault_path = os.path.join(self.vault_dir, quarantined_name)
            meta_path = target_vault_path + ".meta.json"

            file_size = os.path.getsize(file_path)

            # Move file into vault
            shutil.move(file_path, target_vault_path)

            # Strip write/execute permissions (Read-only)
            try:
                os.chmod(target_vault_path, stat.S_IREAD)
            except Exception:
                pass

            # Store metadata
            meta = {
                "original_path": file_path,
                "original_filename": filename,
                "quarantined_file": quarantined_name,
                "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "threat_name": threat_info.get("threat_name", "Unknown Threat"),
                "threat_type": threat_info.get("threat_type", "GENERIC"),
                "severity": threat_info.get("severity", "HIGH"),
                "sha256": threat_info.get("sha256", ""),
                "size_bytes": file_size
            }

            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=4)

            return True, target_vault_path
        except Exception as e:
            return False, str(e)

    def list_quarantined(self):
        """Returns a list of all quarantined files with their metadata."""
        items = []
        if not os.path.exists(self.vault_dir):
            return items

        for fname in os.listdir(self.vault_dir):
            if fname.endswith(".meta.json"):
                meta_path = os.path.join(self.vault_dir, fname)
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        items.append(json.load(f))
                except Exception:
                    pass
        return items

    def restore(self, quarantined_name, restore_dir=None):
        """Restores a quarantined file if verified safe (false positive)."""
        meta_path = os.path.join(self.vault_dir, quarantined_name + ".meta.json")
        source_path = os.path.join(self.vault_dir, quarantined_name)

        if not os.path.exists(source_path) or not os.path.exists(meta_path):
            return False, "Quarantined item or metadata not found."

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)

            dest_path = restore_dir or meta.get("original_path")
            dest_dir = os.path.dirname(dest_path)
            if dest_dir:
                os.makedirs(dest_dir, exist_ok=True)

            # Restore read/write permission before moving
            os.chmod(source_path, stat.S_IWRITE | stat.S_IREAD)
            shutil.move(source_path, dest_path)
            os.remove(meta_path)
            return True, f"Restored to {dest_path}"
        except Exception as e:
            return False, f"Restore failed: {e}"
