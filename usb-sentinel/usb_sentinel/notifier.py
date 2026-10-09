import sys
import subprocess
import threading

class Notifier:
    @staticmethod
    def play_alert(severity="HIGH"):
        if sys.platform != "win32":
            return
        try:
            import winsound
            if severity in ("CRITICAL", "HIGH"):
                winsound.Beep(1200, 140)
                winsound.Beep(1550, 220)
            else:
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        except Exception:
            pass

    @staticmethod
    def show_desktop_notification(title, msg, is_alert=False):
        if sys.platform != "win32":
            return

        def _fire():
            try:
                # Spawn lightweight notification balloon via WinForms assembly
                ps_cmd = f"""
                [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null
                $toast = New-Object System.Windows.Forms.NotifyIcon
                $toast.Icon = if ('{is_alert}' -eq 'True') {{ [System.Drawing.SystemIcons]::Warning }} else {{ [System.Drawing.SystemIcons]::Information }}
                $toast.BalloonTipTitle = '{title}'
                $toast.BalloonTipText = '{msg}'
                $toast.Visible = $True
                $toast.ShowBalloonTip(4500)
                Start-Sleep -Seconds 2
                $toast.Dispose()
                """
                subprocess.run(
                    ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_cmd],
                    capture_output=True,
                    timeout=7
                )
            except Exception:
                pass

        threading.Thread(target=_fire, daemon=True).start()
