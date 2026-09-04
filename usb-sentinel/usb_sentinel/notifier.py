import sys
import subprocess
import threading

class Notifier:
    """Manages system alerts, audio warnings, and desktop notifications."""
    
    @staticmethod
    def play_alert(severity="HIGH"):
        """Plays an audible security alert tone."""
        if sys.platform != "win32":
            return
        try:
            import winsound
            if severity in ("CRITICAL", "HIGH"):
                # Double high-pitch warning beep
                winsound.Beep(1200, 150)
                winsound.Beep(1600, 250)
            else:
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        except Exception:
            pass

    @staticmethod
    def show_desktop_notification(title, message, is_threat=False):
        """Displays a native Windows toast notification."""
        if sys.platform != "win32":
            return

        def _notify_thread():
            try:
                # Use PowerShell toast/balloon notification
                ps_script = f"""
                [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null
                $notify = New-Object System.Windows.Forms.NotifyIcon
                $notify.Icon = [System.Drawing.SystemIcons]::Information
                if ('{is_threat}' -eq 'True') {{
                    $notify.Icon = [System.Drawing.SystemIcons]::Warning
                }}
                $notify.BalloonTipTitle = '{title}'
                $notify.BalloonTipText = '{message}'
                $notify.Visible = $True
                $notify.ShowBalloonTip(5000)
                Start-Sleep -Seconds 3
                $notify.Dispose()
                """
                subprocess.run(
                    ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_script],
                    capture_output=True,
                    timeout=8
                )
            except Exception:
                pass

        threading.Thread(target=_notify_thread, daemon=True).start()
