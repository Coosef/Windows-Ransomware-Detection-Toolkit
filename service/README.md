# Running the live monitor in the background

By default the live monitor runs in a console window you keep open. To make it an
always-on guard that survives reboots, install it as a background service for your OS.

| OS | File | Install |
|----|------|---------|
| **Windows** | `Install-WindowsTask.ps1` | `.\service\Install-WindowsTask.ps1 -Path 'D:\Important'` (elevated). Remove with `-Uninstall`. |
| **Linux** | `ransomware-monitor.service` | edit paths/user, then `sudo cp` to `/etc/systemd/system/`, `systemctl enable --now ransomware-monitor` |
| **macOS** | `com.wrdt.monitor.plist` | edit paths, `cp` to `~/Library/LaunchAgents/`, `launchctl load` it |

Each template has step-by-step comments at the top.

## Alerts while unattended

Pair the background service with notifications so alarms reach you even when nobody
is watching the screen. Add a webhook (Slack/Discord/Teams/custom) or Telegram:

```
--notify-webhook https://hooks.example.com/...           # any engine
--notify-telegram-token <bot-token> --notify-telegram-chat <chat-id>   # Python
-NotifyWebhook https://hooks.example.com/...             # PowerShell
```

or set them once in `toolkit.config.json` (see `toolkit.config.example.json`).

## Opt-in containment (advanced, disruptive)

`--contain killproc,network,lock` (Python) / `-Contain "killproc,network,lock"`
(PowerShell) makes the monitor try to STOP the attack on alarm - kill the offending
process, disable the network, and/or lock the session. **Off by default.** These are
deliberately disruptive; test in a safe environment before enabling on production.
