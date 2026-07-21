<#
.SYNOPSIS
    Install (or remove) a Scheduled Task that runs the live monitor in the
    background at logon, so it survives reboots without a visible window.

.EXAMPLE
    # From the toolkit folder, in an elevated PowerShell:
    .\service\Install-WindowsTask.ps1 -Path 'D:\Important'

.EXAMPLE
    .\service\Install-WindowsTask.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string[]]$Path,                 # folders to watch (default: the user's key folders)
    [string]$NotifyWebhook,          # optional: forward alarms to a webhook
    [switch]$Uninstall,
    [string]$TaskName = 'RansomwareMonitor'
)

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Removed scheduled task '$TaskName'." -ForegroundColor Green
    return
}

$toolkit = Join-Path (Split-Path $PSScriptRoot -Parent) 'RansomwareToolkit.ps1'
if (-not (Test-Path $toolkit)) { throw "RansomwareToolkit.ps1 not found next to the service folder." }

$argList = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$toolkit`" -Mode Watch"
if ($Path)          { $argList += " -Path " + (($Path | ForEach-Object { "`"$_`"" }) -join ',') }
if ($NotifyWebhook) { $argList += " -NotifyWebhook `"$NotifyWebhook`"" }

$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argList
$trigger   = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Limited
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Host "Installed scheduled task '$TaskName' (runs the monitor at logon)." -ForegroundColor Green
Write-Host "Start it now with:  Start-ScheduledTask -TaskName $TaskName" -ForegroundColor Gray
