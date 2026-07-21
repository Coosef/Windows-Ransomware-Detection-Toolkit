<#
.SYNOPSIS
    Install (or remove) a Scheduled Task that runs a Quick scan on a schedule and
    writes a report. Point the reports at a shared folder and feed them to the
    fleet dashboard (--mode fleet) to review 50-60 machines centrally.

.EXAMPLE
    .\service\Install-WindowsScanTask.ps1 -At '03:00' -OutputDir '\\server\ransomware-reports'

.EXAMPLE
    .\service\Install-WindowsScanTask.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$At = '03:00',                 # daily time
    [ValidateSet('Quick','Full')] [string]$ScanMode = 'Quick',
    [string]$OutputDir,                    # where to write reports (e.g. a network share)
    [string]$NotifyWebhook,
    [switch]$Uninstall,
    [string]$TaskName = 'RansomwareScan'
)

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Removed scheduled task '$TaskName'." -ForegroundColor Green
    return
}

$toolkit = Join-Path (Split-Path $PSScriptRoot -Parent) 'RansomwareToolkit.ps1'
if (-not (Test-Path $toolkit)) { throw "RansomwareToolkit.ps1 not found next to the service folder." }

$argList = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$toolkit`" -Mode $ScanMode"
if ($OutputDir)     { $argList += " -OutputDir `"$OutputDir`"" }
if ($NotifyWebhook) { $argList += " -NotifyWebhook `"$NotifyWebhook`"" }

$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argList
$trigger   = New-ScheduledTaskTrigger -Daily -At $At
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest   # Full scans want admin
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Host "Installed scheduled task '$TaskName' (runs a $ScanMode scan daily at $At)." -ForegroundColor Green
