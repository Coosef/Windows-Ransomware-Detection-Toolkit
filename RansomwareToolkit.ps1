<#
.SYNOPSIS
    Windows Ransomware Detection Toolkit - single, portable, read-only script.

.DESCRIPTION
    One script, two jobs (pick from the menu or with -Mode):

      SCAN   - walk the target paths ONCE and apply five detection layers to
               every file, then write TXT + JSON + HTML reports back to the USB.
                 1. Extension match      (data/extensions.txt)
                 2. Ransom-note name     (data/ransom-note-names.txt)
                 3. Ransom-note content  (data/note-keywords.txt)
                 4. Entropy analysis     (Shannon entropy -> likely encrypted)
                 5. Mass-change / spread (bursts, one-odd-extension folders,
                                          the same note dropped in many folders)

      WATCH  - real-time early warning: plant hidden canary decoy files and use
               FileSystemWatcher to alarm the instant something starts encrypting
               (canary tampering / change burst / suspicious file drop).

    Read-only and non-destructive: it never deletes, changes or quarantines your
    files (the only files it writes are its own reports and, in watch mode, its
    own canaries which it cleans up again).

.PARAMETER Mode
    Menu (default, interactive), Quick, Full, Custom, or Watch.

.PARAMETER Path
    Paths to scan (Custom mode) or folders to watch (Watch mode).

.EXAMPLE
    .\RansomwareToolkit.ps1                      # interactive menu
.EXAMPLE
    .\RansomwareToolkit.ps1 -Mode Quick -OpenReport
.EXAMPLE
    .\RansomwareToolkit.ps1 -Mode Custom -Path 'D:\Shares','E:\'
.EXAMPLE
    .\RansomwareToolkit.ps1 -Mode Watch -Path 'D:\Shares\Finance'

.NOTES
    Requires Windows PowerShell 5.1+ (built into Windows) or PowerShell 7.
    A supplement to - not a replacement for - professional AV/EDR.
#>
[CmdletBinding()]
param(
    [ValidateSet('Menu','Quick','Full','Custom','Watch','Update','Baseline','Diff','Fleet','Selftest')]
    [string]$Mode = 'Menu',
    [string[]]$Path,

    # --- scan tuning ---
    [int]$RecentHours = 24,
    [int]$MassChangeThreshold = 40,
    [switch]$NoEntropy,
    [int]$MaxFileSizeMB = 150,
    [double]$EntropyThreshold = 7.8,

    # --- watch tuning ---
    [int]$BurstThreshold = 25,
    [int]$BurstWindowSec = 5,

    # --- notifications / containment (group B) ---
    [string]$NotifyWebhook,
    [string]$NotifyTelegramToken,
    [string]$NotifyTelegramChat,
    [string]$Contain,          # opt-in, comma list: killproc,network,lock
    [string]$Syslog,           # forward alerts to a syslog collector (host:port, UDP)

    # --- common ---
    [string]$OutputDir,
    [string]$DataDir,
    [switch]$OpenReport
)

$ErrorActionPreference = 'Stop'

# --- Resolve toolkit root (works when launched by RunScan.bat, dot-sourced, etc.)
$ScriptRoot = $PSScriptRoot
if (-not $ScriptRoot) { $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $DataDir)   { $DataDir   = Join-Path $ScriptRoot 'data' }
if (-not $OutputDir) { $OutputDir = Join-Path $ScriptRoot 'reports' }
$ToolkitPath = $PSCommandPath
if (-not $ToolkitPath) { $ToolkitPath = Join-Path $ScriptRoot 'RansomwareToolkit.ps1' }

# OPTIONAL config: if toolkit.config.json exists next to the script, its values
# become the defaults for parameters you did NOT pass on the command line. Not
# required - the toolkit works out of the box without it.
$cfgFile = Join-Path $ScriptRoot 'toolkit.config.json'
if (Test-Path $cfgFile) {
    try {
        $cfgJson = Get-Content -LiteralPath $cfgFile -Raw | ConvertFrom-Json
        $map = @{
            recent_hours      = 'RecentHours';        mass_threshold  = 'MassChangeThreshold'
            entropy_threshold = 'EntropyThreshold';   max_mb          = 'MaxFileSizeMB'
            no_entropy        = 'NoEntropy';          burst_threshold = 'BurstThreshold'
            burst_window      = 'BurstWindowSec';     open_report     = 'OpenReport'
            notify_webhook    = 'NotifyWebhook';      notify_telegram_token = 'NotifyTelegramToken'
            notify_telegram_chat = 'NotifyTelegramChat'; contain      = 'Contain'; syslog = 'Syslog'
        }
        foreach ($k in $map.Keys) {
            $p = $map[$k]
            if (-not $PSBoundParameters.ContainsKey($p) -and ($cfgJson.PSObject.Properties.Name -contains $k)) {
                $v = $cfgJson.$k
                if ($p -in @('NoEntropy','OpenReport')) { Set-Variable -Name $p -Value ([bool]$v) }
                else { Set-Variable -Name $p -Value $v }
            }
        }
    } catch { Write-Host "[!] Could not read toolkit.config.json: $($_.Exception.Message)" -ForegroundColor Yellow }
}

# ===========================================================================
# Shared helpers
# ===========================================================================
function Write-Info  ($m) { Write-Host "[*] $m" -ForegroundColor Gray }
function Write-Ok    ($m) { Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn2 ($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Bad   ($m) { Write-Host "[X] $m" -ForegroundColor Red }

# Write UTF-8 WITHOUT a BOM. Windows PowerShell 5.1's "Set-Content -Encoding UTF8"
# prepends a BOM, which breaks standard JSON parsers / SIEM ingestion.
function Write-Utf8NoBom {
    param([string]$Path, [string]$Content)
    [System.IO.File]::WriteAllText($Path, [string]$Content, (New-Object System.Text.UTF8Encoding($false)))
}

function Test-IsAdmin {
    try {
        return ([Security.Principal.WindowsPrincipal] `
            [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Convert-WildcardToRegex {
    param([string]$Pattern)
    return ('^' + [regex]::Escape($Pattern).Replace('\*', '.*').Replace('\?', '.') + '$')
}

function Get-SystemInventory {
    # Best-effort machine inventory. Every field guarded so it never breaks a scan.
    # Handy when the same scan is run across many (50-60) devices.
    $inv = [ordered]@{}
    $inv.hostname = $env:COMPUTERNAME
    if (-not $inv.hostname) { try { $inv.hostname = [System.Net.Dns]::GetHostName() } catch { $inv.hostname = 'unknown' } }
    try { $inv.fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { $inv.fqdn = '' }
    $inv.os = ''; $inv.os_version = ''; $inv.arch = $env:PROCESSOR_ARCHITECTURE
    $inv.user = $env:USERNAME; $inv.domain = $env:USERDOMAIN
    $inv.model = ''; $inv.serial = ''; $inv.cpu = ''; $inv.cpu_cores = 0
    $inv.ram_gb = 0; $inv.disks = @(); $inv.ips = @(); $inv.mac = ''; $inv.uptime = ''
    $inv.scan_time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $inv.os = $os.Caption; $inv.os_version = "$($os.Version) build $($os.BuildNumber)"
        $inv.ram_gb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
        if ($os.LastBootUpTime) { $up = (Get-Date) - $os.LastBootUpTime; $inv.uptime = "{0}d {1}h" -f $up.Days, $up.Hours }
    } catch { }
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $inv.model = ("{0} {1}" -f $cs.Manufacturer, $cs.Model).Trim()
        $inv.cpu_cores = $cs.NumberOfLogicalProcessors
        if ($cs.Domain) { $inv.domain = $cs.Domain }
    } catch { }
    try { $inv.serial = (Get-CimInstance Win32_BIOS -ErrorAction Stop).SerialNumber } catch { }
    try { $inv.cpu = (Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1).Name } catch { }
    try {
        $inv.disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | ForEach-Object {
            [ordered]@{ mount = $_.DeviceID; total_gb = [math]::Round($_.Size/1GB,1); free_gb = [math]::Round($_.FreeSpace/1GB,1) } })
    } catch { }
    try {
        $inv.ips = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop |
            ForEach-Object { $_.IPAddress } | Where-Object { $_ -and $_ -notlike 'fe80*' -and $_ -notlike '127.*' })
        $mac = (Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop |
            Select-Object -First 1).MACAddress
        if ($mac) { $inv.mac = $mac }
    } catch { }
    # antivirus (Windows client SecurityCenter2)
    try {
        $av = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
        if ($av) { $inv.antivirus = @($av | ForEach-Object { $_.displayName }) }
    } catch { }
    try { $inv.shadowCopies = @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop).Count } catch { }
    return $inv
}

function Send-Notification {
    param([string]$Title, [string]$Text)
    $hn = $env:COMPUTERNAME; if (-not $hn) { try { $hn = [System.Net.Dns]::GetHostName() } catch { $hn = 'host' } }
    $msg = "[$hn] $Title - $Text"
    $sent = @()
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
    if ($NotifyWebhook) {
        try {
            $body = @{ text = $msg; content = $msg } | ConvertTo-Json
            Invoke-RestMethod -Uri $NotifyWebhook -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 10 | Out-Null
            $sent += 'webhook'
        } catch { Write-Warn2 "webhook notify failed: $($_.Exception.Message)" }
    }
    if ($NotifyTelegramToken -and $NotifyTelegramChat) {
        try {
            $u = "https://api.telegram.org/bot$NotifyTelegramToken/sendMessage"
            Invoke-RestMethod -Uri $u -Method Post -Body @{ chat_id = $NotifyTelegramChat; text = $msg } -TimeoutSec 10 | Out-Null
            $sent += 'telegram'
        } catch { Write-Warn2 "telegram notify failed: $($_.Exception.Message)" }
    }
    if (Send-Syslog -Message "$Title - $Text") { $sent += 'syslog' }
    return $sent
}

function Send-Syslog {
    param([string]$Message)
    if (-not $Syslog) { return $false }
    try {
        $parts = $Syslog.Split(':'); $h = $parts[0]
        $port = if ($parts.Count -gt 1 -and $parts[1]) { [int]$parts[1] } else { 514 }
        $hn = $env:COMPUTERNAME; if (-not $hn) { try { $hn = [System.Net.Dns]::GetHostName() } catch { $hn = 'host' } }
        $ts = (Get-Date).ToString('MMM dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
        $bytes = [Text.Encoding]::UTF8.GetBytes("<131>$ts $hn RansomwareToolkit: $Message")
        $udp = New-Object System.Net.Sockets.UdpClient
        [void]$udp.Send($bytes, $bytes.Length, $h, $port); $udp.Close()
        return $true
    } catch { Write-Warn2 "syslog failed: $($_.Exception.Message)"; return $false }
}

function Get-Culprit {
    # Best-effort: which process has <Path> open. Windows needs handle.exe/Restart
    # Manager (not built-in), so this returns empty there for now; kept for parity.
    param([string]$Path)
    return [pscustomobject]@{ Name = ''; Pids = @() }
}

function Test-DefenseEvasion {
    # Windows-only. Ransomware almost always tries to block recovery: it deletes
    # Volume Shadow Copies / backups, disables recovery, turns off Defender and
    # clears the event logs. These are strong, low-false-positive indicators.
    param([datetime]$Since)
    if ($env:OS -ne 'Windows_NT') { return }

    # 1) Event-log clears + Defender-disabled = classic anti-forensics (High)
    $checks = @(
        @{ Log = 'Security'; Id = 1102; Msg = 'Security audit log was CLEARED (anti-forensics)' },
        @{ Log = 'System';   Id = 104;  Msg = 'An event log was CLEARED' },
        @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5001; Msg = 'Windows Defender real-time protection was DISABLED' }
    )
    foreach ($c in $checks) {
        try {
            $ev = Get-WinEvent -FilterHashtable @{ LogName = $c.Log; Id = $c.Id; StartTime = $Since } -MaxEvents 3 -ErrorAction Stop
            if ($ev) {
                $when = ($ev | Select-Object -First 1).TimeCreated
                Add-Finding -Severity 'High' -Type 'DefenseEvasion' -FilePath ("EventLog:{0}/{1}" -f $c.Log, $c.Id) `
                    -Detail ("{0} (last at {1})" -f $c.Msg, $when) -Modified $when
            }
        } catch { }   # log missing / no access / no events - ignore
    }

    # 2) Recovery-tampering tools run recently (Prefetch) = Medium (some backup
    #    software legitimately uses vssadmin/wbadmin)
    try {
        $pf = Join-Path $env:SystemRoot 'Prefetch'
        if (Test-Path $pf) {
            foreach ($tool in 'VSSADMIN', 'WBADMIN', 'BCDEDIT', 'WMIC', 'CIPHER', 'WEVTUTIL') {
                $hit = @(Get-ChildItem -LiteralPath $pf -Filter "$tool.EXE-*.pf" -Force -ErrorAction SilentlyContinue |
                         Where-Object { $_.LastWriteTime -ge $Since })
                if ($hit.Count) {
                    Add-Finding -Severity 'Medium' -Type 'DefenseEvasion' -FilePath $hit[0].FullName `
                        -Detail ("$tool.exe ran within the last window (possible shadow-copy/backup tampering)") `
                        -Modified $hit[0].LastWriteTime
                }
            }
        }
    } catch { }
    # (the shadow-copy COUNT is recorded in the inventory for context; a bare "0
    #  shadows" is not flagged - it is normal on many machines.)
}

function Invoke-Containment {
    param([string[]]$Pids)
    if (-not $Contain) { return }
    foreach ($a in @($Contain -split '[,\s]+' | Where-Object { $_ })) {
        try {
            switch ($a.ToLower()) {
                'killproc' { foreach ($procId in $Pids) { try { Stop-Process -Id ([int]$procId) -Force -ErrorAction SilentlyContinue; Write-Warn2 "containment: killed process $procId" } catch { } } }
                'network'  { try { Disable-NetAdapter -Name '*' -Confirm:$false -ErrorAction SilentlyContinue; Write-Warn2 'containment: network disabled' } catch { } }
                'lock'     { try { & rundll32.exe user32.dll,LockWorkStation; Write-Warn2 'containment: session locked' } catch { } }
            }
        } catch { Write-Warn2 "containment '$a' failed: $($_.Exception.Message)" }
    }
}

function Import-IocData {
    param([string]$Dir)
    $extExact  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $extAuto   = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $extWild   = New-Object System.Collections.ArrayList
    $noteRegex = New-Object System.Collections.ArrayList
    $keywords  = New-Object System.Collections.ArrayList

    $extFile  = Join-Path $Dir 'extensions.txt'
    $autoFile = Join-Path $Dir 'extensions-auto.txt'
    $noteFile = Join-Path $Dir 'ransom-note-names.txt'
    $kwFile   = Join-Path $Dir 'note-keywords.txt'

    # Curated list: hand-vetted -> HIGH confidence (flag on name alone)
    if (Test-Path $extFile) {
        foreach ($raw in Get-Content -LiteralPath $extFile) {
            $l = $raw.Trim(); if (-not $l -or $l.StartsWith('#')) { continue }
            if ($l.Contains('*')) { [void]$extWild.Add((Convert-WildcardToRegex $l)) }
            else { [void]$extExact.Add($l.ToLowerInvariant()) }
        }
    }
    # Auto/community list: bulk & noisy -> LOW confidence (only flagged when the
    # file is ALSO high-entropy, so .swp/.lock/.key etc. never false-positive).
    if (Test-Path $autoFile) {
        foreach ($raw in Get-Content -LiteralPath $autoFile) {
            $l = $raw.Trim(); if (-not $l -or $l.StartsWith('#') -or $l.Contains('*')) { continue }
            $le = $l.ToLowerInvariant()
            if (-not $extExact.Contains($le)) { [void]$extAuto.Add($le) }
        }
    }
    if (Test-Path $noteFile) {
        foreach ($raw in Get-Content -LiteralPath $noteFile) {
            $l = $raw.Trim(); if (-not $l -or $l.StartsWith('#')) { continue }
            [void]$noteRegex.Add((Convert-WildcardToRegex $l))
        }
    }
    if (Test-Path $kwFile) {
        foreach ($raw in Get-Content -LiteralPath $kwFile) {
            $l = $raw.Trim(); if (-not $l -or $l.StartsWith('#')) { continue }
            [void]$keywords.Add($l.ToLowerInvariant())
        }
    }
    return [pscustomobject]@{ ExtExact=$extExact; ExtAuto=$extAuto; ExtWild=@($extWild); NoteRegex=@($noteRegex); Keywords=@($keywords) }
}

# --- Family / decryptor map (data/families.json) ---------------------------
function Import-Families {
    param([string]$Dir)
    $result = [pscustomobject]@{ ByExt=@{}; ByNote=@{}; Families=@(); Urls=$null; Markers=(New-Object System.Collections.ArrayList) }
    $path = Join-Path $Dir 'families.json'
    if (-not (Test-Path $path)) { return $result }
    try { $json = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json } catch { return $result }
    $result.Urls = $json.identifyUrls
    $result.Families = @($json.families)
    foreach ($fam in $json.families) {
        if ($fam.extensions) { foreach ($e in $fam.extensions) { $result.ByExt[$e.ToLowerInvariant()] = $fam } }
        if ($fam.notes)      { foreach ($n in $fam.notes)      { $result.ByNote[$n.ToLowerInvariant()] = $fam } }
        if ($fam.noteMarkers){ foreach ($mk in $fam.noteMarkers) { [void]$result.Markers.Add([pscustomobject]@{ marker=$mk.ToLowerInvariant(); fam=$fam }) } }
    }
    return $result
}

function Get-LikelyFamilies {
    param($Findings, $Fam)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $out  = New-Object System.Collections.ArrayList
    foreach ($f in $Findings) {
        $ext = ''; $name = ''
        try { $ext  = [System.IO.Path]::GetExtension($f.Path).ToLowerInvariant() } catch { }
        try { $name = [System.IO.Path]::GetFileName($f.Path).ToLowerInvariant() } catch { }
        $hit = $null
        if ($ext -and $Fam.ByExt.ContainsKey($ext)) { $hit = $Fam.ByExt[$ext] }
        elseif ($name -and $Fam.ByNote.ContainsKey($name)) { $hit = $Fam.ByNote[$name] }
        if ($hit -and -not $seen.Contains($hit.name)) { [void]$seen.Add($hit.name); [void]$out.Add($hit) }
    }
    return @($out)
}

# --- Definitions updater ----------------------------------------------------
function Convert-ToCleanExtension {
    # Turn a community-list line into a safe ".ext", or $null if it is a broad
    # wildcard / garbage / numeric-only extension that would cause false positives.
    param([string]$Line)
    $l = $Line.Trim()
    if (-not $l -or $l.StartsWith('#') -or $l.StartsWith('//') -or $l.StartsWith(';')) { return $null }
    if ($l.Contains(',')) { $l = $l.Split(',')[0].Trim() }   # CSV -> first field
    if ($l.StartsWith('*.')) { $l = $l.Substring(1) }        # *.ext -> .ext
    elseif ($l.StartsWith('*')) { return $null }             # *foo* -> too broad
    $l = $l.ToLowerInvariant()
    if ($l -match '^\.[a-z0-9][a-z0-9_\-]{0,15}$' -and $l -match '[a-z]') { return $l }
    return $null
}

function Invoke-Update {
    Write-Host ""
    Write-Host ('=' * 64) -ForegroundColor DarkCyan
    Write-Host "  Update definitions  -  fetch the latest ransomware extensions" -ForegroundColor Cyan
    Write-Host ('=' * 64) -ForegroundColor DarkCyan
    Write-Warn2 "Run this on a CLEAN, online machine to refresh the USB - not on an"
    Write-Warn2 "isolated/infected host."

    $srcFile = Join-Path $DataDir 'update-sources.txt'
    if (-not (Test-Path $srcFile)) { Write-Bad "No update-sources.txt found in $DataDir"; return }
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

    $denySet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($d in @('.doc','.docx','.xls','.xlsx','.ppt','.pptx','.pdf','.txt','.rtf','.jpg','.jpeg','.png',
                     '.gif','.bmp','.tiff','.tif','.svg','.zip','.rar','.7z','.gz','.tar','.exe','.dll','.sys',
                     '.msi','.iso','.mp3','.mp4','.avi','.mkv','.mov','.wav','.csv','.log','.dat','.bak','.bkp',
                     '.tmp','.temp','.cache','.backup','.backups','.html','.htm','.xml','.json','.ini','.cfg','.conf','.db','.sqlite',
                     # common dev/app/backup/crypto files that would false-positive
                     '.swp','.swo','.swn','.lock','.key','.save','.old','.part','.partial','.download','.crdownload',
                     '.data','.dmp','.pem','.crt','.cer','.pub','.pfx','.p12','.asc','.gpg','.pgp','.kdbx','.jks',
                     '.keystore','.vmdk','.vdi','.ova','.torrent','.cr2','.nef','.arw','.dng','.raw','.psd',
                     # too-common/legit extensions removed from the curated list - keep them out of
                     # the community list too so they cannot re-false-positive via the entropy path
                     '.inc','.java','.arrow','.abc','.rdm','.pb','.glb',
                     '.spa','.appx','.appxbundle','.msix','.msixbundle','.xpi','.vsix','.asar','.pak')) { [void]$denySet.Add($d) }

    $communityExt = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $trustedOk = 0; $trustedFail = 0; $commSources = 0

    foreach ($raw in Get-Content -LiteralPath $srcFile) {
        $line = $raw.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        $parts = $line -split '\s+', 3
        if ($parts.Count -lt 3) { continue }
        $type = $parts[0].ToLowerInvariant(); $target = $parts[1]; $url = $parts[2]

        Write-Info "Fetching [$type] $url"
        $content = $null
        try { $content = (Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 25).Content }
        catch { Write-Warn2 "  failed: $($_.Exception.Message)"; if ($type -eq 'trusted') { $trustedFail++ }; continue }
        if (-not $content -or $content.Length -lt 10) { Write-Warn2 "  empty response, skipped"; if ($type -eq 'trusted') { $trustedFail++ }; continue }

        if ($type -eq 'trusted') {
            $dest = Join-Path $DataDir $target
            $ok = $true
            if ($target -like '*.json') { try { $null = ($content | ConvertFrom-Json) } catch { $ok = $false } }
            elseif ((($content -split "`n").Count) -lt 5) { $ok = $false }
            if (-not $ok) { Write-Warn2 "  validation failed, keeping current $target"; $trustedFail++; continue }
            if (Test-Path $dest) { Copy-Item -LiteralPath $dest -Destination "$dest.bak" -Force -ErrorAction SilentlyContinue }
            Write-Utf8NoBom -Path $dest -Content $content
            Write-Ok "  updated $target"; $trustedOk++
        }
        elseif ($type -eq 'community') {
            $commSources++; $added = 0
            foreach ($cl in ($content -split "`r?`n")) {
                $ext = Convert-ToCleanExtension $cl
                if ($ext -and -not $denySet.Contains($ext)) { if ($communityExt.Add($ext)) { $added++ } }
            }
            Write-Info "  accepted $added clean extensions from this source"
        }
        elseif ($type -eq 'hashes') {
            $found = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($m in [regex]::Matches($content, '\b[0-9a-fA-F]{64}\b')) { [void]$found.Add($m.Value.ToLower()) }
            $dest = Join-Path $DataDir $(if ($target -like '*.txt') { $target } else { 'malware-hashes.txt' })
            if (Test-Path $dest) { foreach ($l in Get-Content -LiteralPath $dest) { $t = $l.Trim().ToLower(); if ($t.Length -eq 64) { [void]$found.Add($t) } } }
            $hsb = New-Object System.Text.StringBuilder
            [void]$hsb.AppendLine('# known-malicious sha256 hashes (auto-updated by Update)')
            foreach ($h in ($found | Sort-Object)) { [void]$hsb.AppendLine($h) }
            Write-Utf8NoBom -Path $dest -Content $hsb.ToString()
            Write-Info "  $($found.Count) known-malicious hashes -> $(Split-Path $dest -Leaf)"
        }
    }

    if ($communityExt.Count -gt 0) {
        $curated = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $curatedFile = Join-Path $DataDir 'extensions.txt'
        if (Test-Path $curatedFile) {
            foreach ($r in Get-Content -LiteralPath $curatedFile) { $t=$r.Trim(); if ($t -and -not $t.StartsWith('#') -and -not $t.Contains('*')) { [void]$curated.Add($t.ToLowerInvariant()) } }
        }
        $autoFile = Join-Path $DataDir 'extensions-auto.txt'
        if (Test-Path $autoFile) {
            foreach ($r in Get-Content -LiteralPath $autoFile) {
                $t = $r.Trim().ToLowerInvariant()
                if ($t -and -not $t.StartsWith('#') -and -not $denySet.Contains($t)) { [void]$communityExt.Add($t) }
            }
            Copy-Item -LiteralPath $autoFile -Destination "$autoFile.bak" -Force -ErrorAction SilentlyContinue
        }
        $final = @($communityExt | Where-Object { -not $curated.Contains($_) } | Sort-Object -Unique)
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("# AUTO-GENERATED by 'Update definitions' - DO NOT EDIT BY HAND.")
        [void]$sb.AppendLine("# Clean '.ext' entries merged from the community sources in update-sources.txt,")
        [void]$sb.AppendLine("# minus anything already in extensions.txt. Loaded automatically by the scanner.")
        [void]$sb.AppendLine(("# Total: {0}" -f $final.Count)); [void]$sb.AppendLine("")
        foreach ($e in $final) { [void]$sb.AppendLine($e) }
        Write-Utf8NoBom -Path $autoFile -Content $sb.ToString()
        Write-Ok ("extensions-auto.txt now holds {0} community extensions" -f $final.Count)
    }
    elseif ($commSources -gt 0) { Write-Warn2 "No community extensions parsed (sources unreachable?)." }

    Write-Host ""
    Write-Ok ("Update finished. Trusted files updated: {0}, failed/skipped: {1}." -f $trustedOk, $trustedFail)
    $ioc = Import-IocData -Dir $DataDir
    Write-Info ("Definitions now: {0} curated + {1} community extensions, {2} note patterns, {3} keywords" -f `
        ($ioc.ExtExact.Count + $ioc.ExtWild.Count), $ioc.ExtAuto.Count, $ioc.NoteRegex.Count, $ioc.Keywords.Count)
}

# --- Open online identification sites (manual upload) -----------------------
function Invoke-IdentifyOnline {
    param($Fam)
    Write-Host ""
    Write-Host ('=' * 64) -ForegroundColor DarkCyan
    Write-Host "  Online identification" -ForegroundColor Cyan
    Write-Host ('=' * 64) -ForegroundColor DarkCyan
    Write-Warn2 "This opens third-party sites in your browser. You upload files MANUALLY."
    Write-Warn2 "Do NOT upload sensitive/confidential data. Encrypted files (ciphertext)"
    Write-Warn2 "and the ransom note are generally safe to share for identification."
    $targets = @()
    if ($Fam -and $Fam.Urls) {
        if ($Fam.Urls.idRansomware)  { $targets += $Fam.Urls.idRansomware }
        if ($Fam.Urls.cryptoSheriff) { $targets += $Fam.Urls.cryptoSheriff }
    }
    if (-not $targets.Count) {
        $targets = @('https://id-ransomware.malwarehunterteam.com/','https://www.nomoreransom.org/crypto-sheriff.php')
    }
    foreach ($u in $targets) {
        try { Start-Process $u | Out-Null; Write-Ok "Opened: $u" } catch { Write-Info "Open manually: $u" }
    }
}

function Get-FileEntropy {
    param([string]$FilePath, [int]$SampleBytes = 32768)
    $fs = $null
    try {
        $fs = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open,
                                     [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $len = [int][Math]::Min([long]$SampleBytes, $fs.Length)
        if ($len -le 0) { return -1 }
        $buffer = New-Object byte[] $len
        $read = $fs.Read($buffer, 0, $len)
        if ($read -le 0) { return -1 }
        $counts = New-Object 'int[]' 256
        for ($i = 0; $i -lt $read; $i++) { $counts[$buffer[$i]]++ }
        $entropy = 0.0; $exp = $read / 256.0; $chi = 0.0
        for ($b = 0; $b -lt 256; $b++) {
            $c = $counts[$b]
            if ($c -gt 0) { $p = $c / $read; $entropy -= $p * [Math]::Log($p, 2) }
            if ($exp -gt 0) { $d = $c - $exp; $chi += ($d * $d) / $exp }
        }
        return [pscustomobject]@{ Entropy = [Math]::Round($entropy, 3); Chi = [Math]::Round($chi, 1) }
    }
    catch { return [pscustomobject]@{ Entropy = -1; Chi = -1 } }
    finally { if ($fs) { $fs.Dispose() } }
}

function Get-FileSha256 {
    param([string]$FilePath)
    try { return (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() }
    catch { return $null }
}

function Import-HashSet {
    param([string]$Dir)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $p = Join-Path $Dir 'malware-hashes.txt'
    if (Test-Path $p) {
        foreach ($raw in Get-Content -LiteralPath $p) {
            $t = ($raw.Trim() -split '\s+')[0]
            if ($t -and $t.Length -eq 64 -and $t -match '^[0-9a-fA-F]{64}$') { [void]$set.Add($t.ToLower()) }
        }
    }
    return $set
}

$script:ExecutableExts = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($e in @('.exe','.dll','.scr','.com','.pif','.cpl','.sys','.msi','.jar','.js','.jse','.vbs','.vbe',
                 '.wsf','.ps1','.bat','.cmd','.hta','.lnk','.elf','.bin')) { [void]$script:ExecutableExts.Add($e) }

function Import-Allowlist {
    # Exclusions (like AV exclusions) from data/allowlist.txt: a path prefix,
    # an extension (.ext) or a name wildcard - one per line.
    param([string]$Dir)
    $prefixes = New-Object System.Collections.ArrayList
    $exts = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $names = New-Object System.Collections.ArrayList
    $p = Join-Path $Dir 'allowlist.txt'
    if (Test-Path $p) {
        foreach ($raw in Get-Content -LiteralPath $p) {
            $t = $raw.Trim(); if (-not $t -or $t.StartsWith('#')) { continue }
            if ($t.StartsWith('/') -or $t -match '^[a-zA-Z]:[\\/]') { [void]$prefixes.Add($t.ToLower().Replace('\', '/')) }
            elseif ($t.StartsWith('.')) { [void]$exts.Add($t.ToLower()) }
            else { [void]$names.Add((Convert-WildcardToRegex $t)) }
        }
    }
    return [pscustomobject]@{ Prefixes = @($prefixes); Exts = $exts; Names = @($names) }
}

function Get-YaraRules {
    param([string]$Dir)
    if (-not (Get-Command yara -ErrorAction SilentlyContinue)) { return @() }
    $ydir = Join-Path $Dir 'yara'
    if (-not (Test-Path $ydir)) { return @() }
    return @(Get-ChildItem -LiteralPath $ydir -File -ErrorAction SilentlyContinue |
             Where-Object { $_.Extension -in '.yar', '.yara' } | ForEach-Object { $_.FullName })
}
function Invoke-Yara {
    param([string[]]$Rules, [string[]]$Targets)
    $hits = @()
    foreach ($r in $Rules) {
        foreach ($t in $Targets) {
            try {
                $out = & yara -r -w -N $r $t 2>$null
                foreach ($line in $out) {
                    $idx = $line.IndexOf(' ')
                    if ($idx -gt 0) {
                        $rule = $line.Substring(0, $idx); $p = $line.Substring($idx + 1)
                        if (Test-Path -LiteralPath $p) { $hits += [pscustomobject]@{ rule = $rule; path = $p } }
                    }
                }
            } catch { }
        }
    }
    return $hits
}

function Resolve-Targets {
    param([string[]]$Path, [switch]$Quick, [switch]$Full)
    if ($Path) { return @($Path | Where-Object { Test-Path -LiteralPath $_ }) }
    if ($Full) {
        $drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty DeviceID
        if (-not $drives) { $drives = @($env:SystemDrive) }
        return @($drives | ForEach-Object { "$_\" })
    }
    $targets = New-Object System.Collections.ArrayList
    $usersRoot = Join-Path $env:SystemDrive 'Users'
    if (Test-Path $usersRoot) {
        foreach ($u in Get-ChildItem -LiteralPath $usersRoot -Directory -ErrorAction SilentlyContinue) {
            foreach ($sub in @('Desktop','Documents','Downloads','Pictures','OneDrive','Videos','Music')) {
                $p = Join-Path $u.FullName $sub
                if (Test-Path -LiteralPath $p) { [void]$targets.Add($p) }
            }
        }
    }
    if ($targets.Count -eq 0) { [void]$targets.Add((Join-Path $env:SystemDrive '\')) }
    return @($targets)
}

# Formats that are high-entropy by design - never flagged as "encrypted"
$script:NaturalHighEntropy = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($e in @('.zip','.7z','.rar','.gz','.bz2','.xz','.tar','.tgz','.cab','.jar','.apk','.z','.lz4','.zst','.br',
                 '.jpg','.jpeg','.png','.gif','.webp','.bmp','.tiff','.tif','.heic','.heif','.ico','.jfif',
                 '.cr2','.nef','.arw','.dng','.raw','.orf','.rw2','.raf','.srw','.psd','.psb','.ai','.eps','.indd',
                 '.mp3','.mp4','.mkv','.avi','.mov','.wmv','.flac','.aac','.ogg','.webm','.m4a','.m4v','.opus','.wma',
                 '.3gp','.mpg','.mpeg','.ts','.m2ts','.vob',
                 '.pdf','.docx','.xlsx','.pptx','.odt','.ods','.odp','.epub',
                 '.exe','.dll','.msi','.iso','.dmg','.pkg','.deb','.rpm','.wim','.esd','.vhd','.vhdx','.vmdk','.vdi','.ova',
                 '.bin','.dat','.db','.sqlite','.mdb','.accdb',
                 '.gpg','.pgp','.asc','.pfx','.p12','.pem','.crt','.cer','.kdbx','.jks','.keystore',
                 '.crx','.nupkg','.whl','.torrent','.so','.o','.a','.ko','.dylib',
                 '.pack','.wasm','.pyc','.class','.node','.car','.nib','.icns',
                 '.woff','.woff2','.ttf','.otf','.eot',
                 '.pb','.glb','.gltf','.fbx','.blend','.3mf','.f3d','.usdz','.stl',
                 '.h5','.pt','.pth','.onnx','.tflite','.safetensors','.gguf','.ggml','.pmml',
                 '.numbers','.pages','.key',
                 '.spa','.appx','.appxbundle','.msix','.msixbundle','.xpi','.vsix','.asar','.pak','.crx')) { [void]$script:NaturalHighEntropy.Add($e) }

$script:TextExtensions = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($e in @('.txt','.html','.htm','.hta','.rtf','.md','.log','.nfo','.readme')) { [void]$script:TextExtensions.Add($e) }

# Definitive ransom-note phrases. A text file with NO note-like name needs >=2 of
# these, so security docs that merely mention "bitcoin"/"private key" do not FP.
$script:StrongKeywords = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($k in @('your files have been encrypted','all your files are encrypted','your files are encrypted',
                 'files have been encrypted','have been encrypted','we have encrypted',
                 'decrypt your files','decrypt all your files','buy decryptor',
                 'your network has been','your data has been','we have downloaded','data has been stolen',
                 'restore your files','recover your files','pay the ransom','you have 72 hours','you have 48 hours')) {
    [void]$script:StrongKeywords.Add($k) }

function Add-Finding {
    param([string]$Severity, [string]$Type, [string]$FilePath, [string]$Detail,
          [double]$Entropy = -1, [datetime]$Modified)
    [void]$script:findings.Add([pscustomobject]@{
        Severity = $Severity; Type = $Type; Path = $FilePath
        Detail = $Detail; Entropy = $Entropy; Modified = $Modified
    })
}

function HtmlEncode([string]$s) {
    if ($null -eq $s) { return '' }
    return $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
}

# ===========================================================================
# SCAN
# ===========================================================================
function Invoke-Scan {
    param([string[]]$Targets, [string]$ModeLabel)

    $started = Get-Date
    Write-Host ""
    Write-Host ('=' * 64) -ForegroundColor DarkCyan
    Write-Host "  Ransomware SCAN  -  read-only, results saved to the USB" -ForegroundColor Cyan
    Write-Host ('=' * 64) -ForegroundColor DarkCyan

    $isAdmin = Test-IsAdmin
    $inv = Get-SystemInventory
    Write-Info ("Device        : {0}  ({1} {2}, {3} GB RAM)  user {4}" -f `
        $inv.hostname, ($(if ($inv.model) { $inv.model } else { $inv.os })), $inv.os_version, $inv.ram_gb, $inv.user)
    Write-Info "Mode          : $ModeLabel"
    Write-Info ("Administrator : {0}" -f ($(if ($isAdmin) {'Yes'} else {'No (some system folders may be skipped)'})))
    Write-Info "Report folder : $OutputDir"

    $ioc = Import-IocData -Dir $DataDir
    Write-Info ("IOC loaded    : {0} curated (+{1} community) extensions, {2} note patterns, {3} keywords" -f `
        ($ioc.ExtExact.Count + $ioc.ExtWild.Count), $ioc.ExtAuto.Count, $ioc.NoteRegex.Count, $ioc.Keywords.Count)
    $script:MalHashes = Import-HashSet -Dir $DataDir   # optional known-malware hash IOC
    if ($script:MalHashes.Count) { Write-Info ("Hash IOC      : {0} known-malicious hashes loaded" -f $script:MalHashes.Count) }
    $yaraRules = Get-YaraRules -Dir $DataDir           # optional YARA rules
    if ($yaraRules.Count) { Write-Info ("YARA          : {0} rule file(s) loaded" -f $yaraRules.Count) }
    $script:Allow = Import-Allowlist -Dir $DataDir     # optional exclusions
    $allowN = $script:Allow.Prefixes.Count + $script:Allow.Exts.Count + $script:Allow.Names.Count
    if ($allowN) { Write-Info ("Allowlist     : {0} exclusion rule(s) loaded" -f $allowN) }
    $famDb = Import-Families -Dir $DataDir             # loaded early for note-content family ID
    $script:FamMarkers = $famDb.Markers
    $script:noteFam = @{}                              # family-name -> family, from note CONTENT
    Write-Info ("Targets       : {0}" -f ($Targets -join ' ; '))
    Write-Host ""

    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

    $recentCutoff = (Get-Date).AddHours(-[Math]::Abs($RecentHours))
    $maxBytes     = [long]$MaxFileSizeMB * 1MB

    # never scan the toolkit's own folder (its README/IOC lists/reports legitimately
    # contain ransomware keywords and extensions -> would self-false-positive)
    $skipData = (Resolve-Path -LiteralPath $ScriptRoot -ErrorAction SilentlyContinue).Path
    $skipOut  = (Resolve-Path -LiteralPath $OutputDir  -ErrorAction SilentlyContinue).Path

    # per-scan state (script scope so the ForEach-Object child scope can update it)
    $script:findings   = New-Object System.Collections.ArrayList
    $script:filesSeen  = 0
    $script:bytesSeen  = [long]0
    $script:lastTick   = Get-Date
    $dirStats   = @{}
    $noteSpread = @{}

    foreach ($target in $Targets) {
        Write-Info "Scanning: $target"
        try {
            Get-ChildItem -LiteralPath $target -Recurse -File -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                $file = $_
                if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { return }
                if (($skipData -and $file.FullName.StartsWith($skipData, [StringComparison]::OrdinalIgnoreCase)) -or `
                    ($skipOut  -and $file.FullName.StartsWith($skipOut,  [StringComparison]::OrdinalIgnoreCase))) { return }

                $script:filesSeen++
                $script:bytesSeen += $file.Length
                $name   = $file.Name
                $ext    = $file.Extension
                $dir    = $file.DirectoryName
                $extLow = $ext.ToLowerInvariant()

                # allowlist (exclusions): skip matched files entirely
                if ($script:Allow) {
                    $skipIt = $false
                    if ($script:Allow.Exts.Contains($extLow)) { $skipIt = $true }
                    elseif ($script:Allow.Prefixes.Count) {
                        $pl = $file.FullName.ToLower().Replace('\', '/')
                        foreach ($pre in $script:Allow.Prefixes) { if ($pl.StartsWith($pre)) { $skipIt = $true; break } }
                    }
                    if (-not $skipIt -and $script:Allow.Names.Count) {
                        foreach ($rx in $script:Allow.Names) { if ($name -match $rx) { $skipIt = $true; break } }
                    }
                    if ($skipIt) { return }
                }

                $now = Get-Date
                if (($now - $script:lastTick).TotalMilliseconds -ge 400) {
                    Write-Progress -Activity "Scanning for ransomware indicators" `
                        -Status ("{0:N0} files  |  {1:N0} findings  |  {2}" -f $script:filesSeen, $script:findings.Count, $file.FullName) -Id 1
                    $script:lastTick = $now
                }

                $ds = $dirStats[$dir]
                if (-not $ds) { $ds = @{ Total = 0; Recent = 0; Susp = 0; Ext = @{} }; $dirStats[$dir] = $ds }
                $ds.Total++
                if ($file.LastWriteTime -ge $recentCutoff) { $ds.Recent++ }
                if ($extLow) { if ($ds.Ext.ContainsKey($extLow)) { $ds.Ext[$extLow]++ } else { $ds.Ext[$extLow] = 1 } }

                # Layer 1: extension. Curated list = high confidence (flag on name).
                # Community/auto list = low confidence (only via entropy in Layer 4).
                $extHit = $false
                if ($extLow -and $ioc.ExtExact.Contains($extLow)) { $extHit = $true }
                if (-not $extHit -and $ioc.ExtWild.Count) {
                    foreach ($rx in $ioc.ExtWild) { if ($name -match $rx) { $extHit = $true; break } }
                }
                $autoHit = $false
                if (-not $extHit -and $extLow -and $ioc.ExtAuto.Contains($extLow)) { $autoHit = $true }
                $suspFile = $extHit
                if ($extHit) {
                    Add-Finding -Severity 'High' -Type 'Extension' -FilePath $file.FullName `
                        -Detail "Known ransomware extension '$ext'" -Modified $file.LastWriteTime
                }

                # Layer 2: ransom-note name
                $noteHit = $false
                foreach ($rx in $ioc.NoteRegex) { if ($name -match $rx) { $noteHit = $true; break } }

                # Layer 3: ransom-note content
                $isText = $script:TextExtensions.Contains($extLow)
                $small  = $file.Length -le 200KB -and $file.Length -gt 0
                if (($noteHit -or ($isText -and $small)) -and $small) {
                    $kwHits = @()
                    try {
                        $cl = ([System.IO.File]::ReadAllText($file.FullName)).ToLowerInvariant()
                        foreach ($kw in $ioc.Keywords) { if ($cl.Contains($kw)) { $kwHits += $kw } }
                    } catch { }
                    $strong = @($kwHits | Where-Object { $script:StrongKeywords.Contains($_) })
                    if ($noteHit -and $kwHits.Count -ge 1) {
                        foreach ($mk in $script:FamMarkers) {   # family from the note text
                            if ($cl.Contains($mk.marker) -and -not $script:noteFam.ContainsKey($mk.fam.name)) { $script:noteFam[$mk.fam.name] = $mk.fam }
                        }
                        $preview = ($cl -replace '\s+', ' ').Trim(); if ($preview.Length -gt 160) { $preview = $preview.Substring(0, 160) }
                        Add-Finding -Severity 'High' -Type 'RansomNote' -FilePath $file.FullName `
                            -Detail ("Ransom note (name + content). Keywords: " + (($kwHits | Select-Object -First 4) -join ', ') + $(if ($preview) { "  | note: $preview" } else { '' })) `
                            -Modified $file.LastWriteTime
                        $nl = $name.ToLowerInvariant()   # only confirmed notes count toward spread
                        if (-not $noteSpread.ContainsKey($nl)) { $noteSpread[$nl] = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase) }
                        [void]$noteSpread[$nl].Add($dir)
                    }
                    elseif ($noteHit) {
                        Add-Finding -Severity 'Medium' -Type 'RansomNote' -FilePath $file.FullName `
                            -Detail "File name matches a ransom-note pattern (no keyword match)" -Modified $file.LastWriteTime
                    }
                    elseif ($strong.Count -ge 2) {
                        Add-Finding -Severity 'Medium' -Type 'RansomNote' -FilePath $file.FullName `
                            -Detail ("Text file with ransom-note wording. Keywords: " + (($strong | Select-Object -First 4) -join ', ')) `
                            -Modified $file.LastWriteTime
                    }
                }

                # Layer 4: entropy is a CONFIRMATION signal for the low-confidence
                # community list only. Curated extensions are already flagged above by
                # name; a bare high-entropy file with an ordinary/odd extension (git
                # objects, fonts, binaries, media) is NOT ransomware on its own.
                if ($autoHit -and -not $NoEntropy -and $file.Length -ge 1KB -and $file.Length -le $maxBytes `
                        -and -not $script:NaturalHighEntropy.Contains($extLow)) {
                    $e = Get-FileEntropy -FilePath $file.FullName
                    if ($e.Entropy -ge $EntropyThreshold) {
                        $suspFile = $true
                        Add-Finding -Severity 'High' -Type 'Encrypted' -FilePath $file.FullName `
                            -Detail ("Community-listed extension '{0}' + high entropy {1}/8.0 (chi2 {2}) - likely encrypted" -f $ext, $e.Entropy, $e.Chi) `
                            -Entropy $e.Entropy -Modified $file.LastWriteTime
                    }
                }

                # Layer 6: known-malware hash IOC (only for small executables/scripts)
                if ($script:MalHashes.Count -and $script:ExecutableExts.Contains($extLow) `
                        -and $file.Length -gt 0 -and $file.Length -le 64MB) {
                    $digest = Get-FileSha256 -FilePath $file.FullName
                    if ($digest -and $script:MalHashes.Contains($digest)) {
                        $suspFile = $true
                        Add-Finding -Severity 'High' -Type 'KnownMalware' -FilePath $file.FullName `
                            -Detail ("File hash matches a known-malicious IOC (sha256 {0}...)" -f $digest.Substring(0,16)) `
                            -Modified $file.LastWriteTime
                    }
                }

                # Count recently-modified SUSPICIOUS files per folder (for mass-change)
                if ($suspFile -and $file.LastWriteTime -ge $recentCutoff) { $ds.Susp++ }
            }
        }
        catch { Write-Warn2 "Could not fully scan '$target': $($_.Exception.Message)" }
    }
    Write-Progress -Activity "Scanning for ransomware indicators" -Completed -Id 1

    # Layer 5: post-pass heuristics
    foreach ($dir in $dirStats.Keys) {
        $ds = $dirStats[$dir]
        # Mass-change now counts only recently-modified SUSPICIOUS files, so ordinary
        # busy folders (downloads, builds, active projects) no longer false-positive.
        if ($ds.Susp -ge 10) {
            Add-Finding -Severity 'High' -Type 'MassChange' -FilePath $dir `
                -Detail ("{0} recently-modified suspicious/encrypted files in this folder (active encryption?)" -f $ds.Susp) `
                -Modified $recentCutoff
        }
        # Mass-rename only fires when a hand-vetted ransomware extension dominates a
        # folder - a source-code (.ts) or photo (.heic) folder never triggers it.
        if ($ds.Total -ge 12) {
            foreach ($e in $ds.Ext.Keys) {
                if (-not $ioc.ExtExact.Contains($e)) { continue }
                $cnt = $ds.Ext[$e]; $share = $cnt / $ds.Total
                if ($share -ge 0.6) {
                    Add-Finding -Severity 'High' -Type 'MassRename' -FilePath $dir `
                        -Detail ("{0:P0} of files ({1}/{2}) share the ransomware extension '{3}'" -f $share, $cnt, $ds.Total, $e) `
                        -Modified $recentCutoff
                }
            }
        }
    }
    foreach ($note in $noteSpread.Keys) {
        $dirs = $noteSpread[$note]
        if ($dirs.Count -ge 3) {
            Add-Finding -Severity 'High' -Type 'NoteSpread' -FilePath ($dirs | Select-Object -First 1) `
                -Detail ("Ransom note '{0}' found in {1} different folders" -f $note, $dirs.Count) `
                -Modified $recentCutoff
        }
    }

    # Layer 7 (optional): YARA rule matches
    if ($yaraRules.Count) {
        foreach ($hit in (Invoke-Yara -Rules $yaraRules -Targets $Targets)) {
            Add-Finding -Severity 'High' -Type 'YARA' -FilePath $hit.path `
                -Detail ("YARA rule matched: {0}" -f $hit.rule) -Modified $recentCutoff
        }
    }

    # Layer 8 (Windows): defense evasion - shadow-copy/backup deletion, log clears,
    # Defender disabled (checked once, machine-wide, not per file)
    Test-DefenseEvasion -Since $recentCutoff

    # ---- summarise + verdict ----
    $findings = $script:findings
    $high   = @($findings | Where-Object { $_.Severity -eq 'High' })
    $medium = @($findings | Where-Object { $_.Severity -eq 'Medium' })
    $low    = @($findings | Where-Object { $_.Severity -eq 'Low' })

    $verdict = 'CLEAN'; $verdictColor = 'Green'
    if ($high.Count -gt 0)       { $verdict = 'RANSOMWARE INDICATORS FOUND'; $verdictColor = 'Red' }
    elseif ($medium.Count -gt 0) { $verdict = 'SUSPICIOUS - REVIEW NEEDED';  $verdictColor = 'Yellow' }

    $elapsed = (Get-Date) - $started
    Write-Host ""
    Write-Host ('-' * 64) -ForegroundColor DarkCyan
    Write-Host "  RESULT: $verdict" -ForegroundColor $verdictColor
    Write-Host ('-' * 64) -ForegroundColor DarkCyan
    Write-Info ("Files scanned : {0:N0}  ({1:N1} GB)" -f $script:filesSeen, ($script:bytesSeen / 1GB))
    Write-Info ("Duration      : {0:hh\:mm\:ss}" -f $elapsed)
    Write-Host ("  High   : {0}" -f $high.Count)   -ForegroundColor Red
    Write-Host ("  Medium : {0}" -f $medium.Count) -ForegroundColor Yellow
    Write-Host ("  Low    : {0}" -f $low.Count)    -ForegroundColor Gray
    Write-Host ""
    foreach ($f in ($high | Select-Object -First 15)) { Write-Bad ("[{0}] {1}  ->  {2}" -f $f.Type, $f.Path, $f.Detail) }
    if ($high.Count -gt 15) { Write-Bad ("... and {0} more high-severity findings (see report)" -f ($high.Count - 15)) }

    # ---- likely family + decryptor hints ----
    $likely = @()
    if ($famDb.Families.Count) { $likely = @(Get-LikelyFamilies -Findings $findings -Fam $famDb) }
    $seenFam = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($lf in $likely) { [void]$seenFam.Add($lf.name) }
    foreach ($k in $script:noteFam.Keys) {   # families identified from ransom-note text
        if ($seenFam.Add($k)) { $likely += $script:noteFam[$k] }
    }
    if ($likely.Count) {
        Write-Host ""
        Write-Host "  Likely ransomware family(ies):" -ForegroundColor Cyan
        foreach ($fam in $likely) {
            $tag = switch ($fam.decryptor) { 'available' {'FREE DECRYPTOR MAY EXIST'} 'maybe' {'decryptor MAYBE - verify'} default {'no known free decryptor'} }
            Write-Host ("   - {0,-28} [{1}]" -f $fam.name, $tag) -ForegroundColor Yellow
            Write-Host ("       {0}" -f $fam.url) -ForegroundColor DarkGray
        }
        Write-Host "   (menu [7] opens ID Ransomware / No More Ransom to confirm)" -ForegroundColor DarkGray
    }

    # ---- reports ----
    $stamp = $started.ToString('yyyyMMdd_HHmmss')
    $host_ = $inv.hostname
    if (-not $host_) { $host_ = $env:COMPUTERNAME }
    if (-not $host_) { try { $host_ = [System.Net.Dns]::GetHostName() } catch { $host_ = 'host' } }
    # Computer name FIRST -> reports from many devices identify by device at a glance.
    $safeHost = ($host_ -replace '[^A-Za-z0-9._-]', '-'); if (-not $safeHost) { $safeHost = 'host' }
    $baseName = "${safeHost}_RansomwareScan_${stamp}"
    $txtPath  = Join-Path $OutputDir "$baseName.txt"
    $jsonPath = Join-Path $OutputDir "$baseName.json"
    $htmlPath = Join-Path $OutputDir "$baseName.html"

    $meta = [ordered]@{
        tool='Windows Ransomware Detection Toolkit'; version='3.3'; computer=$host_
        user=$env:USERNAME; scanMode=$ModeLabel; targets=$Targets; inventory=$inv
        startedAt=$started.ToString('s'); durationSec=[int]$elapsed.TotalSeconds
        filesScanned=$script:filesSeen; bytesScanned=$script:bytesSeen; verdict=$verdict
        counts=[ordered]@{ high=$high.Count; medium=$medium.Count; low=$low.Count }
        likelyFamilies=@($likely | ForEach-Object { [ordered]@{ name=$_.name; decryptor=$_.decryptor; tool=$_.tool; url=$_.url } })
    }
    Write-Utf8NoBom -Path $jsonPath -Content ([pscustomobject]@{ meta=$meta; findings=$findings } | ConvertTo-Json -Depth 6)

    $txt = New-Object System.Text.StringBuilder
    [void]$txt.AppendLine('Windows Ransomware Detection Toolkit - Scan Report')
    [void]$txt.AppendLine('=================================================')
    [void]$txt.AppendLine("Computer   : $host_   User: $($env:USERNAME)")
    [void]$txt.AppendLine("Started    : $started")
    [void]$txt.AppendLine("Mode       : $ModeLabel")
    [void]$txt.AppendLine("Targets    : $($Targets -join ' ; ')")
    [void]$txt.AppendLine(("Files      : {0:N0}  ({1:N1} GB) in {2:hh\:mm\:ss}" -f $script:filesSeen, ($script:bytesSeen/1GB), $elapsed))
    [void]$txt.AppendLine("VERDICT    : $verdict")
    [void]$txt.AppendLine(("Findings   : High={0}  Medium={1}  Low={2}" -f $high.Count, $medium.Count, $low.Count))
    [void]$txt.AppendLine('')
    [void]$txt.AppendLine('--- Device inventory ---')
    [void]$txt.AppendLine(("  Hostname : {0}   FQDN: {1}" -f $inv.hostname, $inv.fqdn))
    [void]$txt.AppendLine(("  OS       : {0} {1} ({2})" -f $inv.os, $inv.os_version, $inv.arch))
    [void]$txt.AppendLine(("  Model    : {0}   Serial: {1}" -f $inv.model, $inv.serial))
    [void]$txt.AppendLine(("  CPU/RAM  : {0} ({1} cores) / {2} GB" -f $inv.cpu, $inv.cpu_cores, $inv.ram_gb))
    [void]$txt.AppendLine(("  User     : {0}   Domain: {1}" -f $inv.user, $inv.domain))
    [void]$txt.AppendLine(("  Network  : {0}   MAC: {1}" -f (($inv.ips) -join ', '), $inv.mac))
    if ($inv.antivirus) { [void]$txt.AppendLine(("  Antivirus: {0}" -f (($inv.antivirus) -join ', '))) }
    [void]$txt.AppendLine(("  Disks    : {0}" -f (($inv.disks | ForEach-Object { "$($_.mount) $($_.free_gb)/$($_.total_gb)GB free" }) -join '  ')))
    [void]$txt.AppendLine(("  Uptime   : {0}" -f $inv.uptime))
    [void]$txt.AppendLine('')
    if ($likely.Count) {
        [void]$txt.AppendLine('Likely family(ies) / decryptor:')
        foreach ($fam in $likely) {
            [void]$txt.AppendLine(("  - {0}  [{1}]" -f $fam.name, $fam.decryptor))
            if ($fam.tool) { [void]$txt.AppendLine(("      {0}" -f $fam.tool)) }
            [void]$txt.AppendLine(("      {0}" -f $fam.url))
        }
        [void]$txt.AppendLine('')
    }
    foreach ($sev in @('High','Medium','Low')) {
        $items = @($findings | Where-Object { $_.Severity -eq $sev })
        if (-not $items.Count) { continue }
        [void]$txt.AppendLine("[$sev] ($($items.Count))")
        [void]$txt.AppendLine('-------------------------------------------------')
        foreach ($f in $items) {
            [void]$txt.AppendLine(("  {0,-11} {1}" -f $f.Type, $f.Path))
            [void]$txt.AppendLine(("              {0}" -f $f.Detail))
        }
        [void]$txt.AppendLine('')
    }
    Write-Utf8NoBom -Path $txtPath -Content $txt.ToString()

    # CSV (findings, for Excel / SIEM)
    $csvPath = Join-Path $OutputDir "$baseName.csv"
    $csv = New-Object System.Text.StringBuilder
    [void]$csv.AppendLine('computer,severity,type,path,detail,entropy,modified')
    foreach ($f in $findings) {
        $ent = if ($f.Entropy -ge 0) { '{0:N2}' -f $f.Entropy } else { '' }
        $mod = if ($f.Modified) { $f.Modified.ToString('yyyy-MM-dd HH:mm') } else { '' }
        $vals = @($host_, $f.Severity, $f.Type, $f.Path, $f.Detail, $ent, $mod)
        [void]$csv.AppendLine((($vals | ForEach-Object { '"' + ([string]$_ -replace '"', "'") + '"' }) -join ','))
    }
    Write-Utf8NoBom -Path $csvPath -Content $csv.ToString()

    $rowsHtml = New-Object System.Text.StringBuilder
    foreach ($sev in @('High','Medium','Low')) {
        foreach ($f in @($findings | Where-Object { $_.Severity -eq $sev })) {
            $cls = $sev.ToLower()
            $entTxt = if ($f.Entropy -ge 0) { '{0:N2}' -f $f.Entropy } else { '-' }
            $modTxt = if ($f.Modified) { $f.Modified.ToString('yyyy-MM-dd HH:mm') } else { '-' }
            [void]$rowsHtml.AppendLine(("<tr class='$cls'><td><span class='badge $cls'>{0}</span></td><td>{1}</td><td class='path'>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>" -f `
                $sev, (HtmlEncode $f.Type), (HtmlEncode $f.Path), (HtmlEncode $f.Detail), $entTxt, $modTxt))
        }
    }
    $verdictClass = if ($high.Count) { 'high' } elseif ($medium.Count) { 'medium' } else { 'clean' }
    $famHtml = ''
    if ($likely.Count) {
        $frows = New-Object System.Text.StringBuilder
        foreach ($fam in $likely) {
            $badge = switch ($fam.decryptor) {
                'available' { "<span class='badge low'>decryptor may exist</span>" }
                'maybe'     { "<span class='badge medium'>decryptor maybe</span>" }
                default     { "<span class='badge high'>no free decryptor</span>" }
            }
            [void]$frows.AppendLine(("<li><b>{0}</b> {1}<br><span class='mut'>{2}</span> &middot; <a href='{3}'>{3}</a></li>" -f `
                (HtmlEncode $fam.name), $badge, (HtmlEncode $fam.tool), (HtmlEncode $fam.url)))
        }
        $famHtml = "<div class='fam'><h3>Likely family &amp; decryptor (verify before trusting)</h3><ul>$($frows.ToString())</ul></div>"
    }
    $disksStr = (($inv.disks | ForEach-Object { "$($_.mount) $($_.free_gb)/$($_.total_gb) GB free" }) -join '; ')
    $invPairs = [ordered]@{
        'Hostname'       = $inv.hostname
        'FQDN'           = $(if ($inv.fqdn) { $inv.fqdn } else { '-' })
        'OS'             = ("{0} {1} ({2})" -f $inv.os, $inv.os_version, $inv.arch)
        'Model'          = $(if ($inv.model) { $inv.model } else { '-' })
        'Serial'         = $(if ($inv.serial) { $inv.serial } else { '-' })
        'CPU / RAM'      = ("{0} ({1} cores) / {2} GB" -f $inv.cpu, $inv.cpu_cores, $inv.ram_gb)
        'User'           = $inv.user
        'Domain'         = $(if ($inv.domain) { $inv.domain } else { '-' })
        'Antivirus'      = $(if ($inv.antivirus) { ($inv.antivirus -join ', ') } else { '-' })
        'IP address(es)' = $(if ($inv.ips) { ($inv.ips -join ', ') } else { '-' })
        'MAC'            = $(if ($inv.mac) { $inv.mac } else { '-' })
        'Disks'          = $(if ($disksStr) { $disksStr } else { '-' })
        'Uptime'         = $(if ($inv.uptime) { $inv.uptime } else { '-' })
    }
    $invRows = New-Object System.Text.StringBuilder
    foreach ($k in $invPairs.Keys) {
        [void]$invRows.AppendLine(("<tr><td class='k'>{0}</td><td>{1}</td></tr>" -f (HtmlEncode $k), (HtmlEncode ([string]$invPairs[$k]))))
    }
    $invHtml = "<div class='inv'><h3>Device inventory</h3><table class='invtbl'>$($invRows.ToString())</table></div>"
    $html = @"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Ransomware Scan - $host_ - $stamp</title>
<style>
 :root{--bg:#0f1420;--card:#171d2b;--tx:#e6e9ef;--mut:#8b93a7;--line:#26304a}
 body{margin:0;font-family:Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--tx)}
 .wrap{max-width:1100px;margin:0 auto;padding:28px}
 h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mut);font-size:13px;margin-bottom:20px}
 .verdict{padding:16px 20px;border-radius:12px;font-size:20px;font-weight:700;margin:18px 0}
 .verdict.high{background:#3a1620;color:#ff6b81;border:1px solid #5a1e2e}
 .verdict.medium{background:#3a2f16;color:#ffcf6b;border:1px solid #5a4a1e}
 .verdict.clean{background:#12321f;color:#5ee08a;border:1px solid #1e5a38}
 .cards{display:flex;gap:14px;flex-wrap:wrap;margin:16px 0}
 .card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 18px;min-width:120px}
 .card .n{font-size:26px;font-weight:700}.card .l{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
 table{width:100%;border-collapse:collapse;background:var(--card);border-radius:12px;overflow:hidden;font-size:13px}
 th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
 th{background:#1d2434;color:var(--mut);font-weight:600}
 td.path{font-family:Consolas,monospace;word-break:break-all;color:#bcd0ff}
 .badge{padding:2px 9px;border-radius:20px;font-size:11px;font-weight:700}
 .badge.high{background:#5a1e2e;color:#ff8ea0}.badge.medium{background:#5a4a1e;color:#ffdf9b}.badge.low{background:#2a3350;color:#9fb2df}
 tr.high td{background:rgba(90,30,46,.12)}
 .inv{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:6px 18px 14px;margin:16px 0}
 .inv h3{font-size:14px;color:var(--tx);margin:12px 0 8px}
 .invtbl{width:100%;font-size:13px;background:transparent}
 .invtbl td{border-bottom:1px solid var(--line);padding:6px 10px}
 .invtbl td.k{color:var(--mut);width:170px;white-space:nowrap}
 .fam{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:6px 18px 14px;margin:16px 0}
 .fam h3{font-size:14px;color:var(--tx);margin:12px 0 6px}
 .fam ul{margin:0;padding-left:18px}.fam li{margin:8px 0;font-size:13px;line-height:1.5}
 .fam a{color:#8fb6ff;word-break:break-all}.mut{color:var(--mut)}
 .foot{color:var(--mut);font-size:12px;margin-top:22px;line-height:1.6}
</style></head><body><div class="wrap">
 <h1>Windows Ransomware Detection Toolkit</h1>
 <div class="sub">$host_ &middot; user $($env:USERNAME) &middot; mode $ModeLabel &middot; started $started &middot; $("{0:N0}" -f $script:filesSeen) files in $("{0:hh\:mm\:ss}" -f $elapsed)</div>
 <div class="verdict $verdictClass">$verdict</div>
 <div class="cards">
   <div class="card"><div class="n" style="color:#ff6b81">$($high.Count)</div><div class="l">High</div></div>
   <div class="card"><div class="n" style="color:#ffcf6b">$($medium.Count)</div><div class="l">Medium</div></div>
   <div class="card"><div class="n" style="color:#9fb2df">$($low.Count)</div><div class="l">Low</div></div>
   <div class="card"><div class="n">$("{0:N0}" -f $script:filesSeen)</div><div class="l">Files</div></div>
 </div>
 $invHtml
 $famHtml
 <table><thead><tr><th>Severity</th><th>Type</th><th>Path</th><th>Detail</th><th>Entropy</th><th>Modified</th></tr></thead>
 <tbody>
$($rowsHtml.ToString())
 </tbody></table>
 <div class="foot">
   Detection &amp; alerting only - no files were modified.<br>
   If you see High findings: <b>disconnect this machine from the network/Wi-Fi</b>, do not pay, do not reboot, and preserve this report for your IR/AV team.
 </div>
</div></body></html>
"@
    Write-Utf8NoBom -Path $htmlPath -Content $html

    Write-Host ""
    Write-Ok "Reports saved:"
    Write-Host "     $htmlPath" -ForegroundColor Cyan
    Write-Host "     $txtPath"  -ForegroundColor DarkGray
    Write-Host "     $jsonPath" -ForegroundColor DarkGray
    Write-Host "     $csvPath"  -ForegroundColor DarkGray
    if ($high.Count -gt 0) {
        Write-Host ""
        Write-Bad "ACTION: disconnect from network, do NOT reboot or pay, keep the report, call your AV/IR team."
        $chans = Send-Notification -Title 'RANSOMWARE INDICATORS FOUND' -Text ("{0} high-severity findings in a {1} scan" -f $high.Count, $ModeLabel)
        if ($chans.Count) { Write-Ok ("Alert sent via: {0}" -f ($chans -join ', ')) }
    }
    if ($OpenReport) { try { Invoke-Item -LiteralPath $htmlPath } catch { } }

    if ($high.Count -gt 0) { return 2 } elseif ($medium.Count -gt 0) { return 1 } else { return 0 }
}

# ===========================================================================
# WATCH
# ===========================================================================
function Invoke-Watch {
    param([string[]]$WatchPath)

    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    $stamp   = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $hostName = $env:COMPUTERNAME; if (-not $hostName) { try { $hostName = [System.Net.Dns]::GetHostName() } catch { $hostName = 'host' } }
    $logPath = Join-Path $OutputDir ("RansomwareWatch_{0}_{1}.log" -f $hostName, $stamp)

    function Write-WLog {
        param([string]$Level, [string]$Message)
        $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $line = "[$ts] [$Level] $Message"
        $color = switch ($Level) { 'ALARM' {'Red'} 'WARN' {'Yellow'} 'OK' {'Green'} default {'Gray'} }
        Write-Host $line -ForegroundColor $color
        Add-Content -LiteralPath $logPath -Value $line
    }
    function Invoke-Alarm {
        param([string]$Title, [string]$Detail, [string]$Path)
        $culprit = if ($Path) { Get-Culprit -Path $Path } else { [pscustomobject]@{ Name=''; Pids=@() } }
        if ($culprit.Name) { $Detail = "$Detail  [process: $($culprit.Name)]" }
        Write-Host ""
        Write-Host ('#' * 64) -ForegroundColor Red
        Write-Host ("#  RANSOMWARE ALARM: {0}" -f $Title) -ForegroundColor Red
        Write-Host ('#' * 64) -ForegroundColor Red
        Write-WLog 'ALARM' ("$Title -- $Detail")
        Write-Host "  -> DISCONNECT network/Wi-Fi now.  Do NOT reboot.  Do NOT pay." -ForegroundColor Yellow
        Write-Host "  -> Note the time, keep this log, contact your AV/IR team." -ForegroundColor Yellow
        try { for ($i = 0; $i -lt 5; $i++) { [console]::Beep(1100, 250); [console]::Beep(760, 250) } } catch { }
        $chans = Send-Notification -Title ("RANSOMWARE ALARM: {0}" -f $Title) -Text $Detail
        if ($chans.Count) { Write-WLog 'INFO' ("Alert sent via: {0}" -f ($chans -join ', ')) }
        Invoke-Containment -Pids $culprit.Pids
    }

    if (-not $WatchPath) {
        $WatchPath = @()
        foreach ($sub in @('Desktop','Documents','Downloads','Pictures')) {
            $p = Join-Path $env:USERPROFILE $sub
            if (Test-Path -LiteralPath $p) { $WatchPath += $p }
        }
    }
    $WatchPath = @($WatchPath | Where-Object { Test-Path -LiteralPath $_ })
    if (-not $WatchPath.Count) { Write-WLog 'WARN' 'No valid folders to watch.'; return }

    # minimal IOC (exact extensions + note names)
    $extExact  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $noteRegex = New-Object System.Collections.ArrayList
    $extFile   = Join-Path $DataDir 'extensions.txt'
    $noteFile  = Join-Path $DataDir 'ransom-note-names.txt'
    if (Test-Path $extFile) { foreach ($raw in Get-Content -LiteralPath $extFile) { $l=$raw.Trim(); if (-not $l -or $l.StartsWith('#') -or $l.Contains('*')) { continue }; [void]$extExact.Add($l) } }
    if (Test-Path $noteFile){ foreach ($raw in Get-Content -LiteralPath $noteFile){ $l=$raw.Trim(); if (-not $l -or $l.StartsWith('#')) { continue }; [void]$noteRegex.Add((Convert-WildcardToRegex $l)) } }

    $canaryMarker = 'CANARY-WRDT-2f8a1c-DO-NOT-DELETE'
    $canarySet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $canaryContent = @"
$canaryMarker
CANARY FILE - Windows Ransomware Detection Toolkit
Do not delete, rename or edit this file. It is a decoy used to detect
ransomware activity: if a program modifies it, the monitor raises an alarm.
Created: $stamp
"@
    $canaryNames = @('!!!_canary_do_not_delete_1.docx','!!!_canary_do_not_delete_2.xlsx',
                     'zzz_canary_do_not_delete_3.jpg','zzz_canary_do_not_delete_4.pdf')

    function Remove-Canaries {
        param([switch]$Quiet)
        $removed = 0
        foreach ($folder in $WatchPath) {
            foreach ($n in $canaryNames) {
                $cp = Join-Path $folder $n
                if (-not (Test-Path -LiteralPath $cp)) { continue }
                try {
                    $t = Get-Content -LiteralPath $cp -Raw -ErrorAction SilentlyContinue
                    if ($t -and $t.Contains($canaryMarker)) {
                        $i = Get-Item -LiteralPath $cp -Force; $i.Attributes = 'Normal'
                        Remove-Item -LiteralPath $cp -Force -ErrorAction SilentlyContinue; $removed++
                    }
                } catch { }
            }
        }
        if (-not $Quiet) { Write-WLog 'INFO' ("Canary cleanup: removed {0} decoy file(s)." -f $removed) }
    }
    function Set-Canaries {
        Remove-Canaries -Quiet
        $planted = 0
        foreach ($folder in $WatchPath) {
            foreach ($n in $canaryNames) {
                $cp = Join-Path $folder $n
                try {
                    Set-Content -LiteralPath $cp -Value $canaryContent -Encoding UTF8 -Force
                    $item = Get-Item -LiteralPath $cp -Force
                    $item.Attributes = $item.Attributes -bor [IO.FileAttributes]::Hidden
                    [void]$canarySet.Add($cp); $planted++
                } catch { }
            }
        }
        Write-WLog 'OK' ("Planted {0} canary files across {1} folder(s)." -f $planted, $WatchPath.Count)
    }

    Write-Host ""
    Write-Host ('=' * 64) -ForegroundColor DarkCyan
    Write-Host "  Ransomware LIVE MONITOR - early warning" -ForegroundColor Cyan
    Write-Host ('=' * 64) -ForegroundColor DarkCyan
    Write-WLog 'INFO' ("Watching: " + ($WatchPath -join ' ; '))
    Write-WLog 'INFO' ("Burst rule: >{0} changes / {1}s   Log: {2}" -f $BurstThreshold, $BurstWindowSec, $logPath)
    $nch = @(); if ($NotifyWebhook) { $nch += 'webhook' }
    if ($NotifyTelegramToken -and $NotifyTelegramChat) { $nch += 'telegram' }
    if ($nch.Count) { Write-WLog 'INFO' ("Alerts enabled: {0}" -f ($nch -join ', ')) }
    if ($Contain) { Write-WLog 'WARN' ("Auto-containment ARMED: {0} (disruptive)" -f $Contain) }
    Set-Canaries

    $watchers = New-Object System.Collections.ArrayList
    $srcIds   = New-Object System.Collections.ArrayList
    $filter   = [IO.NotifyFilters]::FileName -bor [IO.NotifyFilters]::LastWrite -bor [IO.NotifyFilters]::Size
    $idx = 0
    foreach ($folder in $WatchPath) {
        $fsw = New-Object System.IO.FileSystemWatcher
        $fsw.Path = $folder; $fsw.IncludeSubdirectories = $true; $fsw.NotifyFilter = $filter; $fsw.EnableRaisingEvents = $true
        foreach ($evtName in @('Changed','Created','Renamed','Deleted')) {
            $sid = "RWT_${idx}_${evtName}"
            Register-ObjectEvent -InputObject $fsw -EventName $evtName -SourceIdentifier $sid | Out-Null
            [void]$srcIds.Add($sid)
        }
        [void]$watchers.Add($fsw); $idx++
    }

    $eventTimes  = New-Object System.Collections.Generic.Queue[datetime]
    $lastBurst   = [datetime]::MinValue
    $lastCanary  = [datetime]::MinValue
    $cooldownSec = 20
    $heartbeat   = Get-Date
    Write-WLog 'OK' 'Monitor armed. Press Ctrl+C to stop.'

    try {
        while ($true) {
            $evt = Wait-Event -Timeout 1
            if ($evt) {
                $a = $evt.SourceEventArgs
                $full = $a.FullPath; $change = [string]$a.ChangeType
                $fname = [System.IO.Path]::GetFileName($full); $ext = [System.IO.Path]::GetExtension($full).ToLowerInvariant()
                Remove-Event -EventIdentifier $evt.EventIdentifier
                $now = Get-Date

                $oldPath = $null
                if ($a.PSObject.Properties['OldFullPath']) { $oldPath = $a.OldFullPath }
                if ($canarySet.Contains($full) -or ($oldPath -and $canarySet.Contains($oldPath))) {
                    if ($change -ne 'Created' -and ($now - $lastCanary).TotalSeconds -ge $cooldownSec) {
                        $lastCanary = $now
                        Invoke-Alarm -Title 'CANARY TRIPPED' -Detail ("Decoy file was ${change}: $full") -Path $full
                    }
                    continue
                }
                if ($change -eq 'Created' -or $change -eq 'Renamed') {
                    $bad = $false; $why = ''
                    if ($ext -and $extExact.Contains($ext)) { $bad = $true; $why = "known ransomware extension '$ext'" }
                    if (-not $bad) { foreach ($rx in $noteRegex) { if ($fname -match $rx) { $bad = $true; $why = "ransom-note name '$fname'"; break } } }
                    if ($bad) { Invoke-Alarm -Title 'SUSPICIOUS FILE' -Detail ("$why  ->  $full") -Path $full }
                }
                if ($change -eq 'Changed' -or $change -eq 'Renamed') {
                    $eventTimes.Enqueue($now)
                    while ($eventTimes.Count -gt 0 -and ($now - $eventTimes.Peek()).TotalSeconds -gt $BurstWindowSec) { [void]$eventTimes.Dequeue() }
                    if ($eventTimes.Count -ge $BurstThreshold -and ($now - $lastBurst).TotalSeconds -ge $cooldownSec) {
                        $lastBurst = $now
                        Invoke-Alarm -Title 'CHANGE BURST' -Detail ("{0} file changes in {1}s (near {2})" -f $eventTimes.Count, $BurstWindowSec, $full)
                        $eventTimes.Clear()
                    }
                }
            }
            if (((Get-Date) - $heartbeat).TotalSeconds -ge 60) {
                $heartbeat = Get-Date
                Write-Host ("[{0:HH:mm:ss}] monitoring... (last {1}s: {2} changes)" -f (Get-Date), $BurstWindowSec, $eventTimes.Count) -ForegroundColor DarkGray
            }
        }
    }
    finally {
        Write-Host ""
        Write-WLog 'INFO' 'Stopping monitor...'
        foreach ($sid in $srcIds) { Unregister-Event -SourceIdentifier $sid -ErrorAction SilentlyContinue }
        foreach ($w in $watchers) { $w.EnableRaisingEvents = $false; $w.Dispose() }
        Get-Event | Remove-Event -ErrorAction SilentlyContinue
        Remove-Canaries
        Write-WLog 'OK' "Monitor stopped. Log saved: $logPath"
    }
}

# ===========================================================================
# Baseline / diff  (snapshot a folder now, compare later)
# ===========================================================================
function Get-BaselinePath {
    param([string[]]$Targets)
    $h = $env:COMPUTERNAME; if (-not $h) { try { $h = [System.Net.Dns]::GetHostName() } catch { $h = 'host' } }
    $safe = ($h -replace '[^A-Za-z0-9._-]', '-'); if (-not $safe) { $safe = 'host' }
    $tag = (($Targets | Sort-Object) -join '') -replace '[^A-Za-z0-9]', ''
    if ($tag.Length -gt 24) { $tag = $tag.Substring($tag.Length - 24) }
    if (-not $tag) { $tag = 'all' }
    $d = Join-Path $OutputDir 'baselines'
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    return Join-Path $d "${safe}_${tag}.baseline.txt"
}
function Invoke-Baseline {
    param([string[]]$Targets)
    Write-Host ""
    Write-Host "  Baseline snapshot - records the current file state to compare later" -ForegroundColor Cyan
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("# baseline created $((Get-Date).ToString('s'))")
    $n = 0
    foreach ($t in $Targets) {
        Get-ChildItem -LiteralPath $t -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { return }
            $mt = [long]($_.LastWriteTimeUtc - [datetime]'1970-01-01').TotalSeconds
            [void]$sb.AppendLine(("{0}|{1}|{2}" -f [long]$_.Length, $mt, $_.FullName)); $n++
        }
    }
    $bp = Get-BaselinePath -Targets $Targets
    Write-Utf8NoBom -Path $bp -Content $sb.ToString()
    Write-Ok ("Baseline saved: {0} files -> {1}" -f $n, $bp)
    return 0
}
function Invoke-Diff {
    param([string[]]$Targets)
    $bp = Get-BaselinePath -Targets $Targets
    if (-not (Test-Path $bp)) { Write-Bad "No baseline for these paths. Run:  -Mode Baseline -Path $($Targets -join ' ')"; return 3 }
    $started = Get-Date
    $old = @{}
    foreach ($line in Get-Content -LiteralPath $bp) {
        if (-not $line -or $line.StartsWith('#')) { continue }
        $p = $line.Split('|', 3)
        if ($p.Count -eq 3) { $old[$p[2]] = @([long]$p[0], [long]$p[1]) }
    }
    $ioc = Import-IocData -Dir $DataDir
    $known = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($e in $ioc.ExtExact) { [void]$known.Add($e) }
    foreach ($e in $ioc.ExtAuto) { [void]$known.Add($e) }

    Write-Host ""
    Write-Host "  Diff vs baseline - what changed since the snapshot" -ForegroundColor Cyan
    $script:findings = New-Object System.Collections.ArrayList
    $current = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $script:diffChanged = 0
    foreach ($t in $Targets) {
        Get-ChildItem -LiteralPath $t -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { return }
            $fp = $_.FullName; [void]$current.Add($fp)
            $ext = $_.Extension.ToLowerInvariant()
            $mt = [long]($_.LastWriteTimeUtc - [datetime]'1970-01-01').TotalSeconds
            if ($old.ContainsKey($fp)) {
                $o = $old[$fp]
                if ($o[0] -ne [long]$_.Length -or $o[1] -ne $mt) { $script:diffChanged++ }
            } elseif ($known.Contains($ext)) {
                Add-Finding -Severity 'High' -Type 'NewRansomExt' -FilePath $fp `
                    -Detail "New file with ransomware extension '$ext' since baseline" -Modified $_.LastWriteTime
                $baseNoExt = $fp.Substring(0, $fp.Length - $ext.Length)
                if ($old.ContainsKey($baseNoExt) -and -not $current.Contains($baseNoExt)) {
                    Add-Finding -Severity 'High' -Type 'Encrypted' -FilePath $fp `
                        -Detail ("'{0}' appears encrypted/renamed to '{1}' since baseline" -f (Split-Path $baseNoExt -Leaf), $ext) `
                        -Modified $_.LastWriteTime
                }
            }
        }
    }
    $deleted = @($old.Keys | Where-Object { -not $current.Contains($_) })
    if ($script:diffChanged -ge $MassChangeThreshold) {
        Add-Finding -Severity 'High' -Type 'MassChange' -FilePath $Targets[0] `
            -Detail ("{0} baseline files were modified since the snapshot (possible mass encryption)" -f $script:diffChanged)
    }
    if ($deleted.Count -ge $MassChangeThreshold) {
        Add-Finding -Severity 'High' -Type 'MassDelete' -FilePath $Targets[0] `
            -Detail ("{0} files present in the baseline are now gone (originals deleted after encryption?)" -f $deleted.Count)
    }
    $high = @($script:findings | Where-Object { $_.Severity -eq 'High' })
    $verdict = if ($high.Count) { 'RANSOMWARE INDICATORS FOUND' } else { 'NO SIGNIFICANT CHANGE' }
    Write-Info ("Changed: {0}   Deleted: {1}   Findings: {2}" -f $script:diffChanged, $deleted.Count, $high.Count)
    Write-Host ("  RESULT: {0}" -f $verdict) -ForegroundColor $(if ($high.Count) { 'Red' } else { 'Green' })
    foreach ($f in ($high | Select-Object -First 20)) { Write-Bad ("[{0}] {1} -> {2}" -f $f.Type, $f.Path, $f.Detail) }

    # concise TXT + JSON report
    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    $stamp = $started.ToString('yyyyMMdd_HHmmss')
    $h = $env:COMPUTERNAME; if (-not $h) { try { $h = [System.Net.Dns]::GetHostName() } catch { $h = 'host' } }
    $safe = ($h -replace '[^A-Za-z0-9._-]', '-'); if (-not $safe) { $safe = 'host' }
    $rp = Join-Path $OutputDir "${safe}_RansomwareDiff_${stamp}"
    [pscustomobject]@{ meta = [ordered]@{ tool='Windows Ransomware Detection Toolkit'; mode='Diff'; computer=$h;
        baseline=$bp; targets=$Targets; changed=$script:diffChanged; deleted=$deleted.Count; verdict=$verdict };
        findings = $script:findings } | ConvertTo-Json -Depth 6 | ForEach-Object { Write-Utf8NoBom -Path "$rp.json" -Content $_ }
    Write-Ok "Report: $rp.json"
    return $(if ($high.Count) { 2 } else { 0 })
}

# ===========================================================================
# Fleet dashboard  (combine many devices' JSON reports into one view)
# ===========================================================================
function Invoke-Fleet {
    param([string]$Folder)
    if (-not $Folder) { $Folder = $OutputDir }
    Write-Host ""
    Write-Host "  Fleet dashboard - combine many devices' reports into one view" -ForegroundColor Cyan
    Write-Info "Source folder : $Folder"
    $files = @(Get-ChildItem -LiteralPath $Folder -Filter '*RansomwareScan_*.json' -ErrorAction SilentlyContinue)
    $devices = @{}
    foreach ($f in $files) {
        try { $m = (Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json).meta } catch { continue }
        if (-not $m) { continue }
        $inv = $m.inventory
        $hn = if ($m.computer) { $m.computer } elseif ($inv -and $inv.hostname) { $inv.hostname } else { $f.BaseName }
        $started = [string]$m.startedAt
        if ($devices.ContainsKey($hn) -and $started -le $devices[$hn].started) { continue }
        $fam = @(); if ($m.likelyFamilies) { $fam = @($m.likelyFamilies | ForEach-Object { $_.name }) }
        $devices[$hn] = [pscustomobject]@{
            host = $hn; started = $started; verdict = [string]$m.verdict
            high = [int]$m.counts.high; medium = [int]$m.counts.medium; low = [int]$m.counts.low
            mode = [string]$m.scanMode; files = [string]$m.filesScanned
            os = $(if ($inv.os) { $inv.os } else { $inv.platform }); model = [string]$inv.model; user = [string]$m.user
            ips = (@($inv.ips | Select-Object -First 2) -join ', '); families = ($fam -join ', ')
        }
    }
    $rows = @($devices.Values | Sort-Object @{Expression = 'high'; Descending = $true}, @{Expression = 'medium'; Descending = $true})
    $infected = @($rows | Where-Object { $_.high -gt 0 }).Count
    $suspicious = @($rows | Where-Object { $_.high -eq 0 -and $_.medium -gt 0 }).Count
    $clean = $rows.Count - $infected - $suspicious
    Write-Info ("Devices: {0}   infected: {1}   suspicious: {2}   clean: {3}" -f $rows.Count, $infected, $suspicious, $clean)
    if (-not $rows.Count) { Write-Warn2 "No scan reports found. Collect the devices' reports/*.json into one folder first."; return 0 }

    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $base = Join-Path $OutputDir "FleetDashboard_$stamp"

    # CSV
    $csv = New-Object System.Text.StringBuilder
    [void]$csv.AppendLine('device,verdict,high,medium,low,families,os,model,user,ip,scan_mode,files,last_scan')
    foreach ($d in $rows) {
        $vals = @($d.host, $d.verdict, $d.high, $d.medium, $d.low, $d.families, $d.os, $d.model, $d.user, $d.ips, $d.mode, $d.files, $d.started)
        [void]$csv.AppendLine((($vals | ForEach-Object { '"' + ([string]$_ -replace '"', "'") + '"' }) -join ','))
    }
    Write-Utf8NoBom -Path "$base.csv" -Content $csv.ToString()

    # HTML
    $tr = New-Object System.Text.StringBuilder
    foreach ($d in $rows) {
        $cls = if ($d.high) { 'high' } elseif ($d.medium) { 'medium' } else { 'clean' }
        $badge = switch ($cls) { 'high' { "<span class='badge high'>INFECTED</span>" } 'medium' { "<span class='badge medium'>SUSPICIOUS</span>" } default { "<span class='badge low'>clean</span>" } }
        [void]$tr.AppendLine(("<tr class='$cls'><td><b>{0}</b></td><td>{1}</td><td style='color:#ff6b81'>{2}</td><td style='color:#ffcf6b'>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td><td class='path'>{8}</td><td>{9}</td><td>{10}</td></tr>" -f `
            (HtmlEncode $d.host), $badge, $d.high, $d.medium, $d.low, (HtmlEncode $d.families), (HtmlEncode (($d.os + ' ' + $d.model).Trim())), (HtmlEncode $d.user), (HtmlEncode $d.ips), (HtmlEncode $d.files), (HtmlEncode $d.started)))
    }
    $html = @"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Fleet dashboard - $stamp</title>
<style>
 :root{--bg:#0f1420;--card:#171d2b;--tx:#e6e9ef;--mut:#8b93a7;--line:#26304a}
 body{margin:0;font-family:Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--tx)}
 .wrap{max-width:1200px;margin:0 auto;padding:28px}h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mut);font-size:13px;margin-bottom:16px}
 .cards{display:flex;gap:14px;flex-wrap:wrap;margin:16px 0}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 18px;min-width:120px}
 .card .n{font-size:26px;font-weight:700}.card .l{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
 table{width:100%;border-collapse:collapse;background:var(--card);border-radius:12px;overflow:hidden;font-size:13px}
 th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line)}th{background:#1d2434;color:var(--mut)}
 td.path{font-family:Consolas,monospace;color:#bcd0ff}.badge{padding:2px 9px;border-radius:20px;font-size:11px;font-weight:700}
 .badge.high{background:#5a1e2e;color:#ff8ea0}.badge.medium{background:#5a4a1e;color:#ffdf9b}.badge.low{background:#2a3350;color:#9fb2df}
 tr.high td{background:rgba(90,30,46,.12)}.foot{color:var(--mut);font-size:12px;margin-top:20px}
</style></head><body><div class="wrap">
 <h1>Ransomware Fleet Dashboard</h1><div class="sub">$($rows.Count) device(s) &middot; generated $((Get-Date).ToString('yyyy-MM-dd HH:mm'))</div>
 <div class="cards">
   <div class="card"><div class="n" style="color:#ff6b81">$infected</div><div class="l">Infected</div></div>
   <div class="card"><div class="n" style="color:#ffcf6b">$suspicious</div><div class="l">Suspicious</div></div>
   <div class="card"><div class="n" style="color:#5ee08a">$clean</div><div class="l">Clean</div></div>
   <div class="card"><div class="n">$($rows.Count)</div><div class="l">Devices</div></div>
 </div>
 <table><thead><tr><th>Device</th><th>Status</th><th>High</th><th>Med</th><th>Low</th><th>Likely family</th><th>OS / model</th><th>User</th><th>IP</th><th>Files</th><th>Last scan</th></tr></thead>
 <tbody>
$($tr.ToString())
 </tbody></table>
 <div class="foot">Latest report per device. Collect each machine's reports\*.json into one folder and run: -Mode Fleet -Path &lt;folder&gt;.</div>
</div></body></html>
"@
    Write-Utf8NoBom -Path "$base.html" -Content $html
    Write-Ok "Dashboard: $base.html"
    Write-Ok "CSV:       $base.csv"
    if ($OpenReport) { try { Invoke-Item -LiteralPath "$base.html" } catch { } }
    return $(if ($infected) { 2 } elseif ($suspicious) { 1 } else { 0 })
}

# ===========================================================================
# Self-test  (verify detection works in this environment)
# ===========================================================================
function Invoke-Selftest {
    Write-Host ""
    Write-Host "  Self-test - verify detection works here (a temp fixture, no real changes)" -ForegroundColor Cyan
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("rwt_selftest_" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $atk = Join-Path $tmp 'attack'; $cln = Join-Path $tmp 'clean'
    New-Item -ItemType Directory -Path (Join-Path $atk 'mass') -Force | Out-Null
    New-Item -ItemType Directory -Path $cln -Force | Out-Null
    $savedOut = $OutputDir
    $passed = $true
    try {
        Set-Content -LiteralPath (Join-Path $atk 'a.docx.lockbit') -Value 'x'
        Set-Content -LiteralPath (Join-Path $atk 'HOW TO DECRYPT FILES.txt') -Value 'YOUR FILES HAVE BEEN ENCRYPTED. all your files are encrypted. bitcoin .onion decrypt your files'
        $rand = [System.Random]::new()
        $buf = New-Object byte[] 3000
        for ($i = 0; $i -lt 20; $i++) { $rand.NextBytes($buf); [System.IO.File]::WriteAllBytes((Join-Path $atk "mass\f$i.crypted"), $buf) }
        Set-Content -LiteralPath (Join-Path $cln 'reference.txt') -Value 'just some reference notes about the project'
        $big = New-Object byte[] 40000; $rand.NextBytes($big); [System.IO.File]::WriteAllBytes((Join-Path $cln 'app.lock'), $big)

        Set-Variable -Name OutputDir -Value (Join-Path $tmp 'out') -Scope Script
        $rcAtk = (Invoke-Scan -Targets @($atk) -ModeLabel 'Selftest' 6>$null | Select-Object -Last 1)
        $rcCln = (Invoke-Scan -Targets @($cln) -ModeLabel 'Selftest' 6>$null | Select-Object -Last 1)
        $okAtk = ($rcAtk -eq 2); $okCln = ($rcCln -eq 0)
        if ($okAtk) { Write-Host "  [PASS]" -ForegroundColor Green -NoNewline } else { Write-Host "  [FAIL]" -ForegroundColor Red -NoNewline }
        Write-Host " detects a synthetic ransomware attack"
        if ($okCln) { Write-Host "  [PASS]" -ForegroundColor Green -NoNewline } else { Write-Host "  [FAIL]" -ForegroundColor Red -NoNewline }
        Write-Host " leaves a clean folder clean (no false positives)"
        $passed = $okAtk -and $okCln
    }
    catch { Write-Bad "Self-test error: $($_.Exception.Message)"; $passed = $false }
    finally {
        Set-Variable -Name OutputDir -Value $savedOut -Scope Script
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host ""
    if ($passed) { Write-Ok "Self-test PASSED - the toolkit is detecting correctly in this environment." }
    else { Write-Bad "Self-test FAILED - the toolkit did not behave as expected (see above)." }
    return $(if ($passed) { 0 } else { 1 })
}

# ===========================================================================
# Interactive menu
# ===========================================================================
function Show-Menu {
    while ($true) {
        Write-Host ""
        Write-Host ('=' * 64) -ForegroundColor DarkCyan
        Write-Host "   Windows Ransomware Detection Toolkit  (portable)" -ForegroundColor Cyan
        Write-Host "   Read-only scan - reports saved to the 'reports' folder" -ForegroundColor DarkGray
        Write-Host ('=' * 64) -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "   [1]  Quick scan     user folders (Desktop, Documents, ...)"
        Write-Host "   [2]  Full scan      all internal drives (needs admin)"
        Write-Host "   [3]  Live monitor   real-time early warning (canary + burst)"
        Write-Host "   [4]  Custom path    scan a folder or drive you choose"
        Write-Host "   [5]  Open reports folder"
        Write-Host "   [6]  Update definitions   fetch latest extensions online"
        Write-Host "   [7]  Identify online       open ID Ransomware / No More Ransom"
        Write-Host "   [8]  Baseline snapshot     record a folder's state to compare later"
        Write-Host "   [9]  Diff vs baseline      show what changed since the snapshot"
        Write-Host "   [F]  Fleet dashboard       combine many devices' reports into one view"
        Write-Host "   [T]  Self-test             verify detection works in this environment"
        Write-Host "   [0]  Exit"
        Write-Host ""
        $choice = Read-Host "   Select an option"
        switch ($choice) {
            '1' { [void](Invoke-Scan -Targets (Resolve-Targets) -ModeLabel 'Quick'); [void](Read-Host "`n   Press Enter to return to the menu") }
            '2' { Invoke-FullScan; [void](Read-Host "`n   Press Enter to return to the menu") }
            '3' { Invoke-Watch -WatchPath $Path }
            '4' {
                $t = Read-Host "   Enter full path (e.g. D:\ or C:\Users\me\Downloads)"
                if ($t) { [void](Invoke-Scan -Targets (Resolve-Targets -Path @($t)) -ModeLabel 'Custom') }
                [void](Read-Host "`n   Press Enter to return to the menu")
            }
            '5' { if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }; try { Invoke-Item -LiteralPath $OutputDir } catch { } }
            '6' { Invoke-Update; [void](Read-Host "`n   Press Enter to return to the menu") }
            '7' { Invoke-IdentifyOnline -Fam (Import-Families -Dir $DataDir); [void](Read-Host "`n   Press Enter to return to the menu") }
            '8' {
                $t = Read-Host "   Folder to snapshot (blank = user folders)"
                [void](Invoke-Baseline -Targets ($(if ($t) { Resolve-Targets -Path @($t) } else { Resolve-Targets })))
                [void](Read-Host "`n   Press Enter to return to the menu")
            }
            '9' {
                $t = Read-Host "   Folder to diff (blank = user folders)"
                [void](Invoke-Diff -Targets ($(if ($t) { Resolve-Targets -Path @($t) } else { Resolve-Targets })))
                [void](Read-Host "`n   Press Enter to return to the menu")
            }
            { $_ -eq 'F' -or $_ -eq 'f' } {
                $t = Read-Host "   Reports folder (blank = this tool's reports)"
                [void](Invoke-Fleet -Folder ($(if ($t) { $t } else { $null })))
                [void](Read-Host "`n   Press Enter to return to the menu")
            }
            { $_ -eq 'T' -or $_ -eq 't' } {
                [void](Invoke-Selftest)
                [void](Read-Host "`n   Press Enter to return to the menu")
            }
            '0' { return }
            default { }
        }
    }
}

function Invoke-FullScan {
    if (-not (Test-IsAdmin)) {
        Write-Warn2 "A full-drive scan works best as administrator."
        $ans = Read-Host "   Relaunch elevated now? (Y/N)"
        if ($ans -match '^[Yy]') {
            try {
                Start-Process -Verb RunAs -FilePath 'powershell' -ArgumentList @(
                    '-NoProfile','-ExecutionPolicy','Bypass','-File', "`"$ToolkitPath`"",
                    '-Mode','Full','-OpenReport')
                Write-Info "An elevated window is running the full scan; its report will open when done."
                return
            } catch { Write-Warn2 "Elevation cancelled/failed; running without admin (some folders may be skipped)." }
        }
    }
    [void](Invoke-Scan -Targets (Resolve-Targets -Full) -ModeLabel 'Full')
}

# ===========================================================================
# Dispatch
# ===========================================================================
if ($Path -and $Mode -eq 'Menu') { $Mode = 'Custom' }

switch ($Mode) {
    'Menu'   { Show-Menu }
    'Quick'  { exit (Invoke-Scan -Targets (Resolve-Targets) -ModeLabel 'Quick') }
    'Full'   { exit (Invoke-Scan -Targets (Resolve-Targets -Full) -ModeLabel 'Full') }
    'Custom' { exit (Invoke-Scan -Targets (Resolve-Targets -Path $Path) -ModeLabel 'Custom') }
    'Watch'  { Invoke-Watch -WatchPath $Path }
    'Update' { Invoke-Update }
    'Baseline' { exit (Invoke-Baseline -Targets ($(if ($Path) { Resolve-Targets -Path $Path } else { Resolve-Targets }))) }
    'Diff'     { exit (Invoke-Diff     -Targets ($(if ($Path) { Resolve-Targets -Path $Path } else { Resolve-Targets }))) }
    'Fleet'    { exit (Invoke-Fleet -Folder ($(if ($Path) { $Path[0] } else { $null }))) }
    'Selftest' { exit (Invoke-Selftest) }
}
