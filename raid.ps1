

Write-Host "RAID: Rapid Acquisition of Interesting Data"
$datetime = Get-Date -Format "MM_dd_yyyy_HH_mm"
$evidence_path = "Evidence_triage_$env:computername"+"$datetime"

function Create-Evidence-Dir
{
    try{
        Write-Host "Creating Evidence Directory: $evidence_path"
        if (Test-Path -Path "$evidence_path") {
        } else {
            New-Item -Path ".\" -Name "$evidence_path" -ItemType "directory"  | Out-Null
        }
        }
    catch{}
}

function Gather-TCPConnections
{
    try{
        Write-Host "Capturing: Network Connections"
        Get-NetTcpConnection -ErrorAction SilentlyContinue | Select * | Export-Csv -NoTypeInformation -Path .\$evidence_path\network_connections.csv
    }catch{}
}

function Gather-Services
{
    try{
        Write-Host "Capturing: Installed Services"
        Get-WmiObject win32_service -ErrorAction SilentlyContinue | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\windows_services.csv
    }catch{}
}

function Gather-Processes
{
    try{
        Write-Host "Capturing: Running Processes"
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select * | Export-Csv -NoTypeInformation -Path .\$evidence_path\running_processes.csv
    }catch{}
}

function Gather-DNS
{
    try{
        Write-Host "Capturing: DNS Cache"
        Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\dns_cache.csv
    }catch{}
}

function Gather-SMB
{
    try{
        Write-Host "Capturing: SMB Shares"
        Get-SmbShare -ErrorAction SilentlyContinue | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\smb_shares.csv
    }catch{}
}

function Gather-Tasks
{
    try{
        Write-Host "Capturing: Scheduled Tasks"
        Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\scheduled_tasks.csv
    }catch{}
}

function Gather-Defender-Detections
{
    try{
        Write-Host "Capturing: Defender Detections"
        Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\defender_threats.csv
    }catch{}
}

function Gather-EventLogs
{
    try{
        Write-Host "Capturing: Windows Event Logs"
        try{
            New-Item -Path ".\" -Name "$evidence_path\eventlogs" -ItemType "directory" | Out-Null
        }catch{}
    Copy-Item -Path "$env:SystemRoot\System32\winevt\logs\*" -Destination ".\$evidence_path\eventlogs" -Recurse -ErrorAction SilentlyContinue
    }catch{
        Write-Warning "Error Capturing Event Logs"
    }
}

function Gather-NetConfig
{
    try{
        Write-Host "Capturing: Network Configuration"
        ipconfig /all > $evidence_path\ipconfig.txt
    }catch{}
}

function Gather-PatchInfo
{
    try{
        Write-Host "Capturing: Patch Information"
        wmic qfe list full > $evidence_path\patches.txt
    }catch{}
}

function Gather-QData
{
    try{
        Write-Host "Capturing: Remote Sessions/Processes"
        "QWINSTA" > $evidence_path\remote_sessions.txt
        qwinsta >> $evidence_path\remote_sessions.txt
        "QUSER" >> $evidence_path\remote_sessions.txt
        quser >> $evidence_path\remote_sessions.txt
        "QPROCESS" >> $evidence_path\remote_sessions.txt
        qprocess >> $evidence_path\remote_sessions.txt
    }catch{}
}

function Gather-LocalAdmins
{
    try{
        Write-Host "Capturing: Local Admins"
        net localgroup administrators > $evidence_path\local_admins.txt
    }catch{}
}

function Gather-StartupItems
{
    try{
        Write-Host "Capturing: Startup Items"
        net start > $evidence_path\startup_items.txt
        "WMIC STARTUP ITEMS" >> $evidence_path\startup_items.txt
        wmic startup get * /format:list >> $evidence_path\startup_items.txt
    }catch{}
}

function Gather-SysInfo
{
    try{
    Write-Host "Capturing: System Information"
    system info > $evidence_path\system_info.txt
    }catch{}
}

function Gather-FirewallRules
{
    try {
    Write-Host "Capturing: Firewall Rules"
    Get-NetFirewallRule -ErrorAction SilentlyContinue | Select * | Export-Csv -NoTypeInformation -Path  $evidence_path\firewall_rules.csv
    } catch{}
}

function Gather-ARP
{
    try {
        Write-Host "Capturing: ARP Cache"
        Get-NetNeighbor -ErrorAction SilentlyContinue | Select * | Export-Csv -NoTypeInformation -Path  $evidence_path\arp_cache.csv
    } catch{}
}

function Gather-NetCommands
{
    Write-Host "Capturing: Net Commands"
    try {
        Write-Host "Capturing: Net Session"
        Invoke-Expression "cmd.exe /c net session >> $evidence_path\net_session.txt" -ErrorAction SilentlyContinue | Out-Null
    }
    catch { }
    try {
        Write-Host "Capturing: Net Use"
        Invoke-Expression "cmd.exe /c net use >> $evidence_path\net_use.txt" -ErrorAction SilentlyContinue | Out-Null
    }
    catch { }
    try {
        Write-Host "Capturing: Net User"
        Invoke-Expression "cmd.exe /c net user >> $evidence_path\net_user.txt" -ErrorAction SilentlyContinue | Out-Null
    }
    catch { }
    try {
        Write-Host "Capturing: Net View"
        Invoke-Expression "cmd.exe /c net view >> $evidence_path\net_view.txt" -ErrorAction SilentlyContinue | Out-Null
    }
    catch { }
    try {
        Write-Host "Capturing: Net Share"
        Invoke-Expression "cmd.exe /c net share >> $evidence_path\net_share.txt" -ErrorAction SilentlyContinue | Out-Null
    }
    catch { }
    try {
        Write-Host "Capturing: Net File"
        Invoke-Expression "cmd.exe /c net file >> $evidence_path\net_file.txt" -ErrorAction SilentlyContinue | Out-Null
    }
    catch { }
    try {
        Write-Host "Capturing: Net Accounts"
        Invoke-Expression "cmd.exe /c net accounts >> $evidence_path\net_accounts.txt" -ErrorAction SilentlyContinue | Out-Null
    }
    catch { }
    try {
        Write-Host "Capturing: Net Localgroup"
        Invoke-Expression "cmd.exe /c net localgroup >> $evidence_path\net_localgroup.txt" -ErrorAction SilentlyContinue | Out-Null
    }
    catch { }
}

function Gather-SuspiciousFiles
{
    try
    {
        Write-Host "Capturing: Suspicious Files [LONG]"
        Get-ChildItem -Path C:\ -Include *.exe, *.bat, *.ps1, *.dll -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-15) } | Select-Object PSPath, PSParentPath, PSChildName, PSDrive, PSProvider, PSIsContainer, Mode, LinkType, Name, Length, DirectoryName, Directory, IsReadOnly, Exists, FullName, Extension, CreationTime, CreationTimeUtc, LastAccessTime, LastAccessTimeUtc, LastWriteTime, LastWriteTimeUtc | Export-Csv -NoTypeInformation -Path  $evidence_path\suspicious_files.csv

    }
    catch
    {
    }
}

function Gather-USN
{
    try
    {
        Write-Host "Capturing: USN Journal [LONG]"
        fsutil usn readjournal C: csv > .\$evidence_path\usn_journal.csv
    }
    catch
    {
    }
}

function Gather-AV-Data
# https://github.com/ForensicArtifacts/artifacts/blob/main/data/antivirus.yaml
{

    try {
        if (Test-Path -Path ".\$evidence_path\quarantined_files") {
        } else {
            New-Item -Path ".\" -Name ".\$evidence_path\quarantined_files" -ItemType "directory" | Out-Null
        }
        }
    catch {}
    try {
        Write-Host "Capturing: CrowdStrike Quarantined Files"
        New-Item -Path ".\" -Name ".\$evidence_path\quarantined_files\crowdstrike" -ItemType "directory" | Out-Null
        Copy-Item -Path "$env:SystemRoot\System32\drivers\CrowdStrike\Quarantine\*" -Destination ".\$evidence_path\quarantined_files\crowdstrike" -Recurse -ErrorAction SilentlyContinue
    }
    catch {}
    try {
        Write-Host "Capturing: ESET AV Log Files"
        New-Item -Path ".\" -Name ".\$evidence_path\quarantined_files\eset" -ItemType "directory" | Out-Null
        Copy-Item -Path "$env:SystemDrive\ProgramData\ESET\ESET NOD32 Antivirus\Logs\*" -Destination ".\$evidence_path\quarantined_files\eset" -Recurse -ErrorAction SilentlyContinue
    }
    catch {}
    try {
        Write-Host "Capturing: Microsoft Antimalware"
        New-Item -Path ".\" -Name ".\$evidence_path\quarantined_files\microsoft" -ItemType "directory" | Out-Null
        Copy-Item -Path "$env:SystemDrive\ProgramData\Microsoft\Microsoft Antimalware\Quarantine\*" -Destination ".\$evidence_path\quarantined_files\microsoft" -Recurse -ErrorAction SilentlyContinue
    }
    catch {}
    try {
        Write-Host "Capturing: Microsoft Defender"
        Copy-Item -Path "$env:SystemDrive\ProgramData\Microsoft\Windows Defender\Quarantine\*" -Destination ".\$evidence_path\quarantined_files\microsoft" -Recurse -ErrorAction SilentlyContinue
    }
    catch {}
    try {
        Write-Host "Capturing: Microsoft AV Logs"
        Copy-Item -Path "$env:SystemDrive\ProgramData\Microsoft\Windows AntiMalware\Support\MPDetection-*.log" -Destination ".\$evidence_path\quarantined_files\microsoft" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$env:SystemDrive\ProgramData\Microsoft\Windows AntiMalware\Support\MPLog-*.log" -Destination ".\$evidence_path\quarantined_files\microsoft" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$env:SystemDrive\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\*" -Destination ".\$evidence_path\quarantined_files\microsoft" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$env:SystemDrive\ProgramData\Microsoft\Windows Defender\Support\MPDetection-*.log" -Destination ".\$evidence_path\quarantined_files\microsoft" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$env:SystemDrive\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log" -Destination ".\$evidence_path\quarantined_files\microsoft" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\Temp\MpCmdRun.log" -Destination ".\$evidence_path\quarantined_files\microsoft" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$env:SystemRoot\Temp\MpCmdRun.log" -Destination ".\$evidence_path\quarantined_files\microsoft" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$env:SystemDrive\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\*\*-*-*-*" -Destination ".\$evidence_path\quarantined_files\microsoft" -Recurse -ErrorAction SilentlyContinue
    }
    catch {}
    try {
        Write-Host "Capturing: Sophos AV Data"
        New-Item -Path ".\" -Name ".\$evidence_path\quarantined_files\sophos" -ItemType "directory" | Out-Null
        Copy-Item -Path "$env:SystemDrive\ProgramData\Sophos\Sophos Anti-Virus\Logs\*" -Destination ".\$evidence_path\quarantined_files\sophos" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$env:SystemDrive\ProgramData\Sophos\Sophos Anti-Virus\INFECTED\*" -Destination ".\$evidence_path\quarantined_files\sophos" -Recurse -ErrorAction SilentlyContinue
    }
    catch {}
    try {
        Write-Host "Capturing: Symantec AV Data"
        New-Item -Path ".\" -Name ".\$evidence_path\quarantined_files\symantec" -ItemType "directory" | Out-Null
        Copy-Item -Path "$env:SystemDrive\ProgramData\Symantec\Symantec Endpoint Protection\*\Data\Logs\*.log" -Destination ".\$evidence_path\quarantined_files\symantec" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$env:SystemDrive\ProgramData\Symantec\Symantec Endpoint Protection\*\Data\Logs\AV\*.log" -Destination ".\$evidence_path\quarantined_files\symantec" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$env:SystemDrive\ProgramData\Symantec\Symantec Endpoint Protection\Logs\AV\*.log" -Destination ".\$evidence_path\quarantined_files\symantec" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$env:SystemRoot\Users\*\AppData\Local\Symantec\Symantec Endpoint Protection\Logs\*.log" -Destination ".\$evidence_path\quarantined_files\symantec" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$env:SystemDrive\ProgramData\Symantec\Symantec Endpoint Protection\**5\*.vbn" -Destination ".\$evidence_path\quarantined_files\symantec" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$env:SystemDrive\ProgramData\Symantec\Symantec Endpoint Protection\Quarantine\*" -Destination ".\$evidence_path\quarantined_files\symantec" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$env:SystemDrive\Symantec\Symantec Endpoint Protection\*\Data\Quarantine\*" -Destination ".\$evidence_path\quarantined_files\symantec" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$env:SystemDrive\Symantec\Symantec Endpoint Protection\*\Data\CmnClnt\ccSubSDK\*" -Destination ".\$evidence_path\quarantined_files\symantec" -Recurse -ErrorAction SilentlyContinue
    }
    catch {}

}

function Gather-Prefetch-Files
{
    try{
        Write-Host "Capturing: Prefetch Files"
        try{
            New-Item -Path ".\" -Name "$evidence_path\prefetch" -ItemType "directory" | Out-Null
        }catch{}
    Copy-Item -Path "$env:SystemRoot\prefetch\*" -Destination ".\$evidence_path\prefetch" -Recurse -ErrorAction SilentlyContinue
    }catch{
        Write-Warning "Error Capturing Prefetch Files"
    }
}


function Main
{
    Logo
    Create-Evidence-Dir
    Gather-EventLogs
    Gather-TCPConnections
    Gather-Services
    Gather-Processes
    Gather-DNS
    Gather-SMB
    Gather-Tasks
    Gather-Defender-Detections
    Gather-NetConfig
    Gather-PatchInfo
    Gather-QData
    Gather-LocalAdmins
    Gather-StartupItems
    Gather-SysInfo
    Gather-FirewallRules
    Gather-ARP
    Gather-NetCommands
    Gather-AV-Data
    Gather-Prefetch-Files
    #Gather-SuspiciousFiles
    #Gather-USN
}

function Logo {
    $logo = "
                  ▄████████    ▄████████  ▄█  ████████▄
                  ███    ███   ███    ███ ███  ███   ▀███
                  ███    ███   ███    ███ ███▌ ███    ███
                 ▄███▄▄▄▄██▀   ███    ███ ███▌ ███    ███
                ▀▀███▀▀▀▀▀   ▀███████████ ███▌ ███    ███
                ▀███████████   ███    ███ ███  ███    ███
                  ███    ███   ███    ███ ███  ███   ▄███
                  ███    ███   ███    █▀  █▀   ████████▀
                  ███    ███
            "
    Write-Host $logo
    Write-Host "Rapid Acquisition of Interesting Data"
    Write-Host "github.com/joeavanzato/RAID"
}


Main