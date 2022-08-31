

Write-Host "RAID: Rapid Acquisition of Interesting Data"
$evidence_path = "Evidence_triage_$env:computername"

function Create-Evidence-Dir
{
    try{
        Write-Host "Creating Evidence Directory: $evidence_path"
        if (Test-Path -Path "$evidence_path") {
        } else {
            New-Item -Path ".\" -Name "$evidence_path" -ItemType "directory"
        }
        }
    catch{}
}

function Gather-TCPConnections
{
    try{
        Write-Host "Capturing: Network Connections"
        Get-NetTcpConnection | Select * | Export-Csv -NoTypeInformation -Path .\$evidence_path\network_connections.csv
    }catch{}
}

function Gather-Services
{
    try{
        Write-Host "Capturing: Installed Services"
        Get-WmiObject win32_service | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\windows_services.csv
    }catch{}
}

function Gather-Processes
{
    try{
        Write-Host "Capturing: Running Processes"
        Get-CimInstance Win32_Process | Select * | Export-Csv -NoTypeInformation -Path .\$evidence_path\running_processes.csv
    }catch{}
}

function Gather-DNS
{
    try{
        Write-Host "Capturing: DNS Cache"
        Get-DnsClientCache | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\dns_cache.csv
    }catch{}
}

function Gather-SMB
{
    try{
        Write-Host "Capturing: SMB Shares"
        Get-SmbShare | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\smb_shares.csv
    }catch{}
}

function Gather-Tasks
{
    try{
        Write-Host "Capturing: Scheduled Tasks"
        Get-ScheduledTask | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\scheduled_tasks.csv
    }catch{}
}

function Gather-Defender-Detections
{
    try{
        Write-Host "Capturing: Defender Detections"
        Get-MpThreatDetection | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\defender_threats.csv
    }catch{}
}

function Gather-EventLogs
{
    try{
        Write-Host "Capturing: Windows Event Logs"
        try{
            New-Item -Path ".\" -Name "$evidence_path\eventlogs" -ItemType "directory"
        }catch{}
    Copy-Item -Path "C:\Windows\System32\winevt\logs\*" -Destination ".\$evidence_path\eventlogs" -Recurse
    }catch{}
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
    Get-NetFirewallRule | Select * | Export-Csv -NoTypeInformation -Path  $evidence_path\firewall_rules.csv
    } catch{}
}

function Gather-ARP
{
    try {
        Write-Host "Capturing: ARP Cache"
        Get-NetNeighbor | Select * | Export-Csv -NoTypeInformation -Path  $evidence_path\arp_cache.csv
    } catch{}
}

function Gather-NetCommands
{

    try
    {
        Write-Host "Capturing: NET Data"
        "NET SESSION" >> $evidence_path\net_data.csv
        net session >> $evidence_path\net_data.csv
        "NET USE" >> $evidence_path\net_data.csv
        net use >> $evidence_path\net_data.csv
        "NET USER" >> $evidence_path\net_data.csv
        net user >> $evidence_path\net_data.csv
        "NET VIEW" >> $evidence_path\net_data.csv
        net view >> $evidence_path\net_data.csv
        "NET SHARE" >> $evidence_path\net_data.csv
        net share >> $evidence_path\net_data.csv
        "NET FILE" >> $evidence_path\net_data.csv
        net file >> $evidence_path\net_data.csv
        "NET ACCOUNTS" >> $evidence_path\net_data.csv
        net accounts >> $evidence_path\net_data.csv
        "NET LOCALGROUP" >> $evidence_path\net_data.csv
        net localgroup >> $evidence_path\net_data.csv
    }
    catch
    {
    }

}

function Gather-SuspiciousFiles
{
    try
    {
        Write-Host "Capturing: Suspicious File Types [LONG]"
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

function Main
{
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
    Gather-SuspiciousFiles
    Gather-USN
}

Main