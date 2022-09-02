<#
.SYNOPSIS

RAID - Rapid Acquisition of Interesting Data

RAID is a PowerShell script designed to add DFIR response teams in the collection of forensically useful and interesting data from potentially compromised endpoints.

.DESCRIPTION

RAID will execute a series of functions which will extract data, copy files, read registry key-values or otherwise export data from the system and aggregate it into a centralized location.

Data pulled includes network configurations, ARP/DNS caches, Windows Event Logs, various Windows activity databases, Scheduled Tasks and Services, Firewall Rules, NET Command output, Prefetch data, Windows Error Reporting dumps, URL Caches, BITS/Cortana/etc DBs, Browser Files, NTUSER.dat data-stores and more.

Additionally, RAID will offer analysts the ability to download multiple third-party utilities and automate their use against collected data once it has been removed from the suspicious device or in-line if internet access is available.

.PARAMETER vss
Specifies whether or not vssadmin will be used to allow access to locked files.

.PARAMETER utils

.INPUTS

None.

.OUTPUTS

None.

.EXAMPLE

PS> .\raid.ps1 vss

.EXAMPLE

PS> .\raid.ps1 utils -path ".\evidence_hostname_example\

#>


param(
     [Parameter()]
     [string]$vss,

     [Parameter()]
     [string]$utils,

     [Parameter()]
     [string]$path
 )

if ($vss) {
    $shadowcopy_name = "shadowcopy"
    $root = $env:systemdrive+"\"+$shadowcopy_name
} else {
    $root = $env:systemdrive
}

if ($data_types) {
} else {
}


$datetime = Get-Date -Format "MM_dd_yyyy_HH_mm"
$evidence_path = "Evidence_triage_$env:computername"+"$datetime"
$shadowcopy_name = "shadowcopy"
$shadow_root = $env:systemdrive+"\"+$shadowcopy_name
$LogFile = "$evidence_path\log.txt"

function Create-Evidence-Dir
{
    try{
        Write-Host "Creating Evidence Directory: $evidence_path"
        if (Test-Path -Path "$evidence_path") {
        } else {
            New-Item -Path ".\" -Name "$evidence_path" -ItemType "directory"  | Out-Null
            Write-Log "Evidence Directory Created Successfully"
        }
        }
    catch{
        Write-Warning "Error Creating Evidence Directory!"
    }
}

function Gather-TCPConnections
{
    try{
        Write-Host "Capturing: TCP Connections"
        Write-Log "Capturing: TCP Connections"
        Get-NetTcpConnection -ErrorAction SilentlyContinue | Select * | Export-Csv -NoTypeInformation -Path .\$evidence_path\network_connections.csv
    }catch{
        Write-Warning "Error Capturing TCP Connections"
        Write-Log "Error Capturing TCP Connections"
    }
}

function Gather-Services
{
    try{
        Write-Host "Capturing: Windows Services"
        Write-Log "Capturing: Windows Services"
        Get-WmiObject win32_service -ErrorAction SilentlyContinue | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\windows_services.csv
    }catch{
        Write-Warning "Error Capturing Windows Services"
        Write-Log "Error Capturing Windows Services"
    }
}

function Gather-Processes
{
    try{
        Write-Host "Capturing: Running Processes"
        Write-Log "Capturing: Running Processes"
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select * | Export-Csv -NoTypeInformation -Path .\$evidence_path\running_processes.csv
    }catch{
        Write-Warning "Error Capturing Running Processes"
        Write-Log "Error Capturing Running Processes"
    }
}

function Gather-DNS
{
    try{
        Write-Host "Capturing: DNS Cache"
        Write-Log "Capturing: DNS Cache"
        Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\dns_cache.csv
    }catch{
        Write-Warning "Error Capturing DNS Cache"
        Write-Log "Error Capturing DNS Cache"
    }
}

function Gather-SMB
{
    try{
        Write-Host "Capturing: SMB Shares"
        Write-Log "Capturing: SMB Shares"
        Get-SmbShare -ErrorAction SilentlyContinue | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\smb_shares.csv
    }catch{
        Write-Warning "Error Capturing SMB Shares"
        Write-Log "Error Capturing SMB Shares"
    }
}

function Gather-Tasks
{
    try{
        Write-Host "Capturing: Windows Scheduled Tasks"
        Write-Log "Capturing: Windows Scheduled Tasks"
        Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\scheduled_tasks.csv
    }catch{
        Write-Warning "Error Capturing Windows Scheduled Tasks"
        Write-Log "Error Capturing Windows Scheduled Tasks"
    }
}

function Gather-Defender-Detections
{
    try{
        Write-Host "Capturing: Windows Defender Detections"
        Write-Log "Capturing: Windows Defender Detections"
        Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\defender_threats.csv
    }catch{
        Write-Warning "Error Capturing Windows Defender Detections"
        Write-Log "Error Capturing Windows Defender Detections"
    }
}

function Gather-EventLogs
{
    try{
        Write-Host "Capturing: Windows Event Logs"
        Write-Log "Capturing: Windows Event Logs"
        try{
            New-Item -Path ".\" -Name "$evidence_path\eventlogs" -ItemType "directory" | Out-Null
        }catch{}
    Copy-Item -Path "$env:SystemRoot\System32\winevt\logs\*" -Destination ".\$evidence_path\eventlogs" -Recurse -ErrorAction SilentlyContinue
    }catch{
        Write-Warning "Error Capturing Windows Event Logs"
        Write-Log "Error Capturing Windows Event Logs"
    }
}

function Gather-NetConfig
{
    try{
        Write-Host "Capturing: Network Configuration"
        Write-Log "Capturing: Network Configuration"
        ipconfig /all > $evidence_path\ipconfig.txt
    }catch{
        Write-Warning "Error Capturing Network Configuration"
        Write-Log "Error Capturing Network Configuration"
    }
}

function Gather-PatchInfo
{
    try{
        Write-Host "Capturing: Patch Information"
        Write-Log "Capturing: Patch Information"
        wmic qfe list full > $evidence_path\patches.txt
    }catch{
        Write-Warning "Error Capturing Patch Information"
        Write-Log "Error Capturing Patch Information"
    }
}

function Gather-QData
{
    try{
        Write-Host "Capturing: Remote Sessions/Processes"
        Write-Log "Capturing: Remote Sessions/Processes"
        qwinsta >> $evidence_path\qwinsta.txt
        quser >> $evidence_path\quser.txt
        qprocess >> $evidence_path\qprocess.txt
    }catch{
        Write-Warning "Error Capturing Remote Sessions/Processes"
        Write-Log "Error Capturing Remote Sessions/Processes"
    }
}

function Gather-LocalAdmins
{
    try{
        Write-Host "Capturing: Local Admins"
        Write-Log "Capturing: Local Admins"
        net localgroup administrators > $evidence_path\local_admins.txt
    }catch{
        Write-Warning "Error Capturing Local Admins"
        Write-Log "Error Capturing Local Admins"
    }
}

function Gather-StartupItems
{
    try{
        Write-Host "Capturing: Startup Items"
        Write-Log "Capturing: Startup Items"
        net start > $evidence_path\startup_items.txt
        "WMIC STARTUP ITEMS" >> $evidence_path\startup_items.txt
        wmic startup get * /format:list >> $evidence_path\startup_items.txt
    }catch{
        Write-Warning "Error Capturing Startup Items"
        Write-Log "Error Capturing Startup Items"
    }
}

function Gather-SysInfo
{
    try{
        Write-Host "Capturing: System Information"
        Write-Log "Capturing: System Information"
        systeminfo > $evidence_path\systeminfo.txt
    }catch{
        Write-Warning "Error Capturing System Information"
        Write-Log "Error Capturing System Information"
    }
}

function Gather-FirewallRules
{
    try {
        Write-Host "Capturing: Firewall Rules"
        Write-Log "Capturing: Firewall Rules"
        Get-NetFirewallRule -ErrorAction SilentlyContinue | Select * | Export-Csv -NoTypeInformation -Path  $evidence_path\firewall_rules.csv
    } catch{
        Write-Warning "Error Capturing Firewall Rules"
        Write-Log "Error Capturing Firewall Rules"
    }
}

function Gather-ARP
{
    try {
        Write-Host "Capturing: ARP Cache"
        Write-Log "Capturing: ARP Cache"
        Get-NetNeighbor -ErrorAction SilentlyContinue | Select * | Export-Csv -NoTypeInformation -Path  $evidence_path\arp_cache.csv
    } catch{
        Write-Warning "Error Capturing ARP Cache"
        Write-Log "Error Capturing ARP Cache"
    }
}

function Gather-NetCommands
{
    Write-Host "Capturing: Net Commands"
    try {
        Write-Host "Capturing: Net Session"
        Write-Log "Capturing: Net Session"
        Invoke-Expression "cmd.exe /c net session >> $evidence_path\net_session.txt" -ErrorAction SilentlyContinue | Out-Null
    }
    catch { }
    try {
        Write-Host "Capturing: Net Use"
        Write-Log "Capturing: Net Use"
        Invoke-Expression "cmd.exe /c net use >> $evidence_path\net_use.txt" -ErrorAction SilentlyContinue | Out-Null
    }
    catch { }
    try {
        Write-Host "Capturing: Net User"
        Write-Log "Capturing: Net User"
        Invoke-Expression "cmd.exe /c net user >> $evidence_path\net_user.txt" -ErrorAction SilentlyContinue | Out-Null
    }
    catch { }
    try {
        Write-Host "Capturing: Net View"
        Write-Log "Capturing: Net View"
        Invoke-Expression "cmd.exe /c net view >> $evidence_path\net_view.txt" -ErrorAction SilentlyContinue | Out-Null
    }
    catch { }
    try {
        Write-Host "Capturing: Net Share"
        Write-Log "Capturing: Net Share"
        Invoke-Expression "cmd.exe /c net share >> $evidence_path\net_share.txt" -ErrorAction SilentlyContinue | Out-Null
    }
    catch { }
    try {
        Write-Host "Capturing: Net File"
        Write-Log "Capturing: Net File"
        Invoke-Expression "cmd.exe /c net file >> $evidence_path\net_file.txt" -ErrorAction SilentlyContinue | Out-Null
    }
    catch { }
    try {
        Write-Host "Capturing: Net Accounts"
        Write-Log "Capturing: Net Accounts"
        Invoke-Expression "cmd.exe /c net accounts >> $evidence_path\net_accounts.txt" -ErrorAction SilentlyContinue | Out-Null
    }
    catch { }
    try {
        Write-Host "Capturing: Net Localgroup"
        Write-Log "Capturing: Net Localgroup"
        Invoke-Expression "cmd.exe /c net localgroup >> $evidence_path\net_localgroup.txt" -ErrorAction SilentlyContinue | Out-Null
    }
    catch { }
}

function Gather-SuspiciousFiles
{
    try
    {
        Write-Host "Capturing: Suspicious Files [LONG]"
        Write-Log "Capturing: Suspicious Files [LONG]"
        Get-ChildItem -Path $root\temp,$root\windows\system32,$root\windows\temp,$root\Users,$root\programdata -Include *.htm,*.vbs,*.hta,*.chm,*.exe,*.bat,*.ps1,*.zip,*.gz,*.7z,*.vba,*.ps,*.psm1,*.docm,*.xlsm,*.pptm,*.potm,*.ppam,*.ppsm,*.sldm,*.dotm,*.xltm,*.xlam,*.lnk,*.vb,*.pdf,*.jar,*.msi,*.msp,*.gadget,*.cmd,*.vbe,*.jsp,*.scr,*.rar,*.msh,*.wsh,*.wsf,*.scf -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-15) } | Select-Object PSPath, PSParentPath, PSChildName, PSDrive, PSProvider, PSIsContainer, Mode, LinkType, Name, Length, DirectoryName, Directory, IsReadOnly, Exists, FullName, Extension, CreationTime, CreationTimeUtc, LastAccessTime, LastAccessTimeUtc, LastWriteTime, LastWriteTimeUtc | Export-Csv -NoTypeInformation -Path  $evidence_path\suspicious_files.csv
    }
    catch
    {
        Write-Warning "Error Capturing Suspicious Files"
        Write-Log "Error Capturing Suspicious Files"
    }
}

function Gather-USN
{
    try
    {
        Write-Host "Capturing: USN Journal [LONG]"
        Write-Log "Capturing: USN Journal [LONG]"
        fsutil usn readjournal C: csv > .\$evidence_path\usn_journal.csv
    }
    catch
    {
        Write-Warning "Error Capturing USN Journal"
        Write-Log "Error Capturing USN Journal"
    }
}

function Gather-AV-Data
{
    # https://github.com/ForensicArtifacts/artifacts/blob/main/data/antivirus.yaml
    Write-Host "Capturing: AV Logs/Data"
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
    Write-Host "Capturing: Prefetch Files"
    Write-Log "Capturing: Prefetch Files"
    try{
        try{
            New-Item -Path ".\" -Name "$evidence_path\prefetch" -ItemType "directory" | Out-Null
        }catch{}
        Copy-Item -Path "$env:SystemRoot\prefetch\*" -Destination ".\$evidence_path\prefetch" -Recurse -ErrorAction SilentlyContinue
    }catch{
        Write-Warning "Error Capturing Prefetch Files"
        Write-Log "Error Capturing Prefetch Files"
    }
}

function Gather-PowerShell-History
{
    Write-Host "Capturing: PowerShell History Files"
    Write-Log "Capturing: PowerShell History Files"
    try{
        New-Item -Path ".\" -Name "$evidence_path\ps_history" -ItemType "directory" | Out-Null
        Copy-Item -Path "$env:SystemDrive\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Destination ".\$evidence_path\ps_history" -Recurse -ErrorAction SilentlyContinue
    } catch{
        Write-Warning "Error Capturing PS History Files"
        Write-Log "Error Capturing PS History Files"
    }
}

function Gather-Installed-Software
{
    Write-Host "Capturing: Installed Software"
    Write-Log "Capturing: Installed Software"
    try{
        $InstalledSoftware = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        $InstalledSoftware += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        $InstalledSoftware | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Export-Csv "$evidence_path\installed_software.csv" -Encoding UTF8 -NoTypeInformation
    }
     catch{
        Write-Warning "Error Capturing Installed Software"
        Write-Log "Error Capturing Installed Software"
    }
}

function Gather-Amcache-Files
{
    Write-Host "Capturing: Amcache Hive Files"
    Write-Log "Capturing: Amcache Hive Files"
    New-Item -Path ".\" -Name "$evidence_path\amcache" -ItemType "directory" | Out-Null
    Copy-Item -Path "$root\Windows\AppCompat\Programs\Amcache.hve" -Destination ".\$evidence_path\amcache" -Recurse -ErrorAction SilentlyContinue
    Copy-Item -Path "$root\Windows\AppCompat\Programs\Amcache.hve.LOG1" -Destination ".\$evidence_path\amcache" -Recurse -ErrorAction SilentlyContinue
    Copy-Item -Path "$root\Windows\AppCompat\Programs\Amcache.hve.LOG2" -Destination ".\$evidence_path\amcache" -Recurse -ErrorAction SilentlyContinue

}

function Gather-Activities-Cache
{
    Write-Host "Capturing: Activity Cache"
    Write-Log "Capturing: Activity Cache"
    try{
        try{
            New-Item -Path ".\" -Name "$evidence_path\win_activity_cache" -ItemType "directory" | Out-Null
        }catch{}
        Copy-Item -Path "$root\Users\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db" -Destination ".\$evidence_path\win_activity_cache" -Recurse -ErrorAction SilentlyContinue
    }catch{
        Write-Warning "Error Capturing Activity Cache"
        Write-Log "Error Capturing Activity Cache"
    }
}

function Gather-BITS-DB
{
    Write-Host "Capturing: BITS Databases"
    Write-Log "Capturing: BITS Databases"
    try{
        New-Item -Path ".\" -Name "$evidence_path\win_bits" -ItemType "directory" | Out-Null
    }catch{}
    Copy-Item -Path "$root\ProgramData\Microsoft\Network\Downloader\qmgr*.dat" -Destination ".\$evidence_path\win_bits" -Recurse -ErrorAction SilentlyContinue
    Copy-Item -Path "$root\ProgramData\Microsoft\Network\Downloader\qmgr.db" -Destination ".\$evidence_path\win_bits" -Recurse -ErrorAction SilentlyContinue
}

function Gather-Cortana-DB
{
    Write-Host "Capturing: Cortana Databases"
    Write-Log "Capturing: Cortana Databases"
    try{
        try{
            New-Item -Path ".\" -Name "$evidence_path\win_cortana" -ItemType "directory" | Out-Null
        }catch{}
        Copy-Item -Path "$root\Users\*\AppData\Local\Packages\Microsoft.Windows.Cortana_*\AppData\Indexed DB\IndexedDB.edb" -Destination ".\$evidence_path\win_cortana" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$root\Users\*\AppData\Local\Packages\Microsoft.Windows.Cortana_*\LocalState\ESEDatabase_CortanaCoreInstance\CortanaCoreDb.dat" -Destination ".\$evidence_path\win_cortana" -Recurse -ErrorAction SilentlyContinue
    }catch{
        Write-Warning "Error Capturing Cortana Databases"
        Write-Log "Error Capturing Cortana Databases"
    }
}

function Gather-WER-Data
{
    Write-Host "Capturing: Windows Error Reporting Data"
    Write-Log "Capturing: Windows Error Reporting Data"
    New-Item -Path ".\" -Name "$evidence_path\win_wer" -ItemType "directory" | Out-Null
    Copy-Item -Path "$root\ProgramData\Microsoft\Windows\WER\*" -Destination ".\$evidence_path\win_wer" -Recurse -ErrorAction SilentlyContinue
    Copy-Item -Path "$root\Windows\*.dmp" -Destination ".\$evidence_path\win_wer" -Recurse -ErrorAction SilentlyContinue
    Copy-Item -Path "$root\Windows\Minidump\*.dmp" -Destination ".\$evidence_path\win_wer" -Recurse -ErrorAction SilentlyContinue
    Copy-Item -Path "$root\Windows\ServiceProfiles\AppData\Local\CrashDumps\*" -Destination ".\$evidence_path\win_wer" -Recurse -ErrorAction SilentlyContinue
    Copy-Item -Path "$root\Windows\ServiceProfiles\AppData\Local\Temp\*.dmp" -Destination ".\$evidence_path\win_wer" -Recurse -ErrorAction SilentlyContinue
    Copy-Item -Path "$root\Windows\System32\config\systemprofile\AppData\Local\CrashDumps\*" -Destination ".\$evidence_path\win_wer" -Recurse -ErrorAction SilentlyContinue
    Copy-Item -Path "$root\Windows\System32\config\systemprofile\AppData\Local\Temp\*.dmp" -Destination ".\$evidence_path\win_wer" -Recurse -ErrorAction SilentlyContinue
    Copy-Item -Path "$root\Windows\Temp\*.dmp" -Destination ".\$evidence_path\win_wer" -Recurse -ErrorAction SilentlyContinue
    Copy-Item -Path "$root\Users\*\AppData\Local\CrashDumps\*" -Destination ".\$evidence_path\win_wer" -Recurse -ErrorAction SilentlyContinue
    Copy-Item -Path "$root\Users\*\AppData\Microsoft\Windows\WER\*" -Destination ".\$evidence_path\win_wer" -Recurse -ErrorAction SilentlyContinue
    Copy-Item -Path "$root\Users\*\AppData\Temp\*.dmp" -Destination ".\$evidence_path\win_wer" -Recurse -ErrorAction SilentlyContinue

}

function Gather-Crypnet-Data {
    Write-Host "Capturing: Windows Cryptnet URL Caches"
    Write-Log "Capturing: Windows Cryptnet URL Caches"
    try{
        try{
            New-Item -Path ".\" -Name "$evidence_path\win_cryptnet_caches" -ItemType "directory" | Out-Null
        }catch{}
        Copy-Item -Path "$root\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\*" -Destination ".\$evidence_path\win_cryptnet_caches" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$root\Windows\SysWOW64\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\*" -Destination ".\$evidence_path\win_cryptnet_caches" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$root\Users\*\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\*" -Destination ".\$evidence_path\win_cryptnet_caches" -Recurse -ErrorAction SilentlyContinue
    }catch{
        Write-Warning "Error Capturing Windows Cryptnet URL Caches"
        Write-Log "Error Capturing Windows Cryptnet URL Caches"
    }

}


function Gather-Browser-Data {
    Write-Host "Capturing: Browser Artifacts"
    Write-Log "Capturing: Browser Artifacts"

    New-Item -Path ".\" -Name "$evidence_path\browser_data" -ItemType "directory" | Out-Null
    New-Item -Path ".\" -Name "$evidence_path\browser_data\chrome" -ItemType "directory" | Out-Null
    New-Item -Path ".\" -Name "$evidence_path\browser_data\edge" -ItemType "directory" | Out-Null
    New-Item -Path ".\" -Name "$evidence_path\browser_data\brave" -ItemType "directory" | Out-Null
    New-Item -Path ".\" -Name "$evidence_path\browser_data\chromium" -ItemType "directory" | Out-Null
    New-Item -Path ".\" -Name "$evidence_path\browser_data\opera" -ItemType "directory" | Out-Null
    New-Item -Path ".\" -Name "$evidence_path\browser_data\ie" -ItemType "directory" | Out-Null
    New-Item -Path ".\" -Name "$evidence_path\browser_data\firefox" -ItemType "directory" | Out-Null

    Write-Host "Capturing: Browser Caches"
    Write-Log "Capturing: Browser Caches"

    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\Application Cache\Cache\*" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\Cache\*" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\Media Cache\*" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\GPUCache\*" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\Application Cache\Cache\*" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\Cache\*" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\Media Cache\*" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\GPUCache\*" -target ".\$evidence_path\browser_data\chrome"

    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\User Data\*\Application Cache\Cache\*" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\User Data\*\Cache\*" -target ".\$evidence_path\browser_data\chromium"

    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Cache\*" -target ".\$evidence_path\browser_data\edge"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Edge\User Data\*\GPUCache\*" -target ".\$evidence_path\browser_data\edge"

    Copy-Tree -src "$root\Users\*\AppData\Roaming\Brave\*\Application Cache\Cache\*" -target ".\$evidence_path\browser_data\brave"
    Copy-Tree -src "$root\Users\*\AppData\Roaming\Brave\*\Cache\*" -target ".\$evidence_path\browser_data\brave"
    Copy-Tree -src "$root\Users\*\AppData\Roaming\Brave\*\GPUCache\*" -target ".\$evidence_path\browser_data\brave"
    Copy-Tree -src "$root\Users\*\AppData\Roaming\Brave\*\Media Cache\*" -target ".\$evidence_path\browser_data\brave"

    Copy-Tree -src "$root\Users\*\AppData\Roaming\Opera Software\Opera Stable\*\Application Cache\Cache\*" -target ".\$evidence_path\browser_data\opera"
    Copy-Tree -src "$root\Users\*\AppData\Roaming\Opera Software\Opera Stable\*\Cache\*" -target ".\$evidence_path\browser_data\opera"
    Copy-Tree -src "$root\Users\*\AppData\Roaming\Opera Software\Opera Stable\*\GPUCache\*" -target ".\$evidence_path\browser_data\opera"
    Copy-Tree -src "$root\Users\*\Opera Software\Opera Stable\*\Media Cache\*" -target ".\$evidence_path\browser_data\opera"

    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\*\Application Cache\Cache\*" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\*\Cache\*" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\*\GPUCache\*" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\*\Media Cache\*" -target ".\$evidence_path\browser_data\chromium"

    Write-Host "Capturing: Browser Cookies"
    Write-Log "Capturing: Browser Cookies"

    # Chromium
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\User Data\*\Cookies" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\User Data\*\Cookies-journal" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\User Data\*\Network\Cookies" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\User Data\*\Network\Cookies-journal" -target ".\$evidence_path\browser_data\chromium"

    # Chrome
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\Cookies" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\Cookies-journal" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\Network\Cookies" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\Network\Cookies-journal" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\Cookies" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\Cookies-journal" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\Network\Cookies" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\Network\Cookies-journal" -target ".\$evidence_path\browser_data\chrome"

    # Edge
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Cookies" -target ".\$evidence_path\browser_data\edge"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Cookies-journal" -target ".\$evidence_path\browser_data\edge"

    # IE
    Copy-Tree -src "$root\Users\*\AppData\Roaming\Microsoft\Windows\Cookies\index.dat" -target ".\$evidence_path\browser_data\ie"
    Copy-Tree -src "$root\Users\*\AppData\Roaming\Microsoft\Windows\Cookies\Low\index.dat" -target ".\$evidence_path\browser_data\ie"

    Write-Host "Capturing: Browser Extensions (Chromium)"
    Write-Log "Capturing: Browser Extensions (Chromium)"

    Copy-Tree -src "$root\Users\*\AppData\Roaming\Opera Software\Opera Stable\*\Extensions\*" -target ".\$evidence_path\browser_data\opera"
    Copy-Tree -src "$root\Users\*\AppData\Roaming\Brave\*\Extensions\*" -target ".\$evidence_path\browser_data\brave"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\*\Extensions\*" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\User Data\*\Extensions\*" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\Extensions\*" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\Extensions\*" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Edge Beta\User Data\*\Extensions\*" -target ".\$evidence_path\browser_data\edge"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Extensions\*" -target ".\$evidence_path\browser_data\edge"

    Write-Host "Capturing: Browser Activity Databases"
    Write-Log "Capturing: Browser Activity Databases"

    Copy-Tree -src "$root\Users\*\AppData\Roaming\Brave\*\Extension Activity" -target ".\$evidence_path\browser_data\brave"
    Copy-Tree -src "$root\Users\*\AppData\Roaming\Opera Software\Opera Stable\*\Extension Activity" -target ".\$evidence_path\browser_data\opera"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\*\Extension Activity" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\User Data\*\Extension Activity" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\Extension Activity" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\Extension Activity" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Edge Beta\User Data\*\Extension Activity" -target ".\$evidence_path\browser_data\edge"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Extension Activity" -target ".\$evidence_path\browser_data\edge"

    Write-Host "Capturing: Browser History"
    Write-Log "Capturing: Browser History"

    Copy-Tree -src "$root\Users\*\AppData\Roaming\Brave\*\Archived History" -target ".\$evidence_path\browser_data\brave"
    Copy-Tree -src "$root\Users\*\AppData\Roaming\Brave\*\Archived History-journal" -target ".\$evidence_path\browser_data\brave"
    Copy-Tree -src "$root\Users\*\AppData\Roaming\Brave\*\History" -target ".\$evidence_path\browser_data\brave"
    Copy-Tree -src "$root\Users\*\AppData\Roaming\Brave\*\History-journal" -target ".\$evidence_path\browser_data\brave"

    Copy-Tree -src "$root\Users\*\AppData\Roaming\Opera Software\Opera Stable\*\Archived History" -target ".\$evidence_path\browser_data\opera"
    Copy-Tree -src "$root\Users\*\AppData\Roaming\Opera Software\Opera Stable\*\Archived History-journal" -target ".\$evidence_path\browser_data\opera"
    Copy-Tree -src "$root\Users\*\AppData\Roaming\Opera Software\Opera Stable\*\History" -target ".\$evidence_path\browser_data\opera"
    Copy-Tree -src "$root\Users\*\AppData\Roaming\Opera Software\Opera Stable\*\History-journal" -target ".\$evidence_path\browser_data\opera"

    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\*\Archived History" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\*\Archived History-journal" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\*\History" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\*\History-journal" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\User Data\*\Archived History" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\User Data\*\Archived History-journal" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\User Data\*\History" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\User Data\*\History-journal" -target ".\$evidence_path\browser_data\chromium"

    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\Archived History" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\Archived History-journal" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\History" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\History-journal" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\Archived History" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\Archived History-journal" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\History" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\History-journal" -target ".\$evidence_path\browser_data\chrome"

    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Edge Beta\User Data\*\Archived History" -target ".\$evidence_path\browser_data\edge"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Edge Beta\User Data\*\Archived History-journal" -target ".\$evidence_path\browser_data\edge"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Edge Beta\User Data\*\History" -target ".\$evidence_path\browser_data\edge"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Edge Beta\User Data\*\History-journal" -target ".\$evidence_path\browser_data\edge"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Archived History" -target ".\$evidence_path\browser_data\edge"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Archived History-journal" -target ".\$evidence_path\browser_data\edge"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Edge\User Data\*\History" -target ".\$evidence_path\browser_data\edge"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Edge\User Data\*\History-journal" -target ".\$evidence_path\browser_data\edge"

    Write-Host "Capturing: Browser IndexedDB Files"
    Write-Log "Capturing: Browser IndexedDB Files"

    Copy-Tree -src "$root\Users\*\AppData\Local\Chromium\User Data\*\IndexedDB\*" -target ".\$evidence_path\browser_data\chromium"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\IndexedDB\*" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\IndexedDB\*" -target ".\$evidence_path\browser_data\chrome"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Edge\User Data\*\IndexedDB\*" -target ".\$evidence_path\browser_data\chrome"

    Write-Host "Capturing: Firefox Caches"
    Write-Log "Capturing: Firefox Caches"

    Copy-Tree -src "$root\Users\*\AppData\Local\Mozilla\Firefox\Profiles\*.default\Cache\*" -target ".\$evidence_path\browser_data\firefox"
    Copy-Tree -src "$root\Users\*\AppData\Local\Mozilla\Firefox\Profiles\*.default\cache2\*" -target ".\$evidence_path\browser_data\firefox"
    Copy-Tree -src "$root\Users\*\AppData\Local\Mozilla\Firefox\Profiles\*.default\cache2\doomed\*" -target ".\$evidence_path\browser_data\firefox"
    Copy-Tree -src "$root\Users\*\AppData\Local\Mozilla\Firefox\Profiles\*.default\cache2\entries\*" -target ".\$evidence_path\browser_data\firefox"

    Write-Host "Capturing: Firefox History"
    Write-Log "Capturing: Firefox History"

    Copy-Tree -src "$root\Users\*\AppData\Local\Mozilla\Firefox\Profiles\*\places.sqlite" -target ".\$evidence_path\browser_data\firefox"
    Copy-Tree -src "$root\Users\*\AppData\Local\Mozilla\Firefox\Profiles\*\places.sqlite-wal" -target ".\$evidence_path\browser_data\firefox"
    Copy-Tree -src "$root\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite" -target ".\$evidence_path\browser_data\firefox"

    Write-Host "Capturing: IE Browser Cache"
    Write-Log "Capturing: IE Browser Cache"

    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\*\*" -target ".\$evidence_path\browser_data\ie"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\Low\Content.IE5\*\*" -target ".\$evidence_path\browser_data\ie"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Windows\INetCache\IE\*\*" -target ".\$evidence_path\browser_data\ie"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Windows\INetCache\Low\*\*" -target ".\$evidence_path\browser_data\ie"

    Write-Host "Capturing: IE Browser History"
    Write-Log "Capturing: IE Browser History"

    Copy-Tree -src "$root\Users\*\AppData\Roaming\Microsoft\Windows\IEDownloadHistory\index.dat" -target ".\$evidence_path\browser_data\ie"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Feeds Cache\index.dat" -target ".\$evidence_path\browser_data\ie"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Windows\History\History.IE5\*\index.dat" -target ".\$evidence_path\browser_data\ie"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Windows\History\History.IE5\index.dat" -target ".\$evidence_path\browser_data\ie"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Windows\History\Low\History.IE5\*\index.dat" -target ".\$evidence_path\browser_data\ie"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Windows\History\Low\History.IE5\index.dat" -target ".\$evidence_path\browser_data\ie"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\index.dat" -target ".\$evidence_path\browser_data\ie"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\Low\Content.IE5\index.dat" -target ".\$evidence_path\browser_data\ie"
    Copy-Tree -src "$root\Users\*\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat" -target ".\$evidence_path\browser_data\ie"
    Copy-Tree -src "$root\Users\*\Local Settings\History\History.IE5\index.dat" -target ".\$evidence_path\browser_data\ie"


    #Copy-Item -Path "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\Application Cache\Cache\*" -Destination ".\$evidence_path\browser_data\chrome" -Recurse -ErrorAction SilentlyContinue
    #Copy-Item -Path "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\Cache\*" -Destination ".\$evidence_path\browser_data\chrome" -Recurse -ErrorAction SilentlyContinue
    #Copy-Item -Path "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\Media Cache\*" -Destination ".\$evidence_path\browser_data\chrome" -Recurse -ErrorAction SilentlyContinue
    #Copy-Item -Path "$root\Users\*\AppData\Local\Google\Chrome\User Data\*\GPUCache\*" -Destination ".\$evidence_path\browser_data\chrome" -Recurse -ErrorAction SilentlyContinue
    #Copy-Item -Path "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\Application Cache\Cache\*" -Destination ".\$evidence_path\browser_data\chrome" -Recurse -ErrorAction SilentlyContinue
    #Copy-Item -Path "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\Cache\*" -Destination ".\$evidence_path\browser_data\chrome" -Recurse -ErrorAction SilentlyContinue
    #Copy-Item -Path "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\Media Cache\*" -Destination ".\$evidence_path\browser_data\chrome" -Recurse -ErrorAction SilentlyContinue
    #Copy-Item -Path "$root\Users\*\AppData\Local\Google\Chrome SxS\User Data\*\GPUCache\*" -Destination ".\$evidence_path\browser_data\chrome" -Recurse -ErrorAction SilentlyContinue
    #Copy-Item -Path "$root\Users\*\AppData\Local\Chromium\User Data\*\Application Cache\Cache\*" -Destination ".\$evidence_path\browser_data\chrome" -Recurse -ErrorAction SilentlyContinue
    #Copy-Item -Path "$root\Users\*\AppData\Local\Chromium\User Data\*\Application Cache\Cache\*" -Destination ".\$evidence_path\browser_data\chrome" -Recurse -ErrorAction SilentlyContinue

}

function Gather-WMI-Data
{
    Write-Host "Capturing: WMI Information"
    New-Item -Path ".\" -Name "$evidence_path\win_wmi" -ItemType "directory" | Out-Null
    Write-Host "Capturing: WMI Users"
    Get-WmiObject -Query "select * FROM Win32_UserAccount" -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_useraccounts.csv"
    Write-Host "Capturing: WMI AV Products"
    Get-WmiObject -Query "select * FROM AntivirusProduct" -Namespace root\SecurityCenter2 -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_av.csv"
    Write-Host "Capturing: WMI PC Info"
    Get-WmiObject -Query "SELECT * FROM Win32_ComputerSystemProduct" -Namespace root/SecurityCenter2 -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_pc_info.csv"
    Write-Host "Capturing: WMI DNS Cache"
    Get-WmiObject -Query "SELECT * from MSFT_DNSClientCache" -Namespace root\StandardCimv2 -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_dns_cache.csv"
    Write-Host "Capturing: WMI Installed Drivers"
    Get-WmiObject -Query "SELECT DisplayName, Description, InstallDate, Name, PathName, Status, State, ServiceType from Win32_SystemDriver"  -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_drivers.csv"
    Write-Host "Capturing: WMI Active Script Event Consumers"
    Get-WmiObject -Query "SELECT * FROM ActiveScriptEventConsumer" -Namespace root\subscription  -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_asec.csv"
    Write-Host "Capturing: WMI Command Line Event Consumers"
    Get-WmiObject -Query "SELECT * FROM CommandLineEventConsumer" -Namespace root\subscription  -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_clec.csv"
    Write-Host "Capturing: WMI Hotfixes"
    Get-WmiObject -Query "SELECT * from Win32_QuickFixEngineering" -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_kbs.csv"
    Write-Host "Capturing: WMI Installed Software"
    Get-WmiObject -Query "SELECT Name, Vendor, Description, InstallDate, InstallDate2, Version from Win32_Product" -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_software.csv"
    Write-Host "Capturing: WMI Logical Disks"
    Get-WmiObject -Query "SELECT * FROM Win32_LogicalDisk" -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_disks.csv"
    Write-Host "Capturing: WMI Logged-On Sessions"
    Get-WmiObject -Query "SELECT * FROM Win32_LogonSession" -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_loggedon_sessions.csv"
    Write-Host "Capturing: WMI Logged-On Users"
    Get-WmiObject -Query "SELECT * FROM Win32_LoggedonUser" -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_loggedon_users.csv"
    Write-Host "Capturing: WMI Net Neighbors"
    Get-WmiObject -Query "SELECT * FROM MSFT_NetNeighbor" -Namespace root\StandardCimv2 -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_net_neighbors.csv"
    Write-Host "Capturing: WMI TCP Connections"
    Get-WmiObject -Query "SELECT * FROM MSFT_NetTCPConnection" -Namespace root\StandardCimv2 -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_tcp_connections.csv"
    Write-Host "Capturing: WMI UDP Endpoints"
    Get-WmiObject -Query "SELECT * FROM MSFT_NetUDPEndpoint" -Namespace root\StandardCimv2 -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_udp_endpoints.csv"
    Write-Host "Capturing: WMI Process List"
    Get-WmiObject -Query "SELECT * FROM Win32_Process" -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_process_list.csv"
    Write-Host "Capturing: WMI Scheduled Tasks"
    Get-WmiObject -Query "SELECT * FROM MSFT_ScheduledTask" -Namespace root\Microsoft\Windows\TaskScheduler -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_scheduled_tasks.csv"
    Write-Host "Capturing: WMI Services"
    Get-WmiObject -Query "SELECT * FROM Win32_Service" -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_services.csv"
    Write-Host "Capturing: WMI Startup"
    Get-WmiObject -Query "SELECT * FROM Win32_StartupCommand" -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_startup.csv"
    Write-Host "Capturing: WMI CCM Recent Apps"
    Get-WmiObject -Query "SELECT * FROM CCM_RecentlyUsedApps" -Namespace root\ccm\SoftwareMeteringAgent -ErrorAction SilentlyContinue | Select-Object * | Export-CSV -NoTypeInformation -Path "$evidence_path\win_wmi\wmi_ccm_recent_apps.csv"
}

function Gather-Recycle-Bin
{
    try
    {
        Write-Host "Capturing: Recycle Bin Information"
        Write-Log "Capturing: Recycle Bin Information"
        $shell = New-Object -com shell.application
        $rb = $shell.Namespace(10)
        $bin = $rb.items() | Parse-RecycleBin-Item | Export-CSV -NoTypeInformation -Path "$evidence_path\win_recyclebin.csv"
    } catch {
        Write-Warning "Error Capturing Recycle Bin Information"
        Write-Log "Error Capturing Recycle Bin Information"
    }

}

# Courtesy of https://jdhitsolutions.com/blog/powershell/7024/managing-the-recycle-bin-with-powershell/
Function Parse-RecycleBin-Item {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Item
    )
    #this function relies variables set in a parent scope
    Process {
        Write-Verbose "[$((Get-Date).TimeofDay) PROCESS] Processing $($item.path)"

        # uncomment for troubleshooting
        # $global:raw += $item
        if ($item.IsFolder -AND ($item.type -notmatch "ZIP")) {
            Write-Verbose "Enumerating $($item.name)"
            Try {
                #track the path name through each child object
                if ($fldpath) {
                    $fldpath = Join-Path -Path $fldPath -ChildPath $item.GetFolder.Title
                }
                else {
                    $fldPath = $item.GetFolder.Title
                }
                #recurse through child items
                $item.GetFolder().Items() | Parse-RecycleBin-Item
                Remove-Variable -Name fldpath
            }
            Catch {
               # Uncomment for troubleshooting
               # $global:rbwarn += $item
                Write-Warning ($item | Out-String)
                Write-Warning $_.exception.message
            }
        }
        else {
            #sometimes the original location is stored in an extended property
            $data = $item.ExtendedProperty("infotip").split("`n") | Where-Object { $_ -match "Original location" }
            if ($data) {
                $origPath = $data.split(":", 2)[1].trim()
                $full = Join-Path -path $origPath -ChildPath $item.name -ErrorAction stop
                Remove-Variable -Name data
            }
            else {
                #no extended property so use this code to attemp to rebuild the original location
                if ($item.parent.title -match "^[C-Zc-z]:\\") {
                    $origPath = $item.parent.title
                }
                elseif ($fldpath) {
                    $origPath = $fldPath
                }
                else {
                    $test = $item.parent
                    Write-Host "searching for parent on $($test.self.path)" -ForegroundColor cyan
                    do { $test = $test.parentfolder; $save = $test.title } until ($test.title -match "^[C-Zc-z]:\\" -OR $test.title -eq $save)
                    $origPath = $test.title
                }

                $full = Join-Path -path $origPath -ChildPath $item.name -ErrorAction stop
            }

            [pscustomobject]@{
                PSTypename       = "DeletedItem"
                Name             = $item.name
                Path             = $item.Path
                Modified         = $item.ModifyDate
                OriginalPath     = $origPath
                OriginalFullName = $full
                Size             = $item.Size
                IsFolder         = $item.IsFolder
                Type             = $item.Type
            }
        }
    } #process
}

function Copy-Tree {
    # This is not perfect because tree structure is not appropriately maintained.  Other solutions did not work cleanly.
    # Will revisit to implement copying full paths as directory names to at least preserve them
    Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [string] $src,
         [Parameter(Mandatory=$true, Position=1)]
         [string] $target
    )

    Get-ChildItem $src -filter "*" -recurse | `
        foreach{
            if($_.PsIsContainer)
            {
                Write-Log "Creating Directory: $targetFile"
                $targetFile = $target + $_.FullName.SubString($src.Length);
                New-Item -ItemType File -Path "$targetFile" -Force -ErrorAction SilentlyContinue | Out-Null
            }else
            {
                $temp = $_.FullName
                Write-Log "Copying: $temp to $targetFile"
                $targetFile = $target + $_.FullName.SubString($src.Length);
                New-Item -ItemType File -Path "$targetFile" -Force -ErrorAction SilentlyContinue | Out-Null
                Copy-Item "$_.FullName" -destination "$targetFile" -ErrorAction SilentlyContinue -Force | Out-Null
            }
        }
}

function Write-Log
{
    Param ([string]$message)
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $LogMessage = "$Stamp $message"
    Add-content $LogFile -value $LogMessage
}

# Below functions modified From JJ Fulmer awesome answer at https://stackoverflow.com/questions/14207788/accessing-volume-shadow-copy-vss-snapshots-from-powershell
function New-ShadowLink {
    [CmdletBinding()]
    param (
        $linkPath="$($ENV:SystemDrive)\$shadowcopy_name"
    )

    begin {
        Write-Host "Creating Shadow Copy of System Drive"
        Write-Verbose "Creating a snapshot of $($ENV:SystemDrive)\"
        $class=[WMICLASS]"root\cimv2:win32_shadowcopy";
        $result = $class.create("$ENV:SystemDrive\", "ClientAccessible");
        Write-Verbose "Getting the full target path for a symlink to the shadow snapshot"
        $global:shadow = Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object ID -eq $result.ShadowID
        $target = "$($shadow.DeviceObject)\";
        $global:shadowid = $shadow.ID
    }

    process {
        Write-Verbose "Creating SymLink to shadowcopy at $linkPath"
        Invoke-Expression -Command "cmd /c mklink /d '$linkPath' '$target'";
    }

    end {
        Write-Verbose "Created link to shadowcopy snapshot of $($ENV:SystemDrive)\ at $linkPath";
        Write-Verbose "Returning shadowcopy snapshot object"
        Write-Host "Shadow Copy ID: $shadowid"
        return $shadow;
    }
}

function Remove-ShadowLink {
    [CmdletBinding()]
    param (
        $shadow,
        $linkPath="$($ENV:SystemDrive)\$shadowcopy_name"
    )
    begin {
        Write-Host "Removing Shadow Copy Link at $linkPath"
    }

    process {
        #Write-Verbose "Deleting the shadowcopy snapshot"
        Write-Host "Executing: vssadmin delete shadows /shadow=$shadowid /quiet"
        vssadmin delete shadows /shadow=$shadowid /quiet > "$evidence_path\vss_output.txt"
        #$shadow.Delete();
        #Write-Verbose "Deleting the now empty folder"
        Try {
            Remove-Item -Force -Recurse $linkPath -ErrorAction Stop;
        }
        catch {
            Invoke-Expression -Command "cmd /c rmdir /S /Q '$linkPath'";
        }
    }

    end {
        #Write-Verbose "Shadow link and snapshot have been removed";
        return;
    }
}

function Main
{
    Logo
    Create-Evidence-Dir
    if ($vss) {
        $shadow = New-ShadowLink
    } else {}
    Gather-EventLogs
    Gather-PowerShell-History
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
    Gather-Installed-Software
    Gather-Amcache-Files
    Gather-Activities-Cache
    Gather-BITS-DB
    Gather-Cortana-DB
    Gather-WER-Data
    Gather-Crypnet-Data
    Gather-Browser-Data
    Gather-WMI-Data
    Gather-SuspiciousFiles
    Gather-USN
    Gather-Recycle-Bin
    if ($vss) {
        Remove-ShadowLink -shadow $shadow;
    } else {}
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
    Write-Host ""
    Write-Host "RAID: Rapid Acquisition of Interesting Data"
    Write-Host "github.com/joeavanzato/RAID"
    Write-Host ""
}


Main