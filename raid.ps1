

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

function Create-Evidence-Dir
{
    try{
        Write-Host "Creating Evidence Directory: $evidence_path"
        if (Test-Path -Path "$evidence_path") {
        } else {
            New-Item -Path ".\" -Name "$evidence_path" -ItemType "directory"  | Out-Null
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
        Get-NetTcpConnection -ErrorAction SilentlyContinue | Select * | Export-Csv -NoTypeInformation -Path .\$evidence_path\network_connections.csv
    }catch{
        Write-Warning "Error Capturing TCP Connections"
    }
}

function Gather-Services
{
    try{
        Write-Host "Capturing: Windows Services"
        Get-WmiObject win32_service -ErrorAction SilentlyContinue | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\windows_services.csv
    }catch{
        Write-Warning "Error Capturing Windows Services"
    }
}

function Gather-Processes
{
    try{
        Write-Host "Capturing: Running Processes"
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select * | Export-Csv -NoTypeInformation -Path .\$evidence_path\running_processes.csv
    }catch{
        Write-Warning "Error Capturing Running Processes"
    }
}

function Gather-DNS
{
    try{
        Write-Host "Capturing: DNS Cache"
        Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\dns_cache.csv
    }catch{
        Write-Warning "Error Capturing DNS Cache"
    }
}

function Gather-SMB
{
    try{
        Write-Host "Capturing: SMB Shares"
        Get-SmbShare -ErrorAction SilentlyContinue | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\smb_shares.csv
    }catch{
        Write-Warning "Error Capturing SMB Shares"
    }
}

function Gather-Tasks
{
    try{
        Write-Host "Capturing: Windows Scheduled Tasks"
        Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\scheduled_tasks.csv
    }catch{
        Write-Warning "Error Capturing Windows Scheduled Tasks"
    }
}

function Gather-Defender-Detections
{
    try{
        Write-Host "Capturing: Windows Defender Detections"
        Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object * | Export-Csv -NoTypeInformation -Path .\$evidence_path\defender_threats.csv
    }catch{
        Write-Warning "Error Capturing Windows Defender Detections"
    }
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
        Write-Warning "Error Capturing Windows Event Logs"
    }
}

function Gather-NetConfig
{
    try{
        Write-Host "Capturing: Network Configuration"
        ipconfig /all > $evidence_path\ipconfig.txt
    }catch{
        Write-Warning "Error Capturing Network Configuration"
    }
}

function Gather-PatchInfo
{
    try{
        Write-Host "Capturing: Patch Information"
        wmic qfe list full > $evidence_path\patches.txt
    }catch{
        Write-Warning "Error Capturing Patch Information"
    }
}

function Gather-QData
{
    try{
        Write-Host "Capturing: Remote Sessions/Processes"
        qwinsta >> $evidence_path\qwinsta.txt
        quser >> $evidence_path\quser.txt
        qprocess >> $evidence_path\qprocess.txt
    }catch{
        Write-Warning "Error Capturing Remote Sessions/Processes"
    }
}

function Gather-LocalAdmins
{
    try{
        Write-Host "Capturing: Local Admins"
        net localgroup administrators > $evidence_path\local_admins.txt
    }catch{
        Write-Warning "Error Capturing Local Admins"
    }
}

function Gather-StartupItems
{
    try{
        Write-Host "Capturing: Startup Items"
        net start > $evidence_path\startup_items.txt
        "WMIC STARTUP ITEMS" >> $evidence_path\startup_items.txt
        wmic startup get * /format:list >> $evidence_path\startup_items.txt
    }catch{
        Write-Warning "Error Capturing Startup Items"
    }
}

function Gather-SysInfo
{
    try{
        Write-Host "Capturing: System Information"
        systeminfo > $evidence_path\systeminfo.txt
    }catch{
        Write-Warning "Error Capturing System Information"
    }
}

function Gather-FirewallRules
{
    try {
        Write-Host "Capturing: Firewall Rules"
        Get-NetFirewallRule -ErrorAction SilentlyContinue | Select * | Export-Csv -NoTypeInformation -Path  $evidence_path\firewall_rules.csv
    } catch{
        Write-Warning "Error Capturing Firewall Rules"
    }
}

function Gather-ARP
{
    try {
        Write-Host "Capturing: ARP Cache"
        Get-NetNeighbor -ErrorAction SilentlyContinue | Select * | Export-Csv -NoTypeInformation -Path  $evidence_path\arp_cache.csv
    } catch{
        Write-Warning "Error Capturing ARP Cache"
    }
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
        Get-ChildItem -Path C:\temp,C:\windows\system32,C:\windows\temp,C:\Users -Include *.htm,*.vbs,*.hta,*.chm,*.exe,*.bat,*.ps1,*.zip,*.gz,*.7z -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-15) } | Select-Object PSPath, PSParentPath, PSChildName, PSDrive, PSProvider, PSIsContainer, Mode, LinkType, Name, Length, DirectoryName, Directory, IsReadOnly, Exists, FullName, Extension, CreationTime, CreationTimeUtc, LastAccessTime, LastAccessTimeUtc, LastWriteTime, LastWriteTimeUtc | Export-Csv -NoTypeInformation -Path  $evidence_path\suspicious_files.csv
    }
    catch
    {
        Write-Warning "Error Capturing Suspicious Files"
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
        Write-Warning "Error Capturing USN Journal"
    }
}

function Gather-AV-Data
{
    # https://github.com/ForensicArtifacts/artifacts/blob/main/data/antivirus.yaml

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
    try{
        try{
            New-Item -Path ".\" -Name "$evidence_path\prefetch" -ItemType "directory" | Out-Null
        }catch{}
        Copy-Item -Path "$env:SystemRoot\prefetch\*" -Destination ".\$evidence_path\prefetch" -Recurse -ErrorAction SilentlyContinue
    }catch{
        Write-Warning "Error Capturing Prefetch Files"
    }
}

function Gather-PowerShell-History
{
    Write-Host "Capturing: PowerShell History Files"
    try{
        New-Item -Path ".\" -Name "$evidence_path\ps_history" -ItemType "directory" | Out-Null
        Copy-Item -Path "$env:SystemDrive\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Destination ".\$evidence_path\ps_history" -Recurse -ErrorAction SilentlyContinue
    } catch{
        Write-Warning "Error Capturing PS History Files"
    }
}

function Gather-Installed-Software
{
    Write-Host "Capturing: Installed Software"
    try{
        $InstalledSoftware = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        $InstalledSoftware += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        $InstalledSoftware | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Export-Csv "$evidence_path\installed_software.csv" -Encoding UTF8 -NoTypeInformation
    }
     catch{
        Write-Warning "Error Capturing Installed Software"
    }
}

function Gather-Amcache-Files
{
    Write-Host "Capturing: Amcache Hive Files"
    try{
        try{
            New-Item -Path ".\" -Name "$evidence_path\amcache" -ItemType "directory" | Out-Null
        }catch{}
        Copy-Item -Path "$root\Windows\AppCompat\Programs\Amcache.hve" -Destination ".\$evidence_path\amcache" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$root\Windows\AppCompat\Programs\Amcache.hve.LOG1" -Destination ".\$evidence_path\amcache" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$root\Windows\AppCompat\Programs\Amcache.hve.LOG2" -Destination ".\$evidence_path\amcache" -Recurse -ErrorAction SilentlyContinue
    }catch{
        Write-Warning "Error Capturing Amcache Files"
    }
}

function Gather-Activities-Cache
{
    Write-Host "Capturing: Activity Cache"
    try{
        try{
            New-Item -Path ".\" -Name "$evidence_path\win_activity_cache" -ItemType "directory" | Out-Null
        }catch{}
        Copy-Item -Path "$root\Users\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db" -Destination ".\$evidence_path\win_activity_cache" -Recurse -ErrorAction SilentlyContinue
    }catch{
        Write-Warning "Error Capturing Activity Cache"
    }
}

function Gather-BITS-DB
{
    Write-Host "Capturing: BITS Databases"
    try{
        try{
            New-Item -Path ".\" -Name "$evidence_path\win_bits" -ItemType "directory" | Out-Null
        }catch{}
        Copy-Item -Path "$root\ProgramData\Microsoft\Network\Downloader\qmgr*.dat" -Destination ".\$evidence_path\win_bits" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$root\ProgramData\Microsoft\Network\Downloader\qmgr.db" -Destination ".\$evidence_path\win_bits" -Recurse -ErrorAction SilentlyContinue
    }catch{
        Write-Warning "Error Capturing BITS Databases"
    }
}

function Gather-Cortana-DB
{
    Write-Host "Capturing: Cortana Databases"
    try{
        try{
            New-Item -Path ".\" -Name "$evidence_path\win_cortana" -ItemType "directory" | Out-Null
        }catch{}
        Copy-Item -Path "$root\Users\*\AppData\Local\Packages\Microsoft.Windows.Cortana_*\AppData\Indexed DB\IndexedDB.edb" -Destination ".\$evidence_path\win_cortana" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$root\Users\*\AppData\Local\Packages\Microsoft.Windows.Cortana_*\LocalState\ESEDatabase_CortanaCoreInstance\CortanaCoreDb.dat" -Destination ".\$evidence_path\win_cortana" -Recurse -ErrorAction SilentlyContinue
    }catch{
        Write-Warning "Error Capturing Cortana Databases"
    }
}

function Gather-WER-Data
{
    Write-Host "Capturing: Windows Error Reporting Data"
    try{
        New-Item -Path ".\" -Name "$evidence_path\win_wer" -ItemType "directory" | Out-Null
    }catch{}
    try
    {
        Copy-Item -Path "$root\ProgramData\Microsoft\Windows\WER\*" -Destination ".\$evidence_path\win_wer" -Recurse -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Error Copying Data from $env:SystemDrive\ProgramData\Microsoft\Windows\WER"
    }
    try
    {
        Copy-Item -Path "$root\Windows\*.dmp" -Destination ".\$evidence_path\win_wer" -Recurse -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Error Copying Data from $env:SystemRoot"
    }
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

function Gather-Crypnet-Data
{
    Write-Host "Capturing: Windows Cryptnet URL Caches"
    try{
        try{
            New-Item -Path ".\" -Name "$evidence_path\win_cryptnet_caches" -ItemType "directory" | Out-Null
        }catch{}
        Copy-Item -Path "$root\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\*" -Destination ".\$evidence_path\win_cryptnet_caches" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$root\Windows\SysWOW64\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\*" -Destination ".\$evidence_path\win_cryptnet_caches" -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Path "$root\Users\*\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\*" -Destination ".\$evidence_path\win_cryptnet_caches" -Recurse -ErrorAction SilentlyContinue
    }catch{
        Write-Warning "Error Capturing Windows Cryptnet URL Caches"
    }

}


# Below functions modified From JJ Fulmer awesome answer at https://stackoverflow.com/questions/14207788/accessing-volume-shadow-copy-vss-snapshots-from-powershell
function New-ShadowLink {
    [CmdletBinding()]
    param (
        $linkPath="$($ENV:SystemDrive)\$shadowcopy_name"
    )

    begin {
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
        Write-verbose "Removing shadow copy link at $linkPath"
    }

    process {
        Write-Verbose "Deleting the shadowcopy snapshot"
        Write-Host "Executing: vssadmin delete shadows /shadow=$shadowid /quiet"
        vssadmin delete shadows /shadow=$shadowid /quiet > "$evidence_path\vss_output.txt"
        #$shadow.Delete();
        Write-Verbose "Deleting the now empty folder"
        Try {
            Remove-Item -Force -Recurse $linkPath -ErrorAction Stop;
        }
        catch {
            Invoke-Expression -Command "cmd /c rmdir /S /Q '$linkPath'";
        }
    }

    end {
        Write-Verbose "Shadow link and snapshot have been removed";
        return;
    }
}

function Main
{
    Logo
    Create-Evidence-Dir
    if ($vss) {
        $shadow = New-ShadowLink -Verbose
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
    #Gather-SuspiciousFiles
    #Gather-USN
    if ($vss) {
        Remove-ShadowLink -shadow $shadow -Verbose;
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
    Write-Host "RAID: Rapid Acquisition of Interesting Data"
    Write-Host "github.com/joeavanzato/RAID"
    Write-Host ""
}


Main