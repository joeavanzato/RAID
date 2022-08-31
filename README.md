# RAID
### Rapid Acquisition of Interesting Data

RAID is a PowerShell script designed to aid Incident Response and Forensic analysis of a suspected compromised device via the collection of multiple pieces of evidence often used for DFIR investigations.  RAID also supports the capability to download a series of third-party forensic utilities to parse collected data once it is removed from a suspect machine.    

RAID will also attempt to generate an HTML report on collected data to make browsing the final evidence slightly easier.  Additionally, RAID offers the capability to browse data natively in PowerShell throuhg a multi-tabbed UI approach.

```
* Launch RAID in collection mode
powershell .\raid.ps1

* Launch RAID in analysis mode - must provide a path to collected evidence - this will generate a PowerShell GUI over the data
powershell .\raid.ps1 -p "C:\Evidence_HOSTNAME"

* Analysis mode with third-party utilities downloaded and invoked to parse relevant evidence.
powershell .\raid.ps1 -p "C:\Evidence_HOSTNAME" -utils

```

### What is collected?

RAID will collect the following pieces of evidence;

* Windows Event Logs
* TCP Connections
* Windows Services
* Running Processes
* DNS Cache
* SMB Shares
* Scheduled Tasks
* Defender Detections
* Network Configuration
* Patch Information
* Remote Session/Process/User Data
* Local Administrators
* Startup Items
* System Information
* Firewall Rules
* ARP Cache
* Net Command Outputs
* Suspicious Files
* USN Journal


### Sources
Many thanks to the useful information present at the following sources, without which this type of aggregate evidence collection would not be possible.
* https://github.com/ForensicArtifacts/artifacts