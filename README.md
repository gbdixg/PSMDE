# PSMDE

PowerShell module for interactive access to the Defender Security API

Functions:

- Connect-PSMDE  
- Get-PSMDEDeviceInfo  
- Get-PSMDELatestVersion  
- Invoke-PSMDEAvScan
- Invoke-PSMDEAdvancedHunting
- Invoke-PSMDEIsolation
- Revoke-PSMDEIsolation
- Invoke-PSMDEFileQuarantine
- Save-PSMDESupportInfo  
- Test-PSMDEMapsConnection  

## Installation

Create an Azure application to control authentication and authorization.  
A step by step process is available here: https://write-verbose.com/2023/05/24/DefenderSecurityAPI/  

## Security Context

Start PowerShell in the context of an account with access to Defender information i.e. a member of

- A built in reader role such as Global Reader or Security Reader
- A privileged role such as Global Admin, Security Opertator, Security Admin
- A custom role with delegated access to your tenant

## Usage

Use the module interactively at PowerShell console as in the examples below.

## EXAMPLE 1 - Get device information

The following example confirms the following for an endpoint:

- Defender is active and onboarded
- Engine and signatures are up-to-date
- Last scan times
- OS version and IP address information
- Logged-on users
- MDE alerts
- Vulnerabilities

```PowerShell
Import-Module PSMDE  
Connect-PSMDE -TenantID $TenantID -ClientID $AppID  
Get-PSMDEDeviceInfo -Computername PC12345  
```

```cmd
Computername                  : PC12345
osPlatform                    : Windows10
version                       : 22H2
osBuild                       : 19045
isPotentialDuplication        : False
machineTags                   : {MDEPilot}
healthStatus                  : Active
onboardingStatus              : Onboarded
defenderAvStatus              : Updated
exposureLevel                 : Medium
riskScore                     : Medium
avEngineVersion               : 1.1.23080.2005
avSignatureVersion            : 1.395.1403.0
avPlatformVersion             : 4.18.23080.2006
avIsSignatureUpToDate         : True
avIsEngineUpToDate            : True
avIsPlatformUpToDate          : True
avSignatureDataRefreshTime    : 27/08/2023 15:35:36
avSignatureDataRefreshTimeUTC : 27/08/2023 14:35:36
quickScanTime                 : 22/08/2023 03:16:00
quickScanTimeUTC              : 22/08/2023 02:16:00
fullScanTime                  : 
fullScanTimeUTC               : 
avmode                        : 0
LastSeen                      : 27/08/2023 14:53:08
LastSeenUTC                   : 27/08/2023 13:53:08
lastIpAddress                 : 192.168.1.140
lastExternalIpAddress         : 100.19.112.28
managedBy                     : Intune
loggedOnUsers                 : {@{id=RnD\user1; lastSeen=27/08/2023 16:23:38; logonTypes=RemoteInteractive}, @{id=azuread\admin1; lastSeen=27/08/2023 16:02:54; logonTypes=Interactive}}
alertCount                    : 9
alerts                        : {@{serverity=Informational; alertCreationTime=2023-05-08T19:45:47.8359999Z; detectionSource=AutomatedInvestigation; category=SuspiciousActivity; threatName=; threatFamilyName=}, 
                                @{serverity=Informational; alertCreationTime=2023-08-15T21:55:56.9250938Z; detectionSource=WindowsDefenderAv; category=Malware; threatName=Virus:DOS/EICAR_Test_File; 
                                threatFamilyName=EICAR_Test_File}, @{serverity=Medium; alertCreationTime=2023-05-08T16:11:02.4388031Z; detectionSource=WindowsDefenderAv; category=SuspiciousActivity; 
                                threatName=Trojan:PowerShell/Powersploit.L; threatFamilyName=Powersploit}, @{serverity=Medium; alertCreationTime=2023-05-08T16:02:13.0120825Z; detectionSource=WindowsDefenderAtp; 
                                category=Execution; threatName=; threatFamilyName=}...}
CVEs                          : {@{name=CVE-2023-33144; description=Visual Studio Code Spoofing Vulnerability; severity=Medium; publicExploit=False; firstDetected=2023-06-13T17:30:51Z}, @{name=CVE-2023-21779; 
                                description=Visual Studio Code Remote Code Execution Vulnerability; severity=High; publicExploit=False; firstDetected=2023-05-02T14:45:15Z}, @{name=CVE-2023-24893; description=Visual 
                                Studio Code Remote Code Execution Vulnerability; severity=High; publicExploit=False; firstDetected=2023-05-02T14:45:15Z}, @{name=CVE-2023-29338; description=Visual Studio Code 
                                Information Disclosure Vulnerability; severity=Medium; publicExploit=False; firstDetected=2023-06-08T10:30:35Z}}
deviceid                      : c6a833d9a0da6ad439076368d1781e7940c49fef
```

## EXAMPLE 2: Scan computers based on Advanced Hunting Query results

The following example:

- Runs an Advanced Hunting query to find endpoints where a file has executed in the last 6 hours
- Triggers a full scan on those endpoints

```PowerShell
Invoke-PSMDEAdvancedHunting -Query @'  
DeviceProcessEvents
| where Timestamp > ago(6h)
| where ActionType == "ProcessCreated"
| where SHA1 == "1bc5066ddf693fc034d6514618854e26a85fd0d1"
| distinct DeviceName 
'@ | Invoke-PSMDEAvscan -ScanType Full
```

```cmd
Computername     : PC123456
type             : RunAntiVirusScan
ScanType         : Full
status           : Pending
errorHResult     : 0
requestor        : admin@tenant.com
requestorComment : Full scan initiated by PSMDE
DeviceId         : c6a833d9a0da6ad439056368d1681e7940c49fee
```

## EXAMPLE 3: Isolate computers

The following example:

- Runs an Advanced Hunting query to find endpoints where PowerShell has communicated with a specific public IP
- Triggers full isolation of those endpoints

```PowerShell
Invoke-PSMDEAdvancedHunting -Query @'  
DeviceNetworkEvents
| where Timestamp > ago (6h)
| where InitiatingProcessFileName =~"PowerShell.exe"
| where RemoteIP == "20.50.201.195"
| distinct DeviceName
'@ | Invoke-PSMDEIsolation
```

```cmd
computername  : PC123456
isolationType : Full
comment       : PSMDE: Isolate device
requestor     : <admin@tenant.com>
status        : Pending
deviceid      : c6a833d9a0da6ad439056368d1681e7940c49fee
```

## EXAMPLE 4

The following example queries a Microsoft URI for the latest available version of Defender for Endpoint

```PowerShell
Get-PSMDELatestVersion
```

```cmd
Engine         Platform        Signatures
------         --------        ----------
1.1.23070.1005 4.18.23070.1004 1.395.1451.0
```
