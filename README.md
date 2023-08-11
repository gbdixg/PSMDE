# PSMDE
PowerShell module for interactive access to the Defender Security API

Functions:  
Connect-SecurityCenter  
Get-PSMDEDeviceInfo  
Get-PSMDELatestVersion  
Invoke-PSMDEAdvancedHunting  
Save-PSMDESupportInfo  
Test-PSMDEMapsConnection  

Step1: 
Create an Azure application to control authentication and authorization.  
A step by step process is available here: https://write-verbose.com/2023/05/24/DefenderSecurityAPI/  

Step2:  
Start PowerShell in the contect of an account with access to Defender information:
- Built in reader roles such as Global Reader or Security Reader
- Privileged roles such as Global Admin, Security Opertator, Security Admin
- A custom role with delegated access to your tenant

Step3:  
Use the module...  

```PowerShell
Import-Module PSMDE  
Connect-SecurityCenter -TenantID $TenantID -ClientID $ClientID  
Get-PSMDEDeviceInfo -Computername PC12345  
```

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
avEngineVersion               : 1.1.23070.1005  
avSignatureVersion            : 1.393.2414.0  
avPlatformVersion             : 4.18.23070.1004  
avIsSignatureUpToDate         : True  
avIsEngineUpToDate            : True  
avIsPlatformUpToDate          : True  
avSignatureDataRefreshTime    : 06/08/2023 20:50:40  
avSignatureDataRefreshTimeUTC : 06/08/2023 19:50:40  
quickScanTime                 : 01/08/2023 05:11:09  
quickScanTimeUTC              : 01/08/2023 04:11:09  
fullScanTime                  :  
fullScanTimeUTC               :  
avmode                        : 0  
LastSeen                      : 06/08/2023 19:57:16  
LastSeenUTC                   : 06/08/2023 18:57:16  
lastIpAddress                 : 192.168.1.170  
lastExternalIpAddress         : 90.13.111.27  
managedBy                     : Intune


```PowerShell
Get-PSMDEAdvancedHunting -Query @'  
DeviceNetworkEvents  
| where Timestamp > ago(6d)  
| where RemoteUrl!=""  
| summarize count() by RemoteUrl  
| order by count_ desc
| limit 5
'@
```

 RemoteUrl                           count_
---------                           ------
login.microsoftonline.com               32
v10.events.data.microsoft.com           32
ctldl.windowsupdate.com                 25
eu-mobile.events.data.microsoft.com     23
self.events.data.microsoft.com          19


