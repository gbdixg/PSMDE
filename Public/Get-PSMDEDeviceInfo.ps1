Function Get-PSMDEDeviceInfo{
<#
  .SYNOPSIS
  Gets information about an MDE endpoint from the Defender Security API
  .DESCRIPTION
  Maximum of 10000 rows returned
  .PARAMETER COMPUTERNAME
  The computername of an MDE endpoint or a partial name with a wildcard suffix.
  .PARAMETER MAXRESULTS
  The query will return up to this number of cmputer records from the API
  A value of 0 will return all results

  .EXAMPLE
  Get-PSMDEDeviceInfo

  This command will return detailed information on up-to 1000 MDE computers

  .EXAMPLE
  Get-PSMDEDeviceInfo -MaxResults 0

  This command will return detailed information on all MDE computers

  .EXAMPLE
  Get-PSMDEDeviceInfo -Computername PC123456

  This command will return detailed information on the MDE computer called PC123456

  .EXAMPLE
  Get-PSMDEDeviceInfo -Computername PC*

  This command will return detailed information on all MDE computers with names starting "PC".
  Example of detailed output:

    Computername                  : PC123456
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
    lastIpAddress                 : 192.168.1.175
    lastExternalIpAddress         : 90.13.110.29
    managedBy                     : Intune
    loggedOnUsers                 : {@{id=rnd\user1; lastSeen=25/08/2023 14:41:16; logonTypes=RemoteInteractive}, @{id=azuread\adminuser; lastSeen=15/08/2023 22:51:25; logonTypes=Interactive}}
    id                            : c4a833d8a0da6ad339076368d1681e6930c49fef
 .NOTES
    Delegated API permissions : Machine.Read (Read machine information)
 .LINK
   https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-machines?view=o365-worldwide
#>
[cmdletBinding()]
param(
    [parameter(position=0,ValueFromPipeLine,ValueFromPipeLineByPropertyName)]
    [Alias("MachineName","hostname","devicename","device","host","computer")]
    [ValidateNotNullOrEmpty()]
    [String]$Computername
    ,
    [parameter()]
    [int]$MaxResults=10000
)
BEGIN{
    Add-Type -AssemblyName 'System.Web'
}

PROCESS{


    if([string]::IsNullOrEmpty($Computername)){
        $URI = "https://api.securitycenter.microsoft.com/api/machines?`$top=$MaxResults"
    }else{
        if($Computername.EndsWith('*')){
            $Computername=$Computername.TrimEnd('*')
            $Computername = [System.Web.HttpUtility]::UrlEncode($Computername)
            $URI = "https://api.securitycenter.windows.com/api/machines?`$Filter=startswith(computerDnsName,'$Computername')&`$top=$MaxResults"
        }else{
            $Computername = [System.Web.HttpUtility]::UrlEncode($Computername)
            $URI = "https://api.securitycenter.microsoft.com/api/machines?`$Filter=ComputerDNSName eq '$Computername'"
        }
    }


    Do{
         # First get machine info API
        try{
            $MachineAPIResult = Invoke-APIRequest -Method Get -Uri $URI
        }catch{
            Write-Warning "$Computername : Request failed for URL '$URI' `n'$_'"
        }

        if ($MachineAPIResult.value){

            Foreach($Entry in $MachineAPIResult.Value){

                $MachineResult = $Entry

                $output = $MachineResult | Select-Object @{n = 'Computername'; e = { $_.computerDnsName } }, computerDnsName,isPotentialDuplication,osPlatform,version,agentVersion,osBuild,healthStatus,exposureLevel,riskScore,machineTags,onboardingStatus,defenderAVStatus,managedBy,lastIpAddress,lastExternalIpAddress,id

                $LastSeenMachine = ConvertFrom-ISO8601 -Date $MachineResult.lastSeen

                # Then call deviceavinfo API
                # ComputerDNSName is case sensitive in the call to deviceavinfo but not machines!
                $ComputerNameCS = $MachineResult.computerDnsName

                $URI = "https://api.securitycenter.microsoft.com/api/deviceavinfo?`$Filter=ComputerDNSName eq '$ComputerNameCS'"
                try{
                    $AVAPIResult = Invoke-APIRequest -Method Get -Uri $URI
                }catch{
                    Write-Warning "$Computername : Request failed for API '$URI' `n'$_'"
                }

                if ($AVAPIResult.value){

                    $MDAVResult = $AVAPIResult.value

                    # Use the most recent last seen date between machine and avinfo apis
                    $LastSeenMDAV = ConvertFrom-ISO8601 -Date $MDAVResult.lastSeenTime
                    if ($LastSeenMDAV -ge $LastSeenMachine) {
                        $LastSeen = $LastSeenMDAV
                    }else{
                        $LastSeen = $LastSeenMachine
                    }

                    # DateTime conversion
                    $output | Add-Member -MemberType NoteProperty -Name LastSeen -Value $LastSeen
                    if($LastSeen){
                        $LastSeenUTC = $LastSeen.ToUniversalTime()
                    }else{
                        $LastSeenUTC = $null
                    }
                    $output | Add-Member -MemberType NoteProperty -Name LastSeenUTC -Value $LastSeenUTC

                    # Append avInfo fields to machine object
                    'quickScanTime','fullScanTime','fullScanResult', 'quickScanResult', 'avIsSignatureUpToDate', 'avIsEngineUpToDate', 'avIsPlatformUpToDate', 'avmode', 'avEngineVersion','avSignatureVersion', 'avPlatformVersion', 'avSignatureDataRefreshTime' | ForEach-Object{
                        $output | Add-Member -MemberType NoteProperty -Name $_ -Value $MDAVResult."$_"
                    }

                    # Convert to DateTime and add UTC time
                    $output.avSignatureDataRefreshTime = ConvertFrom-ISO8601 -Date $output.avSignatureDataRefreshTime
                    if($output.avSignatureDataRefreshTime){
                        $avSignatureDataRefreshTimeUTC = $output.avSignatureDataRefreshTime.ToUniversalTime()
                    }else{
                        $avSignatureDataRefreshTimeUTC = $null
                    }
                    $output | Add-Member -MemberType NoteProperty -Name avSignatureDataRefreshTimeUTC -Value $avSignatureDataRefreshTimeUTC

                    $output.quickScanTime = ConvertFrom-ISO8601 -Date $output.quickScanTime
                    if($output.quickScanTime){
                        $quickScanUTC = $output.quickScanTime.ToUniversalTime()
                    }else{
                        $quickScanUTC = $null
                    }
                    $output | Add-Member -MemberType NoteProperty -Name quickScanTimeUTC -Value $quickScanUTC

                    $output.fullScanTime = ConvertFrom-ISO8601 -Date $output.fullScanTime
                    if($output.fullScanTime){
                        $fullscanUTC = $output.fullScanTime.ToUniversalTime()
                    }else{
                        $fullscanUTC = $null
                    }
                    $output | Add-Member -MemberType NoteProperty -Name fullScanTimeUTC -Value $fullscanUTC

                    # Logged on user info
                    $URI = "https://api.securitycenter.microsoft.com/api/machines/$($MachineResult.id)/logonusers"
                    try{
                        $UserResult = Invoke-APIRequest -Method Get -Uri $URI
                    }catch{
                        Write-Warning "$Computername : Request failed for API '$URI' `n'$_'"
                    }

                    $UserList = @()
                    if($UserResult.Value){
                        Foreach($UserEntry in $UserResult.value){
                            $UserList+=[PSCustomObject]@{
                                id = $UserEntry.id
                                lastSeen = $(ConvertFrom-ISO8601 -Date $UserEntry.lastSeen)
                                logonTypes = $UserEntry.logonTypes
                            }
                        }
                    }else{
                        $UserList = @()
                    }
                    $output | Add-Member -MemberType NoteProperty -Name loggedOnUsers -Value $UserList
                }

                $Output | Select-Object computername,osPlatform,version,osBuild,isPotentialDuplication,machineTags,healthStatus,onboardingStatus,defenderAvStatus,exposureLevel,riskScore,avEngineVersion,avSignatureVersion,avPlatformVersion,avIsSignatureUpToDate,avIsEngineUpToDate,avIsPlatformuptoDate,avSignatureDataRefreshTime,avSignatureDataRefreshTimeUTC,quickScanTime,quickScanTimeUTC,fullScanTime,fullScanTimeUTC,avmode,LastSeen,LastSeenUTC,lastIpAddress,lastExternalIpAddress,managedBy,loggedOnUsers,@{n='deviceid';e={$_.id}}

            }#foreach

        } #endif

        # Set the URI to the next page of results
        if($null -ne $MachineAPIResult."@odata.nextLink"){
            $URI = $MachineAPIResult."@odata.nextLink"
        }

    }While(($null -ne $MachineAPIResult."@odata.nextLink") -and ($ReturnedRecords -le $MaxResults)) # Large result sets are paged

}

END{

}

}
