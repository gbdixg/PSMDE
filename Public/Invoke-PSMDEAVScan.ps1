Function Invoke-PSMDEAvscan{
<#
  .SYNOPSIS
  Runs a Defender anti-virus scan
  .PARAMETER DeviceId
  The MDE DeviceID of the endpoint to scan

  .PARAMETER COMPUTERNAME
  Alternatively, the computername of an MDE endpoint to scan

  .PARAMETER ScanType
    The type of scan to run - quick or full

  .EXAMPLE
  Invoke-PSMDEAvScan -deviceName PC123456

  This command will start a quick scan on the computer PC123456

  .EXAMPLE
    Invoke-PSMDEAdvancedHunting -query @'AlertInfo
    | where Timestamp > ago(1h)
    | where Category =="Malware"
    | join AlertEvidence on AlertId
    | distinct DeviceId
    @' | Invoke-PSMDEAvScan -ScanType Full

  This command will return run a full scan on any computer that triggered a malware alert in the past 1 hour

 .NOTES
    Delegated API permissions :
        Machine.Scan (Scan machine)

#>
[cmdletBinding(DefaultParameterSetName="byid")]
param(
    [parameter(position=0,Mandatory,ValueFromPipeLineByPropertyName,ParameterSetName = "byid")]
    [Alias("id")]
    [ValidateNotNullOrEmpty()]
    [String]$DeviceId
    ,
    [parameter(Mandatory, ParameterSetName = "byname")]
    [Alias("MachineName", "hostname", "devicename", "device", "host", "computer")]
    [ValidateNotNullOrEmpty()]
    [String]$Computername
    ,
    [parameter()]
    [ValidateSet('quick','full')]
    [String]$ScanType="quick"

)

PROCESS{

    if($PSCmdlet.ParameterSetName -eq 'byname'){
        try{
            $DeviceId = Get-PSMDEDeviceInfo -Computername $Computername -MaxResults 1 -ErrorAction stop | Select-Object -ExpandProperty deviceid
        }catch{
            Write-Warning "$Computername : Not found '$'"
            break
        }
    }

    $url = "https://api.securitycenter.microsoft.com/api/machines/$Deviceid/runAntiVirusScan"

    $body = ConvertTo-Json -InputObject @{ 'Comment' = "Scan initiated by $($ENV:Username)" ; 'ScanType' = 'Quick' }

    try{
        $Response = Invoke-APIRequest -URI $url -Method POST -Body $body
        $Response | Select-Object @{n='Computername';e={$_.computerDnsName}},type,status,errorHResult,requestor,requestorComment,@{n='DeviceId';e={$_.machineId}}
    }catch{
        Write-Warning "$Computername : Failed to trigger scan '$_'"
    }

}

}


