Function Invoke-PSMDEIsolation {
    <#
  .SYNOPSIS
  Isolate a Defender endpoint on the network
  .DESCRIPTION
  Full isolation allows an inbound connection from the Defender console or Live Response and blocks all other traffic in and out
  Selective isolation allows Outlook and Teams to run, but blocks all other traffic apart from Defender
  .PARAMETER Computername
   The endpoint to isolate (short name)
  .PARAMETER IsolationType
  Either full isolation or selective isolation (allows Outlook and Teams)
  .PARAMETER Comment
  A comment to associate with the action in audit logs

  .EXAMPLE
  Invoke-PSMDEIsolation -Computername "PC123456"

  This command will immediately isolate PC123456 on the network
                        
 .NOTES
 Delegated API permissions : Machine.Isolate (Isolate Machine)
 .LINK
 https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/isolate-machine?view=o365-worldwide
#>
[cmdletBinding(DefaultParameterSetName="ByName")]
param(
    [parameter(position = 0, ValueFromPipeLine, ValueFromPipeLineByPropertyName,ParameterSetName="ByName")]
    [Alias("MachineName", "hostname", "devicename", "device", "host", "computer")]
    [ValidateNotNullOrEmpty()]
    [String]$Computername
    ,
    [parameter(ValueFromPipeLineByPropertyName,ParameterSetName="ByID")]
    [Alias("Id", "machineId")]
    [ValidateNotNullOrEmpty()]
    [String]$DeviceId
    ,
    [parameter()]
    [ValidateSet('Full','Selective')]
    [string]$IsolationType='Full'
    ,
    [parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Comment = "Isolate device"
)
BEGIN {
    Add-Type -AssemblyName 'System.Web'
}

PROCESS {

    if($PSCmdlet.ParameterSetName -eq "ByName"){

        # Use StartsWith so don't have to specifify fqdn, but use Top= so get multiple results unexpectedly
        $Computername = [System.Web.HttpUtility]::UrlEncode($Computername)
        $URI = "https://api.securitycenter.windows.com/api/machines?`$Filter=startswith(computerDnsName,'$Computername')&Top=1"

    }else{
        $URI = "https://api.securitycenter.windows.com/api/machines/$DeviceId"
    }

    # Confirm machine id
    try{
        $MachineAPIResult = Invoke-APIRequest -Method Get -Uri $URI
    }catch{
        Write-Warning "$Computername : Request failed for URL '$URI' `n'$_'"
    }


    if ($MachineAPIResult.value) {

        Foreach ($Entry in $MachineAPIResult.Value) {

            $MachineResult = $Entry

            $body = ConvertTo-Json -InputObject @{
                IsolationType = $IsolationType
                Comment = "PSMDE: $Comment"
            }

            # Now call isolation method
            $URI = "https://api.securitycenter.microsoft.com/api/machines/$($MachineResult.id)/isolate"

            try{
                $Response = Invoke-APIRequest -URI $URI -Method POST -Body $body
                if($Response.machineid) {

                    [PSCustomObject]@{
                        computername = $Response.computerDnsName
                        action = $Response.type
                        isolationType = $IsolationType
                        comment = $Response.requestorComment
                        requestor = $Response.requestor
                        status = $Response.status
                        deviceid = $MachineResult.id


                    }
                }else{
                    Write-Warning "Something went wrong"
                }
            }catch{
                Write-Warning "$Computername : Request failed - '$_'"
            }
        }
    }else{
        Write-Warning "$Computername : not found in Defender for Endpoint"
    }

}
}
