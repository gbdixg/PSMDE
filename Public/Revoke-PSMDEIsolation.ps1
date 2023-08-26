Function Revoke-PSMDEIsolation {
<#
  .SYNOPSIS
  Releases a Defender endpoint from isolation
  .PARAMETER Computername
  The endpoint to release from isolation (short name)
  .PARAMETER Comment
  A comment associated with the action in the audit logs

  .EXAMPLE
  Revoke-PSMDEIsolation -Computername "PC123456"

  This command will immediately release the computer PC123456 from isolation

 .NOTES
 Delegated API permissions : Machine.Isolate (Isolate Machine)
 .LINK
 https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/unisolate-machine?view=o365-worldwide
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
    [ValidateNotNullOrEmpty()]
    [string]$Comment = "PSMDE: Release device from isolation"
)
BEGIN {
    Add-Type -AssemblyName 'System.Web'
}

PROCESS {

    if($PSCmdlet.ParameterSetName -eq "ByName"){

        $Computername = [System.Web.HttpUtility]::UrlEncode($Computername)
        $URI = "https://api.securitycenter.windows.com/api/machines?`$Filter=startswith(computerDnsName,'$Computername')"

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
                Comment = "PSMDE: $Comment"
            }

            # Now call release method
            $URI = "https://api.securitycenter.microsoft.com/api/machines/$($MachineResult.id)/unisolate"

            try{
                $Response = Invoke-APIRequest -URI $URI -Method POST -Body $body
                if($Response.machineid) {

                    [PSCustomObject]@{
                        computername = $Response.computerDnsName
                        action = $Response.type
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
