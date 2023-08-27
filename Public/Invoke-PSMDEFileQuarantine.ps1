Function Invoke-PSMDEFileQuarantine{
<#
 .SYNOPSIS
 Initiate file quarantine on a process running on a remote computer

 .DESCRIPTION
 Requires knowledge of the SHA1 hash - from EDR data or Get-FileHash

 .PARAMETER Computername
 The computername of an MDE endpoint (short name)
 .PARAMETER sha1
 The SHA1 hash of the file to quarantine

 .PARAMETER Comment
 A comment recorded in the audit logs

.EXAMPLE
 Invoke-PSMDEFileQuarantine -Computername PC123456 -sha1 'CAE4C347F57DC0FB41DA73AA787C232AE0AE5E72' -Comment "Test quarantine"

    computername : PC123456
    Sha1         : CAE4C347F57DC0FB41DA73AA787C232AE0AE5E72
    comment      : PSMDE: Quarantine file by sha1
    status       : Pending
    returnCode   : 0
    type         : StopAndQuarantineFile
    deviceId     : c6a833d8b0da6ad439076268d1681e4930c49fef

 This command will initiate quarantine of the file specified by the SHA1 hash on computer PC123456

 .NOTES
 Delegated API permissions : Machine.StopAndQuarantine (Stop And Quarantine)
 .LINK
 https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/stop-and-quarantine-file?view=o365-worldwide
#>

#>
[cmdletBinding()]
param(
    [parameter(position = 0, ValueFromPipeLine, ValueFromPipeLineByPropertyName, ParameterSetName = "ByName")]
    [Alias("MachineName", "hostname", "devicename", "device", "host", "computer")]
    [ValidateNotNullOrEmpty()]
    [String]$Computername
    ,
    [parameter(Mandatory)]
    [Alias("hash")]
    [ValidateNotNullOrEmpty()]
    [String]$sha1
    ,
    [parameter(ValueFromPipeLineByPropertyName, ParameterSetName = "ByID")]
    [ValidateNotNullOrEmpty()]
    [String]$comment="Quarantine file by sha1"

)

PROCESS{

    if ($PSCmdlet.ParameterSetName -eq "ByName") {

        # Use StartsWith so don't have to specifify fqdn, but use Top= so get multiple results unexpectedly
        $Computername = [System.Web.HttpUtility]::UrlEncode($Computername)
        $URI = "https://api.securitycenter.windows.com/api/machines?`$Filter=startswith(computerDnsName,'$Computername')&Top=1"

    } else {
        $URI = "https://api.securitycenter.windows.com/api/machines/$DeviceId"
    }

    # Confirm machine id
    try {
        $MachineAPIResult = Invoke-APIRequest -Method Get -Uri $URI
    } catch {
        Write-Warning "$Computername : Request failed for URL '$URI' `n'$_'"
    }

    if ($MachineAPIResult.value) {

        Foreach ($Entry in $MachineAPIResult.Value) {

            $MachineResult = $Entry

            $body = ConvertTo-Json -InputObject @{
                Sha1 = $sha1
                Comment = "PSMDE: $Comment"
            }

            # Now call file quarantine method
            $URI = "https://api.securitycenter.microsoft.com/api/machines/$($MachineResult.id)/StopAndQuarantineFile"

            try {
                $Response = Invoke-APIRequest -URI $URI -Method POST -Body $body
                if ($Response.status) {

                    [PSCustomObject]@{
                        computername  = $Computername
                        Sha1 = $sha1
                        comment = "PSMDE: $Comment"
                        status = $Response.status
                        returnCode = $Response.errorHResult
                        type = $Response.type
                        deviceId = $MachineResult.id
                    }
                } else {
                    Write-Warning "Something went wrong"
                }
            } catch {
                Write-Warning "$Computername : Request failed - '$_'"
            }
        }
    } else {
        Write-Warning "$Computername : not found in Defender for Endpoint"
    }

}

}