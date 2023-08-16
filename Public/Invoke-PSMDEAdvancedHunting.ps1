Function Invoke-PSMDEAdvancedHunting{
<#
  .SYNOPSIS
  Runs a Defender advanced hunting query and returns the results
  .PARAMETER Query
  The Advanced Hunting query to run. Note that field names are case sensitive e.g. Timestamp not TimeStamp
  Can be entered on one line or as a here string
  .PARAMETER MAXRESULTS
  The query will return up to this number of records from the API
  A value of 0 will return all results

  .EXAMPLE
  Invoke-PSMDEAdvancedHunting -query 'DeviceProcessEvents | where Timestamp > ago(1d)'

  This command will return up-to 1000 records from the DeviceProcessEvents table
  that were recorded in the last day.

  .EXAMPLE
  Invoke-PSMDEAdvancedHunting -query 'DeviceProcessEvents | where Timestamp > ago(1d)' -MaxResult 0

  This command will return all records from the DeviceProcessEvents table
  that were recorded in the last day.

  .EXAMPLE
  Invoke-PSMDEAdvancedHunting -Query 'DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteUrl != "" | limit 1'

  This command will return one event from the DeviceNetworkEvents table that has the RemoteUrl field populated
  Example of output:

    Timestamp                                    : 05/08/2023 03:31:23
    DeviceId                                     : c6a833d8a0da6ad439076368d1681e7930c49fef
    DeviceName                                   : PC123456
    ActionType                                   : ConnectionFailed
    RemoteIP                                     : 176.255.215.109
    RemotePort                                   : 80
    RemoteUrl                                    : ctldl.windowsupdate.com
    LocalIP                                      : 192.168.1.175
    LocalPort                                    : 50330
    Protocol                                     : Tcp
    LocalIPType                                  : Private
    RemoteIPType                                 : Public
    InitiatingProcessSHA1                        : 1bc5066ddf693fc034d6514618854e26a84fd0d1
    InitiatingProcessSHA256                      : add683a6910abbbf0e28b557fad0ba998166394932ae2aca069d9aa19ea8fe88
    InitiatingProcessMD5                         : b7f884c1b74a263f746ee12a5f7c9f6a
    InitiatingProcessFileName                    : svchost.exe
    InitiatingProcessFileSize                    : 55320
    InitiatingProcessVersionInfoCompanyName      : Microsoft Corporation
    InitiatingProcessVersionInfoProductName      : Microsoft® Windows® Operating System
    InitiatingProcessVersionInfoProductVersion   : 10.0.19041.1806
    InitiatingProcessVersionInfoInternalFileName : svchost.exe
    InitiatingProcessVersionInfoOriginalFileName : svchost.exe
    InitiatingProcessVersionInfoFileDescription  : Host Process for Windows Services
    InitiatingProcessId                          : 1556
    InitiatingProcessCommandLine                 : svchost.exe -k NetworkService -p
    InitiatingProcessCreationTime                : 04/08/2023 22:22:29
    InitiatingProcessFolderPath                  : c:\windows\system32\svchost.exe
    InitiatingProcessParentFileName              : services.exe
    InitiatingProcessParentId                    : 712
    InitiatingProcessParentCreationTime          : 04/08/2023 22:22:26
    InitiatingProcessAccountDomain               : nt authority
    InitiatingProcessAccountName                 : network service
    InitiatingProcessAccountSid                  : S-1-5-20
    InitiatingProcessAccountUpn                  :
    InitiatingProcessAccountObjectId             :
    InitiatingProcessIntegrityLevel              : System
    InitiatingProcessTokenElevation              : TokenElevationTypeDefault
    ReportId                                     : 6613
    AppGuardContainerId                          :
    AdditionalFields                             :
 .NOTES
 Version 1.0
#>
[cmdletBinding()]
param(
    [parameter(position=0,Mandatory)]
    [Alias("")]
    [ValidateNotNullOrEmpty()]
    [String]$Query
    ,
    [parameter()]
    [int]$MaxResults=1000
)

PROCESS{

    #$url = 'https://api.securitycenter.microsoft.com/api/advancedqueries/run'
    $url = 'https://api.securitycenter.microsoft.com/api/advancedhunting/run'

    $body = ConvertTo-Json -InputObject @{ 'Query' = $query }

    if($MaxResults -eq 0){ $MaxResults = [int]::MaxValue } # Get all results

    $ReturnedRecords = 0

    Do{

        $Response = Invoke-APIRequest -URI $url -Method POST -Body $body

        Write-Verbose "Returned '$($Response.Stats.dataset_statistics.table_row_count)' rows in '$($Response.Stats.ExecutionTime)' seconds"

        if($response.Results){

            $Schema = $Response.Schema
            $DateProperties = $Schema | Where-Object { $_.Type -eq 'DateTime' } | Select-Object -ExpandProperty Name

            $Results = $Response.results

                $Results  | ForEach-Object {
                    $ReturnedRecords++
                    if($ReturnedRecords -le $MaxResults){

                        $Result = $_
                        $DateProperties | ForEach-Object{
                            $Result."$_" = ConvertFrom-ISO8601 -Date $Result."$_"
                        }
                        if ($null -ne $Result){$Result}
                    }
                }
        }

        # Set the URI to the next page of results
        if($null -ne $response."@odata.nextLink"){
            $URI = $response."@odata.nextLink"
        }

    }While(($null -ne $response."@odata.nextLink") -and ($ReturnedRecords -le $MaxResults)) # Large result sets are paged

}



}
