Function Connect-SecurityCenter{
<#
.SYNOPSIS
 Connect to the Defender Security API using interactive authentication
.DESCRIPTION
 Uses MSAL.PS module to get an access token interactively
.PARAMETER TENANTID
The ID od the tenant to connect to
.PARAMETER CLIENTID
The application ID of an Azure app to control connection to the API
.PARAMETER SCOPES
The scopes required. Doesn't seem important with interactive auth
.NOTES
Version 1.1
#>
 [CmdletBinding()]
 Param(
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [String]$TenantID = '00000000-0000-0000-0000-TENANTID'
        ,
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [String]$ClientID = '00000000-0000-0000-0000-APPID'
        ,
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [String[]]$Scopes = @("https://api.securitycenter.microsoft.com/Software.Read")
 )
PROCESS{
    $TokenLifeTime = ($Global:AccessToken.ExpiresOn - (Get-Date).ToUniversalTime()).TotalMinutes
    if ($TokenLifeTime -le 2) {
        Write-Verbose "Token needs to be refreshed"
        Remove-Variable -Name 'AccessToken' -Scope Global -Force -ErrorAction SilentlyContinue
        try {
            $Global:AccessToken = Get-MsalToken -ClientId $ClientID -TenantId $TenantID -Scopes $Scopes -Interactive -ErrorAction Stop -Verbose:$false


        } catch {
            Write-Warning "Authentication failed '$_'. Unable to continue"
            break
        }
    } else {
        Write-Verbose "Existing valid token"
    }
}
}