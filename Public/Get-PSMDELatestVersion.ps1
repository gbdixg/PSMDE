Function Get-PSMDELatestVersion{
<#
.SYNOPSIS
Gets the latest available version of the MDE platform, engine and signatures
by connecting to microsoft.com
.NOTES
Version 1.0
#>
[cmdletBinding()]
param()

PROCESS{
    $Result = Invoke-RestMethod -Uri "https://www.microsoft.com/security/encyclopedia/adlpackages.aspx?action=info" | select -ExpandProperty versions
    if($Result){
        [PSCustomObject]@{
            Engine = $Result.engine
            Platform = $Result.platform
            Signatures = $Result.Signatures.'#text'
        }
    }
}


}