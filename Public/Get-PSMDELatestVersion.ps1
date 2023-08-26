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
    $URL = "https://www.microsoft.com/security/encyclopedia/adlpackages.aspx?action=info"
    try{
        $Result = Invoke-RestMethod -Uri $URL -ErrorAction Stop | select -ExpandProperty versions
    }catch{
        Write-Warning "Error accessing URL '$URL' `n'$_'"
    }
    if($Result){
        [PSCustomObject]@{
            Engine = $Result.engine
            Platform = $Result.platform
            Signatures = $Result.Signatures.'#text'
        }
    }
}


}