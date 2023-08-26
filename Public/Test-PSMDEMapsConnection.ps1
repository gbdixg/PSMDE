Function Test-PSMDEMapsConnection{
<#
.SYNOPSIS
 Tests the connection to the Microsoft MAPS service from the local computer
.DESCRIPTION
 Uses MpCmdRun.exe
.NOTES
 Version 1.0
#>
[cmdletBinding()]
param(
    [parameter(position=0)]
    [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
    [String]$MPCMDRun = 'c:\Program Files\Windows Defender\MpCmdRun.exe'
)
PROCESS{
    $Arguments = '-validatemapsconnection'
    try{
        Start-Process -FilePath $MPCMDRun -ArgumentList $Arguments -NoNewWindow -Wait -ErrorAction Stop
    }catch{
        Write-warning "Failed to run '$MPCMDRun $Arguments' `n'$_'"
    }
}


}