Function Test-PSMDEMapsConnection{
<#
.SYNOPSIS
 Tests the connection to the Microsoft MAPS service
#>
[cmdletBinding()]
param(
    [parameter(position=0)]
    [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
    [String]$MPCMDRun = 'c:\Program Files\Windows Defender\MpCmdRun.exe'
)
PROCESS{
    $Arguments = '-validatemapsconnection'
    Start-Process -FilePath $MPCMDRun -ArgumentList $Arguments -NoNewWindow -Wait
}


}