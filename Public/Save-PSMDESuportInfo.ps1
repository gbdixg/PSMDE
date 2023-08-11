Function Save-PSMDESuportInfo{
<#
  .SYNOPSIS
  Collects Defender for Endpoint support files into a cab file
  .DESCRIPTION
  Run on a local computer with elevated rights.
  Output file is saved to C:\ProgramData\Microsoft\Windows Defender\Support\MpSupportFiles.cab
  .EXAMPLE
  Save-PSMDESuportInfo
#>
[cmdletBinding()]
param(
    [parameter(position = 0)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [String]$MPCMDRun = 'c:\Program Files\Windows Defender\MpCmdRun.exe'
)


PROCESS{

    if(Test-IsAdmin){
        $Arguments = '-getfiles'
        Start-Process -FilePath $MPCMDRun -ArgumentList $Arguments -NoNewWindow -Wait

    }else{

        Write-Warning "Administrative rights missing. Please restart elevated (Run As Administrator)"
    }

}


}