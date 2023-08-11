Function Test-IsAdmin {
<#
   .SYNOPSIS
   Tests if current process is running elevated. Returns True or False
   .EXAMPLE
   if(-not(Test-IsAdmin)){
     Write-Warning "Requires administrative access. Please restart elevated"
   }
#>
[cmdletBinding()]
param()
Process{
 
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
}