<#
.SYNOPSIS
  Converts .NET DateTime to/from format used in Security API
#>

Function ConvertFrom-ISO8601([string]$Date){

    $ConvertedDate = New-Object DateTime

    if([DateTime]::TryParse($Date,[ref]$ConvertedDate)){
        $ConvertedDate
    }
}

Function ConvertTo-ISO8601([DateTime]$Date){


     Get-Date ($Date.ToUniversalTime()) -UFormat '+%Y-%m-%dT%H:%M:%S.000Z'

}