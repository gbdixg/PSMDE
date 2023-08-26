function Invoke-APIRequest {
    <#
    .SYNOPSIS
        Perform a Microsoft API call, either as GET, POST or PATCH or DELETE.

    .DESCRIPTION
        Calls the API and returns the results or an error

    .NOTES

    #>
    param(
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$URI
        ,
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("GET", "POST", "PATCH", "DELETE")]
        [string]$Method
        ,
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Object]$Body
        ,
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ContentType = "application/json; charset=utf-8"
        ,
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [Hashtable]$AuthenticationHeader

    )

    BEGIN{

        Connect-SecurityCenter

        $AuthenticationHeader = @{
            "Content-Type"  = $ContentType
            "Authorization" = $Global:AccessToken.CreateAuthorizationHeader()
            "ExpiresOn"     = $Global:AccessToken.ExpiresOn.UTCDateTime
        }
    }

    PROCESS{

        try {
            # Call Graph API and get JSON response
            switch ($Method){
                "GET"{
                    Write-Verbose "$URI"
                    $Response = Invoke-RestMethod -Uri $URI -Headers $AuthenticationHeader -Method $Method -UseBasicParsing -ErrorAction Stop -Verbose:$false
                    break
                }
                "POST"{
                    $Response = Invoke-RestMethod -Uri $URI -Headers $AuthenticationHeader -Method $Method -Body $Body -ContentType $ContentType -ErrorAction Stop -Verbose:$false
                    break
                }
                "PATCH"{
                    $Response = Invoke-RestMethod -Uri $URI -Headers $AuthenticationHeader -Method $Method -Body $Body -ContentType $ContentType -ErrorAction Stop -Verbose:$false
                    break
                }
                "DELETE"{
                    $Response = Invoke-RestMethod -Uri $URI -Headers $AuthenticationHeader -Method $Method -ErrorAction Stop -Verbose:$false
                    break
                }
            }

            $Response

        } catch [System.Exception] {
            # Credit IntuneWin32App Module
            # Capture current error
            $ExceptionItem = $PSItem

            Write-Verbose $ExceptionItem

            # Construct response error custom object for cross platform support
            $ResponseBody = [PSCustomObject]@{
                "ErrorMessage" = [string]::Empty
                "ErrorCode"    = [string]::Empty
            }

            # Read response error details differently depending PSVersion
            switch ($PSVersionTable.PSVersion.Major) {
                "5" {
                    # Read the response stream
                    $StreamReader = New-Object -TypeName "System.IO.StreamReader" -ArgumentList @($ExceptionItem.Exception.Response.GetResponseStream())
                    $StreamReader.BaseStream.Position = 0
                    $StreamReader.DiscardBufferedData()
                    $ResponseReader = ($StreamReader.ReadToEnd() | ConvertFrom-Json)

                    # Set response error details
                    $ResponseBody.ErrorMessage = $ResponseReader.error.message
                    $ResponseBody.ErrorCode = $ResponseReader.error.code
                }
                default {
                    $ErrorDetails = $ExceptionItem.ErrorDetails.Message | ConvertFrom-Json

                    # Set response error details
                    $ResponseBody.ErrorMessage = $ErrorDetails.error.message
                    $ResponseBody.ErrorCode = $ErrorDetails.error.code
                }
            }

            # Convert status code to integer for output
            $HttpStatusCodeInteger = ([int][System.Net.HttpStatusCode]$ExceptionItem.Exception.Response.StatusCode)

            switch ($Method) {
                "GET" {
                    # Output warning message that the request failed with error message description from response stream
                    Write-Warning -Message "Request failed with status code '$($HttpStatusCodeInteger) ($($ExceptionItem.Exception.Response.StatusCode))'. Error details: $($ResponseBody.ErrorCode) - $($ResponseBody.ErrorMessage)"
                }

                default {
                    # Construct new custom error record
                    $SystemException = New-Object -TypeName "System.Management.Automation.RuntimeException" -ArgumentList ("{0}: {1}" -f $ResponseBody.ErrorCode, $ResponseBody.ErrorMessage)
                    $ErrorRecord = New-Object -TypeName "System.Management.Automation.ErrorRecord" -ArgumentList @($SystemException, $ErrorID, [System.Management.Automation.ErrorCategory]::NotImplemented, [string]::Empty)

                    # Throw a terminating custom error record
                    $PSCmdlet.ThrowTerminatingError($ErrorRecord)
                }
            }
        }
    }
}