<#
.SYNOPSIS
    Collect Lenovo specific data and upload to Log Analytics

.DESCRIPTION
    Script should be deployed as a Proactive Remediation in Intune and is dependent on Lenovo Commercial Vantage being installed on endpoints with the following policies enabled:
        - Configure System Update
        - Write warranty information to WMI table
        - Write battery information to WMI table

.EXAMPLE
    Get-LenovoDeviceStatus.ps1

.NOTES
    Author: Philip Jorgensen
    Created: 2022-09-26

    added by mm@mindcore.dk 
    Formatting of Warranty as it was dated wrong in log analytics
    Modified: 2022-12-19

#>

# Replace with your Log Analytics Workspace ID
$customerId = ""  

# Replace with your Primary Key
$sharedKey = ""

# Specify the name of the record type that you'll be creating
$logType = "Lenovo_Device_Status"

<#  Create the functions to create the authorization signature
    https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
#>
$TimeStampField = ""

Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource) {
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId, $encodedHash
    return $authorization
}

# Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType) {
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization"        = $signature;
        "Log-Type"             = $logType;
        "x-ms-date"            = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}

##############

$ErrorActionPreference = 'SilentlyContinue'

$Manufacturer = (Get-CimInstance -Namespace root/CIMV2 -ClassName Win32_BIOS).Manufacturer
if ($Manufacturer -ne "LENOVO") {
    Write-Output "Not a Lenovo system..."; Exit 0
}

else {

    $CommercialVantage = (Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq "E046963F.LenovoSettingsforEnterprise" })
    if ($null -eq $CommercialVantage) {
        Write-Output "Commercial Vantage not installed..."; Exit 0
    }
    
    $LenovoUpdates = Get-CimInstance -Namespace root/Lenovo -ClassName Lenovo_Updates
    if ($null -eq $LenovoUpdates) {
        Write-Output "Lenovo Updates WMI class not present."
        Write-Output "Run Commercial Vantage and initiate a check for updates..."; Exit 0
    }

    $Battery = Get-CimInstance -Namespace root/Lenovo -ClassName Lenovo_Battery
    if ($null -eq $Battery) {
        Write-Output "Lenovo Battery WMI class not present."
        Write-Output "Enable the policy to write battery info to WMI..."; Exit 0
    }

    $Warranty = Get-CimInstance -Namespace root/Lenovo -ClassName Lenovo_WarrantyInformation
    if ($null -eq $Warranty) {
        Write-Output "Lenovo Warranty WMI class not present."
        Write-Output "Enable the policy to write warranty information to WMI..."; Exit 0
    }

    else {

        # Format warranty date for Azure Monitor Workbook
        $s_Array = $Warranty.EndDate.Split("/")
        if ($s_Array[0].Length -eq 1) { $s_Array[0] = "0" + $s_Array[0] }
        if ($s_Array[1].Length -eq 1) { $s_Array[1] = "0" + $s_Array[1] }
        $s_Array[2] = $s_Array[2].Substring(0, 4)
        $Warranty = "{0}-{1}-{2}" -f $s_Array[2], $s_Array[0], $s_Array[1]
        
        if ($Warranty[0] -eq "-")
            {
               $Warranty = $Warranty.Substring(1,10)
            }
    
        $Properties = foreach ($Update in $LenovoUpdates) {
            [PSCustomObject]@{
                Hostname      = $env:COMPUTERNAME
                MTM           = (Get-CimInstance -Namespace root/CIMV2 -ClassName Win32_ComputerSystemProduct).Name.Substring(0, 4).Trim()
                Product       = (Get-CimInstance -Namespace root/CIMV2 -ClassName Win32_ComputerSystemProduct).Version
                PackageID     = $Update.PackageID
                Severity      = $Update.Severity
                Status        = $Update.Status
                Title         = $Update.Title
                Version       = $Update.Version
                BatteryHealth = $Battery.BatteryHealth
                WarrantyEnd   = $Warranty
            }
        }
    
        $UpdateStatusJson = $Properties | ConvertTo-Json
        $params = @{
            CustomerId = $customerId
            SharedKey  = $sharedKey
            Body       = ([System.Text.Encoding]::UTF8.GetBytes($UpdateStatusJson))
            LogType    = $logType 
        }

        $logResponse = Post-LogAnalyticsData @params

    }

}