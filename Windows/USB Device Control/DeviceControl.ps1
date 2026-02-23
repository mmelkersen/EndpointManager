<#
.SYNOPSIS
    Enumerates all currently connected USB devices and reports hardware identifiers.

.DESCRIPTION
    Queries all present USB and USB storage devices using the PnP subsystem, parses
    Vendor ID (VID), Product ID (PID), and instance serial/suffix from each device's
    InstanceId, and enriches the output with manufacturer and hardware ID details.

    Output is presented as a formatted console table and an interactive GridView for
    easy filtering and copying — useful for building Intune Device Control policies.

    Covers both USB\ (HID, hubs, adapters) and USBSTOR\ (mass storage) device classes.

.PARAMETER IncludeStorage
    Include USBSTOR\ (USB mass storage) devices in addition to USB\ class devices.
    Enabled by default.

.PARAMETER IncludeHubs
    Include USB hub devices in the output. Suppressed by default to reduce noise.

.EXAMPLE
    .\DeviceControl.ps1
    Enumerates all currently connected USB devices and opens GridView.

.EXAMPLE
    .\DeviceControl.ps1 -IncludeStorage:$false
    Enumerates only USB\ class devices, excluding mass storage.

.EXAMPLE
    .\DeviceControl.ps1 -IncludeHubs
    Includes USB hub devices in the output.

.NOTES
    Version:        1.0
    Author:         MM
    Creation Date:  2026-02-23

    CHANGELOG
    ---------------
    2026-02-23 - v1.0 - Initial version (MM)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [bool]$IncludeStorage = $true,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeHubs,

    [Parameter(Mandatory = $false)]
    [switch]$StorageOnly
)

#region --- Functions ---

function Get-USBDevices {
    param(
        [bool]$IncludeStorage,
        [bool]$IncludeHubs,
        [bool]$StorageOnly
    )

    Write-Verbose "Querying present PnP devices..."

    $allDevices = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
        Where-Object {
            if ($StorageOnly) {
                $_.InstanceId -match '^USBSTOR\\'
            }
            else {
                $_.InstanceId -match '^USB\\' -or ($IncludeStorage -and $_.InstanceId -match '^USBSTOR\\')
            }
        }

    if (-not $IncludeHubs) {
        $allDevices = $allDevices | Where-Object { $_.Class -ne 'USB' -or $_.FriendlyName -notmatch 'hub' }
        # Also filter by class name for root hubs
        $allDevices = $allDevices | Where-Object { $_.FriendlyName -notmatch 'Root Hub|Generic Hub' }
    }

    return $allDevices
}

function Parse-USBIdentifiers {
    param([string]$InstanceId)

    $vidVal    = if ($InstanceId -match 'VID_([0-9A-Fa-f]{4})') { $Matches[1].ToUpper() } else { 'N/A' }
    $pidVal    = if ($InstanceId -match 'PID_([0-9A-Fa-f]{4})') { $Matches[1].ToUpper() } else { 'N/A' }
    $serial    = if ($InstanceId -match 'VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}\\(.+)$') { $Matches[1] } else { 'N/A' }

    return [PSCustomObject]@{
        VID    = $vidVal
        PID    = $pidVal
        Serial = $serial
    }
}

function Get-DeviceDetails {
    param([Microsoft.Management.Infrastructure.CimInstance]$Device)

    $keys = @(
        'DEVPKEY_Device_Manufacturer',
        'DEVPKEY_Device_HardwareIds',
        'DEVPKEY_Device_CompatibleIds'
    )

    $props = @{}

    try {
        $rawProps = Get-PnpDeviceProperty -InputObject $Device -KeyName $keys -ErrorAction SilentlyContinue
        foreach ($prop in $rawProps) {
            $shortKey = $prop.KeyName -replace '^DEVPKEY_Device_', ''
            $props[$shortKey] = $prop.Data
        }
    }
    catch {
        Write-Verbose "Could not retrieve extended properties for $($Device.InstanceId): $_"
    }

    return $props
}

#endregion

#region --- Main ---

Write-Host ""
Write-Host "USB Device Hardware Enumerator" -ForegroundColor Cyan
Write-Host "Scanning for connected USB devices..." -ForegroundColor Gray
Write-Host ""

$usbDevices = Get-USBDevices -IncludeStorage $IncludeStorage -IncludeHubs $IncludeHubs.IsPresent -StorageOnly $StorageOnly.IsPresent

if (-not $usbDevices) {
    Write-Warning "No USB devices found."
    exit 0
}

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($device in $usbDevices) {
    $ids     = Parse-USBIdentifiers -InstanceId $device.InstanceId
    $details = Get-DeviceDetails -Device $device

    $hardwareId  = if ($details['HardwareIds'] -is [array])    { $details['HardwareIds'][0] }    else { $details['HardwareIds'] }
    $compatibleId = if ($details['CompatibleIds'] -is [array]) { $details['CompatibleIds'][0] } else { $details['CompatibleIds'] }
    $manufacturer = if ($details['Manufacturer'])              { $details['Manufacturer'] }      else { 'N/A' }

    $results.Add([PSCustomObject]@{
        FriendlyName      = $device.FriendlyName
        Status            = $device.Status
        VID               = $ids.VID
        PID               = $ids.PID
        Serial_Instance   = $ids.Serial
        Class             = $device.Class
        Manufacturer      = $manufacturer
        HardwareID        = $hardwareId
        CompatibleID      = $compatibleId
        InstanceId        = $device.InstanceId
    })
}

#endregion

#region --- Output ---

# Console table
$results | Format-Table -Property FriendlyName, Status, VID, PID, Serial_Instance, Class, Manufacturer -AutoSize

# Summary
Write-Host "Total USB devices found: $($results.Count)" -ForegroundColor Green
Write-Host ""
Write-Host "Full details (including HardwareID, CompatibleID, InstanceId) available in GridView." -ForegroundColor Gray
Write-Host ""

# Interactive GridView
$results | Out-GridView -Title "USB Devices - VID / PID / Hardware IDs ($($results.Count) devices)"

#endregion
