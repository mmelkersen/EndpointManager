<#
.SYNOPSIS
    Windows Baseline Comparison Tool for 23H2 vs 25H2

.DESCRIPTION
    Collects system data from Windows devices including event logs, installed applications,
    Windows features, and Intune management logs. Generates JSON, CSV, and interactive HTML reports.
    Supports comparison mode to analyze differences between Windows 23H2 and 25H2 baselines.

.PARAMETER EventLogDays
    Number of days to query event logs (default: 7, range: 1-90)

.PARAMETER ReportPath
    Directory path where reports will be saved (default: $PSScriptRoot\Reports\)

.PARAMETER IncludeIntuneLogDetails
    Include detailed parsing of IntuneManagementExtension logs for errors and warnings

.PARAMETER Compare
    Switch to enable comparison mode between two baseline reports

.PARAMETER BaselineReport
    Path to the baseline (23H2) report directory for comparison

.PARAMETER NewReport
    Path to the new (25H2) report directory for comparison

.EXAMPLE
    .\Baseline23H2vs25H2.ps1
    Collects baseline data with default settings (7 days of event logs)

.EXAMPLE
    .\Baseline23H2vs25H2.ps1 -EventLogDays 30 -IncludeIntuneLogDetails
    Collects baseline data for the last 30 days including detailed Intune log analysis

.EXAMPLE
    .\Baseline23H2vs25H2.ps1 -Compare -BaselineReport "C:\Reports\23H2" -NewReport "C:\Reports\25H2"
    Compares two baseline reports and generates a diff HTML report

.NOTES
    Version:        1.7
    Author:         Mattias Melkersen (mm@mindcore.dk)
    Creation Date:  2026-01-09
    
    CHANGELOG
    ---------------
    2026-01-30 - v1.7 - Fixed comparison logic to use hashtable lookups, eliminating duplicate items across removed/modified/added categories (mm@mindcore.dk)
    2026-01-14 - v1.6 - Added installed drivers collection with version tracking and comparison support (mm@mindcore.dk)
    2026-01-09 - v1.5 - Removed knobs from MDM policies, cleaned up unused GPO comparison functions (mm@mindcore.dk)
    2026-01-09 - v1.4 - Added Windows Services, Security Features (TPM/SecureBoot/Device Guard/Credential Guard), and Scheduled Tasks collections (mm@mindcore.dk)
    2026-01-09 - v1.3 - Added dynamic state filter for Windows Features, removed Local GPO section (mm@mindcore.dk)
    2026-01-09 - v1.2 - Filtered _WinningProvider entries, hidden knobs by default, removed GPResult, enhanced GPO source detection (mm@mindcore.dk)
    2026-01-09 - v1.1 - Added policy collection: Intune MDM policies, Local GPO, GPResult, conflict analysis (mm@mindcore.dk)
    2026-01-09 - v1.0 - Initial release with collection and comparison modes (mm@mindcore.dk)
#>

[CmdletBinding(DefaultParameterSetName = 'Collection')]
param(
    [Parameter(ParameterSetName = 'Collection')]
    [ValidateRange(1, 90)]
    [int]$EventLogDays = 7,

    [Parameter(ParameterSetName = 'Collection')]
    [string]$ReportPath = "$PSScriptRoot\Reports",

    [Parameter(ParameterSetName = 'Collection')]
    [switch]$IncludeIntuneLogDetails,

    [Parameter(ParameterSetName = 'Comparison', Mandatory = $true)]
    [switch]$Compare,

    [Parameter(ParameterSetName = 'Comparison', Mandatory = $true)]
    [ValidateScript({Test-Path $_ -PathType Container})]
    [string]$BaselineReport,

    [Parameter(ParameterSetName = 'Comparison', Mandatory = $true)]
    [ValidateScript({Test-Path $_ -PathType Container})]
    [string]$NewReport
)

#region Helper Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{
        'Info'    = 'Cyan'
        'Success' = 'Green'
        'Warning' = 'Yellow'
        'Error'   = 'Red'
    }
    
    Write-Host "[$timestamp] $Message" -ForegroundColor $colors[$Level]
}

#endregion

#region Data Collection Functions

function Get-SystemMetadata {
    <#
    .SYNOPSIS
        Collects system metadata including OS version, build number, and hardware info
    #>
    
    Write-Log "Collecting system metadata..." -Level Info
    
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        $bios = Get-CimInstance -ClassName Win32_BIOS
        
        $metadata = [PSCustomObject]@{
            ComputerName     = $env:COMPUTERNAME
            OSVersion        = $os.Version
            OSBuildNumber    = $os.BuildNumber
            OSEdition        = $os.Caption
            OSArchitecture   = $os.OSArchitecture
            InstallDate      = $os.InstallDate
            LastBootUpTime   = $os.LastBootUpTime
            Manufacturer     = $cs.Manufacturer
            Model            = $cs.Model
            TotalMemoryGB    = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
            BIOSVersion      = $bios.SMBIOSBIOSVersion
            SerialNumber     = $bios.SerialNumber
            CollectionDate   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        Write-Log "System metadata collected successfully" -Level Success
        return $metadata
    }
    catch {
        Write-Log "Failed to collect system metadata: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Get-IntuneEventLogs {
    <#
    .SYNOPSIS
        Collects Intune-related event logs for the specified number of days
    #>
    
    param(
        [int]$DaysBack = 7
    )
    
    Write-Log "Collecting Intune event logs (last $DaysBack days)..." -Level Info
    
    $startTime = (Get-Date).AddDays(-$DaysBack)
    
    $logNames = @(
        'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
        'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational'
        'Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot'
        'Microsoft-Windows-ModernDeployment-Diagnostics-Provider/ManagementService'
        'Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin'
        'Microsoft-Windows-Shell-Core/Operational'
        'Microsoft-Windows-User Device Registration/Admin'
    )
    
    $allEvents = @()
    
    foreach ($logName in $logNames) {
        try {
            $filterHashtable = @{
                StartTime = $startTime
                LogName   = $logName
            }
            
            $events = Get-WinEvent -FilterHashtable $filterHashtable -ErrorAction SilentlyContinue |
                Where-Object { $_.LevelDisplayName -in @('Error', 'Warning') } |
                Select-Object TimeCreated, LevelDisplayName, LogName, Id, 
                    @{Name = 'Message'; Expression = { ($_.Message -Split "`n")[0] } }
            
            if ($events) {
                $allEvents += $events
                Write-Log "Collected $($events.Count) events from $logName" -Level Info
            }
        }
        catch {
            Write-Log "Could not access log: $logName" -Level Warning
        }
    }
    
    Write-Log "Total events collected: $($allEvents.Count)" -Level Success
    return $allEvents
}

function Get-IntuneManagementExtensionLogs {
    <#
    .SYNOPSIS
        Parses IntuneManagementExtension logs for errors and warnings
    #>
    
    Write-Log "Parsing IntuneManagementExtension logs..." -Level Info
    
    $logPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
    
    if (-not (Test-Path $logPath)) {
        Write-Log "IntuneManagementExtension logs not found at $logPath" -Level Warning
        return @()
    }
    
    $logFiles = @(
        "AgentExecutor*.log"
        "IntuneManagementExtension*.log"
        "*Autopilot*.log"
    )
    
    $logEntries = @()
    
    foreach ($pattern in $logFiles) {
        $files = Get-ChildItem -Path $logPath -Filter $pattern -ErrorAction SilentlyContinue
        
        foreach ($file in $files) {
            try {
                Write-Log "Processing $($file.Name)..." -Level Info
                
                # Read last 5000 lines for performance
                $content = Get-Content -Path $file.FullName -Tail 5000 -ErrorAction SilentlyContinue
                
                $matches = $content | Select-String -Pattern "(error|fail|warning)" -AllMatches
                
                foreach ($match in $matches) {
                    $logEntries += [PSCustomObject]@{
                        FileName  = $file.Name
                        LineText  = $match.Line.Trim()
                        Severity  = if ($match.Line -match "error|fail") { "Error" } else { "Warning" }
                    }
                }
            }
            catch {
                Write-Log "Failed to parse $($file.Name): $($_.Exception.Message)" -Level Warning
            }
        }
    }
    
    Write-Log "Found $($logEntries.Count) error/warning entries in Intune logs" -Level Success
    return $logEntries
}

function Get-AppxInventory {
    <#
    .SYNOPSIS
        Collects all installed AppX packages including provisioned packages
    #>
    
    Write-Log "Collecting AppX package inventory..." -Level Info
    
    try {
        # Get installed packages
        $installedPackages = Get-AppxPackage -AllUsers | Select-Object Name, Version, Publisher, 
            PackageFullName, InstallLocation, 
            @{Name = 'PackageType'; Expression = { 'Installed' } }
        
        # Get provisioned packages
        $provisionedPackages = Get-AppxProvisionedPackage -Online | Select-Object DisplayName, Version, 
            @{Name = 'Publisher'; Expression = { $_.PublisherName } },
            @{Name = 'PackageFullName'; Expression = { $_.PackageName } },
            @{Name = 'InstallLocation'; Expression = { 'Provisioned' } },
            @{Name = 'PackageType'; Expression = { 'Provisioned' } }
        
        # Combine and deduplicate
        $allPackages = @()
        $allPackages += $installedPackages
        
        foreach ($provPkg in $provisionedPackages) {
            if ($installedPackages.Name -notcontains $provPkg.DisplayName) {
                $allPackages += [PSCustomObject]@{
                    Name             = $provPkg.DisplayName
                    Version          = $provPkg.Version
                    Publisher        = $provPkg.Publisher
                    PackageFullName  = $provPkg.PackageFullName
                    InstallLocation  = $provPkg.InstallLocation
                    PackageType      = $provPkg.PackageType
                }
            }
        }
        
        Write-Log "Collected $($allPackages.Count) AppX packages" -Level Success
        return $allPackages
    }
    catch {
        Write-Log "Failed to collect AppX inventory: $($_.Exception.Message)" -Level Error
        return @()
    }
}

function Get-WindowsFeaturesStatus {
    <#
    .SYNOPSIS
        Collects Windows optional features and capabilities status
    #>
    
    Write-Log "Collecting Windows features status..." -Level Info
    
    try {
        # Get optional features
        $optionalFeatures = Get-WindowsOptionalFeature -Online | Select-Object FeatureName, State
        
        # Get capabilities
        $capabilities = Get-WindowsCapability -Online | Select-Object Name, State
        
        $allFeatures = @()
        
        foreach ($feature in $optionalFeatures) {
            $allFeatures += [PSCustomObject]@{
                FeatureName = $feature.FeatureName
                State       = $feature.State
                Type        = 'OptionalFeature'
            }
        }
        
        foreach ($capability in $capabilities) {
            $allFeatures += [PSCustomObject]@{
                FeatureName = $capability.Name
                State       = $capability.State
                Type        = 'Capability'
            }
        }
        
        Write-Log "Collected $($allFeatures.Count) Windows features" -Level Success
        return $allFeatures
    }
    catch {
        Write-Log "Failed to collect Windows features: $($_.Exception.Message)" -Level Error
        return @()
    }
}

function Get-InstalledApplications {
    <#
    .SYNOPSIS
        Collects installed applications from registry (Add/Remove Programs)
    #>
    
    Write-Log "Collecting installed applications..." -Level Info
    
    $registryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    
    $applications = @()
    
    foreach ($path in $registryPaths) {
        try {
            $apps = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, 
                    @{Name = 'UninstallString'; Expression = { $_.UninstallString } },
                    @{Name = 'Architecture'; Expression = { if ($path -match 'Wow6432Node') { 'x86' } else { 'x64' } } }
            
            $applications += $apps
        }
        catch {
            Write-Log "Failed to query registry path: $path" -Level Warning
        }
    }
    
    # Remove duplicates
    $applications = $applications | Sort-Object DisplayName -Unique
    
    Write-Log "Collected $($applications.Count) installed applications" -Level Success
    return $applications
}

function Get-RunningServices {
    <#
    .SYNOPSIS
        Collects Windows services with their status and startup type
    #>
    
    Write-Log "Collecting Windows services status..." -Level Info
    
    try {
        $services = Get-Service | Select-Object Name, DisplayName, Status, StartType, 
            @{Name = 'ServiceType'; Expression = { (Get-CimInstance -ClassName Win32_Service -Filter "Name='$($_.Name)'").ServiceType } },
            @{Name = 'Description'; Expression = { $_.DisplayName } }
        
        Write-Log "Collected $($services.Count) Windows services" -Level Success
        return $services
    }
    catch {
        Write-Log "Failed to collect services: $($_.Exception.Message)" -Level Error
        return @()
    }
}

function Get-SecurityFeatures {
    <#
    .SYNOPSIS
        Collects TPM, SecureBoot, Device Guard, and Credential Guard status
    #>
    
    Write-Log "Collecting security features status..." -Level Info
    
    $securityInfo = [PSCustomObject]@{
        TPMPresent           = $false
        TPMEnabled           = $false
        TPMActivated         = $false
        TPMVersion           = 'N/A'
        SecureBootEnabled    = 'Unknown'
        DeviceGuardStatus    = 'Unknown'
        CredentialGuardStatus = 'Unknown'
        VirtualizationBasedSecurity = 'Unknown'
        HVCIStatus           = 'Unknown'
    }
    
    try {
        # TPM Information
        $tpm = Get-CimInstance -Namespace root\cimv2\Security\MicrosoftTpm -ClassName Win32_Tpm -ErrorAction SilentlyContinue
        if ($tpm) {
            $securityInfo.TPMPresent = $tpm.IsEnabled_InitialValue
            $securityInfo.TPMEnabled = $tpm.IsEnabled_InitialValue
            $securityInfo.TPMActivated = $tpm.IsActivated_InitialValue
            $securityInfo.TPMVersion = $tpm.SpecVersion
        }
        
        # SecureBoot Status
        try {
            $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
            $securityInfo.SecureBootEnabled = if ($secureBootEnabled) { 'Enabled' } else { 'Disabled' }
        }
        catch {
            $securityInfo.SecureBootEnabled = 'Not Supported or Legacy BIOS'
        }
        
        # Device Guard / Credential Guard Status via Registry
        $dgPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
        if (Test-Path $dgPath) {
            $dgScenarios = (Get-ItemProperty -Path $dgPath -Name 'EnableVirtualizationBasedSecurity' -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
            $securityInfo.VirtualizationBasedSecurity = if ($dgScenarios -eq 1) { 'Enabled' } else { 'Disabled' }
            
            $hvciStatus = (Get-ItemProperty -Path $dgPath -Name 'HypervisorEnforcedCodeIntegrity' -ErrorAction SilentlyContinue).HypervisorEnforcedCodeIntegrity
            $securityInfo.HVCIStatus = if ($hvciStatus -eq 1) { 'Enabled' } else { 'Disabled' }
        }
        
        $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        if (Test-Path $lsaPath) {
            $lsaCfgFlags = (Get-ItemProperty -Path $lsaPath -Name 'LsaCfgFlags' -ErrorAction SilentlyContinue).LsaCfgFlags
            $securityInfo.CredentialGuardStatus = switch ($lsaCfgFlags) {
                0 { 'Disabled' }
                1 { 'Enabled with UEFI lock' }
                2 { 'Enabled without lock' }
                default { 'Not Configured' }
            }
        }
        
        # Device Guard overall status
        $dgStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        if ($dgStatus) {
            $securityInfo.DeviceGuardStatus = if ($dgStatus.VirtualizationBasedSecurityStatus -eq 2) { 'Running' } elseif ($dgStatus.VirtualizationBasedSecurityStatus -eq 1) { 'Enabled but not running' } else { 'Disabled' }
        }
        
        Write-Log "Security features status collected" -Level Success
    }
    catch {
        Write-Log "Failed to collect security features: $($_.Exception.Message)" -Level Error
    }
    
    return $securityInfo
}

function Get-ScheduledTasksInventory {
    <#
    .SYNOPSIS
        Collects Windows scheduled tasks
    #>
    
    Write-Log "Collecting scheduled tasks inventory..." -Level Info
    
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -or $_.TaskPath -notlike '\Microsoft\Windows\*' } |
            Select-Object TaskName, TaskPath, State, 
                @{Name = 'Author'; Expression = { $_.Author } },
                @{Name = 'Description'; Expression = { $_.Description } },
                @{Name = 'LastRunTime'; Expression = { (Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue).LastRunTime } },
                @{Name = 'NextRunTime'; Expression = { (Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue).NextRunTime } }
        
        Write-Log "Collected $($tasks.Count) scheduled tasks" -Level Success
        return $tasks
    }
    catch {
        Write-Log "Failed to collect scheduled tasks: $($_.Exception.Message)" -Level Error
        return @()
    }
}

function Get-InstalledDrivers {
    <#
    .SYNOPSIS
        Collects installed drivers with version, hardware, and manufacturer details
    #>
    
    Write-Log "Collecting installed drivers..." -Level Info
    
    try {
        $drivers = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | 
            Where-Object { $_.DeviceName -and $_.DriverVersion } |
            Select-Object @{Name = 'DeviceName'; Expression = { $_.DeviceName } },
                @{Name = 'DriverVersion'; Expression = { $_.DriverVersion } },
                @{Name = 'DriverDate'; Expression = { 
                    if ($_.DriverDate) { 
                        ([WMI]'').ConvertToDateTime($_.DriverDate).ToString("yyyy-MM-dd") 
                    } else { 
                        'N/A' 
                    } 
                } },
                @{Name = 'Manufacturer'; Expression = { $_.Manufacturer } },
                @{Name = 'DeviceClass'; Expression = { $_.DeviceClass } },
                @{Name = 'InfName'; Expression = { $_.InfName } },
                @{Name = 'IsSigned'; Expression = { $_.IsSigned } },
                @{Name = 'Signer'; Expression = { $_.Signer } },
                @{Name = 'DeviceID'; Expression = { $_.DeviceID } } |
            Sort-Object DeviceClass, DeviceName
        
        Write-Log "Collected $($drivers.Count) installed drivers" -Level Success
        return $drivers
    }
    catch {
        Write-Log "Failed to collect drivers: $($_.Exception.Message)" -Level Error
        return @()
    }
}

function Get-IntuneMDMPolicies {
    <#
    .SYNOPSIS
        Retrieves Intune MDM policies applied to the device
    #>
    
    Write-Log "Collecting Intune MDM policies..." -Level Info
    $policies = @()
    $mdmPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device"
    
    try {
        if (Test-Path $mdmPath) {
            $policyAreas = Get-ChildItem -Path $mdmPath -ErrorAction SilentlyContinue
            
            foreach ($area in $policyAreas) {
                $areaName = $area.PSChildName
                $areaPath = $area.PSPath
                
                try {
                    $properties = Get-ItemProperty -Path $areaPath -ErrorAction SilentlyContinue
                    
                    foreach ($prop in $properties.PSObject.Properties) {
                        # Filter out PowerShell properties and _WinningProvider entries
                        if ($prop.Name -notmatch '^PS' -and $prop.Name -notmatch '_WinningProvider$' -and $areaName -ne 'knobs') {
                            $policies += [PSCustomObject]@{
                                PolicyArea   = $areaName
                                PolicyName   = $prop.Name
                                Value        = $prop.Value
                                Source       = "Intune MDM"
                                RegistryPath = $areaPath -replace 'Microsoft.PowerShell.Core\\Registry::', ""
                            }
                        }
                    }
                }
                catch {
                    Write-Log "Could not read policy area: $areaName - $($_.Exception.Message)" -Level Warning
                }
            }
            
            Write-Log "Found $($policies.Count) Intune MDM policies" -Level Success
        }
        else {
            Write-Log "Intune MDM policy path not found: $mdmPath" -Level Warning
        }
    }
    catch {
        Write-Log "Failed to collect Intune MDM policies: $($_.Exception.Message)" -Level Error
    }
    
    return $policies
}

#endregion

#region HTML Report Generation

function New-InteractiveHtmlReport {
    <#
    .SYNOPSIS
        Generates an interactive HTML report with sortable/filterable tables
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ReportData,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    Write-Log "Generating interactive HTML report..." -Level Info
    
    $metadata = $ReportData.Metadata
    $events = $ReportData.Events
    $intuneLogEntries = $ReportData.IntuneLogEntries
    $apps = $ReportData.Apps
    $features = $ReportData.Features
    $programs = $ReportData.Programs
    
    # Calculate summary statistics
    $errorCount = ($events | Where-Object { $_.LevelDisplayName -eq 'Error' }).Count
    $warningCount = ($events | Where-Object { $_.LevelDisplayName -eq 'Warning' }).Count
    $intuneErrorCount = ($intuneLogEntries | Where-Object { $_.Severity -eq 'Error' }).Count
    $intuneWarningCount = ($intuneLogEntries | Where-Object { $_.Severity -eq 'Warning' }).Count
    $enabledFeatures = ($features | Where-Object { $_.State -eq 'Enabled' }).Count
    $disabledFeatures = ($features | Where-Object { $_.State -eq 'Disabled' }).Count
    
    # Top 10 most frequent errors
    $topErrors = $events | Where-Object { $_.LevelDisplayName -eq 'Error' } |
        Group-Object -Property Message |
        Sort-Object Count -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            [PSCustomObject]@{
                Message = $_.Name
                Count   = $_.Count
            }
        }
    
    # Build HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Baseline Report - $($metadata.ComputerName)</title>
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            padding: 20px;
        }
        .container-fluid {
            max-width: 1400px;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }
        .stat-card h3 {
            margin: 0;
            font-size: 2rem;
            color: #333;
        }
        .stat-card p {
            margin: 5px 0 0 0;
            color: #666;
            font-size: 0.9rem;
        }
        .badge-error {
            background-color: #dc3545;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 1.2rem;
        }
        .badge-warning {
            background-color: #ffc107;
            color: #333;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 1.2rem;
        }
        .badge-success {
            background-color: #28a745;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 1.2rem;
        }
        .badge-info {
            background-color: #17a2b8;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 1.2rem;
        }
        .badge-primary {
            background-color: #007bff;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
        }
        .badge-secondary {
            background-color: #6c757d;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
        }
        .section {
            margin-top: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
        }
        table.dataTable {
            width: 100% !important;
        }
        .metadata-table td {
            padding: 8px;
            border: 1px solid #ddd;
        }
        .metadata-table td:first-child {
            font-weight: bold;
            background-color: #f8f9fa;
            width: 200px;
        }
        .collapsible {
            cursor: pointer;
            padding: 10px;
            background-color: #667eea;
            color: white;
            border: none;
            text-align: left;
            width: 100%;
            border-radius: 5px;
            margin-bottom: 10px;
            font-size: 1.1rem;
        }
        .collapsible:hover {
            background-color: #5568d3;
        }
        .content {
            display: none;
            padding: 20px;
            background-color: white;
            border-radius: 5px;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="header">
            <h1>Windows Baseline Report</h1>
            <p style="margin: 0; font-size: 1.1rem;">Computer: $($metadata.ComputerName) | OS Build: $($metadata.OSBuildNumber) | Collection Date: $($metadata.CollectionDate)</p>
        </div>

        <div class="row">
            <div class="col-md-12">
                <h2>System Information</h2>
                <table class="metadata-table" style="width: 100%; margin-bottom: 20px;">
                    <tr><td>Computer Name</td><td>$($metadata.ComputerName)</td></tr>
                    <tr><td>OS Version</td><td>$($metadata.OSVersion)</td></tr>
                    <tr><td>OS Build Number</td><td>$($metadata.OSBuildNumber)</td></tr>
                    <tr><td>OS Edition</td><td>$($metadata.OSEdition)</td></tr>
                    <tr><td>OS Architecture</td><td>$($metadata.OSArchitecture)</td></tr>
                    <tr><td>Install Date</td><td>$($metadata.InstallDate)</td></tr>
                    <tr><td>Last Boot Up Time</td><td>$($metadata.LastBootUpTime)</td></tr>
                    <tr><td>Manufacturer</td><td>$($metadata.Manufacturer)</td></tr>
                    <tr><td>Model</td><td>$($metadata.Model)</td></tr>
                    <tr><td>Total Memory (GB)</td><td>$($metadata.TotalMemoryGB)</td></tr>
                    <tr><td>BIOS Version</td><td>$($metadata.BIOSVersion)</td></tr>
                    <tr><td>Serial Number</td><td>$($metadata.SerialNumber)</td></tr>
                </table>
            </div>
        </div>

        <div class="row" style="margin-top: 20px;">
            <div class="col-md-12">
                <h2>Security Features</h2>
                <table class="metadata-table" style="width: 100%; margin-bottom: 20px;">
                    <tr><td>TPM Present</td><td>$($ReportData.SecurityFeatures.TPMPresent)</td></tr>
                    <tr><td>TPM Enabled</td><td>$($ReportData.SecurityFeatures.TPMEnabled)</td></tr>
                    <tr><td>TPM Version</td><td>$($ReportData.SecurityFeatures.TPMVersion)</td></tr>
                    <tr><td>SecureBoot Enabled</td><td>$($ReportData.SecurityFeatures.SecureBootEnabled)</td></tr>
                    <tr><td>Virtualization-Based Security</td><td>$($ReportData.SecurityFeatures.VirtualizationBasedSecurity)</td></tr>
                    <tr><td>Device Guard Status</td><td>$($ReportData.SecurityFeatures.DeviceGuardStatus)</td></tr>
                    <tr><td>Credential Guard Status</td><td>$($ReportData.SecurityFeatures.CredentialGuardStatus)</td></tr>
                    <tr><td>HVCI (Memory Integrity)</td><td>$($ReportData.SecurityFeatures.HVCIStatus)</td></tr>
                </table>
            </div>
        </div>

        <div class="row">
            <div class="col-md-3">
                <div class="stat-card">
                    <h3><span class="badge-error">$errorCount</span></h3>
                    <p>Event Log Errors</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card">
                    <h3><span class="badge-warning">$warningCount</span></h3>
                    <p>Event Log Warnings</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card">
                    <h3><span class="badge-error">$intuneErrorCount</span></h3>
                    <p>Intune Log Errors</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card">
                    <h3><span class="badge-warning">$intuneWarningCount</span></h3>
                    <p>Intune Log Warnings</p>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-3">
                <div class="stat-card">
                    <h3><span class="badge-info">$($apps.Count)</span></h3>
                    <p>AppX Packages</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card">
                    <h3><span class="badge-success">$enabledFeatures</span></h3>
                    <p>Enabled Features</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card">
                    <h3><span class="badge-info">$disabledFeatures</span></h3>
                    <p>Disabled Features</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card">
                    <h3><span class="badge-info">$($programs.Count)</span></h3>
                    <p>Installed Programs</p>
                </div>
            </div>
        </div>
        
        <!-- Policy Statistics Row -->
        <div class="row" style="margin-top: 20px;">
            <div class="col-md-3">
                <div class="stat-card">
                    <h3><span class="badge-info">$($ReportData.IntuneMDMPolicies.Count)</span></h3>
                    <p>Intune MDM Policies</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card">
                    <h3><span class="badge-info">$($ReportData.Services.Count)</span></h3>
                    <p>Windows Services</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card">
                    <h3><span class="badge-info">$($ReportData.ScheduledTasks.Count)</span></h3>
                    <p>Scheduled Tasks</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card">
                    <h3><span class="badge-info">$($ReportData.Drivers.Count)</span></h3>
                    <p>Installed Drivers</p>
                </div>
            </div>
        </div>
        
        <div class="row" style="margin-top: 20px;">
            <div class="col-md-3">
                <div class="stat-card">
                    <h3><span class="badge-$(if ($ReportData.SecurityFeatures.SecureBootEnabled -eq 'Enabled') { 'success' } else { 'warning' })">SecureBoot</span></h3>
                    <p>$($ReportData.SecurityFeatures.SecureBootEnabled)</p>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Top 10 Most Frequent Errors</h2>
            <table id="topErrorsTable" class="display" style="width:100%">
                <thead>
                    <tr>
                        <th>Error Message</th>
                        <th>Occurrence Count</th>
                    </tr>
                </thead>
                <tbody>
"@
    
    foreach ($error in $topErrors) {
        $html += @"
                    <tr>
                        <td>$($error.Message)</td>
                        <td>$($error.Count)</td>
                    </tr>
"@
    }
    
    $html += @"
                </tbody>
            </table>
        </div>

        <button class="collapsible">Event Logs ($($events.Count) entries)</button>
        <div class="content">
            <table id="eventsTable" class="display" style="width:100%">
                <thead>
                    <tr>
                        <th>Time Created</th>
                        <th>Level</th>
                        <th>Log Name</th>
                        <th>Event ID</th>
                        <th>Message</th>
                    </tr>
                </thead>
                <tbody>
"@
    
    foreach ($event in $events) {
        $html += @"
                    <tr>
                        <td>$($event.TimeCreated)</td>
                        <td>$($event.LevelDisplayName)</td>
                        <td>$($event.LogName)</td>
                        <td>$($event.Id)</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($event.Message))</td>
                    </tr>
"@
    }
    
    $html += @"
                </tbody>
            </table>
        </div>

        <button class="collapsible">Intune Log Entries ($($intuneLogEntries.Count) entries)</button>
        <div class="content">
            <table id="intuneLogsTable" class="display" style="width:100%">
                <thead>
                    <tr>
                        <th>File Name</th>
                        <th>Severity</th>
                        <th>Log Entry</th>
                    </tr>
                </thead>
                <tbody>
"@
    
    foreach ($entry in $intuneLogEntries) {
        $html += @"
                    <tr>
                        <td>$($entry.FileName)</td>
                        <td>$($entry.Severity)</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($entry.LineText))</td>
                    </tr>
"@
    }
    
    $html += @"
                </tbody>
            </table>
        </div>

        <button class="collapsible">AppX Packages ($($apps.Count) entries)</button>
        <div class="content">
            <table id="appsTable" class="display" style="width:100%">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Version</th>
                        <th>Publisher</th>
                        <th>Package Type</th>
                    </tr>
                </thead>
                <tbody>
"@
    
    foreach ($app in $apps) {
        $html += @"
                    <tr>
                        <td>$($app.Name)</td>
                        <td>$($app.Version)</td>
                        <td>$($app.Publisher)</td>
                        <td>$($app.PackageType)</td>
                    </tr>
"@
    }
    
    $html += @"
                </tbody>
            </table>
        </div>

        <button class="collapsible">Windows Features ($($features.Count) entries)</button>
        <div class="content">
            <div style="margin-bottom: 15px;">
                <label for="stateFilter" style="margin-right: 10px; font-weight: bold;">Filter by State:</label>
                <select id="stateFilter" style="padding: 5px 10px; border-radius: 5px; border: 1px solid #ddd;">
                    <option value="">All States</option>
                </select>
            </div>
            <table id="featuresTable" class="display" style="width:100%">
                <thead>
                    <tr>
                        <th>Feature Name</th>
                        <th>State</th>
                        <th>Type</th>
                    </tr>
                </thead>
                <tbody>
"@
    
    foreach ($feature in $features) {
        $html += @"
                    <tr>
                        <td>$($feature.FeatureName)</td>
                        <td>$($feature.State)</td>
                        <td>$($feature.Type)</td>
                    </tr>
"@
    }
    
    $html += @"
                </tbody>
            </table>
        </div>

        <button class="collapsible">Installed Programs ($($programs.Count) entries)</button>
        <div class="content">
            <table id="programsTable" class="display" style="width:100%">
                <thead>
                    <tr>
                        <th>Display Name</th>
                        <th>Version</th>
                        <th>Publisher</th>
                        <th>Install Date</th>
                        <th>Architecture</th>
                    </tr>
                </thead>
                <tbody>
"@
    
    foreach ($program in $programs) {
        $html += @"
                    <tr>
                        <td>$($program.DisplayName)</td>
                        <td>$($program.DisplayVersion)</td>
                        <td>$($program.Publisher)</td>
                        <td>$($program.InstallDate)</td>
                        <td>$($program.Architecture)</td>
                    </tr>
"@
    }
    
    $html += @"
                </tbody>
            </table>
        </div>

        <button class="collapsible">Windows Services ($($ReportData.Services.Count) entries)</button>
        <div class="content">
            <div style="margin-bottom: 15px;">
                <label for="serviceStatusFilter" style="margin-right: 10px; font-weight: bold;">Filter by Status:</label>
                <select id="serviceStatusFilter" style="padding: 5px 10px; border-radius: 5px; border: 1px solid #ddd;">
                    <option value="">All Status</option>
                </select>
                <label for="serviceStartTypeFilter" style="margin-left: 20px; margin-right: 10px; font-weight: bold;">Filter by Start Type:</label>
                <select id="serviceStartTypeFilter" style="padding: 5px 10px; border-radius: 5px; border: 1px solid #ddd;">
                    <option value="">All Start Types</option>
                </select>
            </div>
            <table id="servicesTable" class="display" style="width:100%">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Display Name</th>
                        <th>Status</th>
                        <th>Start Type</th>
                        <th>Service Type</th>
                    </tr>
                </thead>
                <tbody>
"@
    
    foreach ($service in $ReportData.Services) {
        $statusBadge = switch ($service.Status) {
            'Running' { 'badge-success' }
            'Stopped' { 'badge-secondary' }
            default { 'badge-warning' }
        }
        $html += @"
                    <tr>
                        <td>$($service.Name)</td>
                        <td>$($service.DisplayName)</td>
                        <td><span class="$statusBadge">$($service.Status)</span></td>
                        <td>$($service.StartType)</td>
                        <td>$($service.ServiceType)</td>
                    </tr>
"@
    }
    
    $html += @"
                </tbody>
            </table>
        </div>

        <button class="collapsible">Scheduled Tasks ($($ReportData.ScheduledTasks.Count) entries)</button>
        <div class="content">
            <div style="margin-bottom: 15px;">
                <label for="taskStateFilter" style="margin-right: 10px; font-weight: bold;">Filter by State:</label>
                <select id="taskStateFilter" style="padding: 5px 10px; border-radius: 5px; border: 1px solid #ddd;">
                    <option value="">All States</option>
                </select>
            </div>
            <table id="scheduledTasksTable" class="display" style="width:100%">
                <thead>
                    <tr>
                        <th>Task Name</th>
                        <th>Task Path</th>
                        <th>State</th>
                        <th>Author</th>
                        <th>Last Run Time</th>
                        <th>Next Run Time</th>
                    </tr>
                </thead>
                <tbody>
"@
    
    foreach ($task in $ReportData.ScheduledTasks) {
        $stateBadge = switch ($task.State) {
            'Ready' { 'badge-success' }
            'Running' { 'badge-info' }
            'Disabled' { 'badge-secondary' }
            default { 'badge-warning' }
        }
        $html += @"
                    <tr>
                        <td>$($task.TaskName)</td>
                        <td style="font-size: 0.85em;">$($task.TaskPath)</td>
                        <td><span class="$stateBadge">$($task.State)</span></td>
                        <td style="font-size: 0.85em;">$($task.Author)</td>
                        <td>$($task.LastRunTime)</td>
                        <td>$($task.NextRunTime)</td>
                    </tr>
"@
    }
    
    $html += @"
                </tbody>
            </table>
        </div>

        <button class="collapsible">Installed Drivers ($($ReportData.Drivers.Count) entries)</button>
        <div class="content">
            <div style="margin-bottom: 15px;">
                <label for="driverClassFilter" style="margin-right: 10px; font-weight: bold;">Filter by Device Class:</label>
                <select id="driverClassFilter" style="padding: 5px 10px; border-radius: 5px; border: 1px solid #ddd;">
                    <option value="">All Classes</option>
                </select>
                <label for="driverManufacturerFilter" style="margin-left: 20px; margin-right: 10px; font-weight: bold;">Filter by Manufacturer:</label>
                <select id="driverManufacturerFilter" style="padding: 5px 10px; border-radius: 5px; border: 1px solid #ddd;">
                    <option value="">All Manufacturers</option>
                </select>
            </div>
            <table id="driversTable" class="display" style="width:100%">
                <thead>
                    <tr>
                        <th>Device Name</th>
                        <th>Driver Version</th>
                        <th>Driver Date</th>
                        <th>Manufacturer</th>
                        <th>Device Class</th>
                        <th>Signed</th>
                    </tr>
                </thead>
                <tbody>
"@
    
    foreach ($driver in $ReportData.Drivers) {
        $signedBadge = if ($driver.IsSigned) { 'badge-success' } else { 'badge-warning' }
        $signedText = if ($driver.IsSigned) { 'Signed' } else { 'Unsigned' }
        $html += @"
                    <tr>
                        <td>$($driver.DeviceName)</td>
                        <td>$($driver.DriverVersion)</td>
                        <td>$($driver.DriverDate)</td>
                        <td>$($driver.Manufacturer)</td>
                        <td>$($driver.DeviceClass)</td>
                        <td><span class="$signedBadge">$signedText</span></td>
                    </tr>
"@
    }
    
    $html += @"
                </tbody>
            </table>
        </div>

        <button class="collapsible">Intune MDM Policies ($($ReportData.IntuneMDMPolicies.Count) entries)</button>
        <div class="content">
            <table id="mdmPoliciesTable" class="display" style="width:100%">
                <thead>
                    <tr>
                        <th>Policy Area</th>
                        <th>Policy Name</th>
                        <th>Value</th>
                        <th>Source</th>
                        <th>Registry Path</th>
                    </tr>
                </thead>
                <tbody>
"@
    
    foreach ($policy in $ReportData.IntuneMDMPolicies) {
        $html += @"
                    <tr>
                        <td>$($policy.PolicyArea)</td>
                        <td>$($policy.PolicyName)</td>
                        <td>$([System.Security.SecurityElement]::Escape($policy.Value))</td>
                        <td><span class="badge-primary">$($policy.Source)</span></td>
                        <td style="font-size: 0.85em; color: #666;">$([System.Security.SecurityElement]::Escape($policy.RegistryPath))</td>
                    </tr>
"@
    }
    
    $html += @"
                </tbody>
            </table>
        </div>

    </div>

    <script>
        // Initialize DataTables
        `$(document).ready(function() {
            `$('#topErrorsTable').DataTable({
                "pageLength": 10,
                "order": [[1, "desc"]]
            });
            `$('#eventsTable').DataTable({
                "pageLength": 25,
                "order": [[0, "desc"]]
            });
            `$('#intuneLogsTable').DataTable({
                "pageLength": 25
            });
            `$('#appsTable').DataTable({
                "pageLength": 25,
                "order": [[0, "asc"]]
            });
            
            // Initialize features table
            var featuresTable = `$('#featuresTable').DataTable({
                "pageLength": 25,
                "order": [[0, "asc"]]
            });
            
            // Populate state filter dropdown dynamically
            var stateFilter = document.getElementById('stateFilter');
            var uniqueStates = [];
            featuresTable.column(1).data().unique().sort().each(function(value) {
                if (value && uniqueStates.indexOf(value) === -1) {
                    uniqueStates.push(value);
                    var option = document.createElement('option');
                    option.value = value;
                    option.textContent = value;
                    stateFilter.appendChild(option);
                }
            });
            
            // Apply filter when dropdown changes
            stateFilter.addEventListener('change', function() {
                featuresTable.column(1).search(this.value).draw();
            });
            
            `$('#programsTable').DataTable({
                "pageLength": 25,
                "order": [[0, "asc"]]
            });
            
            // Initialize services table
            var servicesTable = `$('#servicesTable').DataTable({
                "pageLength": 50,
                "order": [[1, "asc"]]
            });
            
            // Populate service status filter
            var serviceStatusFilter = document.getElementById('serviceStatusFilter');
            var uniqueStatuses = [];
            servicesTable.column(2).data().unique().sort().each(function(value) {
                var textValue = value.match(/>([^<]+)</)?.[1] || value;
                if (textValue && uniqueStatuses.indexOf(textValue) === -1) {
                    uniqueStatuses.push(textValue);
                    var option = document.createElement('option');
                    option.value = textValue;
                    option.textContent = textValue;
                    serviceStatusFilter.appendChild(option);
                }
            });
            
            // Populate service start type filter
            var serviceStartTypeFilter = document.getElementById('serviceStartTypeFilter');
            var uniqueStartTypes = [];
            servicesTable.column(3).data().unique().sort().each(function(value) {
                if (value && uniqueStartTypes.indexOf(value) === -1) {
                    uniqueStartTypes.push(value);
                    var option = document.createElement('option');
                    option.value = value;
                    option.textContent = value;
                    serviceStartTypeFilter.appendChild(option);
                }
            });
            
            // Service status filter event
            serviceStatusFilter.addEventListener('change', function() {
                servicesTable.column(2).search(this.value).draw();
            });
            
            // Service start type filter event
            serviceStartTypeFilter.addEventListener('change', function() {
                servicesTable.column(3).search(this.value).draw();
            });
            
            // Initialize scheduled tasks table
            var scheduledTasksTable = `$('#scheduledTasksTable').DataTable({
                "pageLength": 50,
                "order": [[0, "asc"]]
            });
            
            // Populate task state filter
            var taskStateFilter = document.getElementById('taskStateFilter');
            var uniqueTaskStates = [];
            scheduledTasksTable.column(2).data().unique().sort().each(function(value) {
                var textValue = value.match(/>([^<]+)</)?.[1] || value;
                if (textValue && uniqueTaskStates.indexOf(textValue) === -1) {
                    uniqueTaskStates.push(textValue);
                    var option = document.createElement('option');
                    option.value = textValue;
                    option.textContent = textValue;
                    taskStateFilter.appendChild(option);
                }
            });
            
            // Task state filter event
            taskStateFilter.addEventListener('change', function() {
                scheduledTasksTable.column(2).search(this.value).draw();
            });
            
            // Initialize drivers table
            var driversTable = `$('#driversTable').DataTable({
                "pageLength": 50,
                "order": [[4, "asc"], [0, "asc"]]
            });
            
            // Populate driver class filter
            var driverClassFilter = document.getElementById('driverClassFilter');
            var uniqueClasses = [];
            driversTable.column(4).data().unique().sort().each(function(value) {
                if (value && uniqueClasses.indexOf(value) === -1) {
                    uniqueClasses.push(value);
                    var option = document.createElement('option');
                    option.value = value;
                    option.text = value;
                    driverClassFilter.appendChild(option);
                }
            });
            
            // Populate driver manufacturer filter
            var driverManufacturerFilter = document.getElementById('driverManufacturerFilter');
            var uniqueManufacturers = [];
            driversTable.column(3).data().unique().sort().each(function(value) {
                if (value && uniqueManufacturers.indexOf(value) === -1) {
                    uniqueManufacturers.push(value);
                    var option = document.createElement('option');
                    option.value = value;
                    option.text = value;
                    driverManufacturerFilter.appendChild(option);
                }
            });
            
            // Driver class filter event
            driverClassFilter.addEventListener('change', function() {
                driversTable.column(4).search(this.value).draw();
            });
            
            // Driver manufacturer filter event
            driverManufacturerFilter.addEventListener('change', function() {
                driversTable.column(3).search(this.value).draw();
            });
            
            `$('#mdmPoliciesTable').DataTable({
                "pageLength": 50,
                "order": [[0, "asc"]]
            });
        });

        // Collapsible sections
        var coll = document.getElementsByClassName("collapsible");
        for (var i = 0; i < coll.length; i++) {
            coll[i].addEventListener("click", function() {
                this.classList.toggle("active");
                var content = this.nextElementSibling;
                if (content.style.display === "block") {
                    content.style.display = "none";
                } else {
                    content.style.display = "block";
                }
            });
        }
    </script>
</body>
</html>
"@
    
    # Add System.Web assembly for HtmlEncode
    Add-Type -AssemblyName System.Web
    
    try {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        Write-Log "HTML report generated: $OutputPath" -Level Success
    }
    catch {
        Write-Log "Failed to generate HTML report: $($_.Exception.Message)" -Level Error
    }
}

#endregion

#region Comparison Functions

function Compare-BaselineReports {
    <#
    .SYNOPSIS
        Compares two baseline reports and generates a diff HTML report
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaselinePath,
        
        [Parameter(Mandatory = $true)]
        [string]$NewPath
    )
    
    Write-Log "Starting baseline comparison..." -Level Info
    
    # Find JSON files
    $baselineJson = Get-ChildItem -Path $BaselinePath -Filter "*_Full.json" | Select-Object -First 1
    $newJson = Get-ChildItem -Path $NewPath -Filter "*_Full.json" | Select-Object -First 1
    
    if (-not $baselineJson) {
        Write-Log "No baseline JSON file found in $BaselinePath" -Level Error
        return
    }
    
    if (-not $newJson) {
        Write-Log "No new JSON file found in $NewPath" -Level Error
        return
    }
    
    Write-Log "Loading baseline: $($baselineJson.Name)" -Level Info
    Write-Log "Loading new: $($newJson.Name)" -Level Info
    
    # Load JSON data
    $baselineData = Get-Content -Path $baselineJson.FullName -Raw | ConvertFrom-Json
    $newData = Get-Content -Path $newJson.FullName -Raw | ConvertFrom-Json
    
    # ==================== APPS COMPARISON (FIXED) ====================
    # Create hashtables for efficient lookup by Name only
    $baselineAppsHash = @{}
    foreach ($app in $baselineData.Apps) {
        $baselineAppsHash[$app.Name] = $app
    }
    
    $newAppsHash = @{}
    foreach ($app in $newData.Apps) {
        $newAppsHash[$app.Name] = $app
    }
    
    $appsOnlyInBaseline = @()
    $appsOnlyInNew = @()
    $appVersionChanges = @()
    
    # Check baseline apps
    foreach ($appName in $baselineAppsHash.Keys) {
        if (-not $newAppsHash.ContainsKey($appName)) {
            # App removed
            $app = $baselineAppsHash[$appName]
            $appsOnlyInBaseline += "$($app.Name)|$($app.Version)"
        }
        else {
            # App exists in both - check version
            $baselineApp = $baselineAppsHash[$appName]
            $newApp = $newAppsHash[$appName]
            
            if ($baselineApp.Version -ne $newApp.Version) {
                # Version changed
                $appVersionChanges += [PSCustomObject]@{
                    Name            = $appName
                    BaselineVersion = $baselineApp.Version
                    NewVersion      = $newApp.Version
                }
            }
        }
    }
    
    # Check for new apps
    foreach ($appName in $newAppsHash.Keys) {
        if (-not $baselineAppsHash.ContainsKey($appName)) {
            # App added
            $app = $newAppsHash[$appName]
            $appsOnlyInNew += "$($app.Name)|$($app.Version)"
        }
    }
    
    # ==================== FEATURES COMPARISON (FIXED) ====================
    $baselineFeaturesHash = @{}
    foreach ($feature in $baselineData.Features) {
        $baselineFeaturesHash[$feature.FeatureName] = $feature
    }
    
    $newFeaturesHash = @{}
    foreach ($feature in $newData.Features) {
        $newFeaturesHash[$feature.FeatureName] = $feature
    }
    
    $featuresOnlyInBaseline = @()
    $featuresOnlyInNew = @()
    $featuresChanged = @()
    
    foreach ($featureName in $baselineFeaturesHash.Keys) {
        if (-not $newFeaturesHash.ContainsKey($featureName)) {
            $feature = $baselineFeaturesHash[$featureName]
            $featuresOnlyInBaseline += "$($feature.FeatureName)|$($feature.State)"
        }
        else {
            $baselineFeature = $baselineFeaturesHash[$featureName]
            $newFeature = $newFeaturesHash[$featureName]
            
            if ($baselineFeature.State -ne $newFeature.State) {
                $featuresChanged += [PSCustomObject]@{
                    FeatureName   = $featureName
                    BaselineState = $baselineFeature.State
                    NewState      = $newFeature.State
                }
            }
        }
    }
    
    foreach ($featureName in $newFeaturesHash.Keys) {
        if (-not $baselineFeaturesHash.ContainsKey($featureName)) {
            $feature = $newFeaturesHash[$featureName]
            $featuresOnlyInNew += "$($feature.FeatureName)|$($feature.State)"
        }
    }
    
    # ==================== PROGRAMS COMPARISON (FIXED) ====================
    $baselineProgramsHash = @{}
    foreach ($program in $baselineData.Programs) {
        $baselineProgramsHash[$program.DisplayName] = $program
    }
    
    $newProgramsHash = @{}
    foreach ($program in $newData.Programs) {
        $newProgramsHash[$program.DisplayName] = $program
    }
    
    $programsOnlyInBaseline = @()
    $programsOnlyInNew = @()
    $programVersionChanges = @()
    
    foreach ($programName in $baselineProgramsHash.Keys) {
        if (-not $newProgramsHash.ContainsKey($programName)) {
            $program = $baselineProgramsHash[$programName]
            $programsOnlyInBaseline += "$($program.DisplayName)|$($program.DisplayVersion)"
        }
        else {
            $baselineProgram = $baselineProgramsHash[$programName]
            $newProgram = $newProgramsHash[$programName]
            
            if ($baselineProgram.DisplayVersion -ne $newProgram.DisplayVersion) {
                $programVersionChanges += [PSCustomObject]@{
                    Name            = $programName
                    BaselineVersion = $baselineProgram.DisplayVersion
                    NewVersion      = $newProgram.DisplayVersion
                }
            }
        }
    }
    
    foreach ($programName in $newProgramsHash.Keys) {
        if (-not $baselineProgramsHash.ContainsKey($programName)) {
            $program = $newProgramsHash[$programName]
            $programsOnlyInNew += "$($program.DisplayName)|$($program.DisplayVersion)"
        }
    }
    
    # ==================== SERVICES COMPARISON (FIXED) ====================
    $baselineServicesHash = @{}
    foreach ($service in $baselineData.Services) {
        $baselineServicesHash[$service.Name] = $service
    }
    
    $newServicesHash = @{}
    foreach ($service in $newData.Services) {
        $newServicesHash[$service.Name] = $service
    }
    
    $servicesOnlyInBaseline = @()
    $servicesOnlyInNew = @()
    $servicesChanged = @()
    
    foreach ($serviceName in $baselineServicesHash.Keys) {
        if (-not $newServicesHash.ContainsKey($serviceName)) {
            $service = $baselineServicesHash[$serviceName]
            $servicesOnlyInBaseline += "$($service.Name)|$($service.Status)|$($service.StartType)"
        }
        else {
            $baselineSvc = $baselineServicesHash[$serviceName]
            $newSvc = $newServicesHash[$serviceName]
            
            if ($baselineSvc.Status -ne $newSvc.Status -or $baselineSvc.StartType -ne $newSvc.StartType) {
                $servicesChanged += [PSCustomObject]@{
                    Name              = $serviceName
                    BaselineStatus    = $baselineSvc.Status
                    NewStatus         = $newSvc.Status
                    BaselineStartType = $baselineSvc.StartType
                    NewStartType      = $newSvc.StartType
                }
            }
        }
    }
    
    foreach ($serviceName in $newServicesHash.Keys) {
        if (-not $baselineServicesHash.ContainsKey($serviceName)) {
            $service = $newServicesHash[$serviceName]
            $servicesOnlyInNew += "$($service.Name)|$($service.Status)|$($service.StartType)"
        }
    }
    
    # Compare Security Features
    $securityChanges = @()
    $baselineSecurity = $baselineData.SecurityFeatures
    $newSecurity = $newData.SecurityFeatures
    
    if ($baselineSecurity.SecureBootEnabled -ne $newSecurity.SecureBootEnabled) {
        $securityChanges += [PSCustomObject]@{
            Feature = 'SecureBoot'
            Baseline = $baselineSecurity.SecureBootEnabled
            New = $newSecurity.SecureBootEnabled
        }
    }
    if ($baselineSecurity.TPMEnabled -ne $newSecurity.TPMEnabled) {
        $securityChanges += [PSCustomObject]@{
            Feature = 'TPM'
            Baseline = $baselineSecurity.TPMEnabled
            New = $newSecurity.TPMEnabled
        }
    }
    if ($baselineSecurity.DeviceGuardStatus -ne $newSecurity.DeviceGuardStatus) {
        $securityChanges += [PSCustomObject]@{
            Feature = 'Device Guard'
            Baseline = $baselineSecurity.DeviceGuardStatus
            New = $newSecurity.DeviceGuardStatus
        }
    }
    if ($baselineSecurity.CredentialGuardStatus -ne $newSecurity.CredentialGuardStatus) {
        $securityChanges += [PSCustomObject]@{
            Feature = 'Credential Guard'
            Baseline = $baselineSecurity.CredentialGuardStatus
            New = $newSecurity.CredentialGuardStatus
        }
    }
    if ($baselineSecurity.HVCIStatus -ne $newSecurity.HVCIStatus) {
        $securityChanges += [PSCustomObject]@{
            Feature = 'HVCI'
            Baseline = $baselineSecurity.HVCIStatus
            New = $newSecurity.HVCIStatus
        }
    }
    
    # ==================== SCHEDULED TASKS COMPARISON (FIXED) ====================
    $baselineTasksHash = @{}
    foreach ($task in $baselineData.ScheduledTasks) {
        $baselineTasksHash[$task.TaskName] = $task
    }
    
    $newTasksHash = @{}
    foreach ($task in $newData.ScheduledTasks) {
        $newTasksHash[$task.TaskName] = $task
    }
    
    $tasksOnlyInBaseline = @()
    $tasksOnlyInNew = @()
    $tasksChanged = @()
    
    foreach ($taskName in $baselineTasksHash.Keys) {
        if (-not $newTasksHash.ContainsKey($taskName)) {
            $task = $baselineTasksHash[$taskName]
            $tasksOnlyInBaseline += "$($task.TaskName)|$($task.State)"
        }
        else {
            $baselineTask = $baselineTasksHash[$taskName]
            $newTask = $newTasksHash[$taskName]
            
            if ($baselineTask.State -ne $newTask.State) {
                $tasksChanged += [PSCustomObject]@{
                    TaskName      = $taskName
                    BaselineState = $baselineTask.State
                    NewState      = $newTask.State
                }
            }
        }
    }
    
    foreach ($taskName in $newTasksHash.Keys) {
        if (-not $baselineTasksHash.ContainsKey($taskName)) {
            $task = $newTasksHash[$taskName]
            $tasksOnlyInNew += "$($task.TaskName)|$($task.State)"
        }
    }
    
    # ==================== MDM POLICIES COMPARISON (FIXED) ====================
    $baselinePoliciesHash = @{}
    foreach ($policy in $baselineData.IntuneMDMPolicies) {
        $key = "$($policy.PolicyArea)|$($policy.PolicyName)"
        $baselinePoliciesHash[$key] = $policy
    }
    
    $newPoliciesHash = @{}
    foreach ($policy in $newData.IntuneMDMPolicies) {
        $key = "$($policy.PolicyArea)|$($policy.PolicyName)"
        $newPoliciesHash[$key] = $policy
    }
    
    $policiesOnlyInBaseline = @()
    $policiesOnlyInNew = @()
    $policyValueChanges = @()
    
    foreach ($policyKey in $baselinePoliciesHash.Keys) {
        if (-not $newPoliciesHash.ContainsKey($policyKey)) {
            $policy = $baselinePoliciesHash[$policyKey]
            $policiesOnlyInBaseline += "$($policy.PolicyArea)|$($policy.PolicyName)"
        }
        else {
            $baselinePolicy = $baselinePoliciesHash[$policyKey]
            $newPolicy = $newPoliciesHash[$policyKey]
            
            if ($baselinePolicy.Value -ne $newPolicy.Value) {
                $policyValueChanges += [PSCustomObject]@{
                    PolicyArea    = $baselinePolicy.PolicyArea
                    PolicyName    = $baselinePolicy.PolicyName
                    BaselineValue = $baselinePolicy.Value
                    NewValue      = $newPolicy.Value
                }
            }
        }
    }
    
    foreach ($policyKey in $newPoliciesHash.Keys) {
        if (-not $baselinePoliciesHash.ContainsKey($policyKey)) {
            $policy = $newPoliciesHash[$policyKey]
            $policiesOnlyInNew += "$($policy.PolicyArea)|$($policy.PolicyName)"
        }
    }
    
    # ==================== DRIVERS COMPARISON (FIXED) ====================
    $baselineDriversHash = @{}
    foreach ($driver in $baselineData.Drivers) {
        $key = "$($driver.DeviceName)|$($driver.Manufacturer)"
        $baselineDriversHash[$key] = $driver
    }
    
    $newDriversHash = @{}
    foreach ($driver in $newData.Drivers) {
        $key = "$($driver.DeviceName)|$($driver.Manufacturer)"
        $newDriversHash[$key] = $driver
    }
    
    $driversOnlyInBaseline = @()
    $driversOnlyInNew = @()
    $driverVersionChanges = @()
    
    foreach ($driverKey in $baselineDriversHash.Keys) {
        if (-not $newDriversHash.ContainsKey($driverKey)) {
            $driver = $baselineDriversHash[$driverKey]
            $driversOnlyInBaseline += "$($driver.DeviceName)|$($driver.DriverVersion)|$($driver.Manufacturer)"
        }
        else {
            $baselineDriver = $baselineDriversHash[$driverKey]
            $newDriver = $newDriversHash[$driverKey]
            
            if ($baselineDriver.DriverVersion -ne $newDriver.DriverVersion) {
                $driverVersionChanges += [PSCustomObject]@{
                    DeviceName      = $baselineDriver.DeviceName
                    Manufacturer    = $baselineDriver.Manufacturer
                    BaselineVersion = $baselineDriver.DriverVersion
                    BaselineDate    = $baselineDriver.DriverDate
                    NewVersion      = $newDriver.DriverVersion
                    NewDate         = $newDriver.DriverDate
                }
            }
        }
    }
    
    foreach ($driverKey in $newDriversHash.Keys) {
        if (-not $baselineDriversHash.ContainsKey($driverKey)) {
            $driver = $newDriversHash[$driverKey]
            $driversOnlyInNew += "$($driver.DeviceName)|$($driver.DriverVersion)|$($driver.Manufacturer)"
        }
    }
    
    # Generate comparison HTML
    $comparisonHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Baseline Comparison Report</title>
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            padding: 20px;
        }
        .container-fluid {
            max-width: 1600px;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .comparison-summary {
            display: flex;
            justify-content: space-around;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
            flex: 1;
            margin: 0 10px;
        }
        .stat-card h3 {
            margin: 0;
            font-size: 2.5rem;
        }
        .stat-card p {
            margin: 10px 0 0 0;
            color: #666;
        }
        .removed { background-color: #ffe6e6; border-left: 4px solid #dc3545; }
        .added { background-color: #e6ffe6; border-left: 4px solid #28a745; }
        .changed { background-color: #fff8e6; border-left: 4px solid #ffc107; }
        .section {
            margin-top: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        .section h2 {
            color: #f5576c;
            margin-bottom: 20px;
        }
        table.dataTable {
            width: 100% !important;
        }
        .badge-removed {
            background-color: #dc3545;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
        }
        .badge-added {
            background-color: #28a745;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
        }
        .badge-changed {
            background-color: #ffc107;
            color: #333;
            padding: 5px 10px;
            border-radius: 5px;
        }
        .comparison-grid {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        .comparison-col {
            padding: 15px;
            border-radius: 8px;
        }
        .comparison-col h4 {
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="header">
            <h1>Windows Baseline Comparison Report</h1>
            <p style="margin: 0; font-size: 1.1rem;">
                Baseline: $($baselineData.Metadata.ComputerName) (Build $($baselineData.Metadata.OSBuildNumber)) vs 
                New: $($newData.Metadata.ComputerName) (Build $($newData.Metadata.OSBuildNumber))
            </p>
            <p style="margin: 5px 0 0 0;">Comparison Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        </div>

        <div class="comparison-summary">
            <div class="stat-card removed">
                <h3>$($appsOnlyInBaseline.Count + $featuresOnlyInBaseline.Count + $programsOnlyInBaseline.Count + $servicesOnlyInBaseline.Count + $tasksOnlyInBaseline.Count + $policiesOnlyInBaseline.Count + $driversOnlyInBaseline.Count)</h3>
                <p>Items Removed</p>
            </div>
            <div class="stat-card added">
                <h3>$($appsOnlyInNew.Count + $featuresOnlyInNew.Count + $programsOnlyInNew.Count + $servicesOnlyInNew.Count + $tasksOnlyInNew.Count + $policiesOnlyInNew.Count + $driversOnlyInNew.Count)</h3>
                <p>Items Added</p>
            </div>
            <div class="stat-card changed">
                <h3>$($appVersionChanges.Count + $programVersionChanges.Count + $featuresChanged.Count + $servicesChanged.Count + $tasksChanged.Count + $securityChanges.Count + $policyValueChanges.Count + $driverVersionChanges.Count)</h3>
                <p>Configuration Changes</p>
            </div>
        </div>

        <div class="section">
            <h2>AppX Packages Comparison</h2>
            <div class="comparison-grid">
                <div class="comparison-col removed">
                    <h4><span class="badge-removed">Removed ($($appsOnlyInBaseline.Count))</span></h4>
                    <ul>
"@
    
    foreach ($app in $appsOnlyInBaseline | Select-Object -First 50) {
        $parts = $app -split '\|'
        $comparisonHtml += "                        <li>$($parts[0]) (v$($parts[1]))</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
                <div class="comparison-col changed">
                    <h4><span class="badge-changed">Version Changes ($($appVersionChanges.Count))</span></h4>
                    <ul>
"@
    
    foreach ($change in $appVersionChanges | Select-Object -First 50) {
        $comparisonHtml += "                        <li>$($change.Name): $($change.BaselineVersion) -> $($change.NewVersion)</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
                <div class="comparison-col added">
                    <h4><span class="badge-added">Added ($($appsOnlyInNew.Count))</span></h4>
                    <ul>
"@
    
    foreach ($app in $appsOnlyInNew | Select-Object -First 50) {
        $parts = $app -split '\|'
        $comparisonHtml += "                        <li>$($parts[0]) (v$($parts[1]))</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Windows Features Comparison</h2>
            <div class="comparison-grid">
                <div class="comparison-col removed">
                    <h4><span class="badge-removed">Removed/Disabled ($($featuresOnlyInBaseline.Count))</span></h4>
                    <ul>
"@
    
    foreach ($feature in $featuresOnlyInBaseline | Select-Object -First 50) {
        $parts = $feature -split '\|'
        $comparisonHtml += "                        <li>$($parts[0]) ($($parts[1]))</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
                <div class="comparison-col changed">
                    <h4><span class="badge-changed">State Changes ($($featuresChanged.Count))</span></h4>
                    <ul>
"@
    
    foreach ($change in $featuresChanged | Select-Object -First 30) {
        $comparisonHtml += "                        <li>$($change.FeatureName): $($change.BaselineState) → $($change.NewState)</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
                <div class="comparison-col added">
                    <h4><span class="badge-added">Added/Enabled ($($featuresOnlyInNew.Count))</span></h4>
                    <ul>
"@
    
    foreach ($feature in $featuresOnlyInNew | Select-Object -First 50) {
        $parts = $feature -split '\|'
        $comparisonHtml += "                        <li>$($parts[0]) ($($parts[1]))</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Installed Programs Comparison</h2>
            <div class="comparison-grid">
                <div class="comparison-col removed">
                    <h4><span class="badge-removed">Removed ($($programsOnlyInBaseline.Count))</span></h4>
                    <ul>
"@
    
    foreach ($program in $programsOnlyInBaseline | Select-Object -First 50) {
        $parts = $program -split '\|'
        $comparisonHtml += "                        <li>$($parts[0]) (v$($parts[1]))</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
                <div class="comparison-col changed">
                    <h4><span class="badge-changed">Version Changes ($($programVersionChanges.Count))</span></h4>
                    <ul>
"@
    
    foreach ($change in $programVersionChanges | Select-Object -First 30) {
        $comparisonHtml += "                        <li>$($change.Name): v$($change.BaselineVersion) → v$($change.NewVersion)</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
                <div class="comparison-col added">
                    <h4><span class="badge-added">Added ($($programsOnlyInNew.Count))</span></h4>
                    <ul>
"@
    
    foreach ($program in $programsOnlyInNew | Select-Object -First 50) {
        $parts = $program -split '\|'
        $comparisonHtml += "                        <li>$($parts[0]) (v$($parts[1]))</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Windows Services Comparison</h2>
            <div class="comparison-grid">
                <div class="comparison-col removed">
                    <h4><span class="badge-removed">Removed/Stopped ($($servicesOnlyInBaseline.Count))</span></h4>
                    <ul>
"@
    
    foreach ($service in $servicesOnlyInBaseline | Select-Object -First 30) {
        $parts = $service -split '\|'
        $comparisonHtml += "                        <li>$($parts[0]) - Status: $($parts[1]), StartType: $($parts[2])</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
                <div class="comparison-col changed">
                    <h4><span class="badge-changed">Changed ($($servicesChanged.Count))</span></h4>
                    <ul>
"@
    
    foreach ($change in $servicesChanged | Select-Object -First 30) {
        $statusChange = if ($change.BaselineStatus -ne $change.NewStatus) { "Status: $($change.BaselineStatus) -> $($change.NewStatus)" } else { "" }
        $startTypeChange = if ($change.BaselineStartType -ne $change.NewStartType) { "StartType: $($change.BaselineStartType) -> $($change.NewStartType)" } else { "" }
        $comparisonHtml += "                        <li>$($change.Name): $statusChange $startTypeChange</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
                <div class="comparison-col added">
                    <h4><span class="badge-added">Added/Started ($($servicesOnlyInNew.Count))</span></h4>
                    <ul>
"@
    
    foreach ($service in $servicesOnlyInNew | Select-Object -First 30) {
        $parts = $service -split '\|'
        $comparisonHtml += "                        <li>$($parts[0]) - Status: $($parts[1]), StartType: $($parts[2])</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Security Features Comparison</h2>
"@
    
    if ($securityChanges.Count -gt 0) {
        $comparisonHtml += @"
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Security Feature</th>
                        <th>Baseline (23H2)</th>
                        <th>New (25H2)</th>
                    </tr>
                </thead>
                <tbody>
"@
        foreach ($change in $securityChanges) {
            $comparisonHtml += @"
                    <tr>
                        <td>$($change.Feature)</td>
                        <td>$($change.Baseline)</td>
                        <td>$($change.New)</td>
                    </tr>
"@
        }
        $comparisonHtml += @"
                </tbody>
            </table>
"@
    } else {
        $comparisonHtml += "            <p>No security feature changes detected.</p>`n"
    }
    
    $comparisonHtml += @"
        </div>

        <div class="section">
            <h2>Scheduled Tasks Comparison</h2>
            <div class="comparison-grid">
                <div class="comparison-col removed">
                    <h4><span class="badge-removed">Removed ($($tasksOnlyInBaseline.Count))</span></h4>
                    <ul>
"@
    
    foreach ($task in $tasksOnlyInBaseline | Select-Object -First 30) {
        $parts = $task -split '\|'
        $comparisonHtml += "                        <li>$($parts[0]) ($($parts[1]))</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
                <div class="comparison-col">
                    <h4><span class="badge-changed">Common Tasks</span></h4>
                    <p>Tasks present in both baselines</p>
                </div>
                <div class="comparison-col added">
                    <h4><span class="badge-added">Added ($($tasksOnlyInNew.Count))</span></h4>
                    <ul>
"@
    
    foreach ($task in $tasksOnlyInNew | Select-Object -First 30) {
        $parts = $task -split '\|'
        $comparisonHtml += "                        <li>$($parts[0]) ($($parts[1]))</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Intune MDM Policies Comparison</h2>
            <div class="comparison-grid">
                <div class="comparison-col removed">
                    <h4><span class="badge-removed">Removed ($($policiesOnlyInBaseline.Count))</span></h4>
                    <ul>
"@
    
    foreach ($policy in $policiesOnlyInBaseline | Select-Object -First 30) {
        $parts = $policy -split '\|'
        $comparisonHtml += "                        <li>$($parts[0])\$($parts[1])</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
                <div class="comparison-col changed">
                    <h4><span class="badge-changed">Value Changes ($($policyValueChanges.Count))</span></h4>
                    <ul>
"@
    
    foreach ($change in $policyValueChanges | Select-Object -First 30) {
        $comparisonHtml += "                        <li>$($change.PolicyArea)\$($change.PolicyName): '$($change.BaselineValue)' -> '$($change.NewValue)'</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
                <div class="comparison-col added">
                    <h4><span class="badge-added">Added ($($policiesOnlyInNew.Count))</span></h4>
                    <ul>
"@
    
    foreach ($policy in $policiesOnlyInNew | Select-Object -First 30) {
        $parts = $policy -split '\|'
        $comparisonHtml += "                        <li>$($parts[0])\$($parts[1])</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Installed Drivers Comparison</h2>
            <div class="comparison-grid">
                <div class="comparison-col removed">
                    <h4><span class="badge-removed">Removed ($($driversOnlyInBaseline.Count))</span></h4>
                    <ul>
"@
    
    foreach ($driver in $driversOnlyInBaseline | Select-Object -First 30) {
        $parts = $driver -split '\|'
        $comparisonHtml += "                        <li>$($parts[0]) - $($parts[2]) (v$($parts[1]))</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
                <div class="comparison-col changed">
                    <h4><span class="badge-changed">Version Changes ($($driverVersionChanges.Count))</span></h4>
                    <ul>
"@
    
    foreach ($change in $driverVersionChanges | Select-Object -First 30) {
        $comparisonHtml += "                        <li>$($change.DeviceName) ($($change.Manufacturer)): v$($change.BaselineVersion) ($($change.BaselineDate)) → v$($change.NewVersion) ($($change.NewDate))</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
                <div class="comparison-col added">
                    <h4><span class="badge-added">Added ($($driversOnlyInNew.Count))</span></h4>
                    <ul>
"@
    
    foreach ($driver in $driversOnlyInNew | Select-Object -First 30) {
        $parts = $driver -split '\|'
        $comparisonHtml += "                        <li>$($parts[0]) - $($parts[2]) (v$($parts[1]))</li>`n"
    }
    
    $comparisonHtml += @"
                    </ul>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Summary Statistics</h2>
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Baseline (23H2)</th>
                        <th>New (25H2)</th>
                        <th>Delta</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>AppX Packages</td>
                        <td>$($baselineData.Apps.Count)</td>
                        <td>$($newData.Apps.Count)</td>
                        <td>$(if ($newData.Apps.Count -gt $baselineData.Apps.Count) { "+" })$($newData.Apps.Count - $baselineData.Apps.Count)</td>
                    </tr>
                    <tr>
                        <td>Windows Features</td>
                        <td>$($baselineData.Features.Count)</td>
                        <td>$($newData.Features.Count)</td>
                        <td>$(if ($newData.Features.Count -gt $baselineData.Features.Count) { "+" })$($newData.Features.Count - $baselineData.Features.Count)</td>
                    </tr>
                    <tr>
                        <td>Installed Programs</td>
                        <td>$($baselineData.Programs.Count)</td>
                        <td>$($newData.Programs.Count)</td>
                        <td>$(if ($newData.Programs.Count -gt $baselineData.Programs.Count) { "+" })$($newData.Programs.Count - $baselineData.Programs.Count)</td>
                    </tr>
                    <tr>
                        <td>Event Log Errors</td>
                        <td>$(($baselineData.Events | Where-Object { $_.LevelDisplayName -eq 'Error' }).Count)</td>
                        <td>$(($newData.Events | Where-Object { $_.LevelDisplayName -eq 'Error' }).Count)</td>
                        <td>$(if ((($newData.Events | Where-Object { $_.LevelDisplayName -eq 'Error' }).Count) -gt (($baselineData.Events | Where-Object { $_.LevelDisplayName -eq 'Error' }).Count)) { "+" })$((($newData.Events | Where-Object { $_.LevelDisplayName -eq 'Error' }).Count) - (($baselineData.Events | Where-Object { $_.LevelDisplayName -eq 'Error' }).Count))</td>
                    </tr>
                    <tr>
                        <td>Event Log Warnings</td>
                        <td>$(($baselineData.Events | Where-Object { $_.LevelDisplayName -eq 'Warning' }).Count)</td>
                        <td>$(($newData.Events | Where-Object { $_.LevelDisplayName -eq 'Warning' }).Count)</td>
                        <td>$(if ((($newData.Events | Where-Object { $_.LevelDisplayName -eq 'Warning' }).Count) -gt (($baselineData.Events | Where-Object { $_.LevelDisplayName -eq 'Warning' }).Count)) { "+" })$((($newData.Events | Where-Object { $_.LevelDisplayName -eq 'Warning' }).Count) - (($baselineData.Events | Where-Object { $_.LevelDisplayName -eq 'Warning' }).Count))</td>
                    </tr>
                    <tr>
                        <td>Windows Services</td>
                        <td>$($baselineData.Services.Count)</td>
                        <td>$($newData.Services.Count)</td>
                        <td>$(if ($newData.Services.Count -gt $baselineData.Services.Count) { "+" })$($newData.Services.Count - $baselineData.Services.Count)</td>
                    </tr>
                    <tr>
                        <td>Scheduled Tasks</td>
                        <td>$($baselineData.ScheduledTasks.Count)</td>
                        <td>$($newData.ScheduledTasks.Count)</td>
                        <td>$(if ($newData.ScheduledTasks.Count -gt $baselineData.ScheduledTasks.Count) { "+" })$($newData.ScheduledTasks.Count - $baselineData.ScheduledTasks.Count)</td>
                    </tr>
                    <tr>
                        <td>Intune MDM Policies</td>
                        <td>$($baselineData.IntuneMDMPolicies.Count)</td>
                        <td>$($newData.IntuneMDMPolicies.Count)</td>
                        <td>$(if ($newData.IntuneMDMPolicies.Count -gt $baselineData.IntuneMDMPolicies.Count) { "+" })$($newData.IntuneMDMPolicies.Count - $baselineData.IntuneMDMPolicies.Count)</td>
                    </tr>
                    <tr>
                        <td>Installed Drivers</td>
                        <td>$($baselineData.Drivers.Count)</td>
                        <td>$($newData.Drivers.Count)</td>
                        <td>$(if ($newData.Drivers.Count -gt $baselineData.Drivers.Count) { "+" })$($newData.Drivers.Count - $baselineData.Drivers.Count)</td>
                    </tr>
                    <tr>
                        <td>Security Changes</td>
                        <td colspan="2">$($securityChanges.Count) feature(s) changed</td>
                        <td>N/A</td>
                    </tr>
                </tbody>
            </table>
        </div>

    </div>
</body>
</html>
"@
    
    # Save comparison report
    $comparisonPath = Join-Path -Path $BaselinePath -ChildPath "Baseline_Comparison_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    try {
        $comparisonHtml | Out-File -FilePath $comparisonPath -Encoding UTF8 -Force
        Write-Log "Comparison report generated: $comparisonPath" -Level Success
        Write-Log "" -Level Info
        Write-Log "Summary:" -Level Success
        Write-Log "  Apps removed: $($appsOnlyInBaseline.Count)" -Level Info
        Write-Log "  Apps added: $($appsOnlyInNew.Count)" -Level Info
        Write-Log "  App version changes: $($appVersionChanges.Count)" -Level Info
        Write-Log "  Features removed/disabled: $($featuresOnlyInBaseline.Count)" -Level Info
        Write-Log "  Features added/enabled: $($featuresOnlyInNew.Count)" -Level Info
        Write-Log "  Feature state changes: $($featuresChanged.Count)" -Level Info
        Write-Log "  Programs removed: $($programsOnlyInBaseline.Count)" -Level Info
        Write-Log "  Programs added: $($programsOnlyInNew.Count)" -Level Info
        Write-Log "  Program version changes: $($programVersionChanges.Count)" -Level Info
        Write-Log "  Services removed: $($servicesOnlyInBaseline.Count)" -Level Info
        Write-Log "  Services added: $($servicesOnlyInNew.Count)" -Level Info
        Write-Log "  Services configuration changes: $($servicesChanged.Count)" -Level Info
        Write-Log "  Security features changed: $($securityChanges.Count)" -Level Info
        Write-Log "  Tasks removed: $($tasksOnlyInBaseline.Count)" -Level Info
        Write-Log "  Tasks added: $($tasksOnlyInNew.Count)" -Level Info
        Write-Log "  Task state changes: $($tasksChanged.Count)" -Level Info
        Write-Log "  Policies removed: $($policiesOnlyInBaseline.Count)" -Level Info
        Write-Log "  Policies added: $($policiesOnlyInNew.Count)" -Level Info
        Write-Log "  Policy value changes: $($policyValueChanges.Count)" -Level Info
        Write-Log "  Drivers removed: $($driversOnlyInBaseline.Count)" -Level Info
        Write-Log "  Drivers added: $($driversOnlyInNew.Count)" -Level Info
        Write-Log "  Driver version changes: $($driverVersionChanges.Count)" -Level Info
    }
    catch {
        Write-Log "Failed to generate comparison report: $($_.Exception.Message)" -Level Error
    }
}

#endregion

#region Main Execution

# Check if in comparison mode
if ($Compare) {
    Compare-BaselineReports -BaselinePath $BaselineReport -NewPath $NewReport
    exit 0
}

# Collection mode
Write-Log "=== Windows Baseline Data Collection ===" -Level Success
Write-Log "Event log timeframe: $EventLogDays days" -Level Info
Write-Log "Report path: $ReportPath" -Level Info

# Create report directory if it doesn't exist
if (-not (Test-Path $ReportPath)) {
    New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
    Write-Log "Created report directory: $ReportPath" -Level Success
}

# Collect all data
$reportData = @{
    Metadata           = Get-SystemMetadata
    Events             = Get-IntuneEventLogs -DaysBack $EventLogDays
    IntuneLogEntries   = @()
    Apps               = Get-AppxInventory
    Features           = Get-WindowsFeaturesStatus
    Programs           = Get-InstalledApplications
    IntuneMDMPolicies  = Get-IntuneMDMPolicies
    Services           = Get-RunningServices
    SecurityFeatures   = Get-SecurityFeatures
    ScheduledTasks     = Get-ScheduledTasksInventory
    Drivers            = Get-InstalledDrivers
}

# Optionally collect detailed Intune logs
if ($IncludeIntuneLogDetails) {
    $reportData.IntuneLogEntries = Get-IntuneManagementExtensionLogs
}

# Generate file names
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$computerName = $reportData.Metadata.ComputerName
$osBuild = $reportData.Metadata.OSBuildNumber
$filePrefix = "${computerName}_${osBuild}_${timestamp}"

# Export data to files
Write-Log "Exporting data to files..." -Level Info

# JSON (full data)
$jsonPath = Join-Path -Path $ReportPath -ChildPath "${filePrefix}_Full.json"
$reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8 -Force
Write-Log "Saved: $jsonPath" -Level Success

# CSV files
$eventsPath = Join-Path -Path $ReportPath -ChildPath "${filePrefix}_Events.csv"
$reportData.Events | Export-Csv -Path $eventsPath -NoTypeInformation -Encoding UTF8
Write-Log "Saved: $eventsPath" -Level Success

$appsPath = Join-Path -Path $ReportPath -ChildPath "${filePrefix}_Apps.csv"
$reportData.Apps | Export-Csv -Path $appsPath -NoTypeInformation -Encoding UTF8
Write-Log "Saved: $appsPath" -Level Success

$featuresPath = Join-Path -Path $ReportPath -ChildPath "${filePrefix}_Features.csv"
$reportData.Features | Export-Csv -Path $featuresPath -NoTypeInformation -Encoding UTF8
Write-Log "Saved: $featuresPath" -Level Success

$programsPath = Join-Path -Path $ReportPath -ChildPath "${filePrefix}_Programs.csv"
$reportData.Programs | Export-Csv -Path $programsPath -NoTypeInformation -Encoding UTF8
Write-Log "Saved: $programsPath" -Level Success

$mdmPoliciesPath = Join-Path -Path $ReportPath -ChildPath "${filePrefix}_IntuneMDMPolicies.csv"
$reportData.IntuneMDMPolicies | Export-Csv -Path $mdmPoliciesPath -NoTypeInformation -Encoding UTF8
Write-Log "Saved: $mdmPoliciesPath" -Level Success

$servicesPath = Join-Path -Path $ReportPath -ChildPath "${filePrefix}_Services.csv"
$reportData.Services | Export-Csv -Path $servicesPath -NoTypeInformation -Encoding UTF8
Write-Log "Saved: $servicesPath" -Level Success

$securityFeaturesPath = Join-Path -Path $ReportPath -ChildPath "${filePrefix}_SecurityFeatures.csv"
$reportData.SecurityFeatures | Export-Csv -Path $securityFeaturesPath -NoTypeInformation -Encoding UTF8
Write-Log "Saved: $securityFeaturesPath" -Level Success

$scheduledTasksPath = Join-Path -Path $ReportPath -ChildPath "${filePrefix}_ScheduledTasks.csv"
$reportData.ScheduledTasks | Export-Csv -Path $scheduledTasksPath -NoTypeInformation -Encoding UTF8
Write-Log "Saved: $scheduledTasksPath" -Level Success

$driversPath = Join-Path -Path $ReportPath -ChildPath "${filePrefix}_Drivers.csv"
$reportData.Drivers | Export-Csv -Path $driversPath -NoTypeInformation -Encoding UTF8
Write-Log "Saved: $driversPath" -Level Success

if ($IncludeIntuneLogDetails -and $reportData.IntuneLogEntries.Count -gt 0) {
    $intuneLogsPath = Join-Path -Path $ReportPath -ChildPath "${filePrefix}_IntuneLogs.csv"
    $reportData.IntuneLogEntries | Export-Csv -Path $intuneLogsPath -NoTypeInformation -Encoding UTF8
    Write-Log "Saved: $intuneLogsPath" -Level Success
}

# HTML report
$htmlPath = Join-Path -Path $ReportPath -ChildPath "${filePrefix}_Summary.html"
New-InteractiveHtmlReport -ReportData $reportData -OutputPath $htmlPath

Write-Log "" -Level Info
Write-Log "=== Collection Complete ===" -Level Success
Write-Log "All reports saved to: $ReportPath" -Level Info
Write-Log "" -Level Info
Write-Log "To compare two baselines, run:" -Level Info
Write-Log "  .\Baseline23H2vs25H2.ps1 -Compare -BaselineReport 'C:\Path\To\23H2\Reports' -NewReport 'C:\Path\To\25H2\Reports'" -Level Info

#endregion
