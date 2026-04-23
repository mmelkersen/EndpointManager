<#
.SYNOPSIS
    Comprehensive Intune policy review tool that generates an interactive HTML report showing all configurations with assignment status.

.DESCRIPTION
    This script queries Microsoft Graph API to retrieve all Intune policy types (Configuration Policies, Device Configurations, 
    Group Policy Configurations, Compliance Policies, PowerShell Scripts, Remediation Scripts, Apps, etc.) and generates a 
    modern HTML dashboard with three main views:
    
    1. Unassigned Policies - Policies with no assignments
    2. Assigned Policies - Policies with assignments and their target groups/filters
    3. Deprecated/Test Policies - Policies containing "deprecated" or "test" in their names
    
    The report includes change tracking when a previous report JSON is provided, showing new, modified, deleted, and 
    assignment-changed policies with visual indicators.

.PARAMETER OutputPath
    Path where the HTML report will be saved. Defaults to ".\IntunePolicy Review_YYYYMMDD_HHmmss.html"

.PARAMETER IncludeSettings
    Switch to include detailed policy settings in the report. Warning: This significantly increases execution time as it 
    requires additional API calls for each policy.

.PARAMETER PreviousReport
    Path to a previously generated JSON baseline file for change tracking. The script will highlight differences between 
    the current state and the baseline.

.PARAMETER ExportToCSV
    Switch to export each category (Unassigned, Assigned, Deprecated/Test) to separate CSV files.

.PARAMETER NoHTMLReport
    Switch to skip HTML report generation (useful when only exporting to CSV or JSON).

.PARAMETER SkipGroupResolution
    Switch to skip resolving group names from IDs. This significantly improves performance in large environments 
    with 350K+ groups by showing Group IDs instead of names. Recommended for quick audits focused on assignment 
    status rather than group details.

.PARAMETER ThrottleMilliseconds
    Adds a delay in milliseconds between assignment API calls to prevent overwhelming the service in large tenants.
    Recommended values: 50-200ms for tenants with 350K+ groups experiencing InternalServerError issues.
    Default: 0 (no throttling).

.EXAMPLE
    .\ReviewIntunePolicyState.ps1
    
    Generates an HTML report with all Intune policies categorized by assignment status.

.EXAMPLE
    .\ReviewIntunePolicyState.ps1 -OutputPath "C:\Reports\IntuneReview.html" -ExportToCSV
    
    Generates HTML report at specified path and exports each category to CSV files.

.EXAMPLE
    .\ReviewIntunePolicyState.ps1 -PreviousReport ".\IntunePolicy Review_20260127_baseline.json"
    
    Generates report with change tracking, comparing current state against the baseline from January 27, 2026.

.EXAMPLE
    .\ReviewIntunePolicyState.ps1 -IncludeSettings -OutputPath "C:\Reports\DetailedReview.html"
    
    Generates detailed report including policy settings (slower execution).

.EXAMPLE
    .\ReviewIntunePolicyState.ps1 -SkipGroupResolution
    
    Generates report showing group IDs instead of names for maximum performance in large environments (350K+ groups).

.EXAMPLE
    .\ReviewIntunePolicyState.ps1 -ThrottleMilliseconds 100
    
    Adds 100ms delay between assignment API calls to prevent InternalServerError in large tenants.

.EXAMPLE
    .\ReviewIntunePolicyState.ps1 -SkipGroupResolution -ThrottleMilliseconds 50
    
    Optimal settings for very large tenants: skips group resolution and throttles API calls.

.NOTES
    Version:        1.3
    Author:         Mattias Melkersen
    Creation Date:  2026-01-28
    
    CHANGELOG
    ---------------
    2026-02-24 - v1.3 - Fully implemented -IncludeSettings: Get-PolicySettings function, per-policy settings fetch, expandable settings rows in HTML report (Mattias Melkersen)
    2026-02-24 - v1.2 - Fixed broken Write-Host step separator, removed demo event branding from HTML header, fixed subtitle capitalisation, corrected version banner (Mattias Melkersen)
    2026-02-24 - v1.1 - Removed unused module declarations (Microsoft.Graph.DeviceManagement, Microsoft.Graph.Groups); script uses Invoke-MgGraphRequest exclusively (Mattias Melkersen)
    2026-01-28 - v1.0 - Initial release with change tracking and modern HTML UI (Mattias Melkersen)
    
    REQUIREMENTS
    ---------------
    - Microsoft.Graph.Authentication module
    
    PERMISSIONS
    ---------------
    Required Microsoft Graph API permissions:
    - DeviceManagementConfiguration.Read.All
    - DeviceManagementApps.Read.All
    - Group.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSettings,
    
    [Parameter(Mandatory = $false)]
    [string]$PreviousReport,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportToCSV,
    
    [Parameter(Mandatory = $false)]
    [switch]$NoHTMLReport,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipGroupResolution,
    
    [Parameter(Mandatory = $false)]
    [int]$ThrottleMilliseconds = 0
)

#region Helper Functions

function Test-RequiredModules {
    <#
    .SYNOPSIS
        Checks and installs required PowerShell modules.
    #>
    param()
    
    $requiredModules = @(
        "Microsoft.Graph.Authentication"
    )
    
    Write-Host "Checking required modules..." -ForegroundColor Cyan
    
    foreach ($moduleName in $requiredModules) {
        if (-not (Get-Module -Name $moduleName -ListAvailable)) {
            Write-Host "Module $moduleName not found. Installing..." -ForegroundColor Yellow
            
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
            
            try {
                if ($isAdmin) {
                    Install-Module -Name $moduleName -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
                } else {
                    Install-Module -Name $moduleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                }
                Write-Host "Successfully installed $moduleName" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to install $moduleName : $_"
                exit 1
            }
        } else {
            Write-Host "Module $moduleName is already installed" -ForegroundColor Green
        }
    }
}

function Invoke-MSGraphRequestWithPagination {
    <#
    .SYNOPSIS
        Invokes Microsoft Graph API request with automatic pagination and retry logic.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,
        
        [Parameter(Mandatory = $false)]
        [int]$RetryDelay = 2
    )
    
    $allResults = [System.Collections.Generic.List[PSObject]]::new()
    $currentUri = $Uri
    
    do {
        $retryCount = 0
        $success = $false
        
        while (-not $success -and $retryCount -le $MaxRetries) {
            try {
                $headers = @{ "ConsistencyLevel" = "eventual" }
                $response = Invoke-MgGraphRequest -Uri $currentUri -Method Get -OutputType PSObject -Headers $headers -ErrorAction Stop
                $success = $true
                
                if (Get-Member -InputObject $response -Name 'value' -MemberType Properties) {
                    $allResults.AddRange([System.Collections.Generic.List[PSObject]]$response.value)
                } else {
                    $allResults.Add($response)
                }
                
                if ($response.'@odata.nextLink') {
                    $currentUri = $response.'@odata.nextLink'
                } else {
                    $currentUri = $null
                }
            }
            catch {
                $retryCount++
                
                if ($_.Exception.Message -match "429" -or $_.Exception.Message -match "Too Many Requests") {
                    if ($retryCount -le $MaxRetries) {
                        $waitTime = $RetryDelay * [Math]::Pow(2, $retryCount - 1)
                        Write-Host "Rate limited. Waiting $waitTime seconds before retry..." -ForegroundColor Yellow
                        Start-Sleep -Seconds $waitTime
                    } else {
                        Write-Warning "Max retries reached for URI: $currentUri"
                        throw
                    }
                } else {
                    Write-Warning "Error calling Graph API: $($_.Exception.Message)"
                    throw
                }
            }
        }
    } while ($currentUri)
    
    return $allResults
}

function Get-IntunePoliciesByType {
    <#
    .SYNOPSIS
        Retrieves all Intune policies for a specific policy type.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyType,
        
        [Parameter(Mandatory = $true)]
        [string]$Endpoint,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeAssignments
    )
    
    try {
        Write-Host "Retrieving $PolicyType..." -ForegroundColor Cyan
        
        $uri = $Endpoint
        if ($IncludeAssignments) {
            if ($uri -like "*?*") {
                $uri += "&`$expand=assignments"
            } else {
                $uri += "?`$expand=assignments"
            }
        }
        
        $policies = Invoke-MSGraphRequestWithPagination -Uri $uri
        
        Write-Host "Found $($policies.Count) $PolicyType" -ForegroundColor Green
        
        return $policies
    }
    catch {
        Write-Warning "Failed to retrieve $PolicyType : $($_.Exception.Message)"
        return @()
    }
}

function Get-PolicyAssignments {
    <#
    .SYNOPSIS
        Retrieves assignment details for a specific policy with retry logic for large tenants.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $true)]
        [string]$PolicyType,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 5,
        
        [Parameter(Mandatory = $false)]
        [int]$RetryDelay = 3
    )
    
    $assignmentUri = switch ($PolicyType) {
        "ConfigurationPolicies" { "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$PolicyId')/assignments" }
        "DeviceConfigurations" { "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$PolicyId')/assignments" }
        "GroupPolicyConfigurations" { "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$PolicyId')/assignments" }
        "CompliancePolicies" { "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$PolicyId')/assignments" }
        "PowerShellScripts" { "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts('$PolicyId')/assignments" }
        "RemediationScripts" { "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts('$PolicyId')/assignments" }
        "MobileApps" { "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$PolicyId')/assignments" }
        "AutopilotProfiles" { "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles('$PolicyId')/assignments" }
        "EnrollmentStatusPage" { "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations('$PolicyId')/assignments" }
        "FeatureUpdatePolicies" { "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles('$PolicyId')/assignments" }
        "EndpointSecurityPolicies" { "https://graph.microsoft.com/beta/deviceManagement/intents('$PolicyId')/assignments" }
        default { $null }
    }
    
    if (-not $assignmentUri) {
        return @()
    }
    
    $retryCount = 0
    $lastError = $null
    
    while ($retryCount -le $MaxRetries) {
        try {
            $assignments = Invoke-MSGraphRequestWithPagination -Uri $assignmentUri
            return $assignments
        }
        catch {
            $lastError = $_
            $errorMessage = $_.Exception.Message
            
            # Check if it's a retriable error
            if ($errorMessage -match "InternalServerError|ServiceUnavailable|TooManyRequests|429|500|503") {
                $retryCount++
                
                if ($retryCount -le $MaxRetries) {
                    $waitTime = $RetryDelay * [Math]::Pow(2, $retryCount - 1)
                    Write-Verbose "Assignment retrieval failed for policy $PolicyId (attempt $retryCount/$MaxRetries). Retrying in $waitTime seconds..."
                    Start-Sleep -Seconds $waitTime
                } else {
                    Write-Warning "Failed to retrieve assignments for policy $PolicyId after $MaxRetries retries. Skipping this policy's assignments."
                    return @()
                }
            }
            else {
                # Non-retriable error (e.g., NotFound, Forbidden)
                Write-Verbose "Could not retrieve assignments for policy $PolicyId : $errorMessage"
                return @()
            }
        }
    }
    
    # If we get here, all retries failed
    Write-Warning "Failed to retrieve assignments for policy $PolicyId after $MaxRetries retries."
    return @()
}

function Resolve-AssignmentTargets {
    <#
    .SYNOPSIS
        Resolves group and filter names from assignment targets.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$Assignments,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$GroupCache,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$FilterCache
    )
    
    $resolvedAssignments = [System.Collections.Generic.List[PSObject]]::new()
    
    foreach ($assignment in $Assignments) {
        $targetInfo = [PSCustomObject]@{
            TargetType = "Unknown"
            TargetName = "Unknown"
            FilterId = $null
            FilterName = $null
            FilterType = $null
        }
        
        $target = $assignment.target
        
        if ($target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
            $targetInfo.TargetType = "All Devices"
            $targetInfo.TargetName = "All Devices"
        }
        elseif ($target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
            $targetInfo.TargetType = "All Users"
            $targetInfo.TargetName = "All Users"
        }
        elseif ($target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
            $targetInfo.TargetType = "Group (Include)"
            if ($GroupCache -and $GroupCache.ContainsKey($target.groupId)) {
                $targetInfo.TargetName = $GroupCache[$target.groupId]
            } else {
                $targetInfo.TargetName = "[Group ID: $($target.groupId)]"
            }
        }
        elseif ($target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
            $targetInfo.TargetType = "Group (Exclude)"
            if ($GroupCache -and $GroupCache.ContainsKey($target.groupId)) {
                $targetInfo.TargetName = $GroupCache[$target.groupId]
            } else {
                $targetInfo.TargetName = "[Group ID: $($target.groupId)]"
            }
        }
        
        # Handle assignment filters
        if ($target.deviceAndAppManagementAssignmentFilterId) {
            $targetInfo.FilterId = $target.deviceAndAppManagementAssignmentFilterId
            $targetInfo.FilterType = $target.deviceAndAppManagementAssignmentFilterType
            
            if ($FilterCache.ContainsKey($targetInfo.FilterId)) {
                $targetInfo.FilterName = $FilterCache[$targetInfo.FilterId]
            }
        }
        
        $resolvedAssignments.Add($targetInfo)
    }
    
    return $resolvedAssignments
}

function Get-GroupsByIds {
    <#
    .SYNOPSIS
        Retrieves specific groups by IDs using batched $filter queries for optimal performance.
        This is much faster than retrieving all groups when you have 350K+ groups.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$GroupIds
    )
    
    if ($GroupIds.Count -eq 0) {
        return @{}
    }
    
    Write-Host "Retrieving $($GroupIds.Count) specific groups using batched queries..." -ForegroundColor Cyan
    
    try {
        $groupCache = @{}
        $uniqueGroupIds = $GroupIds | Select-Object -Unique
        $batchSize = 15  # Microsoft Graph $filter 'or' limit per query
        $totalBatches = [Math]::Ceiling($uniqueGroupIds.Count / $batchSize)
        $batchCount = 0
        
        for ($i = 0; $i -lt $uniqueGroupIds.Count; $i += $batchSize) {
            $batchCount++
            Write-Progress -Activity "Retrieving Group Names" -Status "Processing batch $batchCount of $totalBatches" -PercentComplete (($batchCount / $totalBatches) * 100)
            
            $batch = $uniqueGroupIds[$i..[Math]::Min($i + $batchSize - 1, $uniqueGroupIds.Count - 1)]
            
            # Build $filter query with 'or' conditions
            $filterParts = [System.Collections.Generic.List[string]]::new()
            foreach ($groupId in $batch) {
                $filterParts.Add("id eq '$groupId'")
            }
            $filterQuery = $filterParts -join ' or '
            
            $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=$filterQuery&`$select=id,displayName"
            
            try {
                $batchGroups = Invoke-MSGraphRequestWithPagination -Uri $uri
                
                foreach ($group in $batchGroups) {
                    $groupCache[$group.id] = $group.displayName
                }
            }
            catch {
                Write-Verbose "Failed to retrieve batch: $($_.Exception.Message)"
                # Continue with other batches
            }
        }
        
        Write-Progress -Activity "Retrieving Group Names" -Completed
        Write-Host "Successfully resolved $($groupCache.Count) out of $($uniqueGroupIds.Count) groups" -ForegroundColor Green
        
        return $groupCache
    }
    catch {
        Write-Warning "Failed to retrieve groups: $($_.Exception.Message)"
        return @{}
    }
}

function Get-GroupIdsFromAssignments {
    <#
    .SYNOPSIS
        Extracts all unique group IDs from policy assignments.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$AllPolicies
    )
    
    $groupIds = [System.Collections.Generic.HashSet[string]]::new()
    
    foreach ($policy in $AllPolicies) {
        if ($policy.Assignments) {
            foreach ($assignment in $policy.Assignments) {
                $target = $assignment.target
                
                if ($target.groupId) {
                    [void]$groupIds.Add($target.groupId)
                }
            }
        }
    }
    
    return @($groupIds)
}

function Get-AllAssignmentFilters {
    <#
    .SYNOPSIS
        Retrieves all assignment filters and creates a cache for quick lookup.
    #>
    param()
    
    Write-Host "Retrieving assignment filters..." -ForegroundColor Cyan
    
    try {
        $filterCache = @{}
        $uri = "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters?`$select=id,displayName,platform,rule"
        $filters = Invoke-MSGraphRequestWithPagination -Uri $uri
        
        foreach ($filter in $filters) {
            $filterCache[$filter.id] = "$($filter.displayName) ($($filter.platform))"
        }
        
        Write-Host "Cached $($filterCache.Count) assignment filters" -ForegroundColor Green
        return $filterCache
    }
    catch {
        Write-Warning "Failed to retrieve assignment filters: $($_.Exception.Message)"
        return @{}
    }
}

function Get-PolicySettings {
    <#
    .SYNOPSIS
        Retrieves policy settings from Graph API and returns them as an HTML string for embedding in the report.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $true)]
        [string]$PolicyType
    )
    
    $metadataProps = @('@odata.type','id','createdDateTime','lastModifiedDateTime',
                       'version','supportsScopeTags','roleScopeTagIds','description',
                       'displayName','name')
    
    $rows = [System.Collections.Generic.List[string]]::new()
    
    function Add-Row {
        param($Name, $Value)
        $rows.Add("<tr><td>$([System.Net.WebUtility]::HtmlEncode($Name))</td><td>$([System.Net.WebUtility]::HtmlEncode(`"$Value`"))</td></tr>")
    }
    
    try {
        switch ($PolicyType) {
            "ConfigurationPolicies" {
                $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$PolicyId')/settings"
                $settings = Invoke-MSGraphRequestWithPagination -Uri $uri
                foreach ($s in $settings) {
                    $si = $s.settingInstance
                    if (-not $si) { continue }
                    $defId = ($si.settingDefinitionId -split '_')[-1]
                    $value = if ($si.simpleSettingValue)             { $si.simpleSettingValue.value }
                             elseif ($si.choiceSettingValue)          { ($si.choiceSettingValue.value -split '_')[-1] }
                             elseif ($si.groupSettingCollectionValue) { "Group collection ($($si.groupSettingCollectionValue.Count) items)" }
                             else                                     { ($si.'@odata.type' -replace '#microsoft.graph.', '') }
                    Add-Row $defId $value
                }
            }
            "EndpointSecurityPolicies" {
                $uri = "https://graph.microsoft.com/beta/deviceManagement/intents('$PolicyId')/settings"
                $settings = Invoke-MSGraphRequestWithPagination -Uri $uri
                foreach ($s in $settings) {
                    Add-Row (($s.definitionId -split '_')[-1]) $s.valueJson
                }
            }
            "GroupPolicyConfigurations" {
                $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$PolicyId')/definitionValues?`$expand=definition"
                $settings = Invoke-MSGraphRequestWithPagination -Uri $uri
                foreach ($s in $settings) {
                    $name  = if ($s.definition) { $s.definition.displayName } else { $s.id }
                    $state = if ($s.enabled) { "Enabled" } else { "Disabled" }
                    Add-Row $name $state
                }
            }
            "PowerShellScripts" {
                $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$PolicyId"
                $obj  = Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject
                Add-Row "Run As Account"         $obj.runAsAccount
                Add-Row "Enforce Signature Check" $obj.enforceSignatureCheck
                Add-Row "Run As 32 Bit"           $obj.runAs32Bit
                if ($obj.scriptContent) {
                    $preview = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($obj.scriptContent))
                    $preview = ($preview -split "`n" | Select-Object -First 15) -join "`n"
                    $rows.Add("<tr><td colspan='2'><strong>Script Preview (first 15 lines):</strong><br><pre class='script-preview'>$([System.Net.WebUtility]::HtmlEncode($preview))</pre></td></tr>")
                }
            }
            "RemediationScripts" {
                $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$PolicyId"
                $obj  = Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject
                Add-Row "Run As Account"          $obj.runAsAccount
                Add-Row "Enforce Signature Check" $obj.enforceSignatureCheck
                Add-Row "Run As 32 Bit"           $obj.runAs32Bit
                if ($obj.detectionScriptContent) {
                    $preview = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($obj.detectionScriptContent))
                    $preview = ($preview -split "`n" | Select-Object -First 10) -join "`n"
                    $rows.Add("<tr><td colspan='2'><strong>Detection Script (first 10 lines):</strong><br><pre class='script-preview'>$([System.Net.WebUtility]::HtmlEncode($preview))</pre></td></tr>")
                }
                if ($obj.remediationScriptContent) {
                    $preview = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($obj.remediationScriptContent))
                    $preview = ($preview -split "`n" | Select-Object -First 10) -join "`n"
                    $rows.Add("<tr><td colspan='2'><strong>Remediation Script (first 10 lines):</strong><br><pre class='script-preview'>$([System.Net.WebUtility]::HtmlEncode($preview))</pre></td></tr>")
                }
            }
            default {
                $endpointMap = @{
                    "DeviceConfigurations"  = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$PolicyId"
                    "CompliancePolicies"    = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$PolicyId"
                    "MobileApps"            = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$PolicyId"
                    "AutopilotProfiles"     = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles/$PolicyId"
                    "EnrollmentStatusPage"  = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/$PolicyId"
                    "FeatureUpdatePolicies" = "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles/$PolicyId"
                }
                if ($endpointMap.ContainsKey($PolicyType)) {
                    $obj = Invoke-MgGraphRequest -Uri $endpointMap[$PolicyType] -Method Get -OutputType PSObject
                    $obj.PSObject.Properties | Where-Object { $_.Name -notin $metadataProps -and $null -ne $_.Value -and $_.Value -ne '' } | ForEach-Object {
                        $val = if ($_.Value -is [System.Collections.IEnumerable] -and $_.Value -isnot [string]) {
                            $_.Value | ConvertTo-Json -Compress -Depth 2
                        } else { "$($_.Value)" }
                        Add-Row $_.Name $val
                    }
                }
            }
        }
    }
    catch {
        Write-Verbose "Could not retrieve settings for $PolicyType '$PolicyId': $($_.Exception.Message)"
        $rows.Add("<tr><td colspan='2' style='color:#ff5252'>Could not retrieve settings: $([System.Net.WebUtility]::HtmlEncode($_.Exception.Message))</td></tr>")
    }
    
    if ($rows.Count -eq 0) { return "" }
    
    return "<table class='settings-table'><thead><tr><th>Setting</th><th>Value</th></tr></thead><tbody>$($rows -join '')</tbody></table>"
}

function Compare-PolicyStates {
    <#
    .SYNOPSIS
        Compares current policy state with previous baseline to detect changes.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$CurrentPolicies,
        
        [Parameter(Mandatory = $true)]
        [array]$BaselinePolicies
    )
    
    $changes = @{
        New = [System.Collections.Generic.List[PSObject]]::new()
        Modified = [System.Collections.Generic.List[PSObject]]::new()
        Deleted = [System.Collections.Generic.List[PSObject]]::new()
        AssignmentChanged = [System.Collections.Generic.List[PSObject]]::new()
        ChangeDetails = @{}  # Stores detailed change info by policy ID
    }
    
    # Create baseline lookup
    $baselineHash = @{}
    foreach ($policy in $BaselinePolicies) {
        $baselineHash[$policy.Id] = $policy
    }
    
    # Find new and modified policies
    foreach ($currentPolicy in $CurrentPolicies) {
        if (-not $baselineHash.ContainsKey($currentPolicy.Id)) {
            $changes.New.Add($currentPolicy)
            $changes.ChangeDetails[$currentPolicy.Id] = @{ ChangeType = "New"; Details = "Policy was newly created" }
        }
        else {
            $baselinePolicy = $baselineHash[$currentPolicy.Id]
            $changeDetailsList = [System.Collections.Generic.List[string]]::new()
            
            # Check if modified - Compare datetime values properly by parsing them
            $currentModified = $null
            $baselineModified = $null
            
            # Try to parse both datetimes
            if ($currentPolicy.LastModifiedDateTime) {
                try {
                    $currentModified = [datetime]::Parse($currentPolicy.LastModifiedDateTime).ToUniversalTime()
                } catch {
                    $currentModified = $currentPolicy.LastModifiedDateTime
                }
            }
            
            if ($baselinePolicy.LastModifiedDateTime) {
                try {
                    $baselineModified = [datetime]::Parse($baselinePolicy.LastModifiedDateTime).ToUniversalTime()
                } catch {
                    $baselineModified = $baselinePolicy.LastModifiedDateTime
                }
            }
            
            # Compare - only flag as modified if difference is more than 1 second (to account for serialization differences)
            $isModified = $false
            if ($currentModified -is [datetime] -and $baselineModified -is [datetime]) {
                $timeDiff = [Math]::Abs(($currentModified - $baselineModified).TotalSeconds)
                if ($timeDiff -gt 1) {
                    $isModified = $true
                    $changeDetailsList.Add("Settings modified (Last modified: $($currentModified.ToString('yyyy-MM-dd HH:mm:ss')) UTC)")
                }
            } elseif ($currentModified -ne $baselineModified) {
                $isModified = $true
                $changeDetailsList.Add("Settings modified")
            }
            
            # Check if assignments changed - compare actual assignment count
            $currentAssignmentCount = if ($currentPolicy.Assignments -and $currentPolicy.Assignments.Count) { $currentPolicy.Assignments.Count } else { 0 }
            $baselineAssignmentCount = if ($baselinePolicy.Assignments -and $baselinePolicy.Assignments.Count) { $baselinePolicy.Assignments.Count } else { 0 }
            
            if ($currentAssignmentCount -ne $baselineAssignmentCount) {
                $changes.AssignmentChanged.Add($currentPolicy)
                $changeDetailsList.Add("Assignments changed ($baselineAssignmentCount → $currentAssignmentCount assignments)")
            }
            
            # Add to modified list if settings changed
            if ($isModified) {
                $changes.Modified.Add($currentPolicy)
            }
            
            # Store change details if any changes detected
            if ($changeDetailsList.Count -gt 0) {
                $changes.ChangeDetails[$currentPolicy.Id] = @{
                    ChangeType = if ($isModified) { "Modified" } else { "Assignment Changed" }
                    Details = $changeDetailsList -join "; "
                }
            }
        }
    }
    
    # Find deleted policies
    $currentHash = @{}
    foreach ($policy in $CurrentPolicies) {
        $currentHash[$policy.Id] = $policy
    }
    
    foreach ($baselinePolicy in $BaselinePolicies) {
        if (-not $currentHash.ContainsKey($baselinePolicy.Id)) {
            $changes.Deleted.Add($baselinePolicy)
        }
    }
    
    return $changes
}

function New-HTMLReport {
    <#
    .SYNOPSIS
        Generates an interactive HTML report with modern UI.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$AllPolicies,
        
        [Parameter(Mandatory = $true)]
        [array]$UnassignedPolicies,
        
        [Parameter(Mandatory = $true)]
        [array]$AssignedPolicies,
        
        [Parameter(Mandatory = $true)]
        [array]$DeprecatedTestPolicies,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Changes,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [datetime]$ReportDate,
        
        [Parameter(Mandatory = $false)]
        [switch]$ShowSettings
    )
    
    $changesSummary = ""
    if ($Changes) {
        $changesSummary = @"
        <div class="stat-card">
            <h3>Changes Detected</h3>
            <div class="stat-number change-summary">
                <span class="badge-new filter-badge" onclick="filterByChange('New')" title="Click to show only new policies">$($Changes.New.Count) New</span>
                <span class="badge-modified filter-badge" onclick="filterByChange('Modified')" title="Click to show only modified policies">$($Changes.Modified.Count) Modified</span>
                <span class="badge-deleted filter-badge" onclick="filterByChange('Deleted')" title="Click to show only deleted policies">$($Changes.Deleted.Count) Deleted</span>
                <span class="badge-assignment filter-badge" onclick="filterByChange('Assignment Changed')" title="Click to show only policies with assignment changes">$($Changes.AssignmentChanged.Count) Assignment Changed</span>
            </div>
            <div style="margin-top: 15px; text-align: center;">
                <button class="clear-filter-btn" onclick="clearChangeFilter()" style="display: none;">Clear Filter</button>
            </div>
        </div>
"@
    }
    
    # Generate table rows for each category
    $unassignedRows = ($UnassignedPolicies | ForEach-Object {
        $changeStatus = ""
        if ($Changes) {
            if ($_.Id -in $Changes.New.Id) { 
                $changeStatus = '<span class="badge-new">New</span>' 
            }
            elseif ($_.Id -in $Changes.Modified.Id) { 
                $tooltip = ""
                if ($Changes.ChangeDetails.ContainsKey($_.Id)) {
                    $details = $Changes.ChangeDetails[$_.Id].Details -replace '"', '&quot;'
                    $tooltip = " title=`"$details`" class=`"has-tooltip`""
                }
                $changeStatus = "<span class=`"badge-modified`"$tooltip>Modified</span>" 
            }
        }
        
        $settingsAttr = ""
        $settingsBtn  = ""
        if ($ShowSettings -and $_.SettingsHtml) {
            $settingsEscaped = $_.SettingsHtml -replace '"', '&quot;'
            $settingsAttr    = " data-settings=`"$settingsEscaped`""
            $settingsBtn     = "<button class='settings-btn' onclick='toggleSettings(this)' title='Expand/collapse settings'>&#9654; Details</button>"
        }
        
        @"
        <tr$settingsAttr>
            <td>$($_.PolicyType)</td>
            <td><span class="policy-name-cell">$($_.Name -replace '"', '&quot;')<button class="copy-btn" data-name="$($_.Name -replace '"', '&quot;')" onclick="copyToClipboard(this)" title="Copy policy name to clipboard">&#x2398; Copy</button>$settingsBtn</span></td>
            <td>$($_.LastModified)</td>
            <td class="no-assignments">Not Assigned</td>
            <td>$changeStatus</td>
        </tr>
"@
    }) -join "`n"
    
    $assignedRows = ($AssignedPolicies | ForEach-Object {
        $assignmentText = if ($_.ResolvedAssignments) {
            ($_.ResolvedAssignments | ForEach-Object {
                $filterText = if ($_.FilterName) { " [Filter: $($_.FilterName)]" } else { "" }
                "$($_.TargetType): $($_.TargetName)$filterText"
            }) -join "<br>"
        } else {
            "Unknown"
        }
        
        $changeStatus = ""
        if ($Changes) {
            if ($_.Id -in $Changes.New.Id) { 
                $changeStatus = '<span class="badge-new">New</span>' 
            }
            elseif ($_.Id -in $Changes.Modified.Id) { 
                $tooltip = ""
                if ($Changes.ChangeDetails.ContainsKey($_.Id)) {
                    $details = $Changes.ChangeDetails[$_.Id].Details -replace '"', '&quot;'
                    $tooltip = " title=`"$details`" class=`"has-tooltip`""
                }
                $changeStatus = "<span class=`"badge-modified`"$tooltip>Modified</span>" 
            }
            elseif ($_.Id -in $Changes.AssignmentChanged.Id) { 
                $tooltip = ""
                if ($Changes.ChangeDetails.ContainsKey($_.Id)) {
                    $details = $Changes.ChangeDetails[$_.Id].Details -replace '"', '&quot;'
                    $tooltip = " title=`"$details`" class=`"has-tooltip`""
                }
                $changeStatus = "<span class=`"badge-assignment`"$tooltip>Assignment Changed</span>" 
            }
        }
        
        $settingsAttr = ""
        $settingsBtn  = ""
        if ($ShowSettings -and $_.SettingsHtml) {
            $settingsEscaped = $_.SettingsHtml -replace '"', '&quot;'
            $settingsAttr    = " data-settings=`"$settingsEscaped`""
            $settingsBtn     = "<button class='settings-btn' onclick='toggleSettings(this)' title='Expand/collapse settings'>&#9654; Details</button>"
        }
        
        @"
        <tr$settingsAttr>
            <td>$($_.PolicyType)</td>
            <td><span class="policy-name-cell">$($_.Name -replace '"', '&quot;')<button class="copy-btn" data-name="$($_.Name -replace '"', '&quot;')" onclick="copyToClipboard(this)" title="Copy policy name to clipboard">&#x2398; Copy</button>$settingsBtn</span></td>
            <td>$($_.LastModified)</td>
            <td class="assignment-details">$assignmentText</td>
            <td>$changeStatus</td>
        </tr>
"@
    }) -join "`n"
    
    $deprecatedRows = ($DeprecatedTestPolicies | ForEach-Object {
        $assignmentText = if ($_.ResolvedAssignments) {
            ($_.ResolvedAssignments | ForEach-Object {
                $filterText = if ($_.FilterName) { " [Filter: $($_.FilterName)]" } else { "" }
                "$($_.TargetType): $($_.TargetName)$filterText"
            }) -join "<br>"
        } else {
            "Not Assigned"
        }
        
        $changeStatus = ""
        if ($Changes) {
            if ($_.Id -in $Changes.New.Id) { 
                $changeStatus = '<span class="badge-new">New</span>' 
            }
            elseif ($_.Id -in $Changes.Modified.Id) { 
                $tooltip = ""
                if ($Changes.ChangeDetails.ContainsKey($_.Id)) {
                    $details = $Changes.ChangeDetails[$_.Id].Details -replace '"', '&quot;'
                    $tooltip = " title=`"$details`" class=`"has-tooltip`""
                }
                $changeStatus = "<span class=`"badge-modified`"$tooltip>Modified</span>" 
            }
        }
        
        $settingsAttr = ""
        $settingsBtn  = ""
        if ($ShowSettings -and $_.SettingsHtml) {
            $settingsEscaped = $_.SettingsHtml -replace '"', '&quot;'
            $settingsAttr    = " data-settings=`"$settingsEscaped`""
            $settingsBtn     = "<button class='settings-btn' onclick='toggleSettings(this)' title='Expand/collapse settings'>&#9654; Details</button>"
        }
        
        @"
        <tr$settingsAttr>
            <td>$($_.PolicyType)</td>
            <td class="deprecated-name"><span class="policy-name-cell">$($_.Name -replace '"', '&quot;')<button class="copy-btn" data-name="$($_.Name -replace '"', '&quot;')" onclick="copyToClipboard(this)" title="Copy policy name to clipboard">&#x2398; Copy</button>$settingsBtn</span></td>
            <td>$($_.LastModified)</td>
            <td class="assignment-details">$assignmentText</td>
            <td>$changeStatus</td>
        </tr>
"@
    }) -join "`n"
    
    # Generate unique policy types for filter dropdown
    $uniquePolicyTypes = ($AllPolicies | Select-Object -ExpandProperty PolicyType -Unique | Sort-Object)
    $policyTypeOptions = ($uniquePolicyTypes | ForEach-Object {
        "<option value='$_'>$_</option>"
    }) -join "`n                    "
    
    $deletedRows = ""
    if ($Changes -and $Changes.Deleted.Count -gt 0) {
        $deletedRows = ($Changes.Deleted | ForEach-Object {
            @"
        <tr class="deleted-row">
            <td>$($_.PolicyType)</td>
            <td><span class="policy-name-cell">$($_.Name -replace '"', '&quot;')<button class="copy-btn" data-name="$($_.Name -replace '"', '&quot;')" onclick="copyToClipboard(this)" title="Copy policy name to clipboard">&#x2398; Copy</button></span></td>
            <td>$($_.LastModified)</td>
            <td>N/A</td>
            <td><span class="badge-deleted">Deleted</span></td>
        </tr>
"@
        }) -join "`n"
    }
    
    $deletedSection = ""
    if ($Changes -and $Changes.Deleted.Count -gt 0) {
        $deletedSection = @"
        <div class="tab-content" id="deleted">
            <h2>Deleted Policies Since Last Report ($($Changes.Deleted.Count))</h2>
            <p class="section-description">Policies that were present in the baseline report but are now deleted.</p>
            <table id="deletedTable">
                <thead>
                    <tr>
                        <th>Policy Type</th>
                        <th>Policy Name</th>
                        <th>Last Modified (Baseline)</th>
                        <th>Assignments (Baseline)</th>
                        <th>Change Status</th>
                    </tr>
                </thead>
                <tbody>
                    $deletedRows
                </tbody>
            </table>
        </div>
"@
    }
    
    $deletedTabButton = ""
    if ($Changes -and $Changes.Deleted.Count -gt 0) {
        $deletedTabButton = @"
            <button class="tab-button" onclick="openTab(event, 'deleted')">
                Deleted Policies <span class="badge-count">$($Changes.Deleted.Count)</span>
            </button>
"@
    }
    
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intune Policy Review - $($ReportDate.ToString("yyyy-MM-dd HH:mm:ss"))</title>
    
    <!-- External Libraries -->
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #121212;
            color: #e0e0e0;
            padding: 20px;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
        }
        
        header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }
        
        h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            color: #ffffff;
        }
        
        .subtitle {
            font-size: 1.1em;
            color: #b0b0b0;
            margin-bottom: 5px;
        }
        
        .report-date {
            font-size: 0.95em;
            color: #909090;
            font-style: italic;
        }
        
        .stats-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background-color: #1e1e1e;
            padding: 25px;
            border-radius: 10px;
            border-left: 4px solid #00bcd4;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }
        
        .stat-card h3 {
            font-size: 1em;
            color: #b0b0b0;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #00bcd4;
        }
        
        .change-summary {
            display: flex;
            flex-direction: column;
            gap: 8px;
            font-size: 1em;
        }
        
        /* Filter Controls */
        .filter-controls {
            background-color: #1e1e1e;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            display: flex;
            gap: 20px;
            align-items: flex-end;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
            flex-wrap: wrap;
        }
        
        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 8px;
            flex: 1;
            min-width: 200px;
        }
        
        .filter-group label {
            color: #b0b0b0;
            font-size: 0.9em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .filter-group select {
            background-color: #2a2a2a;
            border: 2px solid #444;
            color: #e0e0e0;
            padding: 10px 15px;
            border-radius: 6px;
            font-size: 1em;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .filter-group select:hover {
            border-color: #00bcd4;
        }
        
        .filter-group select:focus {
            outline: none;
            border-color: #00bcd4;
            box-shadow: 0 0 0 3px rgba(0, 188, 212, 0.2);
        }
        
        .clear-all-filters-btn {
            background-color: #ff5252;
            color: #ffffff;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.95em;
            font-weight: bold;
            transition: all 0.3s;
            height: fit-content;
        }
        
        .clear-all-filters-btn:hover {
            background-color: #ff1744;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(255, 82, 82, 0.4);
        }
        
        .tab-container {
            background-color: #1e1e1e;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }
        
        .tab-buttons {
            display: flex;
            background-color: #252525;
            border-bottom: 2px solid #333;
        }
        
        .tab-button {
            flex: 1;
            padding: 15px 20px;
            background-color: transparent;
            border: none;
            color: #b0b0b0;
            font-size: 1em;
            cursor: pointer;
            transition: all 0.3s ease;
            border-bottom: 3px solid transparent;
        }
        
        .tab-button:hover {
            background-color: #2a2a2a;
            color: #ffffff;
        }
        
        .tab-button.active {
            background-color: #1e1e1e;
            color: #00bcd4;
            border-bottom-color: #00bcd4;
        }
        
        .badge-count {
            display: inline-block;
            background-color: #00bcd4;
            color: #121212;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            margin-left: 8px;
        }
        
        .tab-content {
            display: none;
            padding: 30px;
        }
        
        .tab-content.active {
            display: block;
        }
        
        h2 {
            color: #00bcd4;
            margin-bottom: 15px;
            font-size: 1.8em;
        }
        
        .section-description {
            color: #909090;
            margin-bottom: 20px;
            font-size: 1.05em;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background-color: #252525;
            border-radius: 8px;
            overflow: hidden;
        }
        
        thead {
            background-color: #00bcd4;
            color: #121212;
        }
        
        th {
            padding: 15px;
            text-align: left;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 0.5px;
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #333;
        }
        
        tr:hover {
            background-color: #2a2a2a;
        }
        
        .no-assignments {
            color: #ff5252;
            font-weight: bold;
        }
        
        .assignment-details {
            font-size: 0.9em;
            line-height: 1.8;
        }
        
        .deprecated-name {
            color: #ffa500;
            font-weight: bold;
        }

        .policy-name-cell {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .copy-btn {
            background: none;
            border: 1px solid #555;
            border-radius: 3px;
            color: #aaa;
            cursor: pointer;
            font-size: 0.8em;
            padding: 1px 5px;
            opacity: 0;
            transition: opacity 0.15s, color 0.15s, border-color 0.15s;
            flex-shrink: 0;
            line-height: 1.4;
        }

        tr:hover .copy-btn {
            opacity: 1;
        }

        .copy-btn:hover {
            color: #ffffff;
            border-color: #7c4dff;
        }

        .copy-btn.copied {
            color: #00e676;
            border-color: #00e676;
        }

        /* Settings child row */
        .settings-child {
            padding: 15px 20px;
            background-color: #1a1a2e;
            border-top: 1px solid #00bcd4;
        }

        .settings-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9em;
        }

        .settings-table th {
            background-color: #263238;
            color: #80cbc4;
            padding: 8px 12px;
            text-align: left;
            font-size: 0.85em;
        }

        .settings-table td {
            padding: 6px 12px;
            border-bottom: 1px solid #2a2a2a;
            color: #cfd8dc;
            vertical-align: top;
        }

        .settings-table tr:hover td {
            background-color: #22303c;
        }

        .script-preview {
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.85em;
            background-color: #0d1117;
            color: #c9d1d9;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            white-space: pre;
            margin-top: 6px;
            border: 1px solid #30363d;
        }

        .settings-btn {
            background: none;
            border: 1px solid #00bcd4;
            border-radius: 3px;
            color: #00bcd4;
            cursor: pointer;
            font-size: 0.8em;
            padding: 1px 6px;
            transition: background-color 0.15s, color 0.15s;
            flex-shrink: 0;
            line-height: 1.4;
        }

        .settings-btn:hover {
            background-color: #00bcd4;
            color: #121212;
        }
        
        .deleted-row {
            background-color: #2a1a1a;
            opacity: 0.7;
        }
        
        /* Badge Styles */
        .badge-new {
            display: inline-block;
            background-color: #00e676;
            color: #121212;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            margin: 2px;
        }
        
        .badge-modified {
            display: inline-block;
            background-color: #ffc107;
            color: #121212;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            margin: 2px;
        }
        
        .badge-deleted {
            display: inline-block;
            background-color: #ff5252;
            color: #ffffff;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            margin: 2px;
        }
        
        .badge-assignment {
            display: inline-block;
            background-color: #2196f3;
            color: #ffffff;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            margin: 2px;
        }
        
        /* Clickable filter badges */
        .filter-badge {
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .filter-badge:hover {
            transform: scale(1.05);
            box-shadow: 0 4px 8px rgba(0, 188, 212, 0.4);
        }
        
        .filter-badge:active {
            transform: scale(0.95);
        }
        
        .filter-badge.active-filter {
            box-shadow: 0 0 10px 2px rgba(0, 188, 212, 0.8);
            border: 2px solid #ffffff;
        }
        
        .clear-filter-btn {
            background-color: #ff5252;
            color: #ffffff;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9em;
            font-weight: bold;
            transition: background-color 0.3s;
        }
        
        .clear-filter-btn:hover {
            background-color: #ff1744;
        }
        
        tr.filtered-out {
            display: none !important;
        }
        
        /* Tooltips for change details */
        .has-tooltip {
            position: relative;
            cursor: help;
        }
        
        .has-tooltip:hover::after {
            content: attr(title);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background-color: #1e1e1e;
            color: #ffffff;
            padding: 8px 12px;
            border-radius: 6px;
            white-space: nowrap;
            z-index: 1000;
            font-size: 0.85em;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
            border: 1px solid #00bcd4;
            margin-bottom: 5px;
            max-width: 400px;
            white-space: normal;
        }
        
        .has-tooltip:hover::before {
            content: '';
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            border: 6px solid transparent;
            border-top-color: #00bcd4;
            z-index: 1000;
        }
        
        /* DataTables Dark Theme Overrides */
        .dataTables_wrapper .dataTables_filter input {
            background-color: #2a2a2a;
            border: 1px solid #444;
            color: #e0e0e0;
            padding: 5px 10px;
            border-radius: 4px;
        }
        
        .dataTables_wrapper .dataTables_length select {
            background-color: #2a2a2a;
            border: 1px solid #444;
            color: #e0e0e0;
            padding: 5px;
            border-radius: 4px;
        }
        
        .dataTables_wrapper .dataTables_info,
        .dataTables_wrapper .dataTables_paginate {
            color: #b0b0b0;
        }
        
        .dataTables_wrapper .dataTables_paginate .paginate_button {
            color: #00bcd4 !important;
            background: transparent;
            border: 1px solid #444;
        }
        
        .dataTables_wrapper .dataTables_paginate .paginate_button:hover {
            color: #ffffff !important;
            background: #2a2a2a;
            border: 1px solid #00bcd4;
        }
        
        .dataTables_wrapper .dataTables_paginate .paginate_button.current {
            color: #121212 !important;
            background: #00bcd4;
            border: 1px solid #00bcd4;
        }
        
        footer {
            margin-top: 40px;
            padding: 20px;
            text-align: center;
            color: #707070;
            font-size: 0.9em;
            border-top: 1px solid #333;
        }
        
        @media (max-width: 768px) {
            .stats-container {
                grid-template-columns: 1fr;
            }
            
            .tab-buttons {
                flex-direction: column;
            }
            
            h1 {
                font-size: 1.8em;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Intune Policy Review Dashboard</h1>
            <div class="subtitle">Configuration analysis and assignment status report</div>
            <div class="report-date">Generated: $($ReportDate.ToString("yyyy-MM-dd HH:mm:ss"))</div>
        </header>
        
        <div class="stats-container">
            <div class="stat-card">
                <h3>Total Policies</h3>
                <div class="stat-number">$($AllPolicies.Count)</div>
            </div>
            <div class="stat-card">
                <h3>Unassigned Policies</h3>
                <div class="stat-number">$($UnassignedPolicies.Count)</div>
            </div>
            <div class="stat-card">
                <h3>Assigned Policies</h3>
                <div class="stat-number">$($AssignedPolicies.Count)</div>
            </div>
            <div class="stat-card">
                <h3>Deprecated/Test</h3>
                <div class="stat-number">$($DeprecatedTestPolicies.Count)</div>
            </div>
            $changesSummary
        </div>
        
        <div class="filter-controls">
            <div class="filter-group">
                <label for="policyTypeFilter">Filter by Policy Type:</label>
                <select id="policyTypeFilter" onchange="applyAllFilters()">
                    <option value="all">All Policy Types</option>
                    $policyTypeOptions
                </select>
            </div>
            
            <div class="filter-group">
                <label for="dateFilter">Filter by Last Modified:</label>
                <select id="dateFilter" onchange="applyAllFilters()">
                    <option value="all">All Time</option>
                    <option value="7">Last 7 Days</option>
                    <option value="30">Last 30 Days</option>
                    <option value="90">Last 90 Days</option>
                    <option value="180">Last 6 Months</option>
                    <option value="365">Last Year</option>
                </select>
            </div>
            
            <button class="clear-all-filters-btn" onclick="clearAllFilters()">Clear All Filters</button>
        </div>
        
        <div class="tab-container">
            <div class="tab-buttons">
                <button class="tab-button active" onclick="openTab(event, 'unassigned')">
                    Unassigned Policies <span class="badge-count">$($UnassignedPolicies.Count)</span>
                </button>
                <button class="tab-button" onclick="openTab(event, 'assigned')">
                    Assigned Policies <span class="badge-count">$($AssignedPolicies.Count)</span>
                </button>
                <button class="tab-button" onclick="openTab(event, 'deprecated')">
                    Deprecated/Test <span class="badge-count">$($DeprecatedTestPolicies.Count)</span>
                </button>
                $deletedTabButton
            </div>
            
            <div class="tab-content active" id="unassigned">
                <h2>Unassigned Policies ($($UnassignedPolicies.Count))</h2>
                <p class="section-description">These policies are not assigned to any groups, devices, or users. Consider reviewing if they should be assigned or deleted.</p>
                <table id="unassignedTable">
                    <thead>
                        <tr>
                            <th>Policy Type</th>
                            <th>Policy Name</th>
                            <th>Last Modified</th>
                            <th>Assignment Status</th>
                            <th>Change Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        $unassignedRows
                    </tbody>
                </table>
            </div>
            
            <div class="tab-content" id="assigned">
                <h2>Assigned Policies ($($AssignedPolicies.Count))</h2>
                <p class="section-description">These policies are actively assigned to groups, devices, or users in your organization.</p>
                <table id="assignedTable">
                    <thead>
                        <tr>
                            <th>Policy Type</th>
                            <th>Policy Name</th>
                            <th>Last Modified</th>
                            <th>Assignments</th>
                            <th>Change Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        $assignedRows
                    </tbody>
                </table>
            </div>
            
            <div class="tab-content" id="deprecated">
                <h2>Deprecated/Test Policies ($($DeprecatedTestPolicies.Count))</h2>
                <p class="section-description">These policies contain 'deprecated' or 'test' in their names and may need cleanup or review.</p>
                <table id="deprecatedTable">
                    <thead>
                        <tr>
                            <th>Policy Type</th>
                            <th>Policy Name</th>
                            <th>Last Modified</th>
                            <th>Assignments</th>
                            <th>Change Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        $deprecatedRows
                    </tbody>
                </table>
            </div>
            
            $deletedSection
        </div>
        
        <footer>
            <p>Intune Policy Review Script v1.0 | Generated by ReviewIntunePolicyState.ps1</p>
            <p>Report saved to: $OutputPath</p>
        </footer>
    </div>
    
    <script>
        function toggleSettings(btn) {
            var tr = `$(btn).closest('tr');
            var tableEl = `$(btn).closest('table');
            var tableId = tableEl.attr('id');
            var settingsHtml = tr.attr('data-settings');
            if (!settingsHtml || !tableId || !dataTables[tableId]) return;
            var row = dataTables[tableId].row(tr);
            if (row.child.isShown()) {
                row.child.hide();
                btn.innerHTML = '&#9654; Details';
            } else {
                row.child('<div class="settings-child">' + settingsHtml + '</div>').show();
                btn.innerHTML = '&#9660; Details';
            }
        }

        function copyToClipboard(btn) {
            var name = btn.getAttribute('data-name');
            var originalHTML = btn.innerHTML;
            function showFeedback() {
                btn.classList.add('copied');
                btn.innerHTML = 'Copied!';
                setTimeout(function() {
                    btn.classList.remove('copied');
                    btn.innerHTML = originalHTML;
                }, 1500);
            }
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(name).then(showFeedback).catch(function() {
                    fallbackCopy(name, showFeedback);
                });
            } else {
                fallbackCopy(name, showFeedback);
            }
        }

        function fallbackCopy(text, callback) {
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            try { document.execCommand('copy'); } catch(e) {}
            document.body.removeChild(ta);
            if (callback) callback();
        }

        var currentChangeFilter = null;
        var dataTables = {};
        
        function openTab(evt, tabName) {
            var i, tabcontent, tabbuttons;
            
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].classList.remove("active");
            }
            
            tabbuttons = document.getElementsByClassName("tab-button");
            for (i = 0; i < tabbuttons.length; i++) {
                tabbuttons[i].classList.remove("active");
            }
            
            document.getElementById(tabName).classList.add("active");
            evt.currentTarget.classList.add("active");
            
            // Reapply all filters if active
            applyAllFilters();
        }
        
        function parseDate(dateStr) {
            // Parse dates in format: yyyy-MM-dd HH:mm:ss or ISO format
            try {
                var date = new Date(dateStr);
                if (isNaN(date.getTime())) {
                    // Try parsing MM/dd/yyyy format
                    var parts = dateStr.split(' ')[0].split('/');
                    if (parts.length === 3) {
                        date = new Date(parts[2], parts[0] - 1, parts[1]);
                    }
                }
                return date;
            } catch (e) {
                return null;
            }
        }
        
        function applyAllFilters() {
            // Force DataTables to redraw all tables with custom filtering
            Object.keys(dataTables).forEach(function(tableId) {
                if (dataTables[tableId]) {
                    dataTables[tableId].draw();
                }
            });
        }
        
        function customFilterFunction(settings, data, dataIndex) {
            var policyTypeFilter = document.getElementById('policyTypeFilter').value;
            var dateFilter = document.getElementById('dateFilter').value;
            var changeFilter = currentChangeFilter;
            
            // data array: [PolicyType, PolicyName, LastModified, Assignments, ChangeStatus]
            var policyType = data[0];
            var lastModified = data[2];
            var changeStatus = data[data.length - 1];
            
            // Filter by policy type
            if (policyTypeFilter !== 'all' && policyType !== policyTypeFilter) {
                return false;
            }
            
            // Filter by date
            if (dateFilter !== 'all') {
                var daysBack = parseInt(dateFilter);
                var cutoffDate = new Date();
                cutoffDate.setDate(cutoffDate.getDate() - daysBack);
                
                var rowDate = parseDate(lastModified);
                if (rowDate && rowDate < cutoffDate) {
                    return false;
                }
            }
            
            // Filter by change type
            if (changeFilter && !changeStatus.includes(changeFilter)) {
                return false;
            }
            
            return true;
        }
        
        function filterByChange(changeType) {
            // Toggle filter if clicking same badge
            if (currentChangeFilter === changeType) {
                clearChangeFilter();
                return;
            }
            
            currentChangeFilter = changeType;
            
            // Update badge styling
            var badges = document.querySelectorAll('.filter-badge');
            badges.forEach(function(badge) {
                badge.classList.remove('active-filter');
            });
            event.target.classList.add('active-filter');
            
            // Show clear button
            document.querySelector('.clear-filter-btn').style.display = 'inline-block';
            
            // Apply all filters
            applyAllFilters();
        }
        
        function clearChangeFilter() {
            currentChangeFilter = null;
            
            // Remove badge styling
            var badges = document.querySelectorAll('.filter-badge');
            badges.forEach(function(badge) {
                badge.classList.remove('active-filter');
            });
            
            // Hide clear button
            document.querySelector('.clear-filter-btn').style.display = 'none';
            
            // Reapply remaining filters
            applyAllFilters();
        }
        
        function clearAllFilters() {
            // Reset all filter controls
            document.getElementById('policyTypeFilter').value = 'all';
            document.getElementById('dateFilter').value = 'all';
            
            // Clear change filter badge styling
            currentChangeFilter = null;
            var badges = document.querySelectorAll('.filter-badge');
            badges.forEach(function(badge) {
                badge.classList.remove('active-filter');
            });
            document.querySelector('.clear-filter-btn').style.display = 'none';
            
            // Redraw DataTables with filters cleared
            applyAllFilters();
        }
        
        `$(document).ready(function() {
            // Register custom filter function for DataTables
            `$.fn.dataTable.ext.search.push(customFilterFunction);
            
            // Initialize DataTables
            var tableConfig = {
                pageLength: 25,
                order: [[2, 'desc']],
                language: {
                    search: "Filter policies:",
                    lengthMenu: "Show _MENU_ policies per page"
                }
            };
            
            dataTables['unassignedTable'] = `$('#unassignedTable').DataTable(tableConfig);
            dataTables['assignedTable'] = `$('#assignedTable').DataTable(tableConfig);
            dataTables['deprecatedTable'] = `$('#deprecatedTable').DataTable(tableConfig);
            
            if (document.getElementById('deletedTable')) {
                dataTables['deletedTable'] = `$('#deletedTable').DataTable(tableConfig);
            }
        });
    </script>
</body>
</html>
"@
    
    try {
        $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        Write-Host "`nHTML report generated successfully: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to write HTML report: $_"
    }
}

function Export-ToCSV {
    <#
    .SYNOPSIS
        Exports policy collections to CSV files.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$UnassignedPolicies,
        
        [Parameter(Mandatory = $true)]
        [array]$AssignedPolicies,
        
        [Parameter(Mandatory = $true)]
        [array]$DeprecatedTestPolicies,
        
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Export Unassigned
    if ($UnassignedPolicies.Count -gt 0) {
        $csvPath = "$BasePath`_Unassigned_$timestamp.csv"
        $UnassignedPolicies | Select-Object PolicyType, Name, Id, LastModified | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported unassigned policies to: $csvPath" -ForegroundColor Green
    }
    
    # Export Assigned
    if ($AssignedPolicies.Count -gt 0) {
        $csvPath = "$BasePath`_Assigned_$timestamp.csv"
        $AssignedPolicies | Select-Object PolicyType, Name, Id, LastModified, @{
            Name = 'Assignments'
            Expression = {
                if ($_.ResolvedAssignments) {
                    ($_.ResolvedAssignments | ForEach-Object {
                        $filterText = if ($_.FilterName) { " [Filter: $($_.FilterName)]" } else { "" }
                        "$($_.TargetType): $($_.TargetName)$filterText"
                    }) -join "; "
                } else {
                    "Unknown"
                }
            }
        } | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported assigned policies to: $csvPath" -ForegroundColor Green
    }
    
    # Export Deprecated/Test
    if ($DeprecatedTestPolicies.Count -gt 0) {
        $csvPath = "$BasePath`_DeprecatedTest_$timestamp.csv"
        $DeprecatedTestPolicies | Select-Object PolicyType, Name, Id, LastModified, @{
            Name = 'Assignments'
            Expression = {
                if ($_.ResolvedAssignments) {
                    ($_.ResolvedAssignments | ForEach-Object {
                        $filterText = if ($_.FilterName) { " [Filter: $($_.FilterName)]" } else { "" }
                        "$($_.TargetType): $($_.TargetName)$filterText"
                    }) -join "; "
                } else {
                    "Not Assigned"
                }
            }
        } | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported deprecated/test policies to: $csvPath" -ForegroundColor Green
    }
}

#endregion

#region Main Execution

try {
    $ErrorActionPreference = "Stop"
    
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host "Intune Policy Review Script v1.3" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    
    # Set default output path if not provided
    if (-not $OutputPath) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $OutputPath = Join-Path $PSScriptRoot "IntunePolicy Review_$timestamp.html"
    }
    
    # Step 1: Check and install required modules
    Test-RequiredModules
    
    # Step 2: Connect to Microsoft Graph
    Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Cyan
    
    $requiredScopes = @(
        "DeviceManagementConfiguration.Read.All",
        "DeviceManagementApps.Read.All",
        "Group.Read.All"
    )
    
    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $context) {
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome
        } else {
            Write-Host "Already connected to Microsoft Graph" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        exit 1
    }
    
    # Step 3: Retrieve assignment filters (lightweight)
    $filterCache = Get-AllAssignmentFilters
    
    # Step 3b: Placeholder for group cache (will be populated after assignments with lazy loading)
    $groupCache = @{}
    
    # Step 4: Define policy types and endpoints
    $policyTypes = @(
        @{
            Type = "ConfigurationPolicies"
            Endpoint = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$select=id,name,description,lastModifiedDateTime,createdDateTime"
            NameProperty = "name"
        },
        @{
            Type = "DeviceConfigurations"
            Endpoint = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$select=id,displayName,description,lastModifiedDateTime,createdDateTime"
            NameProperty = "displayName"
        },
        @{
            Type = "GroupPolicyConfigurations"
            Endpoint = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?`$select=id,displayName,description,lastModifiedDateTime,createdDateTime"
            NameProperty = "displayName"
        },
        @{
            Type = "CompliancePolicies"
            Endpoint = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?`$select=id,displayName,description,lastModifiedDateTime,createdDateTime"
            NameProperty = "displayName"
        },
        @{
            Type = "PowerShellScripts"
            Endpoint = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?`$select=id,displayName,description,lastModifiedDateTime,createdDateTime"
            NameProperty = "displayName"
        },
        @{
            Type = "RemediationScripts"
            Endpoint = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?`$select=id,displayName,description,lastModifiedDateTime,createdDateTime"
            NameProperty = "displayName"
        },
        @{
            Type = "MobileApps"
            Endpoint = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$select=id,displayName,publisher,description,lastModifiedDateTime,createdDateTime"
            NameProperty = "displayName"
        },
        @{
            Type = "AutopilotProfiles"
            Endpoint = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles?`$select=id,displayName,description,lastModifiedDateTime,createdDateTime"
            NameProperty = "displayName"
        },
        @{
            Type = "EnrollmentStatusPage"
            Endpoint = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations?`$select=id,displayName,description,lastModifiedDateTime,createdDateTime"
            NameProperty = "displayName"
        },
        @{
            Type = "FeatureUpdatePolicies"
            Endpoint = "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles?`$select=id,displayName,description,lastModifiedDateTime,createdDateTime"
            NameProperty = "displayName"
        },
        @{
            Type = "EndpointSecurityPolicies"
            Endpoint = "https://graph.microsoft.com/beta/deviceManagement/intents"
            NameProperty = "displayName"
        }
    )
    
    # Step 5: Retrieve all policies
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host "Retrieving Intune Policies" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    
    $allPolicies = [System.Collections.Generic.List[PSObject]]::new()
    $policyCount = 0
    
    foreach ($policyType in $policyTypes) {
        Write-Progress -Activity "Retrieving Intune Policies" -Status "Processing $($policyType.Type)..." -PercentComplete (($policyCount / $policyTypes.Count) * 100)
        
        $policies = Get-IntunePoliciesByType -PolicyType $policyType.Type -Endpoint $policyType.Endpoint
        
        foreach ($policy in $policies) {
            # Normalize the policy object
            $nameProperty = $policyType.NameProperty
            
            $normalizedPolicy = [PSCustomObject]@{
                Id = $policy.id
                Name = $policy.$nameProperty
                PolicyType = $policyType.Type
                Description = $policy.description
                LastModifiedDateTime = $policy.lastModifiedDateTime
                LastModified = if ($policy.lastModifiedDateTime) { ([datetime]$policy.lastModifiedDateTime).ToString("yyyy-MM-dd HH:mm") } else { "Unknown" }
                CreatedDateTime = $policy.createdDateTime
                Assignments = @()
                ResolvedAssignments = @()
                SettingsHtml = ""
            }
            
            $allPolicies.Add($normalizedPolicy)
        }
        
        $policyCount++
    }
    
    Write-Progress -Activity "Retrieving Intune Policies" -Completed
    
    Write-Host "`nTotal policies retrieved: $($allPolicies.Count)" -ForegroundColor Green
    
    # Step 6: Retrieve assignments for all policies
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host "Retrieving Policy Assignments" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    
    $processedCount = 0
    $failedCount = 0
    foreach ($policy in $allPolicies) {
        $processedCount++
        Write-Progress -Activity "Retrieving Assignments" -Status "Processing $($policy.Name)..." -PercentComplete (($processedCount / $allPolicies.Count) * 100)
        
        # Add small delay to prevent overwhelming the API in large tenants
        if ($ThrottleMilliseconds -gt 0 -and $processedCount -gt 1) {
            Start-Sleep -Milliseconds $ThrottleMilliseconds
        }
        
        $assignments = Get-PolicyAssignments -PolicyId $policy.Id -PolicyType $policy.PolicyType
        
        if ($assignments) {
            $policy.Assignments = $assignments
        } elseif ($policy.Assignments -eq $null) {
            $failedCount++
        }
    }
    
    Write-Progress -Activity "Retrieving Assignments" -Completed
    
    if ($failedCount -gt 0) {
        Write-Host "`nWarning: Failed to retrieve assignments for $failedCount policies due to API errors" -ForegroundColor Yellow
    }
    
    # Step 6b: Lazy load group names (only for groups actually used in assignments)
    if (-not $SkipGroupResolution) {
        Write-Host "`n==========================================" -ForegroundColor Cyan
        Write-Host "Resolving Group Names (Lazy Loading)" -ForegroundColor Cyan
        Write-Host "==========================================" -ForegroundColor Cyan
        
        $groupIds = Get-GroupIdsFromAssignments -AllPolicies $allPolicies
        
        if ($groupIds.Count -gt 0) {
            Write-Host "Found $($groupIds.Count) unique groups used in assignments" -ForegroundColor Cyan
            $groupCache = Get-GroupsByIds -GroupIds $groupIds
        } else {
            Write-Host "No group assignments found" -ForegroundColor Green
        }
        
        # Now resolve assignments with the group cache
        Write-Host "Resolving assignment details..." -ForegroundColor Cyan
        $resolveCount = 0
        $resolvedCount = 0
        $skippedCount = 0
        
        foreach ($policy in $allPolicies) {
            $resolveCount++
            
            if ($resolveCount % 100 -eq 0) {
                Write-Progress -Activity "Resolving Assignments" -Status "Processing policy $resolveCount of $($allPolicies.Count)" -PercentComplete (($resolveCount / $allPolicies.Count) * 100)
            }
            
            # Check if policy has assignments (handle both array and single object)
            $hasAssignments = $false
            if ($policy.Assignments) {
                if ($policy.Assignments -is [System.Array]) {
                    $hasAssignments = $policy.Assignments.Count -gt 0
                } else {
                    # Single assignment object
                    $hasAssignments = $true
                }
            }
            
            if ($hasAssignments) {
                $policy.ResolvedAssignments = Resolve-AssignmentTargets -Assignments $policy.Assignments -GroupCache $groupCache -FilterCache $filterCache
                $resolvedCount++
            } else {
                $skippedCount++
            }
        }
        
        Write-Progress -Activity "Resolving Assignments" -Completed
        Write-Host "Successfully resolved assignments for $resolvedCount policies" -ForegroundColor Green
        
        if ($skippedCount -gt 0) {
            Write-Host "Skipped $skippedCount policies with no assignments" -ForegroundColor Yellow
        }
    } else {
        Write-Host "`n==========================================" -ForegroundColor Cyan
        Write-Host "Skipping Group Name Resolution" -ForegroundColor Yellow
        Write-Host "==========================================" -ForegroundColor Cyan
        Write-Host "Group IDs will be displayed instead of names (-SkipGroupResolution specified)" -ForegroundColor Yellow
        
        # Resolve assignments without group names
        $resolvedCount = 0
        foreach ($policy in $allPolicies) {
            # Check if policy has assignments (handle both array and single object)
            $hasAssignments = $false
            if ($policy.Assignments) {
                if ($policy.Assignments -is [System.Array]) {
                    $hasAssignments = $policy.Assignments.Count -gt 0
                } else {
                    # Single assignment object
                    $hasAssignments = $true
                }
            }
            
            if ($hasAssignments) {
                $policy.ResolvedAssignments = Resolve-AssignmentTargets -Assignments $policy.Assignments -GroupCache @{} -FilterCache $filterCache
                $resolvedCount++
            }
        }
        
        Write-Host "Resolved $resolvedCount policy assignments (showing Group IDs)" -ForegroundColor Green
    }
    
    # Step 7: Categorize policies
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host "Categorizing Policies" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    
    $unassignedPolicies = [System.Collections.Generic.List[PSObject]]::new()
    $assignedPolicies = [System.Collections.Generic.List[PSObject]]::new()
    $deprecatedTestPolicies = [System.Collections.Generic.List[PSObject]]::new()
    
    foreach ($policy in $allPolicies) {
        # Check for deprecated/test in name
        if ($policy.Name -match "deprecated|test") {
            $deprecatedTestPolicies.Add($policy)
        }
        
        # Check assignment status
        if ($policy.Assignments.Count -eq 0) {
            $unassignedPolicies.Add($policy)
        } else {
            $assignedPolicies.Add($policy)
        }
    }
    
    Write-Host "Unassigned policies: $($unassignedPolicies.Count)" -ForegroundColor Yellow
    Write-Host "Assigned policies: $($assignedPolicies.Count)" -ForegroundColor Green
    Write-Host "Deprecated/Test policies: $($deprecatedTestPolicies.Count)" -ForegroundColor Magenta
    
    # Diagnostic: Check how many assigned policies have resolved assignments
    $assignedWithResolved = ($assignedPolicies | Where-Object { $_.ResolvedAssignments -and $_.ResolvedAssignments.Count -gt 0 }).Count
    $assignedWithoutResolved = $assignedPolicies.Count - $assignedWithResolved
    
    if ($assignedWithoutResolved -gt 0) {
        Write-Host "`nDiagnostic: $assignedWithoutResolved out of $($assignedPolicies.Count) assigned policies have unresolved assignments" -ForegroundColor Yellow
        Write-Host "This may indicate API throttling or errors during assignment resolution" -ForegroundColor Yellow
        
        # Sample a few for diagnosis
        $unresolved = $assignedPolicies | Where-Object { -not $_.ResolvedAssignments -or $_.ResolvedAssignments.Count -eq 0 } | Select-Object -First 5
        Write-Host "`nSample policies with unresolved assignments:" -ForegroundColor Cyan
        foreach ($pol in $unresolved) {
            $assignCount = if ($pol.Assignments) { 
                if ($pol.Assignments -is [System.Array]) { $pol.Assignments.Count } else { 1 }
            } else { 0 }
            Write-Host "  - $($pol.Name)" -ForegroundColor White
            Write-Host "    Type: $($pol.PolicyType), Assignments retrieved: $assignCount" -ForegroundColor Gray
        }
        Write-Host "`nTip: Try running with -ThrottleMilliseconds 200 -Verbose for more details" -ForegroundColor Cyan
    } else {
        Write-Host "`nAll assigned policies have successfully resolved assignments!" -ForegroundColor Green
    }
    
    # Step 6c: Retrieve policy settings (if requested)
    if ($IncludeSettings) {
        Write-Host "`n==========================================" -ForegroundColor Cyan
        Write-Host "Retrieving Policy Settings" -ForegroundColor Cyan
        Write-Host "==========================================" -ForegroundColor Cyan
        Write-Host "Warning: Fetching detailed settings requires one API call per policy." -ForegroundColor Yellow
        
        $settingsCount = 0
        foreach ($policy in $allPolicies) {
            $settingsCount++
            Write-Progress -Activity "Retrieving Policy Settings" `
                           -Status "[$settingsCount/$($allPolicies.Count)] $($policy.Name)..." `
                           -PercentComplete (($settingsCount / $allPolicies.Count) * 100)
            
            if ($ThrottleMilliseconds -gt 0 -and $settingsCount -gt 1) {
                Start-Sleep -Milliseconds $ThrottleMilliseconds
            }
            
            $policy.SettingsHtml = Get-PolicySettings -PolicyId $policy.Id -PolicyType $policy.PolicyType
        }
        
        Write-Progress -Activity "Retrieving Policy Settings" -Completed
        $settingsPopulated = ($allPolicies | Where-Object { $_.SettingsHtml }).Count
        Write-Host "Settings retrieved for $settingsPopulated out of $($allPolicies.Count) policies" -ForegroundColor Green
    }
    $changes = $null
    if ($PreviousReport -and (Test-Path $PreviousReport)) {
        Write-Host "`n==========================================" -ForegroundColor Cyan
        Write-Host "Comparing with Previous Report" -ForegroundColor Cyan
        Write-Host "==========================================" -ForegroundColor Cyan
        
        try {
            $baselinePolicies = Get-Content -Path $PreviousReport -Raw | ConvertFrom-Json
            $changes = Compare-PolicyStates -CurrentPolicies $allPolicies -BaselinePolicies $baselinePolicies
            
            Write-Host "New policies: $($changes.New.Count)" -ForegroundColor Green
            Write-Host "Modified policies: $($changes.Modified.Count)" -ForegroundColor Yellow
            Write-Host "Deleted policies: $($changes.Deleted.Count)" -ForegroundColor Red
            Write-Host "Assignment changes: $($changes.AssignmentChanged.Count)" -ForegroundColor Cyan
        }
        catch {
            Write-Warning "Failed to compare with previous report: $_"
        }
    }
    
    # Step 9: Export current state to JSON for future comparison
    $jsonExportPath = $OutputPath -replace '\.html$', '_baseline.json'
    try {
        $allPolicies | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonExportPath -Encoding UTF8 -Force
        Write-Host "`nBaseline JSON exported to: $jsonExportPath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to export baseline JSON: $_"
    }
    
    # Step 10: Generate HTML report
    if (-not $NoHTMLReport) {
        Write-Host "`n==========================================" -ForegroundColor Cyan
        Write-Host "Generating HTML Report" -ForegroundColor Cyan
        Write-Host "==========================================" -ForegroundColor Cyan
        
        New-HTMLReport -AllPolicies $allPolicies `
                       -UnassignedPolicies $unassignedPolicies `
                       -AssignedPolicies $assignedPolicies `
                       -DeprecatedTestPolicies $deprecatedTestPolicies `
                       -Changes $changes `
                       -OutputPath $OutputPath `
                       -ReportDate (Get-Date) `
                       -ShowSettings:$IncludeSettings
    }
    
    # Step 11: Export to CSV (if requested)
    if ($ExportToCSV) {
        Write-Host "`n==========================================" -ForegroundColor Cyan
        Write-Host "Exporting to CSV" -ForegroundColor Cyan
        Write-Host "==========================================" -ForegroundColor Cyan
        
        $csvBasePath = $OutputPath -replace '\.html$', ''
        Export-ToCSV -UnassignedPolicies $unassignedPolicies `
                     -AssignedPolicies $assignedPolicies `
                     -DeprecatedTestPolicies $deprecatedTestPolicies `
                     -BasePath $csvBasePath
    }
    
    # Final summary
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host "Script Completed Successfully" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "`nSummary:" -ForegroundColor Cyan
    Write-Host "  Total Policies: $($allPolicies.Count)"
    Write-Host "  Unassigned: $($unassignedPolicies.Count)"
    Write-Host "  Assigned: $($assignedPolicies.Count)"
    Write-Host "  Deprecated/Test: $($deprecatedTestPolicies.Count)"
    
    if ($changes) {
        Write-Host "`nChanges since last report:"
        Write-Host "  New: $($changes.New.Count)"
        Write-Host "  Modified: $($changes.Modified.Count)"
        Write-Host "  Deleted: $($changes.Deleted.Count)"
        Write-Host "  Assignment Changed: $($changes.AssignmentChanged.Count)"
    }
    
    if (-not $NoHTMLReport) {
        Write-Host "`nHTML Report: $OutputPath" -ForegroundColor Green
    }
    Write-Host "Baseline JSON: $jsonExportPath" -ForegroundColor Green
    
    Write-Host "`nTo compare changes next time, run:" -ForegroundColor Yellow
    Write-Host "  .\ReviewIntunePolicyState.ps1 -PreviousReport `"$jsonExportPath`"" -ForegroundColor Yellow
}
catch {
    Write-Error "An error occurred during script execution: $_"
    Write-Error $_.ScriptStackTrace
    exit 1
}
finally {
    # Cleanup
    Write-Host "`n==========================================" -ForegroundColor Cyan
}

#endregion
