<#
.SYNOPSIS
    Retrieves Entra groups and checks for Intune policy assignments.

.DESCRIPTION
    This script queries Microsoft Entra ID for security groups. You can optionally filter
    by a display name prefix (e.g. "sec-mem-cmw"). If no filter is provided, ALL groups
    in the tenant are scanned. For each group found, it retrieves:
    - Group description
    - Audit trail of who created the group
    - All Intune policy assignments (device configurations, compliance policies,
      settings catalog, administrative templates, scripts, proactive remediations,
      app protection policies, app assignments, endpoint security, and more)

    Results are exported to a modern HTML report with dark/light mode toggle, showing
    which groups have assignments (and what they are) and which groups are candidates
    for cleanup.

    Optimized for large-scale tenants (350K+ groups):
    - Server-side filtering with ConsistencyLevel:eventual for startsWith queries
    - Fetch-once/match-all pattern: all Intune policies fetched once, matched via HashSet
    - $expand=assignments to eliminate per-policy API calls where supported
    - Graph batch API for audit log lookups (20 per batch request)
    - Parallel runspaces for concurrent policy type fetching
    - [List[object]] and [StringBuilder] to avoid O(n^2) concatenation
    - Automatic retry with exponential backoff for 429 throttling
    - $select to minimize payload size on all API calls

.PARAMETER OutputPath
    The path where the HTML report will be saved. Defaults to the script directory.

.PARAMETER GroupFilter
    Optional prefix to filter group display names (e.g. "sec-mem-cmw", "sg-intune").
    Supports any leading string — the script will use a startsWith filter in Graph.
    Leave empty or omit to scan ALL groups in the tenant.

.PARAMETER MaxParallelThreads
    Maximum number of parallel runspaces for fetching policy types concurrently.
    Defaults to 6. Increase for faster execution in large tenants with high Graph API limits.

.EXAMPLE
    .\ReviewGroupAssignments.ps1
    Scans ALL groups in the tenant and saves the report in the script directory.

.EXAMPLE
    .\ReviewGroupAssignments.ps1 -GroupFilter "sec-mem-cmw" -OutputPath "C:\Reports"
    Searches for groups starting with "sec-mem-cmw" and saves to C:\Reports.

.EXAMPLE
    .\ReviewGroupAssignments.ps1 -GroupFilter "sg-intune" -MaxParallelThreads 8
    Searches for groups starting with "sg-intune" with increased parallelism.

.NOTES
    Version:        1.1
    Author:         Mattias Melkersen
    Creation Date:  2026-02-13

    CHANGELOG
    ---------------
   2026-02-13 - v1.0 - Initial version (MM)

    Required Graph Permissions:
    - Group.Read.All
    - GroupMember.Read.All
    - DeviceManagementConfiguration.Read.All
    - DeviceManagementManagedDevices.Read.All
    - DeviceManagementApps.Read.All
    - DeviceManagementServiceConfig.Read.All
    - AuditLog.Read.All
    - DeviceManagementRBAC.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter(Mandatory = $false)]
    [string]$GroupFilter = "",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 16)]
    [int]$MaxParallelThreads = 6
)

# Fallback when $PSScriptRoot is null (e.g. run from ISE, paste into console)
if ([string]::IsNullOrEmpty($OutputPath)) { $OutputPath = $PWD.Path }

#region Functions

function Install-RequiredModules {
    $requiredModules = @(
        'Microsoft.Graph.Authentication'
    )

    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Host "Installing module: $module" -ForegroundColor Yellow
            try {
                Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-Host "Successfully installed $module" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to install $module. Error: $_"
                return $false
            }
        }
        # Import the module if not already loaded in the current session
        if (-not (Get-Module -Name $module)) {
            try {
                Import-Module -Name $module -Force -ErrorAction Stop
            }
            catch {
                Write-Error "Failed to import $module. Error: $_"
                return $false
            }
        }
    }
    return $true
}

function Invoke-MgGraphRequestWithRetry {
    <#
    .SYNOPSIS
        Calls Microsoft Graph with automatic retry on 429 throttling and transient errors.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [string]$Method = "GET",

        [Parameter(Mandatory = $false)]
        [hashtable]$Headers = @{},

        [Parameter(Mandatory = $false)]
        [object]$Body = $null,

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 5
    )

    $retryCount = 0
    while ($true) {
        try {
            $params = @{
                Method      = $Method
                Uri         = $Uri
                ErrorAction = 'Stop'
            }
            if ($Headers.Count -gt 0) { $params['Headers'] = $Headers }
            if ($null -ne $Body) {
                $params['Body'] = $Body
                $params['ContentType'] = 'application/json'
            }
            return (Invoke-MgGraphRequest @params)
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            # Retry on 429 (throttled), 503 (service unavailable), 504 (gateway timeout)
            if ($statusCode -in @(429, 503, 504) -and $retryCount -lt $MaxRetries) {
                $retryCount++
                $retryAfter = 0

                # Check Retry-After header
                if ($_.Exception.Response.Headers) {
                    try {
                        $retryAfterHeader = $_.Exception.Response.Headers | Where-Object { $_.Key -eq 'Retry-After' }
                        if ($retryAfterHeader) {
                            $retryAfter = [int]$retryAfterHeader.Value[0]
                        }
                    }
                    catch { }
                }

                # Exponential backoff: 2^retry seconds, minimum from Retry-After header
                $backoffSeconds = [Math]::Max($retryAfter, [Math]::Pow(2, $retryCount))
                $backoffSeconds = [Math]::Min($backoffSeconds, 120) # Cap at 2 minutes
                Write-Verbose "Throttled (HTTP $statusCode). Retry $retryCount/$MaxRetries in ${backoffSeconds}s..."
                Start-Sleep -Seconds $backoffSeconds
            }
            else {
                throw
            }
        }
    }
}

function Invoke-MgGraphRequestWithPagination {
    <#
    .SYNOPSIS
        Calls Microsoft Graph with automatic pagination and throttle-retry handling.
        Uses [List[object]] to avoid O(n^2) array concatenation.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [string]$Method = "GET",

        [Parameter(Mandatory = $false)]
        [hashtable]$Headers = @{}
    )

    $allResults = [System.Collections.Generic.List[object]]::new()
    $currentUri = $Uri

    do {
        try {
            $response = Invoke-MgGraphRequestWithRetry -Uri $currentUri -Method $Method -Headers $Headers
            if ($response.value) {
                $allResults.AddRange([object[]]$response.value)
            }
            $currentUri = $response.'@odata.nextLink'
        }
        catch {
            Write-Warning "Graph request failed for $currentUri : $_"
            $currentUri = $null
        }
    } while ($currentUri)

    return $allResults
}

function Get-GroupCreationAuditBatch {
    <#
    .SYNOPSIS
        Retrieves audit log entries for group creation using Graph batch API.
        Processes up to 20 groups per batch request for efficiency.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$Groups
    )

    $auditResults = @{}
    $defaultAudit = @{
        CreatedBy     = "Unknown (audit log expired or unavailable)"
        CreatedDate   = "N/A"
        CorrelationId = "N/A"
    }

    # Process in batches of 20 (Graph batch API limit)
    $batchSize = 20
    $totalBatches = [Math]::Ceiling($Groups.Count / $batchSize)

    for ($batchNum = 0; $batchNum -lt $totalBatches; $batchNum++) {
        $startIdx = $batchNum * $batchSize
        $batchGroups = $Groups | Select-Object -Skip $startIdx -First $batchSize

        $requests = [System.Collections.Generic.List[object]]::new()

        foreach ($group in $batchGroups) {
            $filter = "activityDisplayName eq 'Add group' and targetResources/any(t: t/id eq '$($group.id)')"
            $encodedFilter = [System.Web.HttpUtility]::UrlEncode($filter)
            $requests.Add(@{
                id     = $group.id
                method = "GET"
                url    = "/auditLogs/directoryAudits?`$filter=$encodedFilter&`$top=1&`$orderby=activityDateTime desc"
            })
        }

        $batchBody = @{ requests = $requests.ToArray() } | ConvertTo-Json -Depth 10

        try {
            $batchResponse = Invoke-MgGraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/`$batch" -Method POST -Body $batchBody

            foreach ($response in $batchResponse.responses) {
                $groupId = $response.id

                if ($response.status -eq 200 -and $response.body.value -and $response.body.value.Count -gt 0) {
                    $auditEntry = $response.body.value[0]
                    $initiatedBy = $auditEntry.initiatedBy

                    if ($initiatedBy.user) {
                        $auditResults[$groupId] = @{
                            CreatedBy     = if ($initiatedBy.user.userPrincipalName) { $initiatedBy.user.userPrincipalName } else { $initiatedBy.user.displayName }
                            CreatedDate   = $auditEntry.activityDateTime
                            CorrelationId = $auditEntry.correlationId
                        }
                    }
                    elseif ($initiatedBy.app) {
                        $auditResults[$groupId] = @{
                            CreatedBy     = "App: $($initiatedBy.app.displayName)"
                            CreatedDate   = $auditEntry.activityDateTime
                            CorrelationId = $auditEntry.correlationId
                        }
                    }
                    else {
                        $auditResults[$groupId] = $defaultAudit
                    }
                }
                else {
                    $auditResults[$groupId] = $defaultAudit
                }
            }
        }
        catch {
            Write-Warning "Batch audit request failed (batch $($batchNum + 1)/$totalBatches): $_"
            # Fall back to default for all groups in this batch
            foreach ($group in $batchGroups) {
                if (-not $auditResults.ContainsKey($group.id)) {
                    $auditResults[$group.id] = $defaultAudit
                }
            }
        }

        if ($totalBatches -gt 1) {
            Write-Progress -Activity "Fetching Audit Logs" -Status "Batch $($batchNum + 1)/$totalBatches" -PercentComplete ((($batchNum + 1) / $totalBatches) * 100)
        }
    }

    Write-Progress -Activity "Fetching Audit Logs" -Completed
    return $auditResults
}

function Get-GroupMemberCountBatch {
    <#
    .SYNOPSIS
        Retrieves member counts for groups using Graph batch API.
        Processes up to 20 groups per batch request.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$Groups
    )

    $memberCounts = @{}

    # Process in batches of 20 (Graph batch API limit)
    $batchSize = 20
    $totalBatches = [Math]::Ceiling($Groups.Count / $batchSize)

    for ($batchNum = 0; $batchNum -lt $totalBatches; $batchNum++) {
        $startIdx = $batchNum * $batchSize
        $batchGroups = $Groups | Select-Object -Skip $startIdx -First $batchSize

        $requests = [System.Collections.Generic.List[object]]::new()

        foreach ($group in $batchGroups) {
            $requests.Add(@{
                id      = $group.id
                method  = "GET"
                url     = "/groups/$($group.id)/members/`$count"
                headers = @{ 'ConsistencyLevel' = 'eventual' }
            })
        }

        $batchBody = @{ requests = $requests.ToArray() } | ConvertTo-Json -Depth 10

        try {
            $batchResponse = Invoke-MgGraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/`$batch" -Method POST -Body $batchBody

            foreach ($response in $batchResponse.responses) {
                $groupId = $response.id

                if ($response.status -eq 200) {
                    # $count returns a plain integer in the body
                    $memberCounts[$groupId] = [int]$response.body
                }
                else {
                    Write-Verbose "[MemberCount] Failed for group $groupId : HTTP $($response.status)"
                    $memberCounts[$groupId] = -1
                }
            }
        }
        catch {
            Write-Warning "Batch member count request failed (batch $($batchNum + 1)/$totalBatches): $_"
            foreach ($group in $batchGroups) {
                if (-not $memberCounts.ContainsKey($group.id)) {
                    $memberCounts[$group.id] = -1
                }
            }
        }

        if ($totalBatches -gt 1) {
            Write-Progress -Activity "Fetching Member Counts" -Status "Batch $($batchNum + 1)/$totalBatches" -PercentComplete ((($batchNum + 1) / $totalBatches) * 100)
        }
    }

    Write-Progress -Activity "Fetching Member Counts" -Completed
    return $memberCounts
}

function Get-AllIntuneAssignments {
    <#
    .SYNOPSIS
        Fetches ALL Intune policies with assignments in one pass, then returns
        a hashtable keyed by group ID containing matching assignments.
        Uses map-reduce pattern: each runspace returns local results, merged single-threaded.
        This avoids thread-safety issues with shared mutable collections.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]]$TargetGroupIds,

        [Parameter(Mandatory = $false)]
        [int]$MaxParallel = 6
    )

    # Build a case-insensitive lookup for group IDs to normalize casing
    # Graph may return groupIds in different casing across API responses
    $groupIdNormalizer = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($gid in $TargetGroupIds) {
        $groupIdNormalizer[$gid] = $gid
    }

    # Policy types that support $expand=assignments (reduces N+1 to single call per type)
    # IMPORTANT: Do NOT use $select on these - it strips the expanded assignments relationship
    $expandableTypes = @(
        @{ Name = "Device Configuration Profiles"; Uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"; Expand = $true; Filter = "" }
        @{ Name = "Settings Catalog Policies"; Uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"; Expand = $true; Filter = "" }
        @{ Name = "Compliance Policies"; Uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"; Expand = $true; Filter = "" }
        @{ Name = "Endpoint Security Policies"; Uri = "https://graph.microsoft.com/beta/deviceManagement/intents"; Expand = $true; Filter = "" }
        @{ Name = "Enrollment Configurations"; Uri = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations"; Expand = $true; Filter = "" }
        @{ Name = "Feature Update Policies"; Uri = "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles"; Expand = $true; Filter = "" }
        @{ Name = "Quality Update Policies"; Uri = "https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdateProfiles"; Expand = $true; Filter = "" }
        @{ Name = "Expedited Quality Updates"; Uri = "https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdatePolicies"; Expand = $true; Filter = "" }
        @{ Name = "Driver Update Policies"; Uri = "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles"; Expand = $true; Filter = "" }
        @{ Name = "App Configuration Policies (MDM)"; Uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations"; Expand = $true; Filter = "" }
    )

    # Policy types requiring separate /assignments calls (no $expand support or unreliable expand)
    $nonExpandableTypes = @(
        @{ Name = "Administrative Templates (ADMX)"; Uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations"; Expand = $false; Filter = "" }
        @{ Name = "Windows Autopilot Profiles"; Uri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles"; Expand = $false; Filter = "" }
        @{ Name = "PowerShell Scripts"; Uri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts"; Expand = $false; Filter = "" }
        @{ Name = "Proactive Remediations"; Uri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts"; Expand = $false; Filter = "isGlobalScript eq false" }
        @{ Name = "Compliance Scripts"; Uri = "https://graph.microsoft.com/beta/deviceManagement/deviceComplianceScripts"; Expand = $false; Filter = "" }
        @{ Name = "Scope Tags"; Uri = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags"; Expand = $false; Filter = "" }
        @{ Name = "Intune Role Assignments"; Uri = "https://graph.microsoft.com/beta/deviceManagement/roleAssignments"; Expand = $false; Filter = ""; SpecialType = "RoleAssignment" }
    )

    $allPolicyTypes = $expandableTypes + $nonExpandableTypes
    $totalTypes = $allPolicyTypes.Count + 1 # +1 for mobile apps

    # Process policy types using parallel runspaces (map-reduce pattern)
    # Each runspace returns its own local results list - NO shared mutable state
    Write-Host "  Fetching policies across $totalTypes policy types using $MaxParallel parallel threads..." -ForegroundColor Gray

    $runspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxParallel)
    $runspacePool.Open()

    $runspaces = [System.Collections.Generic.List[object]]::new()

    # MAP phase: each runspace independently collects matching assignments
    $scriptBlock = {
        param(
            [hashtable]$PolicyType,
            [System.Collections.Generic.HashSet[string]]$TargetIds,
            [bool]$EnableVerbose
        )

        if ($EnableVerbose) { $VerbosePreference = 'Continue' }

        $policyTypeName = $PolicyType.Name
        $baseUri = $PolicyType.Uri
        $supportsExpand = $PolicyType.Expand
        $specialType = $PolicyType.SpecialType
        $policyFilter = $PolicyType.Filter

        # Local results list - thread-safe because only this runspace writes to it
        $localResults = [System.Collections.Generic.List[PSCustomObject]]::new()

        # Diagnostic counters for verbose output
        $policiesFound = 0
        $policiesWithAnyAssignments = 0
        $totalAssignmentsScanned = 0

        # Helper: paginated fetch with retry
        function Invoke-PagedRequest {
            param([string]$RequestUri, [int]$Retries = 5)
            $items = [System.Collections.Generic.List[object]]::new()
            $currentUri = $RequestUri
            do {
                $attempt = 0
                $response = $null
                while ($attempt -lt $Retries) {
                    try {
                        $response = Invoke-MgGraphRequest -Method GET -Uri $currentUri -ErrorAction Stop
                        break
                    }
                    catch {
                        $attempt++
                        $sc = $null
                        if ($_.Exception.Response) { $sc = [int]$_.Exception.Response.StatusCode }
                        if ($sc -in @(429, 503, 504) -and $attempt -lt $Retries) {
                            $wait = [Math]::Min([Math]::Pow(2, $attempt), 120)
                            Start-Sleep -Seconds $wait
                        }
                        else { throw }
                    }
                }
                if ($response.value) { $items.AddRange([object[]]$response.value) }
                $currentUri = $response.'@odata.nextLink'
            } while ($currentUri)
            return $items
        }

        # Helper: extract assignments from a policy and match against target groups
        function Process-Assignments {
            param([array]$Assignments, [string]$PolicyName, [string]$TypeName)

            foreach ($assignment in $Assignments) {
                $targetGroupId = $null
                if ($assignment.target) { $targetGroupId = $assignment.target.groupId }
                elseif ($assignment.targetGroupId) { $targetGroupId = $assignment.targetGroupId }

                if ($targetGroupId -and $TargetIds.Contains($targetGroupId)) {
                    $assignType = "Include"
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                        $assignType = "Exclude"
                    }

                    $filterInfo = ""
                    if ($assignment.target.deviceAndAppManagementAssignmentFilterId) {
                        $filterInfo = "Filter applied (ID: $($assignment.target.deviceAndAppManagementAssignmentFilterId), Type: $($assignment.target.deviceAndAppManagementAssignmentFilterType))"
                    }

                    $localResults.Add([PSCustomObject]@{
                        GroupId        = $targetGroupId
                        PolicyType     = $TypeName
                        PolicyName     = $PolicyName
                        AssignmentType = $assignType
                        FilterInfo     = $filterInfo
                    })
                }
            }
        }

        try {
            if ($specialType -eq 'RoleAssignment') {
                # Role assignments use members/scopeMembers arrays instead of standard assignment targets
                $uri = "$baseUri`?`$top=100"
                $policies = Invoke-PagedRequest -RequestUri $uri
                $policiesFound = @($policies).Count
                Write-Verbose "[$policyTypeName] Fetched $policiesFound role assignments"

                foreach ($policy in $policies) {
                    $pName = if ($policy.displayName) { $policy.displayName } else { $policy.id }

                    # Check members (groups whose members get this Intune role)
                    if ($policy.members) {
                        foreach ($memberId in $policy.members) {
                            $totalAssignmentsScanned++
                            if ($TargetIds.Contains($memberId)) {
                                $localResults.Add([PSCustomObject]@{
                                    GroupId        = $memberId
                                    PolicyType     = $policyTypeName
                                    PolicyName     = "$pName (Members)"
                                    AssignmentType = "Include"
                                    FilterInfo     = ""
                                })
                                Write-Verbose "  [$policyTypeName] HIT '$pName': GroupId=$memberId in Members"
                            }
                        }
                    }

                    # Check scopeMembers (scope groups for this role)
                    if ($policy.scopeMembers) {
                        foreach ($scopeId in $policy.scopeMembers) {
                            $totalAssignmentsScanned++
                            if ($TargetIds.Contains($scopeId)) {
                                $localResults.Add([PSCustomObject]@{
                                    GroupId        = $scopeId
                                    PolicyType     = $policyTypeName
                                    PolicyName     = "$pName (Scope)"
                                    AssignmentType = "Include"
                                    FilterInfo     = "Scope Type: $($policy.scopeType)"
                                })
                                Write-Verbose "  [$policyTypeName] HIT '$pName': GroupId=$scopeId in ScopeMembers (scopeType=$($policy.scopeType))"
                            }
                        }
                    }
                }
            }
            elseif ($supportsExpand) {
                # Fetch policies with assignments expanded inline -- single API call per page
                # NOTE: Do NOT use $select here - it strips the expanded assignments on many Intune beta endpoints
                $uri = "$baseUri`?`$expand=assignments&`$top=100"
                if ($policyFilter) { $uri += "&`$filter=$policyFilter" }
                $policies = Invoke-PagedRequest -RequestUri $uri
                $policiesFound = @($policies).Count
                Write-Verbose "[$policyTypeName] Fetched $policiesFound policies (expand=assignments)"

                $expandNullCount = 0
                foreach ($policy in $policies) {
                    $pName = if ($policy.displayName) { $policy.displayName } elseif ($policy.name) { $policy.name } else { $policy.id }
                    if ($policy.assignments -and @($policy.assignments).Count -gt 0) {
                        $policiesWithAnyAssignments++
                        $assignCount = @($policy.assignments).Count
                        $totalAssignmentsScanned += $assignCount
                        $beforeCount = $localResults.Count
                        Process-Assignments -Assignments $policy.assignments -PolicyName $pName -TypeName $policyTypeName
                        $matched = $localResults.Count - $beforeCount
                        if ($matched -gt 0) {
                            Write-Verbose "  [$policyTypeName] HIT '$pName': $assignCount total assignments, $matched matched target groups"
                        }
                    }
                    elseif ($null -eq $policy.assignments) {
                        $expandNullCount++
                    }
                }
                if ($expandNullCount -gt 0) {
                    Write-Verbose "  [$policyTypeName] WARNING: $expandNullCount/$policiesFound policies had NULL assignments property (expand may not be supported)"
                }
            }
            else {
                # Fetch policies first, then assignments separately
                # Only select id and displayName - not all resource types have 'name'
                $uri = "$baseUri`?`$select=id,displayName&`$top=100"
                if ($policyFilter) { $uri += "&`$filter=$policyFilter" }
                $policies = Invoke-PagedRequest -RequestUri $uri
                $policiesFound = @($policies).Count
                Write-Verbose "[$policyTypeName] Fetched $policiesFound policies (separate /assignments calls)"

                $assignFetchErrors = 0
                foreach ($policy in $policies) {
                    $pName = if ($policy.displayName) { $policy.displayName } elseif ($policy.name) { $policy.name } else { $policy.id }
                    try {
                        $assignUri = "$baseUri/$($policy.id)/assignments"
                        $policyAssignments = Invoke-PagedRequest -RequestUri $assignUri
                        if ($policyAssignments.Count -gt 0) {
                            $policiesWithAnyAssignments++
                            $assignCount = @($policyAssignments).Count
                            $totalAssignmentsScanned += $assignCount
                            $beforeCount = $localResults.Count
                            Process-Assignments -Assignments $policyAssignments -PolicyName $pName -TypeName $policyTypeName
                            $matched = $localResults.Count - $beforeCount
                            if ($matched -gt 0) {
                                Write-Verbose "  [$policyTypeName] HIT '$pName': $assignCount total assignments, $matched matched target groups"
                            }
                        }
                    }
                    catch {
                        $assignFetchErrors++
                        Write-Verbose "  [$policyTypeName] ERROR fetching assignments for '$pName' ($($policy.id)): $_"
                    }
                }
                if ($assignFetchErrors -gt 0) {
                    Write-Verbose "  [$policyTypeName] $assignFetchErrors policies failed when fetching assignments"
                }
            }
        }
        catch {
            Write-Verbose "[$policyTypeName] FATAL: Failed to fetch policies - $_"
        }

        Write-Verbose "[$policyTypeName] RESULT: $policiesFound policies | $policiesWithAnyAssignments with assignments | $totalAssignmentsScanned scanned | $($localResults.Count) matched target groups"

        # Return local results to the caller (map output)
        return $localResults
    }

    # Determine if verbose logging is active to pass to runspaces
    $isVerbose = $VerbosePreference -ne 'SilentlyContinue'
    if ($isVerbose) {
        Write-Verbose "Verbose logging enabled - runspace diagnostics will be captured"
        Write-Verbose "Target group count: $($TargetGroupIds.Count)"
        Write-Verbose "Target group IDs: $($TargetGroupIds -join ', ')"
    }

    # Launch parallel runspaces for each policy type
    foreach ($policyType in $allPolicyTypes) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $runspacePool
        [void]$ps.AddScript($scriptBlock)
        [void]$ps.AddArgument($policyType)
        [void]$ps.AddArgument($TargetGroupIds)
        [void]$ps.AddArgument($isVerbose)

        $handle = $ps.BeginInvoke()
        $runspaces.Add(@{
            PowerShell = $ps
            Handle     = $handle
            Name       = $policyType.Name
        })
    }

    # REDUCE phase: collect results from completed runspaces and merge single-threaded
    # This eliminates all thread-safety issues with shared mutable collections
    $groupAssignments = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[PSCustomObject]]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($gid in $TargetGroupIds) {
        $groupAssignments[$gid] = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    $completed = 0
    while ($runspaces.Count -gt 0) {
        $finishedList = [System.Collections.Generic.List[int]]::new()
        for ($i = 0; $i -lt $runspaces.Count; $i++) {
            if ($runspaces[$i].Handle.IsCompleted) {
                $finishedList.Add($i)
            }
        }

        # Process finished items in reverse order to preserve indices
        for ($j = $finishedList.Count - 1; $j -ge 0; $j--) {
            $idx = $finishedList[$j]
            $rs = $runspaces[$idx]
            try {
                $rsResults = $rs.PowerShell.EndInvoke($rs.Handle)

                # Surface verbose and error streams from the runspace
                if ($isVerbose) {
                    foreach ($vr in $rs.PowerShell.Streams.Verbose) {
                        Write-Verbose $vr.Message
                    }
                }
                foreach ($er in $rs.PowerShell.Streams.Error) {
                    Write-Warning "[$($rs.Name)] Runspace error: $($er.Exception.Message)"
                }

                # Merge this runspace's results into the main dictionary (single-threaded, safe)
                # NOTE: PowerShell enumerates the returned List, so EndInvoke yields individual
                # PSCustomObject items - NOT a List wrapper. Each item has GroupId, PolicyType, etc.
                $itemsMerged = 0
                $itemsSkipped = 0
                if ($rsResults -and $rsResults.Count -gt 0) {
                    foreach ($item in $rsResults) {
                        if ($null -eq $item -or $null -eq $item.GroupId) {
                            $itemsSkipped++
                            Write-Verbose "[REDUCE] $($rs.Name): Skipped null item or item without GroupId"
                            continue
                        }
                        $normalizedId = $item.GroupId
                        # Normalize the group ID casing
                        if ($groupIdNormalizer.ContainsKey($normalizedId)) {
                            $normalizedId = $groupIdNormalizer[$normalizedId]
                        }
                        if ($groupAssignments.ContainsKey($normalizedId)) {
                            $groupAssignments[$normalizedId].Add([PSCustomObject]@{
                                PolicyType     = $item.PolicyType
                                PolicyName     = $item.PolicyName
                                AssignmentType = $item.AssignmentType
                                FilterInfo     = $item.FilterInfo
                            })
                            $itemsMerged++
                        }
                        else {
                            $itemsSkipped++
                            Write-Verbose "[REDUCE] $($rs.Name): GroupId '$($item.GroupId)' not in target dictionary after normalization"
                        }
                    }
                }
                Write-Verbose "[REDUCE] $($rs.Name): received=$(@($rsResults).Count) merged=$itemsMerged skipped=$itemsSkipped"
            }
            catch {
                Write-Warning "Failed to process $($rs.Name): $_"
                Write-Verbose "[REDUCE] $($rs.Name) EXCEPTION: $($_.ScriptStackTrace)"
            }
            finally {
                $rs.PowerShell.Dispose()
            }
            $runspaces.RemoveAt($idx)
            $completed++
            Write-Progress -Activity "Fetching Intune Assignments" -Status "$completed/$totalTypes policy types processed" -PercentComplete (($completed / $totalTypes) * 100)
        }

        if ($runspaces.Count -gt 0) {
            Start-Sleep -Milliseconds 200
        }
    }

    # Mobile Apps: sequential (different structure, needs $filter=isAssigned)
    Write-Progress -Activity "Fetching Intune Assignments" -Status "Mobile App Assignments ($totalTypes/$totalTypes)" -PercentComplete 95
    $mobileAppCount = 0
    $mobileAppAssignmentsScanned = 0
    $mobileAppMatches = 0
    $mobileAppErrors = 0
    try {
        $apps = Invoke-MgGraphRequestWithPagination -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true&`$select=id,displayName"
        $mobileAppCount = @($apps).Count
        Write-Verbose "[Mobile Apps] Fetched $mobileAppCount apps with isAssigned=true"

        foreach ($app in $apps) {
            try {
                $appAssignments = Invoke-MgGraphRequestWithPagination -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($app.id)/assignments"

                foreach ($assignment in $appAssignments) {
                    $mobileAppAssignmentsScanned++
                    $targetGroupId = $null
                    if ($assignment.target) { $targetGroupId = $assignment.target.groupId }

                    if ($targetGroupId -and $TargetGroupIds.Contains($targetGroupId)) {
                        $normalizedId = $targetGroupId
                        if ($groupIdNormalizer.ContainsKey($normalizedId)) {
                            $normalizedId = $groupIdNormalizer[$normalizedId]
                        }

                        $assignmentType = "Include"
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                            $assignmentType = "Exclude"
                        }

                        $intent = if ($assignment.intent) { $assignment.intent } else { "N/A" }
                        $appName = if ($app.displayName) { $app.displayName } else { $app.id }

                        if ($groupAssignments.ContainsKey($normalizedId)) {
                            $groupAssignments[$normalizedId].Add([PSCustomObject]@{
                                PolicyType     = "Mobile Apps ($intent)"
                                PolicyName     = $appName
                                AssignmentType = $assignmentType
                                FilterInfo     = ""
                            })
                            $mobileAppMatches++
                            Write-Verbose "  [Mobile Apps] HIT '$appName': GroupId=$targetGroupId, $assignmentType, intent=$intent"
                        }
                    }
                }
            }
            catch {
                $mobileAppErrors++
                Write-Verbose "  [Mobile Apps] ERROR reading assignments for '$($app.displayName)' ($($app.id)): $_"
            }
        }
    }
    catch {
        Write-Warning "Could not query mobile app assignments: $_"
    }
    Write-Verbose "[Mobile Apps] RESULT: $mobileAppCount apps | $mobileAppAssignmentsScanned scanned | $mobileAppMatches matched | $mobileAppErrors errors"

    $runspacePool.Close()
    $runspacePool.Dispose()
    Write-Progress -Activity "Fetching Intune Assignments" -Completed

    # Print per-type assignment summary (always visible, not just verbose)
    Write-Host "`n  --- Assignment Summary by Policy Type ---" -ForegroundColor Gray
    $typeSummary = @{}
    foreach ($kvp in $groupAssignments.GetEnumerator()) {
        foreach ($a in $kvp.Value) {
            $t = $a.PolicyType
            if (-not $typeSummary.ContainsKey($t)) { $typeSummary[$t] = @{ Include = 0; Exclude = 0 } }
            if ($a.AssignmentType -eq 'Exclude') { $typeSummary[$t].Exclude++ } else { $typeSummary[$t].Include++ }
        }
    }
    if ($typeSummary.Count -eq 0) {
        Write-Host "  (no assignments found for any target group)" -ForegroundColor DarkYellow
    }
    else {
        foreach ($t in ($typeSummary.Keys | Sort-Object)) {
            $inc = $typeSummary[$t].Include
            $exc = $typeSummary[$t].Exclude
            $detail = if ($exc -gt 0) { "$inc include, $exc exclude" } else { "$inc include" }
            Write-Host "  $($t): $detail" -ForegroundColor Gray
        }
    }

    # Per-group verbose summary
    $groupsWithAny = 0
    $totalMerged = 0
    foreach ($kvp in $groupAssignments.GetEnumerator()) {
        if ($kvp.Value.Count -gt 0) {
            $groupsWithAny++
            $totalMerged += $kvp.Value.Count
            Write-Verbose "[FINAL] Group $($kvp.Key): $($kvp.Value.Count) assignments"
        }
    }
    Write-Verbose "[FINAL] Total: $totalMerged assignments across $groupsWithAny/$($TargetGroupIds.Count) groups"

    return $groupAssignments
}

function New-HtmlReport {
    <#
    .SYNOPSIS
        Generates a modern HTML report with dark/light mode from group data.
        Uses [StringBuilder] for O(n) string construction instead of O(n^2) concatenation.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$GroupData,

        [Parameter(Mandatory = $true)]
        [string]$OutputFile,

        [Parameter(Mandatory = $true)]
        [string]$GroupPrefix
    )

    $totalGroups = $GroupData.Count
    $assignedGroups = 0
    $excludeOnlyGroups = 0
    $cleanupCandidates = 0
    $totalAssignments = 0
    $emptyGroups = 0
    $assignedMembershipGroups = 0
    $dynamicMembershipGroups = 0

    # Pre-calculate group statuses for summary
    foreach ($g in $GroupData) {
        $assignArr = @($g.Assignments)
        $totalAssignments += $assignArr.Count
        if ($g.MemberCount -eq 0) { $emptyGroups++ }
        $mType = if ($g.MembershipType) { $g.MembershipType } else { "Assigned" }
        if ($mType -eq "Dynamic") { $dynamicMembershipGroups++ } else { $assignedMembershipGroups++ }
        if ($assignArr.Count -eq 0) {
            $cleanupCandidates++
        }
        elseif (@($assignArr | Where-Object { $_.AssignmentType -eq 'Include' }).Count -eq 0) {
            # All assignments are Exclude - group is used only as an exclusion target
            $excludeOnlyGroups++
        }
        else {
            $assignedGroups++
        }
    }

    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $filterDescription = if ($GroupPrefix -eq 'AllGroups') {
        "Scope: <strong>All Groups</strong>"
    } else {
        "Filter: <strong>$([System.Web.HttpUtility]::HtmlEncode($GroupPrefix))*</strong>"
    }

    # Use StringBuilder for efficient HTML construction
    $sb = [System.Text.StringBuilder]::new(1MB)

    foreach ($group in ($GroupData | Sort-Object -Property DisplayName)) {
        $groupAssignArr = @($group.Assignments)
        $hasAssignments = $groupAssignArr.Count -gt 0
        $hasIncludes = @($groupAssignArr | Where-Object { $_.AssignmentType -eq 'Include' }).Count -gt 0
        $hasExcludes = @($groupAssignArr | Where-Object { $_.AssignmentType -eq 'Exclude' }).Count -gt 0

        if (-not $hasAssignments) {
            $statusClass = "status-cleanup"
            $statusText = "Cleanup Candidate"
            $statusIcon = "&#9888;"
        }
        elseif ($hasExcludes -and -not $hasIncludes) {
            $statusClass = "status-exclude-only"
            $statusText = "Exclude Only"
            $statusIcon = "&#9949;"
        }
        else {
            $statusClass = "status-assigned"
            $statusText = "In Use"
            $statusIcon = "&#9679;"
        }

        $assignmentsHtml = [System.Text.StringBuilder]::new(4096)
        if ($hasAssignments) {
            [void]$assignmentsHtml.Append(@"
                <div class="assignments-section">
                    <h4>Assignments ($($groupAssignArr.Count))</h4>
                    <table class="assignment-table">
                        <thead>
                            <tr>
                                <th>Policy Type</th>
                                <th>Policy Name</th>
                                <th>Direction</th>
                                <th>Filter</th>
                            </tr>
                        </thead>
                        <tbody>
"@)
            foreach ($assignment in $groupAssignArr) {
                $directionClass = if ($assignment.AssignmentType -eq "Exclude") { "direction-exclude" } else { "direction-include" }
                $filterDisplay = if ($assignment.FilterInfo) { $assignment.FilterInfo } else { "-" }
                [void]$assignmentsHtml.Append(@"
                            <tr>
                                <td><span class="policy-type-badge">$([System.Web.HttpUtility]::HtmlEncode($assignment.PolicyType))</span></td>
                                <td>$([System.Web.HttpUtility]::HtmlEncode($assignment.PolicyName))</td>
                                <td><span class="direction-badge $directionClass">$($assignment.AssignmentType)</span></td>
                                <td class="filter-cell">$([System.Web.HttpUtility]::HtmlEncode($filterDisplay))</td>
                            </tr>
"@)
            }
            [void]$assignmentsHtml.Append(@"
                        </tbody>
                    </table>
                </div>
"@)
        }
        else {
            [void]$assignmentsHtml.Append(@"
                <div class="no-assignments">
                    <span class="no-assignments-icon">&#128465;</span>
                    <p>No Intune assignments found. This group is a <strong>cleanup candidate</strong>.</p>
                </div>
"@)
        }

        $descriptionDisplay = if ($group.Description) { [System.Web.HttpUtility]::HtmlEncode($group.Description) } else { "<em>No description set</em>" }
        $createdByDisplay = [System.Web.HttpUtility]::HtmlEncode($group.CreatedBy)
        $createdDateDisplay = if ($group.CreatedDate -and $group.CreatedDate -ne "N/A") {
            try { (Get-Date $group.CreatedDate -Format "yyyy-MM-dd HH:mm") } catch { $group.CreatedDate }
        } else { "N/A" }
        $membershipType = if ($group.MembershipType) { $group.MembershipType } else { "Assigned" }

        # Format member count display
        $memberCountDisplay = if ($group.MemberCount -ge 0) { $group.MemberCount.ToString("N0") } else { "N/A" }
        $memberCountClass = ""
        if ($group.MemberCount -eq 0) { $memberCountClass = " member-count-zero" }

        # Data attributes for JS filtering
        $dataEmpty = if ($group.MemberCount -eq 0) { 'true' } else { 'false' }
        $dataMembership = if ($membershipType -eq 'Dynamic') { 'dynamic' } else { 'assigned' }

        [void]$sb.Append(@"
            <div class="group-card $statusClass" data-empty="$dataEmpty" data-membership="$dataMembership">
                <div class="card-header">
                    <div class="card-title-section">
                        <h3>$([System.Web.HttpUtility]::HtmlEncode($group.DisplayName))</h3>
                        <span class="status-badge $statusClass">$statusIcon $statusText</span>
                    </div>
                    <button class="expand-btn" onclick="toggleCard(this)" aria-label="Expand card">
                        <svg width="20" height="20" viewBox="0 0 20 20" fill="none"><path d="M5 8l5 5 5-5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
                    </button>
                </div>
                <div class="card-meta">
                    <div class="meta-item">
                        <span class="meta-label">Members</span>
                        <span class="meta-value$memberCountClass">$memberCountDisplay</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Membership</span>
                        <span class="meta-value">$membershipType</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Created By</span>
                        <span class="meta-value">$createdByDisplay</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Created Date</span>
                        <span class="meta-value">$createdDateDisplay</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Group ID</span>
                        <span class="meta-value mono">$($group.Id)</span>
                    </div>
                </div>
                <div class="card-body collapsed">
                    <div class="description-section">
                        <h4>Description</h4>
                        <p>$descriptionDisplay</p>
                    </div>
                    $($assignmentsHtml.ToString())
                </div>
            </div>
"@)
    }

    $groupCardsHtml = $sb.ToString()

    $html = @"
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Entra Group Assignment Report - $([System.Web.HttpUtility]::HtmlEncode($GroupPrefix))</title>
    <style>
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --bg-card: #ffffff;
            --bg-table-header: #f1f3f5;
            --bg-table-row-hover: #f8f9fa;
            --text-primary: #1a1a2e;
            --text-secondary: #6c757d;
            --text-muted: #adb5bd;
            --border-color: #e9ecef;
            --border-card: #dee2e6;
            --accent-blue: #4361ee;
            --accent-blue-light: #eef2ff;
            --accent-green: #2d9d78;
            --accent-green-light: #ecfdf5;
            --accent-orange: #e67e22;
            --accent-orange-light: #fff7ed;
            --accent-red: #ef4444;
            --accent-red-light: #fef2f2;
            --accent-purple: #8b5cf6;
            --accent-purple-light: #f5f3ff;
            --shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
            --shadow-md: 0 4px 6px -1px rgba(0,0,0,0.07), 0 2px 4px -2px rgba(0,0,0,0.05);
            --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.08), 0 4px 6px -4px rgba(0,0,0,0.05);
            --radius: 12px;
            --radius-sm: 8px;
            --transition: 0.2s ease;
        }

        [data-theme="dark"] {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --bg-table-header: #334155;
            --bg-table-row-hover: #334155;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --border-color: #334155;
            --border-card: #334155;
            --accent-blue: #818cf8;
            --accent-blue-light: #1e1b4b;
            --accent-green: #34d399;
            --accent-green-light: #064e3b;
            --accent-orange: #fbbf24;
            --accent-orange-light: #451a03;
            --accent-red: #f87171;
            --accent-red-light: #450a0a;
            --accent-purple: #a78bfa;
            --accent-purple-light: #2e1065;
            --shadow-sm: 0 1px 2px rgba(0,0,0,0.3);
            --shadow-md: 0 4px 6px -1px rgba(0,0,0,0.4);
            --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.5);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            transition: background var(--transition), color var(--transition);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem 1.5rem;
        }

        /* Header */
        .report-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 2rem;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .report-header h1 {
            font-size: 1.75rem;
            font-weight: 700;
            letter-spacing: -0.02em;
        }

        .report-header h1 span {
            color: var(--accent-blue);
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .report-date {
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        /* Theme Toggle */
        .theme-toggle {
            position: relative;
            width: 56px;
            height: 28px;
            background: var(--border-color);
            border-radius: 14px;
            cursor: pointer;
            border: none;
            transition: background var(--transition);
            flex-shrink: 0;
        }

        .theme-toggle::after {
            content: '';
            position: absolute;
            top: 3px;
            left: 3px;
            width: 22px;
            height: 22px;
            background: var(--bg-card);
            border-radius: 50%;
            transition: transform var(--transition);
            box-shadow: var(--shadow-sm);
        }

        [data-theme="dark"] .theme-toggle::after {
            transform: translateX(28px);
        }

        .theme-toggle-icon {
            position: absolute;
            top: 50%;
            transform: translateY(-50%);
            font-size: 14px;
            transition: opacity var(--transition);
        }

        .theme-toggle-icon.sun { left: 7px; }
        .theme-toggle-icon.moon { right: 7px; }

        [data-theme="light"] .theme-toggle-icon.sun { opacity: 1; }
        [data-theme="light"] .theme-toggle-icon.moon { opacity: 0.3; }
        [data-theme="dark"] .theme-toggle-icon.sun { opacity: 0.3; }
        [data-theme="dark"] .theme-toggle-icon.moon { opacity: 1; }

        /* Summary Cards */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .summary-card {
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            border-radius: var(--radius);
            padding: 1.25rem;
            box-shadow: var(--shadow-sm);
            transition: all var(--transition);
        }

        .summary-card:hover {
            box-shadow: var(--shadow-md);
            transform: translateY(-1px);
        }

        .summary-card .value {
            font-size: 2rem;
            font-weight: 700;
            line-height: 1.2;
        }

        .summary-card .label {
            font-size: 0.8rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 0.25rem;
        }

        .summary-card.total .value { color: var(--accent-blue); }
        .summary-card.assigned .value { color: var(--accent-green); }
        .summary-card.cleanup .value { color: var(--accent-orange); }
        .summary-card.empty .value { color: var(--accent-red); }
        .summary-card.membership-assigned { border-top: 3px solid #6366f1; }
        .summary-card.membership-assigned .value { color: #6366f1; }
        .summary-card.membership-dynamic { border-top: 3px solid #0ea5e9; }
        .summary-card.membership-dynamic .value { color: #0ea5e9; }

        /* Member count zero highlight */
        .member-count-zero {
            color: var(--accent-red) !important;
            font-weight: 600;
        }

        /* Filter Bar */
        .filter-bar {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }

        .filter-btn {
            padding: 0.5rem 1rem;
            border: 1px solid var(--border-color);
            border-radius: 20px;
            background: var(--bg-card);
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 500;
            transition: all var(--transition);
        }

        .filter-btn:hover {
            border-color: var(--accent-blue);
            color: var(--accent-blue);
        }

        .filter-btn.active {
            background: var(--accent-blue);
            color: #fff;
            border-color: var(--accent-blue);
        }

        .search-input {
            flex: 1;
            min-width: 200px;
            padding: 0.5rem 1rem;
            border: 1px solid var(--border-color);
            border-radius: 20px;
            background: var(--bg-card);
            color: var(--text-primary);
            font-size: 0.85rem;
            outline: none;
            transition: border-color var(--transition);
        }

        .search-input:focus {
            border-color: var(--accent-blue);
        }

        .search-input::placeholder {
            color: var(--text-muted);
        }

        /* Group Cards */
        .group-card {
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            border-radius: var(--radius);
            margin-bottom: 1rem;
            box-shadow: var(--shadow-sm);
            overflow: hidden;
            transition: all var(--transition);
        }

        .group-card:hover {
            box-shadow: var(--shadow-md);
        }

        .group-card.status-assigned {
            border-left: 4px solid var(--accent-green);
        }

        .group-card.status-cleanup {
            border-left: 4px solid var(--accent-orange);
        }

        .group-card.status-exclude-only {
            border-left: 4px solid var(--accent-purple);
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.25rem;
            cursor: pointer;
        }

        .card-title-section {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex-wrap: wrap;
        }

        .card-title-section h3 {
            font-size: 1rem;
            font-weight: 600;
        }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.3rem;
            padding: 0.2rem 0.6rem;
            border-radius: 12px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }

        .status-badge.status-assigned {
            background: var(--accent-green-light);
            color: var(--accent-green);
        }

        .status-badge.status-cleanup {
            background: var(--accent-orange-light);
            color: var(--accent-orange);
        }

        .status-badge.status-exclude-only {
            background: var(--accent-purple-light);
            color: var(--accent-purple);
        }

        .expand-btn {
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            padding: 0.25rem;
            border-radius: 6px;
            transition: all var(--transition);
            display: flex;
            align-items: center;
        }

        .expand-btn:hover {
            background: var(--bg-secondary);
            color: var(--text-primary);
        }

        .expand-btn.expanded svg {
            transform: rotate(180deg);
        }

        .expand-btn svg {
            transition: transform var(--transition);
        }

        .card-meta {
            display: flex;
            gap: 1.5rem;
            padding: 0 1.25rem 0.75rem;
            flex-wrap: wrap;
        }

        .meta-item {
            display: flex;
            flex-direction: column;
        }

        .meta-label {
            font-size: 0.7rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .meta-value {
            font-size: 0.85rem;
            color: var(--text-secondary);
        }

        .meta-value.mono {
            font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
            font-size: 0.75rem;
        }

        .card-body {
            padding: 0 1.25rem 1.25rem;
            border-top: 1px solid var(--border-color);
        }

        .card-body.collapsed {
            display: none;
        }

        .description-section {
            margin-top: 1rem;
            margin-bottom: 1rem;
        }

        .description-section h4,
        .assignments-section h4 {
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 0.5rem;
        }

        .description-section p {
            color: var(--text-secondary);
            font-size: 0.9rem;
            background: var(--bg-secondary);
            padding: 0.75rem 1rem;
            border-radius: var(--radius-sm);
        }

        /* Assignment Table */
        .assignment-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            border-radius: var(--radius-sm);
            overflow: hidden;
            border: 1px solid var(--border-color);
            font-size: 0.85rem;
        }

        .assignment-table thead th {
            background: var(--bg-table-header);
            padding: 0.6rem 0.75rem;
            text-align: left;
            font-weight: 600;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--border-color);
        }

        .assignment-table tbody td {
            padding: 0.6rem 0.75rem;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
        }

        .assignment-table tbody tr:last-child td {
            border-bottom: none;
        }

        .assignment-table tbody tr:hover {
            background: var(--bg-table-row-hover);
        }

        .policy-type-badge {
            display: inline-block;
            padding: 0.15rem 0.5rem;
            background: var(--accent-blue-light);
            color: var(--accent-blue);
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 500;
            white-space: nowrap;
        }

        .direction-badge {
            display: inline-block;
            padding: 0.15rem 0.5rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
        }

        .direction-include {
            background: var(--accent-green-light);
            color: var(--accent-green);
        }

        .direction-exclude {
            background: var(--accent-red-light);
            color: var(--accent-red);
        }

        .filter-cell {
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        /* No assignments */
        .no-assignments {
            text-align: center;
            padding: 2rem 1rem;
            color: var(--text-muted);
        }

        .no-assignments-icon {
            font-size: 2.5rem;
            display: block;
            margin-bottom: 0.5rem;
        }

        .no-assignments p {
            font-size: 0.9rem;
        }

        /* Footer */
        .report-footer {
            text-align: center;
            padding: 2rem 0 1rem;
            color: var(--text-muted);
            font-size: 0.8rem;
            border-top: 1px solid var(--border-color);
            margin-top: 2rem;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .container { padding: 1rem; }
            .report-header { flex-direction: column; }
            .card-meta { gap: 1rem; }
            .summary-grid { grid-template-columns: 1fr; }
            .filter-bar { flex-direction: column; }
            .assignment-table { font-size: 0.75rem; }
        }

        /* Print styles */
        @media print {
            .theme-toggle, .filter-bar, .expand-btn { display: none !important; }
            .card-body.collapsed { display: block !important; }
            .group-card { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="report-header">
            <div>
                <h1>Entra Group <span>Assignment Report</span></h1>
                <p class="report-date">Generated: $reportDate | $filterDescription</p>
            </div>
            <div class="header-actions">
                <button class="theme-toggle" onclick="toggleTheme()" aria-label="Toggle dark mode">
                    <span class="theme-toggle-icon sun">&#9728;</span>
                    <span class="theme-toggle-icon moon">&#9790;</span>
                </button>
            </div>
        </header>

        <section class="summary-grid">
            <div class="summary-card total">
                <div class="value">$totalGroups</div>
                <div class="label">Total Groups</div>
            </div>
            <div class="summary-card assigned">
                <div class="value">$assignedGroups</div>
                <div class="label">Included (In Use)</div>
            </div>
            <div class="summary-card" style="border-top: 3px solid var(--accent-purple);">
                <div class="value" style="color: var(--accent-purple);">$excludeOnlyGroups</div>
                <div class="label">Exclude Only</div>
            </div>
            <div class="summary-card cleanup">
                <div class="value">$cleanupCandidates</div>
                <div class="label">Cleanup Candidates</div>
            </div>
            <div class="summary-card empty">
                <div class="value">$emptyGroups</div>
                <div class="label">Empty Groups (0 Members)</div>
            </div>
            <div class="summary-card" style="border-top: 3px solid var(--accent-blue);">
                <div class="value" style="color: var(--accent-blue);">$totalAssignments</div>
                <div class="label">Total Assignments</div>
            </div>
            <div class="summary-card membership-assigned">
                <div class="value">$assignedMembershipGroups</div>
                <div class="label">Assigned Groups</div>
            </div>
            <div class="summary-card membership-dynamic">
                <div class="value">$dynamicMembershipGroups</div>
                <div class="label">Dynamic Groups</div>
            </div>
        </section>

        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterGroups('all', this)">All</button>
            <button class="filter-btn" onclick="filterGroups('assigned', this)">In Use</button>
            <button class="filter-btn" onclick="filterGroups('exclude-only', this)">Exclude Only</button>
            <button class="filter-btn" onclick="filterGroups('cleanup', this)">Cleanup Candidates</button>
            <button class="filter-btn" onclick="filterGroups('empty', this)">Empty Groups</button>
            <button class="filter-btn" onclick="filterGroups('membership-assigned', this)">Assigned</button>
            <button class="filter-btn" onclick="filterGroups('membership-dynamic', this)">Dynamic</button>
            <input type="text" class="search-input" placeholder="Search groups..." oninput="searchGroups(this.value)">
        </div>

        <section id="group-list">
            $groupCardsHtml
        </section>

        <footer class="report-footer">
            <p>Entra Group Assignment Report | Generated by ReviewGroupAssignments.ps1</p>
        </footer>
    </div>

    <script>
        // Theme toggle
        function toggleTheme() {
            const html = document.documentElement;
            const current = html.getAttribute('data-theme');
            const next = current === 'light' ? 'dark' : 'light';
            html.setAttribute('data-theme', next);
            localStorage.setItem('theme', next);
        }

        // Load saved theme
        (function() {
            const saved = localStorage.getItem('theme');
            if (saved) {
                document.documentElement.setAttribute('data-theme', saved);
            } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
                document.documentElement.setAttribute('data-theme', 'dark');
            }
        })();

        // Expand/collapse card
        function toggleCard(btn) {
            const card = btn.closest('.group-card');
            const body = card.querySelector('.card-body');
            body.classList.toggle('collapsed');
            btn.classList.toggle('expanded');
        }

        // Filter groups
        function filterGroups(type, btn) {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            document.querySelectorAll('.group-card').forEach(card => {
                if (type === 'all') {
                    card.style.display = '';
                } else if (type === 'assigned') {
                    card.style.display = card.classList.contains('status-assigned') ? '' : 'none';
                } else if (type === 'exclude-only') {
                    card.style.display = card.classList.contains('status-exclude-only') ? '' : 'none';
                } else if (type === 'cleanup') {
                    card.style.display = card.classList.contains('status-cleanup') ? '' : 'none';
                } else if (type === 'empty') {
                    card.style.display = card.dataset.empty === 'true' ? '' : 'none';
                } else if (type === 'membership-assigned') {
                    card.style.display = card.dataset.membership === 'assigned' ? '' : 'none';
                } else if (type === 'membership-dynamic') {
                    card.style.display = card.dataset.membership === 'dynamic' ? '' : 'none';
                }
            });
        }

        // Search groups
        function searchGroups(query) {
            const q = query.toLowerCase();
            document.querySelectorAll('.group-card').forEach(card => {
                const text = card.textContent.toLowerCase();
                card.style.display = text.includes(q) ? '' : 'none';
            });
            // Reset filter buttons
            if (q.length > 0) {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            } else {
                document.querySelector('.filter-btn').classList.add('active');
            }
        }

        // Click header to expand
        document.querySelectorAll('.card-header').forEach(header => {
            header.addEventListener('click', function(e) {
                if (e.target.closest('.expand-btn')) return;
                const btn = this.querySelector('.expand-btn');
                toggleCard(btn);
            });
        });
    </script>
</body>
</html>
"@

    # Add System.Web assembly for HTML encoding (already loaded in .NET)
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    $html | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
    Write-Host "HTML report saved to: $OutputFile" -ForegroundColor Green
}

#endregion Functions

#region Main Script

# Check prerequisites
Write-Host "`n=== Entra Group Assignment Report ===" -ForegroundColor Cyan
if ($GroupFilter) {
    Write-Host "Filter: $GroupFilter* (startsWith)`n" -ForegroundColor Cyan
} else {
    Write-Host "Filter: None - scanning ALL groups in tenant`n" -ForegroundColor Cyan
}

if (-not (Install-RequiredModules)) {
    Write-Error "Failed to install required modules. Exiting."
    exit 1
}

# Connect to Microsoft Graph
$requiredScopes = @(
    "Group.Read.All",
    "GroupMember.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementApps.Read.All",
    "DeviceManagementServiceConfig.Read.All",
    "DeviceManagementRBAC.Read.All",
    "AuditLog.Read.All"
)

$context = Get-MgContext
if (-not $context) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome
    $context = Get-MgContext
}
else {
    # Verify the existing connection has all required scopes; reconnect if any are missing
    $missingScopes = $requiredScopes | Where-Object { $context.Scopes -notcontains $_ }
    if ($missingScopes) {
        Write-Warning "Current Graph session is missing required scope(s): $($missingScopes -join ', ')"
        Write-Host "Re-connecting to Microsoft Graph with required scopes..." -ForegroundColor Yellow
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome
        $context = Get-MgContext
    }
}

if (-not $context) {
    Write-Error "Failed to connect to Microsoft Graph. Exiting."
    exit 1
}

Write-Host "Connected as: $($context.Account)" -ForegroundColor Green

# Load System.Web for HTML encoding
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# Validate / create output directory
if (-not (Test-Path -Path $OutputPath -PathType Container)) {
    try {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Host "Created output directory: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Cannot create output directory '$OutputPath': $_"
        exit 1
    }
}

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Step 1: Get groups (optionally filtered by prefix)
# Uses ConsistencyLevel:eventual + $count for reliable startsWith in large directories (350K+ groups)
$consistencyHeaders = @{ 'ConsistencyLevel' = 'eventual' }

if ($GroupFilter) {
    Write-Host "`n[1/5] Searching for groups starting with '$GroupFilter'..." -ForegroundColor Yellow
    $graphFilter = "startsWith(displayName, '$GroupFilter')"
    $groupUri = "https://graph.microsoft.com/v1.0/groups?`$filter=$graphFilter&`$select=id,displayName,description,groupTypes,membershipRule,createdDateTime&`$orderby=displayName&`$count=true&`$top=999"
} else {
    Write-Host "`n[1/5] Fetching ALL groups (no filter applied)..." -ForegroundColor Yellow
    $groupUri = "https://graph.microsoft.com/v1.0/groups?`$select=id,displayName,description,groupTypes,membershipRule,createdDateTime&`$orderby=displayName&`$count=true&`$top=999"
}

$groups = Invoke-MgGraphRequestWithPagination -Uri $groupUri -Headers $consistencyHeaders

if ($groups.Count -eq 0) {
    if ($GroupFilter) {
        Write-Host "No groups found with prefix '$GroupFilter'. Exiting." -ForegroundColor Red
    } else {
        Write-Host "No groups found in the tenant. Exiting." -ForegroundColor Red
    }
    exit 0
}

Write-Host "Found $($groups.Count) group(s) in $([Math]::Round($stopwatch.Elapsed.TotalSeconds, 1))s" -ForegroundColor Green

# Build HashSet of target group IDs for O(1) lookup
$targetGroupIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($group in $groups) {
    [void]$targetGroupIds.Add($group.id)
}

# Step 2: Batch fetch member counts (20 per batch request via Graph $batch API)
Write-Host "`n[2/5] Fetching member counts (batched, $($groups.Count) groups)..." -ForegroundColor Yellow
$memberCounts = Get-GroupMemberCountBatch -Groups $groups
Write-Host "Member counts retrieved in $([Math]::Round($stopwatch.Elapsed.TotalSeconds, 1))s" -ForegroundColor Green

# Step 3: Batch fetch audit logs (20 per batch request via Graph $batch API)
Write-Host "`n[3/5] Fetching audit trails (batched, $($groups.Count) groups)..." -ForegroundColor Yellow
$auditResults = Get-GroupCreationAuditBatch -Groups $groups
Write-Host "Audit logs retrieved in $([Math]::Round($stopwatch.Elapsed.TotalSeconds, 1))s" -ForegroundColor Green

# Step 4: Fetch ALL Intune assignments in one pass (fetch-once/match-all pattern)
# Policies are fetched with $expand=assignments where supported, then matched against HashSet
Write-Host "`n[4/5] Fetching all Intune assignments (parallel, $MaxParallelThreads threads)..." -ForegroundColor Yellow
$assignmentStartTime = $stopwatch.Elapsed
$allAssignments = Get-AllIntuneAssignments -TargetGroupIds $targetGroupIds -MaxParallel $MaxParallelThreads
$assignmentDuration = ($stopwatch.Elapsed - $assignmentStartTime).TotalSeconds
Write-Host "Intune assignments fetched in $([Math]::Round($assignmentDuration, 1))s" -ForegroundColor Green

# Step 5: Assemble results
Write-Host "`n[5/5] Assembling group data..." -ForegroundColor Yellow
$groupData = [System.Collections.Generic.List[PSCustomObject]]::new($groups.Count)

foreach ($group in $groups) {
    $membershipType = "Assigned"
    if ($group.groupTypes -contains "DynamicMembership") {
        $membershipType = "Dynamic"
    }

    if ($auditResults.ContainsKey($group.id)) {
        $auditInfo = $auditResults[$group.id]
    }
    else {
        $auditInfo = @{ CreatedBy = "Unknown (audit log expired or unavailable)"; CreatedDate = "N/A"; CorrelationId = "N/A" }
    }

    # Direct assignment avoids pipeline enumeration that unwraps single-item lists
    if ($allAssignments.ContainsKey($group.id)) {
        $assignments = $allAssignments[$group.id]
    }
    else {
        $assignments = @()
    }
    # Ensure assignments is always an array for consistent .Count behavior
    $assignments = @($assignments)

    $createdDate = $group.createdDateTime
    if ($auditInfo.CreatedDate -ne "N/A") { $createdDate = $auditInfo.CreatedDate }

    # Get member count (-1 means error fetching)
    $groupMemberCount = if ($memberCounts.ContainsKey($group.id)) { $memberCounts[$group.id] } else { -1 }

    $groupData.Add([PSCustomObject]@{
        Id             = $group.id
        DisplayName    = $group.displayName
        Description    = $group.description
        MembershipType = $membershipType
        MembershipRule = $group.membershipRule
        CreatedDate    = $createdDate
        CreatedBy      = $auditInfo.CreatedBy
        MemberCount    = $groupMemberCount
        Assignments    = $assignments
    })
}

# Generate HTML Report
Write-Host "`nGenerating HTML report..." -ForegroundColor Yellow
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportSuffix = if ($GroupFilter) { $GroupFilter } else { "AllGroups" }
$outputFile = Join-Path -Path $OutputPath -ChildPath "EntraGroupReport_${reportSuffix}_$timestamp.html"

New-HtmlReport -GroupData $groupData -OutputFile $outputFile -GroupPrefix $reportSuffix

$stopwatch.Stop()
$totalTime = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 1)

# Summary
$assignedCount = 0
$excludeOnlyCount = 0
$cleanupCount = 0
$totalAssignmentCount = 0

foreach ($g in $groupData) {
    $gAssignArr = @($g.Assignments)
    $totalAssignmentCount += $gAssignArr.Count
    if ($gAssignArr.Count -eq 0) {
        $cleanupCount++
    }
    elseif (@($gAssignArr | Where-Object { $_.AssignmentType -eq 'Include' }).Count -eq 0) {
        $excludeOnlyCount++
    }
    else {
        $assignedCount++
    }
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Total groups found:       $($groupData.Count)" -ForegroundColor White
Write-Host "Groups with includes:     $assignedCount" -ForegroundColor Green
Write-Host "Exclude-only groups:      $excludeOnlyCount" -ForegroundColor Magenta
Write-Host "Cleanup candidates:       $cleanupCount" -ForegroundColor Yellow
Write-Host "Total assignments:        $totalAssignmentCount" -ForegroundColor White
Write-Host "Execution time:           ${totalTime}s" -ForegroundColor White
Write-Host "`nReport: $outputFile" -ForegroundColor Cyan

# Open the report in default browser
try {
    Start-Process $outputFile
    Write-Host "Report opened in browser." -ForegroundColor Green
}
catch {
    Write-Host "Could not auto-open report. Please open manually: $outputFile" -ForegroundColor Yellow
}

#endregion Main Script
