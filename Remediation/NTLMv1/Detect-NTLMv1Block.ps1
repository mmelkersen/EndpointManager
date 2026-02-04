<#
.SYNOPSIS
    Detects if NTLMv1 blocking is configured for Windows 11 25H2+ compliance

.DESCRIPTION
    This detection script checks the BlockNtlmv1SSO registry setting to determine if NTLMv1-derived 
    credentials for Single Sign-On are properly configured (audit or enforce mode).
    
    The script performs the following checks:
    1. Verifies Credential Guard status (if enabled, device is already protected and compliant)
    2. Checks BlockNtlmv1SSO registry value in HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\msv1_0
    3. Queries Microsoft-Windows-NTLM/Operational event log for Event IDs 4024/4025 (last 30 days)
    4. Reports compliance status to Intune Management Extension
    
    Starting with Windows 11 24H2 and Windows Server 2025, Microsoft is removing NTLMv1 protocol
    and introducing BlockNtlmv1SSO to control NTLMv1-derived credentials for SSO (e.g., MS-CHAPv2).
    
    Registry Values:
    - 0 = Audit mode (logs Event ID 4024 but allows NTLMv1)
    - 1 = Enforce mode (blocks NTLMv1 and logs Event ID 4025)
    - Not Set = Non-compliant (will default to enforce in October 2026)
    
    Note: If Credential Guard is enabled, NTLMv1 is already blocked and BlockNtlmv1SSO does not apply.

.EXAMPLE
    .\Detect-NTLMv1Block.ps1
    Checks NTLMv1 blocking configuration and reports compliance status

.NOTES
    Version:        1.0
    Author:         Mattias Melkersen
    Creation Date:  2026-02-04
    
    CHANGELOG
    ---------------
    2026-02-04 - v1.0 - Initial version for NTLMv1 compliance detection
    
    References:
    - https://support.microsoft.com/en-us/topic/upcoming-changes-to-ntlmv1-in-windows-11-version-24h2-and-windows-server-2025-c0554217-cdbc-420f-b47c-e02b2db49b2e
    
    Exit Codes:
    - 0 = Compliant (BlockNtlmv1SSO is configured OR Credential Guard is enabled)
    - 1 = Non-compliant (BlockNtlmv1SSO is not configured AND Credential Guard is disabled)
#>

[CmdletBinding()]
param()

#region Logging Configuration
[string]$LogFile = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\RemediationByIntune-NTLMv1Block.log"
[string]$ScriptName = "DETECT"
[int]$MaxLogSizeMB = 4

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$TimeStamp [$ScriptName] [$Level] $Message"
    
    try {
        # Ensure log directory exists
        $LogDir = Split-Path -Path $LogFile -Parent
        if (-not (Test-Path $LogDir)) {
            New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
        }
        
        # Check log file size and rotate if necessary
        if (Test-Path $LogFile) {
            $LogFileSizeMB = (Get-Item $LogFile).Length / 1MB
            if ($LogFileSizeMB -ge $MaxLogSizeMB) {
                $BackupLog = "$LogFile.old"
                if (Test-Path $BackupLog) {
                    Remove-Item -Path $BackupLog -Force -ErrorAction SilentlyContinue
                }
                Rename-Item -Path $LogFile -NewName $BackupLog -Force -ErrorAction SilentlyContinue
                $RotationMsg = "$TimeStamp [SYSTEM] [INFO] Log rotated - Previous log archived to: $BackupLog"
                Add-Content -Path $LogFile -Value $RotationMsg -ErrorAction SilentlyContinue
            }
        }
        
        Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Silently fail if logging doesn't work - don't break script execution
    }
}
#endregion

#region Helper Functions
function Get-CredentialGuardStatus {
    <#
    .SYNOPSIS
        Checks if Credential Guard is enabled on the device
    .DESCRIPTION
        If Credential Guard is enabled, NTLMv1 is already blocked and BlockNtlmv1SSO setting does not apply.
        Checks both EnableVirtualizationBasedSecurity and LsaCfgFlags registry values.
    #>
    try {
        $deviceGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        
        $vbsEnabled = $false
        $credGuardEnabled = $false
        
        # Check if Virtualization Based Security is enabled
        if (Test-Path $deviceGuardPath) {
            $vbsValue = (Get-ItemProperty -Path $deviceGuardPath -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
            if ($vbsValue -eq 1) {
                $vbsEnabled = $true
                Write-Log -Message "Virtualization Based Security: Enabled" -Level "INFO"
            }
            else {
                Write-Log -Message "Virtualization Based Security: Disabled or not configured" -Level "INFO"
            }
        }
        
        # Check if Credential Guard is configured
        if (Test-Path $lsaPath) {
            $lsaCfgFlags = (Get-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -ErrorAction SilentlyContinue).LsaCfgFlags
            if ($lsaCfgFlags -eq 1 -or $lsaCfgFlags -eq 2) {
                $credGuardEnabled = $true
                $mode = if ($lsaCfgFlags -eq 1) { "Enabled with UEFI lock" } else { "Enabled without lock" }
                Write-Log -Message "Credential Guard: $mode" -Level "INFO"
            }
            else {
                Write-Log -Message "Credential Guard: Disabled or not configured" -Level "INFO"
            }
        }
        
        # Credential Guard is enabled if both VBS and LsaCfgFlags are properly configured
        $isEnabled = $vbsEnabled -and $credGuardEnabled
        
        return @{
            IsEnabled = $isEnabled
            VBSEnabled = $vbsEnabled
            CredGuardConfigured = $credGuardEnabled
        }
    }
    catch {
        Write-Log -Message "Error checking Credential Guard status: $($_.Exception.Message)" -Level "WARNING"
        return @{
            IsEnabled = $false
            VBSEnabled = $false
            CredGuardConfigured = $false
        }
    }
}

function Get-NTLMv1EventCount {
    <#
    .SYNOPSIS
        Queries the NTLM Operational log for NTLMv1 audit/block events
    .DESCRIPTION
        Counts Event ID 4024 (audit warnings) and Event ID 4025 (block errors) from the last 30 days
    #>
    try {
        Write-Log -Message "Querying Microsoft-Windows-NTLM/Operational log for Event IDs 4024 and 4025 (last 30 days)..." -Level "INFO"
        
        $ntlmEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-NTLM/Operational'
            ID = 4024, 4025
            StartTime = (Get-Date).AddDays(-30)
        } -ErrorAction SilentlyContinue
        
        $event4024Count = ($ntlmEvents | Where-Object { $_.Id -eq 4024 }).Count
        $event4025Count = ($ntlmEvents | Where-Object { $_.Id -eq 4025 }).Count
        
        Write-Log -Message "Event ID 4024 (Audit) count: $event4024Count" -Level "INFO"
        Write-Log -Message "Event ID 4025 (Block) count: $event4025Count" -Level "INFO"
        
        return @{
            Event4024Count = $event4024Count
            Event4025Count = $event4025Count
            TotalEvents = $event4024Count + $event4025Count
        }
    }
    catch {
        Write-Log -Message "Unable to query NTLM event log: $($_.Exception.Message)" -Level "WARNING"
        return @{
            Event4024Count = 0
            Event4025Count = 0
            TotalEvents = 0
        }
    }
}
#endregion

#region Main Detection Logic
try {
    Write-Log -Message "========== DETECTION STARTED ==========" -Level "INFO"
    Write-Log -Message "Script Version: 1.0" -Level "INFO"
    Write-Log -Message "Computer: $env:COMPUTERNAME | User: $env:USERNAME" -Level "INFO"
    Write-Log -Message "OS: $((Get-WmiObject Win32_OperatingSystem).Caption) - Build: $((Get-WmiObject Win32_OperatingSystem).BuildNumber)" -Level "INFO"
    
    # Check Credential Guard status first
    Write-Log -Message "Checking Credential Guard status..." -Level "INFO"
    $credGuardStatus = Get-CredentialGuardStatus
    
    if ($credGuardStatus.IsEnabled) {
        Write-Log -Message "Credential Guard is ENABLED - Device has additional NTLMv1 protection" -Level "INFO"
        Write-Log -Message "BlockNtlmv1SSO will still be enforced for defense in depth" -Level "INFO"
    }
    else {
        Write-Log -Message "Credential Guard is DISABLED - BlockNtlmv1SSO setting is critical" -Level "WARNING"
    }
    
    # Check BlockNtlmv1SSO registry setting - MUST be set to Enforce mode (1)
    Write-Log -Message "Checking BlockNtlmv1SSO registry configuration..." -Level "INFO"
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\msv1_0"
    $regName = "BlockNtlmv1SSO"
    $requiredValue = 1  # Enforce mode required
    
    if (Test-Path $regPath) {
        $blockNtlmValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
        
        if ($null -ne $blockNtlmValue) {
            $mode = switch ($blockNtlmValue) {
                0 { "Audit Mode" }
                1 { "Enforce Mode" }
                default { "Unknown Mode ($blockNtlmValue)" }
            }
            
            Write-Log -Message "BlockNtlmv1SSO current value: $mode (Value: $blockNtlmValue)" -Level "INFO"
            
            # Only Enforce mode (1) is compliant
            if ($blockNtlmValue -eq $requiredValue) {
                Write-Log -Message "BlockNtlmv1SSO is correctly set to Enforce mode" -Level "SUCCESS"
                
                # Query event logs for NTLMv1 usage
                $eventCounts = Get-NTLMv1EventCount
                
                if ($eventCounts.TotalEvents -gt 0) {
                    Write-Log -Message "WARNING: NTLMv1 usage detected in last 30 days - Review Event IDs 4024/4025" -Level "WARNING"
                    Write-Host "COMPLIANT: BlockNtlmv1SSO set to Enforce mode - WARNING: $($eventCounts.TotalEvents) NTLMv1 events detected"
                }
                else {
                    Write-Host "COMPLIANT: BlockNtlmv1SSO set to Enforce mode"
                }
                
                Write-Log -Message "Detection Result: COMPLIANT (exit 0)" -Level "SUCCESS"
                Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
                exit 0
            }
            else {
                Write-Log -Message "BlockNtlmv1SSO is NOT set to Enforce mode (currently: $mode)" -Level "WARNING"
                Write-Log -Message "Required value: 1 (Enforce Mode) | Current value: $blockNtlmValue" -Level "WARNING"
                Write-Host "NON-COMPLIANT: BlockNtlmv1SSO must be set to Enforce mode (1) - Remediation required"
                Write-Log -Message "Detection Result: NON-COMPLIANT (exit 1)" -Level "WARNING"
                Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
                exit 1
            }
        }
        else {
            Write-Log -Message "BlockNtlmv1SSO is NOT configured (registry value missing)" -Level "WARNING"
            Write-Log -Message "Required: Enforce mode (1) must be explicitly set" -Level "WARNING"
            Write-Host "NON-COMPLIANT: BlockNtlmv1SSO not configured - Remediation required"
            Write-Log -Message "Detection Result: NON-COMPLIANT (exit 1)" -Level "WARNING"
            Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
            exit 1
        }
    }
    else {
        Write-Log -Message "Registry path does not exist: $regPath" -Level "WARNING"
        Write-Host "NON-COMPLIANT: Registry path missing - Remediation required"
        Write-Log -Message "Detection Result: NON-COMPLIANT (exit 1)" -Level "WARNING"
        Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
        exit 1
    }
}
catch {
    Write-Log -Message "Unexpected error during detection: $($_.Exception.Message)" -Level "ERROR"
    Write-Log -Message "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    Write-Host "ERROR: $($_.Exception.Message)"
    Write-Log -Message "Detection Result: ERROR (exit 1)" -Level "ERROR"
    Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
    exit 1
}
#endregion
