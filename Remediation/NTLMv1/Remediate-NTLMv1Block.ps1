<#
.SYNOPSIS
    Configures NTLMv1 blocking for Windows 11 25H2+ compliance

.DESCRIPTION
    This remediation script configures the BlockNtlmv1SSO registry setting to control NTLMv1-derived 
    credentials for Single Sign-On in preparation for Windows 11 25H2 and Windows Server 2025.
    
    The script performs the following actions:
    1. Creates the registry path if it doesn't exist
    2. Sets BlockNtlmv1SSO to the specified mode (default: Audit mode)
    3. Verifies the configuration was applied successfully
    4. Logs all operations to Intune Management Extension logs
    
    Starting with Windows 11 24H2 and Windows Server 2025, Microsoft is removing NTLMv1 protocol
    and introducing BlockNtlmv1SSO to control NTLMv1-derived credentials for SSO (e.g., MS-CHAPv2).
    
    Registry Values:
    - 0 = Audit mode (logs Event ID 4024 but allows NTLMv1) - RECOMMENDED FIRST
    - 1 = Enforce mode (blocks NTLMv1 and logs Event ID 4025)
    
    Note: If Credential Guard is enabled, NTLMv1 is already blocked and this setting does not apply.
    
    RECOMMENDED APPROACH:
    1. Start with Audit mode (0) to identify applications using NTLMv1
    2. Review Event ID 4024 in Microsoft-Windows-NTLM/Operational log
    3. Address identified applications/services
    4. Switch to Enforce mode (1) after validation

.PARAMETER Mode
    The BlockNtlmv1SSO mode to configure:
    - Audit (0): Log NTLMv1 usage but allow it
    - Enforce (1): Block NTLMv1 usage
    Default: Enforce

.EXAMPLE
    .\Remediate-NTLMv1Block.ps1
    Configures BlockNtlmv1SSO in Audit mode (0)

.EXAMPLE
    .\Remediate-NTLMv1Block.ps1 -Mode Enforce
    Configures BlockNtlmv1SSO in Enforce mode (1)

.NOTES
    Version:        1.0
    Author:         Mattias Melkersen
    Creation Date:  2026-02-04
    
    CHANGELOG
    ---------------
    2026-02-04 - v1.0 - Initial version for NTLMv1 compliance remediation
    
    References:
    - https://support.microsoft.com/en-us/topic/upcoming-changes-to-ntlmv1-in-windows-11-version-24h2-and-windows-server-2025-c0554217-cdbc-420f-b47c-e02b2db49b2e
    
    Exit Codes:
    - 0 = Success (BlockNtlmv1SSO configured and verified)
    - 1 = Failure (Unable to configure BlockNtlmv1SSO)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Audit", "Enforce")]
    [string]$Mode = "Audit"
)

#region Logging Configuration
[string]$LogFile = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\RemediationByIntune-NTLMv1Block.log"
[string]$ScriptName = "REMEDIATE"
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

#region Main Remediation Logic
try {
    Write-Log -Message "========== REMEDIATION STARTED ==========" -Level "INFO"
    Write-Log -Message "Script Version: 1.0" -Level "INFO"
    Write-Log -Message "Computer: $env:COMPUTERNAME | User: $env:USERNAME" -Level "INFO"
    Write-Log -Message "OS: $((Get-WmiObject Win32_OperatingSystem).Caption) - Build: $((Get-WmiObject Win32_OperatingSystem).BuildNumber)" -Level "INFO"
    Write-Log -Message "Remediation Mode: $Mode" -Level "INFO"
    
    # Define registry configuration
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\msv1_0"
    $regName = "BlockNtlmv1SSO"
    $regValue = if ($Mode -eq "Enforce") { 1 } else { 0 }
    $regType = "DWord"
    
    Write-Log -Message "Registry Configuration:" -Level "INFO"
    Write-Log -Message "  Path: $regPath" -Level "INFO"
    Write-Log -Message "  Name: $regName" -Level "INFO"
    Write-Log -Message "  Value: $regValue ($Mode Mode)" -Level "INFO"
    Write-Log -Message "  Type: $regType" -Level "INFO"
    
    # Create registry path if it doesn't exist
    if (-not (Test-Path $regPath)) {
        Write-Log -Message "Creating registry path: $regPath" -Level "INFO"
        try {
            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
            Write-Log -Message "Registry path created successfully" -Level "SUCCESS"
        }
        catch {
            Write-Log -Message "Failed to create registry path: $($_.Exception.Message)" -Level "ERROR"
            Write-Host "FAILED: Unable to create registry path"
            Write-Log -Message "Remediation Result: FAILED (exit 1)" -Level "ERROR"
            Write-Log -Message "========== REMEDIATION COMPLETED ==========" -Level "INFO"
            exit 1
        }
    }
    else {
        Write-Log -Message "Registry path already exists: $regPath" -Level "INFO"
    }
    
    # Set the registry value
    Write-Log -Message "Setting BlockNtlmv1SSO registry value..." -Level "INFO"
    try {
        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type $regType -Force -ErrorAction Stop
        Write-Log -Message "Registry value set successfully" -Level "SUCCESS"
    }
    catch {
        Write-Log -Message "Failed to set registry value: $($_.Exception.Message)" -Level "ERROR"
        Write-Host "FAILED: Unable to set registry value"
        Write-Log -Message "Remediation Result: FAILED (exit 1)" -Level "ERROR"
        Write-Log -Message "========== REMEDIATION COMPLETED ==========" -Level "INFO"
        exit 1
    }
    
    # Verify the registry value
    Write-Log -Message "Verifying registry configuration..." -Level "INFO"
    try {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).$regName
        
        if ($currentValue -eq $regValue) {
            Write-Log -Message "Registry value verified: $currentValue ($Mode Mode)" -Level "SUCCESS"
            Write-Log -Message "BlockNtlmv1SSO successfully configured" -Level "SUCCESS"
            
            if ($Mode -eq "Audit") {
                Write-Log -Message "RECOMMENDATION: Monitor Event ID 4024 in Microsoft-Windows-NTLM/Operational log" -Level "INFO"
                Write-Log -Message "RECOMMENDATION: After validation, switch to Enforce mode to block NTLMv1" -Level "INFO"
                Write-Host "SUCCESS: BlockNtlmv1SSO configured in Audit mode - Monitor Event ID 4024"
            }
            else {
                Write-Log -Message "NTLMv1 is now blocked - Event ID 4025 will be logged for blocked attempts" -Level "INFO"
                Write-Host "SUCCESS: BlockNtlmv1SSO configured in Enforce mode - NTLMv1 blocked"
            }
            
            Write-Log -Message "Remediation Result: SUCCESS (exit 0)" -Level "SUCCESS"
            Write-Log -Message "========== REMEDIATION COMPLETED ==========" -Level "INFO"
            exit 0
        }
        else {
            Write-Log -Message "Registry value mismatch!" -Level "ERROR"
            Write-Log -Message "  Expected: $regValue" -Level "ERROR"
            Write-Log -Message "  Actual: $currentValue" -Level "ERROR"
            Write-Host "FAILED: Registry value mismatch"
            Write-Log -Message "Remediation Result: FAILED (exit 1)" -Level "ERROR"
            Write-Log -Message "========== REMEDIATION COMPLETED ==========" -Level "INFO"
            exit 1
        }
    }
    catch {
        Write-Log -Message "Failed to verify registry value: $($_.Exception.Message)" -Level "ERROR"
        Write-Host "FAILED: Unable to verify registry configuration"
        Write-Log -Message "Remediation Result: FAILED (exit 1)" -Level "ERROR"
        Write-Log -Message "========== REMEDIATION COMPLETED ==========" -Level "INFO"
        exit 1
    }
}
catch {
    Write-Log -Message "Unexpected error during remediation: $($_.Exception.Message)" -Level "ERROR"
    Write-Log -Message "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    Write-Host "ERROR: $($_.Exception.Message)"
    Write-Log -Message "Remediation Result: ERROR (exit 1)" -Level "ERROR"
    Write-Log -Message "========== REMEDIATION COMPLETED ==========" -Level "INFO"
    exit 1
}
#endregion
