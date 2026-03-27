<#
.SYNOPSIS
    Remediates Windows devices to enable Secure Boot certificate updates before June 2026 expiration.

.DESCRIPTION
    This remediation script configures devices to receive the new Secure Boot certificates before the June 2026 expiration.
    Microsoft Corporation KEK CA 2011 and Microsoft Corporation UEFI CA 2011 certificates expire in June 2026.
    Microsoft Windows Production PCA 2011 expires in October 2026.
    
    The script performs the following actions:
    - Checks if MicrosoftUpdateManagedOptIn is already correctly configured (idempotent)
    - Creates the Secureboot registry path if it doesn't exist
    - Sets MicrosoftUpdateManagedOptIn to 0x5944 (22852 decimal)
    - Verifies the registry value was set correctly
    - Outputs detailed status for Intune logging
    
    After remediation, Windows Update will automatically apply certificate updates through cumulative updates.
    
    Exit codes:
    - 0: Remediation successful (or already configured)
    - 1: Remediation failed

.EXAMPLE
    .\Remediate-SecureBootCertificateUpdate.ps1
    
    Configures the device to receive Secure Boot certificate updates and verifies the configuration.

.NOTES
    Version:        2.1
    Author:         Mattias Melkersen
    Creation Date:  2026-01-15
    
    CHANGELOG
    ---------------
    2026-02-18 - v2.1 - Enhanced logging in ALREADY_CONFIGURED path with cert progress and last boot time (MM)
    2026-02-18 - v2.0 - Made idempotent: skip registry write if OptIn already set correctly (MM)
                        Added CA2023 status to remediation output for progress tracking
    2026-01-15 - v1.0 - Initial version for June 2026 certificate expiration preparation (MM)
    
    References:
    - https://aka.ms/getsecureboot
    - https://techcommunity.microsoft.com/blog/windows-itpro-blog/act-now-secure-boot-certificates-expire-in-june-2026/4426856
    - https://support.microsoft.com/topic/enterprise-deployment-guidance-for-cve-2023-24932-88b8f034-20b7-4a45-80cb-c6049b0f9967
    
    Prerequisites:
    - Secure Boot must be enabled in BIOS/UEFI (this script cannot enable it)
    - Latest OEM firmware should be installed before certificate updates apply
    - Device must receive Windows Updates from Microsoft
#>

[CmdletBinding()]
param()

#region Logging Configuration
[string]$LogFile = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\SecureBootCertificateUpdate.log"
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
                # Rotate log: rename current to .old
                $BackupLog = "$LogFile.old"
                
                # Delete old backup if it exists (keep only N-1)
                if (Test-Path $BackupLog) {
                    Remove-Item -Path $BackupLog -Force -ErrorAction SilentlyContinue
                }
                
                # Rename current log to backup
                Rename-Item -Path $LogFile -NewName $BackupLog -Force -ErrorAction SilentlyContinue
                
                # Create new log file with rotation notice
                $RotationMsg = "$TimeStamp [SYSTEM] [INFO] Log rotated - Previous log archived to: $BackupLog"
                Add-Content -Path $LogFile -Value $RotationMsg -ErrorAction SilentlyContinue
            }
        }
        
        # Write to log file
        Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Silently fail if logging doesn't work - don't break script execution
    }
}
#endregion

#region Functions
function Get-SecureBootStatus {
    try {
        $secureBootEnabled = Confirm-SecureBootUEFI
        return $secureBootEnabled
    }
    catch {
        # If Confirm-SecureBootUEFI fails, try registry method
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
            if (Test-Path $regPath) {
                $value = (Get-ItemProperty -Path $regPath -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue).UEFISecureBootEnabled
                return ($value -eq 1)
            }
        }
        catch {
            return $false
        }
    }
    return $false
}
#endregion

#region Main Remediation Logic
try {
    Write-Log -Message "========== REMEDIATION STARTED ==========" -Level "INFO"
    Write-Log -Message "Script Version: 2.1" -Level "INFO"
    Write-Log -Message "Computer: $env:COMPUTERNAME | User: $env:USERNAME" -Level "INFO"
    Write-Log -Message "PowerShell: $($PSVersionTable.PSVersion) | Process: $(if ([Environment]::Is64BitProcess) {'64-bit'} else {'32-bit'})" -Level "INFO"
    
    # Verify Secure Boot is enabled
    Write-Log -Message "Verifying Secure Boot status..." -Level "INFO"
    $secureBootEnabled = Get-SecureBootStatus
    
    if (-not $secureBootEnabled) {
        Write-Log -Message "Secure Boot is DISABLED - Cannot apply remediation" -Level "ERROR"
        Write-Log -Message "Action Required: Enable Secure Boot in BIOS/UEFI firmware settings manually" -Level "ERROR"
        Write-Host "FAILED: Secure Boot DISABLED - Enable in BIOS/UEFI manually"
        Write-Log -Message "Remediation Result: FAILED (exit 1)" -Level "ERROR"
        Write-Log -Message "========== REMEDIATION COMPLETED ==========" -Level "INFO"
        exit 1
    }
    else {
        Write-Log -Message "Secure Boot is ENABLED - Proceeding with remediation" -Level "SUCCESS"
    }
    
    # Define registry configuration
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    $regName = "MicrosoftUpdateManagedOptIn"
    $regValue = 0x5944  # 22852 decimal - Microsoft recommended value
    $regType = "DWord"
    
    # -- Idempotency check: skip if already correctly configured --
    $existingValue = $null
    if (Test-Path $regPath) {
        $existingValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
    }
    
    if ($existingValue -eq $regValue) {
        Write-Log -Message "MicrosoftUpdateManagedOptIn already set to 0x$($regValue.ToString('X')) - No action needed" -Level "SUCCESS"
        
        # Collect certificate deployment progress for local diagnostic logging
        $servicingPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
        $ca2023Capable = (Get-ItemProperty -Path $servicingPath -Name "WindowsUEFICA2023Capable" -ErrorAction SilentlyContinue).WindowsUEFICA2023Capable
        $ca2023Text = switch ($ca2023Capable) {
            0 { "Not in DB" }
            1 { "In DB" }
            2 { "In DB and booting from 2023 cert" }
            default { "Pending" }
        }
        $remAvailUpdates = (Get-ItemProperty -Path $regPath -Name "AvailableUpdates" -ErrorAction SilentlyContinue).AvailableUpdates
        
        Write-Log -Message "--- Idempotency: Already Configured ---" -Level "INFO"
        Write-Log -Message "  OptIn: 0x$($regValue.ToString('X')) (correct)" -Level "SUCCESS"
        Write-Log -Message "  CA2023Capable: $ca2023Capable ($ca2023Text)" -Level "INFO"
        if ($null -ne $remAvailUpdates) {
            Write-Log -Message "  AvailableUpdates: 0x$($remAvailUpdates.ToString('X')) ($remAvailUpdates)" -Level "INFO"
        }
        else {
            Write-Log -Message "  AvailableUpdates: Key not present" -Level "INFO"
        }
        try {
            $remLastBoot = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
            Write-Log -Message "  Last Boot: $($remLastBoot.ToString('yyyy-MM-dd HH:mm:ss'))" -Level "INFO"
        }
        catch {}
        Write-Log -Message "--- End Idempotency Check ---" -Level "INFO"
        
        Write-Host "ALREADY_CONFIGURED: OptIn 0x$($regValue.ToString('X')) already set. CA2023: $ca2023Text"
        Write-Log -Message "Remediation Result: ALREADY_CONFIGURED (exit 0)" -Level "SUCCESS"
        Write-Log -Message "========== REMEDIATION COMPLETED ==========" -Level "INFO"
        exit 0
    }
    
    Write-Log -Message "Registry Configuration:" -Level "INFO"
    Write-Log -Message "  Path: $regPath" -Level "INFO"
    Write-Log -Message "  Name: $regName" -Level "INFO"
    Write-Log -Message "  Value: 0x$($regValue.ToString('X')) ($regValue)" -Level "INFO"
    Write-Log -Message "  Type: $regType" -Level "INFO"
    
    # Create registry path if it doesn't exist
    if (-not (Test-Path $regPath)) {
        Write-Log -Message "Registry path does not exist, creating: $regPath" -Level "INFO"
        New-Item -Path $regPath -Force | Out-Null
        Write-Log -Message "Registry path created successfully" -Level "SUCCESS"
    }
    else {
        Write-Log -Message "Registry path already exists" -Level "INFO"
    }
    
    # Set the registry value
    Write-Log -Message "Setting MicrosoftUpdateManagedOptIn registry value..." -Level "INFO"
    Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type $regType -Force -ErrorAction Stop
    Write-Log -Message "Registry value set successfully" -Level "SUCCESS"
    
    # Verify the registry value was set correctly
    Write-Log -Message "Verifying registry configuration..." -Level "INFO"
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).$regName
    
    if ($currentValue -eq $regValue) {
        Write-Log -Message "Registry value verified: 0x$($currentValue.ToString('X')) ($currentValue)" -Level "SUCCESS"
        Write-Log -Message "Device is now configured to receive Secure Boot certificate updates" -Level "SUCCESS"
        Write-Log -Message "Windows Update will automatically apply certificate updates through cumulative updates starting early 2026" -Level "INFO"
        Write-Host "SUCCESS: MicrosoftUpdateManagedOptIn set to 0x$($currentValue.ToString('X')). Certificate updates enabled."
        Write-Log -Message "Console Output: SUCCESS: MicrosoftUpdateManagedOptIn set to 0x$($currentValue.ToString('X')). Certificate updates enabled." -Level "SUCCESS"
        Write-Log -Message "Remediation Result: SUCCESS (exit 0)" -Level "SUCCESS"
        Write-Log -Message "========== REMEDIATION COMPLETED ==========" -Level "INFO"
    }
    else {
        Write-Log -Message "Registry value mismatch detected!" -Level "ERROR"
        Write-Log -Message "  Expected: 0x$($regValue.ToString('X')) ($regValue)" -Level "ERROR"
        Write-Log -Message "  Actual: 0x$($currentValue.ToString('X')) ($currentValue)" -Level "ERROR"
        Write-Host "FAILED: Registry mismatch - Expected 0x$($regValue.ToString('X')), Got 0x$($currentValue.ToString('X'))"
        Write-Log -Message "Remediation Result: FAILED (exit 1)" -Level "ERROR"
        Write-Log -Message "========== REMEDIATION COMPLETED ==========" -Level "INFO"
        exit 1
    }
    
    exit 0
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
