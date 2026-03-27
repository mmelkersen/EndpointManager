<#
.SYNOPSIS
    Detects whether Windows devices have completed the Secure Boot certificate transition before June 2026 expiration.

.DESCRIPTION
    This detection script checks if devices have fully transitioned to the new Secure Boot certificates
    before the June 2026 expiration of Microsoft Corporation KEK CA 2011 and UEFI CA 2011.
    Microsoft Windows Production PCA 2011 expires in October 2026.
    
    The script uses a tiered compliance model:
    - Stage 0: Secure Boot disabled (exit 1)
    - Stage 1: MicrosoftUpdateManagedOptIn not configured (exit 1 - triggers remediation)
    - Stage 2: OptIn configured, awaiting Windows Update processing (exit 1)
    - Stage 3: Certificate updates in progress (exit 1)
    - Stage 4: CA2023 certificate in UEFI DB but not yet booting from it (exit 1)
    - Stage 5: COMPLIANT - Booting from 2023 signed boot manager (exit 0)
    
    A device is only considered compliant when WindowsUEFICA2023Capable equals 2,
    meaning the 2023 certificate is in the UEFI DB AND the device is booting from it.
    
    Each detection run logs detailed diagnostic data locally including system uptime,
    TPM status, BitLocker state, Windows Update health, pending reboots, and a full
    Secure Boot registry dump. Stage-specific analysis explains WHY a device is
    non-compliant and WHAT needs to happen next.
    
    Exit codes:
    - 0: Compliant (booting from 2023 certificate chain)
    - 1: Non-compliant (requires remediation or waiting for Windows Update)

.EXAMPLE
    .\Detect-SecureBootCertificateUpdate.ps1
    
    Checks the device for Secure Boot certificate update readiness and outputs tiered compliance status.

.NOTES
    Version:        2.2
    Author:         Mattias Melkersen
    Creation Date:  2026-01-15
    
    CHANGELOG
    ---------------
    2026-02-19 - v2.2 - Fixed misleading "Updates:Not Configured" label when AvailableUpdates=0 (MM)
                        Suppress Updates detail from output when CA2023 cert is already in UEFI DB
    2026-02-18 - v2.1 - Enhanced local device logging with full diagnostic data for IT pro troubleshooting (MM)
                        Added: last boot time, TPM, BitLocker, WU health, pending reboot, registry dump
                        Added: stage-specific WHY/NEXT STEPS guidance in log output
    2026-02-18 - v2.0 - Tiered compliance: exit 0 only when booting from 2023 cert chain (MM)
                        Replaced Get-WmiObject with Get-CimInstance to fix Provider load failures
                        Remediation script made idempotent to avoid unnecessary registry writes
    2026-01-15 - v1.0 - Initial version for June 2026 certificate expiration preparation (MM)
    
    References:
    - https://aka.ms/getsecureboot
    - https://techcommunity.microsoft.com/blog/windows-itpro-blog/act-now-secure-boot-certificates-expire-in-june-2026/4426856
    - https://support.microsoft.com/topic/enterprise-deployment-guidance-for-cve-2023-24932-88b8f034-20b7-4a45-80cb-c6049b0f9967
#>

[CmdletBinding()]
param()

#region Logging Configuration
[string]$LogFile = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\SecureBootCertificateUpdate.log"
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

function Get-AvailableUpdatesStatus {
    param([int]$Value)
    
    switch ($Value) {
        22852 { return "Not Started - All updates pending (0x5944)" }
        16384 { return "Complete - All certificates applied (0x4000)" }
        0     { return "No pending updates (0x0)" }
        default { return "In Progress (0x$($Value.ToString('X')))" }
    }
}

function Get-WindowsUEFICA2023Status {
    param([int]$Value)
    
    switch ($Value) {
        0 { return "Not in DB" }
        1 { return "In DB" }
        2 { return "In DB and booting from 2023 signed boot manager" }
        default { return "Unknown ($Value)" }
    }
}
#endregion

#region Main Detection Logic
try {
    Write-Log -Message "========== DETECTION STARTED ==========" -Level "INFO"
    Write-Log -Message "Script Version: 2.2" -Level "INFO"
    Write-Log -Message "Computer: $env:COMPUTERNAME | User: $env:USERNAME" -Level "INFO"
    Write-Log -Message "PowerShell: $($PSVersionTable.PSVersion) | Process: $(if ([Environment]::Is64BitProcess) {'64-bit'} else {'32-bit'})" -Level "INFO"
    
    # Check Secure Boot Status
    Write-Log -Message "Checking Secure Boot status..." -Level "INFO"
    $secureBootEnabled = Get-SecureBootStatus
    
    # -- Stage 0: Secure Boot must be enabled --
    if (-not $secureBootEnabled) {
        Write-Log -Message "Secure Boot is DISABLED - Cannot apply certificate updates" -Level "ERROR"
        Write-Log -Message "--- Stage 0 Diagnostics ---" -Level "INFO"
        $sbStatePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
        if (Test-Path $sbStatePath) {
            $sbStateValue = (Get-ItemProperty -Path $sbStatePath -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue).UEFISecureBootEnabled
            Write-Log -Message "  Firmware Mode: UEFI (SecureBoot State key exists)" -Level "INFO"
            Write-Log -Message "  UEFISecureBootEnabled: $sbStateValue" -Level "INFO"
            Write-Log -Message "  WHY: Device firmware supports Secure Boot but it is DISABLED in BIOS/UEFI settings" -Level "WARNING"
            Write-Log -Message "  NEXT STEPS: Enter BIOS/UEFI setup and enable Secure Boot under Security settings" -Level "WARNING"
        }
        else {
            Write-Log -Message "  Firmware Mode: Likely Legacy BIOS (SecureBoot State key does not exist)" -Level "WARNING"
            Write-Log -Message "  WHY: Legacy BIOS firmware does not support Secure Boot" -Level "ERROR"
            Write-Log -Message "  NEXT STEPS: Convert disk to GPT and switch firmware mode from Legacy to UEFI" -Level "ERROR"
            Write-Log -Message "  Reference: https://learn.microsoft.com/en-us/windows/deployment/mbr-to-gpt" -Level "INFO"
        }
        try {
            $osDisk = Get-Disk -Number 0 -ErrorAction SilentlyContinue
            if ($osDisk) {
                Write-Log -Message "  OS Disk Partition Style: $($osDisk.PartitionStyle)" -Level "INFO"
                if ($osDisk.PartitionStyle -eq "MBR") {
                    Write-Log -Message "  MBR disk detected - MBR2GPT conversion required before enabling UEFI mode" -Level "WARNING"
                }
            }
        }
        catch {
            Write-Log -Message "  OS Disk: Unable to determine partition style" -Level "WARNING"
        }
        try {
            $biosInfo = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
            if ($biosInfo) {
                Write-Log -Message "  BIOS Manufacturer: $($biosInfo.Manufacturer)" -Level "INFO"
                Write-Log -Message "  BIOS Version: $($biosInfo.SMBIOSBIOSVersion)" -Level "INFO"
                Write-Log -Message "  BIOS Release Date: $($biosInfo.ReleaseDate)" -Level "INFO"
            }
        }
        catch {}
        Write-Log -Message "--- End Stage 0 Diagnostics ---" -Level "INFO"
        Write-Host "SECURE_BOOT_DISABLED | Action: Enable Secure Boot in BIOS/UEFI"
        Write-Log -Message "Detection Result: NON-COMPLIANT - Stage 0 (exit 1)" -Level "WARNING"
        Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
        exit 1
    }
    Write-Log -Message "Secure Boot is ENABLED" -Level "SUCCESS"
    
    # -- Stage 1: MicrosoftUpdateManagedOptIn must be set --
    Write-Log -Message "Checking MicrosoftUpdateManagedOptIn registry key..." -Level "INFO"
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    $regName = "MicrosoftUpdateManagedOptIn"
    
    $optInValue = $null
    if (Test-Path $regPath) {
        $optInValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
    }
    
    if ($null -eq $optInValue -or $optInValue -eq 0) {
        Write-Log -Message "MicrosoftUpdateManagedOptIn is NOT SET or 0 - Remediation required" -Level "WARNING"
        Write-Log -Message "--- Stage 1 Analysis ---" -Level "INFO"
        Write-Log -Message "  Registry Path: $regPath" -Level "INFO"
        Write-Log -Message "  Registry Path Exists: $(Test-Path $regPath)" -Level "INFO"
        Write-Log -Message "  Current Value: $(if ($null -eq $optInValue) {'<does not exist>'} else {"$optInValue (0x$($optInValue.ToString('X')))"})" -Level "INFO"
        Write-Log -Message "  Expected Value: 0x5944 (22852)" -Level "INFO"
        Write-Log -Message "  WHY: The registry key that enables Secure Boot certificate updates via Windows Update is not configured" -Level "INFO"
        Write-Log -Message "  NEXT STEPS: The remediation script will automatically set this value. No manual action required." -Level "INFO"
        Write-Log -Message "--- End Stage 1 Analysis ---" -Level "INFO"
        Write-Host "OPTIN_NOT_SET | Action: Remediation will configure registry"
        Write-Log -Message "Detection Result: NON-COMPLIANT - Stage 1 (exit 1)" -Level "WARNING"
        Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
        exit 1
    }
    Write-Log -Message "MicrosoftUpdateManagedOptIn is SET to 0x$($optInValue.ToString('X')) ($optInValue)" -Level "SUCCESS"
    
    # Check certificate deployment status
    Write-Log -Message "Checking certificate update deployment status..." -Level "INFO"
    $availableUpdates = (Get-ItemProperty -Path $regPath -Name "AvailableUpdates" -ErrorAction SilentlyContinue).AvailableUpdates
    $servicingPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
    $ca2023Capable = (Get-ItemProperty -Path $servicingPath -Name "WindowsUEFICA2023Capable" -ErrorAction SilentlyContinue).WindowsUEFICA2023Capable
    
    if ($null -ne $availableUpdates) {
        $updateStatus = Get-AvailableUpdatesStatus -Value $availableUpdates
        Write-Log -Message "AvailableUpdates: $updateStatus (0x$($availableUpdates.ToString('X')))" -Level "INFO"
    }
    else {
        Write-Log -Message "AvailableUpdates: Key not present (normal before Windows Update detection)" -Level "INFO"
    }
    
    if ($null -ne $ca2023Capable) {
        $ca2023Status = Get-WindowsUEFICA2023Status -Value $ca2023Capable
        Write-Log -Message "WindowsUEFICA2023Capable: $ca2023Status ($ca2023Capable)" -Level "INFO"
    }
    else {
        Write-Log -Message "WindowsUEFICA2023Capable: Key not present (normal before Windows Update processes)" -Level "INFO"
    }
    
    # Check device attributes
    $deviceAttribPath = "$servicingPath\DeviceAttributes"
    if (Test-Path $deviceAttribPath) {
        $manufacturer = (Get-ItemProperty -Path $deviceAttribPath -Name "OEMManufacturerName" -ErrorAction SilentlyContinue).OEMManufacturerName
        $model = (Get-ItemProperty -Path $deviceAttribPath -Name "OEMModelNumber" -ErrorAction SilentlyContinue).OEMModelNumber
        $firmwareVersion = (Get-ItemProperty -Path $deviceAttribPath -Name "FirmwareVersion" -ErrorAction SilentlyContinue).FirmwareVersion
        $firmwareDate = (Get-ItemProperty -Path $deviceAttribPath -Name "FirmwareReleaseDate" -ErrorAction SilentlyContinue).FirmwareReleaseDate
        
        if ($manufacturer) { Write-Log -Message "Device Manufacturer: $manufacturer" -Level "INFO" }
        if ($model) { Write-Log -Message "Device Model: $model" -Level "INFO" }
        if ($firmwareVersion) { Write-Log -Message "Firmware Version: $firmwareVersion" -Level "INFO" }
        if ($firmwareDate) { Write-Log -Message "Firmware Release Date: $firmwareDate" -Level "INFO" }
    }
    
    # ===== DIAGNOSTIC DATA COLLECTION =====
    Write-Log -Message "---------- DIAGNOSTIC DATA ----------" -Level "INFO"
    
    # OS version and last boot time
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $osVersion = $osInfo.Caption
    $osBuild = $osInfo.BuildNumber
    Write-Log -Message "OS: $osVersion (Build $osBuild)" -Level "INFO"
    
    if ($osVersion -like "*Windows 10*") {
        Write-Log -Message "WARNING: Windows 10 support ended October 2025. Consider upgrading to Windows 11 or ESU." -Level "WARNING"
    }
    
    $lastBoot = $osInfo.LastBootUpTime
    $uptime = (Get-Date) - $lastBoot
    Write-Log -Message "Last Boot: $($lastBoot.ToString('yyyy-MM-dd HH:mm:ss')) | Uptime: $([math]::Floor($uptime.TotalDays))d $($uptime.Hours)h $($uptime.Minutes)m" -Level "INFO"
    
    # TPM status
    try {
        $tpm = Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction Stop
        if ($tpm) {
            Write-Log -Message "TPM: Present | Enabled: $($tpm.IsEnabled_InitialValue) | Activated: $($tpm.IsActivated_InitialValue) | Spec: $($tpm.SpecVersion)" -Level "INFO"
        }
        else {
            Write-Log -Message "TPM: Not found" -Level "WARNING"
        }
    }
    catch {
        Write-Log -Message "TPM: Unable to query - $($_.Exception.Message)" -Level "WARNING"
    }
    
    # BitLocker status on OS drive
    try {
        $blVolume = Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftVolumeEncryption" -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$env:SystemDrive'" -ErrorAction Stop
        if ($blVolume) {
            $blProtection = switch ($blVolume.ProtectionStatus) { 0 { "OFF" } 1 { "ON" } 2 { "UNKNOWN" } default { "Unknown ($($blVolume.ProtectionStatus))" } }
            $blConversion = switch ($blVolume.ConversionStatus) { 0 { "FullyDecrypted" } 1 { "FullyEncrypted" } 2 { "EncryptionInProgress" } 3 { "DecryptionInProgress" } 4 { "EncryptionPaused" } 5 { "DecryptionPaused" } default { "Unknown ($($blVolume.ConversionStatus))" } }
            Write-Log -Message "BitLocker ($env:SystemDrive): Protection=$blProtection | Status=$blConversion" -Level "INFO"
            if ($blProtection -eq "ON") {
                Write-Log -Message "BitLocker NOTE: Secure Boot cert changes may trigger BitLocker recovery key prompt on next reboot" -Level "WARNING"
            }
        }
        else {
            Write-Log -Message "BitLocker ($env:SystemDrive): Not encrypted or not available" -Level "INFO"
        }
    }
    catch {
        Write-Log -Message "BitLocker: Unable to query - $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Windows Update service health
    try {
        $wuService = Get-Service -Name wuauserv -ErrorAction Stop
        Write-Log -Message "Windows Update Service: Status=$($wuService.Status) | StartType=$($wuService.StartType)" -Level "INFO"
        if ($wuService.Status -ne 'Running' -and $wuService.Status -ne 'Stopped') {
            Write-Log -Message "WU Service WARNING: Service is in unexpected state '$($wuService.Status)'" -Level "WARNING"
        }
    }
    catch {
        Write-Log -Message "Windows Update Service: Unable to query - $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Last Windows Update scan and install times
    try {
        $autoUpdate = New-Object -ComObject Microsoft.Update.AutoUpdate -ErrorAction Stop
        $lastSearch = $autoUpdate.Results.LastSearchSuccessDate
        if ($lastSearch -and $lastSearch.Year -gt 2000) {
            $searchAge = (Get-Date) - $lastSearch
            Write-Log -Message "Last WU Scan: $($lastSearch.ToString('yyyy-MM-dd HH:mm:ss')) ($([math]::Floor($searchAge.TotalHours))h ago)" -Level "INFO"
            if ($searchAge.TotalDays -gt 7) {
                Write-Log -Message "WU Scan WARNING: Last successful scan was over 7 days ago" -Level "WARNING"
            }
        }
        else {
            Write-Log -Message "Last WU Scan: No successful scan on record" -Level "WARNING"
        }
        $lastInstall = $autoUpdate.Results.LastInstallationSuccessDate
        if ($lastInstall -and $lastInstall.Year -gt 2000) {
            Write-Log -Message "Last WU Install: $($lastInstall.ToString('yyyy-MM-dd HH:mm:ss'))" -Level "INFO"
        }
    }
    catch {
        Write-Log -Message "Windows Update COM: Unable to query - $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Pending reboot indicators
    $pendingRebootReasons = @()
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        $pendingRebootReasons += "CBS-RebootPending"
    }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        $pendingRebootReasons += "WU-RebootRequired"
    }
    $pfro = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pfro) {
        $pendingRebootReasons += "PendingFileRename"
    }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting") {
        $pendingRebootReasons += "WU-PostRebootReporting"
    }
    if ($pendingRebootReasons.Count -gt 0) {
        Write-Log -Message "Pending Reboot: YES - Sources: $($pendingRebootReasons -join ', ')" -Level "WARNING"
    }
    else {
        Write-Log -Message "Pending Reboot: No pending reboot detected" -Level "INFO"
    }
    
    # Full Secure Boot registry dump
    Write-Log -Message "--- Secure Boot Registry Dump ---" -Level "INFO"
    $sbDumpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    if (Test-Path $sbDumpPath) {
        $sbDumpProps = Get-ItemProperty -Path $sbDumpPath -ErrorAction SilentlyContinue
        $sbDumpProps.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
            if ($_.Value -is [int]) {
                Write-Log -Message "  Secureboot\$($_.Name) = $($_.Value) (0x$($_.Value.ToString('X')))" -Level "INFO"
            }
            elseif ($_.Value -is [byte[]]) {
                Write-Log -Message "  Secureboot\$($_.Name) = [byte[]] Length=$($_.Value.Length)" -Level "INFO"
            }
            else {
                Write-Log -Message "  Secureboot\$($_.Name) = $($_.Value)" -Level "INFO"
            }
        }
    }
    else {
        Write-Log -Message "  Secureboot key not found at $sbDumpPath" -Level "WARNING"
    }
    $sbServicingDump = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
    if (Test-Path $sbServicingDump) {
        $svcDumpProps = Get-ItemProperty -Path $sbServicingDump -ErrorAction SilentlyContinue
        $svcDumpProps.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
            if ($_.Value -is [int]) {
                Write-Log -Message "  Servicing\$($_.Name) = $($_.Value) (0x$($_.Value.ToString('X')))" -Level "INFO"
            }
            elseif ($_.Value -is [byte[]]) {
                Write-Log -Message "  Servicing\$($_.Name) = [byte[]] Length=$($_.Value.Length)" -Level "INFO"
            }
            else {
                Write-Log -Message "  Servicing\$($_.Name) = $($_.Value)" -Level "INFO"
            }
        }
    }
    else {
        Write-Log -Message "  SecureBoot\Servicing key does not exist (normal before WU processes cert updates)" -Level "INFO"
    }
    Write-Log -Message "--- End Registry Dump ---" -Level "INFO"
    Write-Log -Message "---------- END DIAGNOSTIC DATA ----------" -Level "INFO"
    
    # Build detail string for output
    $detailParts = @("OptIn:0x$($optInValue.ToString('X'))")
    if ($null -ne $availableUpdates) {
        $updateStatus = Get-AvailableUpdatesStatus -Value $availableUpdates
        # Only include Updates detail if cert is not yet in DB (avoids confusion at Stage 4/5)
        if ($null -eq $ca2023Capable -or $ca2023Capable -lt 1) {
            $detailParts += "Updates:$updateStatus"
        }
    }
    if ($null -ne $ca2023Capable) {
        $ca2023Status = Get-WindowsUEFICA2023Status -Value $ca2023Capable
        $detailParts += "CA2023:$ca2023Status"
    }
    $details = $detailParts -join " | "
    
    # -- Stage 5: COMPLIANT - Booting from 2023 cert chain --
    if ($ca2023Capable -eq 2) {
        Write-Log -Message "--- Stage 5: COMPLIANT ---" -Level "SUCCESS"
        Write-Log -Message "  Device is booting from the 2023-signed boot manager" -Level "SUCCESS"
        Write-Log -Message "  The Secure Boot certificate transition is complete for this device" -Level "SUCCESS"
        Write-Host "COMPLIANT | $details"
        Write-Log -Message "Detection Result: COMPLIANT - Stage 5 (exit 0)" -Level "SUCCESS"
        Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
        exit 0
    }
    
    # -- Stages 2-4: Configured but not yet fully transitioned (all exit 1) --
    # The remediation script will see OptIn is already set and skip re-writing it.
    
    # Stage 4: CA2023 cert is in UEFI DB but device hasn't rebooted to use it yet
    if ($ca2023Capable -eq 1) {
        Write-Log -Message "--- Stage 4 Analysis ---" -Level "INFO"
        Write-Log -Message "  WHY: The Windows UEFI CA 2023 certificate has been written to the UEFI Secure Boot DB" -Level "INFO"
        Write-Log -Message "  WHY: but the device has not yet rebooted to load the new 2023-signed boot manager" -Level "INFO"
        Write-Log -Message "  Last Boot: $($lastBoot.ToString('yyyy-MM-dd HH:mm:ss')) ($([math]::Floor($uptime.TotalDays)) days, $($uptime.Hours)h ago)" -Level "INFO"
        if ($pendingRebootReasons.Count -gt 0) {
            Write-Log -Message "  Pending Reboot Detected: $($pendingRebootReasons -join ', ')" -Level "WARNING"
        }
        else {
            Write-Log -Message "  Pending Reboot: No reboot indicators found - a reboot is still required to activate the new boot manager" -Level "INFO"
        }
        Write-Log -Message "  NEXT STEPS: Reboot the device. After reboot, the boot manager will use the 2023 certificate chain." -Level "WARNING"
        Write-Log -Message "  NEXT STEPS: If the device has been rebooted recently and is still at Stage 4, check BitLocker recovery key availability." -Level "WARNING"
        Write-Log -Message "--- End Stage 4 Analysis ---" -Level "INFO"
        Write-Host "CONFIGURED_CA2023_IN_DB | $details | Action: Reboot to complete transition"
        Write-Log -Message "Detection Result: NON-COMPLIANT - Stage 4 (exit 1)" -Level "WARNING"
        Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
        exit 1
    }
    
    # Stage 3: Certificate updates are actively being applied by Windows Update
    if ($null -ne $availableUpdates -and $availableUpdates -ne 0 -and $availableUpdates -ne 22852) {
        Write-Log -Message "--- Stage 3 Analysis ---" -Level "INFO"
        Write-Log -Message "  WHY: Windows Update is actively processing Secure Boot certificate updates" -Level "INFO"
        Write-Log -Message "  WHY: AvailableUpdates = 0x$($availableUpdates.ToString('X')) ($availableUpdates) indicates partial certificate deployment" -Level "INFO"
        Write-Log -Message "  WHY: Target value is 0x4000 (16384) = all certificates applied" -Level "INFO"
        if ($pendingRebootReasons.Count -gt 0) {
            Write-Log -Message "  Pending Reboot: $($pendingRebootReasons -join ', ') - a reboot may be required to continue WU processing" -Level "WARNING"
        }
        Write-Log -Message "  NEXT STEPS: Allow Windows Update to complete. This typically resolves after 1-2 quality update cycles." -Level "INFO"
        Write-Log -Message "  NEXT STEPS: If stuck here for >30 days, check Windows Update health and run 'usoclient StartScan'" -Level "WARNING"
        Write-Log -Message "--- End Stage 3 Analysis ---" -Level "INFO"
        Write-Host "CONFIGURED_UPDATE_IN_PROGRESS | $details | Action: Waiting for Windows Update"
        Write-Log -Message "Detection Result: NON-COMPLIANT - Stage 3 (exit 1)" -Level "WARNING"
        Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
        exit 1
    }
    
    # Stage 2: OptIn is set but Windows Update hasn't started processing yet
    Write-Log -Message "--- Stage 2 Analysis ---" -Level "INFO"
    Write-Log -Message "  WHY: MicrosoftUpdateManagedOptIn is set (0x$($optInValue.ToString('X'))) but Windows Update has not yet started certificate deployment" -Level "INFO"
    if ($null -eq $availableUpdates) {
        Write-Log -Message "  WHY: AvailableUpdates key does not exist yet - Windows Update has not scanned for Secure Boot cert updates" -Level "INFO"
    }
    else {
        Write-Log -Message "  WHY: AvailableUpdates = 0x$($availableUpdates.ToString('X')) ($availableUpdates) - waiting for WU to begin processing" -Level "INFO"
    }
    if ($null -eq $ca2023Capable) {
        Write-Log -Message "  WHY: WindowsUEFICA2023Capable key does not exist yet - normal before Windows Update processes" -Level "INFO"
    }
    else {
        Write-Log -Message "  WHY: WindowsUEFICA2023Capable = $ca2023Capable (0 = Not in DB)" -Level "INFO"
    }
    Write-Log -Message "  NEXT STEPS: Ensure device is connected to the internet and Windows Update service is running" -Level "INFO"
    Write-Log -Message "  NEXT STEPS: Certificate updates are delivered through cumulative quality updates" -Level "INFO"
    Write-Log -Message "  NEXT STEPS: If stuck here for >14 days, run 'usoclient StartScan' or check WU policy/WSUS configuration" -Level "WARNING"
    Write-Log -Message "--- End Stage 2 Analysis ---" -Level "INFO"
    Write-Host "CONFIGURED_AWAITING_UPDATE | $details | Action: Waiting for Windows Update scan"
    Write-Log -Message "Detection Result: NON-COMPLIANT - Stage 2 (exit 1)" -Level "WARNING"
    Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
    exit 1
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
