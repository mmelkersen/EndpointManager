# Secure Boot Certificate Update - Remediation

## Overview

Microsoft Secure Boot certificates expire in 2026:
- **June 2026**: Microsoft Corporation KEK CA 2011 and Microsoft Corporation UEFI CA 2011
- **October 2026**: Microsoft Windows Production PCA 2011

These Remediation scripts manage the full lifecycle of Secure Boot certificate transition -- from initial configuration through to the device actually booting on the new 2023 certificate chain of trust.

> **Key principle (v2.1):** A device is only reported as **COMPLIANT** when `WindowsUEFICA2023Capable = 2`, meaning the 2023 certificate is in the UEFI DB **and** the device is booting from it. Setting the registry opt-in alone is not sufficient.
>
> **New in v4.0:** Integration with Microsoft's modern `WinCsFlags.exe` API for certificate deployment, completely bypassing the need for `.bin` payload files and preventing legacy `0x80070002` errors. Extensive diagnostic checks were added, including pre-flight payload validation for the legacy scheduled task, firmware-level UEFI DB verification (`Get-SecureBootUEFI`), and Secure Boot Event Log harvesting.
>
> **New in v3.0:** Both scripts now accept `FallbackDays` (default: 30) and `TimestampRegPath` (default: `HKLM:\SOFTWARE\Mindcore\Secureboot`) parameters. If a device has been opted in for longer than `FallbackDays` without reaching compliance, the remediation script automatically falls back to the direct methods (WinCS or AvailableUpdates), bypassing the Windows Update wait. Detection output includes countdown/status for the fallback timer.
>
> **New in v2.1:** Each detection run writes detailed diagnostic data to a local log file, including TPM status, BitLocker state, Windows Update health, pending reboot indicators, and a full Secure Boot registry dump. Stage-specific **WHY** and **NEXT STEPS** guidance helps IT pros quickly identify root causes without remote access.

## Stage Progression

Every device moves through a series of stages from initial detection to full compliance. The detection script reports the current stage; only Stage 5 exits with code `0` (compliant).

```
+-------------------+     +-------------------+     +---------------------------+
|    STAGE 0        |     |    STAGE 1        |     |       STAGE 2             |
| Secure Boot OFF   |     | OptIn NOT SET     |     |  CONFIGURED_AWAITING_     |
|                   |     |                   |     |       UPDATE              |
| Action: Enable in |     | Action: Remediate |     | Action: Waiting for       |
|   BIOS/UEFI       |     |   sets 0x5944     |     |   Windows Update scan     |
| Exit: 1           |     | Exit: 1           |     | Exit: 1                   |
+-------------------+     +--------+----------+     +------------+--------------+
        |                          |                              |
        | (manual)                 | (remediation runs)           | (WU picks up)
        v                         v                              v
  Enable Secure Boot       Remediation writes          +---------------------------+
  then re-detect           MicrosoftUpdateManagedOptIn  |       STAGE 3             |
                           = 0x5944                     |  CONFIGURED_UPDATE_       |
                                  |                     |     IN_PROGRESS           |
                                  |                     | Action: Waiting for       |
                                  +---->  Stage 2  ---->|   Windows Update          |
                                                        | Exit: 1                   |
                                                        +------------+--------------+
                                                                     |
                                                                     | (cert applied)
                                                                     v
                                                        +---------------------------+
                                                        |       STAGE 4             |
                                                        |  CONFIGURED_CA2023_IN_DB  |
                                                        | CA2023 cert in UEFI DB    |
                                                        | but not yet booting       |
                                                        | Action: Reboot device     |
                                                        | Exit: 1                   |
                                                        +------------+--------------+
                                                                     |
                                                                     | (reboot)
                                                                     v
                                                        +---------------------------+
                                                        |       STAGE 5             |
                                                        |       COMPLIANT           |
                                                        | Booting from 2023 signed  |
                                                        | boot manager              |
                                                        | Exit: 0                   |
                                                        +---------------------------+
```

### Expected Timeline per Device

| Stage | Trigger | Typical Wait Time |
|-------|---------|-------------------|
| 0 -> 1 | IT/user enables Secure Boot in BIOS | Manual -- requires physical/remote BIOS access |
| 1 -> 2 | Remediation script sets `OptIn = 0x5944` | Minutes (next Intune sync cycle) |
| 2 -> 3 | Windows Update detects available cert updates | Hours to days (next WU scan) |
| 3 -> 4 | Windows Update applies certificate to UEFI DB | Hours to days (WU processing + reboot) |
| 4 -> 5 | Device reboots using 2023 signed boot manager | Minutes (next reboot) |

> With Microsoft Autopatch, Stages 2-5 are handled automatically through quality update rings over 2-4 months (February-May 2026).

## Scripts

### Detection Script (v4.0)
**File**: `Detect-SecureBootCertificateUpdate.ps1`

**Parameters**:
| Parameter | Default | Description |
|-----------|---------|-------------|
| `FallbackDays` | `30` | Days to wait before fallback activates |
| `TimestampRegPath` | `HKLM:\SOFTWARE\Mindcore\Secureboot` | Registry path for `ManagedOptInDate` timestamp |

**Checks**:
1. Secure Boot enabled status
2. `MicrosoftUpdateManagedOptIn` registry key (required for automatic updates)
3. Certificate update progress (`AvailableUpdates`)
4. Windows UEFI CA 2023 capability status (`WindowsUEFICA2023Capable`)
5. Device firmware version and attributes
6. OS version (warns if Windows 10 past end of support)

**Diagnostic Data (v2.1 & v4.0)** -- written to local log file on every detection run:
7. Last boot time and system uptime
8. TPM status (present, enabled, activated, spec version)
9. BitLocker status on OS drive (protection state, encryption status)
10. Windows Update service health and last scan/install timestamps
11. Pending reboot detection (CBS, WU, PendingFileRename, PostRebootReporting)
12. Full Secure Boot registry dump (`Secureboot\*` and `SecureBoot\Servicing\*`)
13. Stage-specific **WHY** / **NEXT STEPS** analysis per non-compliant stage
14. Fallback timer countdown (v3.0) -- days remaining or `ACTIVE` status for Stages 2-4
15. **(New in v4.0)** Payload folder health (`SecureBootUpdates`), legacy task execution results, WinCS API availability, raw UEFI firmware DB bytes, and Secure Boot Event Logs (IDs 1036, 1043, 1044, 1045, 1801, 1808).

**Tiered Compliance Model**:

| Stage | Intune Output | Exit Code | Meaning |
|-------|---------------|-----------|--------|
| 0 | `SECURE_BOOT_DISABLED` | 1 | Secure Boot off -- cannot proceed |
| 1 | `OPTIN_NOT_SET` | 1 | Registry not configured -- triggers remediation |
| 2 | `CONFIGURED_AWAITING_UPDATE` | 1 | OptIn set, waiting for WU scan |
| 3 | `CONFIGURED_UPDATE_IN_PROGRESS` | 1 | WU actively applying cert updates |
| 4 | `CONFIGURED_CA2023_IN_DB` | 1 | Cert in UEFI DB, reboot needed |
| 5 | `COMPLIANT` | 0 | Booting from 2023 certificate chain |

**Exit Codes**:
- `0` = Compliant (Stage 5 -- booting from 2023 certificate chain)
- `1` = Non-compliant (Stages 0-4 -- see output for specific stage)

### Remediation Script (v4.0)
**File**: `Remediate-SecureBootCertificateUpdate.ps1`

**Parameters**:
| Parameter | Default | Description |
|-----------|---------|-------------|
| `FallbackDays` | `30` | Days to wait before direct method fallback activates |
| `TimestampRegPath` | `HKLM:\SOFTWARE\Mindcore\Secureboot` | Registry path for `ManagedOptInDate` timestamp |

**Actions**:
1. Verifies Secure Boot is enabled (fails if disabled)
2. **Idempotency check**: If `MicrosoftUpdateManagedOptIn` is already `0x5944`, checks compliance status:
   - If `WindowsUEFICA2023Capable = 2`: outputs `ALREADY_CONFIGURED` and exits `0`
   - If not compliant and no timestamp: backfills `ManagedOptInDate` (clock starts now)
   - If not compliant and threshold not reached: outputs countdown and exits `0`
   - If not compliant and `FallbackDays` exceeded: triggers direct method (see below)
3. Creates registry path if missing
4. Sets `HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot\MicrosoftUpdateManagedOptIn` to `0x5944` (22852 decimal)
5. Verifies the value was set correctly
6. Writes `ManagedOptInDate` timestamp to `TimestampRegPath` for fallback tracking

**Fallback Logic (v3.0 & v4.0)**:
When the fallback timer exceeds `FallbackDays`:
1. **(v4.0)** Checks if `WinCsFlags.exe` exists. If so, uses `WinCsFlags.exe /apply --key "F33E0C8E002"` as the primary, modern method.
2. **(v4.0)** If WinCS is unavailable, performs a pre-flight check on `C:\Windows\System32\SecureBootUpdates\`.
3. **(v3.0)** If the payload folder is healthy, sets `AvailableUpdates = 0x40` (DB cert) and `0x100` (boot manager) and triggers the legacy `\Microsoft\Windows\PI\Secure-Boot-Update` scheduled task.
4. A reboot may be required after fallback completes

**Intune Output Values**:

| Output | Meaning |
|--------|---------|
| `ALREADY_CONFIGURED: OptIn 0x5944 already set. CA2023: ...` | No action taken -- registry already correct |
| `ALREADY_CONFIGURED: ... Fallback timer started.` | Timestamp backfilled for pre-v3.0 device |
| `ALREADY_CONFIGURED: ... Fallback in Xd.` | Countdown to fallback activation |
| `FALLBACK_WINCS: WinCS applied key...` | (v4.0) WinCS modern API automatically transitioned certificates |
| `FALLBACK_APPLIED: Direct method triggered...` | Direct legacy method triggered after threshold exceeded |
| `FALLBACK_BLOCKED: Scheduled task not found...` | Required Windows KB not installed for fallback |
| `FALLBACK_BLOCKED: No WinCS and no payload files...` | (v4.0) Missing `SecureBootUpdates` payload, aborting legacy task |
| `FALLBACK_FAILED: Direct method encountered errors...` | Fallback attempted but failed |
| `SUCCESS: MicrosoftUpdateManagedOptIn set to 0x5944...` | Registry value written and verified |
| `FAILED: Secure Boot DISABLED...` | Cannot remediate without Secure Boot |
| `FAILED: Registry mismatch...` | Write succeeded but verification failed |

**Exit Codes**:
- `0` = Remediation successful or already configured
- `1` = Remediation failed

## Deployment to Intune

### Step 1: Create Remediation in Intune

1. Navigate to **Intune** → **Devices** → **Remediations**
2. Click **+ Create script package**
3. Configure:
   - **Name**: Secure Boot Certificate Update - June 2026 Preparation
   - **Description**: Configures devices to receive Secure Boot certificate updates before June 2026 expiration. Part of CVE-2023-24932 mitigation and certificate lifecycle management.
   - **Publisher**: Microsoft Endpoint Management Team

### Step 2: Upload Scripts

**Detection script**:
- File: `Detect-SecureBootCertificateUpdate.ps1`
- Run in 64-bit PowerShell: **Yes**
- Run with user context: **No** (requires System context to read all registry keys)

**Remediation script**:
- File: `Remediate-SecureBootCertificateUpdate.ps1`
- Run in 64-bit PowerShell: **Yes**
- Run with user context: **No** (requires System/Admin to set HKLM registry keys)

### Step 3: Configure Assignments

**Recommended Phased Approach**:

**Phase 1 - Pilot (January 2026)**
- Target: IT test group (50-100 devices)
- Schedule: Daily
- Monitor for 1 week

**Phase 2 - Limited Production (February 2026)**
- Target: 5-10% of production devices per hardware model
- Schedule: Daily
- Monitor for 2 weeks

**Phase 3 - Broad Deployment (March 2026)**
- Target: All eligible devices
- Schedule: Daily or Twice daily
- Complete by April 2026 (2 months before expiration)

### Step 4: Configure Schedule

**Recommended Settings**:
- Run schedule: **Daily** (or **Twice daily** for faster rollout)
- Re-run remediations: **Yes** (in case manual changes revert the key)

## Microsoft Autopatch Considerations

If your environment uses **Microsoft Autopatch**:

1. **Your remediation sets the opt-in**: Registry key enables Windows-managed updates
2. **Microsoft Autopatch handles deployment**: Certificate updates delivered through quality update rings (Test → First → Fast → Broad)
3. **Expected compliance**: 95-98% with minimal manual intervention
4. **Timeline**: Microsoft will deploy certificates starting February 2026 through quality updates

**Key Benefit**: After your remediation completes, Microsoft Autopatch automatically handles the complex multi-month certificate deployment through its managed update rings.

## Monitoring Compliance

### Intune Remediations Dashboard

Monitor in **Intune** -> **Devices** -> **Remediations** -> **Secure Boot Certificate Update**:

- **Detection without remediation (exit 0)**: Devices at Stage 5 -- fully compliant, booting from 2023 cert chain
- **Detection with remediation (exit 1)**: Devices at Stages 1-4. The remediation script runs, but:
  - Stage 1: Writes the registry key (first-time remediation)
  - Stages 2-4: Outputs `ALREADY_CONFIGURED` and exits 0 without changes -- no unnecessary registry writes
- **Failed**: Requires investigation (Stage 0 = Secure Boot disabled, or unexpected errors)

### Detection Output by Stage

Filter the **PreRemediationDetectionScriptOutput** column in the Intune export to understand fleet distribution:

| Output prefix | Stage | Action needed |
|---------------|-------|---------------|
| `SECURE_BOOT_DISABLED` | 0 | Manual BIOS intervention |
| `OPTIN_NOT_SET` | 1 | Remediation will auto-configure |
| `CONFIGURED_AWAITING_UPDATE` | 2 | Wait for Windows Update |
| `CONFIGURED_UPDATE_IN_PROGRESS` | 3 | Wait for Windows Update |
| `CONFIGURED_CA2023_IN_DB` | 4 | Reboot device |
| `COMPLIANT` | 5 | No action -- fully compliant |

### Expected Compliance Rates

**With Microsoft Autopatch** (Stages 2-5 handled by managed update rings):

| Timeframe | Registry Set (Stage 1+) | Fully Compliant (Stage 5) | Notes |
|-----------|-------------------------|---------------------------|-------|
| Week 1 | 60-70% | <5% | Registry remediation rolls out |
| Week 2-3 | 85-90% | 10-20% | WU begins cert deployment |
| Month 2 | 95-98% | 40-60% | Certs applying through update rings |
| Month 3-4 | 95-98% | 70-85% | Most devices through WU cycle |
| Month 5 (May) | 95-98% | 90-95% | Final stragglers |
| Remaining | -- | 2-5% manual exceptions | Secure Boot disabled, offline, etc. |

**Without Autopatch** (manual Windows Update management):

| Timeframe | Registry Set (Stage 1+) | Fully Compliant (Stage 5) |
|-----------|-------------------------|---------------------------|
| Month 1 | 50-65% | <5% |
| Month 2 | 70-80% | 15-30% |
| Month 3 | 75-85% | 40-55% |
| Month 4-5 | 80-90% | 55-75% |
| Remaining | -- | 15-25% requires intervention |

### Post-Remediation Certificate Deployment Tracking

After remediation, track actual certificate deployment progress:

**Registry Key to Monitor**:
```powershell
HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\AvailableUpdates
```

**Values**:
- `0x5944` (22852): Not started - All updates pending
- Other values: In progress
- `0x4000` (16384): Complete - All certificates applied

**Certificate Status**:
```powershell
HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\WindowsUEFICA2023Capable
```

**Values**:
- `0`: Not in DB
- `1`: In DB
- `2`: In DB and booting from 2023 signed boot manager

## Local Device Logging (v2.1)

Both scripts write detailed diagnostic data to a shared log file on every run:

**Log file path**:
```
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\SecureBootCertificateUpdate.log
```

**Log management**:
- Maximum size: **4 MB** (configurable via `$MaxLogSizeMB`)
- Rotation: When the log exceeds 4 MB, the current file is renamed to `.log.old` and a new log is started
- Only one backup is kept (current + `.old`)
- Log entries are tagged with `[DETECT]` or `[REMEDIATE]` and severity `[INFO]`, `[WARNING]`, `[ERROR]`, `[SUCCESS]`

**Diagnostic data collected per detection run**:

| Category | Data Logged | Purpose |
|----------|-------------|---------|
| System | Computer name, PS version, 64-bit check | Script execution context |
| OS | Windows version, build number | Compatibility verification |
| Uptime | Last boot time, uptime duration | Reboot tracking for Stage 4 |
| TPM | Present, enabled, activated, spec version | Hardware security baseline |
| BitLocker | Protection status, encryption status | Risk assessment for cert transition |
| Windows Update | Service status, last scan date, last install | WU health for Stages 2-3 |
| Pending Reboot | CBS, WU, PendingFileRename, PostReboot | Explains why Stage 4 persists |
| Registry Dump | All values under `Secureboot\` and `Servicing\` | Complete state snapshot |
| WHY / NEXT STEPS | Stage-specific root cause analysis | Actionable guidance per stage |

**Sample log output** (Stage 4 device):
```
2026-02-18 14:30:01 [DETECT] [INFO] ========== DETECTION STARTED ==========
2026-02-18 14:30:01 [DETECT] [INFO] Script Version: 3.0
2026-02-18 14:30:01 [DETECT] [INFO] Computer: WS-PC0412 | User: SYSTEM
2026-02-18 14:30:01 [DETECT] [SUCCESS] Secure Boot is ENABLED
2026-02-18 14:30:01 [DETECT] [SUCCESS] MicrosoftUpdateManagedOptIn is SET to 0x5944
2026-02-18 14:30:01 [DETECT] [INFO] Fallback Timer: OptIn date=2026-01-20 10:15:00 | Elapsed=29d | Threshold=30d | Remaining=1d | Active=False
2026-02-18 14:30:01 [DETECT] [INFO] WindowsUEFICA2023Capable: In DB (1)
2026-02-18 14:30:01 [DETECT] [INFO] --- DIAGNOSTIC DATA ---
2026-02-18 14:30:01 [DETECT] [INFO] OS: Windows 11 Enterprise (Build 26100)
2026-02-18 14:30:01 [DETECT] [INFO] Last Boot: 2026-02-15 08:12:30 | Uptime: 3d 6h 17m
2026-02-18 14:30:01 [DETECT] [INFO] TPM: Present | Enabled: True | Spec: 2.0
2026-02-18 14:30:01 [DETECT] [INFO] BitLocker (C:): Protection=ON | Status=FullyEncrypted
2026-02-18 14:30:02 [DETECT] [WARNING] BitLocker NOTE: Secure Boot cert changes may trigger recovery key
2026-02-18 14:30:02 [DETECT] [INFO] Last WU Scan: 2026-02-18 06:00:12 (8h ago)
2026-02-18 14:30:02 [DETECT] [INFO] Pending Reboot: No pending reboot detected
2026-02-18 14:30:02 [DETECT] [INFO] --- Stage 4 Analysis ---
2026-02-18 14:30:02 [DETECT] [INFO]   WHY: CA2023 cert is in UEFI DB but device has not rebooted to use it
2026-02-18 14:30:02 [DETECT] [WARNING]   NEXT STEPS: Reboot the device to activate the new boot manager
2026-02-18 14:30:02 [DETECT] [WARNING] Detection Result: NON-COMPLIANT - Stage 4 (exit 1)
```

**Performance impact**: Diagnostic checks add approximately 0.5-1.2 seconds per detection run. The heaviest check is the Windows Update COM object query (~200-500ms). All checks are local with zero network calls.

## Fallback Timer (v3.0 & v4.0)

The fallback timer provides a safety net for devices where Windows Update fails to complete the certificate transition within the expected timeframe.

### How It Works

1. **First opt-in**: When the remediation script sets `MicrosoftUpdateManagedOptIn` for the first time, it writes a `ManagedOptInDate` ISO 8601 timestamp to `HKLM:\SOFTWARE\Mindcore\Secureboot`
2. **Subsequent runs**: Each remediation run checks:
   - If the device is already compliant (`WindowsUEFICA2023Capable = 2`) -- exits immediately
   - If no timestamp exists -- backfills it (clock starts now)
   - If days elapsed < `FallbackDays` -- reports countdown, exits 0
   - If days elapsed >= `FallbackDays` -- triggers direct method automatically
3. **Direct fallback**: Automatically pivots to the modern `WinCsFlags.exe` API (v4.0). If unavailable, validates the local payload files and falls back to the legacy `Secure-Boot-Update` scheduled task (v3.0).

### Registry Values

| Path | Value | Type | Purpose |
|------|-------|------|---------|
| `HKLM:\SOFTWARE\Mindcore\Secureboot` | `ManagedOptInDate` | `REG_SZ` | ISO 8601 timestamp of when opt-in was first configured |

### Customizing the Fallback Timer

To change the threshold or registry path, modify the script parameters when deploying via Intune:

```powershell
# Example: 45-day threshold with custom path
.\Remediate-SecureBootCertificateUpdate.ps1 -FallbackDays 45 -TimestampRegPath "HKLM:\SOFTWARE\Contoso\Secureboot"
```

Both the detection and remediation scripts must use the **same** `FallbackDays` and `TimestampRegPath` values for consistent reporting.

### Fallback Outputs

| Output | Exit Code | Meaning |
|--------|-----------|---------|
| `FALLBACK_WINCS` | 0 | (v4.0) Modern WinCS API successfully applied the F33E0C8E002 key |
| `FALLBACK_APPLIED` | 0 | Direct legacy method triggered successfully, reboot may be required |
| `FALLBACK_BLOCKED` | 1 | Scheduled task missing, or (v4.0) Payload folder missing/empty |
| `FALLBACK_FAILED` | 1 | Fallback attempted but encountered errors |

## Troubleshooting

### Check the Local Log First (v2.1)

Before remote investigation, review the local diagnostic log:

```powershell
Get-Content "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\SecureBootCertificateUpdate.log" -Tail 50
```

The log contains **WHY** and **NEXT STEPS** for each non-compliant stage, making remote troubleshooting significantly faster.

### Device Shows "Failed" in Intune

**Most Common Cause**: Secure Boot is disabled

**Resolution**:
1. Check the local log for Stage 0 diagnostics (disk partition style, BIOS info, firmware mode)
2. Check output for "Secure Boot is DISABLED" message
3. Enable Secure Boot in BIOS/UEFI firmware (requires user/IT physical access)
4. Re-run remediation after Secure Boot is enabled

### Secure Boot Enabled But Remediation Still Fails

**Possible Causes**:
- Registry permissions issue (rare)
- Anti-malware blocking registry modifications
- Device in maintenance mode/reboot pending
- Legacy task missing `.bin` payload files (Error `0x80070002`). This is mitigated in v4.0 with pre-flight checks and `WinCsFlags.exe`.

**Resolution**:
1. Check the Secure Boot diagnostic log: `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\SecureBootCertificateUpdate.log`
2. Review IntuneManagementExtension logs: `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs`
3. Manually run remediation script as Administrator
4. Check for any anti-malware exclusions needed

### Registry Key Set But Certificates Not Installing

**This is normal**: After registry key is set, Windows Update must deliver the certificates. This happens automatically through cumulative updates starting February 2026.

**Check the local log (v2.1)** for Windows Update health indicators:
- `Windows Update Service: Status=Running` -- service is operational
- `Last WU Scan` -- if >7 days ago, the log raises a warning
- `Pending Reboot` -- an outstanding reboot may block WU processing

**Check**:
- Device is receiving Windows Updates normally
- No update deferrals or paused updates
- Latest quality updates installed

**Timeline**: Expect certificate deployment to complete over 2-4 months after remediation (February-May 2026)

## Manual Exceptions (2-5% of devices)

**Expected exceptions requiring manual intervention**:

1. **Secure Boot Disabled** (~1-2%)
   - Cannot remediate via script
   - Requires manual BIOS access to enable
   - Create IT ticket workflow for these devices

2. **Firmware Incompatibility** (~0.5-1%)
   - Specific hardware models with known issues
   - Check Microsoft KB5025885 for known incompatibilities
   - May require OEM firmware updates

3. **Offline/Inactive Devices** (~1-2%)
   - Extended offline periods
   - Lost/stolen devices still in Intune
   - Will remediate when reconnected

4. **Specialty Devices** (~0.5-1%)
   - Kiosk devices with locked configurations
   - Air-gapped devices
   - May require custom deployment approach

## Timeline and Milestones

| Date | Milestone |
|------|-----------|
| **January 15, 2026** | Scripts created and tested |
| **January 2026** | Pilot deployment (IT test group) |
| **February 2026** | Limited production rollout |
| **March 2026** | Broad deployment begins |
| **April 2026** | Target 95%+ remediation compliance |
| **February-May 2026** | Microsoft Autopatch deploys certificates via quality updates |
| **May 2026** | Final compliance check before expiration |
| **June 2026** | ⚠️ Certificate expiration deadline |
| **October 2026** | ⚠️ Windows Production PCA 2011 expiration |

## Success Criteria

**Remediation Phase (January-April 2026)** -- Stages 0-1:
- 95%+ devices past Stage 1 (registry configured)
- <2% devices stuck at Stage 0 (Secure Boot disabled, documented exceptions)
- Clear exception list for manual follow-up

**Certificate Deployment Phase (February-June 2026)** -- Stages 2-5:
- Track stage distribution weekly via Intune export
- 95%+ devices at Stage 5 (`WindowsUEFICA2023Capable = 2`) before June 2026
- Devices at Stage 4 should be prioritized for reboot
- Devices stuck at Stage 2/3 for >30 days should be investigated for WU issues

## Additional Resources

- **Microsoft Landing Page**: https://aka.ms/getsecureboot
- **Blog Post**: https://techcommunity.microsoft.com/blog/windows-itpro-blog/act-now-secure-boot-certificates-expire-in-june-2026/4426856
- **Enterprise Deployment Guide**: https://support.microsoft.com/topic/enterprise-deployment-guidance-for-cve-2023-24932-88b8f034-20b7-4a45-80cb-c6049b0f9967
- **Known Issues**: https://support.microsoft.com/topic/41a975df-beb2-40c1-99a3-b3ff139f832d
- **Windows Secure Boot certificate expiration and CA updates**: https://support.microsoft.com/en-us/topic/windows-secure-boot-certificate-expiration-and-ca-updates-7ff40d33-95dc-4c3c-8725-a9b95457578e

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 4.0 | 2026-04-06 | **WinCS & Payload Validation**: Integrated the modern `WinCsFlags.exe` API as the primary certificate transition method to prevent `0x80070002` errors. Legacy scheduled task is now gated by a pre-flight payload validation check (`SecureBootUpdates` folder). **Firmware verification**: Added `Get-SecureBootUEFI db` to check raw NVRAM variables. Added event log harvesting (kernel-boot event IDs). |
| 3.1 | 2026-04-05 | **Optimized execution**: Buffered logging in `List[string]` (flush to disk once per run). Stage 5 compliance check runs before expensive local diagnostics. |
| 3.0 | 2026-03-27 | **Fallback timer**: configurable `FallbackDays`/`TimestampRegPath` parameters. When opt-in exceeds threshold without compliance, automatically triggers direct methods. Backfills timestamp on pre-v3.0 devices. |
| 2.2 | 2026-02-19 | Fixed misleading display labels; suppress update statuses when CA2023 cert is already present. |
| 2.1 | 2026-02-18 | **Local diagnostic logging**: added TPM, BitLocker, WU health, pending reboots, registry dump to local log file `SecureBootCertificateUpdate.log`. Added "WHY / NEXT STEPS" guidance. |
| 2.0 | 2026-02-18 | Tiered compliance model; idempotent registry edits. |
| 1.0 | 2026-01-15 | Initial script versions for June 2026 transition. |

| Version | Date | Changes |
|---------|------|---------|
| 3.0 | 2026-03-27 | **Fallback timer**: configurable `FallbackDays`/`TimestampRegPath` parameters. When opt-in exceeds threshold without compliance, automatically triggers direct `AvailableUpdates` method (KB5025885). New outputs: `FALLBACK_APPLIED`, `FALLBACK_BLOCKED`, `FALLBACK_FAILED`. Writes `ManagedOptInDate` timestamp to custom registry path. Backfills timestamp on pre-v3.0 devices. |
| 2.1 | 2026-02-18 | Enhanced local device logging with full diagnostic data (TPM, BitLocker, WU health, pending reboot, registry dump). Stage-specific WHY/NEXT STEPS analysis in log output. Remediation `ALREADY_CONFIGURED` path now logs `AvailableUpdates`, CA2023 progress, and last boot time. Performance impact: ~0.5-1.2s added per detection run. |
| 2.0 | 2026-02-18 | Tiered compliance model (exit 0 only at Stage 5). `Get-WmiObject` replaced with `Get-CimInstance`. Idempotent remediation (skips write if already configured). Updated Intune output format with stage identifiers. |
| 1.0 | 2026-01-15 | Initial release - Detection and remediation scripts created |

---

**Author**: Mattias Melkersen  
**Last Updated**: March 27, 2026
