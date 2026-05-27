<#
    .SYNOPSIS
    BitLocker PIN Detection

    .DESCRIPTION
    Detects whether a BitLocker PIN is required and correctly set.
    Returns exit code 0 (compliant) or 1 (remediation required).
    Logs activity locally in CMTrace format.

    .NOTES
    Author: WPNinjas
    Date: 2026-05-24
#>

[string]$Global:LogLocation = "$env:ProgramData\WPNinjas\Logs"
[string]$Global:LogName     = "BitLockerPIN-Test"
[int]$Global:ExitCode       = 0

function Write-Log {
    param (
        [Parameter(Mandatory=$true)][string]$LogOutput,
        [Parameter(Mandatory=$true)][string]$ComponentName,
        [Parameter(Mandatory=$false)][string]$ScriptLine,
        [Parameter(Mandatory=$false)][string]$Path = "$PSScriptRoot\Logs",
        [Parameter(Mandatory=$false)][string]$Name,
        [Parameter(Mandatory=$false)][ValidateSet(1,2,3)][int]$LogLevel = 1
    )

    if (!$ScriptLine) { $ScriptLine = $MyInvocation.ScriptLineNumber }
    if (!$LogOutput)  { return }

    $FullLogName      = "$Path\$Name.log"
    $FullSecondaryLog = $FullLogName.Replace(".log", ".lo_")

    if (Test-Path $FullLogName) {
        if ((Get-Item $FullLogName).Length -gt 1024kb) {
            if (Test-Path $FullSecondaryLog) { Remove-Item -Path $FullSecondaryLog -Force }
            Rename-Item -Path $FullLogName -NewName $FullSecondaryLog
        }
    }

    if (!(Test-Path $Path)) { New-Item -ItemType Directory -Force -Path $Path -ErrorAction SilentlyContinue | Out-Null }

    $TimeGenerated = Get-Date -Format "HH':'mm':'ss.fffffff"
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="{4}" type="{5}" thread="{6}" file="">'
    $LineFormat = $LogOutput, $TimeGenerated, (Get-Date -Format MM-dd-yyyy),
                  "$ComponentName`:$ScriptLine",
                  [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
                  $LogLevel,
                  [Threading.Thread]::CurrentThread.ManagedThreadId
    $Line = $Line -f $LineFormat

    try {
        Write-Host ("[$ComponentName`:$ScriptLine] $LogOutput")
        $Encoding = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::AppendAllLines($FullLogName, [string[]]$Line, $Encoding)
    } catch {}
}

function Exit-Script {
    param ([Parameter(Mandatory=$true)][int]$ExitCode)
    if ($ExitCode -eq 0) {
        Write-Log -LogOutput "Exiting with code 0 - compliant." -ComponentName $MyInvocation.MyCommand -Path $LogLocation -Name $LogName
    } else {
        Write-Log -LogOutput "Exiting with code $ExitCode - remediation required." -ComponentName $MyInvocation.MyCommand -Path $LogLocation -Name $LogName -LogLevel 3
    }
    Exit $ExitCode
}

function Test-IfVirtualMachine {
    $bios     = Get-WmiObject -Class Win32_BIOS          -ErrorAction Stop | Select-Object Version, SerialNumber
    $computer = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop | Select-Object Model, Manufacturer

    $hwType = switch ($true) {
        ($bios.Version    -match 'VRTUAL')                                              { 'Virtual:Hyper-V' }
        ($bios.Version    -match 'A M I')                                               { 'Virtual:Virtual PC' }
        ($bios.Version    -like '*Xen*')                                                { 'Virtual:Xen' }
        ($bios.SerialNumber -like '*VMware*')                                           { 'Virtual:VMware' }
        ($bios.SerialNumber -like '*Parallels*')                                        { 'Virtual:Parallels' }
        (($computer.Manufacturer -like '*Microsoft*') -and ($computer.Model -notlike '*Surface*')) { 'Virtual:Hyper-V' }
        ($computer.Manufacturer  -like '*VMWare*')                                      { 'Virtual:VMware' }
        ($computer.Manufacturer  -like '*Parallels*')                                   { 'Virtual:Parallels' }
        ($computer.Model         -like '*Virtual*')                                     { 'Virtual' }
        default                                                                         { 'Physical' }
    }

    $isVirtual = $hwType -match 'Virtual'
    Write-Log -LogOutput ("Hardware type: '{0}'" -f $hwType) -ComponentName $MyInvocation.MyCommand -Path $LogLocation -Name $LogName
    return $isVirtual
}

function Test-RunningOOBE {
    $typeDef = @"
using System;
using System.Runtime.InteropServices;
namespace Api { public class Kernel32 { [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)] public static extern int OOBEComplete(ref int bIsOOBEComplete); } }
"@
    Add-Type -TypeDefinition $typeDef -Language CSharp
    $isComplete = $false
    [void][Api.Kernel32]::OOBEComplete([ref]$isComplete)
    $oobeRunning = !$isComplete
    Write-Log -LogOutput ("OOBE running: '{0}'" -f $oobeRunning) -ComponentName $MyInvocation.MyCommand -Path $LogLocation -Name $LogName
    return $oobeRunning
}

function Test-IfAnyLoggedOnUsers {
    $users = ((quser) -replace '\s{2,}', ',') -replace '>', '' | ConvertFrom-Csv
    if ($users) {
        Write-Log -LogOutput "Found at least one logged on user." -ComponentName $MyInvocation.MyCommand -Path $LogLocation -Name $LogName
        return $true
    }
    Write-Log -LogOutput "No logged on users found." -ComponentName $MyInvocation.MyCommand -Path $LogLocation -Name $LogName
    return $false
}

function Test-BitLockerShouldBeResumed {
    [int]$suspendCount  = (Get-CimInstance -Namespace "ROOT/CIMV2/Security/MicrosoftVolumeEncryption" -Class Win32_EncryptableVolume -Filter "DriveLetter='$env:SystemDrive'" | Invoke-CimMethod -MethodName "GetSuspendCount").SuspendCount
    [string]$protection = (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus
    $shouldResume       = (!($suspendCount -gt 0) -and $protection -eq "Off")
    Write-Log -LogOutput ("SuspendCount='{0}' ProtectionStatus='{1}' ShouldResume='{2}'" -f $suspendCount, $protection, $shouldResume) -ComponentName $MyInvocation.MyCommand -Path $LogLocation -Name $LogName
    return $shouldResume
}

function Test-BitLockerPINProtectorSet {
    $pinSet = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | Where-Object { $_.KeyProtectorType -eq 'TpmPin' }
    if ($pinSet) {
        Write-Log -LogOutput "BitLocker PIN protector is set." -ComponentName $MyInvocation.MyCommand -Path $LogLocation -Name $LogName
        return $true
    }
    Write-Log -LogOutput "BitLocker PIN protector is not set." -ComponentName $MyInvocation.MyCommand -Path $LogLocation -Name $LogName
    return $false
}

################################################
# Main
################################################

Write-Log -LogOutput "===== BitLocker PIN Detection Script Start =====" -ComponentName "Main" -Path $LogLocation -Name $LogName

# Skip on virtual machines — BitLocker PIN is not applicable
if (Test-IfVirtualMachine) {
    Write-Log -LogOutput "Virtual machine detected, skipping." -ComponentName "Main" -Path $LogLocation -Name $LogName
    Exit-Script -ExitCode 0
}

# Skip during OOBE / Enrollment Status Page
if (Test-RunningOOBE) {
    Write-Log -LogOutput "OOBE is running, skipping." -ComponentName "Main" -Path $LogLocation -Name $LogName
    Exit-Script -ExitCode 0
}

# Skip if no users are logged on (prompt would show on hidden desktop)
if (!(Test-IfAnyLoggedOnUsers)) {
    Write-Log -LogOutput "No interactive user, skipping." -ComponentName "Main" -Path $LogLocation -Name $LogName
    Exit-Script -ExitCode 0
}

# Skip if BitLocker FVE policy is not configured to require a PIN
$fve = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
if ($null -eq $fve -or $fve.UseTPMPIN -ne 2 -or $fve.UseTPM -ne 2 -or $fve.UseEnhancedPIN -ne 1 -or $fve.MinimumPIN -lt 4) {
    Write-Log -LogOutput "BitLocker PIN policy not configured, skipping." -ComponentName "Main" -Path $LogLocation -Name $LogName
    Exit-Script -ExitCode 0
}

# Flag for remediation if BitLocker protection was suspended and needs to be resumed
if (Test-BitLockerShouldBeResumed) {
    Write-Log -LogOutput "BitLocker should be resumed, remediation required." -ComponentName "Main" -Path $LogLocation -Name $LogName
    Exit-Script -ExitCode 1
}

# Flag for remediation if no PIN protector is configured
if (!(Test-BitLockerPINProtectorSet)) {
    Write-Log -LogOutput "PIN protector missing, remediation required." -ComponentName "Main" -Path $LogLocation -Name $LogName
    Exit-Script -ExitCode 1
}

Exit-Script -ExitCode 0
