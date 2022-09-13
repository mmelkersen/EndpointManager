<#
======================================================================================================

# Created on:   13.09.2022
# Created by:   Mattias Melkersen
# Version:	    0.2 
# Mail:         mm@mindcore.dk
# Twitter:      MMelkersen
# Function:     Sample script to determine that a device does the right thing against Windows Update for Business
# 
# This script is provided As Is
# Compatible with Windows 10 and later

Special thanks to Trevor, Jannik and David for great scripting and inspiration.
#https://smsagent.blog/2021/04/20/get-the-current-patch-level-for-windows-10-with-powershell/
#https://jannikreinhard.com/2022/08/24/check-autopilot-enrollment-prerequisite/
#https://www.osdcloud.com/

======================================================================================================

*HISTORY*
Thanks to all testers during the development of this - @ncbrady, @jannik_reinhard, @manelrodero, @chriscorriveau, @brianfgonzalez

Version 0.1 - Created first draft
Version 0.2 - Fixed SKU, Removed the need for local administrative permission by changing a function, added Windows Version, added better text for WindowsUpdate.log, Removed 1014 event

#>

$Title = 'Invoke-WindowsUpdateForBusinessReadiness'
$ScriptVersion = '0.2'

$WindowsUpdateLog = "C:\Temp\Windowsupdate.log"
Get-WindowsUpdateLog -LogPath $WindowsUpdateLog -Verbose

Write-Host ""
Write-Host -ForegroundColor Yellow "* Windows Update eventlogs *"

Function Get-CurrentPatchInfo
{

        [CmdletBinding()]
    Param(
        [switch]$ListAllAvailable,
        [switch]$ExcludePreview,
        [switch]$ExcludeOutofBand
    )
    $ProgressPreference = 'SilentlyContinue'
    $URI = "https://aka.ms/WindowsUpdateHistory" # Windows 10 release history

    Function Get-MyWindowsVersion {
            [CmdletBinding()]
            Param
            (
                $ComputerName = $env:COMPUTERNAME
            )

            $Table = New-Object System.Data.DataTable
            $Table.Columns.AddRange(@("ComputerName","Windows Edition","Version","OS Build"))
            $ProductName = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' –Name ProductName).ProductName
            Try
            {
                $Version = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' –Name ReleaseID –ErrorAction Stop).ReleaseID
            }
            Catch
            {
                $Version = "N/A"
            }
            $CurrentBuild = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' –Name CurrentBuild).CurrentBuild
            $UBR = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' –Name UBR).UBR
            $OSVersion = $CurrentBuild + "." + $UBR
            $TempTable = New-Object System.Data.DataTable
            $TempTable.Columns.AddRange(@("ComputerName","Windows Edition","Version","OS Build"))
            [void]$TempTable.Rows.Add($env:COMPUTERNAME,$ProductName,$Version,$OSVersion)

            Return $TempTable
    }

    Function Convert-ParsedArray {
        Param($Array)

        $ArrayList = New-Object System.Collections.ArrayList
        foreach ($item in $Array)
        {      
            [void]$ArrayList.Add([PSCustomObject]@{
                Update = $item.outerHTML.Split('>')[1].Replace('</a','').Replace('&#x2014;',' – ')
                KB = "KB" + $item.href.Split('/')[-1]
                InfoURL = "https://support.microsoft.com" + $item.href
                OSBuild = $item.outerHTML.Split('(OS ')[1].Split()[1] # Just for sorting
            })
        }
        Return $ArrayList
    }

    If ($PSVersionTable.PSVersion.Major -ge 6)
    {
        $Response = Invoke-WebRequest –Uri $URI –ErrorAction Stop
    }
    else 
    {
        $Response = Invoke-WebRequest –Uri $URI –UseBasicParsing –ErrorAction Stop
    }

    If (!($Response.Links))
    { throw "Response was not parsed as HTML"}
    $VersionDataRaw = $Response.Links | where {$_.outerHTML -match "supLeftNavLink" -and $_.outerHTML -match "KB"}
    $CurrentWindowsVersion = Get-MyWindowsVersion –ErrorAction Stop

    If ($ListAllAvailable)
    {
        If ($ExcludePreview -and $ExcludeOutofBand)
        {
            $AllAvailable = $VersionDataRaw | where {$_.outerHTML -match $CurrentWindowsVersion.'OS Build'.Split('.')[0] -and $_.outerHTML -notmatch "Preview" -and $_.outerHTML -notmatch "Out-of-band"}
        }
        ElseIf ($ExcludePreview)
        {
            $AllAvailable = $VersionDataRaw | where {$_.outerHTML -match $CurrentWindowsVersion.'OS Build'.Split('.')[0] -and $_.outerHTML -notmatch "Preview"}
        }
        ElseIf ($ExcludeOutofBand)
        {
            $AllAvailable = $VersionDataRaw | where {$_.outerHTML -match $CurrentWindowsVersion.'OS Build'.Split('.')[0] -and $_.outerHTML -notmatch "Out-of-band"}
        }
        Else
        {
            $AllAvailable = $VersionDataRaw | where {$_.outerHTML -match $CurrentWindowsVersion.'OS Build'.Split('.')[0]}
        }
        $UniqueList = (Convert-ParsedArray –Array $AllAvailable) | Sort OSBuild –Descending –Unique
        $Table = New-Object System.Data.DataTable
        [void]$Table.Columns.AddRange(@('Update','KB','InfoURL'))
        foreach ($Update in $UniqueList)
        {
            [void]$Table.Rows.Add(
                $Update.Update,
                $Update.KB,
                $Update.InfoURL
            )
        }
        Return $Table
    }

    $CurrentPatch = $VersionDataRaw | where {$_.outerHTML -match $CurrentWindowsVersion.'OS Build'} | Select –First 1
    If ($ExcludePreview -and $ExcludeOutofBand)
    {
        $LatestAvailablePatch = $VersionDataRaw | where {$_.outerHTML -match $CurrentWindowsVersion.'OS Build'.Split('.')[0] -and $_.outerHTML -notmatch "Out-of-band" -and $_.outerHTML -notmatch "Preview"} | Select –First 1
    }
    ElseIf ($ExcludePreview)
    {
        $LatestAvailablePatch = $VersionDataRaw | where {$_.outerHTML -match $CurrentWindowsVersion.'OS Build'.Split('.')[0] -and $_.outerHTML -notmatch "Preview"} | Select –First 1
    }
    ElseIf ($ExcludeOutofBand)
    {
        $LatestAvailablePatch = $VersionDataRaw | where {$_.outerHTML -match $CurrentWindowsVersion.'OS Build'.Split('.')[0] -and $_.outerHTML -notmatch "Out-of-band"} | Select –First 1
    }
    Else
    {
        $LatestAvailablePatch = $VersionDataRaw | where {$_.outerHTML -match $CurrentWindowsVersion.'OS Build'.Split('.')[0]} | Select –First 1
    }


    $Table = New-Object System.Data.DataTable
    [void]$Table.Columns.AddRange(@('OSVersion','OSEdition','OSBuild','CurrentInstalledUpdate','CurrentInstalledUpdateKB','CurrentInstalledUpdateInfoURL','LatestAvailableUpdate','LastestAvailableUpdateKB','LastestAvailableUpdateInfoURL'))
    [void]$Table.Rows.Add(
        $CurrentWindowsVersion.Version,
        $CurrentWindowsVersion.'Windows Edition',
        $CurrentWindowsVersion.'OS Build',
        $CurrentPatch.outerHTML.Split('>')[1].Replace('</a','').Replace('&#x2014;',' – '),
        "KB" + $CurrentPatch.href.Split('/')[-1],
        "https://support.microsoft.com" + $CurrentPatch.href,
        $LatestAvailablePatch.outerHTML.Split('>')[1].Replace('</a','').Replace('&#x2014;',' – '),
        "KB" + $LatestAvailablePatch.href.Split('/')[-1],
        "https://support.microsoft.com" + $LatestAvailablePatch.href
        )
    Return $Table

}

#================================================
# Initialize
#================================================
$Title = 'Watch-FeatureUpdates'
$host.ui.RawUI.WindowTitle = $Title
$host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.size(2000,2000)
$host.ui.RawUI.BackgroundColor = ($bckgrnd = 'Black')
#Clear-Host
#================================================
# Temp
#================================================
if (!(Test-Path "$env:SystemDrive\Temp")) {
    New-Item -Path "$env:SystemDrive\Temp" -ItemType Directory -Force
}
#================================================
# Transcript
#================================================
$Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-$Title.log"
Start-Transcript -Path (Join-Path "$env:SystemDrive\Temp" $Transcript) -ErrorAction Ignore
$host.ui.RawUI.WindowTitle = "$Title $env:SystemDrive\Temp\$Transcript"
#================================================
# Main Variables
#================================================
$Monitor = $true
$Results = @()
$FormatEnumerationLimit = -1
# This will go back 1 days in the logs. Adjust as needed
[DateTime]$StartTime = (Get-Date).AddDays(-8)

$InfoWhite = @()
$InfoCyan = @(62402,62406)
$InfoBlue = @()
$InfoDarkBlue = @()


    $IncludeEventSource = @(19,43,44)


# Remove Line Wrap
reg add HKCU\Console /v LineWrap /t REG_DWORD /d 0 /f
#================================================
# LogName
# These are the WinEvent logs to monitor
#================================================
$LogName = @(
    'System'
)
#================================================
# FilterHashtable
#================================================
$FilterHashtable = @{
    StartTime = $StartTime
    LogName = $LogName
}
#================================================
# Get-WinEvent Results
#================================================
$Results = Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction Ignore | Sort-Object TimeCreated | Where-Object {$_.ID -in $IncludeEventSource}
$Results = $Results | Select-Object TimeCreated,LevelDisplayName,LogName,Id, @{Name='Message';Expression={ ($_.Message -Split '\n')[0]}}
$Clixml = "$env:SystemDrive\Temp\$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-Events.clixml"
$Results | Export-Clixml -Path $Clixml
#================================================
# Display Results
#================================================
foreach ($Item in $Results) {
    if ($Item.LevelDisplayName -eq 'Error') {
        Write-Host "$($Item.TimeCreated) ERROR:$($Item.Id)`t$($Item.Message)" -ForegroundColor Red
    }
    elseif ($Item.LevelDisplayName -eq 'Warning') {
        Write-Host "$($Item.TimeCreated) WARN :$($Item.Id)`t$($Item.Message)" -ForegroundColor Yellow
    }
    elseif (($Item.Message -match 'fail') -or ($Item.Message -match 'empty profile')) {
        Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($Item.Message)" -ForegroundColor Red
    }
    elseif ($Item.Message -like "*Feature update*") {
        Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($Item.Message)" -ForegroundColor Green
        $FeatureName = $Item.Message
    }
    elseif ($Item.id -eq "43") {
        Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($Item.Message)" -ForegroundColor White
    }
    elseif ($Item.Id -in $InfoCyan) {
        Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($Item.Message)" -ForegroundColor Cyan
    }
    elseif ($Item.Id -in $InfoBlue) {
        Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($Item.Message)" -ForegroundColor Blue
    }
    elseif ($Item.Id -in $InfoDarkBlue) {
        Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($Item.Message)" -ForegroundColor DarkBlue
    }
    else {
        Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($Item.Message)" -ForegroundColor DarkGray
    }
}

Write-host ""
Write-host ""
Write-Host -ForegroundColor Yellow "* Windows Update LOGS *"

$Result = Get-Content -Path $WindowsUpdateLog | Select-String -Pattern "Feature update to Windows" | ForEach-Object {$_.Line.Substring([regex]::match($_.Line,"{").index+1,32)} 

If ($Result -ne $null)
    { 
        $WindowsUpdateLogResults = Get-Content -Path $WindowsUpdateLog | Select-String -Pattern $Result.Item($Result.Count -1) -ErrorAction SilentlyContinue
    }
else
    {
        Write-Host "  No Feature Update data found in WindowsUpdate.log. This message appears if there were no recent Feature update installed." -ForegroundColor red
    }    

    foreach ($Item in $WindowsUpdateLogResults) {

        if ($Item -like '*Downloading from*') {
            Write-Host "$($Item)" -ForegroundColor Green
            [String]$FeatureUpdateDownloadPath = $Item 
        }
        elseif ($Item -like '*DownloadManager*') {
            Write-Host "$($Item)" -ForegroundColor White
        }
        elseif ($Item -like '*ComApi*') {
            Write-Host "$($Item)" -ForegroundColor Yellow
        }
        elseif ($Item -like '*UDP*') {
            Write-Host "$($Item)" -ForegroundColor DarkCyan
        }
        elseif ($Item -like '*Requires Reboot:*') {
            Write-Host "$($Item)" -ForegroundColor Cyan
        }
        else {
            Write-Host "$($Item)" -ForegroundColor DarkGray
        }
     }

function Get-ConnectionTest {
    @("dl.delivery.mp.microsoft.com", "update.microsoft.com", "tsfe.trafficshaping.dsp.mp.microsoft.com", "devicelistenerprod.microsoft.com", "login.windows.net") | ForEach-Object {
        $result = (Test-NetConnection -Port 443 -ComputerName $_)    
        Write-Host -NoNewline "  $($result.ComputerName) ($($result.RemoteAddress)): "
        if($result.TcpTestSucceeded) {
            Write-Host -ForegroundColor Green $result.TcpTestSucceeded
        }else{
            Write-Host -ForegroundColor Red $result.TcpTestSucceeded
        }
    }
    @("time.windows.com") | ForEach-Object {
    $result = (Test-NetConnection -Port 80 -ComputerName $_)      
    Write-Host -NoNewline "  $($result.ComputerName) ($($result.RemoteAddress)): "
    if($result.TcpTestSucceeded) {
        Write-Host -ForegroundColor Green $result.TcpTestSucceeded
    }else{
        Write-Host -ForegroundColor Red $result.TcpTestSucceeded
    }
    }

    Write-Host
}

$UpdateEngine = (New-Object -ComObject "Microsoft.Update.ServiceManager").services | Where-Object { $_.IsDefaultAUService -eq 'True' } | Select-Object -ExpandProperty Name
$DeviceName = (Get-CIMInstance -ClassName Win32_OperatingSystem -NameSpace root\cimv2).CSName

#Get OS Information
$WindowsEditionSKU = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

#Get Windows name plus edition
$WindowsEdition = Get-CurrentPatchInfo

#get Update Ring information
$FeatureUpdateDefferal = Get-ItemPropertyValue -path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update\" -name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue

#Gstatus must be 0 otherwise there is a safeguard
$SafeGuard = Get-ItemPropertyValue -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser\GWX\" -name "GStatus" -ErrorAction SilentlyContinue

#Grabbing update health tool
function Search-RegistryUninstallKey {
param($SearchFor,[switch]$Wow6432Node)
$results = @()
$keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | 
    foreach {
        $obj = New-Object psobject
        Add-Member -InputObject $obj -MemberType NoteProperty -Name GUID -Value $_.pschildname
        Add-Member -InputObject $obj -MemberType NoteProperty -Name DisplayName -Value $_.GetValue("DisplayName")
        Add-Member -InputObject $obj -MemberType NoteProperty -Name DisplayVersion -Value $_.GetValue("DisplayVersion")
        if ($Wow6432Node)
        {Add-Member -InputObject $obj -MemberType NoteProperty -Name Wow6432Node? -Value "No"}
        $results += $obj
        }

if ($Wow6432Node) {
$keys = Get-ChildItem HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | 
    foreach {
        $obj = New-Object psobject
        Add-Member -InputObject $obj -MemberType NoteProperty -Name GUID -Value $_.pschildname
        Add-Member -InputObject $obj -MemberType NoteProperty -Name DisplayName -Value $_.GetValue("DisplayName")
        Add-Member -InputObject $obj -MemberType NoteProperty -Name DisplayVersion -Value $_.GetValue("DisplayVersion")
        Add-Member -InputObject $obj -MemberType NoteProperty -Name Wow6432Node? -Value "Yes"
        $results += $obj
        }
    }
$results | sort DisplayName | where {$_.DisplayName -match $SearchFor}
} 

$MicrosoftUpdateHealthTools = Search-RegistryUninstallkey -SearchFor "Microsoft Update Health Tools"       

#Gathering Telemetry data
$MicrosoftTelemetryLevel = Get-ItemPropertyValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" -name "AllowTelemetry_PolicyManager" -ErrorAction SilentlyContinue
if ($MicrosoftTelemetryLevel -eq (1)) {$MicrosoftTelemetryLevel = "Basic"}
if ($MicrosoftTelemetryLevel -eq (2)) {$MicrosoftTelemetryLevel = "Required"}
if ($MicrosoftTelemetryLevel -eq (3)) {$MicrosoftTelemetryLevel = "Full"}

#Get the current patch informations
$CurrentPatchLevel = Get-CurrentPatchInfo

#Get info on the Microsoft Assistance sign-in service
$SignAssistentService = Get-Service "wlidsvc"

#Get info if the Windows Health policy has been enabled
$WindowsHealthMonitor = Get-ItemPropertyValue -path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceHealthMonitoring\" -name "ConfigDeviceHealthMonitoringScope" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host -ForegroundColor Yellow "* Windows Update General Information *"

Write-Host -NoNewline "  DeviceName: "
Write-Host -ForegroundColor Green $DeviceName

Write-host -NoNewline "  OS: "
Write-Host -ForegroundColor Green $WindowsEdition.OSEdition

Write-Host -NoNewline "  OS Supported SKU: "
if($WindowsEditionSKU.EditionID -eq "Enterprise" -or $WindowsEditionSKU.EditionID -eq "Pro" -or $WindowsEditionSKU.EditionID -eq "Professional" -or $WindowsEditionSKU.EditionID -eq "Education" -or $WindowsEditionSKU.EditionID -eq "Pro Education" -or $WindowsEditionSKU.EditionID -eq "Professional Education") 
{
    Write-Host -ForegroundColor Green "$($WindowsEditionSKU.EditionID) (OK)"
}
Else
{
    Write-Host -ForegroundColor red "Current version of Windows is not suppported ($($WindowsEditionSKU.EditionID))"
}

Write-Host -NoNewline "  OS patch Level: "
Write-Host -ForegroundColor Green $CurrentPatchLevel.OSBuild

Write-Host -NoNewline "  Current Installed Update: "
Write-Host -ForegroundColor Green $CurrentPatchLevel.CurrentInstalledUpdate

Write-Host -NoNewline "  Lastest available Update: "
Write-Host -ForegroundColor Green $CurrentPatchLevel.LatestAvailableUpdate

Write-Host -NoNewline "  Windows Update Source: "
if($UpdateEngine -eq "Microsoft Update") {
    Write-Host -ForegroundColor Green $UpdateEngine
}else{
    Write-Host -ForegroundColor Red $UpdateEngine
}

Write-Host -NoNewline "  Microsoft Sign-in Assistant service: "
if($SignAssistentService.StartType -ne "Disabled") 
    {
        Write-Host -ForegroundColor Green "$($SignAssistentService.StartType) (OK)"
    }
    Else
    {
        Write-Host -ForegroundColor red "Microsoft Sign-in Assistant service is disabled and is required to be able to run!"
    }

Write-Host -NoNewline "  Windows Update Feature Deferal Value: "
if($FeatureUpdateDefferal -eq "0") 
    {
        Write-Host -ForegroundColor Green "$($FeatureUpdateDefferal) (OK)"
    }
    Else
    {
        Write-Host -ForegroundColor yellow "Feature Update deferal not set to recommend value (If you are only using Update ring, this is actually fine)"
    }

Write-Host -NoNewline "  Windows Update SafeGuard Hold: "
if($SafeGuard -eq "2") 
    {
        Write-Host -ForegroundColor Green "No SafeGuard found (OK)"
    }
    Else
    {
        Write-Host -ForegroundColor red "SafeGuard found futher debug use: Install-Module -name FU.WhyAMIBlocked"
    }

Write-Host -NoNewline "  Microsoft Health Tool Status: "
   if($MicrosoftUpdateHealthTools -ne $null) 
    {
        Write-Host -ForegroundColor Green "$($MicrosoftUpdateHealthTools.DisplayName) $($MicrosoftUpdateHealthTools.DisplayVersion) (Installed)"
    }
    Else
    {
        Write-Host -ForegroundColor red "Microsoft Update Health Tool (Not found)"
    } 

Write-Host -NoNewline "  Health Monitoring value: "
   if($WindowsHealthMonitor -like "*Updates*") 
    {
        Write-Host -ForegroundColor Green "$($WindowsHealthMonitor) (OK)"
    }
    Else
    {
        Write-Host -ForegroundColor red "To gather data for reporting you need to enable the policy Windows Health Monitoring: $($WindowsHealthMonitor)"
    }      


Write-Host -NoNewline "  Telemetry data: "
   if($MicrosoftTelemetryLevel -ne $null -and $MicrosoftTelemetryLevel -ne "Basic") 
    {
        Write-Host -ForegroundColor Green "$($MicrosoftTelemetryLevel) (OK)"
    }
    Else
    {
        Write-Host -ForegroundColor red "Telemetry level not satisfied (expected Required or Full): $($MicrosoftTelemetryLevel)"
    }  

Write-Host -NoNewline "  Feature Update: "
If ($FeatureName -ne $null)
    { 
        Write-Host $FeatureName.Substring($FeatureName.IndexOf('update:')+8,$FeatureName.Length - $FeatureName.IndexOf('update:')-8) -ForegroundColor Green
    }
else
    {
        Write-Host "Feature Update not applied recently - No data found" -ForegroundColor red
    }

Write-Host -NoNewline "  Feature Update State: "
If ($FeatureName -ne $null)
    { 
        Write-Host $FeatureName.Substring(0,$FeatureName.IndexOf(':')) -ForegroundColor Green
    }
else
    {
        Write-Host "Feature Update not applied recently - No data found" -ForegroundColor red
    }

Write-Host -NoNewline "  Feature Update Downloaded: "
If ($FeatureUpdateDownloadPath -ne $null)
    { 
        Write-host $FeatureUpdateDownloadPath.Substring($FeatureUpdateDownloadPath.IndexOf('Downloading'),$FeatureUpdateDownloadPath.Length - $FeatureUpdateDownloadPath.IndexOf('Downloading')) -ForegroundColor Green
    }
else
    {
        Write-Host "Feature Update not applied recently - No data found" -ForegroundColor red
    }

Write-Host " "
Write-Host -NoNewline "* ENDPOINT CONNECTIONS *`n" -ForegroundColor Yellow
Get-ConnectionTest
Write-Host "  NON-TESTED URLs BUT NEEDS TO BE ACCESSIBLE:" -ForegroundColor Yellow
Write-Host "  *.prod.do.dsp.mp.microsoft.com" -ForegroundColor Cyan
Write-Host "  *.windowsupdate.com" -ForegroundColor Cyan
Write-Host "  *.dl.delivery.mp.microsoft.com" -ForegroundColor Cyan
Write-Host "  *.notify.windows.com" -ForegroundColor Cyan

Write-host ""
Write-Host -NoNewline "* UPDATES FINAL STATUS (8 days back) *`n" -ForegroundColor Yellow
foreach ($Item in $Results) {
    if ($Item.id -eq "19") {
        Write-Host "  $($Item.TimeCreated) - $($Item.Message)" -ForegroundColor Green
    }
 }

 if (!($host.name -match "ISE")) {
    Write-Host ""
    Write-Host "Script Finalized"
    Write-Host "Script version: $ScriptVersion"
    
    $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
