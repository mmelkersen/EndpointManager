<#
======================================================================================================
 
 Created on:    19.04.2021
 Created by:    Mattias Melkersen
 Version:       0.1  
 Mail:          mm@mindcore.dk
 twitter:       @mmelkersen
 Function:      Configure Lenovo BIOS

 This script is provided As Is
 Compatible with Windows 10 and later
======================================================================================================

#>

$Logfile = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\BIOS_Settings.log" 
Start-Transcript -Path $Logfile

Function Get_Lenovo_BIOS_Settings
    {
     $Script:Get_BIOS_Settings = gwmi -class Lenovo_BiosSetting -namespace root\wmi  | select-object currentsetting | Where-Object {$_.CurrentSetting -ne ""} |
     select-object @{label = "Setting"; expression = {$_.currentsetting.split(",")[0]}} , 
     @{label = "Value"; expression = {$_.currentsetting.split(",*;[")[1]}} 
     Write-Host "Current BIOS Settings "$Get_BIOS_Settings
    }  

    $BIOS = (Get-WmiObject -Class Lenovo_BiosSetting -Namespace root\wmi).CurrentSetting | Where-Object {$_ -ne ""} | Sort-Object
    $BIOS.
Stop-Transcript
Write_Log -Message_Type "INFO" -Message "The 'Set BIOS settings for Lenovo' process starts"  
Write_Log -Message_Type "INFO" -Message "Current settings Configurered " + $CurrentBIOSSettings
 

$Script:IsPasswordSet = (gwmi -Class Lenovo_BiosPasswordSettings -Namespace root\wmi).PasswordState					
If (($IsPasswordSet -eq 1) -or ($IsPasswordSet -eq 2) -or ($IsPasswordSet -eq 3))
	{
		Write_Log -Message_Type "INFO" -Message "A password is configured"  
		If($MyPassword -eq "")
			{
				Write_Log -Message_Type "WARNING" -Message "No password has been sent to the script"  	
				Break
			}
		ElseIf($Language -eq "")
			{
				Write_Log -Message_Type "WARNING" -Message "No language has been sent to the script"  	
				Write_Log -Message_Type "WARNING" -Message "The default language will be US" 
				$Script:Language = 'US'
			}			
	}	

$Script:IsPasswordSet = (gwmi -Class Lenovo_BiosPasswordSettings -Namespace root\wmi).SecureBoot

$tag = "$($env:ProgramData)\Lenovo\ThinkBiosConfig\ThinkBiosConfig.tag"
$arg = '"file=ThinkPadBiosConfig.ini" "key=secretkey"'
$log = '"log=%ProgramData%\Lenovo\ThinkBiosConfig\""'

try {
    if (!(Test-Path -Path $tag -PathType Leaf)) {
        Write-Host "Creating TBCT directory..."
        New-Item -ItemType File -Path $tag -Force -ErrorAction Stop
        Set-Content -Path $tag -Value "Bios Settings Configured"
        Write-Host "Tag file created..."

        Start-Process cmd.exe -ArgumentList "/C ThinkBiosConfig.hta $arg $log" -NoNewWindow -Wait
        Write-Host "Bios Settings Configured"
        Exit 3010
    }
    else {
        Write-Host "Bios Settings already configured..."
        Exit 0
    }
}
catch [System.IO.IOException] {
    Write-Host "$($_.Exception.Message)"
}
catch {
    Write-Host "$($_.Exception.Message)"
}



$FileToDownload = "tier1_general.xml"
$Destination = "C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile"

$Logfile = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\CiscoAnyConnectProfile.log"

Start-Transcript -Path $Logfile

Write-Host "Installing NuGet package..."
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

If(-not(Get-InstalledModule azure.storage -ErrorAction silentlycontinue)){
    Install-Module azure.storage -Confirm:$False -Force
}

If(-not(Get-InstalledModule azureRM.profile -ErrorAction silentlycontinue)){
    Install-Module azureRM.profile -Confirm:$False -Force
}

Write-Host "Importing modules..."
Import-Module azure.storage
Import-module AzureRM.profile

$BlobProperties = @{

    StorageAccountName   = 'desktopmgmt'
    storSas              = '?sp=rl&st=2021-04-08T08:22:55Z&se=2025-01-09T08:22:00Z&sv=2020-02-10&sr=c&sig=pldRS7WuH1yQMqgjAi7QM0NciHNvRA4CQ%2BMkmcl%2BrZc%3D'
    container            = 'tier1'
}

Write-Host "Checking if $($Destination) folder exists"
if (!(test-path $Destination))
{
    Write-Host "Creating $($Destination) folder"
    New-Item -ItemType Directory -Path $Destination
}
else 
{
    Write-Host "Folder $($Destination) already existed. Skipping..."
}

Write-Host "Checking if file exists $($Destination)\$($FileToDownload)"
if (test-path "$($Destination)\$($FileToDownload)")
{
    Write-Host "Deleting file ""$($Destination)\$($FileToDownload)"""
    Remove-Item -Path "$($Destination)\$($FileToDownload)" -Force
}

Write-Host "Authenticating with Azure Storage"
$clientContext = New-AzureStorageContext -SasToken ($BlobProperties.storsas) -StorageAccountName ($blobproperties.StorageAccountName)

Write-Host "Getting content and copying to the device"
Get-AzureStorageBlobContent -Destination $Destination -Container ($BlobProperties.container) -Context $clientContext -Blob $FileToDownload -Force
Write-Host "Done"

Stop-Transcript