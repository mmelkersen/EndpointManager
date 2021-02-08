#=====================================================================================================
# Created on:   08.02.2021
# Created by:   Mattias Melkersen
# Version:	    0.2 
# Mail:         mm@mindcore.dk
# Twitter:      MMelkersen
# Function:     Sample script to upload IPU files to Azure Blob storage
# 
# Special Thanks: 
# Tom Degreef https://www.oscc.be/sccm/Logging-in-the-cloud-Part-1/
# Adam Gross  https://www.asquaredozen.com/2020/07/26/demystifying-windows-10-feature-update-blocks/ 
# 
# Requirements:
# install-module azure.storage, AzureRM.profile and FU.WhyAmIBlocked
#
# This script is provided As Is
# Compatible with Windows 10 and later
#=====================================================================================================

If(-not(Get-InstalledModule azure.storage -ErrorAction silentlycontinue)){
    Install-Module azure.storage -Confirm:$False -Force
}

If(-not(Get-InstalledModule FU.WhyAmIBlocked -ErrorAction silentlycontinue)){
    Install-Module FU.WhyAmIBlocked -Confirm:$False -Force
}

import-module FU.WhyAmIBlocked
Import-Module azure.storage

$BlobProperties = @{

    StorageAccountName   = 'xxx'
    storSas              = 'xxx'
    container            = 'xxx'
}

$Setupdiag = 'C:\Windows\Temp\Setupdiag.exe'
$TSHostname = $env:computername

$hostname = ($TSHostname).tolower()
$Timestamp = get-date -f yyyy-MM-dd-HH-mm-ss
$localpath = "C:\temp\Logs\$hostname-IPU-$Timestamp"

#Building temporary folders
New-Item -ItemType Directory -Path $localpath -Force
New-Item -ItemType Directory -Path $localpath\IPU -Force

#Running diagnostics
Start-Process -FilePath $Setupdiag -ArgumentList "/Output:$($localpath)\IPU\Results.log" -Wait

#Determine if .net 2.0 and 3.5 are installed
$DotNetInstallationInfo = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse
$InstalledDotNetVersions = $DotNetInstallationInfo | Get-ItemProperty -Name 'Version' -ErrorAction SilentlyContinue
$InstalledVersionNumbers = $InstalledDotNetVersions | ForEach-Object {$_.Version -as [System.Version]}
$Installed3Point5Versions = $InstalledVersionNumbers | Where-Object {$_.Major -eq 3 -and $_.Minor -eq 5}
$DotNet3Point5IsInstalled = $Installed3Point5Versions.Count -ge 1
Write-Output $DotNet3Point5IsInstalled

If ($DotNet3Point5IsInstalled -eq $False)
    {
        Write-host ".net 3.5 not detected Cannot proceed."
    }
    Else
    {
        #Using Adam Gross method as addition to Setupdiag
        Get-FUBlocks
        Copy-Item -Path "C:\FeatureUpdateBlocks" -Destination "$localpath\IPU" -Recurse
        Remove-Item -path "C:\FeatureUpdateBlocks" -Recurse -Confirm:$false -force
    }

Compress-Archive -Path $localpath -DestinationPath "C:\temp\Logs\$hostname-IPU-$Timestamp.zip"
$clientContext = New-AzureStorageContext -SasToken ($BlobProperties.storsas) -StorageAccountName ($blobproperties.StorageAccountName)

Set-AzureStorageBlobContent -Context $ClientContext -container ($BlobProperties.container) -File "C:\temp\Logs\$hostname-IPU-$Timestamp.zip"