#=====================================================================================================
# Created on:   29.01.2021
# Created by:   Mattias Melkersen
# Version:	    0.1 
# Mail:         mm@mindcore.dk
# Twitter:      MMelkersen
# Function:     Sample script to upload files to Azure Blob storage
# 
# Special Thanks: 
# Tom Degreef https://www.oscc.be/sccm/Logging-in-the-cloud-Part-1/
#
# Requirements:
# install-module azure.storage and AzureRM.profile
#
# This script is provided As Is
# Compatible with Windows 10 and later
#=====================================================================================================

If(-not(Get-InstalledModule azure.storage -ErrorAction silentlycontinue)){
    Install-Module azure.storage -Confirm:$False -Force
}

Import-Module azure.storage

$BlobProperties = @{

    StorageAccountName   = 'xxx'
    storSas              = 'xxx'
    container            = 'xxx'
}

$TSHostname = $env:computername

write-host "Hostname will be : $TSHostname"

$hostname = ($TSHostname).tolower()
$Timestamp = get-date -f yyyy-MM-dd-HH-mm-ss
$localpath = "C:\LogsToAzure\$hostname-$Timestamp"

New-Item -ItemType Directory -Path $localpath -Force
New-Item -ItemType Directory -Path $localpath\Panther -Force
New-Item -ItemType Directory -Path $localpath\Software -Force
New-Item -ItemType Directory -Path $localpath\CCM -Force
New-Item -ItemType Directory -Path $localpath\Dism -Force

Get-ChildItem -Path C:\Windows\Panther | Copy-Item -Destination $localpath\Panther -Recurse
Get-ChildItem -Path C:\Windows\Logs\Software | Copy-Item -Destination $localpath\Software -Recurse
Get-ChildItem -Path C:\Windows\CCM\Logs | Copy-Item -Destination $localpath\CCM -Recurse
Get-ChildItem -Path C:\Windows\Logs\Dism | Copy-Item -Destination $localpath\Dism -Recurse

write-host "compressing logfiles"
Compress-Archive -Path $localpath -DestinationPath "C:\LogsToAzure\$hostname-$Timestamp.zip"

write-host "upload to azure"
$clientContext = New-AzureStorageContext -SasToken ($BlobProperties.storsas) -StorageAccountName ($blobproperties.StorageAccountName)

Set-AzureStorageBlobContent -Context $ClientContext -container ($BlobProperties.container) -File "C:\LogsToAzure\$hostname-$Timestamp.zip"