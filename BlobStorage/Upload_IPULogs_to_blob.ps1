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

$Setupdiag = 'C:\Windows\Temp\Setupdiag.exe'
$TSHostname = $env:computername

$hostname = ($TSHostname).tolower()
$Timestamp = get-date -f yyyy-MM-dd-HH-mm-ss
$localpath = "C:\temp\Logs\$hostname-IPU-$Timestamp"

New-Item -ItemType Directory -Path $localpath -Force
New-Item -ItemType Directory -Path $localpath\IPU -Force
Start-Process -FilePath $Setupdiag -ArgumentList "/Output:$($localpath)\IPU\Results.log" -Wait

Compress-Archive -Path $localpath -DestinationPath "C:\temp\Logs\$hostname-IPU-$Timestamp.zip"

$clientContext = New-AzureStorageContext -SasToken ($BlobProperties.storsas) -StorageAccountName ($blobproperties.StorageAccountName)

Set-AzureStorageBlobContent -Context $ClientContext -container ($BlobProperties.container) -File "C:\temp\Logs\$hostname-IPU-$Timestamp.zip"