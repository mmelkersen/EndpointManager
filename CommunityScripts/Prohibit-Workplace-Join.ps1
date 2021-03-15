<#
======================================================================================================
 
 Created on:    12.03.2021
 Created by:    msendpointmgr
 Version:       0.1  
 Mail:          mm@mindcore.dk
 twitter:       @mmelkersen
 Function:      Removing "allow my organization to manage my device"
 

 https://msendpointmgr.com/2021/03/11/are-you-tired-of-allow-my-organization-to-manage-my-device/

======================================================================================================

#>

#Setting registry key to block AAD Registration to 3rd party tenants. 
$RegistryLocation = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin\"
$keyname = "BlockAADWorkplaceJoin"

#Test if path exists and create if missing
if (!(Test-Path -Path $RegistryLocation)){
Write-Output "Registry location missing. Creating"
New-Item $RegistryLocation | Out-Null
}

#Force create key with value 1 
New-ItemProperty -Path $RegistryLocation -Name $keyname -PropertyType DWord -Value 1 -Force | Out-Null
Write-Output "Registry key set"