#=====================================================================================================
# Created on:   19.04.2022
# Created by:   Mattias Melkersen
# Version:	    0.1 
# Mail:         mm@mindcore.dk
# Twitter:      MMelkersen
# Function:     Sample script to check McAfee status on a device
# 
# This script is provided As Is
# Compatible with Windows 10 and later
#=====================================================================================================

$AV = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct | Where-Object {$_.displayName -eq "McAfee Endpoint Security"}

switch ($AV.productState) {
"262144" {$UpdateStatus = "Up to date" ;$RealTimeProtectionStatus = "Disabled"}
"262160" {$UpdateStatus = "Out of date" ;$RealTimeProtectionStatus = "Disabled"}
"266240" {$UpdateStatus = "Up to date" ;$RealTimeProtectionStatus = "Enabled"}
"266256" {$UpdateStatus = "Out of date" ;$RealTimeProtectionStatus = "Enabled"}
"393216" {$UpdateStatus = "Up to date" ;$RealTimeProtectionStatus = "Disabled"}
"393232" {$UpdateStatus = "Out of date" ;$RealTimeProtectionStatus = "Disabled"}
"393488" {$UpdateStatus = "Out of date" ;$RealTimeProtectionStatus = "Disabled"}
"397312" {$UpdateStatus = "Up to date" ;$RealTimeProtectionStatus = "Enabled"}
"397328" {$UpdateStatus = "Out of date" ;$RealTimeProtectionStatus = "Enabled"}
"397584" {$UpdateStatus = "Out of date" ;$RealTimeProtectionStatus = "Enabled"}
"397568" {$UpdateStatus = "Up to date"; $RealTimeProtectionStatus = "Enabled"}
"393472" {$UpdateStatus = "Up to date" ;$RealTimeProtectionStatus = "Disabled"}
default {$UpdateStatus = "Unknown" ;$RealTimeProtectionStatus = "Unknown"}
}

$AVName = $AV.displayname
$AVUpdateStatus = $UpdateStatus
$AVProtection = $RealTimeProtectionStatus

Write-host "Antivirus: $($AVName) - Protection State: $($AVProtection) - Protection Code: $($AV.productState) - Product State: $($AVUpdateStatus)"

If ($UpdateStatus -eq "Out of date" -or $RealTimeProtectionStatus -eq "Disabled") 
{
    exit 1
}