#=====================================================================================================
# Created on:   09.06.2021
# Created by:   Mattias Melkersen
# Version:	    0.1 
# Mail:         mm@mindcore.dk
# Twitter:      MMelkersen
# Function:     Sample script to check Intune Management Extension is up to date
# 
# This script is provided As Is
# Compatible with Windows 10 and later
#=====================================================================================================

$SoftwareIME = Get-WmiObject -Class Win32_Product | where name -eq "Microsoft Intune Management Extension"

If ($SoftwareIME.version -ge "1.43.203.0")
    {
        Write-host "IME is ok"
    }
    Else
    {
        Write-host "IME need upgrade"
    }