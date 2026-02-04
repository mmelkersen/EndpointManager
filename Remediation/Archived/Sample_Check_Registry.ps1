#=====================================================================================================
# Created on:   14.01.2021
# Created by:   Mattias Melkersen
# Version:	  0.1 
# Mail:         mm@mindcore.dk
# Twitter:      MMelkersen
# Function:     Sample script to check baseline are correct
# 
# This script is provided As Is
# Compatible with Windows 10 and later
#=====================================================================================================

function Check-Registry
 
{

Param ([string]$RegistryPath,[string]$name,[string]$value)

If ((Get-Itemproperty $RegistryPath).$name -eq $value)
       {

        #Exit 0 for machine does contain setting
        Write-Host "Success: Baseline Applied Correctly"
        exit 0  

       } 
Else 
       {

        #Exit 1 for machine does not contain setting
        Write-Host "Failed: Baseline failed. Key not found: $($RegistryPath)\$($name)"
        exit 1 

        }
}
Check-Registry -RegistryPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -name "DisableAutoplay" -Value "1"