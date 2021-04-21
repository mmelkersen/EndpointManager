<#
======================================================================================================
 
 Created on:    21.04.2021
 Created by:    Mattias Melkersen
 Version:       0.1  
 Mail:          mm@mindcore.dk
 twitter:       @mmelkersen
 Function:      Detect setting in Lenovo BIOS

  This script is provided As Is
 Compatible with Windows 10 and later
======================================================================================================

#>

[String]$Manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer

If ($Manufacturer -eq "LENOVO")
{

    $BIOS = (Get-WmiObject -Class Lenovo_BiosSetting -Namespace root\wmi).CurrentSetting | Where-Object {$_ -like "SecureBoot*"} | Sort-Object
    
    If ($BIOS -ne "SecureBoot,Enable")
        {
            write-host "BIOS Settings NOT compliant"
            exit 1
        }
        else 
        {
            write-host "BIOS Settings OK"  
            exit 0  
        }
}