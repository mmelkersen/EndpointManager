<#
======================================================================================================
 
 Created on:    22.04.2021
 Created by:    Mattias Melkersen
 Version:       0.1  
 Mail:          mm@mindcore.dk
 twitter:       @mmelkersen
 Function:      Remediation script if .net 3.5 windows feature has been enabled. Use it together with ProActive Remediation.

 
 This script is provided As Is
 Compatible with Windows 10 and later
======================================================================================================

#>

Try 
    {
        Enable-WindowsOptionalFeature -Online -FeatureName 'NetFx3' -NoRestart
        Write-Host "Installed .Net 3.5 Successfully"
    }
    catch
    {
        Write-Host ".net 3.5 installation failed"
    }