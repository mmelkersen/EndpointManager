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

[string]$Logfile = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Baseline.log" 
Function Write_Log
	{
	param(
	$Message_Type, 
	$Message
	)
		$MyDate = "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)  
		Add-Content $LogFile  "$MyDate - $Message_Type : $Message"  
	} 

Try 
    {
        Write_Log -Message_Type "INFO" -Message "Enabling NetFx3..."
        Enable-WindowsOptionalFeature -Online -FeatureName 'NetFx3' -NoRestart
        Write-Host "Installed .Net 3.5 Successfully"
        Write_Log -Message_Type "INFO" -Message "Enabled NetFx3 Successfully"
    }
    catch
    {
        Write-Host ".net 3.5 installation failed"
        Write_Log -Message_Type "WARNING" -Message "Failed to enable NetFx3"
    }