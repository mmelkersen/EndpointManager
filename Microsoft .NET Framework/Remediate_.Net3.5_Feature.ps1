<#
======================================================================================================
 
 Created on:    22.04.2021
 Created by:    Mattias Melkersen
 Version:       0.2  
 Mail:          mm@mindcore.dk
 twitter:       @mmelkersen
 Function:      Remediation script if .net 3.5 windows feature has been enabled. Use it together with ProActive Remediation.

 History log
 v0.1 - Working natively with downloading content only from Microsoft
 v0.2 - Thanks to @maleroytw for elaborating on devices with state: DisabledWithPayloadRemoved. This version will be able to get payload from Github and add it using /Limitaccess

 This script is provided As Is
 Compatible with Windows 10 and later
======================================================================================================

#>

[String]$GithubPath = "https://github.com/mmelkersen/EndpointManager/blob/main/Microsoft%20.NET%20Framework/1909/Microsoft-Windows-NetFx3-OnDemand-Package~31bf3856ad364e35~amd64~en-US~.cab"
[String]$Repository = "EndpointManager"
[string]$Owner = "MattiasMelkersen"
[String]$path = "Microsoft .NET Framework"
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

    #Get build number
    $WindowsVersion = Get-ComputerInfo WindowsVersion
    Write_Log -Message_Type "INFO" -Message $WindowsVersion

    #Check if C:\Windows\temp\WinSXS exists
    if (!(test-path "C:\Windows\temp"))
        {
            New-Item -ItemType Directory -Path "C:\temp"
        }

    #Get files from Github
    Invoke-WebRequest -Uri $GithubPath - -OutFile "C:\temp\test.cab"
    

    dism /online /enable-feature /featurename:NetFX3 /all /Source:d:sourcessxs /LimitAccess

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