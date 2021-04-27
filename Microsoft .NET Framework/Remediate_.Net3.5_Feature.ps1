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
 Compatible with Windows 10 1909 -> 20H2
======================================================================================================

#>

[string]$Owner = "mmelkersen"
[String]$Repository = "EndpointManager"
[String]$path = "Microsoft .NET Framework/"
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
    if (!(test-path "C:\temp\NetFX\$($WindowsVersion.WindowsVersion)"))
        {
            New-Item -ItemType Directory -Path "C:\temp\NetFX\$($WindowsVersion.WindowsVersion)"
        }
        
    #Get files from Github    
    [String]$DestinationPath = "C:\temp\NetFX\$($WindowsVersion.WindowsVersion)"
    [String]$path = $path + "$($WindowsVersion.WindowsVersion)"
    $baseUri = "https://api.github.com/"
    $args = "repos/$Owner/$Repository/contents/$Path"
    $wr = Invoke-WebRequest -Uri $($baseuri+$args)
    $objects = $wr.Content | ConvertFrom-Json
    $files = $objects | where {$_.type -eq "file"} | Select -exp download_url
    $directories = $objects | where {$_.type -eq "dir"}
    
    $directories | ForEach-Object { 
        DownloadFilesFromRepo -Owner $Owner -Repository $Repository -Path $_.path -DestinationPath $($DestinationPath+$_.name)
    }

    if (-not (Test-Path $DestinationPath)) {
        # Destination path does not exist, let's create it
        try {
            New-Item -Path $DestinationPath -ItemType Directory -ErrorAction Stop
        } catch {
            throw "Could not create path '$DestinationPath'!"
        }
    }

    foreach ($file in $files) {
        $fileDestination = Join-Path $DestinationPath (Split-Path $file -Leaf)
        try {
            Invoke-WebRequest -Uri $file -OutFile $fileDestination -ErrorAction Stop -Verbose
            "Grabbed '$($file)' to '$fileDestination'"
        } catch {
            throw "Unable to download '$($file.path)'"
        }
    }

    dism /online /enable-feature /featurename:NetFX3 /all /Source:$path /LimitAccess

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