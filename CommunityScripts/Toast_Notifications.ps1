<#
===========================================================================
Created on:   22/07/2020 11:04
Created by:   Ben Whitmore
Filename:     Toast_Notify.ps1
===========================================================================

MMelkersen
Made it available to run as a simple powershell script from Intune not to depend on XML.


Version 1.2.14 - 14/01/21
-Fixed logic to return logged on DisplayName - Thanks @MMelkersen
-Changed the way we retrieve the SID for the current user variable $LoggedOnUserSID
-Added Event Title, Description and Source Path to the Scheduled Task that is created to pop the User Toast
-Fixed an issue where Snooze was not being passed from the Scheduled Task
-Fixed an issue with XMLSource full path not being returned correctly from Scheduled Task

Version 1.2.10 - 10/01/21
-Removed XMLOtherSource Parameter
-Cleaned up XML formatting which removed unnecessary duplication when the Snooze parameter was passed. Action ChildNodes are now appended to ToastTemplate XML.

Version 1.2 - 09/01/21
-Added logic so if the script is deployed as SYSTEM it will create a scheduled task to run the script for the current logged on user.

-Special Thanks to: -
-Inspiration for creating a Scheduled Task for Toasts @PaulWetter https://wetterssource.com/ondemandtoast
-Inspiration for running Toasts in User Context @syst_and_deploy http://www.systanddeploy.com/2020/11/display-simple-toast-notification-for.html
-Inspiration for creating scheduled tasks for the logged on user @ccmexec via Community Hub in ConfigMgr https://github.com/Microsoft/configmgr-hub/commit/e4abdc0d3105afe026211805f13cf533c8de53c4

Version 1.1 - 30/12/20
-Added Snooze Switch option

Version 1.0 - 22/07/20
-Release

.SYNOPSIS
The purpose of the script is to create simple Toast Notifications in Windows 10

.DESCRIPTION
Toast_Notify.ps1 will read an XML file so Toast Notifications can be changed "on the fly" without having to repackage an application. The CustomMessage.xml file can be hosted on a fileshare.
To create a custom XML, copy CustomMessage.xml and edit the text you want to disaply in the toast notification. The following files should be present in the Script Directory

Toast_Notify.ps1
BadgeImage.jpg
HeroImage.jpg
CustomMessage.xml

.PARAMETER XMLSource
Specify the name of the XML file to read. The XML file must exist in the same directory as Toast_Notify.ps1. If no parameter is passed, it is assumed the XML file is called CustomMessage.xml.

.PARAMETER Snooze
Add a snooze option to the Toast

.EXAMPLE
Toast_Notify.ps1 -XMLSource "PhoneSystemProblems.xml"

.EXAMPLE
Toast_Notify.ps1 -Snooze
#>

Param
(
    [Parameter(Mandatory = $False)]
    [Switch]$Snooze,
    [String]$ToastGUID
)

#Set Unique GUID for the Toast
If (!($ToastGUID)) {
    $ToastGUID = ([guid]::NewGuid()).ToString().ToUpper()
}

#Current Directory
$ScriptPath = $MyInvocation.MyCommand.Path
$CurrentDir = Split-Path $ScriptPath

#Get Logged On User to prepare Scheduled Task
$LoggedOnUserName = (Get-CimInstance -Namespace "root\cimv2" -ClassName Win32_ComputerSystem).Username
$LoggedOnUserSID = ([System.Security.Principal.NTAccount]($LoggedOnUserName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

# Get Profile Path for LoggedOnUser
Try {

    #Set Toast Path to UserProfile Temp Directory
    $LocalUserPath = (Get-CimInstance -Namespace "root\cimv2" -ClassName "Win32_UserProfile" | Where-Object { $_.SID -eq $LoggedOnUserSID }).LocalPath
    $LoggedOnUserToastPath = (Join-Path $LocalUserPath "AppData\Local\Temp\$($ToastGuid)")
}
Catch {
    Write-Warning $_.Exception.Message
    Write-Warning "Error resolving Logged on User SID to a valid Profile Path"

    #Set Toast Path to C:\Windows\Temp if user profile path cannot be resolved
    $LoggedOnUserToastPath = (Join-Path $ENV:Windir "Temp\$($ToastGuid)")
}

    #Create Toast Variables
    $ToastTitle = $XMLToast.ToastContent.ToastTitle
    $Signature = $XMLToast.ToastContent.Signature
    $EventTitle = $XMLToast.ToastContent.EventTitle
    $EventText = $XMLToast.ToastContent.EventText
    $ButtonTitle = $XMLToast.ToastContent.ButtonTitle
    $ButtonAction = $XMLToast.ToastContent.ButtonAction
    $SnoozeTitle = $XMLToast.ToastContent.SnoozeTitle

    #ToastDuration: Short = 7s, Long = 25s
    $ToastDuration = "long"

    #Images
    $BadgeImage = "https://mindlabstorage.blob.core.windows.net/mindlab/Mindcore/badgeimage.jpg"
    $HeroImage = "https://mindlabstorage.blob.core.windows.net/mindlab/Mindcore/Onedrive.jpg"

#Borrowed code from Martin Bengtsson - https://github.com/imabdk/Toast-Notification-Script    
# Downloading images into user's temp folder if images are hosted online
if (($BadgeImage.StartsWith("https://")) -OR ($BadgeImage.StartsWith("http://"))) {
    #Write-Log -Message "ToastLogoImage appears to be hosted online. Will need to download the file"
    # Testing to see if image at the provided URL indeed is available
    try { $testOnlineLogoImage = Invoke-WebRequest -Uri $BadgeImage -UseBasicParsing } catch { <# nothing to see here. Used to make webrequest silent #> }
    if ($testOnlineLogoImage.StatusDescription -eq "OK") {
        try {
            Invoke-WebRequest -Uri $BadgeImage -OutFile $BadgeImageTemp
            # Replacing image variable with the image downloaded locally
            $BadgeImage = $BadgeImageTemp
            #Write-Log -Message "Successfully downloaded $BadgeImageTemp from $BadgeImage"
        }
        catch { 
            #Write-Log -Level Error -Message "Failed to download the $BadgeImageTemp from $BadgeImageFileName"
        }
    }
    
}

#Borrowed code from Martin Bengtsson - https://github.com/imabdk/Toast-Notification-Script
if (($HeroImage.StartsWith("https://")) -OR ($HeroImage.StartsWith("http://"))) {
    Write-Log -Message "ToastHeroImage appears to be hosted online. Will need to download the file"
    # Testing to see if image at the provided URL indeed is available
    try { $testOnlineHeroImage = Invoke-WebRequest -Uri $HeroImage -UseBasicParsing } catch { <# nothing to see here. Used to make webrequest silent #> }
    if ($testOnlineHeroImage.StatusDescription -eq "OK") {
        try {
            Invoke-WebRequest -Uri $HeroImage -OutFile $HeroImageTemp
            # Replacing image variable with the image downloaded locally
            $HeroImage = $HeroImageTemp
            #Write-Log -Message "Successfully downloaded $HeroImageTemp from $HeroImage"
        }
        catch { 
            #Write-Log -Level Error -Message "Failed to download the $HeroImageTemp from $HeroImageFileName"
        }
    }
}   

    $BadgeImageTemp = "$env:TEMP\ToastLogoImage.jpg"
    $HeroImageTemp = "$env:TEMP\Onedrive.jpg.jpg"

    #Set COM App ID > To bring a URL on button press to focus use a browser for the appid e.g. MSEdge
    #$LauncherID = "Microsoft.SoftwareCenter.DesktopToasts"
    #$LauncherID = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
    $Launcherid = "MSEdge"

    #Dont Create a Scheduled Task if the script is running in the context of the logged on user, only if SYSTEM fired the script i.e. Deployment from Intune/ConfigMgr
    If (([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name -eq "NT AUTHORITY\SYSTEM") {
        
        #Prepare to stage Toast Notification Content in %TEMP% Folder
        Try {

            #Create TEMP folder to stage Toast Notification Content in %TEMP% Folder
            New-Item $LoggedOnUserToastPath -ItemType Directory -Force -ErrorAction Continue | Out-Null
            $ToastFiles = Get-ChildItem $CurrentDir -Recurse

            #Copy Toast Files to Toat TEMP folder
            ForEach ($ToastFile in $ToastFiles) {
                Copy-Item (Join-Path $CurrentDir $ToastFile) -Destination $LoggedOnUserToastPath -ErrorAction Continue
            }
        }
        Catch {
            Write-Warning $_.Exception.Message
        }

        #Set new Toast script to run from TEMP path
        $New_ToastPath = Join-Path $LoggedOnUserToastPath "Toast_Notify.ps1"

        #Created Scheduled Task to run as Logged on User
        $Task_TimeToRun = (Get-Date).AddSeconds(30).ToString('s')
        $Task_Expiry = (Get-Date).AddSeconds(120).ToString('s')
        If ($Snooze) {
            $Task_Action = New-ScheduledTaskAction -Execute "C:\WINDOWS\system32\WindowsPowerShell\v1.0\PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -File ""$New_ToastPath"" -ToastGUID ""$ToastGUID"" -Snooze"
        }
        else {
            $Task_Action = New-ScheduledTaskAction -Execute "C:\WINDOWS\system32\WindowsPowerShell\v1.0\PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -File ""$New_ToastPath"" -ToastGUID ""$ToastGUID"""
        }
        $Task_Trigger = New-ScheduledTaskTrigger -Once -At $Task_TimeToRun
        $Task_Trigger.EndBoundary = $Task_Expiry
        $Task_Principal = New-ScheduledTaskPrincipal -UserId $LoggedOnUserName -LogonType ServiceAccount
        $Task_Settings = New-ScheduledTaskSettingsSet -Compatibility V1 -DeleteExpiredTaskAfter (New-TimeSpan -Seconds 600)
        $New_Task = New-ScheduledTask -Description "Toast_Notification_$($LoggedOnUserSID)_$($ToastGuid) Task for user notification. Title: $($EventTitle) :: Event:$($EventText) :: Source Path: $($LoggedOnUserToastPath) " -Action $Task_Action -Principal $Task_Principal -Trigger $Task_Trigger -Settings $Task_Settings
        Register-ScheduledTask -TaskName "Toast_Notification_$($LoggedOnUserSID)_$($ToastGuid)" -InputObject $New_Task
    }

    #Run the toast of the script is running in the context of the Logged On User
    If (([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name -eq $LoggedOnUserName) {

        #Get logged on user DisplayName
        Try {
            If (Get-Itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Name "LastLoggedOnDisplayName" -ErrorAction SilentlyContinue) {
                $User = Get-Itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Name "LastLoggedOnDisplayName" | Select-Object -ExpandProperty LastLoggedOnDisplayName
                If ($Null -eq $User) {
                    $Firstname = $Null
                } 
                else {
                    $DisplayName = $User.Split(" ")
                    $Firstname = $DisplayName[0]
                }
            }
            else {
                $Firstname = $Null  
            }
        }
        Catch {
            Write-Warning "Warning: Registry value for LastLoggedOnDisplayName could not be found: $($error[0].Exception)."
            $Firstname = $Null
        } 
        
        #Get Hour of Day and set Custom Hello
        $Hour = (Get-Date).Hour
        If ($Hour -lt 12) { $CustomHello = "Good Morning $($Firstname)" }
        ElseIf ($Hour -gt 16) { $CustomHello = "Good Evening $($Firstname)" }
        Else { $CustomHello = "Good Afternoon $($Firstname)" }

        #Load Assemblies
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

        #Build XML ToastTemplate 
        [xml]$ToastTemplate = @"
<toast duration="$ToastDuration" scenario="reminder">
    <visual>
        <binding template="ToastGeneric">
            <text>$CustomHello</text>
            <text>OneDrive sync</text>
            <text placement="attribution">IT Department</text>
            <image placement="hero" src="$HeroImage"/>
            <image placement="appLogoOverride" hint-crop="circle" src="$BadgeImage"/>
            <group>
                <subgroup>
                    <text hint-style="title" hint-wrap="true" >OneDrive Information</text>
                </subgroup>
            </group>
            <group>
                <subgroup>
                    <text hint-style="body" hint-wrap="true" >On next reboot, your device will start repair OneDrive sync issues.</text>
                    <text hint-style="body" hint-wrap="true" ></text>
                    <text hint-style="body" hint-wrap="true" >Please note it will take some time...</text>
                </subgroup>
            </group>
        </binding>
    </visual>
    <audio src="ms-winsoundevent:notification.default"/>
</toast>
"@

        #Build XML ActionTemplateSnooze (Used when $Snooze is passed as a parameter)
        [xml]$ActionTemplateSnooze = @"
<toast>
    <actions>
        <input id="SnoozeTimer" type="selection" title="Select a Snooze Interval" defaultInput="1">
            <selection id="1" content="1 Minute"/>
            <selection id="30" content="30 Minutes"/>
            <selection id="60" content="1 Hour"/>
            <selection id="120" content="2 Hours"/>
            <selection id="240" content="4 Hours"/>
        </input>
        <action activationType="system" arguments="snooze" hint-inputId="SnoozeTimer" content="$SnoozeTitle" id="test-snooze"/>
        <action arguments="$ButtonAction" content="$ButtonTitle" activationType="protocol" />
        <action arguments="dismiss" content="Dismiss" activationType="system"/>
    </actions>
</toast>
"@

        #Build XML ActionTemplate (Used when $Snooze is not passed as a parameter)
        [xml]$ActionTemplate = @"
<toast>
    <actions>
        <action arguments="cmd.exe /c shutdown /r -t 60" content="Reboot Now" activationType="protocol" />
        <action arguments="dismiss" content="Dismiss" activationType="system"/>
    </actions>
</toast>
"@

        #If the Snooze parameter was passed, add additional XML elements to Toast
        If ($Snooze) {

            #Define default and snooze actions to be added $ToastTemplate
            $Action_Node = $ActionTemplateSnooze.toast.actions
        }
        else {

            #Define default actions to be added $ToastTemplate
            $Action_Node = $ActionTemplate.toast.actions
        }

        #Append actions to $ToastTemplate
        [void]$ToastTemplate.toast.AppendChild($ToastTemplate.ImportNode($Action_Node, $true))
        
        #Prepare XML
        $ToastXml = [Windows.Data.Xml.Dom.XmlDocument]::New()
        $ToastXml.LoadXml($ToastTemplate.OuterXml)
    
        #Prepare and Create Toast
        $ToastMessage = [Windows.UI.Notifications.ToastNotification]::New($ToastXML)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($LauncherID).Show($ToastMessage)
    }