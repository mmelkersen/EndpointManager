# What is the Intune Debug Tool?

This article provides resources and tips for using the Intune debug tool:

- Rerun win32 tool
- View registry changes Microsoft Intune related last 36 hours
- Debug policy sync live with SyncMLViewer
- What next? send me feedback on feedback@memtipsandtricks.tech and let me know what could be a huge help for you.

Download the MSI [Here](https://github.com/mmelkersen/EndpointManager/raw/main/Intune%20Debug%20Tools/IntuneDebugToolsv1.3.msi "Microsoft Intune debug toolkit") and install on machines of your choice 

VLOG on how to rerun win32 apps here and now:
[![Rerun win32 apps](https://github.com/mmelkersen/EndpointManager/blob/main/Intune%20Debug%20Tools/Content/hqdefault.jpg)](https://www.youtube.com/watch?v=gHG84MKE5O4 "Rerun Win32 apps")

Demo of Rerun win32 tool
![alt text](https://github.com/mmelkersen/EndpointManager/blob/main/Intune%20Debug%20Tools/Content/Rerun%20Win32%20apps.gif)

Demo of registry changes
![alt text](https://github.com/mmelkersen/EndpointManager/blob/main/Intune%20Debug%20Tools/Content/Find%20registry%20changes.gif)

# History

### Version 1.3
- Added icons on all shortcuts
- Added Oliver Kieselbach's SyncMLViewer debug tool to the kit. Thanks for allowing me to add this tool, [Oliver](https://twitter.com/okieselb "Oliver Kieselbach")

This tool is able to present the SyncML protocol stream between the Windows 10 client and management system. In addition it does some extra parsing to extract details and make the analyzing a bit easier.
The tool uses ETW to trace the MDM Sync session. In general the tool can be very handy to troubleshoot policy issues. Tracing what the client actually sends and receives provides deep protocol insights.
It makes it easy to get confirmation about queried or applied settings. Happy tracing!

Demo of SyncMLViewer
![alt text](https://github.com/mmelkersen/EndpointManager/blob/main/Intune%20Debug%20Tools/Content/Intune%20debug%201.3.gif)

Get more information about the tool [Here](https://github.com/okieselbach/SyncMLViewer "Oliver Kieselbach Github")

---

### Version 1.2
- Added -executionpolicy bypass on all shortcuts

---

### Version 1.1
What is this addon going to help with?
- What if you added a policy from Intune and wanted to see where it added values on the device?
- What if you wanted to know if IME is actually is refreshing its registry and check for the installed apps are installed?
- Did anyone push new GPO's policies to your device? If you are transitioning to Intune with hybrid identity you like to know what goes on.

Added 5 shortcuts to view registry changes from the last 36 hours. (could be done via sysinternals tools. This is just so much easier.)
- Shortcut1: DEBUG - GPO changes last 36 hours (looking for changes in registry: HKLM:\Software\policies)
- Shortcut2: DEBUG - Enrollment changes last 36 hours (looking for changes in registry: HKLM:\Software\Microsoft\Enrollments)
- Shortcut3: DEBUG - IME changes last 36 hours (looking for changes in registry: HKLM:\Software\Microsoft\IntuneManagementExtension)
- Shortcut4: DEBUG - PolicyManager changes last 36 hours (looking for changes in registry: HKLM:\Software\Microsoft\PolicyManager)
- Shortcut5: DEBUG - ALL MS registry changes last 36 hours (OBS takes time to run - looking for changes in registry: HKLM:\Software\Microsoft)

> [!NOTE]
> Script reference: https://github.com/guyrleech/General-Scripts/blob/master/Regrecent.ps1

---

### Version 1.0
First release of the debug tool containting rerun win32 apps.

> [!NOTE]
> Script reference: https://github.com/ztrhgf/useful_powershell_functions/blob/master/INTUNE/Invoke-IntuneWin32AppRedeploy.ps1

