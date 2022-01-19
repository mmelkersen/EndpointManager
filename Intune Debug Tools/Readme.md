# What is the Intune Debug Tool?

This article provides resources and tips for using the Intune debug tool:

- Rerun win32 tool
- View registry changes Microsoft Intune related last 36 hours
- What next? send me feedback on feedback@memtipsandtricks.tech and let me know what could be a huge help for you.

Demo of Rerun win32 tool
![alt text](https://github.com/mmelkersen/EndpointManager/blob/main/Intune%20Debug%20Tools/Rerun%20Win32%20apps.gif)

Demo of registry changes
![alt text](https://github.com/mmelkersen/EndpointManager/blob/main/Intune%20Debug%20Tools/Find%20registry%20changes.gif)

# History

#### Version 1.0
First release of the debug tool containting rerun win32 apps.

> [!NOTE]
> Script reference: https://github.com/ztrhgf/useful_powershell_functions/blob/master/INTUNE/Invoke-IntuneWin32AppRedeploy.ps1

---
#### Version 1.1
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

#### Version 1.2
Whats next?