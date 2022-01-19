# What is the Intune Debug Tool?

This article provides resources and tips for using the Intune debug tool:

- Rerun win32 tool
- View registry changes Microsoft Intune related last 36 hours

Demo of Rerun win32 tool
![alt text](https://github.com/mmelkersen/EndpointManager/blob/main/Intune%20Debug%20Tools/Rerun%20Win32%20apps.gif)

Demo of registry changes
![alt text](https://github.com/mmelkersen/EndpointManager/blob/main/Intune%20Debug%20Tools/Find%20registry%20changes.gif)

# History
---
#### Version 1.0
First release of the debug tool containting rerun win32 apps.

---
#### Version 1.1
Added 5 shortcuts to view registry changes from the last 36 hours. (could be done via sysinternals tools. This is just so much easier.)
- Shortcut1: DEBUG - GPO changes last 36 hours (looking for changes in registry: HKLM:\Software\policies)
- Shortcut2: DEBUG - Enrollment changes last 36 hours (looking for changes in registry: HKLM:\Software\Microsoft\Enrollments)
- Shortcut3: DEBUG - IME changes last 36 hours (looking for changes in registry: HKLM:\Software\Microsoft\IntuneManagementExtension)
- Shortcut4: DEBUG - PolicyManager changes last 36 hours (looking for changes in registry: HKLM:\Software\Microsoft\PolicyManager)
- Shortcut5: DEBUG - ALL MS registry changes last 36 hours (OBS takes time to run - looking for changes in registry: HKLM:\Software\Microsoft)