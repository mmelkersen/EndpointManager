<#
======================================================================================================
 
 Created on:    12.03.2021
 Created by:    Mattias Melkersen
 Version:       0.1  
 Mail:          mm@mindcore.dk
 twitter:       @mmelkersen
 Function:      Create Kiosk shortcut for kiosk profile
 
======================================================================================================

#>

$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Kiosk.lnk")
$Shortcut.TargetPath = '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"'
$Shortcut.Arguments = "--kiosk blog.mindcore.dk --edge-kiosk-type=fullscreen --no-first-run"
$Shortcut.WorkingDirectory = '"C:\Program Files (x86)\Microsoft\Edge\Application"'
$Shortcut.Save()