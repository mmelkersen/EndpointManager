#=====================================================================================================
# Created on:   14.01.2021
# Created by:   Mattias Melkersen
# Version:	    0.1  
# Mail:		    mm@mindcore.dk
# Twitter:      MMelkersen
# Function:     Baseline security that currently not supported by any configuration policies in Intune
# 
# 
#=====================================================================================================


#Harden lsass to protect against abuse such as Pass-the-Hash
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f

#Locally cached passwords or credentials can be accessed by malicious code or unauthorized users.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableDomainCreds /t REG_DWORD /d 00000001 /f

#Allowing this can provide a map of potential points to attack the system.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 00000001 /f

#JavaScript could potentially be used by attackers to manipulate users or to execute undesired code locally.
reg add "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v bDisableJavaScript /t REG_DWORD /d 00000001 /f

#Flash is an unsecure technology with many known vulnerabilities, it is recommended to avoid using it.
reg add "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v bEnableFlash /t REG_DWORD /d 00000000 /f

#Using older/weaker authentication levels (LM & NTLM) make it potentially possible for attackers to sniff that traffic to more easily reproduce the user's password.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 00000005 /f

#This exposes the system sharing the connection to others with potentially malicious purpose.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_ShowSharedAccessUI /t REG_DWORD /d 00000000 /f

#Selecting an incorrect network location may allow greater exposure of a system
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_StdDomainUserSetLocation /t REG_DWORD /d 00000001 /f\