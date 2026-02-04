#=====================================================================================================
# Created on:   14.01.2021
# Created by:   Mattias Melkersen
# Version:	    0.1 
# Mail:         mm@mindcore.dk
# Twitter:      MMelkersen
# Function:     Sample script to remediate registry settings.
# 
# This script is provided As Is
# Compatible with Windows 10 and later
#=====================================================================================================

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v DisableAutoplay /t REG_DWORD /d 00000001 /f