<#
======================================================================================================
 
 Created on:    10.11.2021
 Created by:    Mattias Melkersen
 Version:       1.0  
 Mail:          mm@mindcore.dk
 twitter:       @mmelkersen
 Function:      Test URLs are open for Update Compliance
 
 All ports for this script can be found here: https://docs.microsoft.com/en-us/windows/deployment/update/update-compliance-configuration-manual#required-endpoints last updated 04/10/2021

 Borrowed script parts from David Segura AutopilotOOBE
 This script is provided As Is
 Compatible with Windows 10/11 and later
======================================================================================================

#>

# versioning script
$Title = 'Test-MicrosoftEndpointNetworksUpdateCompliance'
$ScriptVersion = '1.0'

function Test-MicrosoftEndpointNetworks {
    [CmdletBinding()]
    param (
    [parameter(Mandatory=$true)]
    $ComputerNames,$Ports,$TestArea,
    [parameter(Mandatory=$false)]
    $Urls)

    #================================================
    #   Initialize
    #================================================
    $console = $host.ui.rawui
    $console.BackgroundColor = "Black"
    $console.ForegroundColor = "White"
    $console.WindowTitle = $Title
    $console.BufferSize = New-Object System.Management.Automation.Host.size(2000,2000)
    #================================================
    #   Temp
    #================================================
    if (!(Test-Path "$env:SystemDrive\Temp\MSIntune")) {
        New-Item -Path "$env:SystemDrive\Temp\MSIntune" -ItemType Directory -Force
    }
    #================================================
    #   Transcript
    #================================================
    $Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-$Title-$testarea.log"
    $LogPath = Join-Path "$env:SystemDrive\Temp\MSIntune" $Transcript
    Start-Transcript -Path $LogPath -ErrorAction Ignore | Out-Null
    #=======================================================================
    $Global:ProgressPreference = 'SilentlyContinue'

    Write-Host -ForegroundColor DarkGray '========================================================================='
    Write-Host -ForegroundColor Cyan "$TestArea"
    
    foreach ($ComputerName in $ComputerNames){
        foreach ($Port in $Ports){
            try {
                if (Test-NetConnection -ComputerName $ComputerName -Port $Port -InformationLevel Quiet -ErrorAction Stop -WarningAction 'Continue') {
                    Write-Host -ForegroundColor DarkCyan "PASS: $ComputerName [Port: $Port]"
                }
                else {
                    Write-Host ""
                    Write-Host "Script version: $ScriptVersion"
                    Write-Host -ForegroundColor Red "Overall verdict: FAIL $Uri"
                    Write-Host -ForegroundColor DarkGray '========================================================================='
                    Write-Host "Press any key to continue..."
                    $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                    Exit 1
                }
            }
            catch {}
            finally {}
        }
    }

    foreach ($Uri in $Urls){
        try {
            if ($null = Invoke-WebRequest -Uri $Uri -Method Head -UseBasicParsing -ErrorAction Stop) {
                Write-Host -ForegroundColor DarkCyan "PASS: $Uri"
            }
            else {
            }
        }
        catch {
            Write-Host "Script version: $ScriptVersion"
            Write-Host -ForegroundColor Red "Overall verdict: FAIL $Uri"
            Write-Host -ForegroundColor DarkGray '========================================================================='
            Write-Host "Press any key to continue..."
            $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Exit 1
        }
    }
    #=======================================================================
    #   Complete
    #=======================================================================
    Write-Host -ForegroundColor DarkGray '========================================================================='
    $Global:ProgressPreference = 'Continue'
    Write-Host -ForegroundColor Cyan "Log path: $($LogPath)"
    Stop-Transcript | Out-Null
}

    #=======================================================================
    #   Update Compliance
    #=======================================================================
    Test-MicrosoftEndpointNetworks -ComputerNames "v10c.events.data.microsoft.com", "v10.vortex-win.data.microsoft.com", "settings-win.data.microsoft.com", "adl.windows.com", "watson.telemetry.microsoft.com", "oca.telemetry.microsoft.com", "login.live.com" -Ports "443" -TestArea "Update Compliance"


    #=======================================================================
    #   Exit Script
    #=======================================================================

    if (!($host.name -match "ISE")) {
        Write-Host -ForegroundColor DarkGray '========================================================================='
        Write-Host ""
        Write-Host "Script Finalized"
        Write-Host "Script version: $ScriptVersion"
     
        
        $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    else {
        Exit 0
    }