<#
======================================================================================================
 
 Created on:    27.03.2024
 Created by:    Mattias Melkersen
 Version:       1.0  
 Mail:          mm@mindcore.dk
 twitter:       @mmelkersen
 Function:      Get rules from EPM logs and show if they are present or they are blocked. If blocked they will be visible as red and also give you the Hash of the file, easy to import.
 
 This script is provided As Is
 Compatible with Windows 10 and later
======================================================================================================

#>

# Import the EpmCmdlets module
$modulePath = "C:\Program Files\Microsoft EPM Agent\EpmTools\EpmCmdlets.dll"
Import-Module $modulePath -ErrorAction Stop

# Specify the directory containing the log files
$logDirectory = "C:\Program Files\Microsoft EPM Agent\Logs"

# Get the latest log file
$latestLogFile = Get-ChildItem -Path $logDirectory -Filter "EpmService-*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

# Check if the latest log file exists
if ($latestLogFile) {
    # Read the latest log file
    $logContent = Get-Content -Path $latestLogFile.FullName

    # Filter lines containing "Elevation denied for file:"
    $deniedLines = $logContent | Where-Object { $_ -like "*Elevation denied for file:*"}

    # Display the results
    if ($deniedLines) {
        $result = foreach ($line in $deniedLines) {
            if ($line -match "Elevation denied for file: (.+)") {
                $filePath = $matches[1]
                if (Test-Path $filePath -PathType Leaf) {
                    $fileHash = Get-FileAttributes -FilePath $filePath | Select-Object -ExpandProperty FileHash
                    [PSCustomObject]@{
                        FilePath = $filePath
                        FileHash = $fileHash
                    }
                } else {
                    Write-Warning "File not found: $filePath"
                    [PSCustomObject]@{
                        FilePath = $filePath
                        FileHash = "File not found"
                    }
                }
            }
        }

        # Check if elevation rule exists for each result
        $uniqueResults = $result | Select-Object -Property FilePath, FileHash -Unique
        foreach ($entry in $uniqueResults) {
            $fileName = [System.IO.Path]::GetFileName($entry.FilePath)
            if ($fileName -match '\.exe$') {
                $elevationRule = Get-ElevationRules -Target $fileName -Lookup FileName -ErrorAction SilentlyContinue
                if ($elevationRule) {
                    Write-Host ("Elevation rule exists for $($entry.FilePath)") -ForegroundColor Green
                } else {
                    Write-Host ("No elevation rule found for $($entry.FilePath) with hash $($entry.FileHash)") -ForegroundColor Red
                }
            }
        }
    } else {
        Write-Host "No lines containing 'Elevation denied for file:' found."
    }
} else {
    Write-Host "No log files found in directory: $logDirectory"
}
