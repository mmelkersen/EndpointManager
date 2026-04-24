<#
.SYNOPSIS
    Downloads presentation files from all sessions at the Modern Management Summit 2026.

.DESCRIPTION
    Scrapes the public Sched schedule at endpointsummit2026.sched.com, visits each session
    page, and downloads any attached presentation files (PDF, PPTX, etc.).
    No API key or attendee login is required - presentation files on Sched are publicly
    accessible. Sessions without attached files (breaks, lunch, social events) are skipped
    automatically based on the absence of hosted-files.sched.co links.
    The script is safe to re-run - files already downloaded are not re-downloaded.
    Multiple files per session are each saved individually using the original upload filename.

.PARAMETER OutputPath
    Path to the folder where downloaded files will be saved.
    Defaults to .\MEMSummit2026-Presentations in the current working directory.

.PARAMETER EventUrl
    Base URL of the Sched event. Defaults to https://endpointsummit2026.sched.com

.EXAMPLE
    .\Download-presentations-memsummit2026.ps1
    Downloads all available presentations to .\MEMSummit2026-Presentations

.EXAMPLE
    .\Download-presentations-memsummit2026.ps1 -OutputPath "C:\Presentations" -Verbose
    Downloads all available presentations to C:\Presentations with verbose logging.

.NOTES
    Version:        1.1
    Author:         Mattias Melkersen
    Creation Date:  2026-04-23

    CHANGELOG
    ---------------
    2026-04-24 - v1.1 - Use browser-like User-Agent and headers to bypass Cloudflare; fetch all event days (MM)
    2026-04-23 - v1.0 - Initial release (MM)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\MEMSummit2026-Presentations",

    [Parameter(Mandatory = $false)]
    [string]$EventUrl = "https://endpointsummit2026.sched.com"
)

$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
$BrowserHeaders = @{
    'Accept'                    = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
    'Accept-Language'           = 'en-US,en;q=0.9'
    'DNT'                       = '1'
    'Upgrade-Insecure-Requests' = '1'
}
# Shared web session so Cloudflare clearance cookies persist across all requests
$WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession

function Get-SanitizedFileName {
    param([string]$Name)
    # Replace invalid filename characters with a space
    $Name = $Name -replace '[\\/:*?"<>|]', ' '
    # Remove control characters
    $Name = $Name -replace '[\x00-\x1f]', ''
    # Collapse multiple spaces and trim
    return $Name.Trim() -replace '\s{2,}', ' '
}

# Ensure output directory exists
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Verbose "Created output directory: $OutputPath"
}
$resolvedOutput = (Resolve-Path $OutputPath).Path

# Step 1: Fetch the full session list
Write-Host "Fetching session list from: $($EventUrl.TrimEnd('/'))/list/simple"
try {
    $scheduleResponse = Invoke-WebRequest -Uri "$($EventUrl.TrimEnd('/'))/list/simple" `
        -UserAgent $UserAgent -Headers $BrowserHeaders -WebSession $WebSession -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Error "Failed to fetch session list: $_"
    exit 1
}

# Step 2: Collect all day-specific schedule pages
# Sched only returns the current day on /list/simple. Other days appear as navigation links
# in the sched-dates-menu, e.g. href="2026-04-22/list/simple"
$allSchedulePages = [System.Collections.Generic.List[string]]::new()
$allSchedulePages.Add($scheduleResponse.Content)

$dayLinkMatches = [regex]::Matches($scheduleResponse.Content, 'href="(\d{4}-\d{2}-\d{2}/list/simple)"')
$otherDays = $dayLinkMatches | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique

if ($otherDays.Count -gt 0) {
    Write-Host "Found $($otherDays.Count) additional day(s) in schedule navigation. Fetching all days..."
    foreach ($dayPath in $otherDays) {
        $dayUrl = $EventUrl.TrimEnd('/') + '/' + $dayPath
        Write-Verbose "Fetching day page: $dayUrl"
        try {
            $dayResponse = Invoke-WebRequest -Uri $dayUrl -UserAgent $UserAgent -Headers $BrowserHeaders -WebSession $WebSession -UseBasicParsing -ErrorAction Stop
            $allSchedulePages.Add($dayResponse.Content)
        } catch {
            Write-Warning "Failed to fetch day page: $dayUrl - $_"
        }
    }
}

# Extract unique session URLs across all day pages
# Sched uses single-quoted relative hrefs without a leading slash: href='event/{key}/{slug}'
$sessionUrls = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($pageContent in $allSchedulePages) {
    $urlMatches = [regex]::Matches($pageContent, "[href]='(event/[A-Za-z0-9]+/[^'#?]+)'")
    foreach ($m in $urlMatches) {
        [void]$sessionUrls.Add($EventUrl.TrimEnd('/') + '/' + $m.Groups[1].Value)
    }
}

if ($sessionUrls.Count -eq 0) {
    Write-Error "No session URLs found on the schedule page. The page structure may have changed."
    exit 1
}

Write-Host "Found $($sessionUrls.Count) sessions. Starting download..."
Write-Host ""

# Step 3: Process each session
$filesDownloaded  = 0
$sessionsWithFiles = 0
$sessionsSkipped  = 0
$sessionCount     = $sessionUrls.Count
$currentIndex     = 0

foreach ($sessionUrl in $sessionUrls) {
    $currentIndex++
    Write-Verbose "[$currentIndex/$sessionCount] $sessionUrl"

    try {
        Start-Sleep -Milliseconds 300
        $sessionPage = Invoke-WebRequest -Uri $sessionUrl -UserAgent $UserAgent -Headers $BrowserHeaders -WebSession $WebSession -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Warning "[$currentIndex/$sessionCount] Failed to fetch: $sessionUrl"
        Write-Warning "  Error: $_"
        $sessionsSkipped++
        continue
    }

    # Extract session title from <title> tag, stripping the trailing site suffix
    $titleMatch = [regex]::Match($sessionPage.Content, '<title>([^<]+)</title>')
    if ($titleMatch.Success) {
        $sessionTitle = $titleMatch.Groups[1].Value `
            -replace '\s*[-|]\s*Modern Management Summit.*$', '' `
            -replace '\s*[-|]\s*Endpoint Summit.*$', '' `
            -replace '\s*[-|]\s*Sched.*$', '' `
            -replace '&amp;', '&' `
            -replace '&#39;', "'" `
            -replace '&quot;', '"'
        $sessionTitle = $sessionTitle.Trim()
    } else {
        # Fallback: humanize from URL slug
        $sessionTitle = ($sessionUrl -split '/')[-1] -replace '-', ' '
    }

    $safeTitle = Get-SanitizedFileName -Name $sessionTitle

    # Find all hosted-files.sched.co download links on this session page
    $fileMatches = [regex]::Matches($sessionPage.Content, 'href="(https://hosted-files\.sched\.co/[^"]+)"')

    if ($fileMatches.Count -eq 0) {
        Write-Verbose "[$currentIndex/$sessionCount] No files - skipping: $sessionTitle"
        $sessionsSkipped++
        continue
    }

    $sessionsWithFiles++
    $fileWord = if ($fileMatches.Count -eq 1) { "1 file" } else { "$($fileMatches.Count) files" }
    Write-Host "[$currentIndex/$sessionCount] $sessionTitle  ($fileWord)"

    foreach ($fileMatch in $fileMatches) {
        $fileUrl = $fileMatch.Groups[1].Value

        # Derive original filename from the URL path segment, URL-decoded
        $cleanUrl        = ($fileUrl -split '[?#]')[0]
        $encodedSegment  = ($cleanUrl -split '/')[-1]
        $originalFileName = [uri]::UnescapeDataString($encodedSegment)
        $safeOriginalName = Get-SanitizedFileName -Name $originalFileName

        $destFileName = "$safeTitle - $safeOriginalName"
        $destPath     = Join-Path $resolvedOutput $destFileName

        if (Test-Path $destPath) {
            Write-Verbose "  Already exists, skipping: $destFileName"
            continue
        }

        try {
            Invoke-WebRequest -Uri $fileUrl -OutFile $destPath -UserAgent $UserAgent -Headers $BrowserHeaders -WebSession $WebSession -UseBasicParsing -ErrorAction Stop
            Write-Host "  Downloaded: $destFileName" -ForegroundColor Green
            $filesDownloaded++
        } catch {
            Write-Warning "  Failed to download: $fileUrl"
            Write-Warning "  Error: $_"
            # Remove any partial file left behind
            if (Test-Path $destPath) {
                Remove-Item $destPath -Force
            }
        }
    }
}

# Summary
Write-Host ""
Write-Host "--- Summary ---"
Write-Host "Sessions processed : $sessionCount"
Write-Host "Sessions with files: $sessionsWithFiles"
Write-Host "Sessions skipped   : $sessionsSkipped (no files or fetch errors)"
Write-Host "Files downloaded   : $filesDownloaded"
Write-Host "Output folder      : $resolvedOutput"
