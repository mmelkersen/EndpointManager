<#
.SYNOPSIS
    Exports two Intune security baseline policies and their templates to JSON for comparison.

.DESCRIPTION
    Read-only. Signs in interactively as the user running the script (delegated), using the
    DeviceManagementConfiguration.Read.All scope. Enter your credentials in the Microsoft sign-in
    prompt. The sign-in is kept for this PowerShell process only.

    Only baselines built on the settings catalog (configurationPolicies) are supported. Older
    baselines such as November 2021 use the intents API and will not be found.

.PARAMETER ReferenceName
    Exact name of the baseline policy to compare from.

.PARAMETER DifferenceName
    Exact name of the baseline policy to compare to.

.PARAMETER OutDir
    Existing folder that receives baseline-raw.json.

.EXAMPLE
    .\Export-IntuneSecurityBaseline.ps1 -ReferenceName 'baseline 24H2' -DifferenceName '26H2' -OutDir C:\Temp

.NOTES
    Version:        1.0
    Author:         Mattias Melkersen
    Creation Date:  2026-11-16

    CHANGELOG
    ---------------
    2026-11-16 - v1.0 - Initial version (MM)  
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ReferenceName,
    [Parameter(Mandatory)][string]$DifferenceName,
    [Parameter(Mandatory)][string]$OutDir
)
$ErrorActionPreference = 'Stop'

Import-Module Microsoft.Graph.Authentication

# Delegated interactive sign-in: the user enters their own credentials in the Microsoft prompt
Connect-MgGraph -Scopes 'DeviceManagementConfiguration.Read.All' -ContextScope Process -NoWelcome
$ctx = Get-MgContext
if (-not $ctx) { throw 'Sign-in did not complete' }
Write-Output "SIGNED_IN account=$($ctx.Account) tenant=$($ctx.TenantId) authType=$($ctx.AuthType) scopes='$($ctx.Scopes -join ' ')'"

function Get-AllPages([string]$Uri) {
    $items = [System.Collections.Generic.List[object]]::new()
    while ($Uri) {
        $r = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType Hashtable
        if ($r.value) { foreach ($v in $r.value) { $items.Add($v) } }
        $Uri = $r.'@odata.nextLink'
    }
    return , $items
}

$base = 'https://graph.microsoft.com/beta/deviceManagement'
$all = Get-AllPages "$base/configurationPolicies?`$select=id,name,description,settingCount,templateReference,lastModifiedDateTime,createdDateTime&`$top=100"
Write-Output "Total configuration policies: $($all.Count)"

$baselines = @($all | Where-Object { $_.templateReference.templateFamily -like '*baseline*' })
foreach ($b in $baselines) {
    Write-Output ("BASELINE name='{0}' family={1} template={2} ver='{3}' settings={4}" -f $b.name, $b.templateReference.templateFamily, $b.templateReference.templateId, $b.templateReference.templateDisplayVersion, $b.settingCount)
}

$result = @{ tenant = $ctx.TenantId; account = $ctx.Account; baselines = $baselines }

foreach ($pair in @(@('reference', $ReferenceName), @('difference', $DifferenceName))) {
    $label, $name = $pair
    $p = @($baselines | Where-Object { $_.name -eq $name })
    if ($p.Count -ne 1) { throw "Expected exactly one baseline policy named '$name', found $($p.Count)" }
    $p = $p[0]

    $settings = Get-AllPages "$base/configurationPolicies('$($p.id)')/settings?`$expand=settingDefinitions&`$top=1000"
    Write-Output "$label '$name': $($settings.Count) top-level settings"

    $tid = $p.templateReference.templateId
    $tpl = Invoke-MgGraphRequest -Method GET -Uri "$base/configurationPolicyTemplates('$tid')" -OutputType Hashtable
    $tplSettings = Get-AllPages "$base/configurationPolicyTemplates('$tid')/settingTemplates?`$expand=settingDefinitions&`$top=1000"
    Write-Output "$label template '$($tpl.displayName)' v'$($tpl.displayVersion)' state=$($tpl.lifecycleState): $($tplSettings.Count) setting templates"

    $result[$label] = @{ policy = $p; settings = $settings; template = $tpl; templateSettings = $tplSettings }
}

# Category names are only used for grouping, so a failed lookup is not fatal
$categoryIds = foreach ($side in $result.reference, $result.difference) {
    foreach ($item in @($side.settings) + @($side.templateSettings)) {
        foreach ($d in @($item.settingDefinitions)) { if ($d.categoryId) { [string]$d.categoryId } }
    }
}
$categories = @{}
foreach ($cid in @($categoryIds | Sort-Object -Unique)) {
    try {
        $c = Invoke-MgGraphRequest -Method GET -Uri "$base/configurationCategories('$cid')" -OutputType Hashtable
        $categories[$cid] = @{ displayName = $c.displayName }
    }
    catch { Write-Warning "Could not read category '$cid': $($_.Exception.Message)" }
}
$result.categories = $categories
Write-Output "Resolved $($categories.Count) categories"

$outFile = Join-Path $OutDir 'baseline-raw.json'
$result | ConvertTo-Json -Depth 100 -Compress | Set-Content -LiteralPath $outFile -Encoding utf8
Write-Output "DONE wrote $outFile ($((Get-Item -LiteralPath $outFile).Length) bytes)"
Disconnect-MgGraph | Out-Null
