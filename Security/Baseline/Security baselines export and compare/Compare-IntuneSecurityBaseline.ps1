#requires -Version 7.0
<#
.SYNOPSIS
    Builds a self-contained HTML report of the differences between two Intune security baselines.

.DESCRIPTION
    Reads the JSON written by Export-IntuneSecurityBaseline.ps1. Needs no Graph connection and makes
    no changes in Intune. The report needs no internet access to open.

    Settings are matched on their setting definition ID and their position under parent settings.
    A removed and an added setting with the same display name are reported as "New ID".

    The comparison is between the policies as configured in the tenant, so edits made to either
    policy also appear as differences.

.PARAMETER InputPath
    Path to baseline-raw.json.

.PARAMETER OutputPath
    Path of the HTML file to write.

.EXAMPLE
    .\Compare-IntuneSecurityBaseline.ps1 -InputPath C:\Temp\baseline-raw.json -OutputPath C:\Temp\baseline-diff.html

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
    [Parameter(Mandatory)][string]$InputPath,
    [Parameter(Mandatory)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'

function Enc($Value) { [System.Net.WebUtility]::HtmlEncode([string]$Value) }

function New-DefinitionIndex($Side) {
    $index = @{ Definitions = @{}; Options = @{} }
    $groups = @($Side.settings) + @($Side.templateSettings)
    foreach ($item in $groups) {
        if (-not $item) { continue }
        foreach ($d in @($item.settingDefinitions)) {
            if (-not $d -or -not $d.id) { continue }
            $index.Definitions[$d.id] = $d
            foreach ($o in @($d.options)) {
                if ($o -and $o.itemId) { $index.Options[$o.itemId] = $o.displayName }
            }
        }
    }
    return $index
}

function Add-TemplateId($Node, $Set) {
    if ($Node -is [System.Collections.IDictionary]) {
        foreach ($k in @($Node.Keys)) {
            if ($k -eq 'settingDefinitionId' -and $Node[$k]) { [void]$Set.Add([string]$Node[$k]) }
            else { Add-TemplateId $Node[$k] $Set }
        }
    }
    elseif ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
        foreach ($n in $Node) { Add-TemplateId $n $Set }
    }
}

function Get-TemplateIdSet($Side) {
    $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($t in @($Side.templateSettings)) {
        if (-not $t) { continue }
        Add-TemplateId $t.settingInstanceTemplate $set
        foreach ($d in @($t.settingDefinitions)) { if ($d -and $d.id) { [void]$set.Add([string]$d.id) } }
    }
    return , $set
}

function Add-FlatSetting($Instance, [string[]]$PathIds, [string[]]$PathNames, $Index, $Output) {
    if (-not $Instance) { return }
    $id = [string]$Instance.settingDefinitionId
    $def = $Index.Definitions[$id]
    $name = if ($def -and $def.displayName) { [string]$def.displayName } else { $id }
    $ids = @($PathIds) + $id
    $names = @($PathNames) + $name
    $type = ([string]$Instance.'@odata.type' -split '\.')[-1]

    $emit = {
        param($Display)
        $Output.Add([pscustomobject]@{
                Key = ($ids -join '|'); Id = $id; Name = $name; Parents = @($PathNames); Display = [string]$Display
            })
    }
    $optionLabel = {
        param($Raw)
        $label = $Index.Options[[string]$Raw]
        if ($label) { $label } else { [string]$Raw }
    }
    $simpleLabel = {
        param($Value)
        if ($Value.'@odata.type' -like '*Secret*') { '(secret value)' } else { [string]$Value.value }
    }
    $recurse = {
        param($Children)
        foreach ($c in @($Children)) { Add-FlatSetting $c $ids $names $Index $Output }
    }

    switch -Wildcard ($type) {
        '*ChoiceSettingInstance' {
            & $emit (& $optionLabel $Instance.choiceSettingValue.value)
            & $recurse $Instance.choiceSettingValue.children
        }
        '*ChoiceSettingCollectionInstance' {
            foreach ($v in @($Instance.choiceSettingCollectionValue)) {
                if (-not $v) { continue }
                & $emit (& $optionLabel $v.value)
                & $recurse $v.children
            }
        }
        '*SimpleSettingInstance' { & $emit (& $simpleLabel $Instance.simpleSettingValue) }
        '*SimpleSettingCollectionInstance' {
            foreach ($v in @($Instance.simpleSettingCollectionValue)) { if ($v) { & $emit (& $simpleLabel $v) } }
        }
        '*GroupSettingInstance' { & $recurse $Instance.groupSettingValue.children }
        '*GroupSettingCollectionInstance' {
            foreach ($v in @($Instance.groupSettingCollectionValue)) { if ($v) { & $recurse $v.children } }
        }
        default { Write-Warning "Unknown setting instance type '$type' on '$id' was skipped" }
    }
}

function Get-MergedSettings($Side, $Index) {
    $flat = [System.Collections.Generic.List[object]]::new()
    foreach ($s in @($Side.settings)) {
        if ($s) { Add-FlatSetting $s.settingInstance @() @() $Index $flat }
    }
    # Collections produce one record per value, so merge them into one record per setting
    $merged = @{}
    foreach ($r in $flat) {
        if (-not $merged.ContainsKey($r.Key)) {
            $merged[$r.Key] = [pscustomobject]@{
                Key = $r.Key; Id = $r.Id; Name = $r.Name; Parents = $r.Parents
                Values = [System.Collections.Generic.List[string]]::new()
            }
        }
        $merged[$r.Key].Values.Add($r.Display)
    }
    foreach ($m in $merged.Values) {
        $m | Add-Member -NotePropertyName Compare -NotePropertyValue ((@($m.Values | Sort-Object -Unique)) -join "`n")
    }
    return $merged
}

function Get-CategoryName([string]$Id, $RefIndex, $DiffIndex, $Categories) {
    $def = $DiffIndex.Definitions[$Id]
    if (-not $def) { $def = $RefIndex.Definitions[$Id] }
    if ($def -and $def.categoryId -and $Categories -and $Categories[[string]$def.categoryId]) {
        return [string]$Categories[[string]$def.categoryId].displayName
    }
    if ($Id -match '^device_vendor_msft_policy_config_([^_]+)') { return $Matches[1] }
    return 'Other'
}

function Get-ValueHtml($Setting) {
    if (-not $Setting) { return '<span class="none">Not in policy</span>' }
    $parts = @($Setting.Values | Sort-Object -Unique | ForEach-Object { "<div class=`"v`">$(Enc $_)</div>" })
    return ($parts -join '')
}

# ---- Load and compare ----
$data = Get-Content -LiteralPath $InputPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100
foreach ($label in 'reference', 'difference') {
    if (-not $data[$label]) { throw "'$InputPath' has no '$label' section. Was it written by Export-IntuneSecurityBaseline.ps1?" }
}
$ref = $data.reference
$diff = $data.difference
$refIndex = New-DefinitionIndex $ref
$diffIndex = New-DefinitionIndex $diff
$refTemplate = Get-TemplateIdSet $ref
$diffTemplate = Get-TemplateIdSet $diff
$refSettings = Get-MergedSettings $ref $refIndex
$diffSettings = Get-MergedSettings $diff $diffIndex

$rows = [System.Collections.Generic.List[object]]::new()
$added = [System.Collections.Generic.List[object]]::new()
$removed = [System.Collections.Generic.List[object]]::new()

foreach ($key in $diffSettings.Keys) {
    if ($refSettings.ContainsKey($key)) {
        $status = if ($refSettings[$key].Compare -eq $diffSettings[$key].Compare) { 'Unchanged' } else { 'Changed' }
        $rows.Add([pscustomobject]@{ Status = $status; Ref = $refSettings[$key]; Diff = $diffSettings[$key] })
    }
    else { $added.Add($diffSettings[$key]) }
}
foreach ($key in $refSettings.Keys) {
    if (-not $diffSettings.ContainsKey($key)) { $removed.Add($refSettings[$key]) }
}

# Pair a removed and an added setting only when the display name identifies them unambiguously
$addedByName = $added | Group-Object Name -AsHashTable -AsString
$removedByName = $removed | Group-Object Name -AsHashTable -AsString
$paired = [System.Collections.Generic.HashSet[string]]::new()
if ($addedByName -and $removedByName) {
    foreach ($name in @($addedByName.Keys)) {
        if ($removedByName.ContainsKey($name) -and @($addedByName[$name]).Count -eq 1 -and @($removedByName[$name]).Count -eq 1) {
            $a = @($addedByName[$name])[0]
            $r = @($removedByName[$name])[0]
            $rows.Add([pscustomobject]@{ Status = 'New ID'; Ref = $r; Diff = $a })
            [void]$paired.Add($a.Key)
            [void]$paired.Add($r.Key)
        }
    }
}
foreach ($a in $added) { if (-not $paired.Contains($a.Key)) { $rows.Add([pscustomobject]@{ Status = 'Added'; Ref = $null; Diff = $a }) } }
foreach ($r in $removed) { if (-not $paired.Contains($r.Key)) { $rows.Add([pscustomobject]@{ Status = 'Removed'; Ref = $r; Diff = $null }) } }

# ---- Render ----
$refName = Enc $ref.policy.name
$diffName = Enc $diff.policy.name
$statusOrder = @{ 'Added' = 0; 'Changed' = 1; 'Removed' = 2; 'New ID' = 3; 'Unchanged' = 4 }
$counts = @{}
foreach ($s in $statusOrder.Keys) { $counts[$s] = @($rows | Where-Object Status -EQ $s).Count }

foreach ($row in $rows) {
    $main = if ($row.Diff) { $row.Diff } else { $row.Ref }
    $row | Add-Member -NotePropertyName Main -NotePropertyValue $main
    $row | Add-Member -NotePropertyName Category -NotePropertyValue (Get-CategoryName $main.Id $refIndex $diffIndex $data.categories)
    $row | Add-Member -NotePropertyName Order -NotePropertyValue $statusOrder[$row.Status]
}

$sections = [System.Text.StringBuilder]::new()
foreach ($group in ($rows | Group-Object Category | Sort-Object Name)) {
    $trs = [System.Text.StringBuilder]::new()
    foreach ($row in ($group.Group | Sort-Object Order, { $_.Main.Name })) {
        $m = $row.Main
        $def = $diffIndex.Definitions[$m.Id]
        if (-not $def) { $def = $refIndex.Definitions[$m.Id] }

        $note = ''
        if ($row.Status -in 'Added', 'New ID') {
            $note = if ($refTemplate.Contains($m.Id)) { "Also in the $refName template" }
            elseif ($diffTemplate.Contains($m.Id)) { "New in the $diffName template" } else { '' }
        }
        elseif ($row.Status -eq 'Removed') {
            $note = if ($diffTemplate.Contains($m.Id)) { "Still in the $diffName template" }
            elseif ($refTemplate.Contains($m.Id)) { "Dropped from the $diffName template" } else { '' }
        }
        $noteHtml = if ($note) { "<div class=`"note`">$note</div>" } else { '' }

        $parents = @($m.Parents | Where-Object { $_ })
        $parentHtml = if ($parents) { "<div class=`"path`">$(Enc ($parents -join ' > '))</div>" } else { '' }

        $detail = [System.Text.StringBuilder]::new()
        if ($def -and $def.description) { [void]$detail.Append("<p>$(Enc $def.description)</p>") }
        if ($row.Status -eq 'New ID') {
            [void]$detail.Append("<p><span class=`"k`">Old ID</span> <code>$(Enc $row.Ref.Id)</code></p>")
            [void]$detail.Append("<p><span class=`"k`">New ID</span> <code>$(Enc $row.Diff.Id)</code></p>")
        }
        else { [void]$detail.Append("<p><span class=`"k`">ID</span> <code>$(Enc $m.Id)</code></p>") }
        if ($def) {
            foreach ($u in @($def.infoUrls)) {
                if ($u -match '^https?://') { [void]$detail.Append("<p><a href=`"$(Enc $u)`" rel=`"noopener noreferrer`" target=`"_blank`">$(Enc $u)</a></p>") }
            }
        }

        $slug = ($row.Status -replace ' ', '').ToLowerInvariant()
        [void]$trs.Append(@"
<tr class="row" data-status="$($row.Status)">
<td class="name"><div class="title">$(Enc $m.Name)</div>$parentHtml<details><summary>Details</summary>$($detail.ToString())</details></td>
<td class="val" data-label="$refName">$(Get-ValueHtml $row.Ref)</td>
<td class="val" data-label="$diffName">$(Get-ValueHtml $row.Diff)</td>
<td class="stat"><span class="badge $slug">$($row.Status)</span>$noteHtml</td>
</tr>

"@)
    }
    [void]$sections.Append(@"
<section class="cat">
<h2>$(Enc $group.Name)</h2>
<div class="tablewrap"><table>
<thead><tr><th>Setting</th><th>$refName</th><th>$diffName</th><th>Status</th></tr></thead>
<tbody>
$($trs.ToString())</tbody>
</table></div>
</section>

"@)
}

$css = @'
:root{--bg:#f7f7f5;--surface:#fff;--text:#1e2023;--muted:#5f646b;--line:#dfe0dc;--accent:#2452b8;
--add-bg:#e2f3e6;--add-fg:#17602f;--chg-bg:#fbeecb;--chg-fg:#6f4c00;--rem-bg:#fae3e1;--rem-fg:#8f241c;
--id-bg:#e3eafa;--id-fg:#234a9c;--same-bg:#ececea;--same-fg:#55595f}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#17181a;--surface:#212326;--text:#eceded;--muted:#a3a8ae;--line:#36393d;--accent:#8fb0f5;
--add-bg:#17361f;--add-fg:#90dca6;--chg-bg:#3b2f10;--chg-fg:#ecca74;--rem-bg:#401c1a;--rem-fg:#f3a79f;
--id-bg:#1c2a4a;--id-fg:#a9c1f7;--same-bg:#2d2f32;--same-fg:#b4b8bd}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 "Segoe UI",system-ui,-apple-system,Arial,sans-serif}
main{max-width:1240px;margin:0 auto;padding:32px 24px 64px}
h1{font-size:28px;line-height:1.2;margin:0 0 6px;text-wrap:balance}
.sub{color:var(--muted);margin:0 0 4px}
.caveat{color:var(--muted);margin:14px 0 24px;max-width:78ch;font-size:14px}
.filters{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:8px;margin-bottom:12px}
.filters button{font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:10px 12px;text-align:left;cursor:pointer;min-height:44px}
.filters button b{display:block;font-size:22px;line-height:1.2;font-variant-numeric:tabular-nums}
.filters button span{color:var(--muted);font-size:13px}
.filters button[aria-pressed="true"]{border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent)}
button:focus-visible,input:focus-visible,summary:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
#search{width:100%;font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin-bottom:8px;min-height:44px}
#shown{color:var(--muted);font-size:13px;margin:0 0 20px}
.cat{margin-bottom:28px}
.cat h2{font-size:16px;margin:0 0 8px}
.tablewrap{background:var(--surface);border:1px solid var(--line);border-radius:8px;overflow:hidden}
table{width:100%;border-collapse:collapse;table-layout:fixed}
th{font-size:12px;font-weight:600;color:var(--muted);text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
th:nth-child(1){width:38%}th:nth-child(2),th:nth-child(3){width:23%}th:nth-child(4){width:16%}
td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
tbody tr:last-child td{border-bottom:0}
.title{font-weight:600}
.path,.note{color:var(--muted);font-size:12.5px}
.note{margin-top:4px}
details{margin-top:4px;font-size:13px}
summary{color:var(--muted);cursor:pointer}
details p{margin:6px 0}
.k{color:var(--muted)}
code{font:12px Consolas,ui-monospace,monospace;overflow-wrap:anywhere}
a{color:var(--accent)}
.v+.v{margin-top:4px}
.none{color:var(--muted);font-style:italic}
.badge{display:inline-block;font-size:12px;font-weight:600;padding:2px 8px;border-radius:999px;white-space:nowrap}
.added{background:var(--add-bg);color:var(--add-fg)}.changed{background:var(--chg-bg);color:var(--chg-fg)}
.removed{background:var(--rem-bg);color:var(--rem-fg)}.newid{background:var(--id-bg);color:var(--id-fg)}
.unchanged{background:var(--same-bg);color:var(--same-fg)}
#empty{display:none;color:var(--muted);padding:32px 0;text-align:center}
[hidden]{display:none!important}
@media (max-width:760px){main{padding:20px 16px 48px}h1{font-size:23px}
.filters{grid-template-columns:repeat(2,minmax(0,1fr))}
thead{display:none}table,tbody,tr,td{display:block;width:100%}
tr.row{border-bottom:1px solid var(--line);padding:6px 0}tbody tr:last-child{border-bottom:0}
td{border:0;padding:6px 12px}
td.val::before{content:attr(data-label);display:block;font-size:12px;font-weight:600;color:var(--muted)}}
'@

$js = @'
(function(){
var buttons=[].slice.call(document.querySelectorAll('.filters button'));
var rows=[].slice.call(document.querySelectorAll('tr.row'));
var sections=[].slice.call(document.querySelectorAll('section.cat'));
var search=document.getElementById('search');
var shown=document.getElementById('shown');
var empty=document.getElementById('empty');
var filter='changes';
function apply(){
var q=search.value.trim().toLowerCase();
var n=0;
rows.forEach(function(r){
var s=r.getAttribute('data-status');
var ok=filter==='changes'?s!=='Unchanged':s===filter;
if(ok&&q){ok=r.textContent.toLowerCase().indexOf(q)!==-1;}
r.hidden=!ok;
if(ok){n++;}
});
sections.forEach(function(c){c.hidden=!c.querySelector('tr.row:not([hidden])');});
shown.textContent='Showing '+n+' of '+rows.length+' settings';
empty.style.display=n?'none':'block';
}
buttons.forEach(function(b){b.addEventListener('click',function(){
filter=b.getAttribute('data-filter');
buttons.forEach(function(x){x.setAttribute('aria-pressed',x===b?'true':'false');});
apply();
});});
search.addEventListener('input',apply);
apply();
})();
'@

$changeTotal = $rows.Count - $counts['Unchanged']
$fmt = { param($d) if ($d) { ([datetime]$d).ToString('yyyy-MM-dd') } else { 'unknown' } }
$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Baseline Comparison</title>
<style>
$css
</style>
</head>
<body>
<main>
<h1>Security baseline differences: $refName &rarr; $diffName</h1>
<p class="sub">$(Enc $ref.template.displayName), version $(Enc $ref.template.displayVersion) &rarr; version $(Enc $diff.template.displayVersion). Generated $(Get-Date -Format 'yyyy-MM-dd').</p>
<p class="caveat">This compares the two policies as configured in the tenant, not Microsoft's defaults. $refName was last modified $(& $fmt $ref.policy.lastModifiedDateTime) and $diffName on $(& $fmt $diff.policy.lastModifiedDateTime), so a difference can also come from an edit to either policy. The template notes on added and removed settings show whether Microsoft's template changed too.</p>
<div class="filters" role="group" aria-label="Filter by status">
<button type="button" data-filter="changes" aria-pressed="true"><b>$changeTotal</b><span>All differences</span></button>
<button type="button" data-filter="Added" aria-pressed="false"><b>$($counts['Added'])</b><span>Added</span></button>
<button type="button" data-filter="Changed" aria-pressed="false"><b>$($counts['Changed'])</b><span>Changed value</span></button>
<button type="button" data-filter="Removed" aria-pressed="false"><b>$($counts['Removed'])</b><span>Removed</span></button>
<button type="button" data-filter="New ID" aria-pressed="false"><b>$($counts['New ID'])</b><span>New ID, same name</span></button>
<button type="button" data-filter="Unchanged" aria-pressed="false"><b>$($counts['Unchanged'])</b><span>Unchanged</span></button>
</div>
<input id="search" type="search" placeholder="Search settings, values or IDs" aria-label="Search settings, values or IDs">
<p id="shown" aria-live="polite"></p>
$($sections.ToString())
<p id="empty">No settings match this filter.</p>
</main>
<script>
$js
</script>
</body>
</html>
"@

Set-Content -LiteralPath $OutputPath -Value $html -Encoding utf8
Write-Output ("Added={0} Changed={1} Removed={2} NewId={3} Unchanged={4}" -f $counts['Added'], $counts['Changed'], $counts['Removed'], $counts['New ID'], $counts['Unchanged'])
Write-Output "Report written to $OutputPath"
