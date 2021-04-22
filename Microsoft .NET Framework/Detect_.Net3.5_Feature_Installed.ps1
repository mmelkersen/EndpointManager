$DotNetState = Get-WindowsOptionalFeature -Online -FeatureName 'NetFx3'

If ($DotNetState.State -eq "Enabled")
    {
        Write-Host "Net 3.5 state Enabled"
        Exit 0
    }
    else
    {
        Write-Host "Net 3.5 state Disabled"
        Exit 1
    }