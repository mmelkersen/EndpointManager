param (
    [switch] $CheckComplianceOnly = $false
	)

# Variables
[System.Int32]$policyBinaryTimeoutSeconds = 300
[System.Int32]$waitBatchSeconds = 5
[System.Int32]$maxWaitSeconds = 300

[string]$miPolicyBinaryPathRoot = "$env:windir\System32"

if(-not ([Environment]::Is64BitProcess))
{
    $miPolicyBinaryPathRoot = "$env:windir\Sysnative"
}

[string]$miPolicyBinaryPath = Join-Path -Path $miPolicyBinaryPathRoot -ChildPath "AppLocker\ManagedInstaller.AppLocker"

[string]$SccmMiPolicy = 
@"
<AppLockerPolicy Version="1">
    <RuleCollection Type="Appx" EnforcementMode="NotConfigured" />
    <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
        <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Dummy Rule" Description="Dummy Rule" UserOrGroupSid="S-1-1-0" Action="Deny">
            <Conditions>
                <FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" />
            </Conditions>
        </FilePathRule>
        <RuleCollectionExtensions>
            <ThresholdExtensions>
                <Services EnforcementMode="Enabled" />
            </ThresholdExtensions>
            <RedstoneExtensions>
                <SystemApps Allow="Enabled" />
            </RedstoneExtensions>
        </RuleCollectionExtensions>
    </RuleCollection>
    <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
        <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Dummy Rule" Description="Dummy Rule" UserOrGroupSid="S-1-1-0" Action="Deny">
            <Conditions>
                <FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" />
            </Conditions>
        </FilePathRule>
        <RuleCollectionExtensions>
            <ThresholdExtensions>
                <Services EnforcementMode="Enabled" />
            </ThresholdExtensions>
            <RedstoneExtensions>
                <SystemApps Allow="Enabled" />
            </RedstoneExtensions>
        </RuleCollectionExtensions>
    </RuleCollection>
    <RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled">
        <FilePublisherRule Id="6cc9a840-b0fd-4f86-aca7-8424a22b4b93" Name="CMM - CCMEXEC.EXE, 5.0.0.0+, Microsoft signed" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
            <Conditions>
            <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="SYSTEM CENTER CONFIGURATION MANAGER" BinaryName="CCMEXEC.EXE">
                <BinaryVersionRange LowSection="5.0.0.0" HighSection="*" />
            </FilePublisherCondition>
            </Conditions>
        </FilePublisherRule>
        <FilePublisherRule Id="780ae2d3-5047-4240-8a57-767c251cbb12" Name="CCM - CCMSETUP.EXE, 5.0.0.0+, Microsoft signed" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
            <Conditions>
            <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="SYSTEM CENTER CONFIGURATION MANAGER" BinaryName="CCMSETUP.EXE">
                <BinaryVersionRange LowSection="5.0.0.0" HighSection="*" />
            </FilePublisherCondition>
            </Conditions>
        </FilePublisherRule>
        <FilePublisherRule Id="70104ed1-5589-4f29-bb46-2692a86ec089" Name="MICROSOFT.MANAGEMENT.SERVICES.INTUNEWINDOWSAGENT.EXE version 1.38.300.1 exactly in MICROSOFT® INTUNE™ from O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
            <Conditions>
                <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® INTUNE™" BinaryName="MICROSOFT.MANAGEMENT.SERVICES.INTUNEWINDOWSAGENT.EXE">
                    <BinaryVersionRange LowSection="1.38.300.1" HighSection="*" />
                </FilePublisherCondition>
            </Conditions>
        </FilePublisherRule>
    </RuleCollection>
    <RuleCollection Type="Msi" EnforcementMode="NotConfigured" />
    <RuleCollection Type="Script" EnforcementMode="NotConfigured" />
</AppLockerPolicy>
"@

function MergeAppLockerPolicy([string]$policyXml)
{
    $policyFile = '.\AppLockerPolicy.xml'
    $policyXml | Out-File $policyFile

    Write-Host "Merging and setting AppLocker policy"

    Set-AppLockerPolicy -XmlPolicy $policyFile -Merge -ErrorAction SilentlyContinue

    Remove-Item $policyFile
}

function VerifyCompliance([xml]$policy)
{
    $result = $false
    $miNode = $policy.AppLockerPolicy.ChildNodes | Where-Object{$_.Type -eq 'ManagedInstaller'}

    if(-not $miNode)
    {
        Write-Host('Policy does not contain any managed installers')
    }
    else
    {
        $ccmexecNode = $miNode.ChildNodes | Where-Object{($_.LocalName -eq 'FilePublisherRule') -and ($_.Name -eq 'CMM - SMSWD.EXE, 5.0.0.0+, Microsoft signed')}

        if(-not $ccmexecNode)
        {
            Write-Host('Policy does not have CCMEXEC managed installer policy.')
        }
        else
        {
            $ccmsetupNode = $miNode.ChildNodes | Where-Object{($_.LocalName -eq 'FilePublisherRule') -and ($_.Name -eq 'CCM - CCMSETUP.EXE, 5.0.0.0+, Microsoft signed')}

            if(-not $ccmsetupNode)
            {
                Write-Host('Policy does not have CCMSetup managed installer policy.')
            }
            else
            {
                $result = $true
            }
        }
    }

    return $result
}

# Execution flow starts here
# Get and load the current effective AppLocker policy
try
{
    [xml]$effectivePolicyXml = Get-AppLockerPolicy -Effective -Xml -ErrorVariable ev -ErrorAction SilentlyContinue
}
catch 
{ 
    Write-Error('Get-AppLockerPolicy failed. ' + $_.Exception.Message)
    exit 10
}

# Check if it contains MI policy and if the MI policy has rules for Ccmsetup/CcmExec
try
{
    $compliant = VerifyCompliance($effectivePolicyXml)
}
catch
{
    Write-Error('Failed to verify AppLocker policy compliance. ' + $_.Exception.Message)
    exit 12
}

if($compliant)
{
    Write-Host("AppLocker policy is compliant")
    exit 0
}

Write-Host("AppLocker policy is not compliant")

if($CheckComplianceOnly)
{
    exit 2
}

# Start services
Write-Host 'Starting services'

[Diagnostics.Process]::Start("$env:windir\System32\sc.exe","start gpsvc")
[Diagnostics.Process]::Start("$env:windir\System32\appidtel.exe","start -mionly")

[System.Int32]$waitedSeconds = 0

# Check service state, wait up to 1 minute
while($waitedSeconds -lt $maxWaitSeconds)
{
    Start-Sleep -Seconds $waitBatchSeconds
    $waitedSeconds += $waitBatchSeconds

    if(-not ((Get-Service AppIDSvc).Status -eq 'Running'))
    {
        Write-Host 'AppID Service is not fully started yet.'
        continue
    }

    if(-not ((Get-Service appid).Status -eq 'Running'))
    {
        Write-Host 'AppId Driver Service is not fully started yet.'
        continue
    }

    if(-not ((Get-Service applockerfltr).Status -eq 'Running'))
    {
        Write-Host 'AppLocker Filter Driver Service is not fully started yet.'
        continue
    }

    break
}

if (-not ($waitedSeconds -lt $maxWaitSeconds))
{
    Write-Error 'Time-out on waiting for services to start.'
    exit 1
}

# Set the policy
try
{
    MergeAppLockerPolicy($SccmMiPolicy)
}
catch
{
    Write-Error('Failed to merge AppLocker policy. ' + $_.Exception.Message)
    exit 14
}

# Wait for policy update
if(test-path $miPolicyBinaryPath)
{
	$previousPolicyBinaryTimeStamp = (Get-ChildItem $miPolicyBinaryPath).LastWriteTime
	Write-Host ('There is an existing ManagedInstaller policy binary (LastWriteTime: {0})' -f $previousPolicyBinaryTimeStamp.ToString('yyyy-MM-dd 
HH:mm'))
}

if($previousPolicyBinaryTimeStamp)
{
	$action = 'updated'
	$condition = '$previousPolicyBinaryTimeStamp -lt (Get-ChildItem $miPolicyBinaryPath).LastWriteTime'
}
else
{
	$action = 'created'
	$condition = 'test-path $miPolicyBinaryPath'
}

Write-Host "Waiting for policy binary to be $action"

$startTime = get-date

while(-not (Invoke-Expression $condition))
{
	Start-Sleep -Seconds $waitBatchSeconds

	if((new-timespan $startTime $(get-date)).TotalSeconds -ge $policyBinaryTimeoutSeconds)
	{ 
		Write-Error "Policy binary has not been $action within $policyBinaryTimeoutSeconds seconds"
	    exit 1
	}
}

Write-Host ('Policy binary was created after {0:mm} minutes {0:ss} seconds' -f (new-timespan $startTime $(get-date)))

# Check compliance again
try
{
    [xml]$effectivePolicyXml = Get-AppLockerPolicy -Effective -Xml -ErrorVariable ev -ErrorAction SilentlyContinue
}
catch 
{ 
    Write-Error('Get-AppLockerPolicy failed. ' + $_.Exception.Message)
    exit 10
}

# Check if it contains MI policy and if the MI policy has rules for Ccmsetup/CcmExec
try
{
    $compliant = VerifyCompliance($effectivePolicyXml)
}
catch
{
    Write-Error('Failed to verify AppLocker policy compliance. ' + $_.Exception.Message)
    exit 12
}

if($compliant -eq $false)
{
    Write-Error("AppLocker policy is not compliant")
    exit 1
}

Write-Host 'AppLocker with Managed Installer for CcmExec/CcmSetup successfully enabled'