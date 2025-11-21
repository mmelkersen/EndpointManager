<#
.SYNOPSIS
    Retrieves the primary and secondary shared keys for an Azure Log Analytics workspace.

.DESCRIPTION
    This PowerShell script connects to Azure and retrieves both the primary and secondary shared keys 
    for a specified Log Analytics workspace. The script includes error handling for common Azure 
    PowerShell module conflicts and provides a REST API fallback method if the primary PowerShell 
    cmdlet fails. The primary key is automatically copied to the clipboard for convenience.

    Key features:
    - Dual method approach (PowerShell cmdlet + REST API fallback)
    - Automatic module conflict resolution
    - Azure authentication validation
    - Clipboard integration for easy key usage
    - Comprehensive error handling and troubleshooting guidance

.PARAMETER ResourceGroupName
    Specifies the name of the Azure Resource Group containing the Log Analytics workspace.
    Default value: "YourResourceGroupName"

.PARAMETER WorkspaceName
    Specifies the name of the Log Analytics workspace for which to retrieve the shared keys.
    Default value: "YourWorkspaceName"

.PARAMETER ForceModuleReload
    Forces a complete reload of all Azure PowerShell modules to resolve version conflicts.
    Use this switch if encountering serialization or module compatibility errors.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.String
    Displays the primary and secondary shared keys and copies the primary key to clipboard.

.NOTES
    File Name      : FindPrimaryAndSecondaryKey.ps1
    Author         : Mattias Melkersen
    Prerequisite   : Az.OperationalInsights, Az.Accounts, Az.Profile PowerShell modules
    Required Scope : Log Analytics Contributor or Log Analytics Reader with key access
    Version        : 1.0
    
    If module conflicts occur, use the -ForceModuleReload parameter or manually update:
    Update-Module Az -Force

.EXAMPLE
    .\FindPrimaryAndSecondaryKey.ps1
    
    Description
    -----------
    Runs the script with default parameter values to retrieve shared keys.

.EXAMPLE
    .\FindPrimaryAndSecondaryKey.ps1 -ResourceGroupName "rg-loganalytics" -WorkspaceName "MyWorkspace"
    
    Description
    -----------
    Retrieves shared keys for the specified Log Analytics workspace in the given resource group.

.EXAMPLE
    .\FindPrimaryAndSecondaryKey.ps1 -ResourceGroupName "production-rg" -WorkspaceName "prod-logs" -ForceModuleReload
    
    Description
    -----------
    Forces module reload to resolve conflicts and retrieves keys for the production workspace.

.LINK
    https://docs.microsoft.com/en-us/powershell/module/az.operationalinsights/get-azoperationalinsightsworkspacesharedkey

.COMPONENT
    Azure PowerShell, Log Analytics

.FUNCTIONALITY
    Azure Log Analytics workspace key management and retrieval
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ResourceGroupName = "YourResourceGroupName",
    
    [Parameter(Mandatory=$false)]
    [string]$WorkspaceName = "YourWorkspaceName",
    
    [Parameter(Mandatory=$false)]
    [switch]$ForceModuleReload
)

# Function to clean and reload modules
function Reset-AzModules {
    Write-Host "Cleaning and reloading Azure modules..." -ForegroundColor Yellow
    
    # Remove all loaded Az modules
    Get-Module Az.* | Remove-Module -Force -ErrorAction SilentlyContinue
    
    # Clear any potential conflicts
    [System.GC]::Collect()
    
    # Import required modules with force
    Import-Module Az.Accounts -Force
    Import-Module Az.Profile -Force
    Import-Module Az.OperationalInsights -Force
}

# Handle module loading and version conflicts
if ($ForceModuleReload) {
    Reset-AzModules
} else {
    # Check if Az.OperationalInsights module is available
    if (-not (Get-Module -ListAvailable -Name Az.OperationalInsights)) {
        Write-Warning "Az.OperationalInsights module is not installed. Please install it using: Install-Module Az.OperationalInsights"
        exit 1
    }

    # Import the module if not already loaded
    if (-not (Get-Module -Name Az.OperationalInsights)) {
        try {
            Import-Module Az.OperationalInsights -Force
        }
        catch {
            Write-Warning "Module import failed with error. Attempting to reset modules..."
            Reset-AzModules
        }
    }
}

# Check Azure connection
try {
    $context = Get-AzContext
    if (-not $context) {
        Write-Host "Not connected to Azure. Please run Connect-AzAccount first." -ForegroundColor Red
        exit 1
    }
    Write-Host "Connected to Azure as: $($context.Account.Id)" -ForegroundColor Green
}
catch {
    Write-Host "Azure connection check failed. Please run Connect-AzAccount first." -ForegroundColor Red
    exit 1
}

try {
    Write-Host "Getting shared key for Log Analytics workspace: $WorkspaceName in resource group: $ResourceGroupName" -ForegroundColor Green
    
    # Alternative method using REST API if PowerShell cmdlet fails
    $subscriptionId = (Get-AzContext).Subscription.Id
    
    try {
        # Primary method: Use PowerShell cmdlet
        $sharedKey = Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $ResourceGroupName -Name $WorkspaceName -ErrorAction Stop
        
        if ($sharedKey) {
            Write-Host "Successfully retrieved shared key using PowerShell cmdlet!" -ForegroundColor Green
            Write-Host "Primary Key: $($sharedKey.PrimarySharedKey)" -ForegroundColor Yellow
            Write-Host "Secondary Key: $($sharedKey.SecondarySharedKey)" -ForegroundColor Yellow
            
            # Optionally copy primary key to clipboard
            $sharedKey.PrimarySharedKey | Set-Clipboard
            Write-Host "Primary key has been copied to clipboard." -ForegroundColor Cyan
        }
    }
    catch {
        Write-Warning "PowerShell cmdlet failed: $($_.Exception.Message)"
        Write-Host "Attempting alternative method using REST API..." -ForegroundColor Yellow
        
        # Alternative method: Use REST API directly
        $accessToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, "https://management.azure.com/").AccessToken
        
        $headers = @{
            'Authorization' = "Bearer $accessToken"
            'Content-Type' = 'application/json'
        }
        
        $uri = "https://management.azure.com/subscriptions/$subscriptionId/resourcegroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/sharedKeys?api-version=2020-08-01"
        
        $response = Invoke-RestMethod -Uri $uri -Method POST -Headers $headers
        
        if ($response) {
            Write-Host "Successfully retrieved shared key using REST API!" -ForegroundColor Green
            Write-Host "Primary Key: $($response.primarySharedKey)" -ForegroundColor Yellow
            Write-Host "Secondary Key: $($response.secondarySharedKey)" -ForegroundColor Yellow
            
            # Optionally copy primary key to clipboard
            $response.primarySharedKey | Set-Clipboard
            Write-Host "Primary key has been copied to clipboard." -ForegroundColor Cyan
        }
    }
}
catch {
    Write-Error "Error occurred: $($_.Exception.Message)"
    Write-Host "Troubleshooting steps:" -ForegroundColor Red
    Write-Host "1. Ensure you are authenticated: Connect-AzAccount" -ForegroundColor Red
    Write-Host "2. Check if you have the right permissions on the Log Analytics workspace" -ForegroundColor Red
    Write-Host "3. Verify the resource group and workspace name are correct" -ForegroundColor Red
    Write-Host "4. Try running with -ForceModuleReload parameter" -ForegroundColor Red
    Write-Host "5. Update Azure PowerShell: Update-Module Az" -ForegroundColor Red
}