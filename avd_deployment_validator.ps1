<#
.SYNOPSIS
    AVD Deployment Validator -- read-only preflight and post-deployment validation for
    Azure Virtual Desktop on Azure Commercial.

.DESCRIPTION
    Runs a structured set of validation checks against an Azure subscription and reports
    each one as PASS / WARN / FAIL / INFO / SKIP, with a remediation hint where relevant.

    Two modes are available (and can be combined):

      Preflight       Validates that a subscription, region, network, storage, image and
                      policy posture are ready to RECEIVE an AVD deployment. Run this
                      BEFORE deploying.

      PostDeployment  Validates that an AVD deployment actually landed correctly -- host
                      pool wiring, app group RBAC, session host registration and health,
                      FSLogix storage, scaling plans, diagnostics and backup. Run this
                      AFTER deploying.

    READ-ONLY GUARANTEE
    ------------------------------------------------------------------
    This script performs discovery only. It calls Get-* / Test-* cmdlets exclusively and
    never invokes New-*, Set-*, Update-*, Add-*, Remove-*, Restart-*, Start-* or Stop-*
    against any Azure resource. It creates files only inside the local output folder.
    The only network traffic it originates beyond ARM reads is an optional outbound TCP
    connect test (-IncludeNetworkProbe), which opens and immediately closes a socket and
    sends no payload.

    The minimum Azure role required is Reader. Desktop Virtualization Reader is
    recommended for full session host enumeration. No write role is needed.

    This is a readiness and health validation tool. It is NOT a production-readiness
    certification, a compliance attestation, or a security audit.

.PARAMETER Mode
    Preflight (default), PostDeployment, or Both.

.PARAMETER SubscriptionName
    Display name of the subscription to validate. Ignored if -SubscriptionId is supplied.

.PARAMETER SubscriptionId
    GUID of the subscription to validate. Defaults to the current Az context subscription.

.PARAMETER Location
    Azure region the session hosts will be (or were) deployed into. Required for most
    preflight checks (quota, SKU availability, image replication).

.PARAMETER MetadataLocation
    Region hosting the AVD control plane objects (host pool / workspace / app group).
    Defaults to -Location. AVD metadata is only supported in a subset of regions.

.PARAMETER ResourceGroupName
    Target resource group for the deployment, or the resource group holding the host pool.

.PARAMETER VirtualNetworkName
    VNet the session host NICs attach to.

.PARAMETER VirtualNetworkResourceGroup
    Resource group of the VNet. Defaults to -ResourceGroupName.

.PARAMETER SubnetName
    Subnet the session host NICs attach to. Drives the IP capacity, NSG and UDR checks.

.PARAMETER SessionHostCount
    Number of session hosts planned (preflight) or expected (post-deployment). Drives
    quota, subnet capacity and host count parity checks.

.PARAMETER SessionHostVmSize
    Planned VM size, e.g. Standard_D4ads_v5. Drives SKU availability and vCPU quota checks.

.PARAMETER HostPoolName
    Host pool name. Preflight uses it for a naming collision check; PostDeployment scopes
    validation to this host pool. Omit in PostDeployment to validate every host pool in
    the subscription.

.PARAMETER WorkspaceName
    AVD workspace name (preflight naming collision check).

.PARAMETER ApplicationGroupName
    AVD application group name (preflight naming collision check).

.PARAMETER StorageAccountName
    Storage account backing FSLogix profile containers or MSIX app attach.

.PARAMETER StorageAccountResourceGroup
    Resource group of the storage account. Defaults to -ResourceGroupName.

.PARAMETER FileShareName
    Azure Files share used for FSLogix profiles.

.PARAMETER LogAnalyticsWorkspaceName
    Log Analytics workspace expected to receive AVD diagnostics.

.PARAMETER LogAnalyticsResourceGroup
    Resource group of the Log Analytics workspace. Defaults to -ResourceGroupName.

.PARAMETER ImageId
    Resource ID of the session host image -- an Azure Compute Gallery image version or
    image definition, or a managed image. Marketplace URNs are reported as INFO only.

.PARAMETER DomainName
    AD DS domain the session hosts will join. Enables DNS configuration checks.

.PARAMETER MaxHeartbeatAgeMinutes
    PostDeployment. Session hosts whose last heartbeat is older than this are flagged.
    Default 30.

.PARAMETER IpBufferPercent
    Preflight. Headroom required on top of -SessionHostCount when evaluating free subnet
    IPs, to allow for reimaging and scale-out. Default 20.

.PARAMETER IncludeNetworkProbe
    Opt in to outbound TCP connect tests against the AVD required endpoints. These run
    from the machine executing the script, which is usually NOT a session host -- treat
    the result as indicative, not authoritative.

.PARAMETER ConfigPath
    Optional JSON file supplying any of the above parameters. Explicit command line
    parameters always win over config file values.

.PARAMETER OutputPath
    Parent directory for the report package. Defaults to the current directory, or
    ~/clouddrive when running in Azure Cloud Shell.

.PARAMETER SkipZip
    Do not produce a ZIP archive of the report package.

.PARAMETER FailOnWarning
    Return a non-zero exit code when any check reports WARN (by default only FAIL does).

.PARAMETER PassThru
    Emit the check result objects to the pipeline in addition to writing the report.

.EXAMPLE
    .\avd_deployment_validator.ps1 -Mode Preflight -Location eastus2 `
        -ResourceGroupName rg-avd-prod -VirtualNetworkName vnet-avd -SubnetName snet-avd-hosts `
        -SessionHostCount 20 -SessionHostVmSize Standard_D4ads_v5

.EXAMPLE
    .\avd_deployment_validator.ps1 -Mode PostDeployment -ResourceGroupName rg-avd-prod `
        -HostPoolName hp-avd-prod -SessionHostCount 20 `
        -StorageAccountName stavdfslogix01 -FileShareName profiles

.EXAMPLE
    .\avd_deployment_validator.ps1 -Mode Both -ConfigPath .\avd-validation.config.json

.NOTES
    Requires PowerShell 5.1+ or PowerShell 7+, and the Az modules listed in the README.
    Exit codes: 0 = no failures, 1 = one or more FAIL (or WARN with -FailOnWarning),
                2 = the validator itself could not run (auth or subscription resolution).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Preflight', 'PostDeployment', 'Both')]
    [string]$Mode = 'Preflight',

    [Parameter(Mandatory = $false)][string]$SubscriptionName,
    [Parameter(Mandatory = $false)][string]$SubscriptionId,

    [Parameter(Mandatory = $false)][string]$Location,
    [Parameter(Mandatory = $false)][string]$MetadataLocation,

    [Parameter(Mandatory = $false)][string]$ResourceGroupName,

    [Parameter(Mandatory = $false)][string]$VirtualNetworkName,
    [Parameter(Mandatory = $false)][string]$VirtualNetworkResourceGroup,
    [Parameter(Mandatory = $false)][string]$SubnetName,

    [Parameter(Mandatory = $false)][int]$SessionHostCount = 0,
    [Parameter(Mandatory = $false)][string]$SessionHostVmSize,

    [Parameter(Mandatory = $false)][string]$HostPoolName,
    [Parameter(Mandatory = $false)][string]$WorkspaceName,
    [Parameter(Mandatory = $false)][string]$ApplicationGroupName,

    [Parameter(Mandatory = $false)][string]$StorageAccountName,
    [Parameter(Mandatory = $false)][string]$StorageAccountResourceGroup,
    [Parameter(Mandatory = $false)][string]$FileShareName,

    [Parameter(Mandatory = $false)][string]$LogAnalyticsWorkspaceName,
    [Parameter(Mandatory = $false)][string]$LogAnalyticsResourceGroup,

    [Parameter(Mandatory = $false)][string]$ImageId,
    [Parameter(Mandatory = $false)][string]$DomainName,

    [Parameter(Mandatory = $false)][int]$MaxHeartbeatAgeMinutes = 30,
    [Parameter(Mandatory = $false)][ValidateRange(0, 500)][int]$IpBufferPercent = 20,

    [Parameter(Mandatory = $false)][switch]$IncludeNetworkProbe,
    [Parameter(Mandatory = $false)][string]$ConfigPath,
    [Parameter(Mandatory = $false)][string]$OutputPath = (Get-Location).Path,
    [Parameter(Mandatory = $false)][switch]$SkipZip,
    [Parameter(Mandatory = $false)][switch]$FailOnWarning,
    [Parameter(Mandatory = $false)][switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------
# region Cloud Shell Detection
# ---------------------------------------------
$script:IsCloudShell = $false
if ($env:AZUREPS_HOST_ENVIRONMENT -like 'cloud-shell*' -or $env:ACC_CLOUD -eq 'true') {
    $script:IsCloudShell = $true
    if (-not $PSBoundParameters.ContainsKey('OutputPath')) {
        $cloudDrive = Join-Path $HOME 'clouddrive'
        if (Test-Path $cloudDrive) { $OutputPath = $cloudDrive }
    }
}
# endregion

# ---------------------------------------------
# region Script State
# ---------------------------------------------
$script:Timestamp    = Get-Date -Format 'yyyyMMddTHHmmss'
$script:PackageName  = "avd-validation-$script:Timestamp"
$script:RootDir      = Join-Path $OutputPath $script:PackageName
$script:LogMessages  = [System.Collections.Generic.List[string]]::new()
$script:Results      = [System.Collections.Generic.List[psobject]]::new()
$script:CurrentPhase = 'Preflight'
$script:Context      = $null
# endregion

# ---------------------------------------------
# region Core Helpers
# ---------------------------------------------

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $script:LogMessages.Add($entry)
    if ($Level -eq 'ERROR')     { Write-Host $entry -ForegroundColor Red }
    elseif ($Level -eq 'WARN')  { Write-Host $entry -ForegroundColor Yellow }
    else                        { Write-Host $entry }
}

function Get-Prop {
    <#
    .SYNOPSIS
        StrictMode-safe property read. Returns $Default when the property is absent or null.
    .DESCRIPTION
        Az module object shapes drift between major versions (most notably the flattening
        of Get-AzPolicyAssignment output). Every property access on an Az-returned object
        goes through this helper so a shape change downgrades a check rather than
        crashing the run.
    #>
    param([object]$InputObject, [string]$Name, $Default = $null)
    if ($null -eq $InputObject) { return $Default }
    try {
        $prop = $InputObject.PSObject.Properties[$Name]
        if ($null -eq $prop) { return $Default }
        $value = $prop.Value
        if ($null -eq $value) { return $Default }
        return $value
    } catch {
        return $Default
    }
}

function Get-FirstProp {
    <#
    .SYNOPSIS
        Reads the first property that exists from a list of candidate paths.
    .DESCRIPTION
        Accepts dotted paths, e.g. 'Properties.DisplayName'. Used to tolerate the
        Az.Resources v8 property flattening where 'Properties.X' became 'X'.
    #>
    param([object]$InputObject, [string[]]$Paths, $Default = $null)
    foreach ($path in $Paths) {
        $current = $InputObject
        $ok = $true
        foreach ($segment in ($path -split '\.')) {
            $current = Get-Prop -InputObject $current -Name $segment
            if ($null -eq $current) { $ok = $false; break }
        }
        if ($ok) { return $current }
    }
    return $Default
}

function ConvertTo-DisplayString {
    <#
    .SYNOPSIS Flattens a value into a single-line, CSV-safe string.
    #>
    param([object]$Value, [int]$MaxLength = 400)
    if ($null -eq $Value) { return '' }
    $text = ''
    if ($Value -is [string]) {
        $text = $Value
    } elseif ($Value -is [System.Collections.IEnumerable]) {
        $text = (@($Value) | ForEach-Object { "$_" }) -join ', '
    } else {
        $text = "$Value"
    }
    $text = ($text -replace '\r?\n', ' ').Trim()
    if ($text.Length -gt $MaxLength) { $text = $text.Substring(0, $MaxLength) + '...' }
    return $text
}

function Add-Check {
    <#
    .SYNOPSIS Records a single validation result and prints it.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][ValidateSet('PASS', 'WARN', 'FAIL', 'INFO', 'SKIP')][string]$Status,
        [string]$Detail = '',
        [string]$Recommendation = '',
        [string]$Scope = ''
    )

    $record = [pscustomobject]@{
        Phase          = $script:CurrentPhase
        Category       = $Category
        Check          = $Check
        Status         = $Status
        Detail         = (ConvertTo-DisplayString -Value $Detail -MaxLength 1000)
        Recommendation = (ConvertTo-DisplayString -Value $Recommendation -MaxLength 1000)
        Scope          = (ConvertTo-DisplayString -Value $Scope -MaxLength 300)
        CheckedUtc     = (Get-Date).ToUniversalTime().ToString('o')
    }
    $script:Results.Add($record)

    $color = 'Gray'
    switch ($Status) {
        'PASS' { $color = 'Green' }
        'WARN' { $color = 'Yellow' }
        'FAIL' { $color = 'Red' }
        'INFO' { $color = 'Cyan' }
        'SKIP' { $color = 'DarkGray' }
    }
    $line = "  [{0}] {1,-26} {2}" -f $Status.PadRight(4), $Check, $record.Detail
    Write-Host $line -ForegroundColor $color
    $script:LogMessages.Add("[$Status] [$Category] $Check :: $($record.Detail)")
}

function Invoke-Check {
    <#
    .SYNOPSIS
        Runs a check body, converting any unhandled error into a WARN rather than
        aborting the whole validation run.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [string]$Scope = ''
    )
    try {
        & $Body
    } catch {
        Add-Check -Category $Category -Check $Check -Status 'WARN' `
            -Detail "Check could not complete: $($_.Exception.Message)" `
            -Recommendation 'Confirm the validator identity has Reader on this resource and that the required Az module is installed.' `
            -Scope $Scope
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ("-- {0} " -f $Title).PadRight(78, '-') -ForegroundColor White
    $script:LogMessages.Add("--- $Title ---")
}

function Ensure-Module {
    <#
    .SYNOPSIS
        Imports a module, installing it from PSGallery if absent.
    .DESCRIPTION
        Optional modules degrade to a warning and let the dependent checks report SKIP,
        so a missing Az.Monitor does not prevent the rest of the validation from running.
    #>
    param([string]$ModuleName, [switch]$Optional)
    try {
        if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
            Write-Log "Module $ModuleName not found -- installing from PSGallery ..."
            Install-Module -Name $ModuleName -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
        }
        Import-Module $ModuleName -ErrorAction Stop
        return $true
    } catch {
        if ($Optional) {
            Write-Log "Optional module $ModuleName unavailable -- dependent checks will be skipped. $($_.Exception.Message)" -Level WARN
            return $false
        }
        throw
    }
}

function Get-AzModuleVersions {
    Get-Module -Name Az.* -ListAvailable |
        Sort-Object Name -Unique |
        Select-Object Name, @{N = 'Version'; E = { $_.Version.ToString() } }
}

function Get-SubnetUsableIpCount {
    <#
    .SYNOPSIS
        Usable IPv4 addresses in a subnet prefix. Azure reserves 5 addresses per subnet
        (network, 3 platform, broadcast). Returns $null for IPv6 or unparsable input.
    #>
    param([string]$AddressPrefix)
    if ([string]::IsNullOrWhiteSpace($AddressPrefix)) { return $null }
    if ($AddressPrefix -like '*:*') { return $null }
    $parts = $AddressPrefix -split '/'
    if ($parts.Count -ne 2) { return $null }
    $maskBits = 0
    if (-not [int]::TryParse($parts[1], [ref]$maskBits)) { return $null }
    if ($maskBits -lt 0 -or $maskBits -gt 32) { return $null }
    $total = [math]::Pow(2, (32 - $maskBits))
    $usable = [int]$total - 5
    if ($usable -lt 0) { $usable = 0 }
    return $usable
}

function Test-TcpEndpoint {
    <#
    .SYNOPSIS
        Read-only outbound reachability probe. Opens a TCP socket, then closes it
        immediately. No payload is sent and nothing is written anywhere.
    #>
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs = 4000)
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return [pscustomobject]@{ Succeeded = $false; Message = "No response within ${TimeoutMs}ms" }
        }
        $client.EndConnect($async)
        return [pscustomobject]@{ Succeeded = $true; Message = 'Connected' }
    } catch {
        return [pscustomobject]@{ Succeeded = $false; Message = $_.Exception.Message }
    } finally {
        if ($null -ne $client) { $client.Close() }
    }
}

function Get-ResourceNameFromId {
    param([string]$ResourceId, [int]$FromEnd = 1)
    if ([string]::IsNullOrWhiteSpace($ResourceId)) { return '' }
    $segments = $ResourceId -split '/'
    $index = $segments.Count - $FromEnd
    if ($index -lt 0 -or $index -ge $segments.Count) { return '' }
    return $segments[$index]
}

function Sanitize-FileName {
    param([string]$Name)
    ($Name -replace '[^\w\-\.]', '_')
}

# endregion

# ---------------------------------------------
# region Config File Merge
# ---------------------------------------------

if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
    if (-not (Test-Path -Path $ConfigPath)) {
        throw "Config file not found: $ConfigPath"
    }
    Write-Log "Loading configuration from $ConfigPath ..."
    $configObject = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    $knownParameters = @($MyInvocation.MyCommand.Parameters.Keys)
    foreach ($setting in $configObject.PSObject.Properties) {
        if ($PSBoundParameters.ContainsKey($setting.Name)) {
            # An explicit command line parameter always beats the config file.
            continue
        }
        if ($setting.Name -like '_*') {
            # Underscore-prefixed keys are comments in the config file.
            continue
        }
        if ($knownParameters -notcontains $setting.Name) {
            Write-Log "Ignoring unknown config key '$($setting.Name)'." -Level WARN
            continue
        }
        if ($setting.Name -in @('ConfigPath')) { continue }
        Set-Variable -Name $setting.Name -Value $setting.Value -Scope Script
    }
}

# Derived defaults -- resource group fallbacks keep the parameter surface small for the
# common case where everything lives in one resource group.
if ([string]::IsNullOrWhiteSpace($VirtualNetworkResourceGroup))  { $VirtualNetworkResourceGroup  = $ResourceGroupName }
if ([string]::IsNullOrWhiteSpace($StorageAccountResourceGroup))  { $StorageAccountResourceGroup  = $ResourceGroupName }
if ([string]::IsNullOrWhiteSpace($LogAnalyticsResourceGroup))    { $LogAnalyticsResourceGroup    = $ResourceGroupName }
if ([string]::IsNullOrWhiteSpace($MetadataLocation))             { $MetadataLocation             = $Location }

# endregion

# ---------------------------------------------
# region Banner
# ---------------------------------------------

Write-Host ''
Write-Log '==================================================='
Write-Log ' AVD Deployment Validator (read-only)'
Write-Log '==================================================='
Write-Log "Mode          : $Mode"
Write-Log "Run timestamp : $script:Timestamp"
Write-Log "Output target : $script:RootDir"
if ($script:IsCloudShell) {
    Write-Log 'Environment   : Azure Cloud Shell detected -- output defaults to ~/clouddrive for persistence.'
}

# endregion

# ---------------------------------------------
# region Module Bootstrap
# ---------------------------------------------

$script:ModuleAvailable = @{}

$requiredModules = @(
    'Az.Accounts',
    'Az.Resources',
    'Az.Compute',
    'Az.Network',
    'Az.Storage',
    'Az.DesktopVirtualization'
)

# Optional modules power individual checks. When one is missing the dependent checks
# report SKIP instead of failing the run.
$optionalModules = @(
    'Az.OperationalInsights',
    'Az.Monitor',
    'Az.RecoveryServices',
    'Az.KeyVault',
    'Az.PrivateDns',
    'Az.PolicyInsights'
)

foreach ($moduleName in $requiredModules) {
    Ensure-Module -ModuleName $moduleName | Out-Null
    $script:ModuleAvailable[$moduleName] = $true
}
foreach ($moduleName in $optionalModules) {
    $script:ModuleAvailable[$moduleName] = [bool](Ensure-Module -ModuleName $moduleName -Optional)
}

Write-Log 'Az modules loaded.'

# endregion

# ---------------------------------------------
# region Authentication
# ---------------------------------------------

$script:Context = Get-AzContext -ErrorAction SilentlyContinue
if (-not $script:Context) {
    Write-Log 'No active Azure context -- launching interactive login (AzureCloud) ...'
    try {
        Connect-AzAccount -Environment AzureCloud -ErrorAction Stop | Out-Null
        $script:Context = Get-AzContext
    } catch {
        Write-Log "Authentication failed: $($_.Exception.Message)" -Level ERROR
        exit 2
    }
}
Write-Log "Authenticated as $(Get-Prop $script:Context.Account 'Id' '<unknown>') in tenant $(Get-Prop $script:Context.Tenant 'Id' '<unknown>')."

# endregion

# ---------------------------------------------
# region Subscription Resolution
# ---------------------------------------------

$targetSubscription = $null
try {
    if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
        $targetSubscription = Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop
    } elseif (-not [string]::IsNullOrWhiteSpace($SubscriptionName)) {
        $targetSubscription = Get-AzSubscription -ErrorAction Stop |
            Where-Object { $_.Name -eq $SubscriptionName } |
            Select-Object -First 1
        if (-not $targetSubscription) { throw "Subscription '$SubscriptionName' not found or not visible to this identity." }
    } else {
        $contextSubscription = Get-Prop $script:Context 'Subscription'
        if ($null -eq $contextSubscription) { throw 'No subscription in the current context and none supplied.' }
        $targetSubscription = Get-AzSubscription -SubscriptionId $contextSubscription.Id -ErrorAction Stop
        Write-Log "No subscription specified -- using the current context subscription."
    }
} catch {
    Write-Log "Subscription resolution failed: $($_.Exception.Message)" -Level ERROR
    exit 2
}

try {
    Set-AzContext -SubscriptionId $targetSubscription.Id -ErrorAction Stop | Out-Null
    $script:Context = Get-AzContext
} catch {
    Write-Log "Unable to set context to subscription '$($targetSubscription.Name)': $($_.Exception.Message)" -Level ERROR
    exit 2
}

$script:SubscriptionScope = "/subscriptions/$($targetSubscription.Id)"
Write-Log "Validating subscription: $($targetSubscription.Name) ($($targetSubscription.Id))"

# endregion

# =============================================
# region PREFLIGHT VALIDATION
# =============================================

function Invoke-PreflightValidation {
    <#
    .SYNOPSIS
        Validates that the subscription, region, network, storage, image and policy
        posture can receive an AVD deployment. Entirely read-only.
    #>
    $script:CurrentPhase = 'Preflight'
    Write-Host ''
    Write-Log '==================================================='
    Write-Log ' PREFLIGHT VALIDATION'
    Write-Log '==================================================='

    # -----------------------------------------
    # Identity and access
    # -----------------------------------------
    Write-Section 'Identity and Access'

    Invoke-Check -Category 'Identity' -Check 'Azure environment' -Scope $script:SubscriptionScope -Body {
        $environmentName = Get-Prop (Get-Prop $script:Context 'Environment') 'Name' 'Unknown'
        if ($environmentName -eq 'AzureCloud') {
            Add-Check -Category 'Identity' -Check 'Azure environment' -Status 'PASS' `
                -Detail 'Connected to Azure Commercial (AzureCloud).'
        } else {
            Add-Check -Category 'Identity' -Check 'Azure environment' -Status 'WARN' `
                -Detail "Connected to '$environmentName', not AzureCloud." `
                -Recommendation 'This validator targets Azure Commercial. Sovereign clouds have different AVD region and endpoint requirements.'
        }
    }

    Invoke-Check -Category 'Identity' -Check 'Subscription state' -Scope $script:SubscriptionScope -Body {
        $state = Get-Prop $targetSubscription 'State' 'Unknown'
        if ($state -eq 'Enabled') {
            Add-Check -Category 'Identity' -Check 'Subscription state' -Status 'PASS' `
                -Detail "Subscription '$($targetSubscription.Name)' is Enabled."
        } else {
            Add-Check -Category 'Identity' -Check 'Subscription state' -Status 'FAIL' `
                -Detail "Subscription state is '$state'." `
                -Recommendation 'Deployment requires an Enabled subscription.'
        }
    }

    Invoke-Check -Category 'Identity' -Check 'Reader access' -Scope $script:SubscriptionScope -Body {
        $null = Get-AzResourceGroup -ErrorAction Stop | Select-Object -First 1
        Add-Check -Category 'Identity' -Check 'Reader access' -Status 'PASS' `
            -Detail 'Validator identity can enumerate resource groups in this subscription.'
    }

    Invoke-Check -Category 'Identity' -Check 'Deployment role coverage' -Scope $script:SubscriptionScope -Body {
        # Reported as INFO because the identity running this read-only validator is often
        # deliberately NOT the identity that will perform the deployment.
        $accountId   = Get-Prop (Get-Prop $script:Context 'Account') 'Id' ''
        $accountType = Get-Prop (Get-Prop $script:Context 'Account') 'Type' ''
        $assignments = @()
        try {
            if ($accountType -eq 'ServicePrincipal') {
                $assignments = @(Get-AzRoleAssignment -ServicePrincipalName $accountId -ErrorAction Stop)
            } else {
                $assignments = @(Get-AzRoleAssignment -SignInName $accountId -ErrorAction Stop)
            }
        } catch {
            # Graph lookups may be blocked; fall back to the subscription-scoped list.
            $assignments = @(Get-AzRoleAssignment -Scope $script:SubscriptionScope -ErrorAction SilentlyContinue |
                Where-Object { (Get-Prop $_ 'SignInName' '') -eq $accountId })
        }

        if ($assignments.Count -eq 0) {
            Add-Check -Category 'Identity' -Check 'Deployment role coverage' -Status 'INFO' `
                -Detail 'Could not enumerate role assignments for the current identity (Graph or RBAC read may be restricted).' `
                -Recommendation 'Confirm separately that the deploying identity holds Contributor (or Desktop Virtualization Contributor + Virtual Machine Contributor + Network Contributor) on the target scope.'
            return
        }

        $roleNames  = @($assignments | ForEach-Object { Get-Prop $_ 'RoleDefinitionName' '' } | Where-Object { $_ } | Sort-Object -Unique)
        $privileged = @($roleNames | Where-Object { $_ -in @('Owner', 'Contributor', 'Desktop Virtualization Contributor') })

        if ($privileged.Count -gt 0) {
            Add-Check -Category 'Identity' -Check 'Deployment role coverage' -Status 'PASS' `
                -Detail "Current identity holds: $($roleNames -join ', ')." `
                -Recommendation 'Sufficient for deployment if this is also the deploying identity.'
        } else {
            Add-Check -Category 'Identity' -Check 'Deployment role coverage' -Status 'INFO' `
                -Detail "Current identity holds read-level roles only: $($roleNames -join ', ')." `
                -Recommendation 'Expected for a read-only validation run. Ensure the deploying identity separately holds Contributor or the AVD-specific write roles.'
        }
    }

    # -----------------------------------------
    # Resource providers
    # -----------------------------------------
    Write-Section 'Resource Providers'

    Invoke-Check -Category 'Providers' -Check 'Provider registration' -Scope $script:SubscriptionScope -Body {
        $requiredProviders = @(
            'Microsoft.DesktopVirtualization',
            'Microsoft.Compute',
            'Microsoft.Network',
            'Microsoft.Storage'
        )
        $recommendedProviders = @(
            'Microsoft.KeyVault',
            'Microsoft.OperationalInsights',
            'Microsoft.Insights',
            'Microsoft.ManagedIdentity',
            'Microsoft.GuestConfiguration',
            'Microsoft.RecoveryServices'
        )

        $providers = @(Get-AzResourceProvider -ListAvailable -ErrorAction Stop)
        $stateByNamespace = @{}
        foreach ($provider in $providers) {
            $ns = Get-Prop $provider 'ProviderNamespace' ''
            if ($ns) { $stateByNamespace[$ns] = (Get-Prop $provider 'RegistrationState' 'Unknown') }
        }

        foreach ($namespace in $requiredProviders) {
            $state = 'NotFound'
            if ($stateByNamespace.ContainsKey($namespace)) { $state = $stateByNamespace[$namespace] }
            if ($state -eq 'Registered') {
                Add-Check -Category 'Providers' -Check "Provider $namespace" -Status 'PASS' -Detail 'Registered.'
            } else {
                Add-Check -Category 'Providers' -Check "Provider $namespace" -Status 'FAIL' `
                    -Detail "Registration state is '$state'." `
                    -Recommendation "Register with: Register-AzResourceProvider -ProviderNamespace $namespace"
            }
        }

        foreach ($namespace in $recommendedProviders) {
            $state = 'NotFound'
            if ($stateByNamespace.ContainsKey($namespace)) { $state = $stateByNamespace[$namespace] }
            if ($state -eq 'Registered') {
                Add-Check -Category 'Providers' -Check "Provider $namespace" -Status 'PASS' -Detail 'Registered.'
            } else {
                Add-Check -Category 'Providers' -Check "Provider $namespace" -Status 'WARN' `
                    -Detail "Registration state is '$state'." `
                    -Recommendation "Required only if you use this service. Register with: Register-AzResourceProvider -ProviderNamespace $namespace"
            }
        }
    }

    # -----------------------------------------
    # Region and metadata location
    # -----------------------------------------
    Write-Section 'Region'

    if ([string]::IsNullOrWhiteSpace($Location)) {
        Add-Check -Category 'Region' -Check 'Target region' -Status 'SKIP' `
            -Detail 'No -Location supplied.' `
            -Recommendation 'Supply -Location to enable region, SKU availability, quota and image replication checks.'
    } else {
        Invoke-Check -Category 'Region' -Check 'Target region' -Body {
            $locations = @(Get-AzLocation -ErrorAction Stop)
            $match = $locations | Where-Object {
                (Get-Prop $_ 'Location' '') -eq $Location -or (Get-Prop $_ 'DisplayName' '') -eq $Location
            } | Select-Object -First 1

            if ($null -eq $match) {
                Add-Check -Category 'Region' -Check 'Target region' -Status 'FAIL' `
                    -Detail "Region '$Location' is not available to this subscription." `
                    -Recommendation 'Run Get-AzLocation to list regions available to the subscription.'
                return
            }
            $script:ResolvedLocation    = Get-Prop $match 'Location' $Location
            $script:ResolvedLocationName = Get-Prop $match 'DisplayName' $Location
            Add-Check -Category 'Region' -Check 'Target region' -Status 'PASS' `
                -Detail "Region '$script:ResolvedLocation' ($script:ResolvedLocationName) is available."
        }

        Invoke-Check -Category 'Region' -Check 'AVD metadata region' -Body {
            # The AVD control plane (host pool / workspace / app group objects) is only
            # supported in a subset of regions, which can differ from the session host region.
            $avdProvider = Get-AzResourceProvider -ProviderNamespace 'Microsoft.DesktopVirtualization' -ErrorAction Stop
            $hostPoolType = @($avdProvider) | ForEach-Object { Get-Prop $_ 'ResourceTypes' @() } |
                Where-Object { (Get-Prop $_ 'ResourceTypeName' '') -eq 'hostPools' } | Select-Object -First 1

            $supported = @(Get-Prop $hostPoolType 'Locations' @())
            if ($supported.Count -eq 0) {
                Add-Check -Category 'Region' -Check 'AVD metadata region' -Status 'INFO' `
                    -Detail 'Could not read the supported metadata region list from the resource provider.' `
                    -Recommendation 'Verify the metadata region against the AVD documentation before deploying.'
                return
            }

            $locations = @(Get-AzLocation -ErrorAction SilentlyContinue)
            $metadataMatch = $locations | Where-Object {
                (Get-Prop $_ 'Location' '') -eq $MetadataLocation -or (Get-Prop $_ 'DisplayName' '') -eq $MetadataLocation
            } | Select-Object -First 1
            $metadataDisplayName = $MetadataLocation
            if ($null -ne $metadataMatch) { $metadataDisplayName = Get-Prop $metadataMatch 'DisplayName' $MetadataLocation }

            if ($supported -contains $metadataDisplayName) {
                Add-Check -Category 'Region' -Check 'AVD metadata region' -Status 'PASS' `
                    -Detail "'$metadataDisplayName' supports AVD control plane objects."
            } else {
                Add-Check -Category 'Region' -Check 'AVD metadata region' -Status 'FAIL' `
                    -Detail "'$metadataDisplayName' is not in the supported AVD metadata region list." `
                    -Recommendation "Choose a metadata region from: $($supported -join ', '). Session hosts can still run in '$Location'."
            }
        }
    }

    # -----------------------------------------
    # VM SKU availability and quota
    # -----------------------------------------
    Write-Section 'Compute Capacity and Quota'

    $script:PlannedVcpuPerHost = 0
    $script:PlannedVmFamily    = ''

    if ([string]::IsNullOrWhiteSpace($Location) -or [string]::IsNullOrWhiteSpace($SessionHostVmSize)) {
        Add-Check -Category 'Capacity' -Check 'Session host SKU' -Status 'SKIP' `
            -Detail 'Requires both -Location and -SessionHostVmSize.' `
            -Recommendation 'Supply the planned VM size to validate regional availability, zone support and vCPU quota.'
    } else {
        Invoke-Check -Category 'Capacity' -Check 'Session host SKU' -Body {
            $skus = @(Get-AzComputeResourceSku -Location $Location -ErrorAction Stop |
                Where-Object { (Get-Prop $_ 'ResourceType' '') -eq 'virtualMachines' })
            $sku = $skus | Where-Object { (Get-Prop $_ 'Name' '') -eq $SessionHostVmSize } | Select-Object -First 1

            if ($null -eq $sku) {
                Add-Check -Category 'Capacity' -Check 'Session host SKU' -Status 'FAIL' `
                    -Detail "VM size '$SessionHostVmSize' is not offered in region '$Location'." `
                    -Recommendation 'Pick a size available in the region, or deploy into a region that offers it.'
                return
            }

            $script:PlannedVmFamily = Get-Prop $sku 'Family' ''
            $capabilities = @(Get-Prop $sku 'Capabilities' @())
            $vcpuCapability = $capabilities | Where-Object { (Get-Prop $_ 'Name' '') -eq 'vCPUs' } | Select-Object -First 1
            if ($null -ne $vcpuCapability) {
                $parsed = 0
                if ([int]::TryParse((Get-Prop $vcpuCapability 'Value' '0'), [ref]$parsed)) { $script:PlannedVcpuPerHost = $parsed }
            }

            $restrictions = @(Get-Prop $sku 'Restrictions' @())
            if ($restrictions.Count -gt 0) {
                $reasons = @($restrictions | ForEach-Object { Get-Prop $_ 'ReasonCode' 'Unknown' } | Sort-Object -Unique)
                Add-Check -Category 'Capacity' -Check 'Session host SKU' -Status 'FAIL' `
                    -Detail "VM size '$SessionHostVmSize' is restricted in '$Location': $($reasons -join ', ')." `
                    -Recommendation 'Request a quota or SKU restriction lift through Azure support, or select a different size or region.'
            } else {
                Add-Check -Category 'Capacity' -Check 'Session host SKU' -Status 'PASS' `
                    -Detail "VM size '$SessionHostVmSize' is available in '$Location' ($script:PlannedVcpuPerHost vCPU, family $script:PlannedVmFamily)."
            }

            # Availability zone support informs the resilience design.
            $locationInfo = @(Get-Prop $sku 'LocationInfo' @()) | Select-Object -First 1
            $zones = @(Get-Prop $locationInfo 'Zones' @())
            if ($zones.Count -gt 1) {
                Add-Check -Category 'Capacity' -Check 'Availability zones' -Status 'PASS' `
                    -Detail "Zones available for this SKU: $($zones -join ', ')."
            } else {
                Add-Check -Category 'Capacity' -Check 'Availability zones' -Status 'WARN' `
                    -Detail "This SKU exposes no availability zones in '$Location'." `
                    -Recommendation 'Use an availability set, or a zone-capable SKU/region, if zonal resilience is required.'
            }

            # Trusted launch and Gen2 support gate the image you can use.
            $generations = $capabilities | Where-Object { (Get-Prop $_ 'Name' '') -eq 'HyperVGenerations' } | Select-Object -First 1
            if ($null -ne $generations) {
                Add-Check -Category 'Capacity' -Check 'Hyper-V generation' -Status 'INFO' `
                    -Detail "SKU supports generation(s): $(Get-Prop $generations 'Value' 'unknown')." `
                    -Recommendation 'Session host images must match a supported generation. Trusted launch and Windows 11 require Gen2.'
            }
        }

        Invoke-Check -Category 'Capacity' -Check 'vCPU quota' -Body {
            if ($SessionHostCount -le 0) {
                Add-Check -Category 'Capacity' -Check 'vCPU quota' -Status 'SKIP' `
                    -Detail 'No -SessionHostCount supplied.' `
                    -Recommendation 'Supply the planned session host count to validate quota headroom.'
                return
            }
            if ($script:PlannedVcpuPerHost -le 0) {
                Add-Check -Category 'Capacity' -Check 'vCPU quota' -Status 'SKIP' `
                    -Detail 'Could not determine vCPUs per host from the SKU catalog.'
                return
            }

            $requiredVcpus = $SessionHostCount * $script:PlannedVcpuPerHost
            $usages = @(Get-AzVMUsage -Location $Location -ErrorAction Stop)

            # Regional family quota -- the one that most often blocks an AVD rollout.
            $familyUsage = $usages | Where-Object {
                (Get-Prop (Get-Prop $_ 'Name') 'Value' '') -eq $script:PlannedVmFamily
            } | Select-Object -First 1

            if ($null -eq $familyUsage) {
                Add-Check -Category 'Capacity' -Check 'vCPU quota (family)' -Status 'WARN' `
                    -Detail "No quota entry found for family '$script:PlannedVmFamily' in '$Location'." `
                    -Recommendation 'Verify the family quota in the portal under Subscription > Usage + quotas.'
            } else {
                $limit     = [int](Get-Prop $familyUsage 'Limit' 0)
                $current   = [int](Get-Prop $familyUsage 'CurrentValue' 0)
                $available = $limit - $current
                if ($available -ge $requiredVcpus) {
                    Add-Check -Category 'Capacity' -Check 'vCPU quota (family)' -Status 'PASS' `
                        -Detail "$script:PlannedVmFamily : $available of $limit vCPUs free, $requiredVcpus required."
                } else {
                    Add-Check -Category 'Capacity' -Check 'vCPU quota (family)' -Status 'FAIL' `
                        -Detail "$script:PlannedVmFamily : only $available of $limit vCPUs free, $requiredVcpus required for $SessionHostCount host(s)." `
                        -Recommendation "Request a quota increase of at least $($requiredVcpus - $available) vCPUs for $script:PlannedVmFamily in $Location."
                }
            }

            # Total regional vCPU ceiling applies on top of the family quota.
            $regionalUsage = $usages | Where-Object {
                (Get-Prop (Get-Prop $_ 'Name') 'Value' '') -eq 'cores'
            } | Select-Object -First 1
            if ($null -ne $regionalUsage) {
                $limit     = [int](Get-Prop $regionalUsage 'Limit' 0)
                $current   = [int](Get-Prop $regionalUsage 'CurrentValue' 0)
                $available = $limit - $current
                if ($available -ge $requiredVcpus) {
                    Add-Check -Category 'Capacity' -Check 'vCPU quota (regional)' -Status 'PASS' `
                        -Detail "Total regional vCPUs: $available of $limit free, $requiredVcpus required."
                } else {
                    Add-Check -Category 'Capacity' -Check 'vCPU quota (regional)' -Status 'FAIL' `
                        -Detail "Total regional vCPUs: only $available of $limit free, $requiredVcpus required." `
                        -Recommendation "Request an increase to the Total Regional vCPUs quota in $Location."
                }
            }
        }

        Invoke-Check -Category 'Capacity' -Check 'Network quota' -Body {
            if ($SessionHostCount -le 0) {
                Add-Check -Category 'Capacity' -Check 'Network quota' -Status 'SKIP' -Detail 'No -SessionHostCount supplied.'
                return
            }
            $networkUsages = @(Get-AzNetworkUsage -Location $Location -ErrorAction Stop)
            $nicUsage = $networkUsages | Where-Object {
                (Get-Prop (Get-Prop $_ 'Name') 'Value' '') -eq 'NetworkInterfaces'
            } | Select-Object -First 1

            if ($null -eq $nicUsage) {
                Add-Check -Category 'Capacity' -Check 'Network quota' -Status 'INFO' `
                    -Detail 'Network interface quota entry not returned for this region.'
                return
            }
            $limit     = [int](Get-Prop $nicUsage 'Limit' 0)
            $current   = [int](Get-Prop $nicUsage 'CurrentValue' 0)
            $available = $limit - $current
            if ($available -ge $SessionHostCount) {
                Add-Check -Category 'Capacity' -Check 'Network quota' -Status 'PASS' `
                    -Detail "Network interfaces: $available of $limit free, $SessionHostCount required."
            } else {
                Add-Check -Category 'Capacity' -Check 'Network quota' -Status 'FAIL' `
                    -Detail "Network interfaces: only $available of $limit free, $SessionHostCount required." `
                    -Recommendation 'Request a network interface quota increase for this region.'
            }
        }
    }

    # -----------------------------------------
    # Resource group and locks
    # -----------------------------------------
    Write-Section 'Resource Group and Locks'

    if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) {
        Add-Check -Category 'ResourceGroup' -Check 'Target resource group' -Status 'SKIP' `
            -Detail 'No -ResourceGroupName supplied.'
    } else {
        Invoke-Check -Category 'ResourceGroup' -Check 'Target resource group' -Scope $ResourceGroupName -Body {
            $resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
            if ($null -eq $resourceGroup) {
                Add-Check -Category 'ResourceGroup' -Check 'Target resource group' -Status 'INFO' `
                    -Detail "Resource group '$ResourceGroupName' does not exist yet." `
                    -Recommendation 'The deployment must create it, which requires write permission at subscription scope.' `
                    -Scope $ResourceGroupName
            } else {
                Add-Check -Category 'ResourceGroup' -Check 'Target resource group' -Status 'PASS' `
                    -Detail "Resource group '$ResourceGroupName' exists in $(Get-Prop $resourceGroup 'Location' 'unknown')." `
                    -Scope $ResourceGroupName
            }
        }
    }

    Invoke-Check -Category 'ResourceGroup' -Check 'Resource locks' -Scope $script:SubscriptionScope -Body {
        $locks = @(Get-AzResourceLock -ErrorAction SilentlyContinue)
        if ($ResourceGroupName) {
            $locks = @($locks | Where-Object {
                $lockScope = Get-Prop $_ 'ResourceId' ''
                $lockScope -eq $script:SubscriptionScope -or $lockScope -like "*/resourceGroups/$ResourceGroupName*"
            })
        }
        $readOnlyLocks = @($locks | Where-Object { (Get-FirstProp $_ @('Properties.level', 'Level') '') -eq 'ReadOnly' })

        if ($readOnlyLocks.Count -gt 0) {
            $names = @($readOnlyLocks | ForEach-Object { Get-Prop $_ 'Name' 'unnamed' })
            Add-Check -Category 'ResourceGroup' -Check 'Resource locks' -Status 'FAIL' `
                -Detail "ReadOnly lock(s) in scope will block deployment: $($names -join ', ')." `
                -Recommendation 'Remove or temporarily scope out the ReadOnly lock before deploying.'
        } elseif ($locks.Count -gt 0) {
            Add-Check -Category 'ResourceGroup' -Check 'Resource locks' -Status 'INFO' `
                -Detail "$($locks.Count) CanNotDelete lock(s) in scope. These do not block creation."
        } else {
            Add-Check -Category 'ResourceGroup' -Check 'Resource locks' -Status 'PASS' `
                -Detail 'No locks in scope that would block deployment.'
        }
    }

    # -----------------------------------------
    # Azure Policy
    # -----------------------------------------
    Write-Section 'Azure Policy'

    Invoke-Check -Category 'Policy' -Check 'Deny policy exposure' -Scope $script:SubscriptionScope -Body {
        $assignments = @(Get-AzPolicyAssignment -ErrorAction SilentlyContinue)
        if ($assignments.Count -eq 0) {
            Add-Check -Category 'Policy' -Check 'Deny policy exposure' -Status 'PASS' `
                -Detail 'No policy assignments in scope.'
            return
        }

        Add-Check -Category 'Policy' -Check 'Policy assignments' -Status 'INFO' `
            -Detail "$($assignments.Count) policy assignment(s) in scope." `
            -Recommendation 'Deny-effect policies are the most common cause of an AVD deployment failing partway through.'

        # Well-known built-in definitions whose parameters can be compared directly
        # against the requested deployment target.
        $allowedLocationsIds = @(
            'e56962a6-4747-49cd-b67b-bf8b01975c4c',   # Allowed locations
            'e765b5de-1225-4ba3-bd56-1ac6695af988'    # Allowed locations for resource groups
        )
        $allowedSkuId = 'cccc23c7-8427-4f53-ad12-b6a63eb452b3'  # Allowed virtual machine size SKUs

        foreach ($assignment in $assignments) {
            $definitionId = Get-FirstProp $assignment @('PolicyDefinitionId', 'Properties.PolicyDefinitionId') ''
            $displayName  = Get-FirstProp $assignment @('DisplayName', 'Properties.DisplayName') (Get-Prop $assignment 'Name' 'unnamed')
            $parameters   = Get-FirstProp $assignment @('Parameter', 'Parameters', 'Properties.Parameters') $null
            $definitionGuid = Get-ResourceNameFromId -ResourceId $definitionId -FromEnd 1

            if ($allowedLocationsIds -contains $definitionGuid -and -not [string]::IsNullOrWhiteSpace($Location)) {
                $allowed = @(Get-Prop (Get-Prop $parameters 'listOfAllowedLocations') 'value' @())
                if ($allowed.Count -eq 0) { continue }
                if ($allowed -contains $Location) {
                    Add-Check -Category 'Policy' -Check 'Allowed locations policy' -Status 'PASS' `
                        -Detail "'$displayName' permits '$Location'." -Scope $displayName
                } else {
                    Add-Check -Category 'Policy' -Check 'Allowed locations policy' -Status 'FAIL' `
                        -Detail "'$displayName' does not permit '$Location'. Permitted: $($allowed -join ', ')." `
                        -Recommendation 'Deploy into a permitted region or request a policy exemption for the target scope.' `
                        -Scope $displayName
                }
            }

            if ($definitionGuid -eq $allowedSkuId -and -not [string]::IsNullOrWhiteSpace($SessionHostVmSize)) {
                $allowed = @(Get-Prop (Get-Prop $parameters 'listOfAllowedSKUs') 'value' @())
                if ($allowed.Count -eq 0) { continue }
                if ($allowed -contains $SessionHostVmSize) {
                    Add-Check -Category 'Policy' -Check 'Allowed VM SKU policy' -Status 'PASS' `
                        -Detail "'$displayName' permits '$SessionHostVmSize'." -Scope $displayName
                } else {
                    Add-Check -Category 'Policy' -Check 'Allowed VM SKU policy' -Status 'FAIL' `
                        -Detail "'$displayName' does not permit '$SessionHostVmSize'." `
                        -Recommendation "Choose a permitted SKU or request an exemption. Permitted: $($allowed -join ', ')." `
                        -Scope $displayName
                }
            }
        }

        # Generic deny sweep. Resolving every definition is expensive, so cap the number
        # of lookups and report the residual as INFO rather than silently truncating.
        $definitionLookupCap = 60
        $inspected = 0
        $denyAssignments = [System.Collections.Generic.List[string]]::new()
        foreach ($assignment in $assignments) {
            if ($inspected -ge $definitionLookupCap) { break }
            $definitionId = Get-FirstProp $assignment @('PolicyDefinitionId', 'Properties.PolicyDefinitionId') ''
            if ([string]::IsNullOrWhiteSpace($definitionId)) { continue }
            if ($definitionId -notlike '*/policyDefinitions/*') { continue }  # initiatives are not walked
            $inspected++
            try {
                $definition = Get-AzPolicyDefinition -Id $definitionId -ErrorAction Stop
                $rule = Get-FirstProp $definition @('PolicyRule', 'Properties.PolicyRule') $null
                $effect = Get-Prop (Get-Prop $rule 'then') 'effect' ''
                if ("$effect" -match 'deny') {
                    $denyAssignments.Add((Get-FirstProp $assignment @('DisplayName', 'Properties.DisplayName') (Get-Prop $assignment 'Name' 'unnamed')))
                }
            } catch {
                continue
            }
        }

        if ($denyAssignments.Count -gt 0) {
            Add-Check -Category 'Policy' -Check 'Deny policy exposure' -Status 'WARN' `
                -Detail "$($denyAssignments.Count) deny-effect assignment(s): $(($denyAssignments | Select-Object -First 10) -join ', ')." `
                -Recommendation 'Review each against the planned deployment. A deny on public IPs, required tags or disk encryption commonly blocks AVD session host creation.'
        } else {
            Add-Check -Category 'Policy' -Check 'Deny policy exposure' -Status 'PASS' `
                -Detail "No deny-effect policy definitions found in the first $inspected assignment(s) inspected."
        }

        $initiativeCount = @($assignments | Where-Object {
            (Get-FirstProp $_ @('PolicyDefinitionId', 'Properties.PolicyDefinitionId') '') -like '*/policySetDefinitions/*'
        }).Count
        if ($initiativeCount -gt 0) {
            Add-Check -Category 'Policy' -Check 'Policy initiatives' -Status 'INFO' `
                -Detail "$initiativeCount initiative (policy set) assignment(s) were not expanded." `
                -Recommendation 'Initiatives can contain deny effects. Review them in the portal, or run a what-if deployment.'
        }
    }

    # -----------------------------------------
    # Networking
    # -----------------------------------------
    Write-Section 'Networking'

    if ([string]::IsNullOrWhiteSpace($VirtualNetworkName) -or [string]::IsNullOrWhiteSpace($VirtualNetworkResourceGroup)) {
        Add-Check -Category 'Network' -Check 'Virtual network' -Status 'SKIP' `
            -Detail 'Requires -VirtualNetworkName and a resource group.' `
            -Recommendation 'Supply the session host VNet to validate IP capacity, DNS, NSG egress and routing.'
    } else {
        $vnet = $null
        Invoke-Check -Category 'Network' -Check 'Virtual network' -Scope $VirtualNetworkName -Body {
            $vnet = Get-AzVirtualNetwork -Name $VirtualNetworkName -ResourceGroupName $VirtualNetworkResourceGroup -ErrorAction SilentlyContinue
            if ($null -eq $vnet) {
                Add-Check -Category 'Network' -Check 'Virtual network' -Status 'FAIL' `
                    -Detail "VNet '$VirtualNetworkName' not found in resource group '$VirtualNetworkResourceGroup'." `
                    -Recommendation 'Create the VNet first, or correct -VirtualNetworkName / -VirtualNetworkResourceGroup.' `
                    -Scope $VirtualNetworkName
                return
            }
            $addressSpace = @(Get-Prop (Get-Prop $vnet 'AddressSpace') 'AddressPrefixes' @())
            Add-Check -Category 'Network' -Check 'Virtual network' -Status 'PASS' `
                -Detail "VNet '$VirtualNetworkName' found. Address space: $($addressSpace -join ', ')." `
                -Scope $VirtualNetworkName

            $vnetLocation = Get-Prop $vnet 'Location' ''
            if (-not [string]::IsNullOrWhiteSpace($Location) -and $vnetLocation -ne $Location) {
                Add-Check -Category 'Network' -Check 'VNet region' -Status 'FAIL' `
                    -Detail "VNet is in '$vnetLocation' but session hosts are planned for '$Location'." `
                    -Recommendation 'A VM NIC must be in the same region as its VNet. Deploy into the VNet region or peer a VNet in the target region.' `
                    -Scope $VirtualNetworkName
            } elseif (-not [string]::IsNullOrWhiteSpace($Location)) {
                Add-Check -Category 'Network' -Check 'VNet region' -Status 'PASS' `
                    -Detail "VNet region '$vnetLocation' matches the session host region." -Scope $VirtualNetworkName
            }

            # Custom DNS is mandatory for AD DS / Entra Domain Services domain join --
            # Azure-provided DNS cannot resolve the domain's SRV records.
            $dnsServers = @(Get-Prop (Get-Prop $vnet 'DhcpOptions') 'DnsServers' @())
            if ($dnsServers.Count -gt 0) {
                Add-Check -Category 'Network' -Check 'VNet DNS' -Status 'PASS' `
                    -Detail "Custom DNS servers configured: $($dnsServers -join ', ')." -Scope $VirtualNetworkName
            } elseif (-not [string]::IsNullOrWhiteSpace($DomainName)) {
                Add-Check -Category 'Network' -Check 'VNet DNS' -Status 'FAIL' `
                    -Detail "VNet uses Azure-provided DNS but a domain join to '$DomainName' is planned." `
                    -Recommendation 'Point the VNet at domain controllers (or Entra Domain Services / Azure DNS Private Resolver) so session hosts can resolve the domain SRV records.' `
                    -Scope $VirtualNetworkName
            } else {
                Add-Check -Category 'Network' -Check 'VNet DNS' -Status 'INFO' `
                    -Detail 'VNet uses Azure-provided DNS.' `
                    -Recommendation 'Fine for Microsoft Entra joined session hosts. AD DS join requires custom DNS.' `
                    -Scope $VirtualNetworkName
            }

            $peerings = @(Get-Prop $vnet 'VirtualNetworkPeerings' @())
            if ($peerings.Count -gt 0) {
                $peeringSummary = @($peerings | ForEach-Object {
                    "$(Get-Prop $_ 'Name' 'unnamed')=$(Get-Prop $_ 'PeeringState' 'Unknown')"
                })
                $disconnected = @($peerings | Where-Object { (Get-Prop $_ 'PeeringState' '') -ne 'Connected' })
                if ($disconnected.Count -gt 0) {
                    Add-Check -Category 'Network' -Check 'VNet peerings' -Status 'WARN' `
                        -Detail "$($disconnected.Count) peering(s) not in Connected state: $($peeringSummary -join ', ')." `
                        -Recommendation 'A broken peering will break domain controller and file share reachability from the session hosts.' `
                        -Scope $VirtualNetworkName
                } else {
                    Add-Check -Category 'Network' -Check 'VNet peerings' -Status 'PASS' `
                        -Detail "$($peerings.Count) peering(s), all Connected: $($peeringSummary -join ', ')." -Scope $VirtualNetworkName
                }
            } else {
                Add-Check -Category 'Network' -Check 'VNet peerings' -Status 'INFO' `
                    -Detail 'No VNet peerings. Session hosts reach on-premises or hub services only via gateway or public egress.' `
                    -Scope $VirtualNetworkName
            }

            if ([string]::IsNullOrWhiteSpace($SubnetName)) {
                Add-Check -Category 'Network' -Check 'Session host subnet' -Status 'SKIP' `
                    -Detail 'No -SubnetName supplied.' -Scope $VirtualNetworkName
                return
            }

            $subnet = @(Get-Prop $vnet 'Subnets' @()) |
                Where-Object { (Get-Prop $_ 'Name' '') -eq $SubnetName } | Select-Object -First 1
            if ($null -eq $subnet) {
                Add-Check -Category 'Network' -Check 'Session host subnet' -Status 'FAIL' `
                    -Detail "Subnet '$SubnetName' not found in VNet '$VirtualNetworkName'." `
                    -Recommendation 'Create the subnet or correct -SubnetName.' -Scope $VirtualNetworkName
                return
            }

            $subnetScope = "$VirtualNetworkName/$SubnetName"
            $prefixes = @(Get-Prop $subnet 'AddressPrefix' @())
            if ($prefixes.Count -eq 0) { $prefixes = @(Get-Prop $subnet 'AddressPrefixes' @()) }
            $primaryPrefix = ''
            if ($prefixes.Count -gt 0) { $primaryPrefix = "$($prefixes[0])" }

            Add-Check -Category 'Network' -Check 'Session host subnet' -Status 'PASS' `
                -Detail "Subnet '$SubnetName' found. Prefix: $($prefixes -join ', ')." -Scope $subnetScope

            # IP capacity. Azure reserves 5 addresses in every subnet.
            $usableIps = Get-SubnetUsableIpCount -AddressPrefix $primaryPrefix
            $usedIps   = @(Get-Prop $subnet 'IpConfigurations' @()).Count
            if ($null -eq $usableIps) {
                Add-Check -Category 'Network' -Check 'Subnet IP capacity' -Status 'INFO' `
                    -Detail "Could not evaluate capacity for prefix '$primaryPrefix'." -Scope $subnetScope
            } elseif ($SessionHostCount -le 0) {
                Add-Check -Category 'Network' -Check 'Subnet IP capacity' -Status 'INFO' `
                    -Detail "$usableIps usable IP(s), $usedIps currently allocated." `
                    -Recommendation 'Supply -SessionHostCount to validate capacity against the planned deployment.' `
                    -Scope $subnetScope
            } else {
                $freeIps  = $usableIps - $usedIps
                $required = [int][math]::Ceiling($SessionHostCount * (1 + ($IpBufferPercent / 100.0)))
                if ($freeIps -ge $required) {
                    Add-Check -Category 'Network' -Check 'Subnet IP capacity' -Status 'PASS' `
                        -Detail "$freeIps free of $usableIps usable IP(s); $required required ($SessionHostCount hosts + $IpBufferPercent% buffer)." `
                        -Scope $subnetScope
                } else {
                    Add-Check -Category 'Network' -Check 'Subnet IP capacity' -Status 'FAIL' `
                        -Detail "Only $freeIps free of $usableIps usable IP(s); $required required ($SessionHostCount hosts + $IpBufferPercent% buffer)." `
                        -Recommendation 'Enlarge the subnet prefix or add a second session host subnet. Reimaging temporarily doubles IP consumption.' `
                        -Scope $subnetScope
                }
            }

            $delegations = @(Get-Prop $subnet 'Delegations' @())
            if ($delegations.Count -gt 0) {
                $names = @($delegations | ForEach-Object { Get-Prop $_ 'ServiceName' 'unknown' })
                Add-Check -Category 'Network' -Check 'Subnet delegation' -Status 'FAIL' `
                    -Detail "Subnet is delegated to: $($names -join ', ')." `
                    -Recommendation 'A delegated subnet cannot host session host NICs. Use an undelegated subnet.' `
                    -Scope $subnetScope
            } else {
                Add-Check -Category 'Network' -Check 'Subnet delegation' -Status 'PASS' `
                    -Detail 'Subnet has no service delegation.' -Scope $subnetScope
            }

            # Egress. Default outbound access has been retired for new virtual networks,
            # so session hosts need an explicit egress path to reach the AVD control plane.
            $natGateway  = Get-Prop $subnet 'NatGateway'
            $routeTable  = Get-Prop $subnet 'RouteTable'
            $defaultRoute = $null
            if ($null -ne $routeTable) {
                $routeTableName = Get-ResourceNameFromId -ResourceId (Get-Prop $routeTable 'Id' '') -FromEnd 1
                $fullRouteTable = Get-AzRouteTable -ErrorAction SilentlyContinue |
                    Where-Object { (Get-Prop $_ 'Name' '') -eq $routeTableName } | Select-Object -First 1
                if ($null -ne $fullRouteTable) {
                    $defaultRoute = @(Get-Prop $fullRouteTable 'Routes' @()) |
                        Where-Object { (Get-Prop $_ 'AddressPrefix' '') -eq '0.0.0.0/0' } | Select-Object -First 1
                }
            }

            if ($null -ne $natGateway) {
                Add-Check -Category 'Network' -Check 'Outbound connectivity' -Status 'PASS' `
                    -Detail "Subnet has a NAT gateway attached ($(Get-ResourceNameFromId -ResourceId (Get-Prop $natGateway 'Id' '') -FromEnd 1))." `
                    -Scope $subnetScope
            } elseif ($null -ne $defaultRoute) {
                $nextHopType = Get-Prop $defaultRoute 'NextHopType' 'Unknown'
                if ($nextHopType -eq 'None') {
                    Add-Check -Category 'Network' -Check 'Outbound connectivity' -Status 'FAIL' `
                        -Detail "Default route 0.0.0.0/0 has next hop 'None' -- internet egress is black-holed." `
                        -Recommendation 'Session hosts must reach the AVD control plane over 443. Provide a firewall, NVA or NAT gateway egress path.' `
                        -Scope $subnetScope
                } else {
                    $nextHopAddress = Get-Prop $defaultRoute 'NextHopIpAddress' ''
                    $nextHopDetail = "Forced tunneling in effect: 0.0.0.0/0 routes to '$nextHopType'."
                    if (-not [string]::IsNullOrWhiteSpace($nextHopAddress)) {
                        $nextHopDetail = "Forced tunneling in effect: 0.0.0.0/0 routes to '$nextHopType' at $nextHopAddress."
                    }
                    Add-Check -Category 'Network' -Check 'Outbound connectivity' -Status 'WARN' `
                        -Detail $nextHopDetail `
                        -Recommendation 'Confirm the firewall or NVA allows the AVD required FQDNs and the WindowsVirtualDesktop service tag on 443.' `
                        -Scope $subnetScope
                }
            } else {
                Add-Check -Category 'Network' -Check 'Outbound connectivity' -Status 'WARN' `
                    -Detail 'No NAT gateway and no default route on the subnet.' `
                    -Recommendation 'Default outbound access is retired for new virtual networks. Attach a NAT gateway, firewall route or load balancer outbound rule so session hosts can reach the AVD control plane.' `
                    -Scope $subnetScope
            }

            # NSG egress analysis -- a deny-all outbound rule with no AVD allow above it
            # is the classic cause of session hosts never registering.
            $nsgRef = Get-Prop $subnet 'NetworkSecurityGroup'
            if ($null -eq $nsgRef) {
                Add-Check -Category 'Network' -Check 'Subnet NSG' -Status 'WARN' `
                    -Detail 'No NSG associated with the session host subnet.' `
                    -Recommendation 'Deployment will succeed, but an NSG is recommended so session host traffic is explicitly governed.' `
                    -Scope $subnetScope
            } else {
                $nsgName = Get-ResourceNameFromId -ResourceId (Get-Prop $nsgRef 'Id' '') -FromEnd 1
                $nsg = Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue |
                    Where-Object { (Get-Prop $_ 'Name' '') -eq $nsgName } | Select-Object -First 1
                if ($null -eq $nsg) {
                    Add-Check -Category 'Network' -Check 'Subnet NSG' -Status 'INFO' `
                        -Detail "NSG '$nsgName' is associated but could not be read (it may live in another subscription)." `
                        -Scope $subnetScope
                } else {
                    $outboundRules = @(Get-Prop $nsg 'SecurityRules' @()) |
                        Where-Object { (Get-Prop $_ 'Direction' '') -eq 'Outbound' } |
                        Sort-Object { [int](Get-Prop $_ 'Priority' 65000) }

                    $avdDestinations = @('*', 'Internet', 'AzureCloud', 'WindowsVirtualDesktop', "AzureCloud.$Location")
                    $blockingRule = $null
                    foreach ($rule in $outboundRules) {
                        $destinations = @(Get-Prop $rule 'DestinationAddressPrefix' @())
                        $ports        = @(Get-Prop $rule 'DestinationPortRange' @())
                        $coversAvd    = @($destinations | Where-Object { $avdDestinations -contains "$_" }).Count -gt 0
                        $covers443    = @($ports | Where-Object { "$_" -eq '*' -or "$_" -eq '443' -or "$_" -like '*-*' }).Count -gt 0
                        if (-not ($coversAvd -and $covers443)) { continue }
                        if ((Get-Prop $rule 'Access' '') -eq 'Allow') {
                            # An allow at a higher precedence wins; egress is open.
                            $blockingRule = $null
                            break
                        }
                        $blockingRule = $rule
                        break
                    }

                    if ($null -ne $blockingRule) {
                        Add-Check -Category 'Network' -Check 'NSG egress to AVD' -Status 'FAIL' `
                            -Detail "Outbound rule '$(Get-Prop $blockingRule 'Name' 'unnamed')' (priority $(Get-Prop $blockingRule 'Priority' '?')) denies 443 to the AVD control plane before any allow rule." `
                            -Recommendation 'Add a higher-precedence outbound Allow for the WindowsVirtualDesktop service tag on 443 (and AzureFrontDoor.Frontend / Storage as required).' `
                            -Scope "$subnetScope/$nsgName"
                    } else {
                        Add-Check -Category 'Network' -Check 'NSG egress to AVD' -Status 'PASS' `
                            -Detail "NSG '$nsgName' does not block outbound 443 to the AVD control plane." `
                            -Scope "$subnetScope/$nsgName"
                    }
                }
            }
        }
    }

    # -----------------------------------------
    # FSLogix / profile storage
    # -----------------------------------------
    Write-Section 'Profile Storage'

    if ([string]::IsNullOrWhiteSpace($StorageAccountName)) {
        Add-Check -Category 'Storage' -Check 'Profile storage account' -Status 'SKIP' `
            -Detail 'No -StorageAccountName supplied.' `
            -Recommendation 'Supply the FSLogix storage account to validate identity-based auth, TLS, firewall and share capacity.'
    } else {
        Test-ProfileStorage -StorageAccountName $StorageAccountName `
            -StorageResourceGroup $StorageAccountResourceGroup `
            -ShareName $FileShareName `
            -ExpectedHostCount $SessionHostCount
    }

    # -----------------------------------------
    # Session host image
    # -----------------------------------------
    Write-Section 'Session Host Image'

    if ([string]::IsNullOrWhiteSpace($ImageId)) {
        Add-Check -Category 'Image' -Check 'Session host image' -Status 'SKIP' `
            -Detail 'No -ImageId supplied.' `
            -Recommendation 'Supply a Compute Gallery image version or definition resource ID to validate regional replication and generation.'
    } else {
        Invoke-Check -Category 'Image' -Check 'Session host image' -Scope $ImageId -Body {
            if ($ImageId -notlike '/subscriptions/*') {
                Add-Check -Category 'Image' -Check 'Session host image' -Status 'INFO' `
                    -Detail "'$ImageId' is not an ARM resource ID -- treated as a marketplace image reference." `
                    -Recommendation 'Marketplace multi-session images are validated at deployment time. Confirm the offer is available in the target region.' `
                    -Scope $ImageId
                return
            }

            $imageResource = Get-AzResource -ResourceId $ImageId -ErrorAction SilentlyContinue
            if ($null -eq $imageResource) {
                Add-Check -Category 'Image' -Check 'Session host image' -Status 'FAIL' `
                    -Detail "Image resource not found or not readable: $ImageId" `
                    -Recommendation 'Verify the resource ID and that the validator identity has Reader on the gallery.' `
                    -Scope $ImageId
                return
            }

            $resourceType = Get-Prop $imageResource 'ResourceType' ''
            Add-Check -Category 'Image' -Check 'Session host image' -Status 'PASS' `
                -Detail "Found $resourceType '$(Get-Prop $imageResource 'Name' '')'." -Scope $ImageId

            if ($resourceType -like '*galleries/images/versions') {
                # A gallery image version must be replicated into the session host region
                # or the deployment fails at VM creation.
                $segments = $ImageId -split '/'
                $galleryRg      = Get-ResourceNameFromId -ResourceId $ImageId -FromEnd 9
                $galleryName    = Get-ResourceNameFromId -ResourceId $ImageId -FromEnd 5
                $definitionName = Get-ResourceNameFromId -ResourceId $ImageId -FromEnd 3
                $versionName    = Get-ResourceNameFromId -ResourceId $ImageId -FromEnd 1

                $version = Get-AzGalleryImageVersion -ResourceGroupName $galleryRg -GalleryName $galleryName `
                    -GalleryImageDefinitionName $definitionName -Name $versionName -ErrorAction SilentlyContinue
                if ($null -ne $version -and -not [string]::IsNullOrWhiteSpace($Location)) {
                    $publishingProfile = Get-Prop $version 'PublishingProfile'
                    $targetRegions = @(Get-Prop $publishingProfile 'TargetRegions' @())
                    $regionNames = @($targetRegions | ForEach-Object { ((Get-Prop $_ 'Name' '') -replace '\s', '').ToLower() })
                    $normalizedTarget = ($Location -replace '\s', '').ToLower()

                    if ($regionNames -contains $normalizedTarget) {
                        Add-Check -Category 'Image' -Check 'Image replication' -Status 'PASS' `
                            -Detail "Image version is replicated to '$Location'." -Scope $ImageId
                    } else {
                        Add-Check -Category 'Image' -Check 'Image replication' -Status 'FAIL' `
                            -Detail "Image version is not replicated to '$Location'. Replicated regions: $($regionNames -join ', ')." `
                            -Recommendation 'Add the target region to the image version replication list before deploying.' `
                            -Scope $ImageId
                    }

                    $endOfLife = Get-Prop $publishingProfile 'EndOfLifeDate'
                    if ($null -ne $endOfLife -and $endOfLife -is [datetime] -and $endOfLife -lt (Get-Date)) {
                        Add-Check -Category 'Image' -Check 'Image end of life' -Status 'WARN' `
                            -Detail "Image version end-of-life date has passed ($($endOfLife.ToString('yyyy-MM-dd')))." `
                            -Recommendation 'Publish and replicate a newer image version.' -Scope $ImageId
                    }
                }

                $definition = Get-AzGalleryImageDefinition -ResourceGroupName $galleryRg -GalleryName $galleryName `
                    -Name $definitionName -ErrorAction SilentlyContinue
                if ($null -ne $definition) {
                    $generation = Get-Prop $definition 'HyperVGeneration' 'unknown'
                    $osState    = Get-Prop $definition 'OsState' 'unknown'
                    if ("$osState" -match 'Generalized') {
                        Add-Check -Category 'Image' -Check 'Image OS state' -Status 'PASS' `
                            -Detail "Image is Generalized ($generation)." -Scope $ImageId
                    } else {
                        Add-Check -Category 'Image' -Check 'Image OS state' -Status 'FAIL' `
                            -Detail "Image OS state is '$osState'. Session host images must be Generalized." `
                            -Recommendation 'Recapture the image with sysprep /generalize.' -Scope $ImageId
                    }
                }
            }
        }
    }

    # -----------------------------------------
    # Monitoring
    # -----------------------------------------
    Write-Section 'Monitoring'

    if ([string]::IsNullOrWhiteSpace($LogAnalyticsWorkspaceName)) {
        Add-Check -Category 'Monitoring' -Check 'Log Analytics workspace' -Status 'SKIP' `
            -Detail 'No -LogAnalyticsWorkspaceName supplied.' `
            -Recommendation 'AVD Insights requires a Log Analytics workspace. Supply one to validate it exists and is configured.'
    } elseif (-not $script:ModuleAvailable['Az.OperationalInsights']) {
        Add-Check -Category 'Monitoring' -Check 'Log Analytics workspace' -Status 'SKIP' `
            -Detail 'Az.OperationalInsights module is not available.'
    } else {
        Invoke-Check -Category 'Monitoring' -Check 'Log Analytics workspace' -Scope $LogAnalyticsWorkspaceName -Body {
            $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $LogAnalyticsResourceGroup `
                -Name $LogAnalyticsWorkspaceName -ErrorAction SilentlyContinue
            if ($null -eq $workspace) {
                Add-Check -Category 'Monitoring' -Check 'Log Analytics workspace' -Status 'FAIL' `
                    -Detail "Workspace '$LogAnalyticsWorkspaceName' not found in resource group '$LogAnalyticsResourceGroup'." `
                    -Recommendation 'Create the workspace before deploying, or correct the name and resource group.' `
                    -Scope $LogAnalyticsWorkspaceName
                return
            }
            $retention = Get-Prop $workspace 'RetentionInDays' 0
            Add-Check -Category 'Monitoring' -Check 'Log Analytics workspace' -Status 'PASS' `
                -Detail "Workspace found in $(Get-Prop $workspace 'Location' 'unknown'), retention $retention day(s)." `
                -Scope $LogAnalyticsWorkspaceName
            if ([int]$retention -lt 30) {
                Add-Check -Category 'Monitoring' -Check 'Log retention' -Status 'WARN' `
                    -Detail "Retention is $retention day(s)." `
                    -Recommendation 'AVD Insights reporting and connection troubleshooting benefit from at least 30 days.' `
                    -Scope $LogAnalyticsWorkspaceName
            }
        }
    }

    # -----------------------------------------
    # Naming collisions
    # -----------------------------------------
    Write-Section 'Naming'

    Invoke-Check -Category 'Naming' -Check 'AVD name collisions' -Scope $script:SubscriptionScope -Body {
        $requested = @()
        if ($HostPoolName)         { $requested += ,@('Host pool',        $HostPoolName,         { @(Get-AzWvdHostPool -ErrorAction SilentlyContinue) }) }
        if ($WorkspaceName)        { $requested += ,@('Workspace',        $WorkspaceName,        { @(Get-AzWvdWorkspace -ErrorAction SilentlyContinue) }) }
        if ($ApplicationGroupName) { $requested += ,@('Application group', $ApplicationGroupName, { @(Get-AzWvdApplicationGroup -ErrorAction SilentlyContinue) }) }

        if ($requested.Count -eq 0) {
            Add-Check -Category 'Naming' -Check 'AVD name collisions' -Status 'SKIP' `
                -Detail 'No -HostPoolName, -WorkspaceName or -ApplicationGroupName supplied.'
            return
        }

        foreach ($entry in $requested) {
            $kind = $entry[0]
            $name = $entry[1]
            # The outer @() must wrap the whole pipeline: an unwrapped single or empty
            # result is a scalar or $null, and .Count on either throws under StrictMode.
            $existing = @(@(& $entry[2]) | Where-Object { (Get-Prop $_ 'Name' '') -eq $name })
            if ($existing.Count -gt 0) {
                Add-Check -Category 'Naming' -Check "$kind name" -Status 'WARN' `
                    -Detail "$kind '$name' already exists in this subscription." `
                    -Recommendation 'Deploying with this name updates the existing object rather than creating a new one. Confirm that is intended.' `
                    -Scope $name
            } else {
                Add-Check -Category 'Naming' -Check "$kind name" -Status 'PASS' `
                    -Detail "$kind name '$name' is free." -Scope $name
            }
        }
    }

    # -----------------------------------------
    # Endpoint reachability (opt-in)
    # -----------------------------------------
    Write-Section 'Endpoint Reachability'

    if (-not $IncludeNetworkProbe) {
        Add-Check -Category 'Endpoints' -Check 'AVD required endpoints' -Status 'SKIP' `
            -Detail 'Endpoint probing not requested.' `
            -Recommendation 'Re-run with -IncludeNetworkProbe from a VM inside the session host subnet for a meaningful result.'
    } else {
        Test-AvdEndpoints
    }
}

# endregion

# =============================================
# region SHARED CHECKS
# =============================================

function Test-ProfileStorage {
    <#
    .SYNOPSIS
        Validates an Azure Files storage account used for FSLogix profiles or MSIX app
        attach. Shared by both phases; -PostDeployment adds the SMB share RBAC check.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StorageAccountName,
        [string]$StorageResourceGroup,
        [string]$ShareName,
        [int]$ExpectedHostCount = 0,
        [switch]$PostDeployment
    )

    Invoke-Check -Category 'Storage' -Check 'Profile storage account' -Scope $StorageAccountName -Body {
        $storageAccount = $null
        if (-not [string]::IsNullOrWhiteSpace($StorageResourceGroup)) {
            $storageAccount = Get-AzStorageAccount -ResourceGroupName $StorageResourceGroup -Name $StorageAccountName -ErrorAction SilentlyContinue
        }
        if ($null -eq $storageAccount) {
            # Fall back to a subscription-wide lookup when the resource group is unknown.
            $storageAccount = Get-AzStorageAccount -ErrorAction SilentlyContinue |
                Where-Object { (Get-Prop $_ 'StorageAccountName' '') -eq $StorageAccountName } | Select-Object -First 1
        }
        if ($null -eq $storageAccount) {
            Add-Check -Category 'Storage' -Check 'Profile storage account' -Status 'FAIL' `
                -Detail "Storage account '$StorageAccountName' not found or not readable." `
                -Recommendation 'Create the account before deploying, or correct -StorageAccountName / -StorageAccountResourceGroup.' `
                -Scope $StorageAccountName
            return
        }

        $resolvedResourceGroup = Get-Prop $storageAccount 'ResourceGroupName' $StorageResourceGroup
        $kind    = Get-Prop $storageAccount 'Kind' 'unknown'
        $skuName = Get-Prop (Get-Prop $storageAccount 'Sku') 'Name' 'unknown'
        Add-Check -Category 'Storage' -Check 'Profile storage account' -Status 'PASS' `
            -Detail "Found '$StorageAccountName' ($kind / $skuName) in $(Get-Prop $storageAccount 'Location' 'unknown')." `
            -Scope $StorageAccountName

        # FSLogix profile containers are latency sensitive; premium file shares are the
        # documented recommendation for anything beyond a small pilot.
        if ($kind -eq 'FileStorage') {
            Add-Check -Category 'Storage' -Check 'Storage tier' -Status 'PASS' `
                -Detail "Premium file shares (FileStorage / $skuName)." -Scope $StorageAccountName
        } else {
            Add-Check -Category 'Storage' -Check 'Storage tier' -Status 'WARN' `
                -Detail "Account kind is '$kind' ($skuName), not premium FileStorage." `
                -Recommendation 'Standard file shares can throttle FSLogix profile IO at login storms. Premium FileStorage is recommended for production.' `
                -Scope $StorageAccountName
        }

        # Identity-based auth is mandatory -- FSLogix cannot use storage account keys for
        # per-user profile access control.
        $identityAuth = Get-Prop $storageAccount 'AzureFilesIdentityBasedAuth'
        $directoryOption = Get-Prop $identityAuth 'DirectoryServiceOptions' 'None'
        if ("$directoryOption" -in @('AD', 'AADDS', 'AADKERB')) {
            Add-Check -Category 'Storage' -Check 'Identity-based auth' -Status 'PASS' `
                -Detail "Azure Files identity-based authentication is enabled ($directoryOption)." -Scope $StorageAccountName
        } else {
            Add-Check -Category 'Storage' -Check 'Identity-based auth' -Status 'FAIL' `
                -Detail "Azure Files identity-based authentication is '$directoryOption'." `
                -Recommendation 'Enable AD DS, Entra Domain Services or Entra Kerberos authentication. FSLogix profile containers require it for per-user NTFS permissions.' `
                -Scope $StorageAccountName
        }

        $minimumTls = Get-Prop $storageAccount 'MinimumTlsVersion' ''
        if ("$minimumTls" -eq 'TLS1_2' -or "$minimumTls" -eq 'TLS1_3') {
            Add-Check -Category 'Storage' -Check 'Minimum TLS version' -Status 'PASS' `
                -Detail "Minimum TLS version is $minimumTls." -Scope $StorageAccountName
        } else {
            Add-Check -Category 'Storage' -Check 'Minimum TLS version' -Status 'WARN' `
                -Detail "Minimum TLS version is '$minimumTls'." `
                -Recommendation 'Set the minimum TLS version to 1.2 or higher.' -Scope $StorageAccountName
        }

        if ($kind -ne 'FileStorage') {
            $largeFileShares = Get-Prop $storageAccount 'LargeFileSharesState' 'Disabled'
            if ("$largeFileShares" -ne 'Enabled') {
                Add-Check -Category 'Storage' -Check 'Large file shares' -Status 'WARN' `
                    -Detail 'Large file shares are not enabled on this standard account.' `
                    -Recommendation 'Without large file shares a standard share is capped at 5 TiB, which profile growth can exhaust.' `
                    -Scope $StorageAccountName
            } else {
                Add-Check -Category 'Storage' -Check 'Large file shares' -Status 'PASS' `
                    -Detail 'Large file shares are enabled.' -Scope $StorageAccountName
            }
        }

        # Network reachability from the session host subnet.
        $networkRules   = Get-Prop $storageAccount 'NetworkRuleSet'
        $defaultAction  = Get-Prop $networkRules 'DefaultAction' 'Allow'
        $vnetRules      = @(Get-Prop $networkRules 'VirtualNetworkRules' @())
        $privateLinks   = @(Get-Prop $storageAccount 'PrivateEndpointConnections' @())

        if ("$defaultAction" -eq 'Allow') {
            Add-Check -Category 'Storage' -Check 'Storage firewall' -Status 'WARN' `
                -Detail 'Storage firewall default action is Allow (open to all networks).' `
                -Recommendation 'Restrict to the session host subnet via a service endpoint or private endpoint.' `
                -Scope $StorageAccountName
        } else {
            $subnetAllowed = $false
            if (-not [string]::IsNullOrWhiteSpace($SubnetName)) {
                $subnetAllowed = @($vnetRules | Where-Object {
                    (Get-Prop $_ 'VirtualNetworkResourceId' '') -like "*/subnets/$SubnetName"
                }).Count -gt 0
            }
            if ($subnetAllowed) {
                Add-Check -Category 'Storage' -Check 'Storage firewall' -Status 'PASS' `
                    -Detail "Firewall denies by default and explicitly allows subnet '$SubnetName'." -Scope $StorageAccountName
            } elseif ($privateLinks.Count -gt 0) {
                Add-Check -Category 'Storage' -Check 'Storage firewall' -Status 'PASS' `
                    -Detail "Firewall denies by default; $($privateLinks.Count) private endpoint connection(s) provide access." `
                    -Recommendation 'Confirm the privatelink.file.core.windows.net private DNS zone is linked to the session host VNet.' `
                    -Scope $StorageAccountName
            } else {
                Add-Check -Category 'Storage' -Check 'Storage firewall' -Status 'FAIL' `
                    -Detail 'Firewall denies by default, with no matching VNet rule and no private endpoint.' `
                    -Recommendation 'Session hosts will not be able to mount the profile share. Add a service endpoint rule for the session host subnet or a private endpoint.' `
                    -Scope $StorageAccountName
            }
        }

        # File share existence and capacity.
        if ([string]::IsNullOrWhiteSpace($ShareName)) {
            Add-Check -Category 'Storage' -Check 'Profile file share' -Status 'SKIP' `
                -Detail 'No -FileShareName supplied.' -Scope $StorageAccountName
        } else {
            $share = $null
            try {
                # Control-plane read: no storage account key or data-plane access required.
                $share = Get-AzRmStorageShare -ResourceGroupName $resolvedResourceGroup `
                    -StorageAccountName $StorageAccountName -Name $ShareName -ErrorAction Stop
            } catch {
                $share = $null
            }

            if ($null -eq $share) {
                Add-Check -Category 'Storage' -Check 'Profile file share' -Status 'FAIL' `
                    -Detail "File share '$ShareName' not found on '$StorageAccountName'." `
                    -Recommendation 'Create the share before deploying, or correct -FileShareName.' `
                    -Scope "$StorageAccountName/$ShareName"
            } else {
                $quotaGiB = [int](Get-Prop $share 'QuotaGiB' 0)
                Add-Check -Category 'Storage' -Check 'Profile file share' -Status 'PASS' `
                    -Detail "Share '$ShareName' exists with a $quotaGiB GiB quota." -Scope "$StorageAccountName/$ShareName"

                if ($ExpectedHostCount -gt 0 -and $quotaGiB -gt 0) {
                    # A 30 GiB per-user planning figure is a common FSLogix starting point.
                    $estimatedNeed = $ExpectedHostCount * 30
                    if ($quotaGiB -lt $estimatedNeed) {
                        Add-Check -Category 'Storage' -Check 'Share capacity' -Status 'WARN' `
                            -Detail "Share quota is $quotaGiB GiB; a 30 GiB per-profile estimate for $ExpectedHostCount concurrent profile(s) needs about $estimatedNeed GiB." `
                            -Recommendation 'Size the share against your measured profile size and concurrency, not host count alone.' `
                            -Scope "$StorageAccountName/$ShareName"
                    } else {
                        Add-Check -Category 'Storage' -Check 'Share capacity' -Status 'PASS' `
                            -Detail "Share quota $quotaGiB GiB covers the $estimatedNeed GiB planning estimate." `
                            -Scope "$StorageAccountName/$ShareName"
                    }
                }
            }
        }

        # Post-deployment only: without an SMB data-plane role assignment, session hosts
        # mount the share but users cannot read or write their own profile.
        if ($PostDeployment) {
            $storageScope = Get-Prop $storageAccount 'Id' ''
            $smbRoles = @('Storage File Data SMB Share Contributor', 'Storage File Data SMB Share Elevated Contributor', 'Storage File Data SMB Share Reader')
            $assignments = @(Get-AzRoleAssignment -Scope $storageScope -ErrorAction SilentlyContinue |
                Where-Object { $smbRoles -contains (Get-Prop $_ 'RoleDefinitionName' '') })
            if ($assignments.Count -gt 0) {
                $roleSummary = @($assignments | ForEach-Object { Get-Prop $_ 'RoleDefinitionName' '' } | Sort-Object -Unique)
                Add-Check -Category 'Storage' -Check 'SMB share RBAC' -Status 'PASS' `
                    -Detail "$($assignments.Count) SMB data-plane role assignment(s): $($roleSummary -join ', ')." `
                    -Scope $StorageAccountName
            } else {
                Add-Check -Category 'Storage' -Check 'SMB share RBAC' -Status 'FAIL' `
                    -Detail 'No Storage File Data SMB Share role assignments found at the storage account scope.' `
                    -Recommendation 'Assign Storage File Data SMB Share Contributor to the AVD user group and Elevated Contributor to admins, or verify the assignment exists at share scope.' `
                    -Scope $StorageAccountName
            }
        }
    }
}

function Test-AvdEndpoints {
    <#
    .SYNOPSIS
        Outbound TCP reachability probe for the AVD required endpoints.
    .DESCRIPTION
        Opens and immediately closes a socket per endpoint. No payload is sent.
        The result reflects the machine running this script, which is usually not a
        session host, so it is reported as WARN rather than FAIL on failure.
    #>
    $endpoints = @(
        [pscustomobject]@{ Host = 'login.microsoftonline.com';                 Port = 443;  Purpose = 'Microsoft Entra authentication' },
        [pscustomobject]@{ Host = 'rdweb.wvd.microsoft.com';                   Port = 443;  Purpose = 'AVD web client and feed' },
        [pscustomobject]@{ Host = 'rdbroker.wvd.microsoft.com';                Port = 443;  Purpose = 'AVD broker service' },
        [pscustomobject]@{ Host = 'rdgateway.wvd.microsoft.com';               Port = 443;  Purpose = 'AVD gateway' },
        [pscustomobject]@{ Host = 'mrsglobalsteus2prod.blob.core.windows.net'; Port = 443;  Purpose = 'AVD agent and SxS stack updates' },
        [pscustomobject]@{ Host = 'wvdportalstorageblob.blob.core.windows.net'; Port = 443; Purpose = 'AVD portal support' },
        [pscustomobject]@{ Host = 'oneocsp.microsoft.com';                     Port = 443;  Purpose = 'Certificate revocation checks' },
        [pscustomobject]@{ Host = 'azkms.core.windows.net';                    Port = 1688; Purpose = 'Windows activation (KMS)' }
    )

    Add-Check -Category 'Endpoints' -Check 'Probe context' -Status 'INFO' `
        -Detail "Probing from $([System.Net.Dns]::GetHostName()), not from a session host." `
        -Recommendation 'Run this from a VM in the session host subnet for an authoritative result.'

    foreach ($endpoint in $endpoints) {
        $result = Test-TcpEndpoint -ComputerName $endpoint.Host -Port $endpoint.Port
        if ($result.Succeeded) {
            Add-Check -Category 'Endpoints' -Check $endpoint.Host -Status 'PASS' `
                -Detail "$($endpoint.Purpose) -- reachable on $($endpoint.Port)." -Scope $endpoint.Host
        } else {
            Add-Check -Category 'Endpoints' -Check $endpoint.Host -Status 'WARN' `
                -Detail "$($endpoint.Purpose) -- not reachable on $($endpoint.Port). $($result.Message)" `
                -Recommendation 'If this probe ran from the session host subnet, open outbound 443 to the WindowsVirtualDesktop and AzureFrontDoor.Frontend service tags.' `
                -Scope $endpoint.Host
        }
    }

    # Domain controller reachability, when a domain join is planned.
    if (-not [string]::IsNullOrWhiteSpace($DomainName)) {
        $domainResult = Test-TcpEndpoint -ComputerName $DomainName -Port 389
        if ($domainResult.Succeeded) {
            Add-Check -Category 'Endpoints' -Check 'Domain controller LDAP' -Status 'PASS' `
                -Detail "LDAP 389 reachable for '$DomainName'." -Scope $DomainName
        } else {
            Add-Check -Category 'Endpoints' -Check 'Domain controller LDAP' -Status 'WARN' `
                -Detail "LDAP 389 not reachable for '$DomainName'. $($domainResult.Message)" `
                -Recommendation 'Session hosts need LDAP, Kerberos, DNS and SMB to a domain controller to complete a domain join.' `
                -Scope $DomainName
        }
    }
}

# endregion

# =============================================
# region POST-DEPLOYMENT VALIDATION
# =============================================

function Get-ResourceGroupFromId {
    <#
    .SYNOPSIS
        Extracts the resource group from an ARM resource ID. Az.DesktopVirtualization
        list cmdlets do not consistently surface a ResourceGroupName property.
    #>
    param([string]$ResourceId)
    if ([string]::IsNullOrWhiteSpace($ResourceId)) { return '' }
    $segments = $ResourceId -split '/'
    for ($i = 0; $i -lt $segments.Count - 1; $i++) {
        if ($segments[$i] -eq 'resourceGroups') { return $segments[$i + 1] }
    }
    return ''
}

function Invoke-PostDeploymentValidation {
    <#
    .SYNOPSIS
        Validates a deployed AVD environment: host pool configuration, application group
        wiring and RBAC, session host registration and health, supporting VM state,
        profile storage, scaling plans, diagnostics and backup. Entirely read-only.
    #>
    $script:CurrentPhase = 'PostDeployment'
    Write-Host ''
    Write-Log '==================================================='
    Write-Log ' POST-DEPLOYMENT VALIDATION'
    Write-Log '==================================================='

    # Subscription-wide caches so per-host lookups do not become per-host API calls.
    $script:AllVms         = $null
    $script:AllNics        = $null
    $script:AllExtensions  = $null
    $script:ProtectedVmIds = $null

    Write-Section 'Host Pool Discovery'

    $hostPools = @()
    try {
        if (-not [string]::IsNullOrWhiteSpace($HostPoolName)) {
            if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) {
                $hostPools = @(Get-AzWvdHostPool -ErrorAction Stop | Where-Object { (Get-Prop $_ 'Name' '') -eq $HostPoolName })
            } else {
                $hostPools = @(Get-AzWvdHostPool -Name $HostPoolName -ResourceGroupName $ResourceGroupName -ErrorAction Stop)
            }
        } else {
            $hostPools = @(Get-AzWvdHostPool -ErrorAction Stop)
        }
    } catch {
        Add-Check -Category 'HostPool' -Check 'Host pool discovery' -Status 'FAIL' `
            -Detail "Could not enumerate host pools: $($_.Exception.Message)" `
            -Recommendation 'Grant the validator identity Desktop Virtualization Reader on the subscription or resource group.'
        return
    }

    if ($hostPools.Count -eq 0) {
        Add-Check -Category 'HostPool' -Check 'Host pool discovery' -Status 'FAIL' `
            -Detail 'No AVD host pools found in scope.' `
            -Recommendation 'Confirm the deployment completed, that -HostPoolName / -ResourceGroupName are correct, and that the identity holds Desktop Virtualization Reader.'
        return
    }

    Add-Check -Category 'HostPool' -Check 'Host pool discovery' -Status 'PASS' `
        -Detail "$($hostPools.Count) host pool(s) in scope: $((@($hostPools | ForEach-Object { Get-Prop $_ 'Name' '' })) -join ', ')."

    # Workspaces and application groups are fetched once and correlated per host pool.
    $allWorkspaces = @()
    $allAppGroups  = @()
    try { $allWorkspaces = @(Get-AzWvdWorkspace -ErrorAction SilentlyContinue) } catch { $allWorkspaces = @() }
    try { $allAppGroups  = @(Get-AzWvdApplicationGroup -ErrorAction SilentlyContinue) } catch { $allAppGroups = @() }

    foreach ($pool in $hostPools) {
        Test-AvdHostPool -HostPool $pool -AllWorkspaces $allWorkspaces -AllApplicationGroups $allAppGroups
    }

    # -----------------------------------------
    # Profile storage
    # -----------------------------------------
    Write-Section 'Profile Storage'

    if ([string]::IsNullOrWhiteSpace($StorageAccountName)) {
        Add-Check -Category 'Storage' -Check 'Profile storage account' -Status 'SKIP' `
            -Detail 'No -StorageAccountName supplied.' `
            -Recommendation 'Supply the FSLogix storage account to validate identity-based auth, firewall reachability and SMB share RBAC.'
    } else {
        Test-ProfileStorage -StorageAccountName $StorageAccountName `
            -StorageResourceGroup $StorageAccountResourceGroup `
            -ShareName $FileShareName `
            -ExpectedHostCount $SessionHostCount `
            -PostDeployment
    }

    # -----------------------------------------
    # Endpoint reachability (opt-in)
    # -----------------------------------------
    Write-Section 'Endpoint Reachability'

    if (-not $IncludeNetworkProbe) {
        Add-Check -Category 'Endpoints' -Check 'AVD required endpoints' -Status 'SKIP' `
            -Detail 'Endpoint probing not requested.' `
            -Recommendation 'Re-run with -IncludeNetworkProbe from a session host for a meaningful result.'
    } else {
        Test-AvdEndpoints
    }
}

function Test-AvdHostPool {
    <#
    .SYNOPSIS Validates a single host pool and everything hanging off it.
    #>
    param(
        [Parameter(Mandatory = $true)][object]$HostPool,
        [object[]]$AllWorkspaces = @(),
        [object[]]$AllApplicationGroups = @()
    )

    $poolName = Get-Prop $HostPool 'Name' 'unknown'
    $poolId   = Get-Prop $HostPool 'Id' ''
    $poolRg   = Get-ResourceGroupFromId -ResourceId $poolId
    if ([string]::IsNullOrWhiteSpace($poolRg)) { $poolRg = Get-Prop $HostPool 'ResourceGroupName' '' }
    $poolType = "$(Get-Prop $HostPool 'HostPoolType' 'Unknown')"

    Write-Section "Host Pool: $poolName"

    # -----------------------------------------
    # Host pool configuration
    # -----------------------------------------
    Invoke-Check -Category 'HostPool' -Check 'Host pool configuration' -Scope $poolName -Body {
        $loadBalancer = "$(Get-Prop $HostPool 'LoadBalancerType' 'Unknown')"
        Add-Check -Category 'HostPool' -Check 'Host pool type' -Status 'INFO' `
            -Detail "Type '$poolType', load balancing '$loadBalancer', region $(Get-Prop $HostPool 'Location' 'unknown')." -Scope $poolName

        if ($poolType -eq 'Personal' -and $loadBalancer -ne 'Persistent') {
            Add-Check -Category 'HostPool' -Check 'Load balancer type' -Status 'FAIL' `
                -Detail "Personal host pool has load balancer type '$loadBalancer'." `
                -Recommendation 'Personal host pools must use Persistent load balancing so users return to their assigned desktop.' `
                -Scope $poolName
        } else {
            Add-Check -Category 'HostPool' -Check 'Load balancer type' -Status 'PASS' `
                -Detail "Load balancing '$loadBalancer' is valid for a $poolType host pool." -Scope $poolName
        }

        if ($poolType -eq 'Pooled') {
            $maxSessions = [int](Get-Prop $HostPool 'MaxSessionLimit' 0)
            if ($maxSessions -le 0 -or $maxSessions -ge 999999) {
                Add-Check -Category 'HostPool' -Check 'Max session limit' -Status 'WARN' `
                    -Detail "Max session limit is $maxSessions (effectively unlimited)." `
                    -Recommendation 'Set a max session limit sized to the VM SKU so the broker can load balance and so scaling plans work correctly.' `
                    -Scope $poolName
            } else {
                Add-Check -Category 'HostPool' -Check 'Max session limit' -Status 'PASS' `
                    -Detail "Max session limit is $maxSessions per host." -Scope $poolName
            }
        }

        $validationEnvironment = Get-Prop $HostPool 'ValidationEnvironment' $false
        if ("$validationEnvironment" -eq 'True') {
            Add-Check -Category 'HostPool' -Check 'Validation environment' -Status 'WARN' `
                -Detail 'Host pool is flagged as a validation environment.' `
                -Recommendation 'Validation host pools receive AVD service updates first. Clear this flag on production pools.' `
                -Scope $poolName
        } else {
            Add-Check -Category 'HostPool' -Check 'Validation environment' -Status 'PASS' `
                -Detail 'Host pool is not flagged as a validation environment.' -Scope $poolName
        }

        $startVmOnConnect = Get-Prop $HostPool 'StartVMOnConnect' $false
        Add-Check -Category 'HostPool' -Check 'Start VM on connect' -Status 'INFO' `
            -Detail "Start VM on Connect is $startVmOnConnect." `
            -Recommendation 'Required if a scaling plan or cost policy deallocates session hosts outside business hours.' `
            -Scope $poolName

        $customRdp = Get-Prop $HostPool 'CustomRdpProperty' ''
        if ([string]::IsNullOrWhiteSpace($customRdp)) {
            Add-Check -Category 'HostPool' -Check 'RDP properties' -Status 'INFO' `
                -Detail 'No custom RDP properties set; AVD defaults apply.' `
                -Recommendation 'Device redirection, multi-monitor and audio behaviour are usually tuned here.' -Scope $poolName
        } else {
            Add-Check -Category 'HostPool' -Check 'RDP properties' -Status 'PASS' `
                -Detail "Custom RDP properties configured: $customRdp" -Scope $poolName
        }
    }

    # -----------------------------------------
    # Registration token
    # -----------------------------------------
    Invoke-Check -Category 'HostPool' -Check 'Registration token' -Scope $poolName -Body {
        $registration = Get-AzWvdRegistrationInfo -HostPoolName $poolName -ResourceGroupName $poolRg -ErrorAction SilentlyContinue
        $expiry = Get-Prop $registration 'ExpirationTime'

        if ($null -eq $expiry) {
            Add-Check -Category 'HostPool' -Check 'Registration token' -Status 'INFO' `
                -Detail 'No active registration token.' `
                -Recommendation 'Expected for a settled host pool. Generate a token only when adding session hosts.' `
                -Scope $poolName
            return
        }

        $expiryTime = [datetime]$expiry
        $hoursRemaining = [math]::Round(($expiryTime.ToUniversalTime() - (Get-Date).ToUniversalTime()).TotalHours, 1)
        if ($hoursRemaining -le 0) {
            Add-Check -Category 'HostPool' -Check 'Registration token' -Status 'INFO' `
                -Detail "Registration token expired $([math]::Abs($hoursRemaining)) hour(s) ago." `
                -Recommendation 'Harmless for existing hosts. Generate a fresh token before adding session hosts.' `
                -Scope $poolName
        } else {
            Add-Check -Category 'HostPool' -Check 'Registration token' -Status 'WARN' `
                -Detail "Registration token is still valid for $hoursRemaining hour(s) (expires $($expiryTime.ToString('u')))." `
                -Recommendation 'A live token lets anyone who holds it join a host to this pool. Let it expire once provisioning is complete.' `
                -Scope $poolName
        }
    }

    # -----------------------------------------
    # Application group and workspace wiring
    # -----------------------------------------
    Invoke-Check -Category 'AppGroup' -Check 'Application group wiring' -Scope $poolName -Body {
        $poolAppGroups = @($AllApplicationGroups | Where-Object {
            (Get-Prop $_ 'HostPoolArmPath' '') -eq $poolId
        })

        if ($poolAppGroups.Count -eq 0) {
            Add-Check -Category 'AppGroup' -Check 'Application groups' -Status 'FAIL' `
                -Detail "No application groups are linked to host pool '$poolName'." `
                -Recommendation 'Without an application group there is nothing to publish; users will see no resources in their feed.' `
                -Scope $poolName
            return
        }

        Add-Check -Category 'AppGroup' -Check 'Application groups' -Status 'PASS' `
            -Detail "$($poolAppGroups.Count) application group(s) linked: $((@($poolAppGroups | ForEach-Object { Get-Prop $_ 'Name' '' })) -join ', ')." `
            -Scope $poolName

        foreach ($appGroup in $poolAppGroups) {
            $appGroupName = Get-Prop $appGroup 'Name' 'unknown'
            $appGroupId   = Get-Prop $appGroup 'Id' ''
            $appGroupScope = "$poolName/$appGroupName"

            # An application group must be published to a workspace or it never reaches
            # the user's feed, even with correct RBAC.
            $publishingWorkspaces = @($AllWorkspaces | Where-Object {
                @(Get-Prop $_ 'ApplicationGroupReference' @()) -contains $appGroupId
            })

            if ($publishingWorkspaces.Count -eq 0) {
                Add-Check -Category 'AppGroup' -Check 'Workspace publication' -Status 'FAIL' `
                    -Detail "Application group '$appGroupName' is not referenced by any workspace." `
                    -Recommendation 'Register the application group with a workspace so it appears in the user feed.' `
                    -Scope $appGroupScope
            } elseif ($publishingWorkspaces.Count -gt 1) {
                Add-Check -Category 'AppGroup' -Check 'Workspace publication' -Status 'FAIL' `
                    -Detail "Application group '$appGroupName' is referenced by $($publishingWorkspaces.Count) workspaces." `
                    -Recommendation 'An application group may belong to only one workspace. Remove the extra references.' `
                    -Scope $appGroupScope
            } else {
                Add-Check -Category 'AppGroup' -Check 'Workspace publication' -Status 'PASS' `
                    -Detail "Published to workspace '$(Get-Prop $publishingWorkspaces[0] 'Name' 'unknown')'." `
                    -Scope $appGroupScope
            }

            # RBAC: no Desktop Virtualization User assignment means users see nothing.
            $userAssignments = @(Get-AzRoleAssignment -Scope $appGroupId -ErrorAction SilentlyContinue |
                Where-Object { (Get-Prop $_ 'RoleDefinitionName' '') -eq 'Desktop Virtualization User' })

            if ($userAssignments.Count -eq 0) {
                Add-Check -Category 'AppGroup' -Check 'User assignment' -Status 'FAIL' `
                    -Detail "No 'Desktop Virtualization User' role assignment on application group '$appGroupName'." `
                    -Recommendation 'Assign Desktop Virtualization User to the AVD user group at the application group scope, otherwise no one can see or launch the resource.' `
                    -Scope $appGroupScope
            } else {
                $principals = @($userAssignments | ForEach-Object {
                    $displayName = Get-Prop $_ 'DisplayName' ''
                    if ([string]::IsNullOrWhiteSpace($displayName)) { Get-Prop $_ 'ObjectId' 'unknown' } else { $displayName }
                })
                Add-Check -Category 'AppGroup' -Check 'User assignment' -Status 'PASS' `
                    -Detail "$($userAssignments.Count) principal(s) assigned Desktop Virtualization User: $(($principals | Select-Object -First 5) -join ', ')." `
                    -Scope $appGroupScope
            }
        }

        # PreferredAppGroupType steers what the client shows by default.
        $preferredType = "$(Get-Prop $HostPool 'PreferredAppGroupType' '')"
        $appGroupTypes = @($poolAppGroups | ForEach-Object { "$(Get-Prop $_ 'ApplicationGroupType' '')" } | Sort-Object -Unique)
        if (-not [string]::IsNullOrWhiteSpace($preferredType) -and $appGroupTypes.Count -gt 0) {
            $expected = $preferredType
            if ($preferredType -eq 'Desktop')      { $expected = 'Desktop' }
            if ($preferredType -eq 'RailApplications') { $expected = 'RemoteApp' }
            if ($appGroupTypes -contains $expected) {
                Add-Check -Category 'AppGroup' -Check 'Preferred app group type' -Status 'PASS' `
                    -Detail "Preferred type '$preferredType' is backed by a '$expected' application group." -Scope $poolName
            } else {
                Add-Check -Category 'AppGroup' -Check 'Preferred app group type' -Status 'WARN' `
                    -Detail "Preferred type is '$preferredType' but linked application groups are: $($appGroupTypes -join ', ')." `
                    -Recommendation 'Clients follow the preferred type. Align it with the published application groups.' `
                    -Scope $poolName
            }
        }
    }

    # -----------------------------------------
    # Session host registration and health
    # -----------------------------------------
    $sessionHosts = @()
    try {
        $sessionHosts = @(Get-AzWvdSessionHost -HostPoolName $poolName -ResourceGroupName $poolRg -ErrorAction SilentlyContinue)
    } catch {
        $sessionHosts = @()
    }

    Invoke-Check -Category 'SessionHost' -Check 'Session host registration' -Scope $poolName -Body {
        if ($sessionHosts.Count -eq 0) {
            Add-Check -Category 'SessionHost' -Check 'Session host registration' -Status 'FAIL' `
                -Detail "Host pool '$poolName' has no registered session hosts." `
                -Recommendation 'Session hosts register via the AVD agent using a registration token. Check the agent installation and the DSC or extension provisioning state on the VMs.' `
                -Scope $poolName
            return
        }

        if ($SessionHostCount -gt 0) {
            if ($sessionHosts.Count -eq $SessionHostCount) {
                Add-Check -Category 'SessionHost' -Check 'Session host count' -Status 'PASS' `
                    -Detail "$($sessionHosts.Count) session host(s) registered, matching the expected count." -Scope $poolName
            } elseif ($sessionHosts.Count -lt $SessionHostCount) {
                Add-Check -Category 'SessionHost' -Check 'Session host count' -Status 'FAIL' `
                    -Detail "$($sessionHosts.Count) session host(s) registered, $SessionHostCount expected." `
                    -Recommendation 'The missing hosts either failed to deploy or failed to register. Check the VM extension provisioning state and the agent logs on the affected hosts.' `
                    -Scope $poolName
            } else {
                Add-Check -Category 'SessionHost' -Check 'Session host count' -Status 'WARN' `
                    -Detail "$($sessionHosts.Count) session host(s) registered, $SessionHostCount expected." `
                    -Recommendation 'Extra hosts may be orphaned registrations from a previous reimage. Remove stale entries.' `
                    -Scope $poolName
            }
        } else {
            Add-Check -Category 'SessionHost' -Check 'Session host count' -Status 'INFO' `
                -Detail "$($sessionHosts.Count) session host(s) registered." `
                -Recommendation 'Supply -SessionHostCount to validate against the expected count.' -Scope $poolName
        }

        # Availability. Anything other than Available means users cannot be brokered to
        # that host, even when the underlying VM is running.
        $unhealthy = @($sessionHosts | Where-Object { "$(Get-Prop $_ 'Status' '')" -ne 'Available' })
        if ($unhealthy.Count -eq 0) {
            Add-Check -Category 'SessionHost' -Check 'Session host status' -Status 'PASS' `
                -Detail "All $($sessionHosts.Count) session host(s) report Available." -Scope $poolName
        } else {
            $summary = @($unhealthy | ForEach-Object {
                "$(Get-ResourceNameFromId -ResourceId (Get-Prop $_ 'Name' '') -FromEnd 1)=$(Get-Prop $_ 'Status' 'Unknown')"
            })
            Add-Check -Category 'SessionHost' -Check 'Session host status' -Status 'FAIL' `
                -Detail "$($unhealthy.Count) of $($sessionHosts.Count) session host(s) are not Available: $(($summary | Select-Object -First 15) -join ', ')." `
                -Recommendation 'Unavailable / NoHeartbeat usually means the VM is deallocated or the AVD agent cannot reach the broker. UpgradeFailed means the agent update did not complete.' `
                -Scope $poolName
        }

        # Drain mode.
        $draining = @($sessionHosts | Where-Object { "$(Get-Prop $_ 'AllowNewSession' $true)" -eq 'False' })
        if ($draining.Count -eq 0) {
            Add-Check -Category 'SessionHost' -Check 'Drain mode' -Status 'PASS' `
                -Detail 'No session hosts are in drain mode.' -Scope $poolName
        } else {
            $names = @($draining | ForEach-Object { Get-ResourceNameFromId -ResourceId (Get-Prop $_ 'Name' '') -FromEnd 1 })
            Add-Check -Category 'SessionHost' -Check 'Drain mode' -Status 'WARN' `
                -Detail "$($draining.Count) session host(s) have AllowNewSession disabled: $(($names | Select-Object -First 15) -join ', ')." `
                -Recommendation 'Drain mode blocks new connections. Clear it once maintenance is complete, or the pool runs at reduced capacity.' `
                -Scope $poolName
        }

        # Heartbeat freshness.
        $staleHosts = @()
        foreach ($sessionHost in $sessionHosts) {
            $heartbeat = Get-Prop $sessionHost 'LastHeartBeat'
            if ($null -eq $heartbeat) { continue }
            try {
                $age = ((Get-Date).ToUniversalTime() - ([datetime]$heartbeat).ToUniversalTime()).TotalMinutes
                if ($age -gt $MaxHeartbeatAgeMinutes) { $staleHosts += $sessionHost }
            } catch {
                continue
            }
        }
        if ($staleHosts.Count -eq 0) {
            Add-Check -Category 'SessionHost' -Check 'Agent heartbeat' -Status 'PASS' `
                -Detail "All session hosts reported a heartbeat within $MaxHeartbeatAgeMinutes minute(s)." -Scope $poolName
        } else {
            $names = @($staleHosts | ForEach-Object { Get-ResourceNameFromId -ResourceId (Get-Prop $_ 'Name' '') -FromEnd 1 })
            Add-Check -Category 'SessionHost' -Check 'Agent heartbeat' -Status 'WARN' `
                -Detail "$($staleHosts.Count) session host(s) have no heartbeat within $MaxHeartbeatAgeMinutes minute(s): $(($names | Select-Object -First 15) -join ', ')." `
                -Recommendation 'Expected for deallocated hosts. Otherwise the AVD agent has lost contact with the broker.' `
                -Scope $poolName
        }

        # Agent, stack and OS version drift across the pool.
        $agentVersions = @($sessionHosts | ForEach-Object { "$(Get-Prop $_ 'AgentVersion' '')" } | Where-Object { $_ } | Sort-Object -Unique)
        if ($agentVersions.Count -le 1) {
            Add-Check -Category 'SessionHost' -Check 'Agent version consistency' -Status 'PASS' `
                -Detail "All session hosts run AVD agent $($agentVersions -join '')." -Scope $poolName
        } else {
            Add-Check -Category 'SessionHost' -Check 'Agent version consistency' -Status 'WARN' `
                -Detail "$($agentVersions.Count) distinct AVD agent versions in the pool: $($agentVersions -join ', ')." `
                -Recommendation 'Mixed agent versions are normal during a rollout but should converge. Persistent drift points at hosts that cannot reach the agent update storage endpoint.' `
                -Scope $poolName
        }

        $stackVersions = @($sessionHosts | ForEach-Object { "$(Get-Prop $_ 'SxSStackVersion' '')" } | Where-Object { $_ } | Sort-Object -Unique)
        if ($stackVersions.Count -gt 1) {
            Add-Check -Category 'SessionHost' -Check 'SxS stack consistency' -Status 'WARN' `
                -Detail "$($stackVersions.Count) distinct side-by-side stack versions: $($stackVersions -join ', ')." `
                -Recommendation 'Stack version drift can cause inconsistent connection behaviour across hosts.' -Scope $poolName
        } elseif ($stackVersions.Count -eq 1) {
            Add-Check -Category 'SessionHost' -Check 'SxS stack consistency' -Status 'PASS' `
                -Detail "All session hosts run side-by-side stack $($stackVersions -join '')." -Scope $poolName
        }

        $osVersions = @($sessionHosts | ForEach-Object { "$(Get-Prop $_ 'OSVersion' '')" } | Where-Object { $_ } | Sort-Object -Unique)
        if ($osVersions.Count -gt 1) {
            Add-Check -Category 'SessionHost' -Check 'OS version consistency' -Status 'WARN' `
                -Detail "$($osVersions.Count) distinct OS builds in the pool: $($osVersions -join ', ')." `
                -Recommendation 'A pooled host pool should be built from one image version so the user experience is identical on every host.' `
                -Scope $poolName
        } elseif ($osVersions.Count -eq 1) {
            Add-Check -Category 'SessionHost' -Check 'OS version consistency' -Status 'PASS' `
                -Detail "All session hosts run OS build $($osVersions -join '')." -Scope $poolName
        }

        # Agent update state.
        $failedUpdates = @($sessionHosts | Where-Object {
            $state = "$(Get-Prop $_ 'UpdateState' '')"
            $state -and $state -notin @('Succeeded', 'Initial')
        })
        if ($failedUpdates.Count -gt 0) {
            $summary = @($failedUpdates | ForEach-Object {
                "$(Get-ResourceNameFromId -ResourceId (Get-Prop $_ 'Name' '') -FromEnd 1)=$(Get-Prop $_ 'UpdateState' '')"
            })
            Add-Check -Category 'SessionHost' -Check 'Agent update state' -Status 'FAIL' `
                -Detail "$($failedUpdates.Count) session host(s) report a non-successful update state: $(($summary | Select-Object -First 15) -join ', ')." `
                -Recommendation 'Check the AVD agent update logs on the affected hosts and confirm outbound access to the agent update storage endpoint.' `
                -Scope $poolName
        } else {
            Add-Check -Category 'SessionHost' -Check 'Agent update state' -Status 'PASS' `
                -Detail 'No session hosts report a failed agent update.' -Scope $poolName
        }

        # Capacity utilisation against the configured session limit.
        if ($poolType -eq 'Pooled') {
            $maxSessions = [int](Get-Prop $HostPool 'MaxSessionLimit' 0)
            $activeSessions = 0
            foreach ($sessionHost in $sessionHosts) { $activeSessions += [int](Get-Prop $sessionHost 'Session' 0) }
            if ($maxSessions -gt 0 -and $maxSessions -lt 999999) {
                $capacity = $sessionHosts.Count * $maxSessions
                $utilisation = 0
                if ($capacity -gt 0) { $utilisation = [math]::Round(($activeSessions / $capacity) * 100, 1) }
                Add-Check -Category 'SessionHost' -Check 'Pool utilisation' -Status 'INFO' `
                    -Detail "$activeSessions active session(s) against a brokered capacity of $capacity ($utilisation%)." `
                    -Scope $poolName
            }
        }
    }

    # -----------------------------------------
    # Underlying session host VMs
    # -----------------------------------------
    Invoke-Check -Category 'SessionHostVM' -Check 'Session host VM state' -Scope $poolName -Body {
        if ($sessionHosts.Count -eq 0) {
            Add-Check -Category 'SessionHostVM' -Check 'Session host VM state' -Status 'SKIP' `
                -Detail 'No registered session hosts to correlate to VMs.' -Scope $poolName
            return
        }

        if ($null -eq $script:AllVms) {
            $script:AllVms = @(Get-AzVM -Status -ErrorAction SilentlyContinue)
        }

        $matchedVms = @()
        $unmatched  = @()
        foreach ($sessionHost in $sessionHosts) {
            $vmResourceId = "$(Get-Prop $sessionHost 'ResourceId' '')"
            if ([string]::IsNullOrWhiteSpace($vmResourceId)) { $unmatched += $sessionHost; continue }
            $vm = $script:AllVms | Where-Object { (Get-Prop $_ 'Id' '') -eq $vmResourceId } | Select-Object -First 1
            if ($null -eq $vm) { $unmatched += $sessionHost } else { $matchedVms += $vm }
        }

        if ($unmatched.Count -gt 0) {
            Add-Check -Category 'SessionHostVM' -Check 'VM correlation' -Status 'WARN' `
                -Detail "$($unmatched.Count) session host(s) could not be matched to a VM in this subscription." `
                -Recommendation 'Expected when session hosts live in another subscription. Otherwise the registration is orphaned and should be removed.' `
                -Scope $poolName
        }

        if ($matchedVms.Count -eq 0) {
            Add-Check -Category 'SessionHostVM' -Check 'Session host VM state' -Status 'SKIP' `
                -Detail 'No session host VMs resolved in this subscription.' -Scope $poolName
            return
        }

        $stopped = @($matchedVms | Where-Object { "$(Get-Prop $_ 'PowerState' '')" -notlike '*running*' })
        if ($stopped.Count -eq 0) {
            Add-Check -Category 'SessionHostVM' -Check 'VM power state' -Status 'PASS' `
                -Detail "All $($matchedVms.Count) session host VM(s) are running." -Scope $poolName
        } else {
            $names = @($stopped | ForEach-Object { "$(Get-Prop $_ 'Name' '')=$(Get-Prop $_ 'PowerState' 'unknown')" })
            Add-Check -Category 'SessionHostVM' -Check 'VM power state' -Status 'WARN' `
                -Detail "$($stopped.Count) session host VM(s) are not running: $(($names | Select-Object -First 15) -join ', ')." `
                -Recommendation 'Expected if a scaling plan deallocated them. Otherwise capacity is reduced and those hosts will report NoHeartbeat.' `
                -Scope $poolName
        }

        $badProvisioning = @($matchedVms | Where-Object { "$(Get-Prop $_ 'ProvisioningState' '')" -ne 'Succeeded' })
        if ($badProvisioning.Count -gt 0) {
            $names = @($badProvisioning | ForEach-Object { "$(Get-Prop $_ 'Name' '')=$(Get-Prop $_ 'ProvisioningState' '')" })
            Add-Check -Category 'SessionHostVM' -Check 'VM provisioning state' -Status 'FAIL' `
                -Detail "$($badProvisioning.Count) session host VM(s) are not in Succeeded provisioning state: $(($names | Select-Object -First 15) -join ', ')." `
                -Recommendation 'A failed VM never completes agent registration. Redeploy or repair the affected hosts.' `
                -Scope $poolName
        } else {
            Add-Check -Category 'SessionHostVM' -Check 'VM provisioning state' -Status 'PASS' `
                -Detail 'All session host VMs are in Succeeded provisioning state.' -Scope $poolName
        }

        # Zone spread drives the resilience of the pool.
        $zonedVms = @($matchedVms | Where-Object { @(Get-Prop $_ 'Zones' @()).Count -gt 0 })
        if ($zonedVms.Count -eq 0) {
            Add-Check -Category 'SessionHostVM' -Check 'Availability zone spread' -Status 'WARN' `
                -Detail 'No session host VMs are zone-pinned.' `
                -Recommendation 'A zonal outage would take the whole pool offline. Spread session hosts across zones, or use an availability set where zones are unavailable.' `
                -Scope $poolName
        } else {
            $zones = @($zonedVms | ForEach-Object { @(Get-Prop $_ 'Zones' @()) } | ForEach-Object { "$_" } | Sort-Object -Unique)
            if ($zones.Count -le 1) {
                Add-Check -Category 'SessionHostVM' -Check 'Availability zone spread' -Status 'WARN' `
                    -Detail "All zone-pinned session hosts are in a single zone ($($zones -join ', '))." `
                    -Recommendation 'Spread session hosts across at least two zones so a zonal outage does not take the pool offline.' `
                    -Scope $poolName
            } else {
                Add-Check -Category 'SessionHostVM' -Check 'Availability zone spread' -Status 'PASS' `
                    -Detail "Session hosts span $($zones.Count) availability zone(s): $($zones -join ', ')." -Scope $poolName
            }
        }

        # Extension health, read in one call rather than per VM.
        if ($null -eq $script:AllExtensions) {
            $script:AllExtensions = @(Get-AzResource -ResourceType 'Microsoft.Compute/virtualMachines/extensions' -ExpandProperties -ErrorAction SilentlyContinue)
        }
        $vmIds = @($matchedVms | ForEach-Object { "$(Get-Prop $_ 'Id' '')" })
        $poolExtensions = @($script:AllExtensions | Where-Object {
            $extensionId = "$(Get-Prop $_ 'ResourceId' '')"
            $ownerVmId = $extensionId -replace '/extensions/[^/]+$', ''
            $vmIds -contains $ownerVmId
        })

        if ($poolExtensions.Count -eq 0) {
            Add-Check -Category 'SessionHostVM' -Check 'VM extension health' -Status 'INFO' `
                -Detail 'No VM extensions returned for the session host VMs.' `
                -Recommendation 'Agent installation via a custom image or deployment script leaves no extension record; this is not necessarily a problem.' `
                -Scope $poolName
        } else {
            $failedExtensions = @($poolExtensions | Where-Object {
                "$(Get-Prop (Get-Prop $_ 'Properties') 'provisioningState' '')" -notin @('Succeeded', '')
            })
            if ($failedExtensions.Count -eq 0) {
                Add-Check -Category 'SessionHostVM' -Check 'VM extension health' -Status 'PASS' `
                    -Detail "All $($poolExtensions.Count) session host VM extension(s) provisioned successfully." -Scope $poolName
            } else {
                $summary = @($failedExtensions | ForEach-Object {
                    "$(Get-Prop $_ 'Name' 'unnamed')=$(Get-Prop (Get-Prop $_ 'Properties') 'provisioningState' 'unknown')"
                })
                Add-Check -Category 'SessionHostVM' -Check 'VM extension health' -Status 'FAIL' `
                    -Detail "$($failedExtensions.Count) VM extension(s) failed to provision: $(($summary | Select-Object -First 15) -join ', ')." `
                    -Recommendation 'A failed domain join or AVD agent DSC extension is the usual reason a host never registers.' `
                    -Scope $poolName
            }

            # Domain join posture.
            $joinExtensions = @($poolExtensions | Where-Object {
                $type = "$(Get-Prop (Get-Prop $_ 'Properties') 'type' '')"
                $type -in @('JsonADDomainExtension', 'AADLoginForWindows')
            })
            if ($joinExtensions.Count -gt 0) {
                $joinTypes = @($joinExtensions | ForEach-Object { "$(Get-Prop (Get-Prop $_ 'Properties') 'type' '')" } | Sort-Object -Unique)
                Add-Check -Category 'SessionHostVM' -Check 'Domain join method' -Status 'INFO' `
                    -Detail "Join extension(s) present: $($joinTypes -join ', ') across $($joinExtensions.Count) host(s)." `
                    -Scope $poolName
            }

            # Monitoring agent coverage.
            $monitoringExtensions = @($poolExtensions | Where-Object {
                "$(Get-Prop (Get-Prop $_ 'Properties') 'type' '')" -in @('AzureMonitorWindowsAgent', 'MicrosoftMonitoringAgent')
            })
            $hostsWithMonitoring = @($monitoringExtensions | ForEach-Object {
                "$(Get-Prop $_ 'ResourceId' '')" -replace '/extensions/[^/]+$', ''
            } | Sort-Object -Unique).Count

            if ($hostsWithMonitoring -ge $matchedVms.Count) {
                Add-Check -Category 'SessionHostVM' -Check 'Monitoring agent coverage' -Status 'PASS' `
                    -Detail "All $($matchedVms.Count) session host VM(s) carry a monitoring agent extension." -Scope $poolName
            } elseif ($hostsWithMonitoring -eq 0) {
                Add-Check -Category 'SessionHostVM' -Check 'Monitoring agent coverage' -Status 'WARN' `
                    -Detail 'No session host VMs carry the Azure Monitor Agent.' `
                    -Recommendation 'AVD Insights needs the Azure Monitor Agent plus a data collection rule association to report performance and event data.' `
                    -Scope $poolName
            } else {
                Add-Check -Category 'SessionHostVM' -Check 'Monitoring agent coverage' -Status 'WARN' `
                    -Detail "$hostsWithMonitoring of $($matchedVms.Count) session host VM(s) carry a monitoring agent extension." `
                    -Recommendation 'Partial coverage leaves blind spots in AVD Insights. Associate the remaining hosts with the data collection rule.' `
                    -Scope $poolName
            }
        }
    }

    # -----------------------------------------
    # Scaling plan
    # -----------------------------------------
    Invoke-Check -Category 'Scaling' -Check 'Scaling plan' -Scope $poolName -Body {
        $scalingPlans = @(Get-AzWvdScalingPlan -ErrorAction SilentlyContinue)
        $attached = @($scalingPlans | Where-Object {
            @(Get-Prop $_ 'HostPoolReference' @()) | Where-Object { (Get-Prop $_ 'HostPoolArmPath' '') -eq $poolId }
        })

        if ($attached.Count -eq 0) {
            Add-Check -Category 'Scaling' -Check 'Scaling plan' -Status 'WARN' `
                -Detail "No scaling plan is attached to host pool '$poolName'." `
                -Recommendation 'Without autoscale, session hosts run (and bill) continuously. Attach a scaling plan sized to your usage pattern.' `
                -Scope $poolName
            return
        }

        foreach ($plan in $attached) {
            $planName = Get-Prop $plan 'Name' 'unknown'
            $reference = @(Get-Prop $plan 'HostPoolReference' @()) |
                Where-Object { (Get-Prop $_ 'HostPoolArmPath' '') -eq $poolId } | Select-Object -First 1
            $planEnabled = Get-Prop $reference 'ScalingPlanEnabled' $false
            $scheduleCount = @(Get-Prop $plan 'Schedule' @()).Count

            if ("$planEnabled" -eq 'True') {
                Add-Check -Category 'Scaling' -Check 'Scaling plan' -Status 'PASS' `
                    -Detail "Scaling plan '$planName' is attached and enabled ($scheduleCount schedule(s))." -Scope $poolName
            } else {
                Add-Check -Category 'Scaling' -Check 'Scaling plan' -Status 'WARN' `
                    -Detail "Scaling plan '$planName' is attached but disabled for this host pool." `
                    -Recommendation 'Enable the plan on the host pool reference, otherwise no autoscale occurs.' -Scope $poolName
            }

            # Autoscale must be able to start a deallocated host when a user connects.
            if ($scheduleCount -gt 0 -and "$(Get-Prop $HostPool 'StartVMOnConnect' $false)" -ne 'True') {
                Add-Check -Category 'Scaling' -Check 'Start VM on connect' -Status 'WARN' `
                    -Detail "Scaling plan '$planName' is active but Start VM on Connect is disabled on the host pool." `
                    -Recommendation 'Enable Start VM on Connect so users can reach hosts that autoscale has deallocated.' `
                    -Scope $poolName
            }
        }
    }

    # -----------------------------------------
    # Diagnostic settings
    # -----------------------------------------
    Invoke-Check -Category 'Diagnostics' -Check 'Host pool diagnostics' -Scope $poolName -Body {
        if (-not $script:ModuleAvailable['Az.Monitor']) {
            Add-Check -Category 'Diagnostics' -Check 'Host pool diagnostics' -Status 'SKIP' `
                -Detail 'Az.Monitor module is not available.' -Scope $poolName
            return
        }

        $settings = @(Get-AzDiagnosticSetting -ResourceId $poolId -ErrorAction SilentlyContinue)
        if ($settings.Count -eq 0) {
            Add-Check -Category 'Diagnostics' -Check 'Host pool diagnostics' -Status 'FAIL' `
                -Detail "No diagnostic settings on host pool '$poolName'." `
                -Recommendation 'Without diagnostics there is no connection, error or agent health history to troubleshoot from. Send the AVD log categories to a Log Analytics workspace.' `
                -Scope $poolName
            return
        }

        # These categories carry the data AVD Insights and connection troubleshooting rely on.
        $importantCategories = @('Checkpoint', 'Error', 'Management', 'Connection', 'HostRegistration', 'AgentHealthStatus')
        $enabledCategories = @()
        foreach ($setting in $settings) {
            foreach ($logEntry in @(Get-Prop $setting 'Log' @())) {
                $isEnabled = Get-Prop $logEntry 'Enabled' $false
                if ("$isEnabled" -ne 'True') { continue }
                $category = Get-FirstProp $logEntry @('Category', 'CategoryGroup') ''
                if ($category) { $enabledCategories += "$category" }
            }
        }
        $enabledCategories = @($enabledCategories | Sort-Object -Unique)

        # A categoryGroup of allLogs or audit covers the individual categories.
        $coversEverything = @($enabledCategories | Where-Object { $_ -in @('allLogs', 'audit') }).Count -gt 0
        $missing = @($importantCategories | Where-Object { $enabledCategories -notcontains $_ })

        if ($coversEverything -or $missing.Count -eq 0) {
            Add-Check -Category 'Diagnostics' -Check 'Host pool diagnostics' -Status 'PASS' `
                -Detail "$($settings.Count) diagnostic setting(s) covering the AVD log categories." -Scope $poolName
        } else {
            Add-Check -Category 'Diagnostics' -Check 'Host pool diagnostics' -Status 'WARN' `
                -Detail "Diagnostic settings present but these categories are not enabled: $($missing -join ', ')." `
                -Recommendation 'Enable the missing categories so connection failures and agent health are captured.' `
                -Scope $poolName
        }
    }

    # -----------------------------------------
    # Backup coverage (personal host pools)
    # -----------------------------------------
    Invoke-Check -Category 'Resilience' -Check 'Session host backup' -Scope $poolName -Body {
        if ($poolType -ne 'Personal') {
            Add-Check -Category 'Resilience' -Check 'Session host backup' -Status 'INFO' `
                -Detail 'Pooled host pool -- session hosts are stateless and are normally not backed up.' `
                -Recommendation 'Protect user state through FSLogix profile storage backup instead of VM backup.' `
                -Scope $poolName
            return
        }
        if (-not $script:ModuleAvailable['Az.RecoveryServices']) {
            Add-Check -Category 'Resilience' -Check 'Session host backup' -Status 'SKIP' `
                -Detail 'Az.RecoveryServices module is not available.' -Scope $poolName
            return
        }

        if ($null -eq $script:ProtectedVmIds) {
            $script:ProtectedVmIds = @()
            foreach ($vault in @(Get-AzRecoveryServicesVault -ErrorAction SilentlyContinue)) {
                try {
                    $items = @(Get-AzRecoveryServicesBackupItem -VaultId (Get-Prop $vault 'ID' '') `
                        -BackupManagementType AzureVM -WorkloadType AzureVM -ErrorAction Stop)
                    foreach ($item in $items) {
                        $sourceId = "$(Get-Prop $item 'SourceResourceId' '')"
                        if ($sourceId) { $script:ProtectedVmIds += $sourceId }
                    }
                } catch {
                    continue
                }
            }
        }

        $sessionHostVmIds = @($sessionHosts | ForEach-Object { "$(Get-Prop $_ 'ResourceId' '')" } | Where-Object { $_ })
        if ($sessionHostVmIds.Count -eq 0) {
            Add-Check -Category 'Resilience' -Check 'Session host backup' -Status 'SKIP' `
                -Detail 'No session host VM resource IDs to evaluate.' -Scope $poolName
            return
        }

        $protected = @($sessionHostVmIds | Where-Object { $script:ProtectedVmIds -contains $_ })
        if ($protected.Count -eq $sessionHostVmIds.Count) {
            Add-Check -Category 'Resilience' -Check 'Session host backup' -Status 'PASS' `
                -Detail "All $($protected.Count) personal session host VM(s) are protected by Azure Backup." -Scope $poolName
        } elseif ($protected.Count -eq 0) {
            Add-Check -Category 'Resilience' -Check 'Session host backup' -Status 'WARN' `
                -Detail 'No personal session host VMs are protected by Azure Backup.' `
                -Recommendation 'Personal desktops hold user state on the local disk. Protect them, or document the accepted data loss risk.' `
                -Scope $poolName
        } else {
            Add-Check -Category 'Resilience' -Check 'Session host backup' -Status 'WARN' `
                -Detail "$($protected.Count) of $($sessionHostVmIds.Count) personal session host VM(s) are protected by Azure Backup." `
                -Recommendation 'Bring the remaining hosts into the backup policy.' -Scope $poolName
        }
    }

    # -----------------------------------------
    # Live user sessions
    # -----------------------------------------
    Invoke-Check -Category 'Sessions' -Check 'User sessions' -Scope $poolName -Body {
        $userSessions = @(Get-AzWvdUserSession -HostPoolName $poolName -ResourceGroupName $poolRg -ErrorAction SilentlyContinue)
        if ($userSessions.Count -eq 0) {
            Add-Check -Category 'Sessions' -Check 'User sessions' -Status 'INFO' `
                -Detail 'No user sessions currently on this host pool.' `
                -Recommendation 'Connect a pilot user to confirm the end-to-end path before handing the pool over.' `
                -Scope $poolName
            return
        }

        $active       = @($userSessions | Where-Object { "$(Get-Prop $_ 'SessionState' '')" -eq 'Active' })
        $disconnected = @($userSessions | Where-Object { "$(Get-Prop $_ 'SessionState' '')" -eq 'Disconnected' })

        Add-Check -Category 'Sessions' -Check 'User sessions' -Status 'PASS' `
            -Detail "$($userSessions.Count) session(s): $($active.Count) active, $($disconnected.Count) disconnected." `
            -Scope $poolName

        if ($disconnected.Count -gt $active.Count -and $disconnected.Count -gt 5) {
            Add-Check -Category 'Sessions' -Check 'Disconnected sessions' -Status 'WARN' `
                -Detail "$($disconnected.Count) disconnected session(s) outnumber the $($active.Count) active session(s)." `
                -Recommendation 'Disconnected sessions hold host capacity. Configure session time limits so they log off automatically.' `
                -Scope $poolName
        }
    }
}

# endregion

# =============================================
# region DISPATCH
# =============================================

New-Item -ItemType Directory -Path $script:RootDir -Force | Out-Null

if ($Mode -eq 'Preflight' -or $Mode -eq 'Both')      { Invoke-PreflightValidation }
if ($Mode -eq 'PostDeployment' -or $Mode -eq 'Both') { Invoke-PostDeploymentValidation }

# endregion

# =============================================
# region REPORTING
# =============================================

Write-Host ''
Write-Log 'Generating validation report ...'

$results = @($script:Results)
$failCount = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$warnCount = @($results | Where-Object { $_.Status -eq 'WARN' }).Count
$passCount = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
$infoCount = @($results | Where-Object { $_.Status -eq 'INFO' }).Count
$skipCount = @($results | Where-Object { $_.Status -eq 'SKIP' }).Count

# Raw evidence
$csvPath  = Join-Path $script:RootDir 'validation-results.csv'
$jsonPath = Join-Path $script:RootDir 'validation-results.json'
try {
    if ($results.Count -gt 0) { $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force }
} catch {
    Write-Log "CSV export failed: $($_.Exception.Message)" -Level WARN
}
try {
    $resultsJson = $results | ConvertTo-Json -Depth 6 -WarningAction SilentlyContinue
    [System.IO.File]::WriteAllText($jsonPath, $resultsJson, [System.Text.Encoding]::UTF8)
} catch {
    Write-Log "JSON export failed: $($_.Exception.Message)" -Level WARN
}

# Az module versions, so a report can be tied back to the tooling that produced it
try {
    $moduleVersions = @(Get-AzModuleVersions)
    if ($moduleVersions.Count -gt 0) {
        $moduleVersions | Export-Csv -Path (Join-Path $script:RootDir 'az-module-versions.csv') -NoTypeInformation -Encoding UTF8 -Force
    }
} catch {
    Write-Log "Module version export failed: $($_.Exception.Message)" -Level WARN
}

# Markdown report
$report = [System.Collections.Generic.List[string]]::new()
function Add-ReportLine { param([string]$Text = '') $report.Add($Text) }

$identity = Get-Prop (Get-Prop $script:Context 'Account') 'Id' 'unknown'
$tenantId = Get-Prop (Get-Prop $script:Context 'Tenant') 'Id' 'unknown'

Add-ReportLine '# AVD Deployment Validation Report'
Add-ReportLine ''
Add-ReportLine "**Generated:** $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC"
Add-ReportLine "**Mode:** $Mode"
Add-ReportLine "**Subscription:** $($targetSubscription.Name) (``$($targetSubscription.Id)``)"
Add-ReportLine "**Identity:** $identity"
Add-ReportLine "**Tenant:** $tenantId"
if (-not [string]::IsNullOrWhiteSpace($Location)) { Add-ReportLine "**Target region:** $Location" }
Add-ReportLine ''
Add-ReportLine '> This validator is read-only. It inspects configuration through Azure Resource Manager and changes nothing.'
Add-ReportLine '> It is a readiness and health check, not a production-readiness certification or a compliance attestation.'
Add-ReportLine ''
Add-ReportLine '---'
Add-ReportLine ''

Add-ReportLine '## Result Summary'
Add-ReportLine ''
Add-ReportLine '| Status | Count | Meaning |'
Add-ReportLine '|---|---|---|'
Add-ReportLine "| FAIL | $failCount | Will block deployment or is actively broken. |"
Add-ReportLine "| WARN | $warnCount | Works, but carries operational or resilience risk. |"
Add-ReportLine "| PASS | $passCount | Validated as expected. |"
Add-ReportLine "| INFO | $infoCount | Recorded for context; no action implied. |"
Add-ReportLine "| SKIP | $skipCount | Not evaluated -- required input or module missing. |"
Add-ReportLine ''

$verdict = 'READY'
if ($failCount -gt 0)      { $verdict = 'NOT READY' }
elseif ($warnCount -gt 0)  { $verdict = 'READY WITH WARNINGS' }
Add-ReportLine "**Overall: $verdict**"
Add-ReportLine ''

foreach ($severity in @('FAIL', 'WARN')) {
    $items = @($results | Where-Object { $_.Status -eq $severity })
    if ($items.Count -eq 0) { continue }
    $heading = 'Failures'
    if ($severity -eq 'WARN') { $heading = 'Warnings' }
    Add-ReportLine "## $heading"
    Add-ReportLine ''
    Add-ReportLine '| Phase | Category | Check | Detail | Recommendation |'
    Add-ReportLine '|---|---|---|---|---|'
    foreach ($item in $items) {
        $detail = ($item.Detail -replace '\|', '\|')
        $recommendation = ($item.Recommendation -replace '\|', '\|')
        Add-ReportLine "| $($item.Phase) | $($item.Category) | $($item.Check) | $detail | $recommendation |"
    }
    Add-ReportLine ''
}

Add-ReportLine '## All Checks'
Add-ReportLine ''
foreach ($phase in @($results | ForEach-Object { $_.Phase } | Select-Object -Unique)) {
    Add-ReportLine "### $phase"
    Add-ReportLine ''
    $phaseResults = @($results | Where-Object { $_.Phase -eq $phase })
    foreach ($category in @($phaseResults | ForEach-Object { $_.Category } | Select-Object -Unique)) {
        Add-ReportLine "#### $category"
        Add-ReportLine ''
        Add-ReportLine '| Status | Check | Scope | Detail |'
        Add-ReportLine '|---|---|---|---|'
        foreach ($item in @($phaseResults | Where-Object { $_.Category -eq $category })) {
            $detail = ($item.Detail -replace '\|', '\|')
            Add-ReportLine "| $($item.Status) | $($item.Check) | $($item.Scope) | $detail |"
        }
        Add-ReportLine ''
    }
}

Add-ReportLine '## Scope and Limitations'
Add-ReportLine ''
Add-ReportLine '- **ARM-level only.** This validator reads Azure Resource Manager configuration. It does not inspect OS-level state, Group Policy, FSLogix registry configuration, Intune policy, or Microsoft Entra conditional access.'
Add-ReportLine '- **Effective network state is not evaluated.** NSG effective rules, firewall and NVA rule sets, and DNS resolution behaviour need separate validation from inside the session host subnet.'
Add-ReportLine '- **Endpoint probes reflect the machine running this script**, not a session host, unless the script was run on one.'
Add-ReportLine '- **Policy initiatives are not expanded.** Deny effects inside an assigned initiative are reported as unexpanded, not evaluated.'
Add-ReportLine '- **Quota reflects the moment of the run.** Another deployment can consume the headroom reported here.'
Add-ReportLine '- **Single subscription per run.** Deployments spanning subscriptions need one run per subscription.'
Add-ReportLine '- **Read-only.** No Azure resource is created, modified or deleted.'
Add-ReportLine ''
Add-ReportLine '---'
Add-ReportLine '*Generated by AVD Deployment Validator*'

# UTF-8 without a BOM: a BOM shows up as a stray character in the first Markdown heading.
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

$reportPath = Join-Path $script:RootDir 'validation-report.md'
[System.IO.File]::WriteAllLines($reportPath, $report.ToArray(), $utf8NoBom)

# Run log
$logPath = Join-Path $script:RootDir 'run-log.txt'
[System.IO.File]::WriteAllLines($logPath, $script:LogMessages.ToArray(), $utf8NoBom)

# Manifest -- records the inputs so a report can be reproduced or compared over time
$manifest = [pscustomobject]@{
    PackageName    = $script:PackageName
    GeneratedUtc   = (Get-Date).ToUniversalTime().ToString('o')
    Mode           = $Mode
    Identity       = $identity
    TenantId       = $tenantId
    SubscriptionId   = $targetSubscription.Id
    SubscriptionName = $targetSubscription.Name
    Verdict        = $verdict
    Counts         = [pscustomobject]@{ Fail = $failCount; Warn = $warnCount; Pass = $passCount; Info = $infoCount; Skip = $skipCount }
    Inputs         = [pscustomobject]@{
        Location                  = $Location
        MetadataLocation          = $MetadataLocation
        ResourceGroupName         = $ResourceGroupName
        VirtualNetworkName        = $VirtualNetworkName
        SubnetName                = $SubnetName
        SessionHostCount          = $SessionHostCount
        SessionHostVmSize         = $SessionHostVmSize
        HostPoolName              = $HostPoolName
        WorkspaceName             = $WorkspaceName
        ApplicationGroupName      = $ApplicationGroupName
        StorageAccountName        = $StorageAccountName
        FileShareName             = $FileShareName
        LogAnalyticsWorkspaceName = $LogAnalyticsWorkspaceName
        ImageId                   = $ImageId
        DomainName                = $DomainName
        MaxHeartbeatAgeMinutes    = $MaxHeartbeatAgeMinutes
        IpBufferPercent           = $IpBufferPercent
        NetworkProbeRequested     = [bool]$IncludeNetworkProbe
    }
}
try {
    $manifestJson = $manifest | ConvertTo-Json -Depth 6 -WarningAction SilentlyContinue
    [System.IO.File]::WriteAllText((Join-Path $script:RootDir 'manifest.json'), $manifestJson, [System.Text.Encoding]::UTF8)
} catch {
    Write-Log "Manifest export failed: $($_.Exception.Message)" -Level WARN
}

# ZIP
$zipPath = ''
if (-not $SkipZip) {
    $zipPath = Join-Path $OutputPath "$script:PackageName.zip"
    try {
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
        Compress-Archive -Path $script:RootDir -DestinationPath $zipPath -Force
    } catch {
        Write-Log "ZIP creation failed: $($_.Exception.Message)" -Level WARN
        $zipPath = ''
    }
}

# endregion

# =============================================
# region Final Output
# =============================================

Write-Host ''
Write-Log '==================================================='
Write-Log " Validation Complete -- $verdict"
Write-Log '==================================================='
Write-Log "FAIL $failCount | WARN $warnCount | PASS $passCount | INFO $infoCount | SKIP $skipCount"
Write-Log "Report folder : $script:RootDir"
Write-Log "Report        : $reportPath"
if ($zipPath) { Write-Log "ZIP archive   : $zipPath" }
Write-Log '==================================================='

if ($PassThru) { $results }

$exitCode = 0
if ($failCount -gt 0) { $exitCode = 1 }
elseif ($FailOnWarning -and $warnCount -gt 0) { $exitCode = 1 }
exit $exitCode

# endregion
