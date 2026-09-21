<#
.SYNOPSIS
    AVD Current State Collector — inventories Azure Commercial environments from an
    Azure Virtual Desktop perspective and produces a portable evidence package.

.DESCRIPTION
    Discovers all enabled Azure subscriptions (or a filtered subset), validates read
    access, and collects AVD workload resources plus supporting platform infrastructure.
    Outputs per-subscription CSV/JSON evidence, a stakeholder-ready summary, a manifest,
    and a final ZIP archive.

    This is a current-state inventory tool. It is NOT a production-readiness certification,
    compliance attestation, or target-state gap analysis.

.PARAMETER SubscriptionNames
    Optional. One or more subscription display names to limit scope. When omitted the
    collector inventories every enabled subscription visible to the authenticated identity.

.PARAMETER OutputPath
    Optional. Parent directory for the evidence package. Defaults to the current directory.

.EXAMPLE
    .\avd_current_state_collector.ps1

.EXAMPLE
    .\avd_current_state_collector.ps1 -SubscriptionNames "Sub-A","Sub-B"

.EXAMPLE
    .\avd_current_state_collector.ps1 -OutputPath "C:\Evidence"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionNames,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────
# region Cloud Shell Detection
# ─────────────────────────────────────────────
$script:IsCloudShell = $false
if ($env:AZUREPS_HOST_ENVIRONMENT -like 'cloud-shell*' -or $env:ACC_CLOUD -eq 'true') {
    $script:IsCloudShell = $true
    # Default output to ~/clouddrive for session persistence unless caller overrode it
    $callerOverrodeOutput = $PSBoundParameters.ContainsKey('OutputPath')
    if (-not $callerOverrodeOutput) {
        $cloudDrive = Join-Path $HOME 'clouddrive'
        if (Test-Path $cloudDrive) {
            $OutputPath = $cloudDrive
        }
    }
}
# endregion

# ─────────────────────────────────────────────
# region Constants
# ─────────────────────────────────────────────
$script:Timestamp       = Get-Date -Format 'yyyyMMddTHHmmss'
$script:PackageName     = "avd-current-state-$script:Timestamp"
$script:RootDir         = Join-Path $OutputPath $script:PackageName
$script:LogMessages     = [System.Collections.Generic.List[string]]::new()
$script:Warnings        = [System.Collections.Generic.List[string]]::new()
$script:SubscriptionResults = [System.Collections.Generic.List[psobject]]::new()
# endregion

# ─────────────────────────────────────────────
# region Helper Functions
# ─────────────────────────────────────────────

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO')
    $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $script:LogMessages.Add($entry)
    if ($Level -eq 'WARN')  { $script:Warnings.Add($Message); Write-Warning $Message }
    elseif ($Level -eq 'ERROR') { Write-Host $entry -ForegroundColor Red }
    else { Write-Host $entry }
}

function Safe-Export-Csv {
    param([string]$Path, [object[]]$Data, [string]$DatasetName)
    try {
        if ($null -eq $Data -or $Data.Count -eq 0) {
            Write-Log "No data for $DatasetName — skipping CSV export." -Level INFO
            return 0
        }
        $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Force
        return $Data.Count
    } catch {
        Write-Log "CSV export failed for ${DatasetName}: $($_.Exception.Message)" -Level WARN
        return 0
    }
}

function Safe-Export-Json {
    param([string]$Path, [object]$Data, [string]$DatasetName)
    try {
        if ($null -eq $Data) {
            Write-Log "No data for $DatasetName — skipping JSON export." -Level INFO
            return
        }
        $json = $Data | ConvertTo-Json -Depth 10 -WarningAction SilentlyContinue
        [System.IO.File]::WriteAllText($Path, $json, [System.Text.Encoding]::UTF8)
    } catch {
        Write-Log "JSON export failed for ${DatasetName}: $($_.Exception.Message)" -Level WARN
    }
}

function Export-Dataset {
    <#
    .SYNOPSIS Exports a dataset as both CSV and JSON under the given subscription folder.
    #>
    param(
        [string]$SubDir,
        [string]$Name,
        [object[]]$Data
    )
    $count = 0
    $csvPath  = Join-Path $SubDir "$Name.csv"
    $jsonPath = Join-Path $SubDir "$Name.json"
    $count = Safe-Export-Csv -Path $csvPath -Data $Data -DatasetName $Name
    Safe-Export-Json -Path $jsonPath -Data $Data -DatasetName $Name
    return $count
}

function Test-SubscriptionAccess {
    <#
    .SYNOPSIS Lightweight read-access validation against a subscription.
    #>
    param([string]$SubscriptionId)
    try {
        $null = Get-AzResourceGroup -ErrorAction Stop | Select-Object -First 1
        return $true
    } catch {
        return $false
    }
}

function Safe-Collect {
    <#
    .SYNOPSIS Wraps a script block in error handling so one dataset failure doesn't kill the run.
    #>
    param(
        [string]$DatasetName,
        [scriptblock]$Collector
    )
    try {
        Write-Log "  Collecting $DatasetName ..."
        $result = & $Collector
        if ($null -eq $result) { $result = @() }
        if ($result -isnot [System.Array]) { $result = @($result) }
        Write-Log "  $DatasetName — $($result.Count) item(s)."
        return $result
    } catch {
        Write-Log "  $DatasetName collection failed: $($_.Exception.Message)" -Level WARN
        return @()
    }
}

function Ensure-Module {
    param([string]$ModuleName)
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Log "Module $ModuleName not found — installing from PSGallery ..."
        Install-Module -Name $ModuleName -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
    }
    Import-Module $ModuleName -ErrorAction Stop
}

function Get-AzModuleVersions {
    $modules = Get-Module -Name Az.* -ListAvailable |
        Sort-Object Name -Unique |
        Select-Object Name, Version, @{N='VersionString';E={$_.Version.ToString()}}
    return $modules
}

function Sanitize-FolderName {
    param([string]$Name)
    $Name -replace '[^\w\-\.\s]', '_' -replace '\s+', '_'
}

function Get-PropValue {
    <#
    .SYNOPSIS
        StrictMode-safe property read that tolerates Az output shape changes.
    .DESCRIPTION
        Az.Resources v8 flattened Get-AzPolicyAssignment output, moving Properties.X
        up to X. Under Set-StrictMode -Version Latest a missing property throws rather
        than returning null, so a bare $_.Properties.DisplayName kills the whole dataset
        via Safe-Collect. Paths are tried in order and the first that resolves wins,
        so one expression works across Az versions.
    #>
    param([object]$InputObject, [string[]]$Paths, $Default = $null)
    foreach ($path in $Paths) {
        $current = $InputObject
        $resolved = $true
        foreach ($segment in ($path -split '\.')) {
            if ($null -eq $current) { $resolved = $false; break }
            $prop = $current.PSObject.Properties[$segment]
            if ($null -eq $prop -or $null -eq $prop.Value) { $resolved = $false; break }
            $current = $prop.Value
        }
        if ($resolved) { return $current }
    }
    return $Default
}

# endregion

# ─────────────────────────────────────────────
# region Module Bootstrap
# ─────────────────────────────────────────────

Write-Log '═══════════════════════════════════════════════════'
Write-Log ' AVD Current State Collector'
Write-Log '═══════════════════════════════════════════════════'
Write-Log "Run timestamp : $script:Timestamp"
Write-Log "Output target : $script:RootDir"
if ($script:IsCloudShell) {
    Write-Log "Environment   : Azure Cloud Shell detected — output defaults to ~/clouddrive for persistence."
}

$requiredModules = @(
    'Az.Accounts',
    'Az.Resources',
    'Az.Compute',
    'Az.Network',
    'Az.Storage',
    'Az.KeyVault',
    'Az.OperationalInsights',
    'Az.RecoveryServices',
    'Az.DesktopVirtualization'
)

foreach ($mod in $requiredModules) {
    Ensure-Module -ModuleName $mod
}

Write-Log "Az modules loaded."

# endregion

# ─────────────────────────────────────────────
# region Authentication
# ─────────────────────────────────────────────

$context = Get-AzContext -ErrorAction SilentlyContinue
if (-not $context) {
    Write-Log 'No active Azure context — launching interactive login (AzureCloud) ...'
    try {
        Connect-AzAccount -Environment AzureCloud -ErrorAction Stop | Out-Null
        $context = Get-AzContext
    } catch {
        Write-Log "Authentication failed: $($_.Exception.Message)" -Level ERROR
        throw 'Unable to authenticate to Azure Commercial. Exiting.'
    }
}
Write-Log "Authenticated as $($context.Account.Id) in tenant $($context.Tenant.Id)."

# endregion

# ─────────────────────────────────────────────
# region Subscription Discovery
# ─────────────────────────────────────────────

Write-Log 'Discovering subscriptions ...'
$allSubs = Get-AzSubscription -ErrorAction Stop |
    Where-Object { $_.State -eq 'Enabled' } |
    Sort-Object Name

if ($allSubs.Count -eq 0) {
    Write-Log 'No enabled subscriptions visible to this identity.' -Level ERROR
    throw 'No enabled subscriptions found.'
}

Write-Log "Found $($allSubs.Count) enabled subscription(s)."

if ($SubscriptionNames -and $SubscriptionNames.Count -gt 0) {
    $filtered = $allSubs | Where-Object { $SubscriptionNames -contains $_.Name }
    $missing  = $SubscriptionNames | Where-Object { $_ -notin $allSubs.Name }
    if ($missing) {
        foreach ($m in $missing) {
            Write-Log "Requested subscription '$m' not found or not enabled." -Level WARN
        }
    }
    if ($filtered.Count -eq 0) {
        Write-Log 'None of the requested subscriptions are accessible.' -Level ERROR
        throw 'No matching subscriptions. Exiting.'
    }
    $targetSubs = $filtered
    Write-Log "Filtered to $($targetSubs.Count) subscription(s) by name."
} else {
    $targetSubs = $allSubs
    Write-Log "Targeting all $($targetSubs.Count) enabled subscription(s)."
}

# endregion

# ─────────────────────────────────────────────
# region Create Output Structure
# ─────────────────────────────────────────────

New-Item -ItemType Directory -Path $script:RootDir -Force | Out-Null

# Record module versions
$moduleVersions = Get-AzModuleVersions
$mvPath = Join-Path $script:RootDir 'az-module-versions'
Safe-Export-Csv  -Path "$mvPath.csv"  -Data $moduleVersions -DatasetName 'AzModuleVersions'
Safe-Export-Json -Path "$mvPath.json" -Data $moduleVersions -DatasetName 'AzModuleVersions'
Write-Log "Recorded Az module versions."

# endregion

# ─────────────────────────────────────────────
# region Per-Subscription Collection
# ─────────────────────────────────────────────

$grandTotals = @{}

foreach ($sub in $targetSubs) {
    $subName = $sub.Name
    $subId   = $sub.Id
    Write-Log "───────────────────────────────────────────────"
    Write-Log "Subscription: $subName ($subId)"

    # Switch context
    try {
        Set-AzContext -SubscriptionId $subId -ErrorAction Stop | Out-Null
    } catch {
        Write-Log "Cannot set context for '$subName': $($_.Exception.Message)" -Level WARN
        $script:SubscriptionResults.Add([pscustomobject]@{
            SubscriptionName = $subName; SubscriptionId = $subId
            Status = 'ContextFailed'; Reason = $_.Exception.Message
        })
        continue
    }

    # Access validation
    if (-not (Test-SubscriptionAccess -SubscriptionId $subId)) {
        Write-Log "Read access validation failed for '$subName' — skipping." -Level WARN
        $script:SubscriptionResults.Add([pscustomobject]@{
            SubscriptionName = $subName; SubscriptionId = $subId
            Status = 'AccessDenied'; Reason = 'Lightweight read validation failed.'
        })
        continue
    }

    Write-Log "  Access validated."
    $folderName = Sanitize-FolderName -Name $subName
    $subDir = Join-Path $script:RootDir $folderName
    New-Item -ItemType Directory -Path $subDir -Force | Out-Null

    # Store counts for this subscription
    $subCounts = @{}

    # ── Core Resources ──
    $resourceGroups = Safe-Collect 'ResourceGroups' {
        Get-AzResourceGroup | Select-Object ResourceGroupName, Location, ProvisioningState,
            @{N='Tags';E={ ($_.Tags | ConvertTo-Json -Compress -WarningAction SilentlyContinue) }}
    }
    $subCounts['ResourceGroups'] = (Export-Dataset -SubDir $subDir -Name 'resource-groups' -Data $resourceGroups)

    $armResources = Safe-Collect 'ARMResources' {
        Get-AzResource | Select-Object Name, ResourceGroupName, ResourceType, Location, ResourceId,
            @{N='Tags';E={ ($_.Tags | ConvertTo-Json -Compress -WarningAction SilentlyContinue) }}
    }
    $subCounts['ARMResources'] = (Export-Dataset -SubDir $subDir -Name 'arm-resources' -Data $armResources)

    # ── Networking ──
    $vnets = Safe-Collect 'VirtualNetworks' {
        Get-AzVirtualNetwork | Select-Object Name, ResourceGroupName, Location,
            @{N='AddressSpace';E={ ($_.AddressSpace.AddressPrefixes -join ', ') }},
            @{N='DnsServers';E={ ($_.DhcpOptions.DnsServers -join ', ') }},
            @{N='SubnetCount';E={ $_.Subnets.Count }},
            @{N='EnableDdosProtection';E={ $_.EnableDdosProtection }},
            Id
    }
    $subCounts['VirtualNetworks'] = (Export-Dataset -SubDir $subDir -Name 'virtual-networks' -Data $vnets)

    $subnets = Safe-Collect 'Subnets' {
        Get-AzVirtualNetwork | ForEach-Object {
            $vnetName = $_.Name
            $_.Subnets | Select-Object Name,
                @{N='VNetName';E={ $vnetName }},
                @{N='AddressPrefix';E={ ($_.AddressPrefix -join ', ') }},
                @{N='NSG';E={ if ($_.NetworkSecurityGroup) { ($_.NetworkSecurityGroup.Id -split '/')[-1] } else { '' } }},
                @{N='RouteTable';E={ if ($_.RouteTable) { ($_.RouteTable.Id -split '/')[-1] } else { '' } }},
                @{N='ServiceEndpoints';E={ ($_.ServiceEndpoints.Service -join ', ') }},
                @{N='Delegations';E={ ($_.Delegations.ServiceName -join ', ') }},
                @{N='PrivateEndpointNetworkPolicies';E={ $_.PrivateEndpointNetworkPolicies }},
                Id
        }
    }
    $subCounts['Subnets'] = (Export-Dataset -SubDir $subDir -Name 'subnets' -Data $subnets)

    $nsgs = Safe-Collect 'NSGs' {
        Get-AzNetworkSecurityGroup | Select-Object Name, ResourceGroupName, Location,
            @{N='SecurityRuleCount';E={ $_.SecurityRules.Count }},
            @{N='DefaultRuleCount';E={ $_.DefaultSecurityRules.Count }},
            Id
    }
    $subCounts['NSGs'] = (Export-Dataset -SubDir $subDir -Name 'nsgs' -Data $nsgs)

    $nsgRules = Safe-Collect 'NSGRules' {
        Get-AzNetworkSecurityGroup | ForEach-Object {
            $nsgName = $_.Name
            $_.SecurityRules | Select-Object Name,
                @{N='NSGName';E={ $nsgName }},
                Direction, Priority, Access, Protocol,
                @{N='SourceAddressPrefix';E={ ($_.SourceAddressPrefix -join ', ') }},
                @{N='SourcePortRange';E={ ($_.SourcePortRange -join ', ') }},
                @{N='DestinationAddressPrefix';E={ ($_.DestinationAddressPrefix -join ', ') }},
                @{N='DestinationPortRange';E={ ($_.DestinationPortRange -join ', ') }}
        }
    }
    $subCounts['NSGRules'] = (Export-Dataset -SubDir $subDir -Name 'nsg-rules' -Data $nsgRules)

    $routeTables = Safe-Collect 'RouteTables' {
        Get-AzRouteTable | Select-Object Name, ResourceGroupName, Location,
            @{N='RouteCount';E={ $_.Routes.Count }},
            @{N='DisableBgpRoutePropagation';E={ $_.DisableBgpRoutePropagation }},
            @{N='Routes';E={ ($_.Routes | ForEach-Object { "$($_.Name):$($_.AddressPrefix)->$($_.NextHopType)" }) -join '; ' }},
            Id
    }
    $subCounts['RouteTables'] = (Export-Dataset -SubDir $subDir -Name 'route-tables' -Data $routeTables)

    $publicIPs = Safe-Collect 'PublicIPs' {
        Get-AzPublicIpAddress | Select-Object Name, ResourceGroupName, Location,
            PublicIpAllocationMethod, IpAddress, Sku,
            @{N='AssociatedTo';E={ if ($_.IpConfiguration) { ($_.IpConfiguration.Id -split '/')[-3] } else { '' } }},
            Id
    }
    $subCounts['PublicIPs'] = (Export-Dataset -SubDir $subDir -Name 'public-ips' -Data $publicIPs)

    # ── Compute ──
    $vms = Safe-Collect 'VirtualMachines' {
        Get-AzVM -Status | Select-Object Name, ResourceGroupName, Location,
            @{N='VMSize';E={ $_.HardwareProfile.VmSize }},
            @{N='OsType';E={ $_.StorageProfile.OsDisk.OsType }},
            @{N='OsDiskSize';E={ $_.StorageProfile.OsDisk.DiskSizeGB }},
            @{N='ImagePublisher';E={ $_.StorageProfile.ImageReference.Publisher }},
            @{N='ImageOffer';E={ $_.StorageProfile.ImageReference.Offer }},
            @{N='ImageSku';E={ $_.StorageProfile.ImageReference.Sku }},
            @{N='ImageVersion';E={ $_.StorageProfile.ImageReference.ExactVersion }},
            @{N='DataDiskCount';E={ $_.StorageProfile.DataDisks.Count }},
            @{N='PowerState';E={ ($_.Statuses | Where-Object { $_.Code -like 'PowerState/*' }).DisplayStatus }},
            @{N='ProvisioningState';E={ $_.ProvisioningState }},
            @{N='AvailabilitySet';E={ if ($_.AvailabilitySetReference) { ($_.AvailabilitySetReference.Id -split '/')[-1] } else { '' } }},
            @{N='Tags';E={ ($_.Tags | ConvertTo-Json -Compress -WarningAction SilentlyContinue) }},
            Id
    }
    $subCounts['VirtualMachines'] = (Export-Dataset -SubDir $subDir -Name 'virtual-machines' -Data $vms)

    $vmExtensions = Safe-Collect 'VMExtensions' {
        Get-AzVM | ForEach-Object {
            $vmName = $_.Name; $rg = $_.ResourceGroupName
            try {
                Get-AzVMExtension -ResourceGroupName $rg -VMName $vmName -ErrorAction SilentlyContinue |
                    Select-Object @{N='VMName';E={ $vmName }}, Name, Publisher, ExtensionType,
                        TypeHandlerVersion, ProvisioningState, @{N='AutoUpgrade';E={ $_.AutoUpgradeMinorVersion }}
            } catch { $null }
        }
    }
    $subCounts['VMExtensions'] = (Export-Dataset -SubDir $subDir -Name 'vm-extensions' -Data $vmExtensions)

    # ── Storage ──
    $storageAccounts = Safe-Collect 'StorageAccounts' {
        Get-AzStorageAccount | Select-Object StorageAccountName, ResourceGroupName, Location,
            @{N='Kind';E={ $_.Kind }},
            @{N='SkuName';E={ $_.Sku.Name }},
            @{N='AccessTier';E={ $_.AccessTier }},
            @{N='EnableHttpsOnly';E={ $_.EnableHttpsTrafficOnly }},
            @{N='MinimumTlsVersion';E={ $_.MinimumTlsVersion }},
            @{N='AllowBlobPublicAccess';E={ $_.AllowBlobPublicAccess }},
            @{N='NetworkRuleDefaultAction';E={ $_.NetworkRuleSet.DefaultAction }},
            @{N='LargeFileShares';E={ $_.LargeFileSharesState }},
            @{N='Tags';E={ ($_.Tags | ConvertTo-Json -Compress -WarningAction SilentlyContinue) }},
            Id
    }
    $subCounts['StorageAccounts'] = (Export-Dataset -SubDir $subDir -Name 'storage-accounts' -Data $storageAccounts)

    # ── Key Vault ──
    $keyVaults = Safe-Collect 'KeyVaults' {
        Get-AzKeyVault | Select-Object VaultName, ResourceGroupName, Location,
            @{N='EnableSoftDelete';E={ $_.EnableSoftDelete }},
            @{N='EnablePurgeProtection';E={ $_.EnablePurgeProtection }},
            @{N='SkuName';E={ $_.Sku }},
            @{N='Tags';E={ ($_.Tags | ConvertTo-Json -Compress -WarningAction SilentlyContinue) }},
            ResourceId
    }
    $subCounts['KeyVaults'] = (Export-Dataset -SubDir $subDir -Name 'key-vaults' -Data $keyVaults)

    # ── Log Analytics ──
    $logAnalytics = Safe-Collect 'LogAnalyticsWorkspaces' {
        Get-AzOperationalInsightsWorkspace | Select-Object Name, ResourceGroupName, Location,
            @{N='Sku';E={ $_.Sku }},
            @{N='RetentionDays';E={ $_.RetentionInDays }},
            CustomerId, ResourceId
    }
    $subCounts['LogAnalyticsWorkspaces'] = (Export-Dataset -SubDir $subDir -Name 'log-analytics-workspaces' -Data $logAnalytics)

    # ── Recovery Services ──
    $recVaults = Safe-Collect 'RecoveryServicesVaults' {
        Get-AzRecoveryServicesVault | Select-Object Name, ResourceGroupName, Location,
            @{N='Type';E={ $_.Type }},
            @{N='ProvisioningState';E={ Get-PropValue $_ @('Properties.ProvisioningState','ProvisioningState') '' }},
            @{N='Tags';E={ ($_.Tags | ConvertTo-Json -Compress -WarningAction SilentlyContinue) }},
            ID
    }
    $subCounts['RecoveryServicesVaults'] = (Export-Dataset -SubDir $subDir -Name 'recovery-services-vaults' -Data $recVaults)

    # ── Private Endpoints ──
    $privateEndpoints = Safe-Collect 'PrivateEndpoints' {
        Get-AzPrivateEndpoint | Select-Object Name, ResourceGroupName, Location,
            @{N='Subnet';E={ if ($_.Subnet) { ($_.Subnet.Id -split '/')[-1] } else { '' } }},
            @{N='VNet';E={ if ($_.Subnet) { ($_.Subnet.Id -split '/')[8] } else { '' } }},
            @{N='TargetResource';E={ ($_.PrivateLinkServiceConnections | ForEach-Object { ($_.PrivateLinkServiceId -split '/')[-1] }) -join ', ' }},
            @{N='GroupIds';E={ ($_.PrivateLinkServiceConnections | ForEach-Object { $_.GroupIds -join ',' }) -join '; ' }},
            @{N='ConnectionStatus';E={ ($_.PrivateLinkServiceConnections | ForEach-Object { $_.PrivateLinkServiceConnectionState.Status }) -join ', ' }},
            Id
    }
    $subCounts['PrivateEndpoints'] = (Export-Dataset -SubDir $subDir -Name 'private-endpoints' -Data $privateEndpoints)

    # ── Policy Assignments ──
    $policyAssignments = Safe-Collect 'PolicyAssignments' {
        Get-AzPolicyAssignment -ErrorAction SilentlyContinue |
            Select-Object @{N='DisplayName';E={ Get-PropValue $_ @('DisplayName','Properties.DisplayName') '' }},
                @{N='PolicyDefinitionId';E={ Get-PropValue $_ @('PolicyDefinitionId','Properties.PolicyDefinitionId') '' }},
                @{N='Scope';E={ Get-PropValue $_ @('Scope','Properties.Scope') '' }},
                @{N='EnforcementMode';E={ Get-PropValue $_ @('EnforcementMode','Properties.EnforcementMode') '' }},
                @{N='AssignmentName';E={ $_.Name }},
                @{N='ResourceId';E={ Get-PropValue $_ @('Id','ResourceId') '' }}
    }
    $subCounts['PolicyAssignments'] = (Export-Dataset -SubDir $subDir -Name 'policy-assignments' -Data $policyAssignments)

    # ── Role Assignments ──
    $roleAssignments = Safe-Collect 'RoleAssignments' {
        Get-AzRoleAssignment -ErrorAction SilentlyContinue |
            Select-Object DisplayName, SignInName, RoleDefinitionName, Scope, ObjectType, ObjectId
    }
    $subCounts['RoleAssignments'] = (Export-Dataset -SubDir $subDir -Name 'role-assignments' -Data $roleAssignments)

    # ── AVD Host Pools ──
    $hostPools = Safe-Collect 'AVDHostPools' {
        Get-AzWvdHostPool | Select-Object Name, ResourceGroupName, Location,
            @{N='HostPoolType';E={ $_.HostPoolType }},
            @{N='LoadBalancerType';E={ $_.LoadBalancerType }},
            @{N='PreferredAppGroupType';E={ $_.PreferredAppGroupType }},
            @{N='MaxSessionLimit';E={ $_.MaxSessionLimit }},
            @{N='ValidationEnvironment';E={ $_.ValidationEnvironment }},
            @{N='StartVMOnConnect';E={ $_.StartVMOnConnect }},
            @{N='CustomRdpProperty';E={ $_.CustomRdpProperty }},
            @{N='Tags';E={ ($_.Tag | ConvertTo-Json -Compress -WarningAction SilentlyContinue) }},
            Id
    }
    $subCounts['AVDHostPools'] = (Export-Dataset -SubDir $subDir -Name 'avd-host-pools' -Data $hostPools)

    # ── AVD Workspaces ──
    $avdWorkspaces = Safe-Collect 'AVDWorkspaces' {
        Get-AzWvdWorkspace | Select-Object Name, ResourceGroupName, Location,
            @{N='FriendlyName';E={ $_.FriendlyName }},
            @{N='Description';E={ $_.Description }},
            @{N='AppGroupReferences';E={ ($_.ApplicationGroupReference -join '; ') }},
            @{N='Tags';E={ ($_.Tag | ConvertTo-Json -Compress -WarningAction SilentlyContinue) }},
            Id
    }
    $subCounts['AVDWorkspaces'] = (Export-Dataset -SubDir $subDir -Name 'avd-workspaces' -Data $avdWorkspaces)

    # ── AVD Application Groups ──
    $appGroups = Safe-Collect 'AVDApplicationGroups' {
        Get-AzWvdApplicationGroup | Select-Object Name, ResourceGroupName, Location,
            @{N='ApplicationGroupType';E={ $_.ApplicationGroupType }},
            @{N='HostPoolArmPath';E={ $_.HostPoolArmPath }},
            @{N='FriendlyName';E={ $_.FriendlyName }},
            @{N='Description';E={ $_.Description }},
            @{N='Tags';E={ ($_.Tag | ConvertTo-Json -Compress -WarningAction SilentlyContinue) }},
            Id
    }
    $subCounts['AVDApplicationGroups'] = (Export-Dataset -SubDir $subDir -Name 'avd-application-groups' -Data $appGroups)

    # ── AVD Session Hosts ──
    $sessionHosts = Safe-Collect 'AVDSessionHosts' {
        $allSH = @()
        foreach ($hp in $hostPools) {
            $hpName = $hp.Name
            $hpRg   = $hp.ResourceGroupName
            try {
                $shs = Get-AzWvdSessionHost -HostPoolName $hpName -ResourceGroupName $hpRg -ErrorAction SilentlyContinue
                foreach ($sh in $shs) {
                    $allSH += [pscustomobject]@{
                        HostPool           = $hpName
                        Name               = $sh.Name
                        ResourceId         = $sh.Id
                        Status             = $sh.Status
                        AllowNewSession    = $sh.AllowNewSession
                        AssignedUser       = $sh.AssignedUser
                        Sessions           = $sh.Session
                        LastHeartBeat      = $sh.LastHeartBeat
                        OSVersion          = $sh.OsVersion
                        SxSStackVersion    = $sh.SxSStackVersion
                        AgentVersion       = $sh.AgentVersion
                        UpdateState        = $sh.UpdateState
                        StatusTimestamp     = $sh.StatusTimestamp
                    }
                }
            } catch {
                Write-Log "  Could not retrieve session hosts for host pool '$hpName': $($_.Exception.Message)" -Level WARN
            }
        }
        $allSH
    }
    $subCounts['AVDSessionHosts'] = (Export-Dataset -SubDir $subDir -Name 'avd-session-hosts' -Data $sessionHosts)

    # ── Record subscription outcome ──
    $script:SubscriptionResults.Add([pscustomobject]@{
        SubscriptionName = $subName
        SubscriptionId   = $subId
        Status           = 'Collected'
        Reason           = ''
    })

    foreach ($k in $subCounts.Keys) {
        if ($grandTotals.ContainsKey($k)) { $grandTotals[$k] += $subCounts[$k] }
        else { $grandTotals[$k] = $subCounts[$k] }
    }

    Write-Log "Subscription '$subName' collection complete."
}

# endregion

# ─────────────────────────────────────────────
# region Summary Generation
# ─────────────────────────────────────────────

Write-Log 'Generating summary ...'

$collectedSubs = $script:SubscriptionResults | Where-Object { $_.Status -eq 'Collected' }
$skippedSubs   = $script:SubscriptionResults | Where-Object { $_.Status -ne 'Collected' }

$summaryLines = [System.Collections.Generic.List[string]]::new()
function Add-Line { param([string]$L='') $summaryLines.Add($L) }

Add-Line "# AVD Current State — Collection Summary"
Add-Line ""
Add-Line "**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"
Add-Line "**Identity:** $($context.Account.Id)"
Add-Line "**Tenant:** $($context.Tenant.Id)"
Add-Line "**Subscriptions collected:** $($collectedSubs.Count) of $($targetSubs.Count) targeted"
Add-Line ""
Add-Line "---"
Add-Line ""

# Executive Summary
Add-Line "## Executive Summary"
Add-Line ""
Add-Line ("This evidence package captures a point-in-time inventory of the Azure environment " +
          "as seen through an Azure Virtual Desktop (AVD) lens. It documents host pools, " +
          "workspaces, application groups, session hosts, and the supporting platform infrastructure " +
          "(networking, storage, identity, monitoring, security) across $($collectedSubs.Count) subscription(s).")
Add-Line ""
Add-Line ("**Important:** This is a current-state inventory. It is not a production-readiness " +
          "certification, a compliance attestation, or a full target-state gap analysis.")
Add-Line ""

# AVD Workload Summary
Add-Line "## AVD Workload Overview"
Add-Line ""
$hpCount  = if ($grandTotals.ContainsKey('AVDHostPools'))         { $grandTotals['AVDHostPools'] }         else { 0 }
$wsCount  = if ($grandTotals.ContainsKey('AVDWorkspaces'))        { $grandTotals['AVDWorkspaces'] }        else { 0 }
$agCount  = if ($grandTotals.ContainsKey('AVDApplicationGroups')) { $grandTotals['AVDApplicationGroups'] } else { 0 }
$shCount  = if ($grandTotals.ContainsKey('AVDSessionHosts'))      { $grandTotals['AVDSessionHosts'] }      else { 0 }

Add-Line "| Component | Count |"
Add-Line "|---|---|"
Add-Line "| Host Pools | $hpCount |"
Add-Line "| Workspaces | $wsCount |"
Add-Line "| Application Groups | $agCount |"
Add-Line "| Session Hosts | $shCount |"
Add-Line ""

if ($hpCount -eq 0) {
    Add-Line "> **Note:** No AVD host pools were discovered. The environment may not yet have AVD deployed, or the collector identity may lack `Desktop Virtualization Reader` permissions."
    Add-Line ""
}

# Per-subscription detail
Add-Line "## Subscription Detail"
Add-Line ""
foreach ($sr in $script:SubscriptionResults) {
    if ($sr.Status -eq 'Collected') {
        Add-Line "### $($sr.SubscriptionName)"
        Add-Line "- **Subscription ID:** $($sr.SubscriptionId)"
        Add-Line "- **Status:** Collected"
        Add-Line ""
    } else {
        Add-Line "### $($sr.SubscriptionName) *(skipped)*"
        Add-Line "- **Subscription ID:** $($sr.SubscriptionId)"
        Add-Line "- **Status:** $($sr.Status) — $($sr.Reason)"
        Add-Line ""
    }
}

# Platform inventory totals
Add-Line "## Supporting Platform Inventory"
Add-Line ""
Add-Line "| Dataset | Total Across Subscriptions |"
Add-Line "|---|---|"

$datasetOrder = @(
    'ResourceGroups', 'ARMResources', 'VirtualNetworks', 'Subnets', 'NSGs', 'NSGRules',
    'RouteTables', 'PublicIPs', 'VirtualMachines', 'VMExtensions', 'StorageAccounts',
    'KeyVaults', 'LogAnalyticsWorkspaces', 'RecoveryServicesVaults', 'PrivateEndpoints',
    'PolicyAssignments', 'RoleAssignments'
)

foreach ($ds in $datasetOrder) {
    $ct = if ($grandTotals.ContainsKey($ds)) { $grandTotals[$ds] } else { 0 }
    Add-Line "| $ds | $ct |"
}
Add-Line ""

# Architecture observations
Add-Line "## Architecture & Platform Observations"
Add-Line ""
$vnetCount = if ($grandTotals.ContainsKey('VirtualNetworks')) { $grandTotals['VirtualNetworks'] } else { 0 }
$peCount   = if ($grandTotals.ContainsKey('PrivateEndpoints')) { $grandTotals['PrivateEndpoints'] } else { 0 }
$vmCount   = if ($grandTotals.ContainsKey('VirtualMachines')) { $grandTotals['VirtualMachines'] } else { 0 }
$saCount   = if ($grandTotals.ContainsKey('StorageAccounts')) { $grandTotals['StorageAccounts'] } else { 0 }
$kvCount   = if ($grandTotals.ContainsKey('KeyVaults')) { $grandTotals['KeyVaults'] } else { 0 }
$laCount   = if ($grandTotals.ContainsKey('LogAnalyticsWorkspaces')) { $grandTotals['LogAnalyticsWorkspaces'] } else { 0 }
$rtCount   = if ($grandTotals.ContainsKey('RouteTables')) { $grandTotals['RouteTables'] } else { 0 }

Add-Line "- **Networking:** $vnetCount virtual network(s) discovered across all subscriptions providing the backbone for AVD session host connectivity."
if ($peCount -gt 0) {
    Add-Line "- **Private Endpoints:** $peCount private endpoint(s) detected, indicating use of private connectivity for platform services."
}
if ($rtCount -gt 0) {
    Add-Line "- **Routing:** $rtCount route table(s) present, which may affect AVD session host traffic patterns (e.g., forced tunneling, NVA routing)."
}
Add-Line "- **Compute:** $vmCount virtual machine(s) total, including any session hosts, image-authoring VMs, and supporting infrastructure."
Add-Line "- **Storage:** $saCount storage account(s), which may include FSLogix profile containers, MSIX app attach shares, or diagnostic storage."
if ($kvCount -gt 0) {
    Add-Line "- **Key Vault:** $kvCount Key Vault(s) available for certificate, secret, and key management supporting AVD or related services."
}
if ($laCount -gt 0) {
    Add-Line "- **Monitoring:** $laCount Log Analytics workspace(s) providing potential AVD diagnostics and monitoring integration."
}
Add-Line ""

# Warnings
if ($script:Warnings.Count -gt 0) {
    Add-Line "## Warnings"
    Add-Line ""
    foreach ($w in $script:Warnings) {
        Add-Line "- $w"
    }
    Add-Line ""
}

# Stakeholder takeaways
Add-Line "## Stakeholder Takeaways"
Add-Line ""
Add-Line "1. This package provides a factual snapshot of the Azure environment as discovered by the collector identity at the time of execution."
Add-Line "2. All AVD-specific resources (host pools, workspaces, application groups, session hosts) and supporting platform components (networking, storage, identity, monitoring) are inventoried."
Add-Line "3. Review the per-subscription CSV and JSON files for detailed resource-level evidence."
Add-Line "4. Any subscriptions that were skipped due to access issues are noted above — expand permissions and re-run if coverage is incomplete."
Add-Line "5. Pair this inventory with a design workshop or assessment to translate current state into actionable recommendations."
Add-Line ""

Add-Line "## Scope & Limitations"
Add-Line ""
Add-Line "- This collector reads Azure Resource Manager (ARM) data only. It does not inspect OS-level configuration, Group Policy, FSLogix registry settings, or Entra ID conditional access policies."
Add-Line "- Session host details depend on the AVD control plane; powered-off or unregistered hosts may show limited metadata."
Add-Line "- The collector does not modify any resources. It is read-only."
Add-Line "- Network and security datasets reflect ARM-level configuration. Effective NSG rules, NVA inspection, and DNS resolution behavior require separate validation."
Add-Line ""
Add-Line "---"
Add-Line "*Generated by AVD Current State Collector*"

$summaryPath = Join-Path $script:RootDir 'summary.md'
[System.IO.File]::WriteAllLines($summaryPath, $summaryLines.ToArray(), [System.Text.Encoding]::UTF8)
Write-Log "Summary written to summary.md."

# endregion

# ─────────────────────────────────────────────
# region Manifest
# ─────────────────────────────────────────────

$manifestFiles = Get-ChildItem -Path $script:RootDir -Recurse -File |
    Select-Object @{N='RelativePath';E={ $_.FullName.Replace($script:RootDir + [IO.Path]::DirectorySeparatorChar, '') }},
        @{N='SizeKB';E={ [math]::Round($_.Length / 1KB, 2) }},
        LastWriteTimeUtc

$manifest = [pscustomobject]@{
    PackageName      = $script:PackageName
    GeneratedUtc     = (Get-Date).ToUniversalTime().ToString('o')
    Identity         = $context.Account.Id
    TenantId         = $context.Tenant.Id
    SubscriptionsTargeted  = $targetSubs.Count
    SubscriptionsCollected = $collectedSubs.Count
    SubscriptionsSkipped   = $skippedSubs.Count
    SubscriptionDetails    = $script:SubscriptionResults
    GrandTotals      = $grandTotals
    Warnings         = $script:Warnings
    Files            = $manifestFiles
}

$manifestPath = Join-Path $script:RootDir 'manifest.json'
Safe-Export-Json -Path $manifestPath -Data $manifest -DatasetName 'Manifest'
Write-Log "Manifest written."

# endregion

# ─────────────────────────────────────────────
# region ZIP Package
# ─────────────────────────────────────────────

$zipPath = Join-Path $OutputPath "$script:PackageName.zip"
Write-Log "Creating ZIP archive: $zipPath"
try {
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path $script:RootDir -DestinationPath $zipPath -Force
    Write-Log "Evidence package archived successfully."
} catch {
    Write-Log "ZIP creation failed: $($_.Exception.Message)" -Level WARN
}

# endregion

# ─────────────────────────────────────────────
# region Final Output
# ─────────────────────────────────────────────

Write-Log '═══════════════════════════════════════════════════'
Write-Log ' Collection Complete'
Write-Log '═══════════════════════════════════════════════════'
Write-Log "Evidence folder : $script:RootDir"
Write-Log "ZIP archive     : $zipPath"
Write-Log "Summary         : $summaryPath"
Write-Log "Subscriptions   : $($collectedSubs.Count) collected, $($skippedSubs.Count) skipped"
Write-Log "Warnings        : $($script:Warnings.Count)"
Write-Log '═══════════════════════════════════════════════════'

# endregion
