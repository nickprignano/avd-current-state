# AVD Tooling for Azure Commercial

Read-only PowerShell tooling for Azure Virtual Desktop (AVD) environments. Both scripts
authenticate to Azure Commercial, read through Azure Resource Manager, and write nothing.

| Script | When to run | What it answers |
|---|---|---|
| [`avd_current_state_collector.ps1`](#avd-current-state-collector) | Any time | *What is in this environment today?* Produces a portable evidence package. |
| [`avd_deployment_validator.ps1`](#avd-deployment-validator) | Before and after an AVD deployment | *Is this subscription ready to deploy, and did the deployment land correctly?* Produces a pass/fail report. |

---

# AVD Current State Collector

A reusable PowerShell script for Azure Commercial that inventories an Azure environment from an **Azure Virtual Desktop (AVD) perspective** and produces a portable evidence package with a stakeholder-ready summary.

## What It Does

The collector authenticates to Azure Commercial, discovers subscriptions, validates read access, and inventories AVD workload resources and supporting platform infrastructure. It produces:

- Per-subscription **CSV and JSON** evidence files for every collected dataset
- A **summary.md** with executive summary, AVD workload overview, architecture observations, and stakeholder takeaways
- A **manifest.json** documenting package contents, subscription outcomes, and collection metadata
- Az module version records (**az-module-versions.csv** / **az-module-versions.json**)
- A final **ZIP archive** of the entire evidence package

### What It Is Not

This is a **current-state inventory tool**. It is not:

- A production-readiness certification
- A compliance attestation
- A target-state gap analysis or design recommendation engine

## Prerequisites

- **PowerShell 5.1+** (Windows PowerShell) or **PowerShell 7+** (cross-platform)
- **Azure identity** with at least **Reader** access to target subscriptions
  - `Desktop Virtualization Reader` is recommended for full AVD session host enumeration
- **Internet access** to PowerShell Gallery (only if Az modules are not pre-installed)

## Az Modules Used

The following modules are required and will be auto-installed from PSGallery if missing:

| Module | Purpose |
|---|---|
| Az.Accounts | Authentication, subscription/context management |
| Az.Resources | Resource groups, ARM resources, policy & role assignments |
| Az.Compute | Virtual machines, VM extensions |
| Az.Network | VNets, subnets, NSGs, route tables, public IPs, private endpoints |
| Az.Storage | Storage accounts |
| Az.KeyVault | Key Vaults |
| Az.OperationalInsights | Log Analytics workspaces |
| Az.RecoveryServices | Recovery Services vaults |
| Az.DesktopVirtualization | Host pools, workspaces, application groups, session hosts |

Exact module versions used during each run are recorded in the evidence package.

## Usage

### Default — All Subscriptions

```powershell
.\avd_current_state_collector.ps1
```

Discovers and inventories **every enabled subscription** visible to the authenticated identity. No subscription names are required.

### Filter by Subscription Name

```powershell
.\avd_current_state_collector.ps1 -SubscriptionNames "Subscription-A", "Subscription-B"
```

Limits collection to the named subscriptions only. Any names not found or not enabled produce a warning and are skipped.

### Custom Output Location

```powershell
.\avd_current_state_collector.ps1 -OutputPath "C:\Evidence"
```

### Combined

```powershell
.\avd_current_state_collector.ps1 -SubscriptionNames "Subscription-A" -OutputPath "D:\Assessments"
```

### Azure Cloud Shell

The script detects Cloud Shell automatically. When running in Cloud Shell:

- **Output defaults to `~/clouddrive/`** so the evidence package persists across sessions. You can override this with `-OutputPath`.
- **Authentication is pre-established** — the script detects the existing context and skips the login prompt.
- **Az modules are pre-installed** — `Ensure-Module` checks first and skips installation if modules are already available.

```powershell
# Upload the script via Cloud Shell's file upload, then:
./avd_current_state_collector.ps1
```

The evidence package and ZIP will appear under `~/clouddrive/avd-current-state-<timestamp>/`, downloadable from the Cloud Shell file browser or via `download` command.

> **Timeout note:** Cloud Shell sessions idle-timeout after 20 minutes. Large environments with many subscriptions should complete well within this window since collection activity keeps the session active, but avoid switching to another browser tab for extended periods mid-run.

## Default Behavior

When run without `-SubscriptionNames`:

1. Detects Azure Cloud Shell (if applicable) and defaults output to `~/clouddrive/` for persistence
2. Authenticates to Azure Commercial (`AzureCloud`) — prompts for login only if no active context exists
3. Discovers all enabled subscriptions visible to the identity
4. Validates lightweight read access per subscription before full collection
5. Skips inaccessible subscriptions with a warning (does not halt the run)
6. Collects all datasets per accessible subscription
7. Generates summary, manifest, and ZIP

## Output Package Structure

```
avd-current-state-20260617T143022/
├── az-module-versions.csv
├── az-module-versions.json
├── summary.md
├── manifest.json
├── Subscription_A/
│   ├── resource-groups.csv
│   ├── resource-groups.json
│   ├── arm-resources.csv
│   ├── arm-resources.json
│   ├── virtual-networks.csv / .json
│   ├── subnets.csv / .json
│   ├── nsgs.csv / .json
│   ├── nsg-rules.csv / .json
│   ├── route-tables.csv / .json
│   ├── public-ips.csv / .json
│   ├── virtual-machines.csv / .json
│   ├── vm-extensions.csv / .json
│   ├── storage-accounts.csv / .json
│   ├── key-vaults.csv / .json
│   ├── log-analytics-workspaces.csv / .json
│   ├── recovery-services-vaults.csv / .json
│   ├── private-endpoints.csv / .json
│   ├── policy-assignments.csv / .json
│   ├── role-assignments.csv / .json
│   ├── avd-host-pools.csv / .json
│   ├── avd-workspaces.csv / .json
│   ├── avd-application-groups.csv / .json
│   └── avd-session-hosts.csv / .json
├── Subscription_B/
│   └── (same structure)
└── avd-current-state-20260617T143022.zip
```

## Collected Datasets

### AVD Workload (Primary)

| Dataset | Description |
|---|---|
| avd-host-pools | Host pool type, load balancer, session limits, validation flag, Start VM on Connect, RDP properties |
| avd-workspaces | Workspace names, friendly names, linked application groups |
| avd-application-groups | App group type, linked host pool, friendly name |
| avd-session-hosts | Per-host-pool session hosts with status, agent version, OS version, heartbeat, assigned user |

### Supporting Platform

| Dataset | Description |
|---|---|
| resource-groups | All resource groups with location, state, tags |
| arm-resources | Full ARM resource inventory (type, location, resource group, tags) |
| virtual-networks | Address spaces, DNS, subnet count, DDoS protection |
| subnets | Address prefixes, NSG/route table associations, service endpoints, delegations |
| nsgs | Network security groups with rule counts |
| nsg-rules | Individual security rules (direction, priority, access, protocol, source/destination) |
| route-tables | UDR configuration including BGP propagation and route summaries |
| public-ips | Allocation method, SKU, associated resource |
| virtual-machines | Size, OS, image reference, power state, data disks, extensions, tags |
| vm-extensions | Per-VM extensions with publisher, type, version, provisioning state |
| storage-accounts | Kind, SKU, access tier, TLS, public access, network rules, large file shares |
| key-vaults | Soft delete, purge protection, SKU |
| log-analytics-workspaces | SKU, retention, customer ID |
| recovery-services-vaults | Vault type, provisioning state |
| private-endpoints | Subnet, VNet, target resource, group IDs, connection status |
| policy-assignments | Display name, definition, scope, enforcement mode |
| role-assignments | Principal, role, scope, object type |

## Limitations

- **ARM-level only.** The collector reads Azure Resource Manager data. It does not inspect OS-level configuration, Group Policy, FSLogix registry settings, Entra ID conditional access, or Intune policies.
- **Session host detail depends on AVD control plane.** Powered-off or unregistered hosts may show limited metadata.
- **Read-only.** The collector does not create, modify, or delete any Azure resources.
- **Network effective state not evaluated.** NSG effective rules, NVA inspection, and DNS resolution behavior require separate validation.
- **No Entra ID object enumeration.** Users, groups, and conditional access policies are outside ARM scope.
- **Single-tenant per run.** Multi-tenant collection requires separate authenticated runs.

## Troubleshooting

| Symptom | Likely Cause | Resolution |
|---|---|---|
| Subscription skipped with "AccessDenied" | Identity lacks Reader role on that subscription | Grant at least Reader; re-run |
| AVD host pools show 0 | No AVD deployed, or missing Desktop Virtualization Reader | Verify AVD exists; check RBAC |
| Session hosts empty for a host pool | Session hosts powered off or agent not registered | Check host pool in the portal |
| Module install fails | No PSGallery access or execution policy restriction | Pre-install Az modules or adjust execution policy |
| Output missing after Cloud Shell session ends | Files written outside `~/clouddrive/` are ephemeral | Re-run without `-OutputPath` so Cloud Shell detection defaults to `~/clouddrive/` |
| Cloud Shell session disconnected mid-run | Idle timeout (20 min) triggered while tab was backgrounded | Keep the Cloud Shell tab active; use `-SubscriptionNames` to scope to fewer subscriptions per run if needed |

---

# AVD Deployment Validator

`avd_deployment_validator.ps1` is a **read-only** validation script that answers two
questions with a structured pass/fail report:

- **Preflight** — is this subscription, region, network, storage, image and policy posture
  ready to *receive* an AVD deployment? Run it **before** you deploy.
- **PostDeployment** — did the deployment actually land correctly? Run it **after** you deploy.

Both modes live in one script so they share the same check framework, report format and
evidence package. Use `-Mode Both` to run them back to back.

## Read-Only Guarantee

The validator performs discovery only:

- It calls `Get-*` and `Test-*` cmdlets exclusively. It never invokes `New-*`, `Set-*`,
  `Update-*`, `Add-*`, `Remove-*`, `Restart-*`, `Start-*` or `Stop-*` against an Azure resource.
- The one `Set-AzContext` call changes local PowerShell session state to select the target
  subscription. It does not touch Azure.
- Files are written only inside the local output folder.
- `-IncludeNetworkProbe` opens a TCP socket to each AVD required endpoint and closes it
  immediately. No payload is sent.

**Minimum role: `Reader`.** `Desktop Virtualization Reader` is recommended for full session
host enumeration. No write role is needed.

## Az Modules

**Required** — the script installs these from PSGallery if missing:

`Az.Accounts`, `Az.Resources`, `Az.Compute`, `Az.Network`, `Az.Storage`, `Az.DesktopVirtualization`

**Optional** — if one is unavailable, its checks report `SKIP` and the run continues:

| Module | Checks it enables |
|---|---|
| Az.OperationalInsights | Log Analytics workspace and retention |
| Az.Monitor | Host pool diagnostic settings |
| Az.RecoveryServices | Personal session host backup coverage |
| Az.KeyVault | Key Vault provider validation |
| Az.PrivateDns | Private DNS zone validation |
| Az.PolicyInsights | Policy compliance state |

## Usage

### Preflight — before deploying

```powershell
.\avd_deployment_validator.ps1 -Mode Preflight `
    -Location eastus2 `
    -ResourceGroupName rg-avd-prod `
    -VirtualNetworkName vnet-avd -SubnetName snet-avd-hosts `
    -SessionHostCount 20 -SessionHostVmSize Standard_D4ads_v5 `
    -StorageAccountName stavdfslogix01 -FileShareName profiles `
    -LogAnalyticsWorkspaceName law-avd `
    -DomainName contoso.com
```

### Post-deployment — after deploying

```powershell
.\avd_deployment_validator.ps1 -Mode PostDeployment `
    -ResourceGroupName rg-avd-prod `
    -HostPoolName hp-avd-prod `
    -SessionHostCount 20 `
    -StorageAccountName stavdfslogix01 -FileShareName profiles `
    -SubnetName snet-avd-hosts
```

Omit `-HostPoolName` to validate **every** host pool in the subscription.

### Both phases from a config file

```powershell
.\avd_deployment_validator.ps1 -ConfigPath .\avd-validation.config.json
```

```json
{
  "Mode": "Both",
  "Location": "eastus2",
  "ResourceGroupName": "rg-avd-prod",
  "VirtualNetworkName": "vnet-avd",
  "SubnetName": "snet-avd-hosts",
  "SessionHostCount": 20,
  "SessionHostVmSize": "Standard_D4ads_v5",
  "HostPoolName": "hp-avd-prod",
  "StorageAccountName": "stavdfslogix01",
  "FileShareName": "profiles",
  "LogAnalyticsWorkspaceName": "law-avd"
}
```

Any config key may be overridden on the command line — explicit parameters always win.

### Azure Cloud Shell

Cloud Shell is detected automatically: output defaults to `~/clouddrive/` for persistence,
the existing authenticated context is reused, and pre-installed Az modules are not reinstalled.

## Parameters

| Parameter | Mode | Purpose |
|---|---|---|
| `-Mode` | both | `Preflight` (default), `PostDeployment`, or `Both` |
| `-SubscriptionName` / `-SubscriptionId` | both | Subscription to validate. Defaults to the current context |
| `-Location` | preflight | Session host region. Drives region, SKU, quota and image replication checks |
| `-MetadataLocation` | preflight | AVD control plane region. Defaults to `-Location` |
| `-ResourceGroupName` | both | Target resource group / host pool resource group |
| `-VirtualNetworkName`, `-VirtualNetworkResourceGroup`, `-SubnetName` | preflight | Session host network |
| `-SessionHostCount` | both | Planned (preflight) or expected (post-deployment) host count |
| `-SessionHostVmSize` | preflight | Planned VM size, e.g. `Standard_D4ads_v5` |
| `-HostPoolName`, `-WorkspaceName`, `-ApplicationGroupName` | both | Naming collision check (preflight); validation scope (post-deployment) |
| `-StorageAccountName`, `-StorageAccountResourceGroup`, `-FileShareName` | both | FSLogix profile storage |
| `-LogAnalyticsWorkspaceName`, `-LogAnalyticsResourceGroup` | preflight | Expected diagnostics destination |
| `-ImageId` | preflight | Compute Gallery image version or definition resource ID |
| `-DomainName` | both | AD DS domain, enables DNS and LDAP checks |
| `-MaxHeartbeatAgeMinutes` | post | Heartbeat staleness threshold. Default `30` |
| `-IpBufferPercent` | preflight | Subnet IP headroom on top of `-SessionHostCount`. Default `20` |
| `-IncludeNetworkProbe` | both | Opt in to outbound TCP endpoint probes |
| `-ConfigPath` | both | JSON file supplying any of the above |
| `-OutputPath` | both | Report package parent directory |
| `-SkipZip` | both | Do not create a ZIP archive |
| `-FailOnWarning` | both | Return exit code 1 on `WARN` as well as `FAIL` |
| `-PassThru` | both | Emit result objects to the pipeline |

Every parameter except `-Mode` is optional. Checks whose inputs are missing report `SKIP`
with a note on what to supply, so a bare `.\avd_deployment_validator.ps1` still runs and
tells you what it could not evaluate.

## Result Statuses

| Status | Meaning |
|---|---|
| `FAIL` | Will block deployment, or is actively broken |
| `WARN` | Works, but carries operational or resilience risk |
| `PASS` | Validated as expected |
| `INFO` | Recorded for context; no action implied |
| `SKIP` | Not evaluated — a required input or optional module is missing |

**Exit codes:** `0` = no failures · `1` = one or more `FAIL` (or `WARN` with `-FailOnWarning`) ·
`2` = the validator could not run (authentication or subscription resolution failed).

## Preflight Checks

| Category | Checks |
|---|---|
| Identity | Azure Commercial environment, subscription state, Reader access, deployment role coverage |
| Providers | Registration state of the required and recommended resource providers |
| Region | Target region availability, AVD metadata region support (read live from the resource provider) |
| Capacity | VM SKU availability and restrictions, availability zone support, Hyper-V generation, per-family vCPU quota, total regional vCPU quota, network interface quota |
| Resource group | Existence, and `ReadOnly` locks that would block deployment |
| Policy | Allowed-locations and allowed-SKU policies compared against the target, deny-effect assignment sweep, unexpanded initiative count |
| Network | VNet existence and region match, custom DNS for domain join, peering health, subnet existence, usable IP capacity vs. host count plus buffer, subnet delegation, outbound egress path (NAT gateway / forced tunneling / no default route), NSG rules that would block outbound 443 to the AVD control plane |
| Storage | Account existence, premium tier, identity-based authentication, minimum TLS, large file shares, storage firewall reachability from the session host subnet, file share existence and quota |
| Image | Gallery image version existence, replication into the target region, end-of-life date, generalized OS state |
| Monitoring | Log Analytics workspace existence and retention |
| Naming | Host pool / workspace / application group name collisions |
| Endpoints | Outbound TCP reachability to the AVD required endpoints (opt-in) |

## Post-Deployment Checks

| Category | Checks |
|---|---|
| Host pool | Type and load balancing (Personal pools must be Persistent), max session limit, validation environment flag, Start VM on Connect, custom RDP properties |
| Registration | Registration token presence and expiry, flagged as a security exposure while live |
| App groups | Application groups linked to the host pool, published to exactly one workspace, `Desktop Virtualization User` role assigned, preferred app group type alignment |
| Session hosts | Registered count vs. expected, availability status, drain mode, heartbeat freshness, agent / SxS stack / OS version drift, agent update state, pool utilisation |
| Session host VMs | VM correlation, power state, provisioning state, availability zone spread, extension provisioning failures, domain join method, monitoring agent coverage |
| Storage | Everything in the preflight storage set, plus SMB data-plane role assignments |
| Scaling | Scaling plan attached and enabled, Start VM on Connect consistency |
| Diagnostics | Host pool diagnostic settings and the enabled AVD log categories |
| Resilience | Azure Backup coverage for personal session host VMs |
| Sessions | Active vs. disconnected user sessions |

## Output Package

```
avd-validation-20260919T141120/
├── validation-report.md      # Executive report: summary, failures, warnings, all checks
├── validation-results.csv    # One row per check
├── validation-results.json   # Same data, structured
├── manifest.json             # Run inputs, verdict and counts, for reproducibility
├── az-module-versions.csv    # Tooling provenance
└── run-log.txt               # Full run log
avd-validation-20260919T141120.zip
```

## Limitations

- **ARM-level only.** No OS-level state, Group Policy, FSLogix registry configuration, Intune policy or Entra conditional access.
- **Effective network state is not evaluated.** NSG effective rules, firewall and NVA rule sets, and DNS resolution behaviour need validation from inside the session host subnet.
- **Endpoint probes reflect the machine running the script**, not a session host, unless you run it on one.
- **Policy initiatives are not expanded.** Deny effects inside an assigned initiative are reported as unexpanded, not evaluated.
- **Quota reflects the moment of the run.** Another deployment can consume the headroom reported here.
- **Single subscription per run.** Deployments spanning subscriptions need one run per subscription.

## Troubleshooting

| Symptom | Likely cause | Resolution |
|---|---|---|
| Many checks report `SKIP` | Optional parameters not supplied | Supply the parameters named in each `SKIP` recommendation, or use `-ConfigPath` |
| `Host pool discovery` fails | Identity lacks `Desktop Virtualization Reader` | Grant the role at subscription or resource group scope |
| `Deployment role coverage` reports INFO | Role assignment enumeration needs Microsoft Graph read | Expected for a read-only identity. Confirm the deploying identity's roles separately |
| `AVD metadata region` reports INFO | The resource provider did not return a location list | Check the metadata region against the AVD documentation |
| Diagnostics check reports `SKIP` | `Az.Monitor` is unavailable | Install `Az.Monitor`, or accept the gap |
| Endpoint probes all fail | Running from a machine without internet egress | Expected. Re-run from a session host, or ignore the probe results |

---

## License

This project is licensed under the [MIT License](LICENSE).
