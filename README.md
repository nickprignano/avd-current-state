# AVD Tooling for Azure Commercial

Read-only PowerShell tooling for Azure Virtual Desktop (AVD) environments on Azure
Commercial. Both scripts read through Azure Resource Manager and write nothing.

| Script | When to run | What it answers |
|---|---|---|
| [`avd_current_state_collector.ps1`](#current-state-collector) | Any time | *What is in this environment today?* Produces a portable evidence package. |
| [`avd_deployment_validator.ps1`](#deployment-validator) | Before and after an AVD deployment | *Is this subscription ready to deploy, and did the deployment land correctly?* Produces a pass/fail report. |

## Read-Only by Design

Both scripts perform discovery only:

- They call `Get-*` and `Test-*` cmdlets exclusively, and never invoke `New-*`, `Set-*`,
  `Update-*`, `Add-*`, `Remove-*`, `Restart-*`, `Start-*` or `Stop-*` against an Azure resource.
- The one `Set-AzContext` call selects the target subscription. It changes local PowerShell
  session state, not Azure.
- Files are written only inside the local output folder.
- The validator's opt-in `-IncludeNetworkProbe` opens a TCP socket to each AVD required
  endpoint and closes it immediately. No payload is sent.

Neither script is a production-readiness certification, a compliance attestation, or a
security audit.

## Prerequisites

- **PowerShell 5.1+** (Windows PowerShell) or **PowerShell 7+** (cross-platform)
- **Azure identity** with at least **Reader** on the target subscriptions
  - `Desktop Virtualization Reader` is recommended for full AVD session host enumeration
  - No write role is needed by either script
- **Internet access** to the PowerShell Gallery, only if the Az modules are not pre-installed

## Az Modules

Missing modules are installed from PSGallery automatically. The exact versions used are
recorded in every output package.

| Module | Collector | Validator | Purpose |
|---|---|---|---|
| Az.Accounts | Required | Required | Authentication, subscription and context management |
| Az.Resources | Required | Required | Resource groups, ARM resources, policy, role assignments, locks, providers |
| Az.Compute | Required | Required | Virtual machines and extensions; VM SKU catalog and gallery images |
| Az.Network | Required | Required | VNets, subnets, NSGs, route tables, public IPs, private endpoints |
| Az.Storage | Required | Required | Storage accounts; Azure Files shares |
| Az.DesktopVirtualization | Required | Required | Host pools, workspaces, application groups, session hosts |
| Az.KeyVault | Required | — | Key Vaults |
| Az.OperationalInsights | Required | Optional | Log Analytics workspaces |
| Az.RecoveryServices | Required | Optional | Recovery Services vaults; backup coverage |
| Az.Monitor | — | Optional | Diagnostic settings |

If one of the validator's **optional** modules is unavailable, only its own checks report
`SKIP` and the run continues.

## Azure Cloud Shell

Both scripts detect Cloud Shell automatically:

- **Output defaults to `~/clouddrive/`** so the package survives the session. Override with `-OutputPath`.
- **Authentication is pre-established** — the existing context is detected and the login prompt skipped.
- **Az modules are pre-installed** — already-available modules are not reinstalled.

```powershell
# Upload the script via Cloud Shell's file upload, then:
./avd_current_state_collector.ps1
```

Output appears under `~/clouddrive/`, downloadable from the Cloud Shell file browser or via
the `download` command.

> **Timeout note:** Cloud Shell sessions idle-timeout after 20 minutes. Collection activity
> keeps the session alive, but avoid backgrounding the browser tab mid-run.

---

## Current State Collector

`avd_current_state_collector.ps1` inventories an Azure environment from an **AVD
perspective** and produces a portable evidence package with a stakeholder-ready summary.

### What It Does

Authenticates, discovers subscriptions, validates read access, and inventories AVD workload
resources plus supporting platform infrastructure. It produces:

- Per-subscription **CSV and JSON** evidence files for every collected dataset
- A **summary.md** with executive summary, AVD workload overview, architecture observations, and stakeholder takeaways
- A **manifest.json** documenting package contents, subscription outcomes, and collection metadata
- Az module version records (**az-module-versions.csv** / **az-module-versions.json**)
- A final **ZIP archive** of the entire evidence package

It is a current-state inventory tool, not a target-state gap analysis or design
recommendation engine.

### Usage

#### Default — all subscriptions

```powershell
.\avd_current_state_collector.ps1
```

Discovers and inventories **every enabled subscription** visible to the authenticated
identity. No subscription names are required.

#### Filter by subscription name

```powershell
.\avd_current_state_collector.ps1 -SubscriptionNames "Subscription-A", "Subscription-B"
```

Names that are not found or not enabled produce a warning and are skipped.

#### Custom output location

```powershell
.\avd_current_state_collector.ps1 -OutputPath "C:\Evidence"
```

#### Combined

```powershell
.\avd_current_state_collector.ps1 -SubscriptionNames "Subscription-A" -OutputPath "D:\Assessments"
```

### Run Sequence

1. Detects Azure Cloud Shell and defaults output to `~/clouddrive/` for persistence
2. Authenticates to Azure Commercial (`AzureCloud`) — prompts for login only if no active context exists
3. Discovers all enabled subscriptions visible to the identity
4. Validates lightweight read access per subscription before full collection
5. Skips inaccessible subscriptions with a warning, without halting the run
6. Collects all datasets per accessible subscription
7. Generates the summary, manifest and ZIP

### Output Package

```
avd-current-state-20260617T143022/
├── az-module-versions.csv
├── az-module-versions.json
├── summary.md
├── manifest.json
├── Subscription_A/
│   ├── resource-groups.csv / .json
│   ├── arm-resources.csv / .json
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

### Collected Datasets

#### AVD workload (primary)

| Dataset | Description |
|---|---|
| avd-host-pools | Host pool type, load balancer, session limits, validation flag, Start VM on Connect, RDP properties |
| avd-workspaces | Workspace names, friendly names, linked application groups |
| avd-application-groups | App group type, linked host pool, friendly name |
| avd-session-hosts | Per-host-pool session hosts with status, agent version, OS version, heartbeat, assigned user |

#### Supporting platform

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

---

## Deployment Validator

`avd_deployment_validator.ps1` answers two questions with a structured pass/fail report:

- **Preflight** — is this subscription, region, network, storage, image and policy posture
  ready to *receive* an AVD deployment? Run it **before** you deploy.
- **PostDeployment** — did the deployment actually land correctly? Run it **after** you deploy.

Both modes live in one script so they share the same check framework, report format and
evidence package. Use `-Mode Both` to run them back to back.

Every parameter except `-Mode` is optional. Checks whose inputs are missing report `SKIP`
with a note on what to supply, so a bare `.\avd_deployment_validator.ps1` still runs and
tells you what it could not evaluate.

### Usage

#### Preflight — before deploying

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

#### Post-deployment — after deploying

```powershell
.\avd_deployment_validator.ps1 -Mode PostDeployment `
    -ResourceGroupName rg-avd-prod `
    -HostPoolName hp-avd-prod `
    -SessionHostCount 20 `
    -StorageAccountName stavdfslogix01 -FileShareName profiles `
    -SubnetName snet-avd-hosts
```

Omit `-HostPoolName` to validate **every** host pool in the subscription.

#### Both phases from a config file

```powershell
.\avd_deployment_validator.ps1 -ConfigPath .\avd-validation.config.json
```

Copy [`avd-validation.config.example.json`](avd-validation.config.example.json) as a
starting point. Any config key can be overridden on the command line — explicit parameters
always win. Keys beginning with `_` are treated as comments.

### Parameters

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
| `-DomainName` | both | AD DS domain. Enables DNS and LDAP checks |
| `-MaxHeartbeatAgeMinutes` | post | Heartbeat staleness threshold. Default `30` |
| `-IpBufferPercent` | preflight | Subnet IP headroom on top of `-SessionHostCount`. Default `20` |
| `-IncludeNetworkProbe` | both | Opt in to outbound TCP endpoint probes |
| `-ConfigPath` | both | JSON file supplying any of the above |
| `-OutputPath` | both | Report package parent directory |
| `-SkipZip` | both | Do not create a ZIP archive |
| `-FailOnWarning` | both | Return exit code 1 on `WARN` as well as `FAIL` |
| `-PassThru` | both | Emit result objects to the pipeline |

### Result Statuses

| Status | Meaning |
|---|---|
| `FAIL` | Will block deployment, or is actively broken |
| `WARN` | Works, but carries operational or resilience risk |
| `PASS` | Validated as expected |
| `INFO` | Recorded for context; no action implied |
| `SKIP` | Not evaluated — a required input or optional module is missing |

**Exit codes:** `0` = no failures · `1` = one or more `FAIL` (or `WARN` with `-FailOnWarning`)
· `2` = the validator could not run (authentication or subscription resolution failed).

### Preflight Checks

| Category | Checks |
|---|---|
| Identity | Azure Commercial environment, subscription state, Reader access, deployment role coverage, Desktop Virtualization power management role |
| Providers | Registration state of the required and recommended resource providers |
| Region | Target region availability, AVD metadata region support (read live from the resource provider) |
| Capacity | VM SKU availability and restrictions, availability zone support, Hyper-V generation, per-family vCPU quota, total regional vCPU quota, network interface quota. On a family quota failure it names the families in the region that do have headroom, and it warns when the regional ceiling is passed by less than one more host |
| Resource group | Existence, and `ReadOnly` locks that would block deployment |
| Policy | Allowed-locations and allowed-SKU policies compared against the target, deny-effect assignment sweep, unexpanded initiative count |
| Network | VNet existence and region match, custom DNS for domain join, peering health, subnet existence, usable IP capacity vs. host count plus buffer, subnet delegation, outbound egress path (NAT gateway / forced tunneling / no default route), NSG rules that would block outbound 443 to the AVD control plane |
| Storage | Account existence, premium tier, identity-based authentication, minimum TLS, large file shares, storage firewall reachability from the session host subnet, file share existence and quota |
| Image | Gallery image version existence, replication into the target region, end-of-life date, generalized OS state |
| Monitoring | Log Analytics workspace existence and retention |
| Naming | Host pool / workspace / application group name collisions |
| Endpoints | Outbound TCP reachability to the AVD required endpoints (opt-in) |

### Post-Deployment Checks

| Category | Checks |
|---|---|
| Host pool | Type and load balancing (Personal pools must be Persistent), max session limit, validation environment flag, Start VM on Connect, custom RDP properties |
| Registration | Registration token presence and expiry, flagged as a security exposure while live |
| App groups | Application groups linked to the host pool, published to exactly one workspace, `Desktop Virtualization User` role assigned, preferred app group type alignment |
| Session hosts | Registered count vs. expected, availability status, drain mode, heartbeat freshness, agent / SxS stack / OS version drift, agent update state, pool utilisation |
| Session host VMs | VM correlation, power state, provisioning state, availability zone spread, extension provisioning failures, domain join method, monitoring agent coverage, and for Microsoft Entra joined hosts a `Virtual Machine User Login` role assignment |
| Storage | Everything in the preflight storage set, plus SMB data-plane role assignments |
| Scaling | Scaling plan attached and enabled, Start VM on Connect consistency |
| Identity | Desktop Virtualization power management role, graded by whether Start VM on Connect or a scaling plan is actually in use, plus whether a scaling plan has only `Power On` when it needs `Power On Off` |
| Diagnostics | Host pool diagnostic settings and the enabled AVD log categories |
| Resilience | Azure Backup coverage for personal session host VMs |
| Sessions | Active vs. disconnected user sessions |

### Output Package

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

---

## Limitations

### Both scripts

- **ARM-level only.** Neither script inspects OS-level configuration, Group Policy, FSLogix registry settings, Intune policy, or Microsoft Entra conditional access.
- **Network effective state is not evaluated.** NSG effective rules, NVA and firewall inspection, and DNS resolution behaviour require separate validation from inside the session host subnet.
- **No Entra ID object enumeration.** Users, groups and conditional access policies are outside ARM scope.
- **Read-only.** No Azure resource is created, modified or deleted.

### Current State Collector

- **Session host detail depends on the AVD control plane.** Powered-off or unregistered hosts may show limited metadata.
- **Single tenant per run.** Multi-tenant collection requires separate authenticated runs.

### Deployment Validator

- **Endpoint probes reflect the machine running the script**, not a session host, unless you run it on one.
- **Policy initiatives are not expanded.** Deny effects inside an assigned initiative are reported as unexpanded, not evaluated.
- **Quota reflects the moment of the run.** Another deployment can consume the headroom reported here.
- **Single subscription per run.** Deployments spanning subscriptions need one run per subscription.

---

## Troubleshooting

### Current State Collector

| Symptom | Likely cause | Resolution |
|---|---|---|
| Subscription skipped with "AccessDenied" | Identity lacks Reader on that subscription | Grant at least Reader, then re-run |
| AVD host pools show 0 | No AVD deployed, or missing `Desktop Virtualization Reader` | Verify AVD exists; check RBAC |
| Session hosts empty for a host pool | Hosts powered off, or agent not registered | Check the host pool in the portal |
| Module install fails | No PSGallery access, or execution policy restriction | Pre-install the Az modules or adjust execution policy |
| Output missing after the Cloud Shell session ends | Files written outside `~/clouddrive/` are ephemeral | Re-run without `-OutputPath` so Cloud Shell detection defaults to `~/clouddrive/` |
| Cloud Shell disconnected mid-run | Idle timeout while the tab was backgrounded | Keep the tab active; use `-SubscriptionNames` to scope to fewer subscriptions per run |

### Deployment Validator

| Symptom | Likely cause | Resolution |
|---|---|---|
| Many checks report `SKIP` | Optional parameters not supplied | Supply the parameters named in each `SKIP` recommendation, or use `-ConfigPath` |
| `Host pool discovery` fails | Identity lacks `Desktop Virtualization Reader` | Grant the role at subscription or resource group scope |
| `Deployment role coverage` reports `INFO` | Role assignment enumeration needs Microsoft Graph read | Expected for a read-only identity. Confirm the deploying identity's roles separately |
| `AVD metadata region` reports `INFO` | The resource provider did not return a location list | Check the metadata region against the AVD documentation |
| A check reports "Check could not complete" | Az module output shape differs from what the check expects | The run continues. Report the check name so the property accessor can be widened |
| Diagnostics check reports `SKIP` | `Az.Monitor` is unavailable | Install `Az.Monitor`, or accept the gap |
| Endpoint probes all fail | Running from a machine without internet egress | Expected. Re-run from a session host, or ignore the probe results |

---

## License

This project is licensed under the [MIT License](LICENSE).
