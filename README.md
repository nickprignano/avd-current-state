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

## License

This project is licensed under the [MIT License](LICENSE).
