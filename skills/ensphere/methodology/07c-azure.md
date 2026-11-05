# Azure Read-Only Appendix — Session 07

Use this appendix only for explicitly authorized Microsoft Entra tenants,
management groups, subscriptions, and resource groups. It inherits
[07-cloud.md](07-cloud.md).

## Binding Boundary

Collect configuration metadata only. Never print tokens, list secret values or
storage/database content, retrieve app settings/connection strings, impersonate
identities, obtain AKS credentials, invoke workloads, or create/change resources
and role assignments.

## Preflight

Record expected tenant/subscription/resource-group/region scope and active
principal. Verify context:

```bash
az account show --query '{tenantId:tenantId,subscriptionId:id,name:name,user:user.name}'
az account list-locations --query '[].name'
```

Stop on target or principal mismatch. Redact tenant, subscription, and identity
details as required in published artifacts.

## Coverage Inventory

### Identity and policy

- management-group/subscription/resource-group role assignments and custom role
  definitions;
- managed identities, service-principal credential expiry metadata (never
  values), Conditional Access/PIM facts when authorized, and privileged standing
  access;
- Azure Policy assignments/exemptions/compliance state and resource locks;
- data-plane versus management-plane permission distinctions.

Use Azure permission/policy evaluation or documented effective-access views for
a named action/resource. Do not sign in as or impersonate another principal.

### Storage and data services

- Storage Account public network/access settings, anonymous-blob allowance,
  firewall/private endpoints, HTTPS/TLS, encryption, soft delete, versioning,
  logging, and SAS policy metadata;
- Azure SQL/Cosmos DB/PostgreSQL/MySQL configuration for public reachability,
  authentication mode, firewall, encryption, auditing, backup, and deletion
  protection;
- backup/snapshot/share policy metadata.

Do not list containers/blobs or retrieve data. The single canary `HEAD`
exception in the main methodology requires operator-provided content and
explicit approval.

### Network

- VNets/subnets/routes/peerings/private endpoints/service endpoints;
- NSGs, Azure Firewall, Application Gateway/Front Door/WAF, public IPs, load
  balancers, API Management exposure, and Network Watcher/flow logs;
- trust boundaries across subscriptions and tenants.

### Compute, serverless, and containers

- VM/VMSS public networking, disk encryption, managed identity, update and
  monitoring configuration;
- Function/App Service authentication, ingress, TLS, identity, deployment/SCM,
  remote-debug/FTP, VNet and logging metadata—excluding app settings;
- AKS endpoint exposure, Entra/RBAC integration, local accounts, authorized IPs,
  workload identity, policy, encryption, and monitoring—without obtaining
  cluster credentials;
- ACR access, public exposure, scanning, encryption, and retention metadata.

### Logging, keys, and secrets metadata

- Activity Log diagnostic settings, Defender for Cloud, Sentinel/workspace
  connections, resource diagnostic coverage, and alert rules;
- Key Vault network/RBAC/access-policy, purge protection, soft delete, logging,
  and key/certificate rotation metadata without values;
- application credential lifetime metadata without secret material.

## Imported Leads and Report

Preserve scanner tool/version, tenant/subscription/region scope, rule, source
severity, artifact, and parser state. Corroborate with current Azure facts,
policy inheritance, and data-plane prerequisites.

Report exact authorized hierarchy, regions/services, active read-only identity,
policy context, simulations, unavailable APIs, evidence citations, and
source/live drift. Managed-identity or deployment combinations are unverified
risk scenarios; never execute them.
