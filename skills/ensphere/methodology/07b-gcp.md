# GCP Read-Only Appendix — Session 07

Use this appendix only for explicitly authorized GCP organizations, folders,
and projects. It inherits [07-cloud.md](07-cloud.md).

## Binding Boundary

Collect configuration metadata only. Never print access/identity tokens,
retrieve secret versions or object/database content, inspect function/container
environment values, impersonate service accounts, create keys, invoke services,
or change IAM/resources.

## Preflight

Record the expected organization/folder/project IDs, regions, active principal,
and excluded services. Verify local context without printing a token:

```bash
gcloud auth list --filter=status:ACTIVE
gcloud config get-value project
gcloud projects describe PROJECT_ID --format=json
```

Stop on any target or identity mismatch.

## Coverage Inventory

### Identity and policy

- organization/folder/project IAM policies and inherited constraints;
- service-account metadata, key age/type metadata, role bindings, custom roles,
  and workload identity federation configuration;
- public principals (`allUsers`, `allAuthenticatedUsers`), primitive roles, and
  broad service-agent grants;
- organization policies affecting external IPs, domain restriction, service
  account keys, public access, and uniform controls.

Use Policy Troubleshooter or other provider simulations for a named
principal/action/resource when authorized. Do not impersonate the principal or
perform the action.

### Storage and data services

- Cloud Storage public-access prevention, uniform access, IAM/ACL metadata,
  encryption, retention, versioning, logging, and CORS;
- Cloud SQL/Spanner/BigQuery/Firestore configuration for public networking,
  encryption, authorization mode, backups, deletion protection, and audit logs;
- snapshot/export destination policy metadata.

Do not list or fetch object/data contents. Anonymous canary validation follows
the main methodology's single operator-provided `HEAD` exception.

### Network

- VPC/subnet/route/firewall/NAT/private-access/peering configuration;
- public forwarding rules, load balancers, serverless ingress, authorized
  networks, and VPC Service Controls;
- flow-log and DNS policy coverage.

### Compute, serverless, and containers

- Compute Engine public IP, shielded/confidential settings, service-account
  attachment, scopes, OS Login, metadata configuration, and encryption;
- Cloud Run/Functions ingress, authentication policy, service account, VPC,
  binary authorization, and logging metadata—excluding environment values;
- GKE endpoint exposure, master authorized networks, private nodes, workload
  identity, release/security settings, logging, and encryption;
- Artifact Registry access, scanning, encryption, and immutability metadata.

### Logging, keys, and secrets metadata

- audit-log coverage and exclusions, log sinks, Monitoring alerts, Security
  Command Center, and asset inventory;
- KMS key policy, rotation, protection level, state, and location metadata;
- Secret Manager secret inventory, IAM, replication, rotation and version-state
  metadata without accessing payloads.

## Imported Leads and Report

Preserve scanner tool/version, project/region scope, rule, source severity,
artifact, and parse state. Corroborate with current provider facts and inherited
organization policy.

Report exact projects/regions/services, active read-only principal, inherited
controls, simulations, unavailable services, source/live drift, and evidence
citations. Service-account impersonation or resource-creation combinations are
risk scenarios only; do not execute them.
