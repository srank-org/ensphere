# AWS Read-Only Appendix — Session 07

Use this appendix only when an AWS account is explicitly in scope. It inherits
[07-cloud.md](07-cloud.md) and the shared workflow contract.

## Binding Boundary

Collect configuration metadata only. Never retrieve secret values, object
bodies, database data, Lambda environment variables, instance user data, or
metadata credentials. Never assume roles, invoke functions, create/update
resources, attach policies, or execute a permission path.

## Preflight

Record the expected account, principal, regions, organizations/OUs if included,
and services excluded from review. Verify the active identity before collection:

```bash
aws sts get-caller-identity
aws configure list
```

Stop if the account/principal differs from the authorized scope. Redact account
identifiers and principal names in report-ready artifacts as required.

## Coverage Inventory

### Identity and policy

- account password/MFA policy metadata;
- users, roles, groups, attached/inline policy names and policy documents;
- trust policies, permission boundaries, SCPs, and resource policies;
- access-analyzer findings and credential age metadata (not credentials);
- explicit allow/deny interactions and unused standing privilege.

Use IAM policy simulation for a named principal/action/resource when it is
available and authorized. Label results simulated; do not call the action.

### Storage and data services

- S3 account/bucket public-access block, policy status, ACL metadata, ownership
  controls, encryption, logging, versioning, object lock, lifecycle, and CORS;
- RDS/Redshift/OpenSearch/DynamoDB configuration for public reachability,
  encryption, backup, deletion protection, logging, and network placement;
- snapshot/share configuration metadata.

Do not list object keys or retrieve object/database content. A single anonymous
`HEAD` is allowed only for an operator-provided non-sensitive canary and explicit
approval under the main methodology.

### Network

- VPC, subnet, route, gateway, endpoint, peering, and flow-log configuration;
- security-group and network-ACL rules;
- public load balancer/API endpoints and WAF association;
- cross-account or internet-exposed resource-policy facts.

Configuration showing `0.0.0.0/0` is an exposure fact; severity still depends
on port, listener, authentication, resource reachability, and business context.

### Compute, serverless, and containers

- EC2 public addressing, security groups, IMDS option metadata, encryption, and
  instance-profile association;
- Lambda/API Gateway/function-URL authentication, resource policy, VPC and
  logging metadata—excluding environment variable values;
- ECS/EKS cluster, task/workload identity references, endpoint exposure,
  logging, encryption, and exec-feature enablement metadata;
- ECR scan/encryption/tag-mutability policy.

Feature enablement is not proof that an attacker can use it. Record the
necessary identity and network prerequisites.

### Logging, keys, and secrets metadata

- CloudTrail organization/multi-region coverage, log validation, destination,
  and current logging state;
- Config/GuardDuty/Security Hub/access-analyzer coverage;
- KMS key policy, rotation, state, and grants metadata;
- Secrets Manager inventory, rotation/encryption/access-policy metadata without
  secret values.

## Imported Leads

Prowler or other AWS output remains an imported lead. Preserve provider account,
regions, tool/version, rule, source severity, artifact, and parser state. Verify
important claims with current read-only AWS configuration and organization
guardrails.

## Report Additions

Include the exact account/regions/services covered, active read-only principal,
resource/policy evidence, organization-control context, simulations, unavailable
services, imported-lead provenance, and source/live/IaC drift. Any escalation
combination is a risk scenario unless every edge was independently observed;
do not execute it.
