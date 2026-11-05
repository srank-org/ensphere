# AWS IAM Checklist

Load this checklist when recon records `aws_iam_*` resources in Terraform or CloudFormation, an `aws` CLI profile in scope, or application code that assumes roles or uses long-lived access keys. IAM is where a compromised application credential turns into account-wide impact, and where a runaway principal can create expensive resources. Shared abuse patterns are in `abuse-and-cost.md`.

## Prerequisites

`ensphere cloud iam` shells out to the `aws` CLI and records attached and inline policies, MFA state, and access key metadata for one principal. If `aws sts get-caller-identity` fails, tell the operator to configure a read-only profile for the staging account and record live items as `blocked` until then. Terraform review proceeds without credentials: `ensphere scan ./infra --category iac_terraform`.

Live measurement for every item below: `ensphere cloud iam --provider aws --principal <arn> --in-scope "aws://<account_id>"`. Read the raw policy documents it returns; the command does not classify them.

## Application principals

- [ ] **Application role or user with wildcard permissions** — `"Action": "*"`, `"Resource": "*"`, or `AdministratorAccess` on the principal the application runs as.
  - Look for: `aws_iam_role_policy`, `aws_iam_policy` documents attached to task, Lambda, EC2 instance, or CI roles.
  - Measure: `ensphere cloud iam` policy output for each application principal.
  - Fix: service-specific actions on specific ARNs; permission boundaries on roles created by CI.

- [ ] **Long-lived access keys in application configuration** — static keys in `.env`, container images, or mobile apps instead of a role.
  - Look for: `AWS_ACCESS_KEY_ID` in source, `.env*`, Dockerfiles, CI variables, git history; key age from the CLI output.
  - Measure: `ensphere cloud iam` access-key metadata; `manual: grep source and git history for AKIA and ASIA prefixes`.
  - Fix: IAM roles for compute, OIDC federation for CI, rotate and delete any key found in a repository.

- [ ] **Principal able to create expensive resources** — a compromised or buggy service can run up the bill through `ec2:RunInstances`, `sagemaker:*`, `bedrock:*`, `lambda:CreateFunction`, or `iam:*`.
  - Look for: those actions in application principal policies; absence of service control policies or budgets.
  - Measure: `ensphere cloud iam` policy output; `manual: aws budgets describe-budgets --account-id <id>`.
  - Fix: deny lists for compute creation on application roles; AWS Budgets alerts with actions.

## Trust and escalation

- [ ] **Role trust policy open to any principal or external account** — `"Principal": {"AWS": "*"}` or a foreign account without `sts:ExternalId` or `aws:PrincipalOrgID`.
  - Look for: `assume_role_policy` documents; third-party integrations.
  - Measure: `ensphere cloud iam` on each role.
  - Fix: specific principals; `ExternalId` condition for vendors.

- [ ] **Privilege escalation paths** — `iam:PassRole` with `*`, `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, `lambda:UpdateFunctionCode` on a function with a privileged role.
  - Look for: those actions on non-admin principals.
  - Measure: `ensphere cloud iam` policy output; do not exercise the path.
  - Fix: constrain `PassRole` to named roles; remove policy-mutation actions from application principals.

- [ ] **Missing permission boundary on delegated roles** — roles that can create users or roles without a boundary can mint full-access principals.
  - Look for: `permissions_boundary` on roles used by CI and platform teams.
  - Measure: `ensphere cloud iam` output field for permission boundary.
  - Fix: a boundary policy required by SCP for every created role.

## Account hygiene

- [ ] **Root account with access keys or no MFA** — the root user must have no keys and hardware MFA.
  - Measure: `manual: aws iam get-account-summary and read AccountAccessKeysPresent and AccountMFAEnabled`.
  - Fix: delete root keys; hardware MFA; alarm on root sign-in.

- [ ] **Human users without MFA** — console or API users without an MFA condition.
  - Look for: `aws:MultiFactorAuthPresent` deny policy; IAM Identity Center adoption.
  - Measure: `ensphere cloud iam` MFA output per user; `manual: aws iam generate-credential-report`.
  - Fix: Identity Center with MFA; deny-without-MFA policy for legacy users.

- [ ] **Stale users, roles, and keys** — unused credentials are the ones nobody notices when abused.
  - Measure: `manual: credential report fields password_last_used and access_key_last_used; aws iam get-role last-used metadata`.
  - Fix: remove or disable after ninety days idle.

- [ ] **No Access Analyzer or organization guardrails** — external access grants and dangerous actions go unnoticed.
  - Measure: `manual: aws accessanalyzer list-analyzers --region <region>; aws organizations list-policies --filter SERVICE_CONTROL_POLICY`.
  - Fix: an analyzer per region in use; SCPs denying region sprawl, root usage, and IAM mutation outside a pipeline role.
