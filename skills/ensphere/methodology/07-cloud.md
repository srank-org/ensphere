# Session 07: Cloud Security

## Objective

Assess authorized cloud, Kubernetes, container, and infrastructure-as-code
configuration using read-only facts. Do not execute privilege escalation,
retrieve secrets, or modify resources.

The shared workflow and this file override any broader example in a provider
appendix.

## Scope and Collection

Record the exact authorized providers and account/project/subscription/tenant
identifiers; regions, clusters, namespaces, registries, repositories, and
environments; principals/credentials and their intended read-only role; IaC
roots, state/backend availability, images/manifests, and scanner artifacts;
and prohibited APIs, data classes, production restrictions, and request
limits.

Validate the active provider/cluster identity before collecting facts. Never
infer scope from whichever credentials happen to be installed.

Coverage rows cover identity/policy, storage, network exposure,
compute/serverless, containers/Kubernetes, encryption/key management, logging
and monitoring, secrets configuration metadata, backups/recovery, and IaC
drift, one set per provider/region/cluster.

If cloud surface exists but authorized read access is absent, run only the IaC
or supplied-artifact lane and mark the live rows `blocked`. Missing
credentials do not make cloud security not applicable.

### Missing tooling

When a provider CLI or MCP server is missing, unauthenticated, or linked to
the wrong account, tell the operator the exact install and login command from
the provider appendix (for example `wrangler login`, `supabase link
--project-ref <ref>`, `gcloud auth login`). Do not install tooling or
authenticate on the operator's behalf without permission. Record every
affected check as `blocked` with the named prerequisite, continue with the
source/IaC lane, and re-run the live lane once the operator confirms.

### Provider and Kubernetes metadata

Use read-only list/describe/get APIs to collect resource identifiers,
configuration, policy documents, public-access state, encryption/logging flags,
network rules, role bindings, workload security context, and audit settings.

Do not read secret values, object bodies, database rows, workload environment
variables, instance user data, identity tokens, or credential material. Do not
assume roles, impersonate service accounts, exec into workloads, attach
policies, create resources, or change configuration.

### IaC and manifest review

Review Terraform, CloudFormation, provider templates, Kubernetes manifests,
Helm output, Dockerfiles, and policy-as-code artifacts. Cite exact file/line and
the deployed environment when known. A source misconfiguration is not proof of
live exposure; record drift uncertainty.

### Operator-supplied scanner output

The analyst may read Prowler, Trivy, or other scanner output the operator
supplies as leads, preserving the tool, version, rule ID, and source severity;
no Ensphere command ingests it. Corroborate any lead with read-only provider
facts or source evidence before it becomes a finding.

## Candidate Validation

For each candidate, state a narrow policy/configuration claim and compare:

- the resource configuration;
- the effective policy or binding as represented by the provider;
- relevant organization/project/namespace guardrails;
- network and identity prerequisites;
- an expected secure configuration or known in-scope control.

Where provider policy simulation APIs are available, simulate the exact action
and resource without performing it. Label simulations as simulations, in the
evidence and in the report.

For public storage or content exposure, prefer configuration and policy facts.
Only when the operator supplies a non-sensitive canary object and expressly
authorizes it may a single anonymous `HEAD`/metadata request be used. Do not
list containers or retrieve object bodies.

Permission combinations and cross-session chains are attack-path hypotheses or
risk scenarios unless every edge was directly observed. Do not execute role
assumption, policy mutation, workload creation, metadata credential access, or
internal lateral movement to confirm a chain.

## Provider Appendices

Read only appendices for providers actually in scope:

- [07a AWS](07a-aws.md)
- [07b GCP](07b-gcp.md)
- [07c Azure](07c-azure.md)
- [07d Kubernetes](07d-k8s.md)
- [07e Cloudflare](07e-cloudflare.md)
- [07f Supabase](07f-supabase.md)

Treat commands in those files as inventory examples, not a mandatory command
list. Skip any example that retrieves secret/content values, changes state,
assumes identity, executes in a workload, or conflicts with current scope.

## Stop Rules

Stop a candidate when the configuration/effective-policy claim is resolved,
the provider request limit is reached, identity/scope changes, required data
would be sensitive, or the next action would mutate state or execute an
escalation. Preserve unavailable regions/services as coverage gaps.

The session report names the exact provider/account/region/cluster and
identity scope, and never publishes secret values, account credentials,
object content, tokens, or personal data.
