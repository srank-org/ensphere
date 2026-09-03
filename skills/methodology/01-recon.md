# Session 01: Recon

## Objective

Learn what the project is before deciding what to check. Recon produces two
things: a **stack profile** (what the system is built on and which services
bill per use) and a **surface inventory** (endpoints, inputs, identities,
objects, renderers, fetchers, storage, infrastructure). Recon never confirms a
vulnerability.

## Preflight

Confirm and record authorization, the selected deployable target, the source
path, the live target and its environment if one is in scope, explicit scope
and exclusions, available test
identities and tenants, cloud or platform accounts in scope, and collection
limits. If a repository contains several apps or services, identify the
selected deployable unit and its direct dependencies. Do not treat the whole
monorepo as one target.

Source is always available. The live target is a sandbox, a staging
deployment, or both (contract, Environments). Default to standing up a
sandbox in Step 2; it is where proof happens. Use staging in addition when
the project has one, for the edge, platform, and drift checks a sandbox cannot
show. Without any live target, record `coverage_label: source_only` and
`environment: none` and continue with source review.

## Step 1: Learn the stack

Start from the repository root and read, in this order, whatever exists:
`README`, `package.json` or `go.mod` or `pyproject.toml` or `Gemfile` or
`composer.json` or `pubspec.yaml`, lock files, `Dockerfile` and compose files,
`wrangler.toml` or `wrangler.jsonc`, `vercel.json`, `netlify.toml`,
`fly.toml`, `supabase/config.toml`, `firebase.json`, Terraform or CDK roots,
`.github/workflows`, `.env.example`, and the top-level directory layout.

Fill this table. Each dimension collects the products that fill the roles
in `shared/fundamentals.md`; the value is whichever product fills it in this
project, written as a free-form lowercase name. The examples are illustrations, not an allowed list. Every
row cites the file that proves it. Use `unknown` rather than guessing.

| Dimension | Examples of values | Evidence |
|-----------|--------------------|----------|
| Languages | typescript, go, python, dart | |
| Frameworks | nextjs, express, hono, fastapi, django, rails, laravel, spring, gin, chi | |
| Data layers | postgres, supabase_postgres, prisma, drizzle, gorm, mongodb, d1, firestore | |
| Auth providers | supabase_auth, nextauth, clerk, firebase_auth, custom_jwt, session_cookie | |
| Hosting | vercel, cloudflare_workers, cloud_run, lambda, fly, kubernetes, vps | |
| Storage | cloudflare_r2, s3, supabase_storage, gcs, firebase_storage | |
| Edge and CDN | cloudflare_proxy, vercel_edge, none | |
| Billing-exposed services | supabase_edge_functions, cloud_run, lambda, cloudflare_workers, r2, openai, anthropic, twilio, resend, stripe | |
| Background work | queues, cron, webhooks consumed | |
| Clients | web_spa, mobile_flutter, mobile_native, cli | |

"Billing-exposed" means any component where an unauthenticated or
low-privilege caller can make the owner pay per invocation, per byte, or per
message. List every one; Session 08.5 checks each.

Then write the role table `shared/fundamentals.md` asks for in
`01-recon/report.md`: one row per role, the product that fills it or `none`
with evidence, and the file where it lives. Then write, in two or three
sentences, what the application does and who its users are. This sentence drives which checks matter (a public file-sharing app
and an internal admin tool have different abuse surfaces).

## Step 2: Stand up the sandbox

Follow [shared/sandbox.md](../shared/sandbox.md): from what Step 1 found, write
the exact start, seed, and reset commands and ask the operator before running
any of them. A missing runtime is an assessment-level blocker; stop and ask.
Complete the isolation check and seed the synthetic fixtures the file lists,
record both in `01-recon/sandbox.md`, and set `environment: sandbox` in the
target profile. If the isolation check cannot pass, the instance is not a
sandbox: record `staging` or stop.

## Step 3: Inventory the surface

Build these tables. Every row has a provenance reference (file and line,
observed request, or supplied document) and a state: `observed`, `inferred`,
`unresolved`, or `not_applicable`. Inference must name its basis.

1. **Deployable components**: service, runtime, base URL, source path,
   environment, trust boundary.
2. **Endpoints and operations**: protocol, method or operation, route, auth
   state, roles, content types, whether it triggers a billed action.
3. **Inputs**: path, query, header, cookie, body, file, and message fields;
   parser; validation layer; destination sink candidate.
4. **Identity and roles**: login, session, token, API key, OAuth flows,
   roles, tenants, supplied test identities.
5. **Objects and workflows**: resource identifiers, ownership boundaries,
   sensitive state transitions, business invariants.
6. **Render contexts**: server templates, DOM sinks, markdown or HTML
   renderers, email, PDF, export.
7. **Outbound fetchers**: webhooks, importers, previews, callbacks, remote
   media, document renderers, redirect behavior.
8. **Storage and files**: buckets, upload paths, presigned URL issuers,
   public object domains, size and type limits already present.
9. **Rate and cost controls already present**: edge rules, middleware
   limiters, quotas, budget alerts, body-size limits. Record where they are
   and what key they use (IP, user, API key). This is the baseline Session
   08.5 measures against.
10. **Cloud and infrastructure**: provider identifiers, regions, IaC roots,
    serverless functions, containers, Kubernetes, DNS proxied state.
11. **Trust and data flows**: component-to-component flows, guards,
    sensitive data classes, third-party boundaries.

### From source

Identify entry points and deployment configuration before searching for sinks.
Extract routes, schemas, handlers, middleware ordering, auth checks, ORM
calls, renderers, outbound clients, storage clients, and IaC assets. Run
`ensphere scan <source> --category <categories>` for sink candidates and cite
file and line; a pattern match is a lead, not a finding. Compare the source
inventory with observed traffic when a live target exists and record drift.

### From the live target

Use passive navigation, supplied documentation or OpenAPI specs (`ensphere
openapi <spec>`), browser and network observation, and targeted requests to
known paths. Fingerprint technologies only when responses support the
inference. Do not brute-force directories, enumerate subdomains, scan ports,
or probe unrelated infrastructure.

## Target profile

Write `01-recon/target-profile.yaml`:

```yaml
target:
  type: web_app
  environment: sandbox
  coverage_label: partial
  classification_confidence: high
  rationale:
    - "Next.js app with route handlers and a Supabase backend"
  evidence_refs:
    - "01-recon/report.md#deployable-components"
stack:
  languages: [typescript]
  frameworks: [nextjs]
  data_layers: [supabase_postgres, prisma]
  auth_providers: [supabase_auth]
  hosting: [vercel]
  storage: [cloudflare_r2]
  edge: [cloudflare_proxy]
  billing_exposed_services: [supabase_edge_functions, cloudflare_r2, openai]
  clients: [web_spa, mobile_flutter]
  evidence_refs:
    - "01-recon/report.md#stack"
backend_inventory:
  - name: primary-api
    base_url: "https://staging.example.invalid/api"
    kind: api_backend
    source: source_review
    evidence_refs:
      - "01-recon/report.md#endpoints-and-operations"
signals:
  browser_ui: true
  api_surface: true
  server_side_surface: true
  authentication: true
  authorization_boundaries: true
  outbound_fetch_surface: false
  cloud_surface: true
  billing_exposed_surface: true
  storage_surface: true
  client_only: false
  monorepo_ambiguous: false
client_exposure_review: []
```

Stack values are free-form lowercase identifiers; use the names from the
checklist map in Session 01.5 where one exists so the plan can match them.

## Completeness gate

Before marking Session 01 `DONE`:

- the selected target and scope boundary are unambiguous;
- the environment is recorded: a sandbox with a completed isolation check
  and seeded fixtures, a staging deployment with fixture data, or `none`;
- the stack table has an evidence reference or `unknown` in every row;
- every billing-exposed service and storage surface is listed;
- every inventory has provenance or an explicit gap;
- source and live discrepancies are recorded;
- missing accounts, roles, tenants, and credentials are listed;
- profile signals agree with the inventories;
- no candidate has been promoted to a finding.

## Report

Write `01-recon/report.md` with: authorization, source path, live target and
environment tier with a link to `sandbox.md`, and scope; the
stack table and application description; coverage and collection limits;
each inventory; existing rate and cost controls; source and live drift;
candidate index for later sessions with provenance; evidence index.

Then proceed to Session 01.5.
