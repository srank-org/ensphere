# Session 01: Recon

## Objective

Learn what the project is before deciding what to check. Recon produces a
**stack profile** (what the system is built on and which services bill per
use), a **surface inventory** (endpoints, inputs, identities, objects,
renderers, fetchers, storage, infrastructure), and the **system map** in
the target repository's `.ensphere/` directory, so the next run starts from
what this one learned. Recon never confirms a vulnerability.

Source is always available. The live target is a sandbox, a staging
deployment, or both (contract, Environments): stand up a sandbox in Step 2
by default, add staging for the edge, platform, and drift checks a sandbox
cannot show, and record `environment: none` when there is neither.

## Step 0: Read the map

If `.ensphere/surfaces.yaml` exists, run `ensphere map validate`, read
`.ensphere/map.md`, and run `ensphere map changed` (since the map's
`reconciled_at`, or since the ref in `config.md` for a delta run). The map
is the starting inventory, not the answer: every `missing_files` and
`unmapped_changed_files` entry is something Step 3 must resolve, and a
surface whose files changed is re-read. In a delta run Step 3 covers only
the changed and unmapped files; the rest of the map is kept and still
validated. Without a map, Step 3 builds one.

## Step 1: Learn the stack

Read, in this order, whatever exists at the repository root: `README`, the
package manifest (`package.json`, `go.mod`, `pyproject.toml`, `Gemfile`,
`composer.json`, `pubspec.yaml`) and its lock file, `Dockerfile` and
compose files, platform config (`wrangler.toml`, `vercel.json`,
`netlify.toml`, `fly.toml`, `supabase/config.toml`, `firebase.json`),
Terraform or CDK roots, `.github/workflows`, `.env.example`, and the
top-level layout.

Fill the stack table: one row per dimension (languages, frameworks, data
layers, auth providers, hosting, storage, edge and CDN, billing-exposed
services, background work, clients), the products that fill it as
free-form lowercase names, and the file that proves each. Use `unknown`
rather than guessing. "Billing-exposed" means any component where an
unauthenticated or low-privilege caller can make the owner pay per
invocation, byte, or message; list every one, Session 08.5 checks each.

Then write the role table `shared/fundamentals.md` asks for, one row per
role with the product that fills it or `none`, its evidence, and the file
where it lives, and two or three sentences on what the application does
and for whom. That description drives which checks matter: a public
file-sharing app and an internal admin tool have different abuse surfaces.

## Step 2: Stand up the sandbox

Follow [shared/sandbox.md](../shared/sandbox.md): from what Step 1 found,
write the exact start, seed, and reset commands and ask the operator before
running any of them unless `config.md` already holds them. A missing
runtime is an assessment-level blocker; stop and ask. Complete the
isolation check, seed the synthetic fixtures the file lists, record both in
`01-recon/sandbox.md`, and set `environment: sandbox` in the target
profile. If the isolation check cannot pass, the instance is not a sandbox:
record `staging` or stop.

## Step 3: Inventory the surface

Build these tables. Every row has provenance (file and line, observed
request, or supplied document) and a state: `observed`, `inferred` with its
basis, `unresolved`, or `not_applicable`.

1. **Deployable components**: service, runtime, base URL, source path,
   environment, trust boundary.
2. **Endpoints and operations**: protocol, method, route, auth state, roles,
   content types, billed action or not.
3. **Inputs**: path, query, header, cookie, body, file, and message fields;
   parser; validation; destination sink candidate.
4. **Identity and roles**: login, session, token, API key, OAuth flows,
   roles, tenants, test identities.
5. **Objects and workflows**: identifiers, ownership boundaries, sensitive
   transitions, business invariants.
6. **Render contexts**: templates, DOM sinks, markdown and HTML renderers,
   email, PDF, export.
7. **Outbound fetchers**: webhooks, importers, previews, callbacks, remote
   media, redirects.
8. **Storage and files**: buckets, upload paths, presigned URL issuers,
   public object domains, existing size and type limits.
9. **Rate and cost controls already present**: edge rules, limiters and
   their keys (IP, user, API key), quotas, budget alerts, body-size limits.
   This is the baseline Session 08.5 measures against.
10. **Cloud and infrastructure**: provider identifiers, regions, IaC roots,
    functions, containers, Kubernetes, DNS proxied state.
11. **Trust and data flows**: component-to-component flows, guards,
    sensitive data classes, third-party boundaries.

From source, identify entry points and deployment configuration before
searching for sinks: routes, schemas, handlers, middleware order, auth
checks, ORM calls, renderers, outbound and storage clients, IaC.
`ensphere scan <source> --category <categories>` gives sink candidates
with file and line; a match is a lead, not a finding. From a live target,
use passive navigation, supplied documentation or OpenAPI specs (`ensphere
openapi <spec>`), browser and network observation, and targeted requests to
known paths; fingerprint only from responses that support it. Never
brute-force directories, enumerate subdomains, scan ports, or probe
unrelated infrastructure. Record drift between source and observed traffic.

### Write the map

The inventories above are the per-run record. Their durable subset is the
map, and `01-recon/report.md` points at it instead of repeating it.

`.ensphere/surfaces.yaml` holds one entry per surface a session checks:
every endpoint and operation, every table a policy protects, every bucket
and upload path, function, job, workflow, and platform config item. Each
carries a stable `SURF-NNN` id (never renumber one), its kind and role
from `shared/fundamentals.md`, the identity it expects, the source files
that implement it, and the sessions that own its checks, plus the `stack`
block and `reconciled_at`, the output of `git rev-parse HEAD`. The schema
and vocabulary are in the contract; `ensphere map validate` enforces them.

`.ensphere/map.md` is for the next reader, human or model: what the system
is for in your own words, the role table, the trust boundaries, how to
drive the sandbox (start, seed, reset, the identity placeholders from
`sandbox.md`, how to reach each surface), and the gotchas that cost you
time this run.

## Step 4: Write hypotheses

The role table says which invariants to check; it does not know what this
system is for. From the application description, the objects and workflows
inventory, the data classes, and the billed services, answer the six
questions in `shared/fundamentals.md` (Beyond the map) and write
`01-recon/hypotheses.md` in the table given there: one `HYP-NNN` row per
goal, with what it rests on and its owning session. An empty table carries
its reasoning. The contract (Hypotheses) says how later sessions treat each
row; here they are candidates, and none is probed.

## Target profile

Write `01-recon/target-profile.yaml`; the runner reads it for the plan.

```yaml
target:
  type: web_app        # web_app, api_backend, static_site, mobile_client_remote_backend, mobile_client_offline, desktop_or_extension_client, cloud_only, library_or_cli
  environment: sandbox
  classification_confidence: high
  rationale: ["Next.js app with route handlers and a Supabase backend"]
  evidence_refs: ["01-recon/report.md#deployable-components"]
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
  evidence_refs: ["01-recon/report.md#stack"]
backend_inventory:
  - {name: primary-api, base_url: "http://localhost:3000/api", kind: api_backend, source: source_review, evidence_refs: ["01-recon/report.md#endpoints-and-operations"]}
signals: {browser_ui: true, api_surface: true, server_side_surface: true, authentication: true, authorization_boundaries: true, outbound_fetch_surface: false, cloud_surface: true, billing_exposed_surface: true, storage_surface: true, client_only: false, monorepo_ambiguous: false}
client_exposure_review: []
```

Stack values are free-form lowercase identifiers; use the names in the
Session 01.5 checklist map where one exists so the plan can match them.
The `stack` block is the same in `.ensphere/surfaces.yaml`: the profile is
what the runner reads this run, the map is what persists.

## Completeness gate

Before marking Session 01 `DONE`:

- the selected target, scope, and environment are unambiguous and recorded:
  a sandbox with its isolation check and seeded fixtures, staging with
  fixture data, or `none`;
- `ensphere map validate` passes, `reconciled_at` is the current HEAD, and
  every file `ensphere map changed` reported is now mapped or recorded in
  `map.md` as not a surface;
- every stack row has evidence or `unknown`; every billing-exposed service
  and storage surface is listed; every inventory has provenance or an
  explicit gap; profile signals agree with the inventories;
- `hypotheses.md` exists with every row's basis, or its emptiness is
  reasoned;
- source-versus-live discrepancies and missing accounts, roles, tenants,
  and credentials are listed;
- no candidate has been promoted to a finding.

## Report

Write `01-recon/report.md` with: authorization, source path, live target
and environment tier with a link to `sandbox.md`, and scope; the stack
table and application description; coverage and collection limits; what
the map reconciliation changed; existing rate and cost controls; source
and live drift; candidate index for later sessions with provenance; a
pointer to `hypotheses.md` and to `.ensphere/map.md`; evidence index.

Then proceed to Session 01.5.
