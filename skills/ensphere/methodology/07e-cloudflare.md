# Cloudflare Read-Only Appendix — Session 07

Use this appendix when a Cloudflare account, zone, Worker, or R2 bucket is
explicitly in scope. It inherits [07-cloud.md](07-cloud.md).

## Binding Boundary

Collect configuration metadata only. Never modify rulesets, purge cache,
rotate or read secret values, deploy Workers, or read KV, D1, or R2 object
contents. Object listing is not authorized; bucket-level metadata is.

## Preflight

Record the expected account ID, zone IDs, hostnames, Workers, and buckets.
Verify the active identity:

```bash
wrangler --version
wrangler whoami
```

If `wrangler` is missing or unauthenticated, tell the operator exactly:

```bash
npm i -g wrangler
wrangler login
```

Do not install or log in on the operator's behalf without permission. Until
the operator does so, record live Cloudflare checks as `blocked` with the
missing prerequisite and continue with the source lane below.

API alternative: an operator-supplied token in `CLOUDFLARE_API_TOKEN` with
read-only scopes (Zone Read, Account Settings Read, Workers Scripts Read, R2
Read). Use `GET` requests only. Stop if `whoami` reports an account outside the
authorized scope.

## Source Lane (no CLI required)

Review `wrangler.toml` / `wrangler.jsonc` in the repository and cite file/line:

- `name`, `main`, `compatibility_date`, `workers_dev`, `routes`/`route`,
  custom domains;
- bindings: `r2_buckets`, `kv_namespaces`, `d1_databases`, `queues`,
  `durable_objects`, `services`, `ai`, `vars` (names only, flag any literal
  secret value as a finding candidate);
- per-environment overrides (`[env.*]`) that differ from production;
- absence of any rate-limiting binding or middleware in the Worker source
  that fronts a bucket, database, AI, or paid third-party call.

## Live Inventory

### Workers and bindings

```bash
wrangler deployments list
wrangler secret list            # names only
wrangler kv namespace list
wrangler d1 list
```

Record deployed Worker names, routes, `workers.dev` enablement, binding names,
and secret names. Never print secret values.

### R2

```bash
wrangler r2 bucket list
wrangler r2 bucket info <name>
wrangler r2 bucket cors list <name>
wrangler r2 bucket lifecycle list <name>
wrangler r2 bucket domain list <name>
```

Record per bucket: location, public `r2.dev` access state, custom domains and
whether each is proxied, CORS origins/methods/headers, lifecycle rules (or
their absence), and object count/size metadata if `info` returns it. Do not
list or fetch objects.

### Zone controls (API GET only)

For each in-scope zone, collect and record as facts:

- rate-limiting rules: `GET /zones/{zone_id}/rulesets` filtered to phase
  `http_ratelimit` — record each rule's expression, threshold, period, and
  action, and which routes/hostnames have no rule;
- WAF custom rules (`http_request_firewall_custom`) and managed-ruleset
  deployment state;
- Bot Fight Mode / Bot Management settings (`/zones/{zone_id}/bot_management`);
- Turnstile widgets: `GET /accounts/{account_id}/challenges/widgets` — record
  widget hostnames and mode, and which login/signup/contact forms in the
  recon inventory have no widget;
- Access applications and policies protecting admin or internal hostnames;
- cache rules and `cache_level`/`browser_cache_ttl` for expensive routes;
- DNS records: proxied (orange-cloud) versus DNS-only (grey-cloud). A DNS-only
  record for an origin hostname is an exposure fact: requests to it bypass
  WAF, rate limiting, and Bot Management.

### Billing exposure

Record where visible: Workers plan (free/paid), R2 storage and Class A/B
operation usage, egress via custom domains, Workers AI usage, and whether
notification or budget alerts are configured under account notifications.
Absence of an alert is a fact for Session 08.5.

## Report Additions

Include the account/zone/Worker/bucket scope, active identity, per-route
rate-limiting coverage, unproxied hostnames, public R2 state and custom
domains, CORS and lifecycle facts, Turnstile/Access coverage against the
recon form and admin inventory, binding inventory, and any `blocked` checks
with the exact prerequisite the operator must supply.
