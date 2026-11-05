# Cloudflare Workers and Pages Functions

Load this checklist when recon finds `wrangler.toml` or `wrangler.jsonc`, a
`functions/` directory in a Pages project, `@cloudflare/workers-types`, or
routes served from `*.workers.dev` or `*.pages.dev`. This file covers the
platform: bindings, routes, secrets, limits, and the Cloudflare-side controls.
Framework specifics live in `hono.md`; R2 bucket configuration lives in
`cloudflare-r2.md`. Facts come from the wrangler config, the Worker source,
and read-only `wrangler` commands (`wrangler whoami`, `wrangler deployments
list`, `wrangler r2 bucket list`, `wrangler kv namespace list`,
`wrangler d1 list`). If `wrangler` is missing or not logged in, ask the
operator to install it and run `wrangler login`, and record the live checks
as blocked until then.

## Exposure and routing

- [ ] **`workers.dev` subdomain still enabled** — the `<name>.<account>.workers.dev` hostname bypasses the zone's WAF, rate-limiting rules, and Access policies that only apply to the custom domain.
  - Look for: `workers_dev = true` (or absent, which defaults to true on first deploy) in `wrangler.toml`; `preview_urls`; whether the dashboard shows the workers.dev route enabled.
  - Measure: `manual: with the operator-supplied workers.dev hostname, send one baseline request and record whether it answers and which cf-* headers are present.`
  - Fix: set `workers_dev = false`, disable preview URLs, and serve only through `routes` or `custom_domain` entries in the zone.

- [ ] **Routes without zone-level rate limiting** — a Worker on `example.com/api/*` has no limiter unless a rate-limiting rule or a Rate Limiting binding exists.
  - Look for: `routes` and `custom_domain` entries; a `[[unsafe.bindings]]` or `[[ratelimits]]` binding (`type = "ratelimit"`) in the config; zone rate-limiting rules in the dashboard or Terraform (`cloudflare_ruleset` with `phase = "http_ratelimit"`).
  - Measure: `ensphere verify ratelimit --url https://<domain>/api/<route> --method POST --burst-count <approved> --window-sec 10 --in-scope <domain>`.
  - Fix: add a zone rate-limiting rule on the path, or use the Workers Rate Limiting binding keyed by user id, or a Durable Object counter for exact limits.

- [ ] **Admin or internal routes without Access** — dashboards, cron endpoints, and debug routes exposed on the public hostname with only application auth.
  - Look for: routes matching `/admin`, `/internal`, `/debug`, `/cron`; Cloudflare Access application policies for those paths; `Cf-Access-Jwt-Assertion` validation in the Worker.
  - Measure: `ensphere verify auth --url https://<domain>/admin --token <valid-jwt> --technique no_token --in-scope <domain>`.
  - Fix: put admin paths behind Cloudflare Access and validate the Access JWT in the Worker.

- [ ] **Signup and login without Turnstile** — public forms served by the Worker are open to automated abuse.
  - Look for: `challenges.cloudflare.com/turnstile` script on the form; server-side `siteverify` call in the handler.
  - Measure: `manual: source review; record whether the token is verified server-side before the action runs.`
  - Fix: add Turnstile and verify the token in the Worker before creating accounts or sending email.

## Bindings

- [ ] **R2 binding used without size or key constraints** — `env.BUCKET.put(key, body)` with a caller-controlled key or unbounded body lets any caller overwrite objects or fill the bucket.
  - Look for: `[[r2_buckets]]` bindings; `.put(` calls; whether the key is derived from the authenticated user; `request.headers.get("content-length")` checks; multipart upload handlers.
  - Measure: `ensphere verify fileupload --url https://<domain>/api/upload --field file --filename probe.txt --technique content_type_mismatch --in-scope <domain>` then `manual: request an upload with an approved oversized content-length and record the status.`
  - Fix: prefix keys with the user id, reject bodies over a byte cap before streaming, and validate content type.

- [ ] **D1 queries built by string concatenation** — D1 is SQLite; `env.DB.prepare("SELECT ... WHERE id = " + id)` is SQL injection.
  - Look for: `[[d1_databases]]` bindings; `.prepare(` calls with template literals or concatenation instead of `.bind(...)`.
  - Measure: `ensphere verify sqli --url "https://<domain>/api/items?id=1" --param id --db sqlite --technique blind_boolean --in-scope <domain>`.
  - Fix: always use `.prepare(sql).bind(params)`; never interpolate.

- [ ] **Workers AI callable by unauthenticated requests** — `env.AI.run(...)` is billed per neuron; a public route that calls it is a cost sink.
  - Look for: `[ai]` binding; the auth check preceding `env.AI.run`; a per-user counter.
  - Measure: `ensphere verify auth --url https://<domain>/api/ai --method POST --token <valid-jwt> --technique no_token --in-scope <domain>`.
  - Fix: require authentication, add a limiter before the call, and set a Workers AI usage notification.

- [ ] **KV or Durable Object keys derived from caller input** — a caller-controlled key reads or writes another user's entry.
  - Look for: `env.KV.get(request.url...)`, `idFromName(userSuppliedValue)`.
  - Measure: `ensphere verify authz --url https://<domain>/api/state/<id> --low-token <user-a-jwt> --high-token <user-b-jwt> --in-scope <domain>` using an object owned by user B.
  - Fix: namespace keys with the verified user id and never accept a raw key from the client.

- [ ] **Queues and cron triggers with unauthenticated producers** — a route that enqueues work or a cron handler exposed as an HTTP path can be spammed.
  - Look for: `[[queues.producers]]`, `[triggers] crons`, `scheduled()` handlers, any `fetch` path that calls `env.QUEUE.send`.
  - Measure: `ensphere verify auth --url https://<domain>/api/enqueue --method POST --token <valid-jwt> --technique no_token --in-scope <domain>`.
  - Fix: authenticate producers, cap batch sizes, and keep scheduled logic in `scheduled()` rather than an HTTP route.

## Secrets and configuration

- [ ] **Secrets stored as `vars`** — `[vars]` values are plain text in the config and in the dashboard; only `wrangler secret put` values are encrypted.
  - Look for: API keys, tokens, or connection strings under `[vars]` or in `.dev.vars` committed to git.
  - Measure: `manual: source and git-history review; list every secret-looking value under [vars].`
  - Fix: move them to `wrangler secret put`, rotate any committed value, and add `.dev.vars` to `.gitignore`.

- [ ] **Permissive CORS in the Worker** — a hand-written CORS block that reflects `Origin` or returns `*` with credentials.
  - Look for: `Access-Control-Allow-Origin` construction in the fetch handler or Hono `cors()` middleware options.
  - Measure: `ensphere verify cors --url https://<domain>/api/<route> --in-scope <domain>`.
  - Fix: allowlist exact origins and never combine `*` with credentials.

- [ ] **Origin reachable around Cloudflare** — when the Worker proxies to an origin server, that origin may accept traffic directly and lose every Cloudflare control.
  - Look for: origin hostnames in the Worker (`fetch("https://origin.example.com")`), DNS records not proxied (grey cloud), missing authenticated origin pulls or origin firewall rules.
  - Measure: `manual: only with an operator-supplied origin hostname, send one baseline request directly to it and record whether it answers.`
  - Fix: restrict the origin to Cloudflare IP ranges, enable authenticated origin pulls, or use Cloudflare Tunnel.
