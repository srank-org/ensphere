# Hono Checklist

Load this checklist when recon finds `hono` in `package.json` (or a `deno.json`
/ `bun.lockb` importing `hono`). It applies to Hono running on Cloudflare
Workers, Bun, Node, Deno, Vercel, or Lambda. Pair it with `cloudflare-workers.md`
when deployed on Workers, `prisma-drizzle.md` for the data layer, and
`abuse-and-cost.md` for billing-exposed routes.

## Routing and middleware

- [ ] **Auth middleware registered after routes or on a narrower path** — Hono applies middleware in registration order and only to matching paths, so `app.get('/admin', ...)` declared before `app.use('/admin/*', auth)` or a mount at `/api` with auth at `/api/v1/*` leaves routes unauthenticated.
  - Look for: the order of `app.use(...)` versus `app.get/post(...)`; path patterns on `app.use` (`'/api/*'` vs `'/api'`); routes added through `app.route('/x', sub)` where `sub` has no middleware of its own.
  - Measure: `ensphere verify auth --url <protected-endpoint> --token <valid-token> --technique no_token --in-scope <pattern>` for every route that should require auth; repeat for a sample of sub-app routes.
  - Fix: register `app.use('*', auth)` (or per-prefix) before any route, or attach auth inside each sub-app so mounting order does not matter.

- [ ] **Sub-app mounts without their own guard** — `app.route('/internal', internalApp)` inherits nothing; if the guard lives on the parent at a different prefix, the sub-app is open.
  - Look for: `app.route(` calls and whether the mounted app declares `use(...)` guards.
  - Measure: `ensphere verify authz --url <sub-app-endpoint> --low-token <user-token> --high-token <admin-token> --in-scope <pattern>`.
  - Fix: put guards in the sub-app file next to its routes.

- [ ] **Method or path variants bypassing a guard** — a guard on `app.get` only, or a route also matched by `app.all`, exposes the same handler through another method.
  - Look for: `app.all(`, `app.on([...], ...)`, and guards applied per-method.
  - Measure: `ensphere verify auth --url <endpoint> --token <valid-token> --technique method_override --in-scope <pattern>`.
  - Fix: guard with `app.use` on the path, not per method.

## Authentication helpers

- [ ] **`hono/jwt` or `bearerAuth` misconfigured** — a `secret` read from an unset env binding becomes `undefined`, `alg` left permissive, or `bearerAuth({ token })` with a static token committed in source.
  - Look for: `jwt({ secret: c.env.JWT_SECRET })` with no startup check; `alg` option; `bearerAuth({ token: '...' })` literals; `verify(token, secret)` without `alg` pin.
  - Measure: `ensphere verify auth --url <endpoint> --token <valid-jwt> --technique alg_none --in-scope <pattern>` and `--technique expired_token`.
  - Fix: fail startup when the secret binding is missing, pin `alg: 'HS256'` (or the RS/ES algorithm actually used), keep tokens in secrets bindings.

- [ ] **Cookie sessions without CSRF protection** — form or fetch endpoints authenticated by cookie accept cross-site POSTs unless `hono/csrf` (origin check) or SameSite cookies are set.
  - Look for: `setCookie(` / `getCookie(` for session cookies; absence of `csrf()` middleware; `SameSite` attribute.
  - Measure: `manual: send a state-changing POST with the session cookie and an Origin header from another site; record status. One request.`
  - Fix: `app.use(csrf({ origin: [...] }))` and `SameSite=Lax` or `Strict` with `Secure`.

## Cross-origin and headers

- [ ] **CORS reflecting any origin with credentials** — `cors({ origin: (o) => o })` or `origin: '*'` together with `credentials: true` lets any site read authenticated responses.
  - Look for: `cors(` options; callbacks that return the incoming origin unconditionally.
  - Measure: `ensphere verify cors --url <endpoint> --in-scope <pattern>`.
  - Fix: an explicit origin allowlist; never combine wildcard or reflection with `credentials: true`.

- [ ] **Security headers absent** — no `secureHeaders()` means no `X-Frame-Options`, CSP, or `nosniff` on HTML responses.
  - Look for: `secureHeaders(` usage.
  - Measure: `ensphere verify clickjacking --url <html-endpoint> --in-scope <pattern>`.
  - Fix: `app.use(secureHeaders())` with a CSP tailored to the app.

## Input handling

- [ ] **`c.req.json()` or `c.req.query()` used without schema validation** — untyped input flows into queries, storage keys, and outbound requests.
  - Look for: `await c.req.json()` / `c.req.query(` / `c.req.param(` not followed by a validator; absence of `@hono/zod-validator` or `validator(`.
  - Measure: `ensphere verify sqli --url "<endpoint>?<param>=1" --param <param> --db <engine> --technique blind_boolean --in-scope <pattern>` for query-backed params; `ensphere verify lfi --url "<endpoint>?<param>=x" --param <param> --in-scope <pattern>` for params used in paths.
  - Fix: `zValidator('json', schema)` on every route that reads a body, query, or param.

- [ ] **`serveStatic` root or path parameter exposing files** — a broad `root`, or `c.req.param('file')` joined into a path, serves files outside the intended directory.
  - Look for: `serveStatic({ root: '.' })`, `serveStatic({ path: ... })`, manual `readFile(join(dir, param))`.
  - Measure: `ensphere verify lfi --url "<endpoint>?<param>=x" --param <param> --in-scope <pattern>`.
  - Fix: a dedicated `public/` root, `rewriteRequestPath` to a fixed prefix, and reject any resolved path outside the root.

- [ ] **Error handler leaking stack traces** — the default `onError` returns `500` with the message; custom handlers often return `err.stack`.
  - Look for: `app.onError(` body; `c.text(err.stack)` / `c.json({ error: err })`.
  - Measure: `manual: send one malformed JSON body to a JSON endpoint and record whether the response contains a stack frame or file path.`
  - Fix: log the error server-side, return a generic message and request ID.

## Resource limits

- [ ] **No rate limiting on write, auth, or expensive routes** — Hono ships no limiter; login, signup, OTP, upload, search, export, and any route that calls a paid API are unbounded unless `hono-rate-limiter` (with a shared store) or a platform rule exists.
  - Look for: `hono-rate-limiter` / `rateLimiter(` and its `store` (in-memory store is per-instance and resets on cold start); Cloudflare rate-limiting rules or a Durable Object counter when on Workers.
  - Measure: `ensphere verify ratelimit --url <login-or-expensive-endpoint> --method POST --body '<benign body>' --burst-count <operator-approved N> --window-sec 10 --in-scope <pattern>`; record whether any 429 appears within the approved burst.
  - Fix: a limiter keyed by user or IP with a shared store (KV, Durable Object, Redis/Upstash), plus an edge rate-limiting rule for unauthenticated routes. See `abuse-and-cost.md`.

- [ ] **Streaming or long-running responses without bounds** — `stream()` / `streamSSE()` handlers that loop on user input or proxy upstream bodies without size or time limits hold instances open.
  - Look for: `stream(c, async (s) => ...)`, `streamSSE(`, proxying `fetch(url).body` where `url` derives from input.
  - Measure: `manual: from source, record whether each streaming handler has a maximum duration, byte cap, or abort on client disconnect.`
  - Fix: `AbortSignal.timeout`, byte counters, and `c.req.raw.signal` handling.

- [ ] **Large or unbounded request bodies** — `c.req.json()` and `c.req.parseBody()` read the whole body; without a limit a single client can exhaust memory or upload budget.
  - Look for: `bodyLimit(` middleware from `hono/body-limit`; `parseBody(` on upload routes.
  - Measure (planned): `ensphere verify limits --technique upload_size --url <upload-endpoint> --sizes 1048576,10485760 --in-scope <pattern>` with operator-approved sizes.
  - Fix: `app.use(bodyLimit({ maxSize: ... }))` per route class; direct-to-storage uploads with size-constrained presigned URLs.
