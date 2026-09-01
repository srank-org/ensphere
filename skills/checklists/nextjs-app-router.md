# Next.js App Router Checklist

Load this checklist when recon records `next` in `package.json` together with an `app/` directory. It covers Server Actions, Route Handlers, `middleware.ts`, React Server Components, caching, and the image optimizer. Data-layer checks belong to the ORM or Supabase checklists; shared cost and rate-limit concerns are in `abuse-and-cost.md`.

## Server Actions

- [ ] **Server Action without an authorization check** — every exported `'use server'` function is a public POST endpoint, regardless of which page renders it.
  - Look for: `'use server'` files and inline actions; whether each reads the session before touching data; actions exported from shared modules.
  - Measure: `ensphere verify csrf --url <origin>/<page-that-renders-the-action> --method POST --in-scope <host>` establishes origin handling; then `manual: invoke the action with the Next-Action header of an unauthenticated session and record status and body`.
  - Fix: call the auth helper at the top of every action; return early with a generic error.

- [ ] **Error details returned from actions** — thrown errors and database messages reach the client in the action result during development and in `error.tsx` boundaries.
  - Look for: `throw new Error(err.message)`, returning `error.stack`, `error.tsx` rendering `error.message` directly.
  - Measure: `manual: trigger a validation failure and a database failure with a test account; record whether stack traces, table names, or file paths appear`.
  - Fix: map errors to fixed messages; log details server-side.

## Middleware

- [ ] **Matcher leaves protected routes uncovered** — `middleware.ts` only runs for paths in `config.matcher`; Route Handlers and pages outside it have no middleware auth.
  - Look for: `export const config = { matcher: [...] }`; every `app/**/route.ts` and page path that the matcher patterns do not include; default exclusions of `_next` and static assets.
  - Measure: for each unmatched protected route `ensphere verify auth --technique no_token --url <origin>/<route> --token <valid-session-token> --in-scope <host>`.
  - Fix: perform authorization inside each handler and action as well; treat middleware as a redirect convenience, not the control.

- [ ] **Middleware depends on a spoofable header** — decisions keyed on `x-middleware-subrequest`, `x-forwarded-host`, or custom headers can be forged unless the platform strips them.
  - Look for: `request.headers.get(...)` used in auth decisions; Next.js version against known middleware bypass advisories.
  - Measure: `manual: send the protected request with the header set from outside and record the response; confirm the Next.js version in package.json`.
  - Fix: upgrade Next.js; never authorize on client-supplied headers.

## Route Handlers

- [ ] **Route Handler missing auth or method restrictions** — `app/api/**/route.ts` handlers are reachable directly and may export more methods than the UI uses.
  - Look for: exported `GET/POST/PUT/PATCH/DELETE` per file; handlers reading session; `export const dynamic`.
  - Measure: `ensphere verify auth --technique no_token --url <origin>/api/<route> --token <valid-session-token> --in-scope <host>`; for role boundaries `ensphere verify authz --url <origin>/api/<route> --low-token <user> --high-token <admin> --in-scope <host>`.
  - Fix: shared auth helper per handler; remove unused method exports.

- [ ] **Route parameters used unsanitized** — `[id]` and `[...slug]` values flow into queries, file paths, or redirects.
  - Look for: `params.id` passed to raw SQL, `fs` calls, `fetch(...)`, or `redirect()`.
  - Measure: `ensphere verify sqli --url <origin>/api/items/<id> --param id --db <engine> --technique error_based --in-scope <host>`; `ensphere verify redirect --url <origin>/login --param next --in-scope <host>`.
  - Fix: parameterized queries, allowlisted redirect targets, path joins constrained to a base directory.

## Data exposure and caching

- [ ] **Server Component props leak fields to the client** — everything passed from a Server Component to a Client Component is serialized into the HTML payload.
  - Look for: full database rows passed as props; `__next_f` payload in page source.
  - Measure: `manual: load an authenticated page as a test user and search the HTML for fields the UI never shows (email, role, tokens, other users)`.
  - Fix: select only rendered fields; use the `server-only` package for data modules.

- [ ] **Cache keyed without tenant or user** — `unstable_cache`, `fetch` cache, and `force-static` segments serve one user's data to another when the key omits identity.
  - Look for: `unstable_cache(fn, [key])` keys, `export const dynamic = 'force-static'` on pages that call `cookies()` or `headers()`.
  - Measure: `manual: request the same URL with two tenant sessions, compare bodies for cross-tenant data`.
  - Fix: include user or tenant identifiers in cache keys; mark personalized segments dynamic.

- [ ] **Revalidation endpoint callable without a secret** — an `/api/revalidate` handler that calls `revalidatePath` or `revalidateTag` from user input lets anyone purge or churn the cache.
  - Look for: handlers calling `revalidatePath`/`revalidateTag`; secret comparison; path taken from the request.
  - Measure: `ensphere verify auth --technique no_token --url <origin>/api/revalidate --token <secret-bearing-request-token> --in-scope <host>`.
  - Fix: require a shared secret or signed webhook; allowlist revalidation targets.

## Rate limiting and abuse

- [ ] **No limiter in front of actions and handlers** — Next.js ships no rate limiting; without one, sign-in, sign-up, contact forms, AI calls, and uploads can be invoked at will.
  - Look for: `@upstash/ratelimit`, `rate-limiter-flexible`, Vercel Firewall rate rules, or a Cloudflare rate-limiting rule covering each expensive action; `serverActions.bodySizeLimit` in `next.config.js`; `export const maxDuration`.
  - Measure: `manual: list every action and handler that sends email, calls a paid API, writes storage, or runs a heavy query, and whether a limiter wraps it`; with operator approval `ensphere verify ratelimit --url <origin>/api/<route> --method POST --burst-count <approved> --window-sec 10 --in-scope <host>`.
  - Fix: a keyed limiter (user ID or IP) per expensive action; platform-level rules as the outer layer.

- [ ] **Image optimizer open to arbitrary origins** — `/_next/image?url=...` fetches and transforms remote images on your compute budget.
  - Look for: `images.remotePatterns` or `images.domains` with wildcards; `unoptimized` setting.
  - Measure: `manual: request /_next/image?url=<url-on-a-domain-you-control>&w=1200&q=75 and record status`.
  - Fix: exact `remotePatterns`; disable the optimizer for user-supplied URLs.

## Headers and static files

- [ ] **Missing security headers** — no CSP, HSTS, or frame options from `next.config.js` `headers()` or middleware.
  - Look for: `headers()` in `next.config.js`; CSP nonce handling in `layout.tsx`.
  - Measure: `ensphere verify clickjacking --url <origin>/ --in-scope <host>`; `manual: record Content-Security-Policy, Strict-Transport-Security, and X-Content-Type-Options on the home page`.
  - Fix: header block in `next.config.js`; nonce-based CSP.

- [ ] **Sensitive files in `public/` or served by the host** — `.env`, source maps, and backups inside `public/` are world-readable.
  - Look for: `public/**` contents; `productionBrowserSourceMaps: true`.
  - Measure: `manual: GET /.env, /.env.local, /.git/config, /next.config.js and expect 404 for each`.
  - Fix: remove the files; keep secrets out of the build directory.
