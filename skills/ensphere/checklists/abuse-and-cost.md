# Abuse and Cost Controls

Load this checklist for every target that has a live backend, regardless of
stack. Recon signals: any authenticated or public HTTP endpoint, any upload or
storage surface, any billed third-party call (email, SMS, AI, payments), or any
pay-per-invocation host (Supabase Edge Functions, Cloud Run, Lambda, Vercel
functions, Cloudflare Workers). The question for every item is the same: can an
unauthenticated or low-privilege caller make the system do expensive work, or
run up the owner's bill, faster than the owner intended? Ensphere records raw
counts and status codes from bounded, operator-approved bursts. The analyst
decides whether a limiter is absent, present at the wrong layer, or adequate.
Never load-test, never distribute sources, never evade a limiter.

## Endpoint classes that need a limiter

- [ ] **Credential endpoints have no limiter** — login, signup, password reset, OTP and magic-link send/verify, and MFA verify are the first targets for stuffing, enumeration, and SMS/email cost abuse.
  - Look for: route handlers for `/login`, `/signup`, `/register`, `/forgot-password`, `/reset`, `/otp`, `/verify`, `/magic-link`; rate-limit middleware on those routes (`express-rate-limit`, `@upstash/ratelimit`, `rack-attack`, `django-ratelimit`, Laravel `throttle:`, `golang.org/x/time/rate`, `hono-rate-limiter`); auth-provider limits (Supabase Auth rate limits in the dashboard or `config.toml [auth.rate_limit]`).
  - Measure: `ensphere verify ratelimit --url <target>/api/login --method POST --body '{"email":"test@example.invalid","password":"x"}' --burst-count <approved> --window-sec 10 --in-scope <pattern>`. Record `first_throttle_at`, status counts, and response headers.
  - Fix: sliding-window limiter keyed by IP and by target account (e.g. `@upstash/ratelimit` with Redis, Cloudflare rate-limiting rule on the path), plus provider-side auth limits.

- [ ] **Send endpoints have no per-user cap** — any route that sends email, SMS, or push (invites, notifications, verification resend, contact forms) bills the owner per message.
  - Look for: calls to Resend, SendGrid, Postmark, Twilio, SNS, FCM, APNs, `nodemailer`; whether the caller identity and a daily cap are checked before the call.
  - Measure: `manual: with an owned test account and operator approval, send the resend/invite request a small approved number of times (e.g. 5) within one minute; record status codes and whether the provider was actually called (check the provider log or a sink mailbox).`
  - Fix: per-user and per-destination counters in Redis or the database, a global daily budget check, and CAPTCHA (Turnstile, hCaptcha) on unauthenticated forms.

- [ ] **AI, image, PDF, or export endpoints are unmetered** — LLM calls, image transforms, PDF rendering, report generation, and bulk exports are CPU- or bill-heavy per request.
  - Look for: `openai`, `@anthropic-ai/sdk`, `sharp`, `puppeteer`, `playwright`, `pdfkit`, `wkhtmltopdf`, `ffmpeg`, `csv-stringify`, background job enqueues; whether the handler checks a per-user quota before starting work.
  - Measure: `ensphere verify ratelimit --url <target>/api/generate --method POST --body <benign minimal body> --token <test-user-jwt> --burst-count <approved small number> --window-sec 30 --in-scope <pattern>`.
  - Fix: per-user quota keyed by user id in a shared store, queue with concurrency limits, and result caching keyed by input hash.

- [ ] **Search and autocomplete are unbounded** — free-text search with no limiter and no minimum length becomes a database-load amplifier.
  - Look for: `LIKE '%...%'`, `ILIKE`, full-text queries on every keystroke, no `limit` clause, no minimum query length.
  - Measure: `ensphere verify limits --technique pagination --url "<target>/api/search?q=a" --param limit --values 10,100,1000 --in-scope <pattern>` and record returned row counts and body bytes per value.
  - Fix: hard server-side `limit`, minimum query length, per-IP limiter, and an index or dedicated search service.

- [ ] **Webhook receivers accept unlimited unsigned calls** — an unauthenticated POST endpoint that triggers work on every call is free to spam.
  - Look for: `/webhook`, `/hooks/`, Stripe/GitHub/Supabase database-webhook handlers; signature verification (`stripe.webhooks.constructEvent`, HMAC compare) before any work; idempotency keys.
  - Measure: `manual: send one POST with a missing signature and one with a wrong signature; record status codes and whether any side effect occurred. Do not send bursts.`
  - Fix: verify the signature first, reject early with 401, enforce idempotency, and limit by source IP range where the provider publishes one.

- [ ] **Public reads of stored objects are unmetered** — public bucket URLs, signed-URL proxies, and `/files/:id` routes serve egress the owner pays for.
  - Look for: public R2/S3/GCS buckets, Supabase public storage buckets, custom domains in front of buckets, image proxies (`/api/image?url=`), hotlink protection or `Referer` rules, CDN caching rules.
  - Measure: `manual: request one known non-sensitive object anonymously and record status, cache headers (cf-cache-status, x-cache, age), and size. Do not enumerate.`
  - Fix: serve through a CDN with caching, enable hotlink protection or signed URLs with short TTLs, and set a per-object-size cap.

## Where the limiter lives

- [ ] **Origin-only limiter on a multi-instance deployment** — in-memory limiters (`express-rate-limit` default `MemoryStore`, a Go `map`) reset per instance and per cold start, so serverless and autoscaled deployments have no effective limit.
  - Look for: limiter store configuration; whether Redis, Upstash, Cloudflare KV, or a Durable Object is used; hosting type (Vercel, Cloud Run, Lambda, Workers).
  - Measure: `manual: record the store type from source. If live, run the approved burst above twice with a 60-second gap and compare first_throttle_at; a limiter that never triggers across instances is a source-review finding, not a load test.`
  - Fix: shared store (Upstash Redis, Cloudflare KV or Durable Objects, Memorystore) or the platform's own limiter (Cloudflare rate-limiting rules, Workers Rate Limiting binding, Vercel Firewall).

- [ ] **Edge limiter bypassed by direct origin access** — a Cloudflare or Vercel rule protects the proxied hostname only; the origin IP or a `workers.dev` / `*.run.app` / `*.vercel.app` hostname is reachable without it.
  - Look for: origin hostnames in DNS records, `wrangler.toml` `workers_dev = true`, Cloud Run ingress set to `all`, missing origin allowlist or authenticated-origin-pull.
  - Measure: `manual: only with an operator-supplied origin hostname, send one baseline request to the proxied hostname and one to the origin hostname; record whether the origin answers and which rate-limit headers are present. Do not discover origins.`
  - Fix: Cloud Run ingress `internal-and-cloud-load-balancing`, authenticated origin pulls, disable `workers.dev`, or firewall the origin to the CDN IP ranges.

- [ ] **Limiter keyed only by IP** — mobile carriers and corporate NATs share IPs, and attackers rotate them; per-user or per-API-key keys are the meaningful ones for authenticated routes.
  - Look for: the key function of the limiter middleware; whether `X-Forwarded-For` is trusted without a trusted-proxy setting.
  - Measure: `manual: run the approved burst once with test user A and once with test user B from the same machine; compare first_throttle_at between runs.`
  - Fix: key authenticated routes by user id or API key, unauthenticated routes by IP behind a trusted proxy setting, and combine both for credential endpoints.

## Storage and upload abuse

- [ ] **Unbounded upload size or count** — no maximum body size, no per-user object quota, and no count limit lets one account fill the bucket.
  - Look for: `multer` `limits.fileSize`, `client_max_body_size`, `bodyParser` limits, `maxFileSize` in Next.js route config, Supabase Storage bucket `file_size_limit`, a per-user quota check before issuing an upload.
  - Measure: `ensphere verify limits --technique upload_size --url <target>/api/upload --field file --sizes <approved sizes in bytes> --token <test-user-jwt> --in-scope <pattern>`.
  - Fix: byte cap at the edge and in the handler, `content-length-range` on presigned POST policies, bucket-level size limits, and a per-user bytes-and-count quota row checked before every upload.

- [ ] **Presigned URLs with long TTL or no size and path constraints** — a leaked URL is reusable and unbounded.
  - Look for: `getSignedUrl`, `createPresignedPost`, `expiresIn`, `ContentLength`, `ContentType`, key prefix derived from the authenticated user id.
  - Measure: `manual: request one presigned upload URL with a test account and record its expiry, allowed content type, size condition, and key prefix from the URL parameters or policy.`
  - Fix: TTL of minutes, `content-length-range`, fixed content type, user-scoped key prefix, and single-use tracking where possible.

## Pagination and response size

- [ ] **Client-controlled page size without a ceiling** — `?limit=100000` returns the table.
  - Look for: `limit`, `per_page`, `first`, `pageSize` parameters; a server-side clamp; GraphQL `first` arguments; PostgREST `max_rows` in `config.toml` or the API settings.
  - Measure: `ensphere verify limits --technique pagination --url "<target>/api/items" --param limit --values 10,100,10000 --token <test-user-jwt> --in-scope <pattern>`.
  - Fix: clamp to a maximum (for example 100), cursor pagination, and PostgREST `db-max-rows`.


## Provider-side spend controls

- [ ] **No spend cap or budget alert** — abuse that slips past application limits is only discovered on the invoice.
  - Look for: Supabase spend cap setting, Cloudflare notifications for Workers and R2 usage, GCP and AWS budget alerts, OpenAI and Anthropic usage limits, Twilio and Resend spending limits.
  - Measure: `manual: record the current setting from the provider dashboard or CLI for each billed service in scope.`
  - Fix: enable the spend cap where the provider offers one, set budget alerts at 50 and 90 percent, and set hard usage limits on AI and messaging APIs.

- [ ] **Pay-per-invocation functions callable without authentication** — Edge Functions, Lambda URLs, Cloud Run services, and Workers with public routes bill per call.
  - Look for: `verify_jwt` in `supabase/config.toml`, Lambda function URL auth type, Cloud Run `allUsers` invoker binding, Worker routes with no auth middleware.
  - Measure: `ensphere verify auth --url <function-url> --token <valid-jwt> --technique no_token --in-scope <pattern>` then, if the operator approves, `ensphere verify ratelimit --url <function-url> --method POST --burst-count <approved> --window-sec 10 --in-scope <pattern>`.
  - Fix: require a JWT or signed request, add a limiter before any work, and put the function behind the platform's rate-limiting rule.
