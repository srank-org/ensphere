# Express.js Checklist

Load this checklist when recon records `express` in `package.json`
dependencies, `app.use(` / `express.Router()` in server source, or an
`app.listen(` entry point. Shared endpoint classes for rate limiting live in
[abuse-and-cost.md](abuse-and-cost.md).

## Data layer

- [ ] **Raw SQL in Knex, Sequelize, or pg** — `knex.raw()`, `sequelize.query()`, or `pool.query()` with template-string interpolation bypasses parameterization.
  - Look for: `.raw(\``, `sequelize.query(\``, `query(\`...${` in `**/*.{js,ts}`.
  - Measure: `ensphere verify sqli --technique error_based --url <endpoint> --param <param> --in-scope <pattern>`; `ensphere scan ./src --category sqli`.
  - Fix: use bound parameters (`?` / `$1`) or query-builder methods.

- [ ] **MongoDB operator injection** — request JSON passed straight into Mongoose or driver queries accepts `$gt`, `$ne`, `$regex`, `$where`.
  - Look for: `find(req.body`, `findOne({ ... req.query`, `$where`.
  - Measure: `ensphere verify nosql --technique operator_injection --url <endpoint> --param <param> --in-scope <pattern>`; `ensphere scan ./src --category nosql`.
  - Fix: validate body shape with a schema (zod, joi) and cast fields to primitives; `express-mongo-sanitize`.

- [ ] **Unbounded list queries** — `limit` taken from the query string without a ceiling, or no limit at all.
  - Look for: `.limit(req.query.limit`, `findAll()` without `limit` on user-facing routes.
  - Measure: `ensphere verify limits --technique pagination --param limit --values 1,100,10000 --in-scope <pattern> (planned)`; otherwise `manual: request with a large limit and record returned count and body bytes`.
  - Fix: clamp `limit` server-side; cursor pagination for large tables.

## Input handling

- [ ] **Prototype pollution via deep merge** — `merge`, `extend`, `defaultsDeep`, or hand-written recursive merges on request JSON honor `__proto__` and `constructor.prototype`.
  - Look for: `lodash.merge`, `deepmerge`, `Object.assign` in recursive helpers, `qs` with `allowPrototypes`.
  - Measure: `ensphere verify protopollution --technique proto_assignment --url <endpoint> --method POST --in-scope <pattern>`.
  - Fix: upgrade merge libraries; reject `__proto__`/`constructor` keys at the validator; create objects with `Object.create(null)` where needed.

- [ ] **Path traversal through `res.sendFile` / `express.static`** — user-controlled path segments resolve outside the intended directory.
  - Look for: `sendFile(path.join(base, req.params`, `res.download(req.query`, `createReadStream(` with request data.
  - Measure: `ensphere verify lfi --url <endpoint> --param <param> --in-scope <pattern>`; `ensphere scan ./src --category lfi`.
  - Fix: resolve and verify the final path starts with the base directory; use `root` option on `sendFile`.

- [ ] **SSRF through `axios`, `node-fetch`, `got`, `undici`** — user-supplied URL fetched server-side.
  - Look for: `axios.get(req.`, `fetch(req.body.url`, webhook and preview handlers.
  - Measure: `ensphere verify ssrf --url <endpoint> --param <param> --in-scope <pattern>`; `ensphere scan ./src --category ssrf`.
  - Fix: allowlist hosts, resolve DNS and reject private ranges, disable redirects.

## Authentication and sessions

- [ ] **`jsonwebtoken` without an `algorithms` allowlist** — enables `none` and RS256-to-HS256 confusion.
  - Look for: `jwt.verify(token, secret)` with no `{ algorithms: [...] }`; `jwt.decode(` used for auth decisions.
  - Measure: `ensphere verify jwt --technique alg_none --url <endpoint> --token <valid-jwt> --in-scope <pattern>`; `ensphere scan ./src --category jwt`.
  - Fix: pass `algorithms`; use `verify`, never `decode`, for trust decisions.

- [ ] **`express-session` defaults** — `MemoryStore` in production, missing `secure`/`httpOnly`/`sameSite`, weak secret, no session regeneration on login.
  - Look for: `session({` options; `req.session.regenerate` absent in the login handler.
  - Measure: `manual: log in and record Set-Cookie attributes and whether the session ID changed after authentication`.
  - Fix: Redis store; cookie flags; `regenerate()` on login.

- [ ] **Missing auth middleware on a router** — routes mounted without the auth guard, or the guard applied after the route.
  - Look for: `app.use("/api"` ordering relative to auth middleware; routers with no `requireAuth`.
  - Measure: `ensphere verify auth --technique no_token --url <endpoint> --token <valid-jwt> --in-scope <pattern>`.
  - Fix: apply the guard at router level before routes; deny by default.

## Headers and CORS

- [ ] **No Helmet or equivalent** — missing `X-Content-Type-Options`, `X-Frame-Options`/`frame-ancestors`, HSTS, CSP.
  - Look for: `helmet(` in app setup.
  - Measure: `ensphere verify clickjacking --url <endpoint> --in-scope <pattern>`; `manual: record response headers`.
  - Fix: `app.use(helmet())` with a real CSP.

- [ ] **Permissive `cors()`** — `origin: true` or `*` together with `credentials: true`.
  - Look for: `cors({` options; reflected `Origin`.
  - Measure: `ensphere verify cors --url <endpoint> --in-scope <pattern>`.
  - Fix: explicit origin list; no credentials with wildcards.

- [ ] **CSRF on cookie-authenticated mutations** — no token or origin check on `POST`/`PUT`/`DELETE` when sessions live in cookies.
  - Look for: `csurf`/`csrf-csrf` absent; `sameSite` not `lax`/`strict`.
  - Measure: `ensphere verify csrf --url <endpoint> --method POST --in-scope <pattern>`.
  - Fix: `SameSite` cookies plus an origin check or double-submit token.

## Uploads

- [ ] **Multer without limits or filter** — unlimited size, any type, original filename reused on disk.
  - Look for: `multer({` without `limits.fileSize` and `fileFilter`; `file.originalname` used in the destination path.
  - Measure: `ensphere verify fileupload --technique content_type_mismatch --url <upload-endpoint> --filename test.html --field file --in-scope <pattern>`.
  - Fix: `limits`, `fileFilter` by magic bytes, random server-side names, object storage with fixed content type.

## Rate limiting and abuse

- [ ] **No limiter on auth endpoints** — `/login`, `/register`, `/forgot-password`, OTP verify accept unlimited attempts.
  - Look for: `express-rate-limit` or `rate-limiter-flexible` applied to those routes.
  - Measure: `ensphere verify ratelimit --url <login-endpoint> --method POST --body '<invalid-credentials-json>' --burst-count <approved> --window-sec 10 --in-scope <pattern>`.
  - Fix: `express-rate-limit` per route keyed by IP and by account identifier.

- [ ] **No limiter on expensive or billed endpoints** — uploads, search, export, email/SMS send, payment intents, LLM or third-party API calls run without per-user caps.
  - Look for: handlers calling `nodemailer`, `twilio`, `stripe`, `openai`, S3/R2 SDKs, image processing (`sharp`), PDF generation (`puppeteer`); check each for a limiter.
  - Measure: `ensphere verify ratelimit` with an approved burst on one endpoint per class; record `429` onset or its absence.
  - Fix: per-route limiters with tighter windows; job queues with per-user concurrency.

- [ ] **Limiter store is in-memory across replicas** — `express-rate-limit`'s default `MemoryStore` counts per process, so limits multiply by replica count and reset on restart.
  - Look for: `store:` option absent while the app runs on PM2 cluster, Kubernetes replicas, or serverless.
  - Measure: `manual: source and deployment review`.
  - Fix: `rate-limit-redis` or `@upstash/ratelimit` backed by a shared store.

- [ ] **Body size limits** — `express.json()` / `express.urlencoded()` at the default 100 kB or raised without reason; proxy `client_max_body_size` unset.
  - Look for: `express.json({ limit:`; nginx or ingress config.
  - Measure: `ensphere verify limits --technique upload_size --sizes 1048576,10485760 --field file (planned)`; otherwise `manual: post one approved oversized body and record the status`.
  - Fix: explicit small limits per route; larger limits only on upload routes.
