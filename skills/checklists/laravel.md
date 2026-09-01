# Laravel Checklist

Load this checklist when recon records `laravel/framework` in
`composer.json`, an `artisan` file at the project root, or `routes/web.php`
and `routes/api.php`. Shared endpoint classes for rate limiting live in
[abuse-and-cost.md](abuse-and-cost.md).

## Data layer

- [ ] **Raw Eloquent methods** — `whereRaw()`, `orderByRaw()`, `selectRaw()`, `havingRaw()`, `DB::raw()`, `DB::statement()` with interpolated input.
  - Look for: those calls with `$request->` or string concatenation in `app/**/*.php`.
  - Measure: `ensphere verify sqli --technique error_based --url <endpoint> --param <param> --in-scope <pattern>`; `ensphere scan ./app --category sqli`.
  - Fix: pass bindings as the second argument; prefer query-builder methods.

- [ ] **Unbounded list queries** — `->get()` on user-facing list routes, or `per_page` accepted without a ceiling.
  - Look for: `->get()` where `->paginate()` is expected; `paginate($request->per_page)` unclamped.
  - Measure: `ensphere verify limits --technique pagination --param per_page --values 1,100,10000 --in-scope <pattern> (planned)`; otherwise `manual: request with a large per_page and record returned count and body bytes`.
  - Fix: `min($request->integer('per_page', 25), 100)`; cursor pagination for large tables.

## Authorization

- [ ] **Mass assignment** — empty `$guarded = []` or `$fillable` containing privileged attributes.
  - Look for: `protected $guarded = [];`, `$fillable` including `role`, `is_admin`, `user_id`; `Model::create($request->all())`.
  - Measure: `ensphere verify massassignment --url <endpoint> --method PUT --body '{"is_admin":1}' --watch-fields is_admin --token <user-token> --in-scope <pattern>`.
  - Fix: explicit `$fillable`; pass `$request->validated()` only.

- [ ] **Route model binding without ownership** — implicit binding resolves any model by ID; policy check missing.
  - Look for: controller methods taking a bound model with no `$this->authorize(` or `Gate::` call; `can:` middleware absent.
  - Measure: `ensphere verify idor --url <endpoint>/<other-user-id> --id <other-user-id> --token <user-token> --in-scope <pattern>`.
  - Fix: policies plus `authorizeResource`; scope bindings with `->scopeBindings()`.

- [ ] **Policy or gate logic errors** — policies returning `true` unconditionally, or `before()` hooks granting all.
  - Look for: `app/Policies/*.php`, `Gate::before(`.
  - Measure: `ensphere verify authz --url <endpoint> --low-token <user-token> --high-token <admin-token> --in-scope <pattern>`.
  - Fix: explicit per-ability checks; tests per policy.

## Configuration

- [ ] **`APP_DEBUG=true` in production** — Ignition pages expose environment variables and credentials.
  - Look for: `.env` in the deployed environment; `config/app.php` `debug` derivation.
  - Measure: `manual: trigger a 404 or validation error on the deployed target and check for Ignition or a stack trace`.
  - Fix: `APP_DEBUG=false`; ensure the Ignition solution runner is disabled in production.

- [ ] **`.env` served by the web server** — document root misconfigured to the project root.
  - Look for: web server config with root not set to `public/`.
  - Measure: `ensphere verify auth --technique no_token --url <target>/.env --token <valid-token> --in-scope <pattern>`.
  - Fix: document root to `public/`; deny dotfiles at the server.

- [ ] **CSRF exclusions** — routes listed in `VerifyCsrfToken::$except`, or session-authenticated routes moved to `routes/api.php` without token auth.
  - Look for: `$except` array; `web` middleware group modifications.
  - Measure: `ensphere verify csrf --url <endpoint> --method POST --in-scope <pattern>`.
  - Fix: remove exclusions; use Sanctum token auth for API routes.

## Rendering

- [ ] **Unescaped Blade output** — `{!! $var !!}` with user data.
  - Look for: `{!!` in `resources/views/**`.
  - Measure: `ensphere verify xss --url <endpoint> --param <param> --payload '<svg onload=alert(1)>' --in-scope <pattern>`; `ensphere scan ./resources --category xss`.
  - Fix: `{{ }}` by default; sanitize HTML with an allowlist where rich text is required.

## Uploads

- [ ] **Upload validation gaps** — extension-only checks; files stored under `storage/app/public` with original names.
  - Look for: `->store(`, `->move(` with `getClientOriginalName()`; validation rules lacking `mimes:`/`mimetypes:` and `max:`.
  - Measure: `ensphere verify fileupload --technique content_type_mismatch --url <upload-endpoint> --filename test.html --field file --in-scope <pattern>`.
  - Fix: `mimetypes` and `max` rules; hashed names; private disk or object storage.

## Rate limiting and abuse

- [ ] **No limiter on auth endpoints** — login, register, password reset, OTP verify without `throttle`.
  - Look for: `throttle:` middleware on those routes; `RateLimiter::for(` definitions in `AppServiceProvider` or `RouteServiceProvider`.
  - Measure: `ensphere verify ratelimit --url <login-endpoint> --method POST --body '<invalid-credentials-json>' --burst-count <approved> --window-sec 10 --in-scope <pattern>`.
  - Fix: `throttle:login` keyed by email plus IP; Fortify's built-in login throttling.

- [ ] **No limiter on expensive or billed endpoints** — uploads, search, export, mail/SMS send, payment, and third-party API routes without a named limiter.
  - Look for: controllers calling `Mail::`, `Notification::`, Cashier, S3/R2 disks, HTTP clients to paid APIs; the route's `throttle` middleware.
  - Measure: `ensphere verify ratelimit` with an approved burst on one endpoint per class; record `429` onset or its absence.
  - Fix: `RateLimiter::for('uploads', fn ($request) => Limit::perMinute(10)->by($request->user()->id))`; queue sends.

- [ ] **Limiter backed by a per-instance cache** — `throttle` uses the default cache store; `file` or `array` stores do not share counts across servers.
  - Look for: `CACHE_STORE` / `CACHE_DRIVER` in the deployed environment while running multiple instances.
  - Measure: `manual: source and deployment review`.
  - Fix: Redis cache store.

- [ ] **Body size limits** — `post_max_size`, `upload_max_filesize`, and proxy `client_max_body_size` at generous values everywhere rather than per route.
  - Look for: PHP ini values; nginx config; `max:` rules on upload validation.
  - Measure: `ensphere verify limits --technique upload_size --sizes 1048576,10485760 --field file (planned)`; otherwise `manual: post one approved oversized body and record the status`.
  - Fix: small global caps; larger caps only on upload routes.
