# Django / DRF Checklist

Load this checklist when recon records `django` in `requirements.txt`,
`pyproject.toml`, or `Pipfile`, a `manage.py` at the project root, or a
`settings.py` with `INSTALLED_APPS`. Add `rest_framework` items when DRF is
installed. Shared endpoint classes for rate limiting live in
[abuse-and-cost.md](abuse-and-cost.md).

## Data layer

- [ ] **Raw SQL sinks** — `raw()`, `extra()`, `RawSQL`, and `cursor.execute()` with string formatting bypass ORM parameterization.
  - Look for: `.raw(`, `.extra(`, `RawSQL(`, `cursor.execute(` with f-strings or `%` formatting in `**/*.py`.
  - Measure: `ensphere verify sqli --technique error_based --url <endpoint> --param <param> --in-scope <pattern>`; `ensphere scan ./ --category sqli`.
  - Fix: pass parameters as the second argument to `raw()`/`execute()`; prefer queryset filters.

- [ ] **Unbounded list endpoints** — querysets returned without pagination let one request load an entire table.
  - Look for: DRF views without `pagination_class`, `REST_FRAMEWORK["DEFAULT_PAGINATION_CLASS"]` unset, `PAGE_SIZE` missing, `max_page_size` unset on `PageNumberPagination` subclasses.
  - Measure: `ensphere verify limits --technique pagination --param page_size --values 1,100,10000 --in-scope <pattern> (planned)`; otherwise `manual: request the list endpoint with a large page_size and record returned count and body bytes`.
  - Fix: set a default pagination class with `max_page_size`; cap `page_size` server-side.

## Configuration

- [ ] **`DEBUG = True` in production** — error pages expose stack traces, settings, SQL, and installed apps.
  - Look for: `DEBUG` in `settings*.py` and how it is derived from the environment; `ALLOWED_HOSTS = ["*"]`.
  - Measure: `manual: request a nonexistent path on the deployed target and check the response for Traceback or the debug 404 page`.
  - Fix: derive `DEBUG` from an environment variable that defaults to `False`; set explicit `ALLOWED_HOSTS`.

- [ ] **`SECRET_KEY` committed** — compromises sessions, CSRF tokens, and password-reset tokens.
  - Look for: literal `SECRET_KEY = "..."` in `settings*.py`; `.env` files in git history (`git log --all -p -- .env`).
  - Measure: `manual: source review; confirm the key is loaded from the environment and rotated if it ever appeared in history`.
  - Fix: load from environment; rotate the key; invalidate sessions after rotation.

- [ ] **Admin exposed without extra controls** — `/admin/` reachable from the internet with password-only login.
  - Look for: `admin.site.urls` in `urls.py`; absence of IP allowlisting or MFA (`django-otp`, `django-two-factor-auth`).
  - Measure: `ensphere verify auth --technique no_token --url <target>/admin/ --token <valid-session> --in-scope <pattern>`.
  - Fix: restrict by network or SSO; enforce MFA for staff accounts; rename the path only as defense in depth.

## Authentication and sessions

- [ ] **Cookie flags** — session and CSRF cookies without `Secure`, `HttpOnly`, or `SameSite`.
  - Look for: `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE`, `CSRF_COOKIE_SECURE` in settings.
  - Measure: `manual: log in and record the Set-Cookie header attributes`.
  - Fix: set all three flags; set `SECURE_HSTS_SECONDS`.

## Authorization

- [ ] **`@csrf_exempt` on state-changing views** — disables CSRF protection per view.
  - Look for: `@csrf_exempt`, `csrf_exempt(` in `**/views.py` and `urls.py`; `CsrfViewMiddleware` removed from `MIDDLEWARE`.
  - Measure: `ensphere verify csrf --url <endpoint> --method POST --in-scope <pattern>`; `ensphere scan ./ --category csrf`.
  - Fix: remove the decorator; for token-authenticated APIs, reject cookie-authenticated requests instead.

- [ ] **DRF serializer mass assignment** — `fields = "__all__"` or missing `read_only_fields` lets a client set `is_staff`, `is_superuser`, `owner`.
  - Look for: `fields = "__all__"`, `exclude =`, serializers without `read_only_fields` in `**/serializers.py`.
  - Measure: `ensphere verify massassignment --url <endpoint> --method PATCH --body '{"is_staff":true}' --watch-fields is_staff --token <user-token> --in-scope <pattern>`.
  - Fix: enumerate `fields` explicitly and mark privileged fields read-only.

- [ ] **Object-level permission missing** — `get_object()` without ownership filtering returns any row by ID.
  - Look for: `get_queryset()` returning `Model.objects.all()` on user-owned models; `has_object_permission` absent.
  - Measure: `ensphere verify idor --url <endpoint>/<other-user-id>/ --id <other-user-id> --token <user-token> --in-scope <pattern>`.
  - Fix: filter querysets by the authenticated user or tenant.

## CORS

- [ ] **Permissive `django-cors-headers`** — `CORS_ALLOW_ALL_ORIGINS = True` with `CORS_ALLOW_CREDENTIALS = True`.
  - Look for: `CORS_ALLOW_ALL_ORIGINS`, `CORS_ALLOWED_ORIGIN_REGEXES` in settings.
  - Measure: `ensphere verify cors --url <endpoint> --in-scope <pattern>`.
  - Fix: list exact origins; never combine wildcard with credentials.

## Uploads and templates

- [ ] **Unvalidated `FileField`/`ImageField`** — no size cap, content-type check, or filename sanitization.
  - Look for: `FileField(` without `validators=`; `DATA_UPLOAD_MAX_MEMORY_SIZE`, `FILE_UPLOAD_MAX_MEMORY_SIZE` unset; `MEDIA_ROOT` served by the app.
  - Measure: `ensphere verify fileupload --technique content_type_mismatch --url <upload-endpoint> --filename test.html --in-scope <pattern>`.
  - Fix: validate extension and magic bytes; cap size; store outside the web root or in object storage with a fixed content type.

- [ ] **Template rendered from user input** — `Template(user_input).render()` allows template injection.
  - Look for: `Template(` and `engines[...].from_string(` with non-literal arguments.
  - Measure: `ensphere verify ssti --url <endpoint> --param <param> --in-scope <pattern>`; `ensphere scan ./ --category ssti`.
  - Fix: pass user data as context, never as template source.

## Rate limiting and abuse

- [ ] **No limiter on auth endpoints** — login, signup, password reset, and OTP verify accept unlimited attempts.
  - Look for: `django-ratelimit` decorators (`@ratelimit`), DRF `throttle_classes` / `DEFAULT_THROTTLE_RATES`, `django-axes`; if absent on `LoginView`, reset views, or token endpoints, record the gap.
  - Measure: `ensphere verify ratelimit --url <login-endpoint> --method POST --body '<invalid-credentials-json>' --burst-count <approved> --window-sec 10 --in-scope <pattern>`.
  - Fix: DRF `AnonRateThrottle`/`ScopedRateThrottle` keyed by IP and by account; `django-axes` for lockout.

- [ ] **No limiter on expensive or billed endpoints** — uploads, search, export, email/SMS send, and third-party API calls run without a per-user cap.
  - Look for: views calling `send_mail`, Celery tasks, S3/R2 uploads, external SDKs; check for a throttle on each.
  - Measure: `ensphere verify ratelimit` as above with an approved burst; record `429` onset or its absence.
  - Fix: `ScopedRateThrottle` per endpoint class; queue and dedupe email/SMS sends.

- [ ] **In-memory throttle store on multiple instances** — DRF throttling uses the configured cache; `LocMemCache` is per process, so limits reset per worker.
  - Look for: `CACHES["default"]["BACKEND"]` is `LocMemCache` while the deployment runs more than one worker or replica.
  - Measure: `manual: source and deployment review`.
  - Fix: back the cache with Redis or Memcached.

- [ ] **Body size limits** — `DATA_UPLOAD_MAX_MEMORY_SIZE` and `DATA_UPLOAD_MAX_NUMBER_FIELDS` at defaults or raised; reverse proxy `client_max_body_size` unset.
  - Look for: those settings; nginx or ingress configuration.
  - Measure: `ensphere verify limits --technique upload_size --sizes 1048576,10485760 --field file (planned)`; otherwise `manual: post one approved oversized body and record the status`.
  - Fix: set explicit caps at the proxy and in settings.
