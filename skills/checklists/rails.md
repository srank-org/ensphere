# Ruby on Rails Checklist

Load this checklist when recon records `rails` in the `Gemfile`, a
`config/routes.rb`, or `bin/rails`. Shared endpoint classes for rate
limiting live in [abuse-and-cost.md](abuse-and-cost.md).

## Data layer

- [ ] **String fragments in ActiveRecord** — `where("name = '#{params[:q]}'")`, `order(params[:sort])`, `pluck(params[:col])`, `Arel.sql(user_input)`.
  - Look for: `where("`, `order(params`, `group(params`, `Arel.sql(` in `app/**/*.rb`.
  - Measure: `ensphere verify sqli --technique error_based --url <endpoint> --param <param> --in-scope <pattern>`; `ensphere scan ./app --category sqli`.
  - Fix: hash or placeholder conditions; allowlist sortable columns.

- [ ] **Unbounded list queries** — `Model.all` rendered without pagination, or `per_page` accepted unclamped.
  - Look for: index actions without `page`/`limit`; Kaminari or Pagy `max_per_page` unset.
  - Measure: `ensphere verify limits --technique pagination --param per_page --values 1,100,10000 --in-scope <pattern> (planned)`; otherwise `manual: request with a large per_page and record returned count and body bytes`.
  - Fix: Pagy with `limit_max`, or Kaminari `max_per_page`.

## Authorization

- [ ] **Strong parameters bypass** — `params.permit!` or attribute writes from `params` without `permit`.
  - Look for: `permit!`, `update(params[:model])` without `require(...).permit(...)`.
  - Measure: `ensphere verify massassignment --url <endpoint> --method PATCH --body '{"user":{"admin":true}}' --watch-fields admin --token <user-token> --in-scope <pattern>`.
  - Fix: explicit `permit` lists; never permit `admin`, `role`, or foreign keys from users.

- [ ] **Record lookup without scoping** — `Model.find(params[:id])` on user-owned records instead of `current_user.models.find`.
  - Look for: `find(params[:id])` in controllers for owned resources; Pundit/CanCan `authorize` absent.
  - Measure: `ensphere verify idor --url <endpoint>/<other-user-id> --id <other-user-id> --token <user-token> --in-scope <pattern>`.
  - Fix: scope lookups through the association; `verify_authorized` after actions.

- [ ] **Missing `authenticate_user!`** — controllers or actions without the Devise before-action.
  - Look for: `before_action :authenticate_user!` coverage; `skip_before_action` usage.
  - Measure: `ensphere verify auth --technique no_token --url <endpoint> --token <valid-session> --in-scope <pattern>`.
  - Fix: apply in `ApplicationController`; opt out explicitly for public actions.

## CSRF and sessions

- [ ] **CSRF protection skipped** — `skip_before_action :verify_authenticity_token` or `protect_from_forgery with: :null_session` on cookie-authenticated state changes.
  - Look for: those directives in `app/controllers/**`.
  - Measure: `ensphere verify csrf --url <endpoint> --method POST --in-scope <pattern>`.
  - Fix: keep `:exception`; token auth for API clients.

- [ ] **Session fixation** — no `reset_session` at login (Devise handles this; custom login flows often do not).
  - Look for: custom `SessionsController#create` without `reset_session`.
  - Measure: `manual: set a session cookie before login, authenticate, and record whether the session ID changed`.
  - Fix: `reset_session` before setting the user.

- [ ] **Cookie flags** — session cookie without `secure`, `httponly`, `same_site`.
  - Look for: `config.session_store` options; `config.force_ssl`.
  - Measure: `manual: log in and record the Set-Cookie attributes`.
  - Fix: `secure: true, httponly: true, same_site: :lax`; `force_ssl = true`.

## Redirects and rendering

- [ ] **`redirect_to params[:return_to]`** — open redirect without host validation.
  - Look for: `redirect_to params`, `redirect_back` with untrusted fallback.
  - Measure: `ensphere verify redirect --url <endpoint> --param <param> --in-scope <pattern>`.
  - Fix: `allow_other_host: false`; `url_from` in Rails 7+.

- [ ] **Unsafe HTML output** — `raw`, `html_safe`, `<%==` on user data; weak CSP.
  - Look for: `.html_safe`, `raw(`, `<%==` in `app/views/**`; `config/initializers/content_security_policy.rb` with `unsafe-inline`.
  - Measure: `ensphere verify xss --url <endpoint> --param <param> --payload '<svg onload=alert(1)>' --in-scope <pattern>`; `ensphere scan ./app --category xss`.
  - Fix: default escaping; `sanitize` with an allowlist; nonce-based CSP.

## Secrets and deserialization

- [ ] **`master.key` or `secret_key_base` committed** — invalidates cookie signing and encrypted credentials.
  - Look for: `config/master.key`, `config/credentials/*.key` in git history; `secret_key_base` literal in `secrets.yml`.
  - Measure: `manual: git log --all -- config/master.key config/secrets.yml`.
  - Fix: rotate; load from environment; purge history if it was pushed.

- [ ] **`Marshal.load` or YAML.load on untrusted data** — code execution on deserialization.
  - Look for: `Marshal.load(`, `YAML.load(` (not `safe_load`), `Oj.load` with default modes on request or cache data.
  - Measure: `manual: source review; confirm inputs are internal only`.
  - Fix: `YAML.safe_load`; JSON for cross-boundary data.

## Uploads

- [ ] **Active Storage without validation** — no content-type or size validation on attachments; files served with original type.
  - Look for: `has_one_attached` without a validator gem (`active_storage_validations`) or model validation.
  - Measure: `ensphere verify fileupload --technique content_type_mismatch --url <upload-endpoint> --filename test.html --field file --in-scope <pattern>`.
  - Fix: validate content type by magic bytes and size; serve via proxy with `Content-Disposition: attachment` for untrusted types.

## Rate limiting and abuse

- [ ] **No limiter on auth endpoints** — sign in, sign up, password reset, OTP verify without throttling.
  - Look for: `rack-attack` initializer (`Rack::Attack.throttle`), Rails 8 `rate_limit` in controllers, Devise `lockable`.
  - Measure: `ensphere verify ratelimit --url <sign-in-endpoint> --method POST --body '<invalid-credentials>' --burst-count <approved> --window-sec 10 --in-scope <pattern>`.
  - Fix: `Rack::Attack.throttle("logins/email", limit: 5, period: 60) { |req| req.params.dig("user", "email") if req.path == "/users/sign_in" && req.post? }`.

- [ ] **No limiter on expensive or billed endpoints** — uploads, search, export, mailers, SMS, payment, and third-party API calls without per-user caps.
  - Look for: controllers invoking `deliver_now`/`deliver_later`, Twilio, Stripe, S3/R2, image processing; a matching `throttle` rule.
  - Measure: `ensphere verify ratelimit` with an approved burst on one endpoint per class; record `429` onset or its absence.
  - Fix: per-path throttles keyed by `current_user`; background jobs with per-user concurrency.

- [ ] **Limiter cache is per instance** — `Rack::Attack.cache.store` defaults to `Rails.cache`; a memory store does not share counts across dynos or pods.
  - Look for: `config.cache_store` in production while running multiple instances.
  - Measure: `manual: source and deployment review`.
  - Fix: Redis or Memcached cache store.

- [ ] **Body size limits** — no request size cap at the proxy; Puma accepts large bodies.
  - Look for: nginx `client_max_body_size`; load balancer settings; `Rack::Attack.blocklist` by `Content-Length`.
  - Measure: `ensphere verify limits --technique upload_size --sizes 1048576,10485760 --field file (planned)`; otherwise `manual: post one approved oversized body and record the status`.
  - Fix: enforce at the proxy; larger cap only for upload routes.
