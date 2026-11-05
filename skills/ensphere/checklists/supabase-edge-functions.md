# Supabase Edge Functions

Load this checklist when recon finds a `supabase/functions/` directory, a
`supabase/config.toml` with `[functions.*]` entries, or calls to
`supabase.functions.invoke(...)` or `https://<ref>.supabase.co/functions/v1/`.
Edge Functions run on Deno at the edge and are billed per invocation, so an
unauthenticated or unlimited function is both a security and a cost exposure.
Read facts from `supabase/functions/*/index.ts`, `supabase/config.toml`, and
deploy scripts before sending any request. Pair this file with
`supabase-rls.md` for the database side and `abuse-and-cost.md` for limiter
placement.

## Invocation authentication

- [ ] **Function deployed without JWT verification** — `verify_jwt = false` in `config.toml` or a `supabase functions deploy --no-verify-jwt` deploy lets anyone call the function with the public anon key or no key at all.
  - Look for: `[functions.<name>] verify_jwt = false` in `supabase/config.toml`; `--no-verify-jwt` in `package.json` scripts, CI workflows, or `Makefile`; whether the function then checks the JWT itself.
  - Measure: `ensphere verify auth --url https://<ref>.supabase.co/functions/v1/<name> --method POST --token <test-user-jwt> --technique no_token --in-scope <ref>.supabase.co`. Record the status with and without the token.
  - Fix: keep `verify_jwt = true` unless the function is a public webhook; for webhooks verify the provider signature inside the function instead.

- [ ] **Anon key treated as authentication** — the anon key is public and ships in every client bundle; a function that only checks for a valid anon JWT is effectively unauthenticated.
  - Look for: `supabase.auth.getUser()` or `getClaims()` calls on the incoming `Authorization` header; whether the function proceeds when the role claim is `anon`.
  - Measure: `manual: call the function once with the anon key as the bearer token and once with a test-user JWT; record both status codes and response hashes.`
  - Fix: reject requests whose JWT role is `anon` unless the function is intentionally public, and read the user id from the verified claims only.

## Invocation cost

- [ ] **No per-user or per-IP limiter before work** — every invocation is billed; a loop of anonymous calls runs up the bill and starves the plan quota.
  - Look for: a counter check (Upstash Redis, a `rate_limits` table, a Postgres advisory function) at the top of the handler; the order of the check relative to expensive work such as database writes, OpenAI calls, or email sends.
  - Measure: `ensphere verify ratelimit --url https://<ref>.supabase.co/functions/v1/<name> --method POST --token <test-user-jwt> --burst-count <approved> --window-sec 10 --in-scope <ref>.supabase.co`.
  - Fix: check a Redis or Postgres counter keyed by user id (or IP for public functions) before doing any work, and enable the Supabase spend cap.

- [ ] **Expensive or long-running work reachable by low-privilege callers** — functions that call LLM APIs, send email, process images, or run large queries amplify one cheap request into a large cost.
  - Look for: `fetch` to `api.openai.com`, `api.anthropic.com`, Resend, Twilio; `Deno.serve` handlers with loops over user-supplied arrays; missing input size caps.
  - Measure: `manual: source review; list each billed outbound call and the authentication and limiter checks that precede it.`
  - Fix: cap input sizes, require an authenticated non-anon user, add a per-user daily budget, and move heavy work to a queued job.

## Privilege inside the function

- [ ] **Service role key used for every query** — `SUPABASE_SERVICE_ROLE_KEY` bypasses row-level security, so any authorization bug in the function exposes every tenant's rows.
  - Look for: `createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"))`; whether the function instead forwards the caller's `Authorization` header so RLS applies.
  - Measure: `manual: source review; for each service-role client, list the tables touched and the user-scoped filter applied in code.`
  - Fix: create the client with the caller's JWT (`global: { headers: { Authorization } }`) and reserve the service role for narrowly scoped admin operations.

- [ ] **Secrets and configuration exposed** — values read from `Deno.env` echoed in responses, logs, or error messages.
  - Look for: `console.log` of env values, error handlers that return `err.message` with connection strings, secrets committed in `supabase/functions/*/.env` or `config.toml`.
  - Measure: `manual: send one malformed request and record whether the error body contains configuration or stack details.`
  - Fix: return generic errors, log server-side only, and set secrets with `supabase secrets set`.

## Request handling

- [ ] **Permissive CORS** — `Access-Control-Allow-Origin: *` with credentials, or reflecting the request origin, lets any site call the function with the user's token from the browser.
  - Look for: the `corsHeaders` object most templates copy; whether the origin is compared against an allowlist.
  - Measure: `ensphere verify cors --url https://<ref>.supabase.co/functions/v1/<name> --method POST --in-scope <ref>.supabase.co`.
  - Fix: allowlist exact origins and never combine `*` with `Access-Control-Allow-Credentials: true`.

- [ ] **Unvalidated JSON input** — the handler trusts `await req.json()` shape, so missing fields, huge arrays, or unexpected types reach the database or an outbound call.
  - Look for: schema validation (`zod`, `valibot`) at the top of the handler; length caps on arrays and strings.
  - Measure: `manual: send one request with a missing required field and one with an oversized array of approved size; record status codes and error bodies.`
  - Fix: validate with a schema, cap sizes, and reject early with 400.

- [ ] **Database or Stripe webhook without signature verification** — a database webhook or payment webhook that trusts the body lets anyone trigger the side effect.
  - Look for: `stripe.webhooks.constructEvent` with `STRIPE_WEBHOOK_SECRET`; for Supabase database webhooks, a shared-secret header check on the incoming request; idempotency on the event id.
  - Measure: `manual: send one POST with no signature header and one with a wrong signature; record the status code and confirm no side effect ran.`
  - Fix: verify the signature before parsing, store processed event ids, and rotate the secret if it was ever committed.
