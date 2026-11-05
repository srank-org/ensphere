# Supabase Checklist (Postgres, PostgREST, Auth, Storage, Realtime)

Load this checklist when recon records a `supabase/` directory, `supabase/config.toml`, `supabase/migrations/*.sql`, or a dependency on `@supabase/supabase-js`, `supabase_flutter`, or `supabase-py`. Supabase exposes the database directly through PostgREST, so row-level security (RLS) policies are the authorization layer, not the application code. Edge Functions have their own checklist (`supabase-edge-functions.md`); cost and rate-limit concerns shared across platforms are in `abuse-and-cost.md`.

## Prerequisites

- Project URL and anon key: `supabase/config.toml` (`api.port`, `project_id`), `.env*` (`SUPABASE_URL`, `SUPABASE_ANON_KEY`, `NEXT_PUBLIC_SUPABASE_*`), or the dashboard under Project Settings → API. Use a staging project, never production.
- JWT secret: dashboard Project Settings → API → JWT Settings. It is required by `verify rls` to forge two tenant tokens. Ask the operator for it; never read it from production secrets stores.
- Supabase CLI: if `supabase` is not installed or `supabase projects list` fails, tell the operator to run `supabase login` and `supabase link --project-ref <ref>` (or supply the values above by hand), and record every item that needs live access as `blocked` until they do. Source-only review of migrations proceeds regardless.

## RLS policies

- [ ] **Table without RLS** — a table reachable through PostgREST with RLS disabled is fully readable and writable with the anon key.
  - Look for: every `CREATE TABLE` in `supabase/migrations/*.sql` without a matching `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`; tables in the `public` schema created from the dashboard with no migration.
  - Measure: `manual: run SELECT tablename FROM pg_tables WHERE schemaname='public' AND NOT rowsecurity against staging`, then for each in-scope tenant table `ensphere verify rls --project-url <url> --anon-key <anon> --jwt-secret <secret> --table <table> --tenant-a <id-a> --tenant-b <id-b> --in-scope <project-host>`.
  - Fix: enable RLS on every exposed table and add explicit policies; revoke `anon`/`authenticated` grants on tables that should never be reached via PostgREST.

- [ ] **Policy missing WITH CHECK or USING** — `USING` governs reads and updates of existing rows, `WITH CHECK` governs inserted or updated row values. A read policy without a write policy leaves writes open or blocked unexpectedly.
  - Look for: `CREATE POLICY` statements per table and command (`FOR SELECT|INSERT|UPDATE|DELETE`); tables with a SELECT policy only.
  - Measure: `manual: query pg_policies for the table and record cmd, qual, with_check per policy`; then `ensphere verify rls` (flags as above) with `--select` narrowed to the tenant column.
  - Fix: one policy per command with both clauses where the command needs them.

- [ ] **Tenant claim trusted from JWT without server-side derivation** — policies keyed on a custom claim such as `auth.jwt() ->> 'company_id'` are only safe if the claim is set by an Auth Hook or trigger, never by the client.
  - Look for: `auth.jwt()` in policies; where the claim is populated (custom access token hook in `supabase/config.toml` `[auth.hook.custom_access_token]`, `raw_app_meta_data` triggers).
  - Measure: `ensphere verify rls` forges tokens with the supplied secret and different tenant claims; a non-zero cross-tenant row count for tenant A reading tenant B's fixture is the observation to report.
  - Fix: derive tenant from `auth.uid()` via a membership table, or populate the claim only in `app_metadata` through a server hook.

- [ ] **SECURITY DEFINER function or view bypasses RLS** — definer functions and views run as their owner and skip RLS unless written carefully.
  - Look for: `SECURITY DEFINER` in migrations; views without `security_invoker = true`; `rpc()` calls from the client to those functions.
  - Measure: `manual: call the RPC with the anon key and with a forged tenant JWT, record row counts and status`; if it takes text parameters into dynamic SQL, `ensphere verify sqli --url <url>/rest/v1/rpc/<fn> --method POST --param <param> --db postgres --technique error_based --in-scope <project-host>`.
  - Fix: `SECURITY INVOKER` by default; `SET search_path` and explicit tenant filters in definer functions; `ALTER VIEW ... SET (security_invoker = true)`.

## Keys and exposure

- [ ] **service_role key in client or repository** — the service role bypasses RLS entirely. Comparing anon against service_role responses is not a test; a difference is expected by design.
  - Look for: `SUPABASE_SERVICE_ROLE_KEY` referenced from client bundles, mobile apps, `NEXT_PUBLIC_*` variables, committed `.env`, or git history.
  - Measure: `manual: grep built client assets and git history for the service role JWT prefix and for "service_role" in decoded payloads`.
  - Fix: rotate the key; use it only from server-side code or Edge Functions with secrets.

- [ ] **Direct PostgREST access bypasses application validation** — validation in the app layer does not apply to a client calling `/rest/v1/<table>` directly.
  - Look for: inserts or updates the app validates with Zod or similar, then writes through the client SDK.
  - Measure: `manual: with an authenticated test user, PATCH a row through /rest/v1 with a value the app UI rejects; record whether the database accepted it`.
  - Fix: constraints, triggers, and policies in Postgres; move privileged writes behind RPC or Edge Functions.

## Storage

- [ ] **Public bucket or permissive storage policy** — `storage.objects` policies decide who can list, read, upload, and delete.
  - Look for: `INSERT INTO storage.buckets ... public = true`; policies on `storage.objects` with `USING (true)`.
  - Measure: `ensphere verify auth --technique no_token --url <url>/storage/v1/object/<bucket>/<known-fixture-key> --token <user-jwt> --in-scope <project-host>`.
  - Fix: private buckets with per-user path policies (`(storage.foldername(name))[1] = auth.uid()::text`).

- [ ] **Signed URL lifetime and upload limits** — long-lived signed URLs and unbounded upload size or count let a leaked link or a single user consume storage.
  - Look for: `createSignedUrl(..., expiresIn)` values; `createSignedUploadUrl`; bucket `file_size_limit` and `allowed_mime_types`.
  - Measure: `manual: record expiresIn values and bucket limits from config or dashboard`; `ensphere verify limits --technique upload_size ... (planned)`.
  - Fix: short expiry, `file_size_limit` and MIME allowlist per bucket, per-user quota enforced by policy or trigger.

## Rate limiting and abuse

- [ ] **Auth endpoint rate limits left at defaults or raised** — sign-up, OTP, magic link, and password reset send email or SMS that costs money.
  - Look for: `[auth.rate_limit]` in `supabase/config.toml`; dashboard Auth → Rate Limits; custom SMTP or SMS provider configured.
  - Measure: `manual: record the configured limits`; only with operator approval `ensphere verify ratelimit --url <url>/auth/v1/otp --method POST --body '{"email":"<owned-test-address>"}' --burst-count <approved> --window-sec 60 --in-scope <project-host>`.
  - Fix: tighten limits, enable CAPTCHA (Turnstile or hCaptcha) on sign-up and OTP.

- [ ] **Expensive RPC or view callable by anon** — an RPC that scans large tables or calls external services can be invoked repeatedly with the public key.
  - Look for: functions granted to `anon` (`GRANT EXECUTE ... TO anon`), views over large tables exposed in `public`.
  - Measure: `manual: list GRANTs on functions to anon and authenticated`; time one call with `ensphere verify ratelimit --burst-count 1`.
  - Fix: revoke from `anon`, require `authenticated`, add limits in an Edge Function front, or move to a queued job.

- [ ] **Realtime channels without authorization** — broadcast and presence channels can be joined by anyone with the anon key unless private channels and RLS on `realtime.messages` are configured.
  - Look for: `channel(...)` names built from tenant IDs; `private: true` option; policies on `realtime.messages`.
  - Measure: `manual: subscribe with a tenant A token to a tenant B channel name and record whether events arrive`.
  - Fix: private channels with RLS policies; do not rely on unguessable channel names.
