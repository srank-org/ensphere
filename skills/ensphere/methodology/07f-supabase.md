# Supabase Read-Only Appendix — Session 07

Use this appendix when a Supabase project is explicitly in scope. It inherits
[07-cloud.md](07-cloud.md). Supabase is detected from the repository
(`supabase/` directory, `@supabase/supabase-js` or `supabase_flutter`
dependency, `SUPABASE_URL` configuration); never assume it.

## Binding Boundary

Collect configuration and schema facts only. Never read row data, never use
the `service_role` key against a production project, never modify policies,
buckets, functions, or auth settings, and never print secret values.

## Preflight

Record the expected project ref, region, project URL, and which environment
(local, staging, production) is authorized.

```bash
supabase --version
supabase projects list
```

If the CLI is missing or unauthenticated, tell the operator exactly:

```bash
brew install supabase/tap/supabase   # or: npm i -g supabase
supabase login
supabase link --project-ref <ref>     # run from the repository root
```

Do not install, log in, or link on the operator's behalf without permission.
If the agent surface provides a Supabase MCP server, it may replace the CLI
for read-only inventory; a failed MCP connection must be reported to the
operator as a blocked prerequisite, not silently skipped. Until the
prerequisite is supplied, record live checks as `blocked` and complete the
source lane, which needs no credentials.

## Source Lane (no CLI required)

Cite file/line for every fact.

### `supabase/config.toml`

- `[auth]`: `site_url`, `additional_redirect_urls`, `enable_signup`,
  `enable_confirmations`, OTP expiry and length, `jwt_expiry`;
- `[auth.rate_limit]`: values for email/SMS sent, token refresh, sign-in/sign-up,
  anonymous users, and token verifications — record absent keys as defaults;
- `[auth.external.*]`: enabled providers;
- `[functions.<name>]`: `verify_jwt` (a `false` here is a fact for Session
  08.5, not a finding by itself);
- `[storage]`: `file_size_limit`, bucket definitions, `public` flags,
  `allowed_mime_types`;
- `[db]`: `pooler` settings and `max_client_conn`.

### `supabase/migrations/*.sql`

For every table: whether `ENABLE ROW LEVEL SECURITY` is present; each
`CREATE POLICY` with its command, role, `USING`, and `WITH CHECK` clauses;
`GRANT` statements to `anon` and `authenticated`; functions declared
`SECURITY DEFINER` and whether they are exposed via RPC; `storage.buckets`
inserts and `storage.objects` policies; views that bypass base-table policies.
Build a table × role × operation matrix from this before any live request.

### Other repository files

- `supabase/functions/*`: each function's auth handling, rate limiting, and
  paid outbound calls (AI, email, SMS);
- `supabase/seed.sql`: literal credentials or real personal data;
- client code: where the anon key and project URL are used, and any use of
  `service_role` outside server-only code.

## Live Inventory

```bash
supabase projects list
supabase functions list
supabase secrets list                     # names only
supabase db lint
supabase inspect db table-sizes
supabase inspect db role-connections
supabase inspect db long-running-queries
```

PostgREST exposure fact: `GET {project-url}/rest/v1/` with the anon key
returns the OpenAPI description of tables and RPC functions visible to the
`anon` role. Record the exposed names; do not query rows.

Record auth facts from the dashboard or Management API where authorized:
enabled providers, confirmation requirements, OTP settings, and rate limits.
Record storage facts: public buckets, size limit, allowed MIME types, and
whether image transformation is enabled. Record function facts: `verify_jwt`
state per deployed function.

### Billing exposure

Record plan tier, whether the spend cap is enabled (Pro), and the metered
dimensions relevant to the recon inventory: edge function invocations, egress,
storage size, database size, monthly active users, and realtime messages.
Each unauthenticated or unlimited path that consumes one of these is a
Session 08.5 candidate.

## Report Additions

Include project ref/environment, active identity, the migration-derived RLS
matrix, exposed PostgREST tables/RPC, auth and storage configuration facts,
edge function auth and rate-limit facts, billing exposure facts, and every
`blocked` check with the prerequisite the operator must supply.
