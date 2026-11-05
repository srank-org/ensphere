# Prisma and Drizzle Data Layer Checklist

Load this checklist when recon finds `@prisma/client` or `prisma` in
`package.json` (with a `prisma/schema.prisma`), or `drizzle-orm` (with a
`drizzle.config.*` and a schema file). It covers the data-access layer between
route handlers and PostgreSQL/MySQL/SQLite: raw query sinks, request-driven
query shapes, tenant scoping, result bounds, and connection settings. Pair it
with the framework checklist for the surrounding app (Next.js, Hono, Express,
tRPC) and with `supabase-rls.md` when the database is Supabase.

## Raw query sinks

- [ ] **Unsafe raw query helpers** — `$queryRawUnsafe` and `$executeRawUnsafe` accept a plain string, so any interpolated request value is SQL injection.
  - Look for: `grep -rn '\$queryRawUnsafe\|\$executeRawUnsafe' src/`, and Drizzle `sql.raw(` calls whose argument includes a variable.
  - Measure: `ensphere scan ./src --category sqli`, then for each reachable sink `ensphere verify sqli --url "<endpoint>?<param>=1" --param <param> --db postgres --technique blind_boolean --in-scope <pattern>`.
  - Fix: use the tagged-template form (`$queryRaw\`...${value}\``, Drizzle `sql\`...${value}\``), which binds parameters, or the query builder.

- [ ] **Tagged template defeated by string building** — `$queryRaw(\`SELECT ... ${x}\`)` with parentheses, or `Prisma.raw(x)` / `sql.raw(x)` nested inside a tagged template, turns a bound value back into concatenated SQL.
  - Look for: `\$queryRaw(` followed by a backtick, `Prisma.raw(`, `Prisma.sql([`, `sql.raw(`, and helpers that build SQL strings before passing them in.
  - Measure: same as above; use `--technique error_based` when the endpoint returns database errors, otherwise `blind_boolean`.
  - Fix: keep every dynamic value inside `${}` of the tagged template; for dynamic identifiers use an allowlist that maps request keys to fixed column names.

## Request-driven query shapes

- [ ] **Dynamic `orderBy`, `where`, or `select` from request input** — passing `req.query.sort` or a JSON filter object straight into the query lets callers sort or filter on any column, including ones they should not see (password hash, token, other tenants' fields).
  - Look for: `orderBy: { [req...]`, `where: req.body.filter`, `select: body.fields`, Drizzle `orderBy(sql.identifier(input))`, or spreading a parsed query object into `findMany`.
  - Measure: `manual: send the list request with a sort or filter key naming a sensitive column (for example password_hash) and record whether the response order or count changes; one request per column, no enumeration of values.`
  - Fix: validate with a schema that enumerates allowed fields (`z.enum([...])`) and map to a fixed `orderBy`/`where` object.

- [ ] **Mass assignment through `data: req.body`** — spreading the request body into `create` or `update` writes every column the model has, such as `role`, `ownerId`, `credits`, or `emailVerified`.
  - Look for: `data: req.body`, `data: { ...body }`, `data: input` where `input` is not schema-filtered, Drizzle `.values(body)` / `.set(body)`.
  - Measure: `ensphere verify massassignment --url <endpoint> --method PATCH --body '<owned object json>' --watch-fields role,ownerId --token <owned-user-token> --in-scope <pattern>` (use a benign field first; restore afterward).
  - Fix: parse the body with a schema that lists only writable fields and pass the parsed object; never pass privileged columns from client input.

## Tenant and ownership scoping

- [ ] **Lookups not bound to the caller** — `findUnique({ where: { id } })`, `update({ where: { id } })`, or `delete({ where: { id } })` without `AND userId = caller` lets any authenticated user act on any row by ID.
  - Look for: `where: { id }` on models that have an owner or tenant column; Drizzle `eq(table.id, id)` without an `and(eq(table.ownerId, ...))`.
  - Measure: `ensphere verify idor --url "<endpoint>/{id}" --id <other-owned-fixture-id> --token <user-a-token> --in-scope <pattern>` using two supplied test accounts and synthetic objects; `ensphere verify authz --url <endpoint> --low-token <user-token> --high-token <admin-token> --in-scope <pattern>` for admin-only routes.
  - Fix: include the owner or tenant column in every `where`, or apply a Prisma client extension / Drizzle wrapper that injects the tenant predicate. When on Supabase, enforce RLS as well (see `supabase-rls.md`).

- [ ] **Relations exposed through `include`** — deep `include` trees return related rows (other users' comments, invoices, tokens) that the top-level authorization never considered.
  - Look for: `include:` with nested `include`, `include: { user: true }` on public responses, Drizzle `with:` in relational queries.
  - Measure: `manual: request an owned object and diff the response keys against the documented API shape; record any relation or column not in the contract.`
  - Fix: use explicit `select` for response shapes; build DTOs instead of returning ORM objects.

- [ ] **Sensitive columns in default results** — returning the model object leaks `passwordHash`, `resetToken`, `apiKey`, `stripeCustomerId`, or internal flags.
  - Look for: models with secret-like columns and handlers that `return user` or `res.json(row)` without `select` / `omit`.
  - Measure: `manual: fetch the profile or list endpoint with an owned account and record whether any secret-like key is present in the JSON.`
  - Fix: Prisma `omit` (per-query or global in client options) or explicit `select`; Drizzle `getTableColumns` minus secrets.

## Result and resource bounds

- [ ] **Unbounded `findMany`** — list endpoints without `take` return the whole table, which is both a data-exposure and a cost/abuse problem (CPU, egress, connection hold time).
  - Look for: `findMany(` calls without `take`, or `take: Number(req.query.limit)` with no cap; Drizzle `select().from()` without `.limit()`.
  - Measure (planned): `ensphere verify limits --technique pagination --param take --values 1,100,10000 --url <list-endpoint> --in-scope <pattern>` to record returned row counts and body bytes per value.
  - Fix: enforce a server-side maximum (`take: Math.min(limit, 100)`), cursor pagination, and index the sort column.

- [ ] **Connection pool and timeouts unset** — serverless runtimes open a pool per instance; without limits and statement timeouts, a burst exhausts Postgres connections and stalls the whole app.
  - Look for: `DATABASE_URL` without `connection_limit` / `pool_timeout` (Prisma) or `max` / `idleTimeoutMillis` (Drizzle with `pg`/`postgres`); Supabase direct port `5432` used from serverless instead of the pooler on `6543`; PgBouncer transaction mode with Prisma lacking `pgbouncer=true`; no `statement_timeout` set for the app role.
  - Measure: `manual: read the datasource URL and pool config from source and deployment config (redact credentials) and record the values; compare against the database's max_connections.`
  - Fix: use the pooler from serverless, set `connection_limit` and `pool_timeout`, set `ALTER ROLE app SET statement_timeout = '5s'` (or per-query), and use a direct connection only for migrations.

## Repository hygiene

- [ ] **Seed or migration files containing credentials** — `prisma/seed.ts` or SQL migrations that insert admin users with fixed passwords or API keys ship those secrets to every environment.
  - Look for: `prisma/seed.*`, `prisma/migrations/**/*.sql`, `drizzle/**/*.sql` containing `password`, `token`, `api_key`, or bcrypt hashes.
  - Measure: `manual: grep the migration and seed directories for the strings above and record file:line only; do not copy the values into evidence.`
  - Fix: seed from environment variables in non-production only; rotate anything already committed.

- [ ] **Studio or debug surfaces reachable** — `prisma studio` or a `drizzle-kit studio` port forwarded from a deployment, or `log: ['query']` printing full parameters in production.
  - Look for: `studio` in deployment scripts or Dockerfiles; `new PrismaClient({ log: [...] })`; Drizzle `logger: true`.
  - Measure: `manual: check deployment manifests and process lists for a studio process; check log configuration in source.`
  - Fix: run studio only locally; use `log: ['error']` in production and redact query parameters.
