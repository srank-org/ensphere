# tRPC Checklist

Load this checklist when recon records `@trpc/server` in `package.json`, a
`router({` / `initTRPC` definition, or an `/api/trpc` route. tRPC v10 and v11
share these items. Shared endpoint classes for rate limiting live in
[abuse-and-cost.md](abuse-and-cost.md).

## Procedures and authentication

- [ ] **Public procedure that should be protected** — a query or mutation built from `publicProcedure` instead of `protectedProcedure`.
  - Look for: every `publicProcedure.` usage; confirm each is intentionally anonymous. Check the auth middleware actually throws `UNAUTHORIZED` when `ctx.session` is null.
  - Measure: `ensphere verify auth --technique no_token --url <target>/api/trpc/<router.procedure> --token <valid-session> --in-scope <pattern>`.
  - Fix: default to `protectedProcedure`; list public procedures explicitly.

- [ ] **Role checks inside handlers instead of middleware** — `if (ctx.user.role !== "admin")` duplicated per procedure and missing in some.
  - Look for: role conditions inside `.mutation(` / `.query(` bodies; absence of an `adminProcedure` builder.
  - Measure: `ensphere verify authz --url <target>/api/trpc/<admin.procedure> --low-token <user> --high-token <admin> --in-scope <pattern>`.
  - Fix: role-scoped procedure builders via `t.procedure.use(...)`.

## Input validation

- [ ] **Zod `.passthrough()` or missing `.strict()`** — extra fields flow into database writes.
  - Look for: `.passthrough()`, `z.object(` used for update inputs that are spread into `prisma.update({ data: input })`.
  - Measure: `ensphere verify massassignment --url <target>/api/trpc/<update.procedure> --method POST --body '{"json":{"id":"<own-id>","role":"admin"}}' --watch-fields role --token <user-token> --in-scope <pattern>`.
  - Fix: `.strict()`; pick allowed fields explicitly before writing.

- [ ] **Coercion surprises** — `z.coerce.number()` turns `""` into `0` and `"0"` into `0`; `z.coerce.boolean()` turns `"false"` into `true`.
  - Look for: `z.coerce.` on IDs, amounts, or flags used in business logic.
  - Measure: `manual: call the procedure with "" and "false" for coerced fields and record the persisted value`.
  - Fix: `z.number()` with client-side parsing, or explicit `preprocess`.

## Authorization

- [ ] **Cross-tenant reads** — procedures accept an ID and query without a tenant or owner filter.
  - Look for: `findUnique({ where: { id: input.id } })` on tenant-owned models without `organizationId: ctx.orgId`.
  - Measure: `ensphere verify idor --url <target>/api/trpc/<procedure>?input=<encoded-other-tenant-id> --id <other-tenant-id> --token <tenant-a-session> --in-scope <pattern>`.
  - Fix: always include the tenant condition; wrap the ORM client per tenant.

- [ ] **Plan or subscription gates missing on mutations** — paid features callable with an expired or canceled subscription.
  - Look for: subscription checks in a middleware versus per-procedure.
  - Measure: `ensphere verify authz --url <target>/api/trpc/<paid.procedure> --low-token <expired-sub> --high-token <active-sub> --in-scope <pattern>`.
  - Fix: `paidProcedure` builder checking entitlement server-side.

## Batching and errors

- [ ] **Batch requests amplify work** — one HTTP call can carry many procedures; a limiter on the HTTP route counts one.
  - Look for: `httpBatchLink` on the client; `maxBatchSize` on the server adapter (`createHTTPHandler` / `fetchRequestHandler` options).
  - Measure: `manual: send a batch of N benign queries (N approved, small) and record whether the limiter counts N or 1`.
  - Fix: set `maxBatchSize`; count procedures, not requests, in the limiter.

- [ ] **Error details leak** — `TRPCError.cause` and stack traces reach clients in production.
  - Look for: `errorFormatter` config; `onError` logging that also returns internals.
  - Measure: `manual: trigger a validation error and a thrown error; record whether the response contains stack or cause`.
  - Fix: strip `cause` and `stack` in `errorFormatter` outside development.

## Rate limiting and abuse

- [ ] **No limiter on auth-adjacent mutations** — login, signup, password reset, OTP, and email-change procedures.
  - Look for: a limiter middleware (`@upstash/ratelimit`, `rate-limiter-flexible`) attached through `t.procedure.use(`; per-procedure application.
  - Measure: `ensphere verify ratelimit --url <target>/api/trpc/<auth.procedure> --method POST --body '{"json":{...}}' --burst-count <approved> --window-sec 10 --in-scope <pattern>`.
  - Fix: `rateLimitedProcedure` builder keyed by IP and by user; tighter limits for auth procedures.

- [ ] **No limiter on expensive or billed procedures** — uploads and presigned URL issuance, search, export, email/SMS send, LLM calls, payment intents.
  - Look for: procedures calling S3/R2 `getSignedUrl`, `resend`/`nodemailer`, `openai`, `stripe`; each should use the limited builder.
  - Measure: `ensphere verify ratelimit` with an approved burst on one procedure per class; record `429` onset or its absence.
  - Fix: `@upstash/ratelimit` sliding window per user for each class; queue side effects.

- [ ] **Limiter runs in memory on serverless** — a `Map`-based limiter resets per cold start and per instance.
  - Look for: in-memory maps or `rate-limiter-flexible` `RateLimiterMemory` in a Vercel, Lambda, or Workers deployment.
  - Measure: `manual: source and deployment review`.
  - Fix: Upstash Redis or another shared store.

- [ ] **Body size limits** — the adapter or platform accepts large JSON inputs; `z.string()` without `.max()`.
  - Look for: `maxBodySize` on the adapter; string schemas lacking `.max(`; platform limits (Vercel 4.5 MB, Workers 100 MB by plan).
  - Measure: `ensphere verify limits --technique upload_size --sizes 1048576,10485760 --field file (planned)`; otherwise `manual: post one approved oversized input and record the status`.
  - Fix: `.max()` on every string and array schema; adapter body limit.
