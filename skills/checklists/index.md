# Checklists

The checks themselves are stack-agnostic and live in
`shared/fundamentals.md` and the session methodologies. A checklist is an
accelerator for one common stack: it says where each fundamental lives in
that framework and what the idiomatic fix is. Session 01 records the stack;
Session 01.5 maps it to these files with the table below (the same table
lives in `methodology/01.5-session-plan.md`). A stack with no checklist is
assessed from the fundamentals; it is not blocked.

Every item has four lines: what and why, **Look for** (source and config),
**Measure** (an `ensphere` command with real flags, or a bounded manual
procedure), and **Fix** (the concrete control). Items are candidates, not
findings; the contract's baseline, probe, control cycle still applies.

| Stack value | Checklist | Covers |
|-------------|-----------|--------|
| any server component | [abuse-and-cost.md](abuse-and-cost.md) | Missing limiters, billed services, upload and storage abuse, pagination caps, spend controls |
| nextjs | [nextjs-app-router.md](nextjs-app-router.md) | Route handlers, Server Actions, middleware matchers, caching, image optimizer |
| express | [express-js.md](express-js.md) | Middleware order, body limits, limiter stores, data layer |
| hono | [hono.md](hono.md) | Middleware order, validators, JWT and bearer auth, limiter, static roots |
| trpc | [trpc.md](trpc.md) | Procedure auth, input schemas, batching, limiter |
| fastapi | [fastapi.md](fastapi.md) | Dependencies, Pydantic models, uploads, `slowapi` |
| django | [django.md](django.md) | ORM raw sinks, DRF permissions, throttling, uploads |
| rails | [rails.md](rails.md) | Strong params, Active Storage, `rack-attack`, raw SQL |
| laravel | [laravel.md](laravel.md) | Mass assignment, `throttle:`, storage, raw queries |
| spring | [spring-boot.md](spring-boot.md) | Security filter chain, binders, actuators, Bucket4j |
| go, gin, chi, echo, fiber, net_http | [go-net-http.md](go-net-http.md) | Handler auth, `database/sql`, body and server timeouts, Cloud Run ingress |
| prisma, drizzle | [prisma-drizzle.md](prisma-drizzle.md) | Raw query sinks, tenant scoping, `take` caps, pool and timeouts |
| supabase_postgres, supabase_auth, supabase_storage | [supabase-rls.md](supabase-rls.md) | RLS policies from migrations, `verify rls`, auth limits, storage buckets |
| supabase_edge_functions | [supabase-edge-functions.md](supabase-edge-functions.md) | `verify_jwt`, anon invocation, limiter, secrets, webhooks |
| cloudflare_workers, cloudflare_pages, d1, kv | [cloudflare-workers.md](cloudflare-workers.md) | Bindings, routes, `workers.dev`, rate limiting, D1 queries, AI binding |
| cloudflare_r2 | [cloudflare-r2.md](cloudflare-r2.md) | Presigned URLs, public domains, CORS, size caps, listing, lifecycle |
| s3 | [aws-s3.md](aws-s3.md) | Public access, policies, presigned URLs, egress |
| aws, lambda | [aws-iam.md](aws-iam.md) | Principals, wildcard policies, MFA, budgets |
| kubernetes | [k8s-pod-security.md](k8s-pod-security.md) | Pod security, resource limits, RBAC, network policy |

Checklists are added only for stacks common enough that many users benefit.
Everything else is covered by the fundamentals.

## Writing a checklist

- One H1, then one paragraph saying which recon stack values load it.
- Sections by concern; the **Rate limiting and abuse** section is mandatory
  for application frameworks.
- Every `ensphere` command must exist with the flags shown. Check
  `cli/cmd/verify_<name>.go` before citing.
- No load testing, no exploitation, no secret retrieval in any Measure line.
- Add the stack values to the map above and in
  `methodology/01.5-session-plan.md`.
