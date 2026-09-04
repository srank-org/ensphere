# Fundamentals

Every system, whatever it is built on, is made of the same roles. Each role
has an invariant that does not depend on the product filling it: a Postgres
row policy, a Prisma `where` clause, and a hand-written handler check are
three ways to satisfy the same authorization invariant. This file is the
stack-agnostic map of what Ensphere checks. Session methodologies say how to
measure each invariant; stack checklists say where it lives in one framework
and what the idiomatic fix is. When no checklist matches, this file and your
own knowledge of the stack are enough. A stack is never `blocked` for
lacking a checklist.

Recon names which product fills each role. The check is the same either way.

## Roles and invariants

| Role | Invariant | How to find it in any stack | Generic fix when absent |
|------|-----------|-----------------------------|-------------------------|
| **Entry point** (HTTP route, RPC, message consumer, cron, webhook receiver, Server Action) | Every entry point is known, its authentication state is deliberate, and debug or admin entry points are absent from the deployed build. | Route registration, router files, function exports, infrastructure config that maps URLs to code, framework conventions that expose files as routes. | Central route table; deny-by-default middleware; public routes in one named list; debug routes compiled out. |
| **Parser** (query string, JSON, form, multipart, XML, YAML, headers, object decoders) | Input is validated against a schema before use, bodies have a size cap, and decoders cannot instantiate types or resolve entities the schema did not name. | Framework body-parser settings, schema libraries, decode and unmarshal calls, XML and YAML loader options, deserialization of client-supplied blobs. | Schema validation at the boundary; body-size limit at the edge and in the app; entity and type resolution disabled. |
| **Query construction** (SQL, NoSQL, LDAP, XPath, command, template, path, header) | User data reaches a query only as a parameter, never as syntax. | ORM raw-query escape hatches, string formatting into query calls, shell invocations, template compilation from strings, path joins, header writes. | Placeholders; allowlists for identifiers such as column and table names; no shell; canonical path prefix check; header value sanitisation. |
| **Identity** (login, signup, session, token, API key, OAuth, reset, MFA) | A credential proves one identity, cannot be replayed, forged, or reused after logout, and every state transition rotates what must rotate. | Auth middleware, token verification, session store, reset-token issuance, OAuth callback handling, provider configuration. | Verified signatures with a fixed algorithm; short-lived tokens; rotation on privilege change and logout; single-use reset tokens; state and PKCE on OAuth. |
| **Cryptographic operation** (password storage, signing, encryption, randomness) | Passwords are stored with a slow adaptive hash, signatures use one fixed algorithm and a server-held key, and every security token comes from a cryptographic random source. | Hashing calls, JWT and cookie signing configuration, encryption helpers, token generators, key material handling. | Argon2id or bcrypt; algorithm pinned at verification; keys from the secret store; CSPRNG for every token and nonce. |
| **Authorization decision** (object, property, function, tenant) | Every read and write binds the caller's identity to the object, tenant, operation, and property. Hiding in the UI is not enforcement. | The layer that owns the decision: handler checks, policy engine, ORM where clauses, database row policies, storage key prefixes. | Enforce in one layer as close to the data as possible; tenant column in every query or a database policy; property allowlists on write. |
| **Workflow** (order, payment, approval, onboarding, subscription state) | Every transition is checked server-side against the current state and the caller, cannot be skipped or replayed to gain, and no client-supplied field is treated as truth about price, role, tenant, or state. | State fields and their writers, transition handlers, payment and webhook confirmation paths, fields copied from the request into the record. | One transition function per state machine with an explicit allowed-transition table; server-computed prices and roles; idempotency keys; webhook signature verification before state change. |
| **Data store** (relational, document, key-value, search index) | Only intended tables and operations are reachable; queries are bounded; connections and statements time out; the store is not exposed past the application. | Grants and policies; pagination parameters and their maxima; pool and timeout settings; exposed database or search APIs; connection strings in client bundles. | Least-privilege roles; row policies where the store supports them; `max_rows` clamps; statement and connection timeouts; store reachable only from the app. |
| **Object storage** (buckets, uploads, downloads, thumbnails, exports) | Writes are bounded in size, count, type, and path per caller; reads are either private or deliberately public with cost controls; nothing can list. | Presigned URL issuers, upload handlers, bucket policy or public flag, CDN in front, lifecycle rules, CORS configuration. | Size and type constraints in the signed policy; caller-scoped key prefix; short TTL; private by default; CDN with cache in front of anything public; listing denied. |
| **Render context** (HTML, DOM, markdown, email, PDF, CSV export, push notification) | Untrusted content is encoded for the exact context it lands in. | Template engines and their unsafe-output helpers, DOM sinks, sanitizer configuration, markdown renderers, export writers, email templates. | Context-aware encoding by default; sanitizer allowlist; formula escaping in CSV; no raw-HTML helpers on user content. |
| **Browser boundary** (cookies, CORS, CSP, framing, redirects) | The browser cannot be made to send credentials to, or execute content from, an origin the application did not name. | Cookie flags, CORS middleware and its origin list, CSP and frame headers, redirect targets built from parameters. | `HttpOnly`, `Secure`, `SameSite` cookies; explicit origin allowlist with credentials; CSP without `unsafe-inline`; frame denial; redirect allowlist. |
| **Outbound call** (fetcher, webhook sender, importer, previewer, PDF renderer) | The destination is validated before connecting, redirects are re-validated, and internal, loopback, and metadata addresses are unreachable. | HTTP client construction, URL parameters, redirect settings, DNS resolution, egress rules and network policy. | Resolve then allowlist; block loopback, link-local, private ranges, and metadata hosts; timeouts; egress through a proxy that enforces the same list. |
| **Expensive or billed operation** (mail, SMS, AI, transforms, exports, search, serverless invocation, third-party API) | It runs only after authentication and after a limiter keyed on the caller, backed by a store shared across instances, with a quota and a provider-side spend cap. | Calls to paid SDKs, heavy libraries, and job enqueues; limiter middleware and its store; provider billing settings and alerts. | Limiter keyed on user or API key (IP only for anonymous routes); shared store; per-user quota; queue with concurrency limit; budget alert and spend cap. |
| **Limiter** (rate, size, count, depth, concurrency) | Every limit is enforced server-side, keyed on the right subject, shared across instances, and present at both the edge and the origin when an edge exists. | Middleware chain order; limiter store type; edge rules; origin reachability without the edge; GraphQL depth and batch settings. | Edge rule plus origin limiter; shared store; origin not reachable except through the edge; depth and batch caps. |
| **Secret** (keys, tokens, connection strings, signing material) | Secrets live only where the code that needs them runs, never in clients, repositories, logs, or error output. | Environment handling, client bundles and public env prefixes, committed files, git history, logging calls, error handlers. | Secret manager or platform secrets; server-only access; log redaction; rotation on exposure. |
| **Audit trail** (security events, admin actions, payments) | Authentication, privilege change, admin, and payment events produce a record the caller cannot suppress, and no record contains a secret or credential. | Logging calls on auth and admin paths, log sinks and retention, redaction configuration, audit tables. | Structured security log at the boundary; append-only sink; redaction; retention that outlasts an investigation. |
| **Platform configuration** (cloud account, serverless, container, DNS, CDN, edge) | Public exposure, invocation permissions, and cost controls are deliberate and recorded, and the deployed configuration matches the source. | Provider configuration read through its CLI; infrastructure-as-code; platform dashboards the operator exports; drift between IaC and live. | Least-privilege invokers; ingress restricted to the edge; budget alerts; IaC as the only writer. |

## Where each role is checked

| Role | Session | Typical measurement |
|------|---------|---------------------|
| Entry point | 01 inventories, 08 measures | `ensphere openapi`; `verify graphql`, `verify grpc`, `verify websocket` for protocol surface |
| Parser | 02, 08, 08.5 | `verify xxe`, `verify protopollution`, `verify limits` (body size) |
| Query construction | 02 | `verify sqli`, `verify nosql`, `verify cmdi`, `verify ssti`, `verify lfi`, `verify ldap`, `verify xpath`, `verify headerinjection` |
| Identity | 03 | `verify auth`, `verify jwt`, `verify csrf`; every other flow step sent with `verify request` under its role |
| Cryptographic operation | 03 | Source review; `verify jwt` for algorithm and signature handling |
| Authorization decision | 04 | `verify authz`, `verify idor`, `verify rls`, `verify propertyauthz` |
| Workflow | 04 (transitions), 08.7 (chains) | Each transition sent with `verify request` as baseline, probe, or control; `verify massassignment`; `verify race` for concurrent transitions |
| Data store | 04, 07f, 08.5 | `verify rls`, `verify limits` (pagination), `cloud` reads of grants and policies |
| Object storage | 07, 08.5 | `verify fileupload`, `verify limits` (upload size), `cloud` reads of bucket policy |
| Render context | 05 | `verify xss`, `verify csvinjection` |
| Browser boundary | 03, 05, 08 | `verify cors`, `verify clickjacking`, `verify redirect`, `verify cachepoisoning`, cookie flags from `verify auth` |
| Outbound call | 06 | `verify ssrf` with `ensphere callback` |
| Expensive or billed operation | 08.5 | `verify ratelimit` with an approved burst; `cloud` reads of spend caps |
| Limiter | 08.5, 07e | `verify ratelimit`, `verify limits`, `verify graphql` for depth and batch; edge rules read as 07e describes |
| Secret | 01, 07 | Source review of env handling, client bundles, and git history; `cloud secrets` metadata |
| Audit trail | 07 | `cloud logging`; source review of auth and admin paths |
| Platform configuration | 07 and its appendices | `ensphere cloud <provider>` read-only |

Where no family fits, `verify request` sends the request and records it
under the role you declare, and the control for any family probe is sent
the same way. The families are conveniences; the cycle is the rule. A
check that reads one response, such as a framing, CSP, CORS, or cookie
header, still has a real control: the same request to a static asset or a
second route, which shows whether the header comes from the application or
from the edge in front of it, and that decides where the fix goes.

## Turning an invariant into claims

Every control in the table can fail in the same five ways. For each role
the sandbox exposes, ask each question and write the answer as a coverage
row; each "no" is a candidate.

1. **Present.** Does the control exist at all on this surface?
2. **Placed.** Is it in a layer the caller cannot bypass? A limiter in the
   app behind an edge that also exposes the origin is not placed. A check
   in the UI is not placed.
3. **Keyed.** Is it bound to the right subject? A rate limit keyed on IP
   behind a proxy that does not forward the client address is keyed on the
   proxy. An object check keyed on object id alone is not keyed on the
   caller.
4. **Shared.** Does it hold across instances and restarts? An in-memory
   limiter on a multi-instance deployment resets per instance.
5. **Bounded.** Does it have a ceiling? A pagination parameter with no
   maximum, an upload with no size cap, a queue with no concurrency limit.

A source-review candidate says which question failed and cites the line. A
live measurement then shows the consequence: the request that should have
been refused and was not, with its baseline and control.

## Beyond the map: hypotheses

The table above is the floor of an assessment. It guarantees every role is
checked; it cannot know what this particular system is for, and the
failures that cost a business most are often specific to it: a coupon that
stacks, a refund that can be replayed, a plan limit enforced only in the
UI. Session 01 therefore writes `01-recon/hypotheses.md` after the role
table, and the contract (Hypotheses) says how the rest of the run treats it.

Generate hypotheses from the application description, the objects and
workflows inventory, the data classes, and the billed services by asking six
questions about this system, not about systems in general:

1. **Where does money move?** Prices, credits, refunds, coupons, quotas,
   metered usage, payouts. What would let a user pay less, get more, or
   make the owner pay?
2. **What is worth reading?** The data classes recon found. Who must not
   see each, and which path passes near it: an export, a search, a
   notification, a shared link, a log line?
3. **What is privilege here?** Roles, tenants, admin, ownership, verified
   status. Which transitions grant it, and which request fields feed those
   transitions?
4. **What does the system trust from outside?** Webhooks, callbacks, OAuth
   returns, imported files, third-party identifiers, signed URLs. What
   happens when one is forged, replayed, or arrives late?
5. **What is scarce?** Invites, seats, codes, storage, model calls,
   free-tier allowances. What counts them, and where is the count enforced?
6. **What did the developers build that a framework usually provides?**
   Custom auth, custom crypto, a hand-written limiter or parser, a home-grown
   template engine. Each is a role filled without the usual guarantees.

An answer that is already a row from the roles table is not a hypothesis;
the row covers it. An answer that is not becomes one row here:

| Id | Goal on synthetic data | Rests on | Owning session | Edges |
|----|------------------------|----------|----------------|-------|
| HYP-001 | Apply one coupon twice to one order by racing two redemption requests | `api/checkout/coupon.ts:41` reads the remaining-uses count and writes it back without a transaction | 04 | single step |
| HYP-002 | Make the owner pay for image transforms with no account | `routes/thumb.ts:12` calls the transform API for any URL before any auth check | 08.5 | single step |
| HYP-003 | Read tenant B's export as tenant A | `jobs/export.ts:77` emails a download token; `api/download.ts:19` checks that the token exists, not whose it is | 04, joined in 08.7 | token issuance (04); download without tenant check (04) |

The goal is concrete and provable in the sandbox. "Rests on" cites the file
and line, or the configuration item, that makes the goal plausible; a
hypothesis with nothing to rest on is a guess and is written as one, with
`rests on: none`, so the owning session tests it last. The owning session
is the category that resolves single-step claims of that kind. A multi-step
goal lists its edges, each owned by a category session, and names 08.7 as
where they join once every edge has been probed.

Zero hypotheses is a legitimate answer for a small system whose role table
already names every path to money, data, and privilege. Write the reasoning
down. A long list is not a better one: five hypotheses that each rest on a
line beat twenty that rest on nothing.

## Using this file

- **Session 01** writes a role table in `01-recon/report.md`: one row per
  role above, the product that fills it (free-form lowercase name, or
  `none` with the evidence that nothing does), and the file where it lives.
  The stack block in the target profile lists those products by dimension
  so Session 01.5 can match them to checklists. Then it writes the
  hypotheses table above into `01-recon/hypotheses.md`.
- **Session 01.5** loads a checklist when one exists for the product. When
  none exists, it plans the session from this table: the "how to find it"
  column gives the source-review target, the session methodology gives the
  measurement procedure, and the five questions give the candidates.
- **Every session** treats a place where the invariant might not hold as a
  candidate and gives it a coverage row. A missing-control finding is a
  place where the invariant does not hold; the fix column, adapted to the
  stack, is the recommendation, and the validation criterion is the
  invariant restated as a test.
- **Managed services** fill roles too. When a vendor fills a role (hosted
  auth, managed storage, an edge limiter), the check is the operator's
  configuration of that service read through its CLI, never a probe of the
  vendor.
- **Never** mark a role `not_applicable` because its product is unfamiliar.
  Ask what fills the role; if nothing does, that is the affirmative
  evidence, and for roles a server component always has (entry point,
  parser, limiter, secret) the absence is itself a candidate.

## What this map does not cover

Some things a due-diligence reader may expect are outside every session:
dependency and supply-chain vulnerabilities, TLS configuration and cipher
choice, architecture review, and malicious-code review. `coverage-map.md`
names these against WSTG and ASVS so the report states them as not covered
rather than leaving them implied. Do not stretch a role above to claim them.
