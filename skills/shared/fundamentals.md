# Fundamentals

Every system, whatever it is built on, is made of the same roles. Each role
has an invariant that does not depend on the product filling it. This file is
the stack-agnostic map of what to check. Stack checklists only translate
these invariants into a framework's idioms; when no checklist matches, work
from this file and your own knowledge of the stack.

Recon names which product fills each role. The check is the same either way.

| Role | Invariant | How to find it in any stack | Generic fix when absent |
|------|-----------|-----------------------------|-------------------------|
| **Entry point** (HTTP route, RPC, message consumer, cron, webhook) | Every entry point is known, and its authentication state is deliberate. | Route registration, router files, function exports, infrastructure config that maps URLs to code. | Central route table; deny-by-default middleware; public routes in one named list. |
| **Parser** (query string, JSON, form, multipart, XML, headers) | Input is validated against a schema before use, and the body has a size cap. | Framework body parser settings, schema libraries, decode calls. | Schema validation at the boundary; body-size limit at the edge and in the app. |
| **Query construction** (SQL, NoSQL, LDAP, XPath, command, template, path) | User data reaches a query only as a parameter, never as syntax. | ORM raw-query escape hatches, string formatting into query calls, shell invocations, template compilation, path joins. | Placeholders; allowlists for identifiers such as column names; no shell; canonical path prefix check. |
| **Identity** (login, session, token, API key, OAuth, reset, MFA) | A credential proves one identity, cannot be replayed, forged, or reused after logout, and every state transition rotates what must rotate. | Auth middleware, token verification, session store, reset-token issuance, provider configuration. | Verified signatures with a fixed algorithm; short-lived tokens; rotation on privilege change; single-use reset tokens. |
| **Authorization decision** (object, property, function, tenant, workflow) | Every read and write binds the caller's identity to the object, tenant, operation, and property. Hiding in the UI is not enforcement. | The layer that owns the decision: handler checks, policy engine, ORM where clauses, database row policies. | Enforce in one layer as close to the data as possible; tenant column in every query or a database policy. |
| **Data store** (relational, document, key-value) | Only intended tables and operations are reachable; queries are bounded; connections and statements time out. | Grants and policies; pagination parameters; pool and timeout settings; exposed database APIs. | Least-privilege roles; row policies where the store supports them; `max_rows` clamps; statement and connection timeouts. |
| **Object storage** (buckets, uploads, downloads) | Writes are bounded in size, count, type, and path per caller; reads are either private or deliberately public with cost controls; nothing can list. | Presigned URL issuers, upload handlers, bucket policy or public flag, CDN in front. | Size and type constraints in the signed policy; caller-scoped key prefix; short TTL; private by default; CDN with cache in front of anything public. |
| **Render context** (HTML, DOM, markdown, email, PDF, export) | Untrusted content is encoded for the exact context it lands in. | Template engines, DOM sinks, sanitizer configuration, export writers. | Context-aware encoding by default; sanitizer allowlist; formula escaping in CSV. |
| **Outbound call** (fetcher, webhook sender, importer, previewer) | The destination is validated before connecting, redirects are re-validated, and internal or metadata addresses are unreachable. | HTTP client construction, URL parameters, redirect settings, egress rules. | Resolve then allowlist; block loopback, link-local, private ranges, and metadata hosts; timeouts. |
| **Expensive or billed operation** (mail, SMS, AI, transforms, exports, search, serverless invocation, third-party API) | It runs only after authentication and after a limiter keyed on the caller, backed by a store shared across instances, with a quota and a provider-side spend cap. | Calls to paid SDKs, heavy libraries, and job enqueues; limiter middleware and its store; provider billing settings. | Limiter keyed on user or API key (IP only for anonymous routes); shared store; per-user quota; queue with concurrency limit; budget alert and spend cap. |
| **Limiter** (rate, size, count, depth) | Every limit is enforced server-side, keyed on the right subject, shared across instances, and present at both the edge and the origin when an edge exists. | Middleware chain order; limiter store type; edge rules; origin reachability. | Edge rule plus origin limiter; shared store; origin not reachable except through the edge. |
| **Secret** (keys, tokens, connection strings) | Secrets live only where the code that needs them runs, never in clients, repositories, or logs. | Environment handling, client bundles, committed files, git history, logging calls. | Secret manager or platform secrets; server-only access; log redaction; rotation. |
| **Platform configuration** (cloud account, serverless, container, DNS, CDN) | Public exposure, invocation permissions, and cost controls are deliberate and recorded. | Provider configuration read through its CLI or console; infrastructure-as-code. | Least-privilege invokers; ingress restricted to the edge; budget alerts. |

## Using this file

- In Session 01, for each role write down which product fills it and where
  in the code it lives. Products are free-form names; the role is what
  matters.
- In Session 01.5, load a checklist when one exists for the product. When
  none exists, plan the session from this table: each row's "how to find it"
  gives the source-review target and each session's methodology gives the
  measurement procedure.
- In every session, a candidate is a place where the invariant might not
  hold. A missing-control finding is a place where the invariant does not
  hold and the fix column, adapted to the stack, is the recommendation.
- Never mark a role `not_applicable` because its product is unfamiliar. Ask
  what fills the role; if nothing does, that is the affirmative evidence.
