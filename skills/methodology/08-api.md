# Session 08: API Security

## Objective

Resolve API-specific candidates not already covered by injection,
authentication, authorization, XSS, or SSRF, without duplicating those sessions
or performing load testing.

## Preflight and Coverage

Build a matrix for each applicable REST, GraphQL, RPC/gRPC, WebSocket, SSE,
webhook, or message surface. Record version, operation, content type, identity
and role, tenant, object/data fixture, expected control, and coverage state.

Cover only relevant categories:

- documentation/schema and deprecated-version exposure;
- object/property authorization cross-checks;
- mass assignment and over-posting;
- GraphQL introspection, field authorization, and batching;
- webhook destination and signature handling;
- content-type/parser consistency;
- WebSocket/RPC origin, authentication, and operation authorization.

Defer underlying injection/auth/authz/XSS/SSRF conclusions to the earlier
session evidence; cite rather than retest them unless the API-specific transport
creates a distinct claim. Pagination caps, export size, rate limits, and
GraphQL cost belong to Session 08.5; record the endpoints here and hand them
over. Open the assigned checklists first.

## Candidate Generation

Source review maps schemas/serializers/binders, middleware ordering, field
allowlists, pagination caps, version routing, rate-limit keys, GraphQL resolvers,
webhook validators, and transport authentication.

Live-target review uses supplied specifications and observed application traffic.
Do not discover APIs through broad version/path brute force.

## Controlled Validation

- **Documentation/versioning**: compare advertised and observed operations;
  treat documentation exposure as informational unless sensitive access or a
  concrete control failure is shown.
- **Property authorization**: use the Session 04 paired-account/object method
  and inspect only controlled fields.
- **Mass assignment**: add one benign canary property to an owned test object,
  verify persistence and authorization, then restore it. Do not set role/admin,
  billing, ownership, or security-sensitive fields merely for proof.
- **Pagination/export ownership**: verify ownership filtering and cursor
  binding with synthetic data; size caps are measured in Session 08.5.
- **GraphQL**: use a harmless query and at most a two-operation batch unless a
  different bound is explicitly approved. Do not run deeply nested or resource-
  exhaustion queries.
- **Webhooks**: use a controlled callback and non-routable/controlled deny
  destination as the negative control. Do not use local-file or internal-service
  schemes. Verify signatures with owned test secrets and benign events.
- **Parser consistency**: compare only supported/closely related content types
  using the same benign data; avoid polyglot or smuggling behavior unless
  separately scoped.
- **WebSocket/RPC**: use owned sessions and benign operations; verify origin,
  authentication, and authorization independently.

## Interpretation and Stop Rules

Distinguish a schema/documentation fact from unauthorized access, a rate-limit
measurement from abuse feasibility, parser rejection from upstream behavior,
and missing response fields from property authorization. Stop when the narrow
claim is resolved, the approved request/action count is reached, or further
testing would create load, mutate sensitive state, enumerate data, or duplicate
an earlier session.

## Report

Write `08-api/report.md` with protocol/operation coverage, approved request
limits, controlled fixtures and cleanup, resolved findings, tested defenses,
cross-references to Sessions 02–06, unresolved transports/versions/roles,
remediation and validation criteria, and evidence citations.
