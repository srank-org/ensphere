# Session 06: Server-Side Request Forgery

## Objective

Determine whether an inventoried server-side fetcher allows an attacker to
influence destinations or protocols beyond the intended outbound policy.

## Candidate Generation

Candidates are the rows of a fetcher matrix: endpoint/input, component,
identity/role, supported schemes, DNS and redirect behavior,
parser/normalization steps, allow/deny rules, proxy/egress controls, response
disclosure, and callback availability.

Open the assigned checklists first; `go-net-http.md` and the framework
checklists name the outbound client idioms and redirect settings to trace.

Use only an operator-controlled callback/canary service and explicitly
authorized target hosts. `ensphere callback` provides a local listener when
the target can reach the analyst machine; otherwise use a callback service the
operator supplies. If no safe callback or live fetcher exists, use
source/configuration evidence and mark dynamic rows `not_tested` with that
reason.

Source review traces the user-controlled URL/host/path through parsing,
resolution, redirects, proxy selection, request creation, response handling,
and egress policy.

Live-target candidates require behavior suggesting a server-side fetch, not
merely client-side navigation, browser prefetch, or reflected input.

## Controlled Validation

1. Establish a normal fetch to the controlled service.
2. Use a unique callback token to attribute the server-side request.
3. Test a bounded disallowed destination using a non-routable/documentation
   address or controlled deny endpoint; do not scan internal hosts or ports.
4. Test redirects, hostname normalization, IP representation, or DNS behavior
   only when tied to a named policy/parser hypothesis and still terminating at
   controlled infrastructure.
5. Compare response disclosure and callback evidence with negative controls.

Do not request cloud metadata paths, obtain instance tokens or credentials,
read local files, use `file://`, `gopher://`, or `dict://` to interact with
internal services, enumerate network ranges/ports, access unrelated third
parties, or retrieve sensitive response bodies. Describe cloud/internal impact
as a risk scenario unless separately observed through authorized benign
canaries.

## Interpretation and Stop Rules

Distinguish browser-side requests, DNS-only interactions, generic URL parsing,
proxy errors, and actual server-side connections. A callback directly proves
the controlled fetch but not access to every internal destination. Stop when the
destination-policy claim is resolved, callback/action limits are reached, or a
next step would access a real internal/metadata resource only to raise impact.

The session report lists outbound policy and egress facts, callback
attribution, untested destination classes, and risk scenarios labeled as
such.
