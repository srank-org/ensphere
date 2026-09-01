# Session 04: Authorization

## Objective

Assess object-level, function-level, property-level, tenant, and workflow
authorization using explicitly supplied identities and owned test objects.

## Preflight and Coverage

Create an authorization matrix:

| Identity/role | Tenant | Object owner | Operation | Property/state | Expected result | Coverage |
|---------------|--------|--------------|-----------|----------------|-----------------|----------|

Include reads and writes, privileged functions, indirect references, list and
search endpoints, bulk operations, exports, background jobs, and material
workflow transitions only when present in recon.

Open the assigned checklists first. When the data layer enforces
authorization (Supabase RLS, Postgres policies), the matrix has one row per
table per policy and `supabase-rls.md` supplies the source-review and
`ensphere verify rls` procedure. When the application enforces it (Prisma or
Drizzle where clauses, handler checks), `prisma-drizzle.md` and the framework
checklist name the idioms to trace.

Use two or more controlled accounts/tenants and paired owned test objects when
the boundary requires them. If these fixtures are unavailable, do not substitute
real users' identifiers; mark the affected rows blocked.

## Candidate Generation

Source review traces authorization from entry point through middleware,
service, data access, serializers, and async consumers. Record whether checks
bind subject, tenant, object, operation, state, and property.

Live-target candidates come from the inventory and expected-access matrix. Do not
discover targets by enumerating sequential or guessed identifiers.

## Controlled Validation

For each candidate:

1. Verify the control identity can access its own test object or permitted
   function (positive control).
2. Replay the same operation with one boundary changed: object owner, tenant,
   role, operation, property, or workflow state.
3. Use a negative control such as a nonexistent owned identifier or disallowed
   state to distinguish authorization behavior from generic errors.
4. Compare status, response body, side effects, audit events, and persistent
   state as applicable.
5. For writes, mutate only a benign canary field on owned fixtures and restore
   it. Verify cleanup.

Do not enumerate other users' objects, read sensitive fields for proof, modify
unauthorized records, or invoke destructive business actions. Outside a
sandbox, do not chain into account takeover; in a sandbox, a chain that
crosses sessions belongs to Session 08.7. A differing status or body length
alone is not proof; verify whether protected data or state was actually
exposed within the controlled fixture.

## Workflow and state

Every workflow in the recon inventory (checkout, refund, invitation, approval,
quota, subscription change, export) is a state machine, and each transition
is an authorization decision that binds subject, object, current state, and
the values the client may supply. One candidate per transition, each a
single-step claim:

- **Skip**: reach a later state without the earlier one (paid without
  payment confirmation, approved without review).
- **Replay**: apply the same transition twice (refund twice, redeem a code
  twice, accept an invitation twice).
- **Wrong state**: transition from a state that should not allow it (edit
  after submission, cancel after fulfilment).
- **Client-supplied truth**: a price, total, quantity, role, or tenant
  accepted from the request instead of recomputed server-side; negative or
  zero quantities that cross a business invariant.
- **Cross-boundary state**: act on another tenant's or user's object in a
  state only its owner should reach.
- **Concurrent transitions**: two transitions racing on one object; use
  `ensphere verify race` on owned fixtures only.

Each is validated with the baseline, probe, control cycle above: the
legitimate transition is the positive control, a nonexistent or disallowed
state the negative control. In a sandbox, drive the transition to completion
and record the resulting state. On staging, use only benign canary
transitions on owned fixtures and restore them. Multi-step paths that combine
two or more of these, or a workflow flaw with a finding from another session,
are chain candidates for Session 08.7; record them in the report's candidate
index rather than pursuing them here.

## Interpretation and Stop Rules

- Distinguish object existence leakage from unauthorized object access.
- Distinguish UI hiding from server-side enforcement.
- Distinguish stale/cached responses and invalid object state from a policy
  decision.
- Treat source-only missing checks as candidates unless reachability and
  enforcement outcome are established.
- Stop after the narrow subject-object-operation claim is resolved. Do not
  broaden to unrelated roles or objects merely to strengthen proof.

## Report

Write `04-authz/report.md` with the tested authorization matrix, fixture and
cleanup record, resolved findings, tested defenses, unresolved boundaries,
baseline/probe/control evidence, root causes, impact, remediation and validation
criteria, and citations. State exactly which roles/tenants were and were not
covered.
