# Session 09: Report

## Objective

Produce the deliverable a developer or team acts on: what is broken, what is
missing, how to fix it, what was checked and held up, and what was not
checked. Session 09 performs no new probing.

## Gate

Run `ensphere run report`. Fix every error. Warnings become explicit
limitations. The gate output includes the coverage counts per session;
those are the numbers the report uses.

## Synthesis

1. Read config, plan, progress, every session report, evidence ledgers,
   transcripts, and checkpoints.
2. Build a claim-to-evidence table, deduplicated by root cause and control
   with distinct assets, roles, and consequences kept visible.
3. Separate observed facts from judgments; resolve contradictions and
   source-versus-live drift explicitly, never by picking the more severe
   reading.
4. Assign status, evidence strength, confidence, severity, and priority
   under the contract, and write remediation at the root-cause level with
   validation criteria the developer can run.
5. Only Session 08.7 produces observed chains; everything else is a risk
   scenario with its unobserved edges marked.

## Finding registry

Write `09-report/finding-registry.yaml`:

```yaml
generated_from: "Sessions 01-08.7"
findings:
  - id: VULN-001
    kind: vulnerability
    title: "Cross-tenant invoice read"
    category: authorization
    status: confirmed
    confidence: high
    evidence_strength: direct
    severity: high
    priority: P1
    cvss_v4: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    affected_assets: ["staging.example.invalid"]
    affected_locations: ["GET /api/invoices/{id}", "app/api/invoices/[id]/route.ts:24"]
    observed_facts:
      - "Account A received Account B's synthetic invoice fixture"
      - "The nonexistent-object control returned a distinct not-found response"
    root_cause: "The lookup is not constrained by the authenticated tenant"
    security_impact: "Any user can read any tenant's invoices"
    remediation: "Add the tenant id to the Prisma where clause and enable RLS on invoices"
    validation_criteria:
      - "Cross-tenant fixture request returns 404 without object data"
      - "Same-tenant owner request still succeeds"
    evidence_ids: [EVID-042]
    transcripts: ["04-authz/transcripts/VULN-001.md"]
  - id: CTRL-001
    kind: missing_control
    title: "No rate limit on OTP send"
    category: abuse_and_cost
    status: confirmed
    confidence: high
    evidence_strength: corroborated
    severity: medium
    priority: P1
    affected_assets: ["staging.example.invalid"]
    affected_locations: ["POST /api/auth/otp", "supabase/functions/send-otp/index.ts"]
    observed_facts:
      - "Handler has no limiter middleware; config.toml has no [auth.rate_limit] override"
      - "Approved burst of 20 in 10s returned 20x 200 with no RateLimit headers"
    root_cause: "Edge function is callable with the anon key and does no counting"
    security_impact: "Anyone can trigger unbounded SMS sends and edge-function invocations at the owner's cost"
    remediation: "Add an Upstash Redis sliding-window limiter keyed on phone number and IP before the send; set a Cloudflare rate-limiting rule on the path; enable the Supabase spend cap"
    validation_criteria:
      - "The 6th request in 60s for one phone number returns 429 with Retry-After"
    evidence_ids: [EVID-088, EVID-089]
    transcripts: ["08.5-abuse/transcripts/CTRL-001.md"]
```

`kind` is `vulnerability` or `missing_control`. Status values are
`confirmed`, `likely`, `informational`, `not_supported`, `not_tested`.
`cvss_v4` is optional and only for `vulnerability`. Every reportable item
needs affected locations, observed facts, root cause, impact, remediation,
validation criteria, and at least one citation.

## Invariants

What this assessment established becomes a check the target's own CI runs
on every pull request, with no agent. Write one file per invariant under
`.ensphere/invariants/` in the target repository, in the schema
`ensphere invariants validate` enforces (kinds `http`, `rate_limit`,
`size_limit`, `source`, `command`; `${VAR}` placeholders for the tokens
and ids the CI job supplies):

- for every `confirmed` or `likely` finding, the invariant its validation
  criteria describe, with `enforce: false` and the finding as `origin`;
  the fix list tells the developer to set `enforce: true` with the fix;
- for every tested defense worth keeping, `enforce: true` and the coverage
  row as `origin`, with the row's control observation among
  `origin.evidence`, so the file shows the check can fail;
- `surface` names the map surface; `origin.evidence` cites the ledger.

Run `ensphere invariants validate`, then `ensphere invariants run` against
the sandbox. An invariant from an unresolved finding is expected to fail
today; one from a tested defense must pass; an `error` is fixed before the
session ends. Retire, with a reason in its file, any existing invariant
this assessment could not re-establish. Set `origin.assessment` to the
statement digest after `ensphere run statement` writes it.

## Report structure

Write `09-report/report.md`:

1. **Summary**: what the system is, what was assessed, the three to five
   things to fix first, and the material coverage limits. No counts without
   context.
2. **Fix list**: every `confirmed` and `likely` finding ordered by priority,
   one paragraph each: what, where, why it matters, the fix, how to verify
   the fix. Missing controls and vulnerabilities are interleaved by priority.
3. **Missing controls by service**: a table of billing-exposed services and
   storage surfaces with the control state for each (limiter, key, cap,
   quota, budget alert) and the recommended control where absent.
4. **Detailed findings**: per finding, observed facts, baseline, probe, and
   control, root cause, prerequisites, safe reproduction, citations,
   remediation, validation criteria. CVSS rationale where a vector is given.
5. **Checks executed**: for each session, the `coverage.yaml` rows marked
   `tested` with the surface, check, identity, and evidence IDs, and the
   defenses found working with the exact conditions tested. Copy the rows;
   do not paraphrase or add checks that have no row. The counts must equal
   the report gate's coverage summary. This section is narrow by
   construction and never says "secure".
6. **Not checked**: every `not_tested`, `blocked`, and `not_applicable`
   coverage row with its reason and its effect on the conclusions.
7. **Hypotheses**: every row of `01-recon/hypotheses.md` with its outcome:
   the finding it became, the tested defense that held, or `not_tested` or
   `blocked` with the reason, taken from the coverage rows that carry its
   id. An empty table is reported with the reasoning recon gave.
8. **Invariants**: every file under `.ensphere/invariants/` with its
   origin, `enforce`, and today's result, and what changed in the map.
9. **Scope and method**: source path, live target and environment tier with
   the sandbox isolation record, dates, in and out of scope, checklists
   loaded, uncovered stack, approved request limits, tool versions.
10. **Appendices**: evidence index with hash-chain state, redactions; the
   coverage appendix from `shared/coverage-map.md` (every WSTG category and
   ASVS chapter with evidence IDs, `not_tested`, or `not covered`); optional
   compliance mapping; optional attack-path notes that keep observed edges
   visibly separate from hypothetical ones.

Then run `ensphere run statement`. It refuses to run until the gate is
ready, and it writes `09-report/statement.yaml` and `09-report/statement.md`
from the workspace: system and environment from `config.md`, session states
and plan decisions, coverage counts from every `coverage.yaml`, finding
counts by kind, status, and severity from the registry, unresolved finding
IDs, the ledger's final hashes, the Ensphere version, and who performed the
assessment. It ends with this sentence verbatim: "This is a self-assessment
performed by the system owner with Ensphere. It is not an independent audit,
attestation, or certification." Then a signature block for the operator.
It records a digest of its inputs, and the gate fails with `statement_stale`
if the workspace changes afterwards. Do not edit the statement by hand. If
a number looks wrong, fix the workspace file it came from and run the
command again. The operator signs it, not the model. The command also
writes `statement.json`, the record a release pipeline signs.

When a previous assessment's workspace is available, run `ensphere run
diff --previous <dir>`. It matches findings by kind, category, and title
first and by a shared affected location second, so keep a finding's title
stable across runs for the same root cause, and let the report's summary
say what is new, reopened, and resolved. Run `ensphere run sarif` when
findings go to code scanning. Both read the registry and decide nothing.

Write `09-report/evidence-appendix.md` as the claim-to-evidence table:
finding ID, claim, evidence category and strength, evidence ID or path,
producer, target and role context, integrity state, limitations.

## Quality gate

Run `ensphere run report` again. Then check for: uncited findings, status
inconsistent with evidence strength, severity unsupported by stated impact,
duplicates, scanner severity presented as Ensphere severity, hypothetical
edges presented as observed, a hypothesis with no outcome, certification
language, broad negative
assurance, secrets or personal data, and coverage statements that disagree
with session reports.

Mark Session 09 `DONE` only after the registry, report, appendix, statement,
and gate agree. The assessment is complete. Impact is confirmed only in the sandbox,
in Session 08.7; Ensphere never confirms it against staging or production.
A finding the sandbox could not reach stays at its evidence-supported status
with the reason recorded.
