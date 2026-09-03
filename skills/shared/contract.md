# Ensphere Contract

> Ensphere produces verifiable facts. The analyst produces all security judgments.

This is the one rulebook for every session. Category files add procedure; they
never weaken the scope, evidence, or stop rules here.

## Who does what

| Area | Ensphere CLI (deterministic) | Analyst (AI agent or human) |
|------|------------------------------|-----------------------------|
| Scope | Validates every request host against `--in-scope`; refuses everything else. | Decides whether authorization and scope are sufficient. |
| Discovery | Scans source for sink patterns; parses OpenAPI specs; records inventories. | Decides what the project is, which stack it runs on, and what needs checking. |
| Measurement | Sends bounded requests and records status, timing, hashes, headers, counts, and configuration values. | Defines the claim, reads the raw numbers, and interprets them. |
| Reporting | Verifies evidence hash chains, citation paths, and registry schema. | Assigns status, confidence, severity, priority, remediation, and missing controls. |

The CLI never emits status, confidence, "vulnerable", "safe", or a threshold
verdict. If a CLI output seems to contain one, treat it as a bug and report the
raw measurement instead.

## Purpose and posture

Ensphere is a defensive checker. The person running it is checking a system
they own or are authorized to assess, and the deliverable is a report of what
was checked, what was found, and which controls are missing. Ensphere never
extracts real data, never escalates on a system that can be hurt, and never
sends a probe to production. Proof happens in a sandbox (below).

## Environments

Source is always in scope. A live target belongs to one of two tiers, and the
tier decides what a session may do:

| Tier | What it is | What is permitted |
|------|------------|-------------------|
| `sandbox` | A local, disposable instance of the source under assessment, seeded with synthetic data, whose third-party calls go to test keys or stubs, reachable only from the operator's machine. `shared/sandbox.md` says how to build, isolate, seed, and reset it; Session 01 records the result. | Everything in scope, including state changes, multi-step chains, and end-to-end proof. Cleanup is a reset. The operator authorizes this once by confirming the isolation check. |
| `staging` | An operator-owned deployment with fixture data, behind the real edge and platform configuration. | Bounded measurement. A state-changing step needs explicit authorization in the session plan, defined limits, rollback, and cleanup evidence. |

Production is never a live target. The only thing Ensphere does with a
production account is read its provider configuration through the provider
CLI, read-only, when the operator names that account. No HTTP request from an
assessment reaches production.

The sandbox proves. Staging measures what a sandbox cannot show: the edge in
front of the origin, deployed environment, the shared limiter store, platform
settings, and drift between source and deployment. A project may have both;
the plan names which sessions use which.

## Session lifecycle

Every session follows this sequence:

1. **Preflight.** Confirm authorization, the selected target, the source
   path, whether a live target is in scope and which environment it is,
   scope, identities and roles, request limits, and a writable evidence path.
2. **Coverage file.** List the applicable surface for this session in
   `coverage.yaml` (schema below) and mark each row `planned`, `tested`,
   `not_tested`, `blocked`, or `not_applicable`. The report gate validates
   this file; it is the record of what was checked.
3. **Candidates.** Turn the recon inventory, the loaded checklists, and source
   review into narrow claims. A candidate is not a finding.
4. **Controlled validation.** Baseline, probe, control (below).
5. **Resolution.** Record status, confidence, evidence strength, alternatives
   considered, and citations for each candidate.
6. **Stop check.** Stop when the claim is supported or contradicted, the
   approved request limit is reached, the target becomes unstable, or the next
   step would only increase impact for a more dramatic proof. In a sandbox the
   last clause does not apply: continue until the claim is demonstrated end to
   end or contradicted.
7. **Session report.** Findings, missing controls, tested defenses,
   unresolved candidates, limitations, evidence index. Before writing it,
   update `coverage.yaml` so no row is still `planned`.

## Coverage file

Every session directory holds `coverage.yaml`. It is machine-read: the
report gate counts it, checks that every `tested` row cites evidence that
exists in that session's ledger, and `ensphere run statement` derives the
"checks executed" numbers from it. Never claim a check in prose that is not
a row here.

```yaml
session: "02"
rows:
  - id: COV-02-001
    surface: "POST /api/search"        # endpoint, table, bucket, function, or config item
    check: "sql_predicate_control"     # short lowercase name of the claim tested
    identity: "[TENANT_A_USER]"        # or anonymous
    state: tested                      # planned | tested | not_tested | blocked | not_applicable
    evidence_ids: [EVID-012, EVID-013] # required for tested; must exist in this session's evidence.jsonl
    transcripts: []                    # optional workspace-relative paths
    checklist: "prisma-drizzle"        # optional: the checklist item that produced the row
    reason: ""                         # required for not_tested, blocked, not_applicable
```

One row per surface and check. A `tested` row means baseline, probe, and
control were run and recorded; a defense that held is still `tested`, with
the finding resolved `not_supported`. Rows with no evidence are not
`tested`, whatever the transcript says.

## Controlled validation

For each candidate:

1. State one narrow, falsifiable claim ("input `q` changes the query
   predicate", "POST /api/upload has no limiter keyed on the user").
2. Capture a **baseline**: the normal request with the same endpoint, identity,
   and state.
3. Send the smallest **probe** that distinguishes the claim.
4. Run a **control** that rules out the obvious alternative explanation. The
   category file names the control for each mechanism. If you cannot name a
   control, the result is `indicative` at best.
5. Repeat only enough to separate signal from noise, caching, or state drift.
6. Compare the raw observations and list plausible alternatives.
7. Resolve and stop.

Do not spray payload lists or run bypass ladders. Variants must test a named
hypothesis about a parser, encoding, key, or control. On staging, never "test
until exploited". In a sandbox, keep going until the claim is demonstrated,
still one named hypothesis at a time.

## Evidence

Every material observation belongs to one of these categories:

| Category | Records |
|----------|---------|
| `ensphere_measurement` | A CLI request, response, timing, hash, count, or configuration value. |
| `source_review` | A cited file and line, data flow, or configuration fact. |
| `manual_observation` | A reproducible observation captured in a transcript. |
| `imported_lead` | An external scanner result with its source tool, rule, and severity preserved. |
| `agent_judgment` | A cited conclusion: status, confidence, severity, priority, remediation. |

For every cited artifact preserve the evidence ID or workspace-relative path,
producer, time, target and identity context, exact request or command, raw or
losslessly redacted result, and hash-chain state.

Evidence strength describes support for a claim, not severity:

| Strength | Use when |
|----------|----------|
| `direct` | The behavior was observed with a baseline and a control, demonstrated end to end in the sandbox, or is unambiguous in source or configuration. |
| `corroborated` | Independent evidence types support the same claim and alternatives were checked. |
| `indicative` | A relevant signal exists but a material alternative or missing input remains. |
| `insufficient` | The evidence cannot support the claim. Keep it as a lead or `not_tested`. |

Timing, status code, response size, reflection, and scanner output are never
`direct` merely because they repeat. The measurement must exclude the
alternative.

## Findings and missing controls

Every finding has a `kind`:

- `vulnerability`: a weakness that was demonstrated or is unambiguous in source.
- `missing_control`: a control the stack needs and the project does not have,
  such as no rate limiter on a billed endpoint, no size cap on uploads, no RLS
  policy on a table. Missing controls are the main defensive output of an
  assessment and are reported with the same rigor as vulnerabilities.

Status records the conclusion about the narrow claim:

| Status | Meaning |
|--------|---------|
| `confirmed` | Direct or corroborated evidence demonstrates the weakness or the absent control. |
| `likely` | Evidence supports it but one material uncertainty remains. |
| `informational` | A factual condition worth reporting without asserting a weakness. |
| `not_supported` | Controlled checks contradict the candidate or show the control works for the tested case. |
| `not_tested` | Out of scope, blocked, inapplicable, or missing input. |

Keep confidence (`high`, `medium`, `low`), severity, and priority as separate
dimensions. `confirmed` needs `direct` or `corroborated` evidence. CVSS v4.0 is
optional and only meaningful for `vulnerability` findings.

Honest negatives: say exactly what was tested, against which assets and roles,
with which controls. Use `not_supported` for the tested claim. Never write
"secure", "safe", or "no vulnerabilities" as a broad conclusion. A missing
signal is not proof that a surface is absent. Blocked, partial, and
source-only coverage must be visible in every report.

## Session decisions and coverage

| Decision | Basis |
|----------|-------|
| `run` | Affirmative evidence that relevant surface exists and required inputs are available. |
| `limited` | Surface exists but some named asset, role, data, or environment is unavailable. |
| `blocked` | Surface exists but testing cannot proceed safely or meaningfully; name the missing input. |
| `skip` | A deliberate human choice with rationale and accepted coverage risk. |
| `not_applicable` | Affirmative inventory shows the category does not exist for this target. |
| `uncertain` | Recon cannot prove presence or absence; run only bounded discovery or ask. |

`not_applicable` requires affirmative absence evidence. Missing credentials,
failed discovery, or an absent signal never justify it.

Coverage labels: `full`, `partial`, `blocked`, `source_only`, `client_only`,
`cloud_only`. They describe the session plan, never product-wide assurance.
Source is always in scope; `source_only` means no live target was available,
so every measurement row is `not_tested` and findings rest on source review.
The environment tier (`sandbox`, `staging`, `none`) is recorded separately as
`target.environment`. Workflow states (`PENDING`, `IN_PROGRESS`,
`DONE`, `SKIPPED`, `BLOCKED`, `NOT_APPLICABLE`) describe progress only; `DONE`
never means secure.

## Scope and safety

- Use only assets, accounts, tenants, data, and roles explicitly placed in
  scope. Default to an external unprivileged perspective.
- Prefer owned or synthetic objects, non-sensitive canaries, read-only
  provider APIs, and reversible changes.
- The live target is a sandbox or staging as defined in Environments. Offer
  to stand up a sandbox when none exists. Never probe production.
- Never enumerate unrelated assets, extract real data, read real secret
  values, obtain cloud tokens, dump credentials, establish persistence, evade
  rate limits or WAFs, or run load or denial-of-service tests. Synthetic data
  and test keys inside the sandbox are not real data or secrets.
- Rate-limit and resource-limit measurement uses an operator-approved bounded
  burst that starts below the expected limit and stops at the first throttle
  or instability. It is behavior measurement, not load testing.
- Outside a sandbox, a state-changing step requires explicit authorization in
  the session plan, defined limits, rollback, and cleanup evidence.
- Source candidates and scanner output are leads. Do not claim reachability or
  exploitability without corresponding evidence.

## Blockers and missing tooling

Two kinds of blocker, handled differently:

**Assessment-level.** Nothing meaningful can proceed: authorization or the
target cannot be established; the source path is wrong; the sandbox cannot be
started (no container runtime, no database, no seed path) and no staging
exists; the sandbox fails its isolation check. Stop. Write a `needs-from-you`
list with the exact command or action for each item, tell the operator, and
do nothing else until they answer.

**Session-level.** One check or one session needs a provider CLI, credential,
test account, second tenant, or approved burst count that is absent:

1. Tell the operator exactly what is needed and the command to run (for
   example `supabase login`, `wrangler login`, `gcloud auth login`).
2. Do not install software or authenticate on the operator's behalf unless
   they say so.
3. Record the affected checks `blocked` with the missing prerequisite and
   continue with everything that does not depend on it.
4. Re-run the blocked checks when the operator confirms, without repeating
   completed work.

Every session report ends with a **Needs from you** list, empty or not, so
the operator never has to search for what is blocking coverage.

## Pacing

An assessment runs from Session 01 to Session 09 in one continuous run. The
agent does not stop between sessions to report progress; it writes the
session report, marks progress, runs `ensphere run next`, and continues.
The only pauses are human gates, where a decision belongs to the operator:

1. Authorization and first-run inputs, once, before Session 01.
2. The sandbox start, seed, and reset commands, once, before they run.
3. An assessment-level blocker.
4. A state-changing step on staging that the plan does not already
   authorize, or a staging burst count the config does not already hold.
5. The finished report and statement, after Session 09.

Foresee gates 2 and 4 in Session 01.5 and ask for everything at once, so a
run that starts with its inputs reaches Session 09 without a question.
Anything else that would need the operator is recorded as `blocked` or
`not_tested` and the run goes on. Checkpoints exist for context loss, not
for pausing: write one before a long operation, and on resume read it and
continue from where it stopped.

## Reproducibility and redaction

A reportable finding includes the affected asset and exact location,
prerequisites and role, safe reproduction steps with non-secret inputs,
baseline, probe, and control observations, expected versus observed behavior,
citations, and cleanup steps when state changed.

Use placeholders such as `[SESSION_TOKEN]` and `[TEST_OBJECT_ID]`. Never place
live secrets or personal data in evidence notes, transcripts, reports, or
prompts. Workspace paths are relative; no absolute paths, URLs, `~`, or parent
traversal in citations.
