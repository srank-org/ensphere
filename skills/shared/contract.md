# Ensphere Contract

> Ensphere produces verifiable facts. The analyst produces all security
> judgments.

This is the one rulebook for an assessment. Every session, checklist, and
report follows it. Methodology files add procedure for one category;
checklists translate that procedure into one stack's idioms. Neither may
weaken a rule stated here, and where they seem to, this file wins. When the
CLI refuses an action (out of scope, over the risk ceiling, unverifiable
ledger), the refusal is part of this contract: do not work around it.

An agent reads this file once before Session 01 and returns to it when a
rule is in doubt. A person reads it to learn what an Ensphere report means
and what it does not claim. It is deliberately complete rather than short.

## Purpose and posture

Ensphere is a defensive checker. The person running it owns the system under
assessment or is explicitly authorized by its owner. The deliverable is a
report of what was checked, what was found, which controls are missing, how
to fix each one, and what was not checked and why, plus a one-page
Statement of Assessment that the operator signs.

Three commitments hold throughout:

- **Facts and judgments stay separate.** Every conclusion cites the
  measurement, source line, or observation it rests on, and the reader can
  follow the citation to the raw record.
- **Nothing real is put at risk.** Proof happens in a disposable sandbox
  seeded with synthetic data. Staging receives bounded measurement only.
  Production is never sent a request.
- **Coverage is stated, never implied.** What was not tested is written
  down with the reason. A report never says "secure".

## Who does what

| Area | Ensphere CLI (deterministic) | Analyst (AI agent or human) |
|------|------------------------------|-----------------------------|
| Scope | Validates every request host against `--in-scope` and refuses everything else. | Decides whether authorization and scope are sufficient to proceed. |
| Discovery | Scans source for sink patterns, parses OpenAPI specs, records inventories. | Decides what the project is, which stack it runs on, and what needs checking. |
| Measurement | Sends bounded requests and records status, timing, hashes, headers, counts, and configuration values into a hash-chained ledger. | Defines the claim, reads the raw numbers, and interprets them. |
| Reporting | Verifies evidence hash chains, citation paths, coverage files, and registry schema; derives the statement from the workspace. | Assigns status, confidence, severity, priority, remediation, and missing controls. |

Given the same inputs the CLI produces the same outputs. It never emits
status, confidence, "vulnerable", "safe", or a threshold verdict, and it
never chooses a technique whose name presumes the outcome. If a CLI output
seems to contain a judgment, treat it as a bug, report the raw measurement,
and note the discrepancy in the session report.

The analyst never delegates a judgment to the CLI and never presents a CLI
number as a conclusion without the baseline and control that give it meaning.

## Authorization and scope

Authorization is confirmed before Session 01, recorded in `config.md`, and
never inferred from repository access, a deploy key, or a running local copy.
The authorization covers one selected deployable target; a monorepo is not a
target until one application or service in it is named.

- **Source is always in scope.** Source review proceeds with or without a
  live target.
- **A live target is optional** and is one of the two tiers in
  Environments. Its URL, tier, and in-scope hosts are recorded in
  `config.md` and every verify command carries `--in-scope`.
- **Third parties are never targets.** A payment, mail, AI, or analytics
  provider the application calls is out of scope even when its hostname
  appears in the code. Only the operator's own configuration of that
  provider, read through the provider's CLI, is assessed. In the sandbox
  those calls go to test keys or stubs.
- **Perspective defaults to external and unprivileged.** Use only the
  identities, roles, tenants, and objects placed in scope. Elevated
  identities are used only for the checks that need them and are named in
  the coverage row.
- **Prohibited without exception:** enumerating unrelated assets, extracting
  real data, reading real secret values, obtaining cloud tokens, dumping
  credentials, establishing persistence, evading rate limits or WAFs, and
  load or denial-of-service testing. Synthetic fixtures and test keys inside
  the sandbox are not real data or secrets.
- **Request limits are operator-approved.** A burst runs only with an
  approved count for that endpoint and environment, starts below the
  expected limit, and stops at the first throttle or sign of instability.
  It measures limiter behavior; it is not load testing. Without an approved
  count the check is `blocked` with that reason.
- **Payload risk is capped.** Every verify command carries `--max-risk`
  (1 to 5, default 3). Record the ceiling in the session plan and do not
  raise it during a session; if a check needs a higher ceiling, record it
  `blocked` and ask at the next human gate. Risk 4 and 5 payloads never
  read credentials or execute code, whatever the ceiling.
- **Leads are not findings.** Source candidates, `ensphere scan` matches,
  and imported scanner results establish that something is worth checking,
  never that it is reachable or exploitable.

Missing optional context (a second tenant, a provider login, a staging URL)
is a coverage limitation. It never widens what may be tested.

## Environments

A live target belongs to one of two tiers, and the tier decides what a
session may do.

| Tier | What it is | What is permitted |
|------|------------|-------------------|
| `sandbox` | A local, disposable instance of the source under assessment, seeded with synthetic data, whose third-party calls go to test keys or stubs, reachable only from the operator's machine. `shared/sandbox.md` says how to build, isolate, seed, and reset it; Session 01 records the result in `01-recon/sandbox.md`. | Everything in scope, including state changes, multi-step chains, and end-to-end proof. Cleanup is a reset. The operator authorizes this once by confirming the isolation check. |
| `staging` | An operator-owned deployment with fixture data, behind the real edge and platform configuration. | Bounded measurement. A state-changing step needs explicit authorization in the session plan, defined limits, rollback, and cleanup evidence. |

`target.environment` is `sandbox`, `staging`, or `none`. There is no
production tier. The only thing Ensphere does with a production account is
read its provider configuration through the provider CLI, read-only, when
the operator names that account. No HTTP request from an assessment reaches
production, and a hostname that resolves to production is never placed in
`--in-scope`.

The sandbox proves. Staging measures what a sandbox cannot show: the edge in
front of the origin, the deployed environment and its secrets handling, the
shared limiter store, platform settings, and drift between source and
deployment. A project may have both; the plan names which sessions use
which, and a finding names the environment it was observed in.

An instance that fails any line of the isolation check is not a sandbox.
Record it as `staging` or stop. Never promote an environment to `sandbox`
to permit a step the plan did not authorize.

## Pacing

An assessment runs from Session 01 to Session 09 in one continuous run. The
agent does not stop between sessions to report progress; it writes the
session report, marks progress, runs `ensphere run next`, and continues.
The only pauses are human gates, where a decision belongs to the operator:

1. Authorization and first-run inputs, once, before Session 01.
2. The sandbox start, seed, and reset commands, once, before they run.
3. An assessment-level blocker (below).
4. A state-changing step on staging that the plan does not already
   authorize, or a staging burst count the config does not already hold.
5. The finished report and statement, after Session 09.

Foresee gates 2 and 4 in Session 01.5 and ask for everything at once, so a
run that starts with its inputs reaches Session 09 without a question.
Anything else that would need the operator is recorded as `blocked` or
`not_tested` and the run goes on.

Checkpoints exist for context loss, not for pausing. Before a long
operation write `checkpoint.md` in the session directory with the position
in `coverage.yaml`, completed and remaining candidates, evidence paths and
chain state, and request counters. On resume, read it and continue from
where it stopped; never repeat a completed probe. Delete it when the
session report is written.

## Blockers

Two kinds of blocker, handled differently.

**Assessment-level.** Nothing meaningful can proceed: authorization or the
target cannot be established; the source path is wrong; the sandbox cannot
be started (no container runtime, no local database, no seed path) and no
staging exists; the sandbox fails its isolation check and cannot be fixed.
Stop. Write a **Needs from you** list with the exact command or action for
each item, tell the operator, and do nothing else until they answer.

**Session-level.** One check or one session needs a provider CLI, a
credential, a test account, a second tenant, an approved burst count, or a
higher risk ceiling that is absent:

1. Tell the operator exactly what is needed and the command to run (for
   example `supabase login`, `wrangler login`, `gcloud auth login`).
2. Do not install software or authenticate on the operator's behalf unless
   they say so.
3. Record the affected coverage rows `blocked` with the missing prerequisite
   as the reason and continue with everything that does not depend on it.
4. Re-run the blocked rows when the operator confirms, without repeating
   completed work.

Every session report ends with a **Needs from you** list, empty or not, so
the operator never has to search for what is limiting coverage. Session 01.5
collects the whole list once; later sessions add only what could not be
foreseen.

## Session lifecycle

Every session from 02 to 08.7 follows this sequence. Sessions 01, 01.5, and
09 have their own procedure in their methodology files and carry no
coverage file.

1. **Preflight.** Confirm authorization, the selected target, the source
   path, whether a live target is in scope and which tier it is, scope,
   identities and roles, request limits, the risk ceiling, and a writable
   evidence path. Read the previous session report and any checkpoint.
2. **Coverage file.** List the applicable surface for this session in
   `coverage.yaml` (schema below), one row per surface and check, each
   marked `planned` or, with a reason, `not_tested`, `blocked`, or
   `not_applicable`. This is the record of what was checked.
3. **Candidates.** Turn the recon inventory, the fundamentals map, the
   loaded checklists, and source review into narrow claims. A candidate is
   not a finding.
4. **Controlled validation.** Baseline, probe, control (below), one
   candidate at a time.
5. **Resolution.** For each candidate record status, confidence, evidence
   strength, alternatives considered, and citations. Update its coverage
   row to `tested` with the evidence IDs.
6. **Stop check.** Stop when the claim is supported or contradicted, the
   approved request limit is reached, the target becomes unstable, or the
   next step would only increase impact for a more dramatic proof. In a
   sandbox the last clause does not apply: continue until the claim is
   demonstrated end to end or contradicted.
7. **Session report.** Findings, missing controls, tested defenses,
   unresolved candidates, limitations, evidence index, Needs from you.
   Before writing it, reconcile `coverage.yaml`: no row is still `planned`,
   every `tested` row cites evidence, and `ensphere evidence verify`
   passes on the session ledger. Then mark the session terminal in
   `progress.md` and run `ensphere run next`.

## Coverage file

Every session directory from 02 to 08.7 holds `coverage.yaml`. It is
machine-read: the report gate validates it, counts it, and checks that every
`tested` row cites evidence that exists in that session's ledger;
`ensphere run statement` derives the "checks executed" and "not checked"
numbers from it. Never claim a check in prose that is not a row here. When
a session discovers surface the plan did not list, add the row before
testing it; nothing is tested unrecorded.

```yaml
session: "02"
rows:
  - id: COV-02-001
    surface: "POST /api/search"        # endpoint, table, bucket, function, or config item
    check: "sql_predicate_control"     # short lowercase name of the claim tested
    identity: "[TENANT_A_USER]"        # placeholder from sandbox.md, or anonymous
    state: tested                      # planned | tested | not_tested | blocked | not_applicable
    evidence_ids: [EVID-012, EVID-013] # required for tested; must exist in this session's evidence.jsonl
    transcripts: []                    # optional workspace-relative paths
    checklist: "prisma-drizzle"        # optional: the checklist item that produced the row
    reason: ""                         # required for not_tested, blocked, not_applicable
```

| State | Meaning |
|-------|---------|
| `planned` | Listed and not yet resolved. No row may remain `planned` when the session report is written. |
| `tested` | Baseline, probe, and control were run and recorded. A defense that held is still `tested`; its finding resolves `not_supported`. |
| `not_tested` | In scope but not run: no live target, out of time, or a stop rule fired. The reason says which. |
| `blocked` | Could not run for a named missing prerequisite: credential, account, burst count, tool, or environment tier. |
| `not_applicable` | Affirmative evidence shows the surface does not exist for this target. The reason cites that evidence. |

One row per surface and check. A row whose check spans several identities
is several rows. Rows with no evidence are not `tested`, whatever the
transcript says. A `source_only` assessment resolves every measurement row
`not_tested` with reason "no live target" and still resolves source-review
rows `tested` when the source evidence is cited.

The row id must match `COV-<session>-NNN`, the `session` field must match
the directory, and `surface`, `check`, and `state` are required. The gate
rejects a `DONE` session without this file.

## Controlled validation

For each candidate:

1. State one narrow, falsifiable claim: "input `q` changes the query
   predicate", "POST /api/upload has no limiter keyed on the user", "tenant
   A's user can read tenant B's invoice by id".
2. Capture a **baseline**: the normal request with the same endpoint,
   identity, and state, so the probe has something to differ from.
3. Send the smallest **probe** that distinguishes the claim.
4. Run a **control** that rules out the obvious alternative explanation:
   the same request against a nonexistent object, the same payload with the
   syntactic element neutralised, the same burst from a second identity, the
   legitimate path through a workflow. The category file names the control
   for each mechanism. If you cannot name a control, the result is
   `indicative` at best.
5. Repeat only enough to separate signal from noise, caching, or state
   drift. Timing claims need repeated baselines and probes interleaved.
6. Compare the raw observations and list the plausible alternatives.
7. Resolve and stop.

Do not spray payload lists or run bypass ladders. Every variant tests a
named hypothesis about a parser, encoding, key, or control. On staging,
never "test until exploited": the first probe that supports the claim ends
the check. In a sandbox, keep going until the claim is demonstrated end to
end, still one named hypothesis at a time, and reset when a probe leaves
state the next check would inherit.

A claim about a limiter or a cap is measured, not inferred: the absence of
a limiter in source is a source-review fact; whether requests are throttled
is a live measurement; the two are recorded separately and both are cited.

## Evidence

Every session writes to its own ledger, `<session-dir>/evidence.jsonl`,
through `ensphere verify` and `ensphere evidence log`. Entries are
hash-chained, ids are `EVID-NNN` and unique within that ledger, and
`ensphere evidence verify` must pass before the session is marked terminal.
When a finding cites an entry from another session's ledger, the citation
names the session directory as well as the id.

Every material observation belongs to one category:

| Category | Records |
|----------|---------|
| `ensphere_measurement` | A CLI request, response, timing, hash, count, or configuration value. |
| `source_review` | A cited file and line, data flow, or configuration fact. |
| `manual_observation` | A reproducible observation captured in a transcript and logged with `ensphere evidence log`. |
| `imported_lead` | An external scanner result with its source tool, rule, and severity preserved. |
| `agent_judgment` | A cited conclusion: status, confidence, severity, priority, remediation. |

For every cited artifact preserve the evidence id or workspace-relative
path, producer, time, target and identity context, exact request or
command, raw or losslessly redacted result, and hash-chain state. Every
registry entry lists its evidence categories and always includes
`agent_judgment`, so the reader can tell which lines are measurement and
which are conclusion.

Evidence strength describes support for a claim, not severity:

| Strength | Use when |
|----------|----------|
| `direct` | The behavior was observed with a baseline and a control, demonstrated end to end in the sandbox, or is unambiguous in source or configuration. |
| `corroborated` | Independent evidence types (for example source review and a live measurement) support the same claim and the alternatives were checked. |
| `indicative` | A relevant signal exists but a material alternative or missing input remains. |
| `insufficient` | The evidence cannot support the claim. Keep it as a lead or `not_tested`. |

Timing, status code, response size, reflection, and scanner output are never
`direct` merely because they repeat. The measurement must exclude the
alternative. Source review alone is `direct` only when the code path is
unambiguous and reachable from an inventoried entry point; otherwise it is
`indicative` until a live measurement or a sandbox run corroborates it.

## Findings

A finding is one resolved claim about one root cause. Deduplicate by root
cause and control while keeping distinct assets, roles, and consequences
visible; ten endpoints missing the same middleware are one finding with ten
affected locations.

**Kind.** Every finding has one:

| Kind | Meaning | Id |
|------|---------|----|
| `vulnerability` | A weakness in something that exists: code, a policy, a configuration value. The fix corrects it. | `VULN-NNN` |
| `missing_control` | A control the stack needs and the project does not have: no limiter on a billed endpoint, no size cap on uploads, no row policy on a tenant table, no budget alert. The fix adds it. | `CTRL-NNN` |

Decide by the fix. Missing controls are the main defensive output of an
assessment and are reported with the same rigor, evidence, and remediation
detail as vulnerabilities. An observed chain from Session 08.7 is a
`vulnerability` whose observed facts are its edge evidence ids in order.

**Status** records the conclusion about the narrow claim:

| Status | Meaning |
|--------|---------|
| `confirmed` | `direct` or `corroborated` evidence demonstrates the weakness or the absent control. |
| `likely` | Evidence supports it but one material uncertainty remains; strength is at least `indicative`. |
| `informational` | A factual condition worth reporting without asserting a weakness. |
| `not_supported` | Controlled checks contradict the candidate or show the control works for the tested case. |
| `not_tested` | Out of scope, blocked, inapplicable, or missing input. |

`confirmed` and `likely` findings are unresolved until fixed and are the
ones the statement counts. `informational` findings need the same fields
and citations. `not_supported` findings are tested defenses (below).

**Confidence** (`high`, `medium`, `low`) is how sure the analyst is of the
status given the evidence and the alternatives considered. It is not a
second severity.

**Severity** (`critical`, `high`, `medium`, `low`, `informational`) is the
impact the finding would have on the real system with real data, judged
from what was achieved on synthetic data. A chain that ends short of its
goal is rated for what it reached. A missing control is rated for the
consequence it fails to prevent. `confirmed` and `likely` findings need one
of the four impact levels.

**Priority** (`P0` to `P4`) is the order to fix in, combining severity,
prerequisites, exposure, and effort. `P0` means before anything else. It is
the analyst's recommendation, stated with its reasoning, and the operator
may reorder it.

**CVSS v4.0** is optional, only meaningful for `vulnerability`, and always
accompanied by the metric rationale. `ensphere cvss` scores a vector the
analyst has already decided; it never decides the metrics.

**Category** is one of `injection`, `authentication`, `authorization`,
`xss`, `ssrf`, `cloud`, `api`, `abuse_and_cost`, `configuration`,
`secrets`, `other`, and normally matches the session that resolved it.

**Tested defenses.** A control that held under a controlled check is
reported as such: the surface, the check, the identity, the exact
conditions, and the evidence, with the finding resolved `not_supported`.
This is the report's positive content and it is narrow by construction.
It never generalises beyond the conditions tested.

**Honest negatives.** Say exactly what was tested, against which assets and
roles, with which controls. Never write "secure", "safe", or "no
vulnerabilities" as a broad conclusion. A missing signal is not proof that a
surface is absent. Blocked, partial, and source-only coverage must be
visible in every report that draws on the session.

**Source versus live drift.** When source and the live target disagree,
report both observations, name which environment each came from, and say
which the finding rests on. Never silently pick the more severe reading and
never assume the source is what is deployed.

**Imported leads.** Scanner and dependency-audit output is `imported_lead`
evidence. Its severity is preserved as the tool's, never presented as
Ensphere's, and a lead becomes a finding only through controlled validation.

**Chains.** A multi-step path is `observed` only when Session 08.7 ran every
edge in one sandbox run and recorded the goal state. Everything else is a
risk scenario with its unobserved edges marked as such. Severity of a risk
scenario rests on the edges that were observed.

## Session decisions and coverage labels

Session 01.5 decides every session and the plan records it. Decisions:

| Decision | Basis |
|----------|-------|
| `run` | Affirmative evidence that relevant surface exists and required inputs are available. |
| `limited` | Surface exists but some named asset, role, data, or environment is unavailable. |
| `blocked` | Surface exists but testing cannot proceed safely or meaningfully; name the missing input. |
| `skip` | A deliberate operator choice with rationale and accepted coverage risk. |
| `not_applicable` | Affirmative inventory shows the category does not exist for this target. |
| `uncertain` | Recon cannot prove presence or absence; run only bounded discovery or ask. |

`not_applicable` requires affirmative absence evidence. Missing credentials,
failed discovery, an unfamiliar product, or an absent signal never justify
it; use `blocked` or `uncertain` and name what is missing. Session 08.5
runs for every target with a server component. Session 08.7 runs only when
the environment is `sandbox`.

Coverage labels describe the plan for one session or the basis of one
finding, never product-wide assurance:

| Label | Meaning |
|-------|---------|
| `full` | Every input for the planned surface was available. |
| `partial` | Some named asset, role, data, or environment was missing; the effect is stated. |
| `blocked` | The session or check could not proceed for a named reason. |
| `source_only` | No live target; every measurement row is `not_tested` and findings rest on source review. |
| `client_only` | The target has no server component in scope; only the client or library was assessed. |
| `cloud_only` | Only provider configuration was in scope; no application HTTP surface was assessed. |

Workflow states in `progress.md` (`PENDING`, `IN_PROGRESS`, `DONE`,
`SKIPPED`, `BLOCKED`, `NOT_APPLICABLE`) describe progress only. `DONE`
means the session report is written and its coverage file reconciled; it
never means secure.

## Reporting and the statement

Session 09 synthesises; it runs no new probe. `ensphere run report` is the
gate: it fails on a non-terminal planned session, a missing or empty session
report, a missing or invalid plan, a broken evidence chain, an invalid
coverage file, or a registry entry that is uncited, mislabelled, or missing
a required field. Every error is fixed in the workspace file it points at;
every warning becomes a stated limitation.

The report obeys these rules, and the quality gate in Session 09 checks
each one before the session is `DONE`:

- No finding or missing control without a citation the reader can follow.
- Every missing control comes with a concrete fix for this stack and
  validation criteria the developer can run.
- "Checks executed" copies the `tested` coverage rows and "Not checked"
  copies every other resolved row with its reason. The counts equal the
  gate's coverage summary; the prose adds nothing that has no row.
- No broad "secure" or "safe" claim from bounded testing.
- No scanner severity presented as Ensphere severity.
- No attack path presented as observed unless every edge has evidence.
- No compliance certification language. A control mapping says which
  control a finding relates to, never that a control is met.
- No secrets, personal data, or absolute paths anywhere in the report.
- Coverage statements agree with the session reports and the plan.

The Statement of Assessment is produced by `ensphere run statement` from
the workspace, never written by the analyst. It carries the system,
environment, dates, assessor, operator, session decisions and states,
coverage counts, finding counts, unresolved findings, ledger hashes, and
the Ensphere version, and ends with the sentence: "This is a
self-assessment performed by the system owner with Ensphere. It is not an
independent audit, attestation, or certification." The operator signs it;
the model does not. If a number in it looks wrong, fix the workspace file
it came from and regenerate. The gate rejects a statement that is stale or
edited by hand.

## Reproducibility and redaction

A reportable finding includes the affected asset and exact location,
prerequisites and role, safe reproduction steps with non-secret inputs,
baseline, probe, and control observations, expected versus observed
behavior, citations, and cleanup steps when state changed. A reader with
the sandbox record must be able to reproduce it.

Use placeholders such as `[SESSION_TOKEN]`, `[TENANT_A_USER]`, and
`[TEST_OBJECT_ID]`, taken from `01-recon/sandbox.md` where they were
defined. Never place live secrets or personal data in evidence notes,
transcripts, reports, or prompts; the ledger redacts known secret shapes,
but redaction is a backstop, not a licence. Workspace paths are relative;
no absolute paths, URLs, `~`, or parent traversal in citations.

Every state change outside the sandbox records what changed and the
cleanup evidence. Inside the sandbox the reset command and its record are
the cleanup.

## Vocabulary

The values the report gate accepts, in one place.

| Field | Values | Where |
|-------|--------|-------|
| Environment tier | `sandbox`, `staging`, `none` | plan, config, findings |
| Coverage row state | `planned`, `tested`, `not_tested`, `blocked`, `not_applicable` | `coverage.yaml` |
| Coverage row id | `COV-<session>-NNN` | `coverage.yaml` |
| Session decision | `run`, `limited`, `blocked`, `skip`, `not_applicable`, `uncertain` | assessment plan |
| Coverage label | `full`, `partial`, `blocked`, `source_only`, `client_only`, `cloud_only` | plan, findings |
| Workflow state | `PENDING`, `IN_PROGRESS`, `DONE`, `SKIPPED`, `BLOCKED`, `NOT_APPLICABLE` | `progress.md` |
| Evidence id | `EVID-NNN`, unique per session ledger | `evidence.jsonl` |
| Evidence category | `ensphere_measurement`, `source_review`, `manual_observation`, `imported_lead`, `agent_judgment` | registry |
| Evidence strength | `direct`, `corroborated`, `indicative`, `insufficient` | registry |
| Finding kind | `vulnerability`, `missing_control` | registry |
| Finding id | `VULN-NNN`, `CTRL-NNN` | registry |
| Finding status | `confirmed`, `likely`, `informational`, `not_supported`, `not_tested` | registry |
| Confidence | `high`, `medium`, `low` | registry |
| Severity | `critical`, `high`, `medium`, `low`, `informational` | registry |
| Priority | `P0`, `P1`, `P2`, `P3`, `P4` | registry |
| Category | `injection`, `authentication`, `authorization`, `xss`, `ssrf`, `cloud`, `api`, `abuse_and_cost`, `configuration`, `secrets`, `other` | registry |

For entries that are `not_supported` or `not_tested` the gate also accepts
`none` or `not_applicable` as confidence and severity and `NONE` or
`NOT_APPLICABLE` as priority. Use them only there. `info` is accepted as an
alias of `informational`; write `informational`.
