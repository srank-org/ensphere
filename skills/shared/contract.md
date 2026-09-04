# Ensphere Contract

> Ensphere produces verifiable facts. The analyst produces all security
> judgments.

This is the one rulebook for an assessment. Every session, checklist, and
report follows it; where a methodology or checklist seems to weaken a rule
here, this file wins. It is written for a capable model and a careful
person: principles where judgment is the analyst's, exact rules where the
CLI or the report gate enforces them. When the CLI refuses an action (out of
scope, over the risk ceiling, unverifiable ledger), the refusal is part of
this contract. Do not work around it.

## Principles

Ensphere is a defensive checker. The person running it owns the system under
assessment or is explicitly authorized by its owner. The deliverable is a
report of what was checked, what was found, which controls are missing, how
to fix each one, and what was not checked and why, plus a one-page Statement
of Assessment the operator signs.

- **Nothing real is put at risk.** Proof happens in a disposable sandbox
  seeded with synthetic data. Staging receives bounded measurement only.
  Production is never sent a request. No real data is read, no real secret
  is retrieved, nothing persists beyond the run.
- **Facts and judgments stay separate.** The CLI measures: it sends scoped
  requests and records status, timing, hashes, headers, counts, and
  configuration values. It never says vulnerable or safe, never applies a
  threshold, and never names a technique by its outcome. The analyst defines
  each claim, reads the raw numbers, and assigns every status, confidence,
  severity, priority, and fix. Every conclusion cites the measurement,
  source line, or observation it rests on, and the reader can follow the
  citation to the raw record. If a CLI output seems to contain a judgment,
  treat it as a bug and report the raw measurement.
- **Coverage is stated, never implied.** What was not tested is written
  down with the reason. A missing signal is never proof that a surface is
  absent. A report never says "secure".

## Authorization and scope

Authorization is confirmed before Session 01, recorded in `config.md`, and
never inferred from repository access, a deploy key, or a running local
copy. It covers one selected deployable; a monorepo is not a target until
one application or service in it is named.

- **Source is always in scope.** Source review proceeds with or without a
  live target.
- **A live target is optional** and belongs to one of the two tiers below.
  Its URL, tier, and in-scope hosts are recorded in `config.md`, and every
  verify command carries `--in-scope`. The CLI refuses any host outside it,
  including redirect hops.
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
  Without an approved count the check is `blocked` with that reason.
- **Payload risk is capped.** Every verify command carries `--max-risk`
  (1 to 5, default 3). Record the ceiling in the session plan and do not
  raise it during a session; a check that needs more is `blocked` until the
  next human gate. Risk 4 and 5 payloads never read credentials or execute
  code, whatever the ceiling. A request you construct yourself carries the
  risk you declare, and you declare it honestly.
- **Leads are not findings.** Source candidates, `ensphere scan` matches,
  hypotheses, and imported scanner results establish that something is
  worth checking, never that it is reachable or exploitable.

Missing optional context (a second tenant, a provider login, a staging URL)
is a coverage limitation. It never widens what may be tested.

## Environments

| Tier | What it is | What is permitted |
|------|------------|-------------------|
| `sandbox` | A local, disposable instance of the source under assessment, seeded with synthetic data, whose third-party calls go to test keys or stubs, reachable only from the operator's machine. `shared/sandbox.md` says how to build, isolate, seed, and reset it; Session 01 records the result in `01-recon/sandbox.md`. | Everything in scope, including state changes, multi-step chains, and end-to-end proof. Cleanup is a reset. The operator authorizes this once by confirming the isolation check. |
| `staging` | An operator-owned deployment with fixture data, behind the real edge and platform configuration. | Bounded measurement. A state-changing step needs explicit authorization in the session plan, defined limits, rollback, and cleanup evidence. |

`target.environment` is `sandbox`, `staging`, or `none`. There is no
production tier. The only thing Ensphere does with a production account is
read its provider configuration through the provider CLI, read-only, when
the operator names that account. A hostname that resolves to production is
never placed in `--in-scope`.

The sandbox proves. Staging measures what a sandbox cannot show: the edge in
front of the origin, the deployed environment and its secrets handling, the
shared limiter store, platform settings, and drift between source and
deployment. A project may have both; the plan names which sessions use
which, and a finding names the environment it was observed in. An instance
that fails any line of the isolation check is not a sandbox: record it as
`staging` or stop, and never promote an environment to permit a step the
plan did not authorize. Without a live target, `environment` is `none`,
every measurement row resolves `not_tested` with reason "no live target",
and source-review rows still resolve `tested` when the source evidence is
cited.

## Pacing and gates

An assessment runs from Session 01 to Session 09 in one continuous run. The
analyst does not stop between sessions to report progress. The only pauses
are human gates, where a decision belongs to the operator:

1. Authorization and first-run inputs, once, before Session 01.
2. The sandbox start, seed, and reset commands, once, before they run.
3. An assessment-level blocker (below).
4. A state-changing step on staging that the plan does not already
   authorize, or a staging burst count the config does not already hold.
5. The finished report and statement, after Session 09.

Foresee gates 2 and 4 in Session 01.5 and ask for everything at once. A gate
whose answer is already in `config.md` is pre-answered: the authorization
statement, sandbox commands under a `Sandbox` heading, approved burst counts
and upload sizes, the operator's name. Do not ask again; cite the heading.
Anything else that would need the operator is recorded as `blocked` or
`not_tested` and the run goes on.

The workspace is the protocol between sessions, not the analyst's memory.
Each session reads its inputs from files and writes its outputs to files, so
a session can run in a fresh context, as a subagent, or after a context
loss without losing its place. `SKILL.md` describes the orchestration.
Before a long operation write `checkpoint.md` in the session directory with
the position in `coverage.yaml`, completed and remaining candidates,
evidence paths and chain state, and request counters; on resume continue
from it and never repeat a completed probe; delete it when the session
report is written.

## Blockers

**Assessment-level.** Nothing meaningful can proceed: authorization or the
target cannot be established; the source path is wrong; the sandbox cannot
be started and no staging exists; the sandbox fails its isolation check and
cannot be fixed. Stop, write a **Needs from you** list with the exact
command or action for each item, and do nothing else until the operator
answers.

**Session-level.** One check or one session needs a provider CLI, a
credential, a test account, a second tenant, an approved burst count, or a
higher risk ceiling that is absent. Tell the operator exactly what is needed
and the command to run; do not install software or authenticate on their
behalf unless they say so; record the affected rows `blocked` with the
missing prerequisite; continue with everything else; re-run the blocked rows
when the operator confirms. Every session report ends with a **Needs from
you** list, empty or not. Session 01.5 collects the whole list once; later
sessions add only what could not be foreseen.

## Session lifecycle

Sessions 02 to 08.7 follow this sequence. Sessions 01, 01.5, and 09 have
their own procedure in their methodology files and carry no coverage file.

1. **Preflight.** Confirm authorization, the selected target, the source
   path, the live target and its tier, scope, identities and roles, request
   limits, the risk ceiling, and a writable evidence path. Read the previous
   session report and any checkpoint.
2. **Coverage file.** List the applicable surface for this session in
   `coverage.yaml`, one row per surface and check, each `planned` or, with a
   reason, `not_tested`, `blocked`, or `not_applicable`. Nothing is tested
   unrecorded: when a session discovers surface the plan did not list, add
   the row before testing it.
3. **Candidates.** Turn the recon inventory, the fundamentals map, the
   loaded checklists, the hypotheses assigned to this session, and source
   review into narrow claims.
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
   every `tested` row cites evidence, and `ensphere evidence verify` passes
   on the session ledger. Then mark the session `DONE` in `progress.md` and
   run `ensphere run next`.

A session the plan decided `skip`, `not_applicable`, or `blocked` writes a
short report naming the decision and its reason, lists its rows as
`blocked` when the decision is `blocked`, and is then `DONE` like any other.

## Hypotheses

The fundamentals map is the floor of an assessment, not its ceiling. It
guarantees every role is checked; it cannot know what one system is for.
Session 01 therefore writes `01-recon/hypotheses.md`: what a motivated user
of this exact system would try to obtain, on synthetic data, generated as
`shared/fundamentals.md` (Beyond the map) describes. Each hypothesis has an
id `HYP-NNN`, a goal, the source or configuration it rests on, an owning
session, and its edges when it needs more than one step.

Hypotheses are candidates and follow every rule candidates follow. Session
01.5 confirms the owning session of each; no hypothesis is left without an
owner. The owning session gives it a coverage row carrying
`hypothesis: HYP-NNN` and resolves the row with baseline, probe, control; a
multi-step hypothesis is split into single-step edges, each with its own row
in the session that owns that kind of claim. Session 08.7 joins the probed
edges into a chain; an edge no session probed is not an edge. A hypothesis
is never dropped silently and becomes a finding only through controlled
validation. Session 09 reports every hypothesis with its outcome. An empty
list is legitimate for a small system whose role table already names every
path to money, data, and privilege; Session 01 writes the reasoning down.

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
6. Compare the raw observations, list the plausible alternatives, resolve,
   and stop.

Every request is a named hypothesis about a parser, encoding, key, or
control; do not spray payload lists or run bypass ladders. On staging the
first probe that supports the claim ends the check. In a sandbox, keep
going until the claim is demonstrated end to end, still one hypothesis at a
time, and reset when a probe leaves state the next check would inherit.

A claim about a limiter or a cap is measured, not inferred: the absence of
a limiter in source is a source-review fact; whether requests are throttled
is a live measurement; the two are recorded separately and both are cited.

The ledger records each request's role. Verify families write their own
baseline and probe entries; a control, and any request shape no family
anticipates, is sent with `ensphere verify request --result control` (or
`baseline`, or `probe`) so it lands in the ledger under its role. The
report gate enforces the cycle: a `tested` row that cites a probe must also
cite a baseline and a control from the same ledger.

## Coverage file

Every session directory from 02 to 08.7 holds `coverage.yaml`. It is
machine-read: the report gate validates it, counts it, and checks its
citations; `ensphere run statement` derives the "checks executed" and "not
checked" numbers from it. Never claim a check in prose that is not a row
here.

```yaml
session: "02"
rows:
  - id: COV-02-001
    surface: "POST /api/search"        # endpoint, table, bucket, function, or config item
    check: "sql_predicate_control"     # short lowercase name of the claim tested
    identity: "[TENANT_A_USER]"        # placeholder from sandbox.md, or anonymous
    state: tested                      # planned | tested | not_tested | blocked | not_applicable
    evidence_ids: [EVID-011, EVID-012, EVID-013]  # required for tested; must exist in this session's evidence.jsonl
    transcripts: []                    # optional workspace-relative paths
    checklist: "prisma-drizzle"        # optional: the checklist item that produced the row
    hypothesis: ""                     # optional: the HYP-NNN row this row resolves
    reason: ""                         # required for not_tested, blocked, not_applicable
```

| State | Meaning |
|-------|---------|
| `planned` | Listed and not yet resolved. None may remain when the session report is written. |
| `tested` | Baseline, probe, and control were run and recorded. A defense that held is still `tested`; its finding resolves `not_supported`. |
| `not_tested` | In scope but not run: no live target, out of time, or a stop rule fired. The reason says which. |
| `blocked` | Could not run for a named missing prerequisite: credential, account, burst count, tool, or environment tier. |
| `not_applicable` | Affirmative evidence shows the surface does not exist for this target. The reason cites that evidence. |

The gate rejects: a row id not of the form `COV-<session>-NNN`; a `session`
field that does not match the directory; a missing `surface`, `check`, or
`state`; a `planned` row; a `tested` row with no evidence ids, with an id
absent from the session ledger, or citing a probe without a baseline and a
control; any other resolved state without a reason; a `DONE` session with
no coverage file unless the plan decided it `skip` or `not_applicable`.
One row per surface and check; a check that spans several identities is
several rows.

## Evidence

Every session writes to its own ledger, `<session-dir>/evidence.jsonl`,
through `ensphere verify` and `ensphere evidence log`. Ids are `EVID-NNN`
and unique within that ledger; a citation from another session names the
session directory as well. Entries carry `prev_hash` and `hash`, and
`ensphere evidence verify` must pass before the session is `DONE`. The chain
is an integrity check on the file: it shows the ledger was not edited or
truncated after the fact. It does not prove what was measured; the operator
runs the measurements and signs for them.

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
command, raw or losslessly redacted result, and chain state. Every registry
entry lists its evidence categories and always includes `agent_judgment`.

Evidence strength describes support for a claim, not severity:

| Strength | Use when |
|----------|----------|
| `direct` | The behavior was observed with a baseline and a control, demonstrated end to end in the sandbox, or is unambiguous in source or configuration. |
| `corroborated` | Independent evidence types (for example source review and a live measurement) support the same claim and the alternatives were checked. |
| `indicative` | A relevant signal exists but a material alternative or missing input remains. |
| `insufficient` | The evidence cannot support the claim. Keep it as a lead or `not_tested`. |

Timing, status code, response size, reflection, and scanner output are never
`direct` merely because they repeat; the measurement must exclude the
alternative. Source review alone is `direct` only when the code path is
unambiguous and reachable from an inventoried entry point; otherwise it is
`indicative` until a live measurement or a sandbox run corroborates it.

## Findings

A finding is one resolved claim about one root cause. Deduplicate by root
cause and control while keeping distinct assets, roles, and consequences
visible; ten endpoints missing the same middleware are one finding with ten
affected locations.

**Kind** is decided by the fix. A `vulnerability` (`VULN-NNN`) is a weakness
in something that exists: code, a policy, a configuration value; the fix
corrects it. A `missing_control` (`CTRL-NNN`) is a control the stack needs
and the project does not have: no limiter on a billed endpoint, no size cap
on uploads, no row policy on a tenant table, no budget alert; the fix adds
it. Missing controls are the main defensive output of an assessment and
carry the same rigor, evidence, and remediation detail as vulnerabilities.
An observed chain from Session 08.7 is a `vulnerability` whose observed
facts are its edge evidence ids in order.

**Status** is the conclusion about the narrow claim. `confirmed`: `direct`
or `corroborated` evidence demonstrates the weakness or the absent control.
`likely`: evidence supports it but one material uncertainty remains, and
strength is at least `indicative`. `informational`: a factual condition
worth reporting without asserting a weakness. `not_supported`: controlled
checks contradict the candidate or show the control works for the tested
case. `not_tested`: out of scope, blocked, inapplicable, or missing input.
`confirmed` and `likely` findings are unresolved until fixed and are the
ones the statement counts.

**Confidence** is how sure the analyst is of the status given the evidence
and the alternatives considered; it is not a second severity. **Severity**
is the impact the finding would have on the real system with real data,
judged from what was achieved on synthetic data; a chain that ends short of
its goal is rated for what it reached, and a missing control for the
consequence it fails to prevent. **Priority** is the order to fix in,
combining severity, prerequisites, exposure, and effort, stated with its
reasoning; the operator may reorder it. **CVSS v4.0** is optional, only
meaningful for a `vulnerability`, and always accompanied by the metric
rationale; `ensphere cvss` scores a vector the analyst has already decided.
**Category** normally matches the session that resolved the finding.

**Tested defenses.** A control that held under a controlled check is
reported as such: the surface, the check, the identity, the exact
conditions, and the evidence, with the finding resolved `not_supported`.
This is the report's positive content, and it never generalises beyond the
conditions tested.

**Honest negatives.** Say exactly what was tested, against which assets and
roles, with which controls. Never write "secure", "safe", or "no
vulnerabilities" as a broad conclusion. Blocked, partial, and source-only
coverage must be visible in every report that draws on the session.

**Source versus live drift.** When source and the live target disagree,
report both observations, name which environment each came from, and say
which the finding rests on. Never silently pick the more severe reading and
never assume the source is what is deployed.

**Imported leads.** Scanner and dependency-audit output is `imported_lead`
evidence. Its severity is the tool's, never presented as Ensphere's, and a
lead becomes a finding only through controlled validation.

**Chains.** A multi-step path is `observed` only when Session 08.7 ran every
edge in one sandbox run and recorded the goal state. Everything else is a
risk scenario with its unobserved edges marked, and its severity rests on
the edges that were observed.

## Session decisions and progress

Session 01.5 decides every session and the plan records it:

| Decision | Basis |
|----------|-------|
| `run` | Affirmative evidence that relevant surface exists and required inputs are available. |
| `limited` | Surface exists but some named asset, role, data, or environment is unavailable; the reason says which. |
| `blocked` | Surface exists but testing cannot proceed safely or meaningfully; name the missing input. |
| `skip` | A deliberate operator choice with rationale and accepted coverage risk. |
| `not_applicable` | Affirmative inventory shows the category does not exist for this target. |
| `uncertain` | Recon cannot prove presence or absence; run only bounded discovery or ask. |

`not_applicable` requires affirmative absence evidence; missing
credentials, failed discovery, or an absent signal never justify it. Session
08.5 runs for every target with a server component. Session 08.7 runs only
when the environment is `sandbox`.

`progress.md` holds one state per session: `PENDING`, `IN_PROGRESS`, or
`DONE`. `DONE` means the session report is written and its coverage file
reconciled; it never means secure. Why a session ran no checks is in its
plan decision and its report, not in a parallel state. Coverage is
described by the row counts, never by a label the analyst chooses.

## Reporting and the statement

Session 09 synthesises; it runs no new probe. `ensphere run report` is the
gate: it fails on a session that is not `DONE`, a missing or empty session
report, a missing or invalid plan, a broken evidence chain, an invalid
coverage file, or a registry entry that is uncited, mislabelled, or missing
a required field. Every error is fixed in the workspace file it points at;
every warning becomes a stated limitation.

The report obeys these rules, and the quality gate in Session 09 checks
each before the session is `DONE`:

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
coverage counts, finding counts, unresolved findings, ledger hashes, and the
Ensphere version, and ends with the sentence: "This is a self-assessment
performed by the system owner with Ensphere. It is not an independent audit,
attestation, or certification." The operator signs it; the model does not.
If a number looks wrong, fix the workspace file it came from and regenerate;
the gate rejects a statement that is stale or edited by hand.

## Reproducibility and redaction

A reportable finding includes the affected asset and exact location,
prerequisites and role, safe reproduction steps with non-secret inputs,
baseline, probe, and control observations, expected versus observed
behavior, citations, and cleanup steps when state changed. Use placeholders
such as `[SESSION_TOKEN]` and `[TENANT_A_USER]` from `01-recon/sandbox.md`.
Never place live secrets or personal data in evidence notes, transcripts,
reports, or prompts; the ledger redacts known secret shapes, but redaction
is a backstop, not a licence. Workspace paths are relative. Every state
change outside the sandbox records what changed and the cleanup evidence;
inside the sandbox the reset command and its record are the cleanup.

## Vocabulary

The values the CLI and the report gate accept, in one place.

| Field | Values | Where |
|-------|--------|-------|
| Environment tier | `sandbox`, `staging`, `none` | plan, config, findings |
| Coverage row state | `planned`, `tested`, `not_tested`, `blocked`, `not_applicable` | `coverage.yaml` |
| Coverage row id | `COV-<session>-NNN` | `coverage.yaml` |
| Session decision | `run`, `limited`, `blocked`, `skip`, `not_applicable`, `uncertain` | assessment plan |
| Progress state | `PENDING`, `IN_PROGRESS`, `DONE` | `progress.md` |
| Evidence id | `EVID-NNN`, unique per session ledger | `evidence.jsonl` |
| Evidence stage | `baseline`, `probe`, `payload`, `control`, `callback`, `manual_note` | `evidence.jsonl` `result` |
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
