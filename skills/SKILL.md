---
name: ensphere
description: Defensive security assessment of a system you own or are authorized to assess. Learns the project's stack, stands up a disposable sandbox, runs bounded measurements with the ensphere CLI, proves chains in the sandbox, and produces an evidence-backed report of findings, missing controls, what was checked, and what was not, plus a Statement of Assessment the operator signs. Say "ensphere" to start or resume.
---

# Ensphere

> Ensphere produces verifiable facts. The analyst produces all security
> judgments.

Ensphere is a defensive checker. You are helping a developer find weaknesses
and missing controls in their own system: injection, broken authentication
or authorization, exposed storage, and endpoints that let an attacker spam
the server or run up the bill. You prove findings only in a sandbox copy
that cannot be hurt, never extract real data, and never send a probe to
production. The deliverable is a report the developer can act on line by
line and a one-page statement they can hand to someone doing due diligence.

Read two files once before the first session, and return to them when a
rule is in doubt:

- [shared/contract.md](shared/contract.md) holds every rule: scope,
  environments, pacing, evidence, findings, coverage, reporting. Nothing in
  this file or any methodology overrides it.
- [shared/fundamentals.md](shared/fundamentals.md) is the stack-agnostic
  map of roles every system has and the invariant each must satisfy. That
  map is what you check. Stack checklists only translate it into a
  framework's idioms and are accelerators, never prerequisites.

## How an assessment works

1. **Learn the project (Session 01).** Read the repository and, when there
   is one, the running target. Identify languages, frameworks, data layers,
   auth provider, hosting, storage, edge, and every third-party service that
   bills per call. Write the role table from the fundamentals, inventory
   the attack surface, and write `01-recon/target-profile.yaml` with its
   `stack` block. Stand up the sandbox as
   [shared/sandbox.md](shared/sandbox.md) describes.
2. **Plan from the stack (Session 01.5).** Map the detected stack to
   checklist files with the table in
   [methodology/01.5-session-plan.md](methodology/01.5-session-plan.md).
   Decide every session with cited evidence, list every input the run will
   need, and ask for all of it at once. Run `ensphere run plan`.
3. **Check (Sessions 02 to 08.5).** Each session opens its methodology plus
   the checklists the plan assigned to it, writes its `coverage.yaml`, and
   resolves every row with baseline, probe, control. The methodology and
   the fundamentals say what to check; a checklist, when one exists, says
   where that lives in this framework and the idiomatic fix.
4. **Prove (Session 08.7).** In the sandbox only, join the `likely`
   findings and workflow candidates into chains and run each end to end,
   so the report separates observed paths from hypothetical ones.
5. **Report (Session 09).** Findings, missing controls with concrete fixes,
   what was checked and held, what was not checked and why. `ensphere run
   report` is the gate; `ensphere run statement` writes the statement.

Sessions 01, 01.5, and 09 always run. Sessions 02 to 08.7 run when the plan
says they apply. The whole run is continuous; you stop only at the human
gates the contract names (Pacing), and you present the result once, after
Session 09.

## Start or resume

When the user says `ensphere` or names a session:

1. Locate `ensphere-pentest/config.md` and `progress.md`. If absent, collect
   the first-run inputs below and run `ensphere run init`. Never assume
   authorization from repository access alone.
2. Run `ensphere run status` and read `next-action.md`, the assessment plan,
   the current session's methodology, its assigned checklists, the previous
   session report, and any `checkpoint.md`.
3. If the workspace contains several deployable applications, confirm which
   one is the target. Do not assess the whole monorepo silently.
4. State the environment: the source path and the live target's tier,
   `sandbox` or `staging`, as the contract defines them. The sandbox is
   where proof happens; offer to stand one up if there is none. Without a
   live target the coverage label is `source_only` and every measurement
   row is `not_tested`; source review and missing-control findings still
   proceed.
5. Resume from the session's `coverage.yaml` and checkpoint. Do not repeat
   a completed probe.

Ask for direction only when authorization, target identity, environment, or
a material boundary cannot be established. Missing optional context is a
coverage limitation, not permission to broaden testing, and not a reason to
stop.

First-run inputs, collected once:

- source path and the selected deployable when the repository has several;
- live target URL and its tier (`sandbox` or `staging`), if any, and the
  target type;
- in-scope and out-of-scope hosts, assets, and accounts;
- stability constraints, prohibited actions, and approved request limits
  (burst counts per endpoint, upload sizes);
- test identities, roles, and tenants for a staging target (the sandbox
  seeds its own);
- cloud or platform accounts in scope and which provider CLIs are logged in;
- who performs the assessment (`--assessed-by`) and who authorizes and
  signs it (`--operator`);
- the authorization statement.

## Session map

| Session | File | Outcome |
|---------|------|---------|
| 01 | [Recon](methodology/01-recon.md) | Stack profile, role table, attack-surface inventory, sandbox record. |
| 01.5 | [Plan](methodology/01.5-session-plan.md) | Session decisions, assigned checklists, the complete Needs-from-you list. |
| 02 | [Injection](methodology/02-injection.md) | SQL, NoSQL, command, template, path, XML, header, LDAP, XPath. |
| 03 | [Authentication](methodology/03-auth.md) | Login, session, token, reset, MFA, OAuth, cookie flags. |
| 04 | [Authorization](methodology/04-authz.md) | Object, property, function, tenant, RLS, workflow transitions. |
| 05 | [XSS](methodology/05-xss.md) | Render contexts and client execution. |
| 06 | [SSRF](methodology/06-ssrf.md) | Outbound fetchers and webhooks. |
| 07 | [Cloud and platform](methodology/07-cloud.md) | AWS, GCP, Azure, Kubernetes, Cloudflare, Supabase configuration, read-only. |
| 08 | [API](methodology/08-api.md) | Schema exposure, mass assignment, GraphQL, gRPC, WebSocket, webhooks. |
| 08.5 | [Abuse and cost](methodology/08.5-abuse.md) | Missing rate limits, billed services, storage and upload abuse, pagination caps. |
| 08.7 | [Chains and workflows](methodology/08.7-chains.md) | Multi-step paths proven end to end; sandbox only. |
| 09 | [Report](methodology/09-report.md) | Finding registry, report, evidence appendix, coverage appendix, statement. |

Checklists live in [checklists/](checklists/index.md) and exist for the
most common stacks only. Every item has four lines: what and why, Look for,
Measure, Fix. A stack with no checklist is assessed from the fundamentals
and your own knowledge of it; it is never `blocked` for that reason.
[shared/coverage-map.md](shared/coverage-map.md) maps sessions to WSTG and
ASVS for the report's coverage appendix and names what no session covers.

## Workspace

`ensphere run init` creates `ensphere-pentest/`:

```text
ensphere-pentest/
  config.md                 target, scope, identities, limits, assessor, operator, authorization
  progress.md               one workflow state per session
  assessment-plan.yaml      written by run plan, mirrored into 01.5-session-plan/
  next-action.md            handoff written by run next; read it first on resume
  agent-prompt.md           the prompt a fresh context should start from
  01-recon/                 report.md, target-profile.yaml, sandbox.md
  01.5-session-plan/        report.md, assessment-plan.yaml
  02-injection/ ... 08.7-chains/
    plan.md                 scope, limits, candidates
    coverage.yaml           every check and its state; validated by the gate
    evidence.jsonl          this session's hash-chained ledger
    transcripts/            manual observations, one file per candidate or chain
    artifacts/              captured files, screenshots, exports
    checkpoint.md           present only during a long operation
    report.md               the session report, ending with Needs from you
  09-report/
    finding-registry.yaml   every finding, validated by the gate
    report.md               the deliverable
    evidence-appendix.md    claim-to-evidence table
    report-gate.yaml, .md   gate result and coverage summary
    statement.yaml, .md     written by run statement; the operator signs statement.md
```

Before a long operation write `checkpoint.md` with the `coverage.yaml`
position, completed and remaining candidates, evidence paths and chain
state, and request counters, so a run that loses its context resumes
rather than restarts. Delete it when the session report is written. Update
`progress.md` only after the report is written.

## Using the CLI

`ensphere help` and each subcommand's `--help` are the source of truth for
syntax. Every verify command requires `--in-scope`; scope failures exit 2,
runtime failures exit 3, and a refusal is never worked around.

- `ensphere run init | status | next | plan | report | statement` manage
  the workspace. `run next` writes the handoff for the next session;
  `run report` is the Session 09 gate; `run statement` writes the
  Statement of Assessment once the gate passes.
- `ensphere scan` finds sink candidates in source by category. A match is a
  lead, not a finding. `ensphere sinks` lists the patterns it uses.
- `ensphere openapi` inventories an OpenAPI spec for the entry-point table.
- `ensphere payloads` selects controlled inputs by family, technique, and
  risk. Presence in the corpus does not make a payload appropriate for this
  scope.
- `ensphere verify <family>` records a measurement: baseline, probe, and
  control values into the session ledger. Read the raw values yourself. The
  families are listed in the fundamentals' role-to-session table.
- `ensphere verify limits` and `ensphere verify ratelimit` measure caps and
  limiters with operator-approved sizes and burst counts only.
- `ensphere callback` runs the local out-of-band listener Session 06 uses.
- `ensphere evidence log` records manual observations into the same ledger;
  `ensphere evidence verify` checks the chain before a session ends.
- `ensphere cloud <area>` reads provider configuration through the provider
  CLI, read-only. If the CLI is missing or logged out, tell the operator
  what to run and mark the rows `blocked`.
- `ensphere cvss` scores a vector after you decide the metrics;
  `ensphere compliance` maps a category to control frameworks. Both are
  optional and neither produces a judgment.

If a checklist command conflicts with the approved scope, the risk ceiling,
or a stop rule, do not run it; record the row `blocked` with the reason.

## Habits that make the report worth reading

- Read the source before probing. Most candidates come from a file and
  line; the live target confirms the consequence.
- One narrow claim at a time, always with a baseline and a control. A
  number without both is not evidence.
- Name things by role. "The limiter on the OTP send" says more than the
  middleware's package name, and the fix follows from the role.
- Write as you go: the coverage row before the probe, the evidence id in
  the row after it, the transcript while the observation is fresh.
- Prefer the sandbox for anything that changes state. Prefer staging only
  for what the sandbox cannot show: the edge, platform settings, drift.
- When source and live disagree, record both and say which the finding
  rests on.
- Tell the operator what is missing once, in the Needs-from-you list, with
  the exact command. Then continue with everything else.

## Ending a session

1. Resolve every planned candidate or record why it is `not_tested`.
2. Reconcile `coverage.yaml` with the work actually done: no `planned`
   rows remain, every `tested` row cites evidence that exists in this
   session's ledger, every other resolved row has a reason.
3. Verify cited paths and run `ensphere evidence verify` on the ledger.
4. Write the session report, ending with the **Needs from you** list.
5. Mark the session terminal in `progress.md`, run `ensphere run next`, and
   continue with the next session. Stop only at a human gate.

## Ending the assessment

Session 09 runs no new probe. In order:

1. `ensphere run report`; fix every error in the workspace file it names,
   and carry every warning into the limitations.
2. Write `finding-registry.yaml`, `report.md`, and `evidence-appendix.md` as
   the Session 09 methodology describes. The "checks executed" and "not
   checked" sections copy coverage rows; their counts equal the gate's.
3. `ensphere run report` again, then `ensphere run statement`. Never edit
   the statement; regenerate it.
4. Mark Session 09 `DONE` and present to the operator: the three to five
   things to fix first, the unresolved findings by severity, the material
   coverage limits, where the report and statement are, and that the
   statement is theirs to sign.

The contract's Reporting section is the full list of report rules. The ones
most often broken: no uncited finding or missing control; no broad
"secure" or "safe" claim; no scanner severity presented as Ensphere
severity; no attack path presented as observed unless every edge has
evidence; no certification language; every missing control with a concrete
fix for this stack.
