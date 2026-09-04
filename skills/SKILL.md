---
name: ensphere
description: Defensive security assessment of a system you own or are authorized to assess. Learns the project's stack, stands up a disposable sandbox, runs bounded measurements with the ensphere CLI, proves chains in the sandbox, and produces an evidence-backed report of findings, missing controls, what was checked, and what was not, plus a Statement of Assessment the operator signs. Say "ensphere" to start or resume.
---

# Ensphere

> Ensphere produces verifiable facts. The analyst produces all security
> judgments.

You are helping a developer find weaknesses and missing controls in their
own system: injection, broken authentication or authorization, exposed
storage, and endpoints that let an attacker spam the server or run up the
bill. You prove findings only in a sandbox copy that cannot be hurt, never
extract real data, and never send a probe to production. The deliverable is
a report the developer can act on line by line and a one-page statement
they can hand to someone doing due diligence.

Read two files once before the first session and return to them when a
rule is in doubt:

- [shared/contract.md](shared/contract.md) holds every rule: scope,
  environments, pacing, evidence, findings, coverage, reporting. Nothing in
  this file or any methodology overrides it.
- [shared/fundamentals.md](shared/fundamentals.md) is the stack-agnostic
  map of roles every system has, the invariant each must satisfy, and the
  six questions that turn the map into hypotheses about this system. That
  map is what you check. Stack checklists translate it into a framework's
  idioms and are accelerators, never prerequisites.

## How an assessment works

1. **Learn the project (Session 01).** Read the repository and, when there
   is one, the running target. Write the stack profile, the role table from
   the fundamentals, the attack-surface inventory, and
   `01-recon/hypotheses.md`. Stand up the sandbox as
   [shared/sandbox.md](shared/sandbox.md) describes.
2. **Plan from the stack (Session 01.5).** Map the stack to checklist files
   with the table in [methodology/01.5-session-plan.md](methodology/01.5-session-plan.md).
   Decide every session with cited evidence, list every input the run will
   need, and ask for all of it at once. Run `ensphere run plan`.
3. **Check (Sessions 02 to 08.5).** Each session opens its methodology plus
   the checklists the plan assigned to it, writes its `coverage.yaml`, and
   resolves every row, including its hypotheses, with baseline, probe,
   control.
4. **Prove (Session 08.7).** In the sandbox only, join the `likely`
   findings and workflow candidates into chains and run each end to end.
5. **Report (Session 09).** Findings, missing controls with concrete fixes,
   what was checked and held, what was not checked and why. `ensphere run
   report` is the gate; `ensphere run statement` writes the statement.

Sessions 01, 01.5, and 09 always run. Sessions 02 to 08.7 run when the plan
says they apply. The whole run is continuous; you stop only at the human
gates the contract names, and you present the result once, after Session
09: the three to five things to fix first, the unresolved findings by
severity, the material coverage limits, where the report and statement are,
and that the statement is the operator's to sign.

## Orchestration

The workspace is the protocol. Every session reads its inputs from files
and writes its outputs to files, so sessions do not need to share a
context. When your harness can run subagents, use this shape:

- **The orchestrator** runs Sessions 01, 01.5, and 09 itself and holds only
  the plan, the role table, the hypotheses, and each session's report. It
  never loads a session's transcripts or ledger.
- **Each check session** runs in a fresh agent with a brief that names its
  methodology file, its assigned checklists, the contract and fundamentals,
  `config.md`, `01-recon/report.md`, `01-recon/hypotheses.md`,
  `01-recon/sandbox.md`, and the previous session report. The agent writes
  the session directory and returns the path to its report.
- **Source review runs in parallel; live probes run in series.** Sessions
  share one sandbox, and a burst in one corrupts a timing measurement in
  another. Dispatch source-only work concurrently and serialize any session
  that sends requests, or give each its own sandbox.
- **Session 08.7** runs after every check session has reported, because it
  joins their edges.

Without subagents, run the sessions in one context in order and rely on
`next-action.md` and `checkpoint.md` to resume after a context loss. The
files are the same either way.

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
   `sandbox` or `staging`. The sandbox is where proof happens; offer to
   stand one up if there is none. Without a live target the tier is `none`
   and source review still proceeds.
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
| 01 | [Recon](methodology/01-recon.md) | Stack profile, role table, attack-surface inventory, sandbox record, system-specific hypotheses. |
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
most common stacks only. A stack with no checklist is assessed from the
fundamentals and your own knowledge of it; it is never `blocked` for that
reason. [shared/coverage-map.md](shared/coverage-map.md) maps sessions to
WSTG and ASVS for the report's coverage appendix.

## Workspace

`ensphere run init` creates `ensphere-pentest/`:

```text
ensphere-pentest/
  config.md                 target, scope, identities, limits, assessor, operator, authorization
  progress.md               PENDING, IN_PROGRESS, or DONE per session
  assessment-plan.yaml      written by run plan, mirrored into 01.5-session-plan/
  next-action.md            handoff written by run next; read it first on resume
  agent-prompt.md           the prompt a fresh context should start from
  01-recon/                 report.md, target-profile.yaml, sandbox.md, hypotheses.md
  01.5-session-plan/        report.md, assessment-plan.yaml
  02-injection/ ... 08.7-chains/
    plan.md                 scope, limits, candidates
    coverage.yaml           every check and its state; validated by the gate
    evidence.jsonl          this session's ledger
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

## Using the CLI

`ensphere help` and each subcommand's `--help` are the source of truth.
Every verify command requires `--in-scope`; scope failures exit 2, runtime
failures exit 3, and a refusal is never worked around. Three commands do
most of the work:

- `ensphere verify request` sends one request you construct, labelled
  `--result baseline`, `probe`, or `control`, and records it in the
  session ledger. Use it for every shape no family anticipates and for the
  control of every family probe. Its output carries the evidence id.
- `ensphere verify <family>` runs a fixed measurement that is fiddly to do
  by hand: `race` with a start barrier, `ratelimit` with header capture,
  `limits`, `rls`, the timing families, and the rest listed in the
  fundamentals under "Where each role is checked".
- `ensphere evidence log` records an observation that is not a request
  (a source citation, a database row after a chain step) into the ledger,
  and `ensphere evidence verify` checks the chain before a session ends.

`ensphere run` manages the workspace, `scan` and `openapi` produce leads
and inventories, `payloads` selects controlled inputs by risk, `callback`
runs the out-of-band listener, `cloud` reads provider configuration
read-only, and `cvss` and `compliance` are optional. If a checklist command
conflicts with the approved scope, the risk ceiling, or a stop rule, do not
run it; record the row `blocked` with the reason.

## Habits that make the report worth reading

- Read the source before probing. Most candidates come from a file and
  line; the live target confirms the consequence.
- One narrow claim at a time, always with a baseline and a control. A
  number without both is not evidence, and the gate will say so.
- Name things by role. "The limiter on the OTP send" says more than the
  middleware's package name, and the fix follows from the role.
- The map is the floor. After the role table, ask what a motivated user of
  this system would go after and write each answer down as a hypothesis
  with a coverage row. That list is where your judgment shows.
- Write as you go: the coverage row before the probe, the evidence id in
  the row after it, the transcript while the observation is fresh.
- Prefer the sandbox for anything that changes state. Prefer staging only
  for what the sandbox cannot show: the edge, platform settings, drift.
- When source and live disagree, record both and say which the finding
  rests on.
- Tell the operator what is missing once, in the Needs-from-you list, with
  the exact command. Then continue with everything else.
