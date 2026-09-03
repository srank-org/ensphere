---
name: ensphere
description: Defensive security assessment of a system you own or are authorized to assess. Learns the project's stack, loads the matching checklists, runs bounded measurements with the ensphere CLI, and produces an evidence-backed report of findings, missing controls, and what was checked. Say "ensphere" to start or resume.
---

# Ensphere

> Ensphere produces verifiable facts. The analyst produces all security
> judgments.

Ensphere is a defensive checker. You are helping a developer find weaknesses
and missing controls in their own system: injection, broken authentication or
authorization, exposed storage, and endpoints that let an attacker spam the
server or run up the bill. You prove findings only in a sandbox copy that
cannot be hurt, never extract real data, and never send a probe to
production.

Read [shared/contract.md](shared/contract.md) once before the first session.
It holds the scope, evidence, stop, and reporting rules; nothing below
overrides it. Read [shared/fundamentals.md](shared/fundamentals.md) with it:
the stack-agnostic map of roles every system has and the invariant each must
satisfy. That map is what you check. Stack checklists only translate it into
a framework's idioms and are optional accelerators, never prerequisites.

## How an assessment works

1. **Learn the project (Session 01).** Read the repository and the running
   target. Identify languages, frameworks, data layers, auth provider, hosting,
   storage, and every third-party service that bills per call. Inventory the
   attack surface. Write `01-recon/target-profile.yaml` including the `stack`
   block.
2. **Plan from the stack (Session 01.5).** Map the detected stack to checklist
   files using the table in
   [methodology/01.5-session-plan.md](methodology/01.5-session-plan.md).
   Decide which sessions run and record the checklists to load. Run
   `ensphere run plan` to validate the plan.
3. **Check (Sessions 02 to 08.5).** Each session opens its methodology file
   plus any checklists the plan assigned to it. The methodology and the
   fundamentals say what to check; a checklist, when one exists for the
   stack, says where that lives in this framework and the idiomatic fix.
   Every measurement uses baseline, probe, control.
4. **Prove (Session 08.7).** In the sandbox only, join the `likely` findings
   and workflow candidates into chains and run each end to end, so the report
   separates observed paths from hypothetical ones.
5. **Report (Session 09).** Findings, missing controls with concrete fixes,
   what was checked and found not supported, what was not checked and why.
   `ensphere run report` verifies citations and evidence chains.

Sessions 01, 01.5, and 09 always run. Sessions 02 to 08.7 run when the plan
says they apply.

## Start or resume

When the user says `ensphere` or names a session:

1. Locate `ensphere-pentest/config.md` and `progress.md`. If absent, collect
   the first-run inputs and run `ensphere run init`. Never assume
   authorization from repository access alone.
2. Run `ensphere run status`. Read `next-action.md`, the assessment plan, the
   current session's methodology, its assigned checklists, the previous
   session report, and any checkpoint.
3. If the workspace contains several deployable applications, confirm which
   one is the target. Do not assess the whole monorepo silently.
4. State the environment: the source path and the live target's tier,
   `sandbox` or `staging`, as the contract defines them. The sandbox is where
   proof happens; offer to stand one up if there is none. Without a live
   target the coverage label is `source_only` and every measurement row is
   `not_tested`; source review and missing-control findings still proceed.
5. Resume from the session's `coverage.yaml`. Do not repeat completed probes.

Ask for direction when authorization, target identity, environment, or a
material boundary cannot be established. Missing optional context is a
coverage limitation, not permission to broaden testing.

First-run inputs: source path; live target URL and environment, if any, and
target type; in-scope and out-of-scope assets; environment and stability constraints; test identities,
roles, and tenants; prohibited actions and request limits; cloud or platform
accounts in scope; authorization statement.

## Session map

| Session | File | Outcome |
|---------|------|---------|
| 01 | [Recon](methodology/01-recon.md) | Stack profile and attack-surface inventory. |
| 01.5 | [Plan](methodology/01.5-session-plan.md) | Session decisions and assigned checklists. |
| 02 | [Injection](methodology/02-injection.md) | SQL, NoSQL, command, template, path, XML, header, LDAP, XPath. |
| 03 | [Authentication](methodology/03-auth.md) | Login, session, token, reset, MFA, OAuth. |
| 04 | [Authorization](methodology/04-authz.md) | Object, property, function, tenant, RLS. |
| 05 | [XSS](methodology/05-xss.md) | Render contexts and client execution. |
| 06 | [SSRF](methodology/06-ssrf.md) | Outbound fetchers and webhooks. |
| 07 | [Cloud and platform](methodology/07-cloud.md) | AWS, GCP, Azure, Kubernetes, Cloudflare, Supabase configuration. |
| 08 | [API](methodology/08-api.md) | Schema exposure, mass assignment, GraphQL, WebSocket, webhooks. |
| 08.5 | [Abuse and cost](methodology/08.5-abuse.md) | Missing rate limits, billing-exposed services, storage and upload abuse. |
| 08.7 | [Chains and workflows](methodology/08.7-chains.md) | Multi-step paths proven end to end in the sandbox; sandbox only. |
| 09 | [Report](methodology/09-report.md) | Findings, missing controls, coverage appendix, statement. |

Checklists live in [checklists/](checklists/index.md). They exist for the
most common stacks only. A stack with no checklist is assessed from the
fundamentals and your own knowledge of it; it is never `blocked` for that
reason.

## Session artifacts

Each session directory contains, as applicable: `plan.md` (scope, limits,
candidates), `coverage.yaml` (the machine-read record of every check and
its state; see the contract), `evidence.jsonl`, `transcripts/` or
`artifacts/`, `checkpoint.md`, and `report.md`. Update `progress.md` only
after the report is written.

Before a long operation, write `checkpoint.md` with the current
`coverage.yaml` position, completed and remaining candidates, evidence paths
and chain state, and request counters, so a run that loses its context can
resume rather than restart. Delete it after the session report is done.

## Using the CLI

`ensphere help` and subcommand help are the source of truth for syntax.

- `ensphere scan` finds sink candidates in source. A match is a lead.
- `ensphere payloads` selects controlled inputs. Presence in the corpus does
  not make a payload appropriate for this scope.
- `ensphere verify <category>` records measurements. Read the raw baseline,
  probe, and control values yourself. Every verify command requires
  `--in-scope`.
- `ensphere evidence log` records manual observations into the same
  hash-chained ledger; `ensphere evidence verify` checks it.
- `ensphere cloud <area>` reads provider configuration through the provider
  CLI. If the CLI is missing or logged out, tell the operator what to run and
  mark the check blocked.
- `ensphere cvss` scores a vector after you fix the metrics. Optional.

If a checklist command conflicts with the approved scope or a stop rule, do
not run it.

## Ending a session

1. Resolve every planned candidate or record why it is `not_tested`.
2. Reconcile `coverage.yaml` with the work actually done: no `planned`
   rows remain, every `tested` row cites evidence.
3. Verify cited evidence paths and run `ensphere evidence verify`.
4. Write the session report, ending with the **Needs from you** list.
5. Mark the session terminal in `progress.md`, run `ensphere run next`, and
   continue with the next session (contract, Pacing). Stop only at a human
   gate, or after Session 09 to present the report and the statement.

## Report rules

The contract's Reporting section is the full list. The rules most often
broken:

- No uncited finding or missing control.
- No broad "secure" or "safe" claim from bounded testing.
- No scanner severity presented as Ensphere severity.
- No attack path presented as observed unless every edge has evidence.
- No compliance certification language.
- Every missing control comes with a concrete fix for this stack.
