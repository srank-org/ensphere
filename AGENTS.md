# Ensphere Development Guide

Guidance for agents working in the Ensphere repository.

## What this is

Ensphere is a defensive security checker for a system its operator owns: a
portable agent skill (`skills/`) that carries the assessment methodology, plus
a Go CLI (`cli/`) that performs scoped measurements and keeps a hash-chained
evidence ledger. The agent reads the operator's source, stands up a sandbox
copy, runs Sessions 01 to 09 (08.7 proves chains in the sandbox), and writes
a report of findings, missing controls, fixes, and what was and was not
checked, plus a one-page self-assessment statement.

When asked what Ensphere is, how it works, or how to use it: `README.md` is
the narrative for people, `docs/cli-reference.md` is the command surface,
`skills/SKILL.md` is how an assessment runs, and `skills/shared/contract.md`
is the rulebook every session follows. `index.md` maps the rest.

## Design principle

> **Ensphere produces verifiable facts. The AI produces all security judgments.**

Everything in this repository is either a deterministic measurement layer
(the Go CLI) or agent methodology (the skill). Given the same inputs the CLI
produces the same outputs. It never classifies, interprets, or judges.

The CLI may: send scoped HTTP requests, measure timing, hash responses,
capture headers, count rows, read provider configuration through a provider
CLI, validate scope, redact secrets, compute CVSS from supplied metrics, map
categories to compliance controls.

The CLI must not: assign status, confidence, or severity; apply thresholds
("delta > 500ms means SQLi"); decide exploitability; name a technique in a
way that presumes the outcome. A contract test in `cli/internal/verify`
rejects forbidden output fields.

The product is defensive. The person running it owns the system. Proof
happens only in a sandbox the operator controls; the CLI has no exploitation
command and never probes production.

## Layout

| Path | Purpose |
|------|---------|
| `skills/SKILL.md` | Agent entry point |
| `skills/shared/contract.md` | The one rulebook: scope, evidence, findings, stop rules |
| `skills/shared/fundamentals.md` | Stack-agnostic map of roles, invariants, and generic fixes; the checks themselves |
| `skills/shared/sandbox.md` | How to build, isolate, seed, and reset the sandbox where proof happens |
| `skills/shared/coverage-map.md` | Sessions mapped to WSTG categories and ASVS chapters, with the gaps named |
| `skills/methodology/` | Sessions 01, 01.5, 02 to 08, 08.5, 08.7, 09, plus cloud appendices 07a to 07f |
| `skills/checklists/` | Stack-specific checklists; the plan maps stack values to these files |
| `skills/evaluation/` | Blind benchmark protocol for methodology changes |
| `cli/cmd/` | Cobra commands, one file per command, flags only |
| `cli/internal/verify/` | Measurement probes and the shared scoped HTTP layer |
| `cli/internal/evidence/` | Hash-chained JSONL ledger, redaction, locking |
| `cli/internal/runner/` | Workspace init, plan validation, next-action handoff, report gate |
| `cli/internal/scan/`, `cli/internal/sinks/` | Regex sink scanner and its pattern data |
| `cli/internal/payloads/` | Embedded payload corpus and query |
| `cli/internal/cloud/` | Read-only provider configuration probes |
| `cli/internal/openapi/` | OpenAPI parser |
| `cli/internal/cvss/`, `cli/internal/compliance/` | CVSS v4.0 scorer, control mappings |
| `cli/internal/callback/` | Local out-of-band listener |
| `cli/internal/enums/` | Shared enum vocabulary |
| `assets/seeds/` | YAML payload sources |
| `templates/` | Workspace config template |

## Build and test

```bash
make build           # bin/ensphere
make test            # go vet + go test
make smoke           # CLI smoke checks
make verify-generated
make install-all     # binary + skill files
cd cli && go test -short ./...
```

See `docs/testing.md` for the test inventory and `docs/development.md` for
conventions.

## Conventions

- One command per file in `cli/cmd/`; commands parse flags, build a config,
  call `cli/internal/<package>`, and encode JSON with two-space indent.
- Shared verify flags come from the helper in `cli/cmd/helpers.go`; do not
  re-declare `--in-scope`, `--throttle`, `--timeout`, `--evidence`,
  `--max-risk`, or `--header` by hand.
- Errors wrap with `fmt.Errorf("context: %w", err)`.
- Every verify command requires `--in-scope`. Scope failures exit 2, runtime
  failures exit 3.
- There is one assessment mode. Source is always in scope; a live target is
  optional (`run init` without `--target` yields a `source_only` draft plan).
  Do not reintroduce a black-box or live-only axis.
- Live targets are `sandbox` or `staging` (`target.environment`). Production
  is never probed; only its provider configuration is read. Session 08.7
  (chains) runs only in a sandbox.
- Technique and vuln-type names describe what is measured, not the outcome
  (`rate_limit_burst`, not `rate_limit_bypass`).
- Payloads live in `assets/seeds/*.yaml`; enum values are validated at load
  time against `cli/internal/enums/enums.go`. Risk 4 and 5 payloads must not
  read credentials or execute code.

## Editing the skill

- `skills/shared/contract.md` is the only place a rule is stated. Category
  files add procedure and reference it; they never restate it.
- Every checklist item has the four lines: title and why, Look for, Measure,
  Fix. Every `ensphere` command in a checklist must exist with those flags.
- Checks are stack-agnostic and belong in `fundamentals.md` or a session
  methodology. A checklist only translates them for one common stack; add
  one only when many users run that stack, and then add its stack values to
  the map in `skills/methodology/01.5-session-plan.md` and a row in
  `skills/checklists/index.md`.
- Keep methodology files under about 1,000 words and checklists under about
  1,300. A mid-tier model has to read them alongside the target's code.
  `skills/SKILL.md`, `skills/shared/contract.md`, and
  `skills/shared/fundamentals.md` are the exception: they are read once at
  the start, and completeness matters more than length.

## Do not

- Add Go dependencies without a clear need.
- Put business logic in `cli/cmd/`.
- Add any command, flag, or payload whose purpose is exploitation, data
  extraction, credential access, or load generation.
- Write "secure", "safe", or "no vulnerabilities" anywhere in a report
  template. Never call any output an attestation or a certification; the
  report is a self-assessment.
- Add a production environment tier. Live targets are `sandbox` or
  `staging` only.
- Edit `CLAUDE.md`. It is `@AGENTS.md` so Claude Code and other harnesses
  read one file; change `AGENTS.md`.

## Docs map

| Topic | File |
|-------|------|
| Overview and quick start | README.md |
| Project index | index.md |
| CLI reference and safety contract (normative) | docs/cli-reference.md |
| Running it from a release pipeline | docs/release-pipeline.md |
| Development guide | docs/development.md |
| Test inventory | docs/testing.md |
| Skill entry point | skills/SKILL.md |
| Contract | skills/shared/contract.md |
| Sandbox | skills/shared/sandbox.md |
| Coverage map | skills/shared/coverage-map.md |
| Benchmark protocol | skills/evaluation/README.md |
| Methodology index | skills/methodology/index.md |
| Checklist index | skills/checklists/index.md |
