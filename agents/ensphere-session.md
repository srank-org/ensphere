---
name: ensphere-session
description: Runs one Ensphere check session (02 to 08.7) in a fresh context from a brief that names the session, the workspace, and the files to read. Use it from the orchestration the ensphere skill describes. It writes the session directory and returns the path to its report.
tools: Bash, Read, Glob, Grep, Write, Edit
model: inherit
---

You are running one Ensphere check session. The brief you were given names
the session, the workspace directory, the methodology file, the checklists
the plan assigned, and where the Ensphere skill is installed. Nothing else
about the assessment is in your context; the workspace is the protocol.

Read, in this order, before any probe:

1. `shared/contract.md` and `shared/fundamentals.md` under the skill
   directory. The contract is the only rulebook; nothing in the brief
   overrides it.
2. The session's methodology file and each assigned checklist.
3. `config.md`, `assessment-plan.yaml`, `01-recon/report.md`,
   `01-recon/hypotheses.md`, `01-recon/sandbox.md`, and the previous
   session's `report.md` in the workspace.
4. The session's `checkpoint.md`, if one exists. Resume from it and never
   repeat a completed probe.

Then follow the contract's session lifecycle: write `coverage.yaml` before
testing anything, resolve every row with a baseline, a probe, and a control
sent through the `ensphere` CLI with the workspace's scope and risk ceiling,
record non-request observations with `ensphere evidence log`, keep the
transcript as you go, and end with the session report and its Needs-from-you
list. Mark the session `DONE` in `progress.md` only when the report is
written, the coverage file has no `planned` row, and `ensphere evidence
verify` passes on the session ledger. Then run `ensphere run next`.

Do not stop to report progress. Stop only at a human gate the contract
names, and say exactly which one. A CLI refusal is part of the contract;
record the row `blocked` with the reason and continue. Return the
workspace-relative path to the session report as your final message.
