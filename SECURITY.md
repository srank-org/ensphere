# Security Policy

Ensphere is a defensive security checker for systems their owners run it
against. Its probes are bounded measurements, its payload corpus is built for
detection, and proof of a finding happens only in a sandbox copy the operator
controls. Production is never probed. Use it only against systems you own or
are explicitly authorized to assess.

Reports produced with Ensphere are self-assessments by the system owner. They
are not independent audits, attestations, or certifications, and a clean run
is not a security guarantee.

## Reporting security issues in Ensphere

Do not open public issues for sensitive vulnerabilities. Use GitHub's private
vulnerability reporting on this repository, or contact the maintainers through
the address listed on the organization profile.

Include the affected component or command, reproduction steps, expected and
actual behavior, impact, and logs or evidence with secrets redacted.

## Scope

Reports should concern Ensphere itself:

- scope bypasses, including a probe reaching a host outside `--in-scope`;
- evidence integrity failures in the hash-chained ledger;
- secret redaction failures;
- unsafe defaults, such as a probe that changes state without the plan
  authorizing it;
- a command, flag, or payload that crosses the measurement-only boundary;
- supply-chain or dependency risk.

Weaknesses in systems assessed with Ensphere belong to that system owner's
own process, not to this repository.

## Handling secrets and assessment data

Do not commit credentials, tokens, sandbox fixtures containing real data,
evidence ledgers, or assessment workspaces. `ensphere-pentest/` and
`evidence.jsonl` are ignored by default. The sandbox must never contain
production data; `skills/shared/sandbox.md` states the isolation check.

## Dependency monitoring

GitHub Dependabot vulnerability alerts and grouped version-update pull
requests are enabled. When GitHub reports a vulnerable dependency, review the
generated pull request or author an equivalent update, run the full
validation gate, and note the alert in the commit or pull request.
