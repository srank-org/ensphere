# Development Guide

## Core Principle

Ensphere is an evidence-first, agent-guided assessment system built around a
measurement and execution engine. The CLI and generated assets produce
deterministic facts. The AI or human analyst produces security judgments.

Allowed in code:

- Execute HTTP requests
- Measure timing and sizes
- Hash requests and responses
- Compare raw values
- Count rows and matches
- Validate scope
- Redact secrets
- Calculate CVSS from fixed user-supplied metrics
- Map to compliance frameworks

Not allowed in code:

- Assign vulnerability status
- Assign confidence
- Decide exploitability
- Treat thresholds as proof
- Declare a finding confirmed, potential, or safe

## Repository Layout

| Path | Purpose |
|------|---------|
| `cli/cmd/` | Cobra command files |
| `cli/internal/` | Business logic packages |
| `cli/internal/verify/` | Verification probe logic |
| `cli/internal/evidence/` | JSONL evidence writer and reader |
| `cli/internal/payloads/` | Embedded YAML payload seeds and query logic |
| `cli/internal/runner/` | Workspace runner, assessment-plan drafting, coverage validation, Session 09 report gate, Statement of Assessment |
| `cli/internal/compliance/` | Compliance mappings |
| `cli/internal/cvss/` | CVSS v4.0 calculator |
| `cli/internal/scan/` | Regex-based sink scanner |
| `cli/internal/sinks/` | Sink pattern database |
| `cli/internal/callback/` | OOB callback HTTP listener |
| `cli/internal/cloud/` | Read-only cloud configuration probes through provider CLIs |
| `cli/internal/openapi/` | OpenAPI parser |
| `cli/internal/enums/` | Shared enum validation maps |
| `assets/seeds/` | Payload YAML sources (embedded via a copy under `cli/internal/payloads/data/`) |
| `skills/` | Agent methodology and checklists |
| `docs/` | Product and engineering documentation |

## Build

```bash
make build
make install
make install-all
make clean
```

Payload seeds are embedded as YAML. `make copy-seeds` (invoked by `make build`) mirrors `assets/seeds/*.yaml` into `cli/internal/payloads/data/` so `go:embed` can read them — Go embed cannot reach files outside the module. The copy under `data/` is generated and tracked so CI can detect drift; edit the sources under `assets/seeds/`, never the copy.

## Testing

```bash
make test
make smoke
make verify-generated
cd cli && go test -short ./...
cd cli && go test ./...
cd cli && go test -race -short ./internal/verify/
```

See [testing.md](testing.md) for the full test inventory and generated-artifact workflow.

## Change Rules

1. The current public contract is the only supported contract. Do not add
   migration readers, aliases, or retired fields without a product decision.
2. Keep security judgment out of CLI output.
3. Business logic lives under `cli/internal/`, never in command files.
4. Every public-contract or safety-boundary change ships with a focused test.
5. Update [cli-reference.md](cli-reference.md) from the implementation in the
   same change; it is the normative description of the CLI.
6. Update the payload count canaries and docs together when seed data changes.
7. Never describe planned behavior as shipped.

## Command Rules

- Keep one Cobra command file per command under `cli/cmd/`.
- Keep business logic in `cli/internal/<package>/`.
- Commands should parse flags, build config, call internal logic, and encode output.
- Structured output should use indented JSON.
- Verify commands must validate `--in-scope` before network execution.
- Header parsing must reject malformed `--header` values as usage errors.

## Adding Payloads

1. Edit or create YAML under `assets/seeds/`.
2. Follow the `defaults:` plus `payloads:` format.
3. Run `make verify-generated` to re-sync the embedded copy under `cli/internal/payloads/data/`.
4. Commit the `assets/seeds/` changes and the re-synced `data/` copy together.
5. Update the payload count canaries in `cli/internal/payloads/store_test.go` and the docs if the totals change.

Valid enum values are defined in `cli/internal/enums/enums.go`.

## Modes and environments

There is one mode. Source is always in scope; a live target is optional and
belongs to one of two tiers, `sandbox` or `staging` (`target.environment`).
`run init` without `--target` produces a `source_only` draft plan with
`environment: none`. Production is never a live target. Do not reintroduce a
black-box or live-only axis, and do not add a production tier.

## Adding Commands

1. Create `cli/cmd/<name>.go`.
2. Create or extend `cli/internal/<package>/`.
3. Register the command with its parent in `init()`.
4. Add subprocess or focused package tests.
5. Update [cli-reference.md](cli-reference.md) when the public contract changes.

## Documentation Rules

- Keep README human-facing and concise.
- Keep [../index.md](../index.md) and folder-local indexes current when
  adding or retiring major docs, seeds, checklists, or benchmark runbooks.
- Put CLI details in [cli-reference.md](cli-reference.md).
- Put agent workflow rules in [../skills/shared/contract.md](../skills/shared/contract.md) and runner semantics in [cli-reference.md](cli-reference.md).
- Update [testing.md](testing.md) when test inventory, gates, or drift checks change.
