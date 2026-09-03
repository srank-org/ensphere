# Ensphere Project Index

Fast orientation for agents and contributors.

## Start here

| Need | File |
|------|------|
| What Ensphere is and how to run it | [README.md](README.md) |
| Rules for working on the code and the skill | [AGENTS.md](AGENTS.md) |
| The agent skill entry point | [skills/SKILL.md](skills/SKILL.md) |
| The one rulebook every session follows | [skills/shared/contract.md](skills/shared/contract.md) |
| What gets checked, independent of stack | [skills/shared/fundamentals.md](skills/shared/fundamentals.md) |
| How the sandbox is built and isolated | [skills/shared/sandbox.md](skills/shared/sandbox.md) |
| How sessions map to WSTG and ASVS | [skills/shared/coverage-map.md](skills/shared/coverage-map.md) |
| How to benchmark a methodology change | [skills/evaluation/README.md](skills/evaluation/README.md) |
| Which checklist a stack loads | [skills/methodology/01.5-session-plan.md](skills/methodology/01.5-session-plan.md) |
| CLI commands and flags | [docs/cli-reference.md](docs/cli-reference.md) |
| Running it from a release pipeline | [docs/release-pipeline.md](docs/release-pipeline.md) |

## Repository map

| Path | Purpose |
|------|---------|
| [skills/](skills/) | Skill, contract, methodology, checklists, evaluation protocol |
| [cli/cmd/](cli/cmd/) | Cobra command layer |
| [cli/internal/](cli/internal/) | Deterministic business logic |
| [assets/seeds/](assets/seeds/) | YAML payload sources |
| [docs/](docs/) | CLI reference, release pipeline, development, testing |
| [templates/](templates/) | Workspace configuration template |

## Folder indexes

| Area | Index |
|------|-------|
| Methodology | [skills/methodology/index.md](skills/methodology/index.md) |
| Checklists | [skills/checklists/index.md](skills/checklists/index.md) |
| Payload seeds | [assets/seeds/index.md](assets/seeds/index.md) |
| Templates | [templates/index.md](templates/index.md) |

## Verification

```bash
cd cli && go test ./...
make build
make smoke
make verify-generated
```
