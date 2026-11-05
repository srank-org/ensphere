# Ensphere Project Index

Fast orientation for agents and contributors.

## Start here

| Need | File |
|------|------|
| What Ensphere is and how to run it | [README.md](README.md) |
| Rules for working on the code and the skill | [AGENTS.md](AGENTS.md) |
| The agent skill entry point | [skills/ensphere/SKILL.md](skills/ensphere/SKILL.md) |
| The one rulebook every session follows | [skills/ensphere/shared/contract.md](skills/ensphere/shared/contract.md) |
| What gets checked, independent of stack | [skills/ensphere/shared/fundamentals.md](skills/ensphere/shared/fundamentals.md) |
| How the sandbox is built and isolated | [skills/ensphere/shared/sandbox.md](skills/ensphere/shared/sandbox.md) |
| How sessions map to WSTG and ASVS | [skills/ensphere/shared/coverage-map.md](skills/ensphere/shared/coverage-map.md) |
| How to benchmark a methodology change | [docs/evaluation/README.md](docs/evaluation/README.md) |
| Which checklist a stack loads | [skills/ensphere/methodology/01.5-session-plan.md](skills/ensphere/methodology/01.5-session-plan.md) |
| CLI commands and flags | [docs/cli-reference.md](docs/cli-reference.md) |
| Running it from a release pipeline | [docs/release-pipeline.md](docs/release-pipeline.md) |

## For agents running an assessment

The repository is a Claude Code plugin: `.claude-plugin/plugin.json` is the
manifest, `skills/ensphere/` the assessment skill, `skills/ensphere-setup/`
the installer for the matching binary, `agents/ensphere-session.md` the
fresh-context agent that runs one check session, and `hooks/` the assessment
guard. `make install-all` copies the skill to `~/.claude/skills/ensphere` and
`~/.codex/skills/ensphere` for harnesses without plugins. The entry point,
[skills/ensphere/SKILL.md](skills/ensphere/SKILL.md), loads the contract, the
fundamentals map, and one methodology file per session. The workspace is the
protocol between sessions: an orchestrator runs recon, planning, and the
report itself and dispatches each check session to a fresh subagent with a
short brief, and a harness without subagents runs the same files in one
context and resumes from `next-action.md` after a context loss.

## Repository map

| Path | Purpose |
|------|---------|
| [.claude-plugin/](.claude-plugin/) | Plugin manifest and marketplace entry |
| [hooks/](hooks/) | Assessment guard and session-start hooks |
| [agents/](agents/) | The fresh-context session agent |
| [skills/](skills/) | The assessment skill (`ensphere/`) and the setup skill (`ensphere-setup/`) |
| [cli/cmd/](cli/cmd/) | Cobra command layer |
| [cli/internal/](cli/internal/) | Deterministic business logic |
| [assets/seeds/](assets/seeds/) | YAML payload sources |
| [docs/](docs/) | CLI reference, release pipeline, development, testing, benchmark protocol |
| [templates/](templates/) | Workspace configuration and CI workflow templates |

## Folder indexes

| Area | Index |
|------|-------|
| Methodology | [skills/ensphere/methodology/index.md](skills/ensphere/methodology/index.md) |
| Checklists | [skills/ensphere/checklists/index.md](skills/ensphere/checklists/index.md) |
| Payload seeds | [assets/seeds/index.md](assets/seeds/index.md) |
| Templates | [templates/index.md](templates/index.md) |

## Verification

```bash
cd cli && go test ./...
make build
make smoke
make verify-generated
```
