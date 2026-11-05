# Templates

| Template | Purpose |
|----------|---------|
| [config.md](config.md) | Baseline `ensphere-pentest/config.md`: target, sandbox commands, accounts, scope, approved rate-limit bursts and upload sizes, authorization statement. `ensphere run init` writes an equivalent file from flags. |
| [github-workflow.yml](github-workflow.yml) | A GitHub Actions workflow that runs an assessment nightly and on release tags: sandbox, workspace, unattended agent run with a tool allow-list, report gate, SARIF upload, diff against the previous run, signed provenance for the statement, and a policy step. `docs/release-pipeline.md` explains each gate. |
| [github-invariants.yml](github-invariants.yml) | A GitHub Actions workflow for the project under assessment that runs its `.ensphere/invariants/` on every pull request with the binary alone: no agent, fails only on an enforced invariant that does not hold. |
| [dot-ensphere/](dot-ensphere/) | A worked example of what an assessment leaves in the target repository: `map.md`, `surfaces.yaml`, and one invariant per kind (`rate_limit`, `http`, `size_limit`, `source`, `command`). The file paths are illustrative, so `map validate` only passes against a tree that has them. |
