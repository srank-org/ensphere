# Templates

| Template | Purpose |
|----------|---------|
| [config.md](config.md) | Baseline `ensphere-pentest/config.md`: target, sandbox commands, accounts, scope, approved rate-limit bursts and upload sizes, authorization statement. `ensphere run init` writes an equivalent file from flags. |
| [github-workflow.yml](github-workflow.yml) | A GitHub Actions workflow that runs an assessment nightly and on release tags: sandbox, workspace, unattended agent run with a tool allow-list, report gate, SARIF upload, diff against the previous run, signed provenance for the statement, and a policy step. `docs/release-pipeline.md` explains each gate. |
