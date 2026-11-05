# Running Ensphere on every release

An Ensphere run needs no one at the keyboard once its inputs are known. This
page is the recipe for running it from a release pipeline: what to prepare,
what to run, what to gate on, and what to publish. It assumes the CLI and
skill are installed on the runner and that the project has a sandbox it can
start from a compose file or a dev script (`skills/ensphere/shared/sandbox.md`).
`templates/github-workflow.yml` is the same recipe as a GitHub Actions
workflow; copy it into the project and fill in the placeholders.

## Cadence and cost

A run is agent time measured in tens of minutes to a few hours, depending on
the size of the system and the model. Run it per release, or nightly against
the release branch. It is not a pull-request check. Two runs of an agent are
never identical, so a pipeline gates on the deterministic outputs (below),
never on the prose.

## Answer the human gates in advance

The contract (Pacing) names five gates where a run pauses for the operator.
Each can be answered before the run starts, and a gate whose answer is
already in `config.md` is not asked again.

| Gate | Where the answer lives |
|------|------------------------|
| Authorization and first-run inputs | `config.md`, written by `run init` flags: target, scope, test identity, assessor, operator. The authorization statement is part of the file. |
| Sandbox start, seed, and reset commands | A `## Sandbox` section in `config.md` with `Start`, `Seed`, and `Reset` lines, written by the `--sandbox-start`, `--sandbox-seed`, and `--sandbox-reset` flags of `run init` or by hand. Writing them there approves them. |
| Assessment-level blocker | Cannot be pre-answered. The run stops, writes a Needs-from-you list, and the pipeline fails. Fix the input and rerun. |
| Staging state change or burst count | Do not give the pipeline a staging target, or record every burst count and upload size in `config.md` with `--approved-bursts` and `--approved-upload-sizes`. |
| Finished report and statement | The pipeline publishes them; the operator signs the statement. |

Provider CLIs (`aws`, `gcloud`, `az`, `wrangler`, `supabase`) must be
logged in on the runner for Session 07 to measure. If they are not, the
session records its rows `blocked` and the run continues; the statement
shows the gap.

## The recipe

Fresh checkout, ephemeral workspace. `run init` refuses to overwrite an
existing workspace, so start clean each time and keep `ensphere-pentest/`
out of version control.

```bash
# 1. Start the sandbox and seed it with synthetic data.
docker compose -f compose.sandbox.yml up -d --wait
npm run seed:synthetic

# 2. Initialise the workspace with every input the run needs. Take the
#    assessor from the same variable that selects the model, so the
#    statement names the model that actually ran.
MODEL=claude-fable-5-1
ensphere run init \
  --target "http://localhost:3000" \
  --environment sandbox \
  --in-scope localhost \
  --login-url /login --username sandbox-a --password "$SANDBOX_PASSWORD" \
  --approved-bursts "POST /api/auth/otp: 20/10s, POST /api/upload: 10/10s" \
  --approved-upload-sizes "26214400" \
  --assessed-by "$MODEL via Claude Code $(claude --version)" \
  --operator "Jane Doe, CTO" \
  --sandbox-start "docker compose -f compose.sandbox.yml up -d --wait" \
  --sandbox-seed "npm run seed:synthetic" \
  --sandbox-reset "docker compose -f compose.sandbox.yml down -v && docker compose -f compose.sandbox.yml up -d --wait && npm run seed:synthetic"
#    The three sandbox flags write the ## Sandbox section of config.md, which
#    is the operator's approval of those exact commands.

# 3. Run the agent unattended with the prompt "ensphere". The allow-list
#    names the ensphere binary, the sandbox commands, and file tools, and
#    nothing that can open a socket on its own.
claude -p "ensphere" --model "$MODEL" \
  --allowedTools "Bash(ensphere:*),Bash(docker compose:*),Bash(npm run seed:synthetic),Read,Glob,Grep,Write,Edit"

# 4. Gate. The statement command exits 2 until the report gate passes.
ensphere run statement

# 5. Compare with the previous release and export for code scanning.
ensphere run diff --previous ../previous-release/ensphere-pentest
ensphere run sarif

# 6. Policy. Fail the release on an unresolved P0 and on any unresolved
#    finding that is new or reopened since the previous run.
p0=$(yq '[.findings[] | select((.status == "confirmed" or .status == "likely") and .priority == "P0")] | length' \
  ensphere-pentest/09-report/finding-registry.yaml)
test "$p0" -eq 0
jq -e '.findings.summary.new_unresolved == 0 and .findings.summary.reopened == 0' \
  ensphere-pentest/09-report/diff.json

# 7. Publish.
tar czf ensphere-report.tgz \
  ensphere-pentest/09-report \
  ensphere-pentest/*/evidence.jsonl \
  ensphere-pentest/*/coverage.yaml
```

Attach the archive to the release. `09-report/report.md` is for the team,
`09-report/statement.md` is for whoever asks for due diligence, and the
ledgers and coverage files are what let a reader verify either one. Keep
the archive of each release; the next run's `diff` reads it.

The credentials in step 2 are the sandbox's synthetic test accounts. Never
put a real credential, or a production hostname, anywhere in the pipeline
or in `config.md`.

## What to gate on

- **The report gate.** `ensphere run statement` exits 2 while
  `ensphere run report` has errors: a non-terminal session, a missing
  coverage file, a broken evidence chain, an uncited finding. This is the
  minimum. A run that cannot produce a statement did not finish.
- **Unresolved findings by priority.** The finding registry is YAML; count
  `confirmed` and `likely` findings at the priority your policy names.
  `P0` means fix before anything else.
- **What changed since the previous run.** `ensphere run diff --previous
  <workspace>` writes `09-report/diff.json` and `diff.md`. It matches
  findings across the two registries by kind, category, and title, and
  failing that by a shared affected location with line numbers ignored, so
  a refactor does not break the match. Its summary counts
  `new_unresolved`, `gone_unresolved`, `reopened` (a finding that was
  `not_supported` or absent and is now `confirmed` or `likely`), and
  `resolved`, and it lists every coverage row whose state changed. A
  missing control that held last release and is absent this release shows
  up as `reopened`, a fact rather than an opinion. The command assigns
  nothing and exits 0 whenever both inputs parse; the policy is yours.

Do not gate on the prose of the report, on finding counts alone, or on
"checks executed" going up. Coverage counts describe what was measured this
run, and a smaller system legitimately has fewer rows.

## Code scanning

`ensphere run sarif` writes `09-report/findings.sarif` (SARIF 2.1.0) from
the registry so findings appear as alerts in GitHub code scanning or any
tool that reads SARIF. Only `confirmed`, `likely`, and `informational`
findings become results; `not_supported` and `not_tested` never do. Each
result carries the analyst's status, confidence, severity, priority, and
evidence ids as properties, a location for every affected file and line
and a logical location for every endpoint, and a fingerprint derived from
the same key the diff uses, so an alert survives across uploads. The SARIF
`level` is a fixed translation of the severity the analyst assigned
(critical and high to error, medium to warning, the rest to note); it is a
format conversion, not a new judgment.

## Provenance, not security attestation

A model cannot sign anything. No provider issues a signing key per model,
and an API response carries a model id, not a signature; "assessed by
Fable 5.1" is a string anyone can type. What a pipeline can do is sign the
statement with its own identity, so a reader can verify that this exact
statement came from this workflow, on this commit, with these ledgers.

`ensphere run statement` writes `statement.json` beside `statement.yaml`
for this purpose. In GitHub Actions, `actions/attest` signs keylessly with
the workflow's OIDC identity through Sigstore:

```yaml
- uses: actions/attest@v2
  with:
    subject-path: ensphere-pentest/09-report/statement.yaml
    predicate-type: https://github.com/srank-org/ensphere/statement/v1
    predicate-path: ensphere-pentest/09-report/statement.json
```

Anyone with the file can then run `gh attestation verify
ensphere-pentest/09-report/statement.yaml --owner <org>` and see the
repository, workflow, commit, and the statement's inputs digest, ledger
hashes, model, and Ensphere version. What this proves is provenance: who
produced the statement and from what. It proves nothing about the system
being secure, and the statement's closing sentence still says it is a
self-assessment and not an independent audit, attestation, or
certification. The operator still signs it. The model's name is a field
inside a signed record, not the thing doing the signing.

## Network boundary

The CLI refuses any host outside `--in-scope`, including redirect hops,
for every request that goes through it. That boundary holds only if the
CLI is the agent's only way to send a request. Two layers make it so:

- **The guard.** The plugin's PreToolUse hook refuses raw network tools,
  inline-code interpreters, and shell constructs it cannot follow whenever
  a workspace exists, on a developer's machine and in `claude -p` alike.
  It also auto-approves `ensphere` and the sandbox commands in `config.md`,
  and every verify command checks its `--in-scope` against the scope the
  operator approved there.
- **The allow-list.** In `claude -p`, allow `Bash(ensphere:*)`, the exact
  sandbox commands, and the file tools. Do not allow `curl`, `wget`, `nc`,
  `python`, `node`, or a shell wrapper that could reach them. Every request
  then lands in the ledger under scope enforcement.
- **The container.** For a physical boundary, run the agent in a container
  attached to an internal Docker network shared with the sandbox, with no
  default route, and a proxy container on that network whose allow-list
  holds only the model API host. Point the agent at it with `HTTPS_PROXY`.
  The sandbox is reachable, the model is reachable, and nothing else
  resolves. "Production is never probed" becomes a property of the network
  rather than a promise by the model.

## What a release run cannot do

- It cannot probe production. The pipeline's target is the sandbox, and the
  only production interaction permitted anywhere in Ensphere is a read of
  provider configuration through the provider CLI.
- It cannot replace the operator's signature. The statement says it is a
  self-assessment; someone still signs it.
- It cannot make two runs identical. Gate on the deterministic outputs and
  read the report for the rest.
