# Running Ensphere on every release

An Ensphere run needs no one at the keyboard once its inputs are known. This
page is the recipe for running it from a release pipeline: what to prepare,
what to run, what to gate on, and what to publish. It assumes the CLI and
skill are installed on the runner and that the project has a sandbox it can
start from a compose file or a dev script (`skills/shared/sandbox.md`).

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
| Sandbox start, seed, and reset commands | A `## Sandbox` section in `config.md` with `Start`, `Seed`, and `Reset` lines. Writing them there approves them. |
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

# 2. Initialise the workspace with every input the run needs.
ensphere run init \
  --target "http://localhost:3000" \
  --environment sandbox \
  --in-scope localhost \
  --login-url /login --username sandbox-a --password "$SANDBOX_PASSWORD" \
  --approved-bursts "POST /api/auth/otp: 20/10s, POST /api/upload: 10/10s" \
  --approved-upload-sizes "26214400" \
  --assessed-by "Claude Fable 5.1 via Claude Code" \
  --operator "Jane Doe, CTO"

# 3. Approve the sandbox commands by writing them into config.md.
cat >> ensphere-pentest/config.md <<'CFG'

## Sandbox
- Start: docker compose -f compose.sandbox.yml up -d --wait
- Seed: npm run seed:synthetic
- Reset: docker compose -f compose.sandbox.yml down -v && docker compose -f compose.sandbox.yml up -d --wait && npm run seed:synthetic
CFG

# 4. Run the agent unattended with the prompt "ensphere".
#    The agent must be allowed to run ensphere, the sandbox commands, and
#    read the repository without prompting. How that permission is granted
#    differs by agent; for Claude Code it is an allow-list in the project's
#    settings and the non-interactive flag:
claude -p "ensphere"

# 5. Gate. The statement command exits 2 until the report gate passes.
ensphere run statement

# 6. Policy. Fail the release on unresolved P0 findings.
p0=$(yq '[.findings[] | select((.status == "confirmed" or .status == "likely") and .priority == "P0")] | length' \
  ensphere-pentest/09-report/finding-registry.yaml)
test "$p0" -eq 0

# 7. Publish.
tar czf ensphere-report.tgz \
  ensphere-pentest/09-report \
  ensphere-pentest/*/evidence.jsonl \
  ensphere-pentest/*/coverage.yaml
```

Attach the archive to the release. `09-report/report.md` is for the team,
`09-report/statement.md` is for whoever asks for due diligence, and the
ledgers and coverage files are what let a reader verify either one.

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
- **Missing controls that regressed.** The report's "Missing controls by
  service" table lists every billed service and storage surface with the
  state of each control. Diff it against the previous release's. A control
  that was present and is now absent is a regression, and the diff is a
  fact, not a judgment. Today this comparison is done by hand or by a
  script over the two registries; a deterministic comparison command is a
  natural addition and is not built yet.

Do not gate on the prose of the report, on finding counts alone, or on
"checks executed" going up. Coverage counts describe what was measured this
run, and a smaller system legitimately has fewer rows.

## What a release run cannot do

- It cannot probe production. The pipeline's target is the sandbox, and the
  only production interaction permitted anywhere in Ensphere is a read of
  provider configuration through the provider CLI.
- It cannot replace the operator's signature. The statement says it is a
  self-assessment; someone still signs it.
- It cannot make two runs identical. Gate on the deterministic outputs and
  read the report for the rest.
