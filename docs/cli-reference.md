# Ensphere CLI Reference

This document is the full command reference for the `ensphere` Go CLI. Commands emit structured JSON where applicable and produce measurements, never security judgments. `ensphere <command> --help` is the source of truth for flags.

## Build and Install

In Claude Code, install the plugin (`/plugin marketplace add srank-org/ensphere`,
then `/plugin install ensphere@srank`) and say `ensphere-setup`: it installs the
binary that matches the plugin's version from a signed release, checks the
checksum and the provenance attestation, reports which provider CLIs are
logged in, and ends with `ensphere run doctor`. The plugin installs two hooks:
while a project holds an assessment workspace, raw network tools such as
`curl` are refused so every request goes through the CLI's scope enforcement,
and each new session starts from the workspace's next action. Set
`ENSPHERE_GUARD=off` to switch the guard off for one shell.

For Codex or another harness that loads skills from a directory, or to build
by hand (Go 1.26 or newer):

```bash
git clone https://github.com/srank-org/ensphere.git
cd ensphere
make build        # build ./bin/ensphere
make install      # install the binary to /usr/local/bin/ensphere
make install-all  # install the binary and copy the skill to ~/.claude and ~/.codex
```

If you later switch to the plugin, remove the copied skill with
`./install-skills.sh --uninstall --target claude` so it is not loaded twice.
A binary built from an untagged checkout reports a commit hash instead of a
release version, and the doctor says so.

For platform configuration checks the agent uses the provider's own CLI, so
have `aws`, `gcloud`, `az`, `wrangler`, or `supabase` installed and logged in
for the platforms you run on. The agent names the one it needs and marks the
check blocked until you sign in; Ensphere never logs in on your behalf.

You can also run directly from source:

```bash
cd cli
go run . --help
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Command completed |
| 1 | Generic command failure or scan matches found |
| 2 | Usage or scope error |
| 3 | Runtime probe failure |

Exit 0 means the operation completed. It is never a security conclusion.

## Safety Contract

These are the guarantees the CLI enforces on its own, independent of the
skill. The methodology adds rules on top; the CLI does not read the session
plan.

- Scope validation precedes every verify request and every redirect hop.
  A host outside `--in-scope` is refused with exit 2.
- When an assessment workspace exists (`ENSPHERE_WORKSPACE`, then
  `./ensphere-pentest`, then `$CLAUDE_PROJECT_DIR/ensphere-pentest`), every
  `--in-scope` pattern must appear in the scope recorded in its `config.md`,
  or the command is refused with exit 2. Scope is approved by the operator
  in the workspace, not chosen on the command line.
- The default maximum risk is 3. Each verify family carries a fixed risk;
  SQLi also selects payload records by risk; `verify request` carries the
  risk the analyst declares with `--risk`. Risk 4 and 5 payloads never read
  credentials or execute code.
- `verify request` accepts a body of at most 256 KiB and a fixed method
  list, and follows redirects only when asked.
- The default inter-probe throttle is 500 ms where a probe uses standard
  throttling.
- Rate-limit measurement requires an explicit `--burst-count`; there is no
  default burst.
- Verify output never contains a field named `status`, `confidence`,
  `confirmed`, `safe`, or `potential`. A contract test enforces this for every
  family.
- Automatic redaction covers JWTs, bearer tokens, and supported sensitive
  query parameters. Manual secret and personal-data review before publication
  is still the analyst's job.
- The report gate checks transcript, artifact, and cleanup paths for safe,
  workspace-relative form.
- There is no exploitation, extraction, or load-generation command, and none
  may be added.

## Payloads

Query the embedded payload set. Seed YAML under `assets/seeds/` is embedded
into the binary and parsed once on first use; there is no runtime database.

```bash
ensphere payloads sqli --db postgres --technique blind_time
ensphere payloads ssrf --max-risk 2
ensphere payloads csv_injection
ensphere payloads sqli --tag pg_sleep --limit 5
```

Flags:

```text
--db            Database engine: postgres, mysql, mssql, sqlite, oracle
--runtime       Runtime: node, jvm, python, php, dotnet, ruby, go
--technique     Technique, e.g. blind_time, error_based, union, metadata_access
--surface       Injection surface: query, path, header, cookie, json_body, form_body
--content-type  Content type, e.g. application/json
--encoding      Encoding: raw, url, double_url, unicode, hex, base64
--boundary      String boundary: single_quote, double_quote, numeric, unquoted
--tag           Filter by tag
--max-risk      Maximum risk level 1-5, 0 = no limit (default 3)
--limit         Maximum results to return (default 20)
```

`--db`, `--runtime`, `--content-type`, and `--boundary` are nullable
"broadening" filters: a set value matches rows with that value **or** with the
column unset (engine-agnostic rows are always included). `--technique`,
`--surface`, and `--encoding` are exact filters. Results are ordered by
broadening rank (exact matches before unset-value fallbacks), then risk, then
the stable content-hash id.

Output includes `query`, `count`, and `results[]` with id, payload,
placeholders, evidence type, risk, notes, source, and tags. Invalid filters
return valid values.

## Run

Create and inspect the `ensphere-pentest/` workspace used by the agent
workflow. The runner writes deterministic workspace files, `next-action.md`,
and `agent-prompt.md`; it does not run AI reasoning and has no exploitation
command. Subcommands are `init`, `status`, `next`, `plan`, `report`,
`statement`, `diff`, `sarif`, and `doctor`.

```bash
ensphere run init \
  --target "http://localhost:3000" \
  --environment sandbox \
  --source-path . \
  --target-type api_backend \
  --in-scope localhost

ensphere run status
ensphere run plan
ensphere run next
ensphere run report
ensphere run statement
ensphere run diff --previous ../previous-release/ensphere-pentest
ensphere run sarif
ensphere run doctor
```

`run doctor` runs every readiness check once, read-only, and prints each
as `ok`, `warning`, `error`, or `skipped` with a detail line: the binary
against the plugin version (`--plugin-version`, or the manifest under
`$CLAUDE_PLUGIN_ROOT`), the workspace and its next session, the source
tree's git commit and drift, the system map and the invariants when
present, one `GET` to the configured target after checking it against the
approved scope, the `Start`, `Seed`, and `Reset` commands under `## Sandbox`,
the provider CLIs the cloud scope needs (installed or not; it never logs
in), and the hash chain of every session ledger. Without a workspace it
still checks the binary, the source tree, the map, and the invariants from
the current directory. It writes nothing and exits 1 when any check is an
`error`. The output describes the tooling, never the system.

Flags for `run init`:

```text
--workspace              Workspace directory, default ensphere-pentest (persistent flag on all run subcommands)
--target                 Base URL of the live target (a sandbox or staging); omit for a source-only assessment
--environment            sandbox, staging, or none; default sandbox when --target is given, none otherwise
--source-path            Path to the source tree under assessment, default "."
--target-type            auto (default), web_app, api_backend, static_site, mobile_client_remote_backend, mobile_client_offline, desktop_or_extension_client, cloud_only, library_or_cli
--cloud                  none (default), aws, gcp, azure, kubernetes, cloudflare, supabase, or comma-separated
--in-scope               Comma-separated host patterns the verify commands must stay within (hostnames, globs such as *.example.com, IPs, CIDRs); defaults to the target's host
--out-of-scope           Out-of-scope boundary summary
--login-url, --username, --password   Test identity for authenticated sessions
--approved-bursts        Operator-approved rate-limit bursts, e.g. "POST /api/otp: 10/10s"
--approved-upload-sizes  Operator-approved upload sizes in bytes for the size-limit probe
--assessed-by            Model or person performing the assessment, e.g. "Claude Fable 5.1 via Claude Code"
--operator               Person who authorizes the assessment and signs the statement
--sandbox-start          Command that starts the sandbox; written under ## Sandbox in config.md, which approves it
--sandbox-seed           Command that seeds the sandbox with synthetic data
--sandbox-reset          Command that resets the sandbox to its seeded state
--delta-since            Git ref for a delta run: only surfaces whose files changed since it are re-checked (needs .ensphere/surfaces.yaml)
```

`--delta-since` writes `- Delta since: <ref>` into `config.md`. When the
source tree has a valid map, `run plan` computes the change set with the
same logic as `map changed`, records it in the plan's `delta` block
(`since`, `head`, `changed_surfaces`, `unmapped_changed_files`,
`sessions_affected`), and drafts every session the change set does not
touch as `skip` with the ref in its reason. A changed file no surface
claims keeps every session's normal draft. Without a valid map the plan is
drafted in full and `delta` carries only the ref and a reason. The
statement prints the ref as "Delta since".

The three sandbox flags write a `## Sandbox` section into `config.md` with
`Start`, `Seed`, and `Reset` lines. Writing a command there is the
operator's approval of it: the agent may run it, and the plugin's guard
allows it without prompting. Add further lines by hand for anything else
the sandbox needs, one `- Label: command` per line.

`--assessed-by` and `--operator` are recorded under an `Assessment` heading
in `config.md` and copied into the Statement of Assessment. Both may be
filled in later by editing `config.md`.

`run plan` accepts `--force` to overwrite an existing assessment plan from
config.

Source is always in scope; a live target is optional. Without `--target` the
draft plan carries `environment: none` and drafts each measurement session
`limited` with a reason that says source review only. `target.environment`
is required: `none` requires an empty `target.url`, and `sandbox` and
`staging` require one. The environment tier is the plan's only statement
about whether a live target exists; there is no separate coverage label.
The chains session drafts as `run` only when the recon target profile
records `environment: sandbox`; otherwise it drafts `blocked`. The cloud
session drafts `skip` when `--cloud` is `none`.

`run plan` writes `assessment-plan.yaml` and mirrors it to
`01.5-session-plan/assessment-plan.yaml` when no plan exists. Existing plans are
validated, copied to the Session 01.5 mirror, and not overwritten unless
`--force` is set. The generated plan is deterministic. It starts from
`config.md` and, when present, incorporates
`01-recon/target-profile.yaml` for Recon-generated target type, stack profile,
backend inventory, client-only limitations, and session applicability signals.

`run init` refuses to overwrite a workspace that already contains `config.md`
or `progress.md`; use `run status` or `run next` to resume an initialized
assessment.

`run report` writes `09-report/report-gate.yaml` and
`09-report/report-gate.md`. Every finding in the registry carries a required
`kind` of `vulnerability` or `missing_control` and an id that matches its
kind: `VULN-001` for a vulnerability, `CTRL-001` for a missing control.
`cvss_v4` is optional and, when present, must be a `CVSS:4.0/` vector; a CVSS
vector on a `missing_control` finding is reported as a warning because CVSS is
only meaningful for a vulnerability. `progress.md` holds one of three states per session: `PENDING`,
`IN_PROGRESS`, or `DONE`. `DONE` means the session report is written; a
session the plan decided `skip`, `not_applicable`, or `blocked` is `DONE`
once its short report names that decision. Any other value is a gate
error. The gate blocks report readiness when a session from 01 to 08.7 is
not `DONE`, a session report is missing or empty, `assessment-plan.yaml` is
missing or invalid, evidence chain verification fails, a tracked file in
the source tree differs from its commit (`source_tree_modified`; untracked
files are the warning `source_tree_untracked`, and a source path outside
git is the warning `source_not_git`), a `confirmed` or
`likely` finding has no invariant under the source tree's
`.ensphere/invariants/` whose `origin.ref` names it
(`finding_invariant_missing`) or has one with `enforce: true`
(`invariant_enforced_before_fix`), an invariant file does not load or
validate (the `invariants validate` codes), or the finding
registry contains uncited findings, missing required finding fields,
invalid or duplicate finding ids, missing or invalid finding kinds, invalid
statuses (`confirmed`, `likely`, `informational`, `not_supported`,
`not_tested`), inconsistent evidence strength, invalid
confidence/severity/priority values, invalid evidence categories, missing or
unsafe transcript/artifact/cleanup paths, or an incomplete final report and
evidence appendix.

The gate also reads every session's `coverage.yaml` (Sessions 02 through
08.7; Recon and the plan carry none). A `DONE` session without the file is
an error unless the plan decided that session `skip` or `not_applicable`.
Each row needs an id of the form `COV-<session>-NNN`, a `surface`, a
`check`, and a `state` of `planned`, `tested`, `not_tested`, `blocked`, or
`not_applicable`. A row may carry `surface_id`, the `SURF-NNN` id from
`.ensphere/surfaces.yaml`; when the source tree has that map, the gate
validates the map (its issue codes become gate issues, `map_parse_failed`
when it does not parse) and rejects an id it does not list
(`coverage_surface_unknown`). A `planned` row blocks the report. A `tested` row must
cite `evidence_ids` that exist in that session's `evidence.jsonl`, and when
any cited entry is a `probe`, `payload`, or `callback` the row must also
cite a `baseline` entry and a `control` entry from the same ledger
(`coverage_baseline_missing`, `coverage_control_missing`); a row that cites
only `manual_note` entries, such as a source-review row, is exempt. Every
other resolved state needs a `reason`. `identity`, `transcripts`,
`checklist`, and `hypothesis` (the `HYP-NNN` recon hypothesis the row
resolves) are optional; the gate checks transcript paths and records the
rest. The gate output carries a `coverage` block with counts per session
and in total, and `report-gate.md` renders the same table. Those counts are
the only source for the report's "checks executed" and "not checked"
numbers; there is no analyst-chosen coverage label.

`run statement` derives `09-report/statement.yaml` and
`09-report/statement.md`, the one-page Statement of Assessment, from the
workspace alone: target, environment, source path and the git commit the
tree is at (`source_commit`), platforms, assessor and
operator from `config.md`; every session's plan decision and progress
state; the coverage counts above; finding counts by kind, status,
and severity with the unresolved findings listed; each ledger's entry count,
chain validity, and final hash; the earliest and latest evidence timestamps;
and the Ensphere version. Nothing is typed by the caller. The command exits 2
while the report gate has errors. It records a SHA-256 digest of its inputs
in both files; afterwards the gate reports `statement_stale` if any input
changes, `statement_edited` if `statement.md` no longer matches
`statement.yaml`, and `statement_markdown_missing` if the markdown is
deleted. Regenerate rather than edit. The markdown ends with the fixed
self-assessment sentence and a signature block for the operator.

`run statement` also writes `09-report/statement.json`, the same record as
JSON, for a release pipeline to sign as the predicate of a provenance
attestation (`docs/release-pipeline.md`). The gate reports
`statement_json_missing` when it is absent and `statement_edited` when its
digest differs from the YAML's.

`run diff --previous <dir>` compares the current workspace with a previous
assessment's workspace and writes `09-report/diff.json` and `diff.md`.
Findings are matched across the two registries by kind, category, and
normalised title, then by a shared affected location with any `:line`
suffix ignored; each match records `matched_by`. The output lists findings
that are `new`, `gone`, `changed` (status, severity, or priority), and
`unchanged`, with a summary of `unresolved_before`, `unresolved_after`,
`new_unresolved`, `gone_unresolved`, `reopened`, and `resolved`, where
unresolved means `confirmed` or `likely`. Coverage rows are keyed by
session, surface, check, and identity and reported as `added`, `removed`,
or `changed` with the state before and after, plus counts per session.
When both workspaces hold a statement, their Ensphere version, assessor,
and ledger entry counts are compared. The command assigns nothing, is
deterministic, and exits 0 whenever both inputs parse; a missing
`--previous`, or one that is not a directory, is a usage error (exit 2).

`run sarif` writes `09-report/findings.sarif`, SARIF 2.1.0, from the
finding registry. Results are the `confirmed`, `likely`, and
`informational` findings; `not_supported` and `not_tested` entries are
never results. Each result carries one rule per kind and category
(`ensphere/<kind>/<category>`, with a help link to the methodology file), a
`level` that is a fixed translation of the analyst's severity (critical and
high to `error`, medium to `warning`, the rest to `note`), a physical
location for every affected `path:line` and a logical location for every
endpoint, a fingerprint derived from the diff's matching key so an alert
survives across uploads, and the registry's status, confidence, evidence
strength, severity, priority, evidence ids, and assets as properties. A
finding with no file location points at its own entry in the registry so
code scanning still displays it. The file is deterministic for a given
registry.

Runner-generated state, plans, recon profiles, report artifacts, and finding
registries use one canonical schema. Unknown fields are rejected rather than
ignored.

## Map

The system map is the persistent inventory an assessment leaves in the
target repository: `<source-path>/.ensphere/surfaces.yaml` (machine-read,
validated here) beside `.ensphere/map.md` (prose, not parsed). Session 01
writes and reconciles both; the contract (System map and invariants) states
the rules and the vocabulary.

```bash
ensphere map validate [--source-path .] [--map <path>]
ensphere map changed [--since <ref>] [--source-path .] [--map <path>]
```

`map changed` also lists `invariants_affected`: every invariant under
`.ensphere/invariants/` whose `surface` is among the changed surfaces, with
its id, surface, `enforce`, and path, so a change to a surface's files
names the declared expectations that cover it.

`map validate` checks `version: 1`, a non-empty `reconciled_at`, unique
`SURF-NNN` ids, a known `kind` (`endpoint`, `table`, `bucket`, `function`,
`job`, `config`, `client`, `workflow`), a non-empty `name`, a `role` from
the fundamentals vocabulary, at least one file that exists under the source
path with no absolute or `..` component, and at least one owning session.
Output is JSON with `path`, `valid`, `surfaces`, and `issues` (`severity`,
`code`, `path`, `message`); exit 1 on an error issue, 3 when the file
cannot be read.

`map changed` validates, then asks git which files changed since `--since`
(a commit, tag, or branch; default `reconciled_at`) against the working
tree, uncommitted edits and untracked files included, and reports
`changed_files`,
`changed_surfaces` (each with its `changed_files` and `sessions`),
`unmapped_changed_files` (changed files no surface claims),
`missing_files` (files a surface claims that no longer exist), and
`sessions_affected`. A surface may list a directory and then claims every
changed file beneath it. Files under `.ensphere/` and under the
`ensphere-pentest/` workspace are never part of the change set, since
both change on every assessment by design. It is the input to a delta run and to Session 01's
reconciliation. Exit 3 when git fails.

## Invariants

Invariants are declared expectations, one YAML file each under
`<source-path>/.ensphere/invariants/`, that the target's own CI runs on
every pull request with no agent. Session 09 writes them from findings'
validation criteria and from tested defenses; `templates/dot-ensphere/`
shows one of each kind. The report gate checks that every `confirmed` or
`likely` finding has one, with `enforce: false` (see Run).

```bash
ensphere invariants validate [--dir <path>] [--source-path .] [--map <path>]
ensphere invariants run --in-scope <patterns> [--target <base url>] \
  [--dir <path>] [--source-path .] [--map <path>] [--only INV-001,INV-002] \
  [--since <ref>] [--max-risk N] [--throttle ms] [--timeout s] \
  [--header k:v] [--out <file>]
```

`--since <ref>` joins the working tree's changes since the ref to the
system map, as `map changed` does, and marks each result whose `surface`
changed with `surface_changed: true`; the report records `since` and the
summary counts `surface_changed`. It needs a valid map (usage error
otherwise). A pull-request job passes the base commit so the reviewer sees
which invariants cover the files the change touched.

`--target` may be omitted when the directory holds only `source` and
`command` invariants; an HTTP-kind invariant run without one is `error`.

Each file has `id` (`INV-NNN`), `title`, optional `surface`, `origin`
(`kind` of `vulnerability`, `missing_control`, or `tested_defense`, the
`ref` it came from, optional `assessment` digest and `evidence` ids),
`enforce`, a `kind`, the kind's inputs, and an `expect` block:

| Kind | Inputs | Expectations |
|------|--------|--------------|
| `http` | `request` (`method`, `path`, `headers`, `body`) | `status`, `status_in`, `header_present`, `header_absent`, `header_matches`, `body_contains`, `body_not_contains` |
| `rate_limit` | `request`, `burst` (1 to 50), `window_sec` | `throttled_within`, `retry_after_header` |
| `size_limit` | `request`, `size_bytes`, `field` | `rejected`, `status_in` |
| `source` | `include`, `exclude` globs, `pattern` or `require` | `matches`, `every_file_matches` |
| `command` | `run` (through `sh -c` in the source path), `timeout_sec` | `exit_code`, `stdout_equals`, `stdout_matches` |

`${VAR}` in request fields, bodies, commands, and expectation strings is
read from the environment at run time; an unset or empty variable makes
that invariant `error`, never pass or fail, and no request or command is
sent. A value substituted into a regex expectation is matched literally.
The report echoes the expectation with the `${VAR}` reference, so a
substituted secret never reaches it.

`invariants validate` checks the schema, unique ids, the fields each kind
requires and forbids, their ranges (a burst of 1 to 50, a size up to the
verify cap, a window and a timeout in bounds), regexes, and that `surface`
names an id in the map when one exists; its codes are
`invariant_yaml_invalid`, `invariant_id_invalid`, `invariant_id_duplicate`,
`invariant_title_missing`, `invariant_kind_invalid`,
`invariant_origin_invalid`, `invariant_field_missing`,
`invariant_field_foreign`, `invariant_field_invalid`,
`invariant_burst_out_of_range`, `invariant_expect_missing`,
`invariant_expect_foreign`, `invariant_expect_invalid`,
`invariant_regex_invalid`, and `invariant_surface_unknown`. `invariants run` validates first, sends
every HTTP-kind request through the same scope check as the verify
commands (and the workspace-approved scope when a workspace exists),
writes no ledger, and prints a report: `target`, `source_path`,
`guarded`, per invariant `id`, `title`, `kind`, `enforce`, `origin`,
`surface`, `result` (`pass`, `fail`, or `error`), `message`, `measured`
(per kind: the status, the named headers, and body length; the first
throttled request, throttled count, and status codes; the status for the
size and `connection_closed` when the server closed the connection before
consuming the body; files scanned, matches, and redacted samples; exit code and
truncated, redacted output), `expect`, and `duration_ms`, with a `summary`
of `total`, `pass`, `fail`, `error`, `enforced_fail`, `unenforced_fail`,
and `unenforced_pass`. A `rate_limit` invariant counts a 429 or a 503 as
throttled, as the verify family does. Exit 0 when no enforced invariant
failed and nothing errored, else 1. A pass means the declared expectation
held when it ran; the runner says nothing else.

When an assessment workspace is active, a `command` invariant's shell
string goes through the same classifier as the plugin's guard before it
runs: a raw network tool or inline-code interpreter in it makes the
invariant `error` instead of running, and the report's `guarded` is true.
In CI, with no workspace, commands run as written.

## Hook

The two commands behind the plugin's hooks (`hooks/hooks.json`). Each reads
the Claude Code hook JSON on stdin and exits 0; the decision is in the
output, so a missing binary is the only thing that blocks, and the shell
wrapper reports that itself.

```bash
ensphere hook pre-tool-use                      # PreToolUse for Bash
ensphere hook session-start --plugin-version 0.2.0
```

`hook pre-tool-use` has no opinion unless an assessment workspace exists
for the hook's `cwd` (discovered as above) and `ENSPHERE_GUARD` is not
`off`. With a workspace it splits the Bash command into simple commands,
following pipes, `&&`, `;`, `$(...)`, backticks, and `sh -c` strings, and
strips `sudo`, `env`, `timeout`, and similar wrappers before classifying
each command word. It prints a `deny` decision when any simple command is a
raw network tool (`curl`, `wget`, `nc`, `ssh`, `nmap`, and the rest of a
fixed list in `cli/internal/guard`), an interpreter running inline code
(`python -c`, `node -e`, a shell or interpreter fed by a pipe or here-doc,
and similar), or a construct it cannot follow (`eval`, `xargs`, `source`, a
command word that is a variable, an unterminated quote). Commands run by
`find -exec` are classified like any other. The scanner does not read
scripts from disk or follow programs that run other programs (`make`, npm
scripts); those fall through to the normal permission flow, and the
container boundary in `docs/release-pipeline.md` is the layer that holds
when a script reaches the network. It prints an `allow`
decision when every simple command is `ensphere` or the whole line equals
a command the operator wrote under `## Sandbox` in `config.md`. Otherwise
it prints nothing and the harness's normal permission flow applies. The
deny reason names the command and the way forward: the CLI for requests,
`evidence log` for observations, the `## Sandbox` section for an approved
command, or `ENSPHERE_GUARD=off`.

`hook session-start` prints, when a workspace exists, the workspace path,
the contents of `next-action.md`, the session states from `progress.md`,
and whether the binary's version matches the plugin's. The harness adds
the text to the session's context.

## Verify

All verify commands require `--in-scope`. Output is measurement-only JSON. No
verify command emits CLI-owned vulnerability status, confidence, or
exploitability.

Every verify family shares these flags (registered centrally in
`cli/cmd/helpers.go`):

```text
--in-scope   In-scope patterns: globs (*.example.com) or CIDR (10.0.0.0/8) (required)
--max-risk   Maximum risk level 1-5 (default 3)
--throttle   Milliseconds between probes (default 500)
--timeout    HTTP request timeout in seconds (default 10)
--header     Custom header key:value, repeatable
--evidence   Evidence JSONL path (default ./evidence.jsonl)
```

A malformed `--header` value (not `key:value`) is a usage error (exit 2).

Representative commands:

```bash
ensphere verify sqli --url "https://target/search?id=1" --param id --db postgres --technique blind_time --in-scope target
ensphere verify xss --url "https://target/search" --param q --payload "<script>alert(1)</script>" --in-scope target
ensphere verify idor --url "https://target/api/items/{id}" --id "victim-id" --token "attacker-token" --owner-token "owner-token" --in-scope target
ensphere verify ssrf --url "https://target/fetch" --param url --callback-url "https://callback.example" --in-scope target
ensphere verify auth --url "https://target/api/admin" --token "valid-token" --technique alg_none --in-scope target
ensphere verify authz --url "https://target/api/admin" --low-token "user-token" --high-token "admin-token" --in-scope target
ensphere verify ratelimit --url "https://target/api/login" --method POST --burst-count 10 --window-sec 10 --in-scope target
ensphere verify request --url "https://target/api/orders/42/refund" --method POST --result control --note "nonexistent order" --in-scope target
```

Supported probe families:

```text
request,
auth, authz, cachepoisoning, clickjacking, cmdi, cors, csrf,
csvinjection, fileupload, graphql, grpc, headerinjection, idor,
jwt, ldap, lfi, limits, massassignment, nosql, propertyauthz,
protopollution, race, ratelimit, redirect, rls, sqli, ssrf, ssti,
websocket, xpath, xss, xxe
```

Two kinds of family exist. **Primitives** do something that is fiddly or
error-prone to reproduce by hand: `request` (any shape, labelled with its
role), `race` (a start barrier), `ratelimit` (a bounded burst with header
capture), `limits`, `rls`, the interleaved timing families (`sqli
blind_time`, `cmdi`, `nosql where_time`), and the transport families.
**Presets** send a fixed request shape that `verify request` could send
equally well (`cors`, `clickjacking`, `redirect`, `headerinjection`,
`csrf`, and similar); they exist for convenience and are frozen. Do not add
a family whose request shape `verify request` can already send; write a
recipe in the methodology instead.

Every HTTP-based family accepts `--url`; most also accept `--method` (and
`--param` where a single parameter is targeted). Beyond the shared probe flags
and those common ones, each family's distinctive flags are:

| Family | Distinctive flags |
|--------|-------------------|
| `request` | `--body`, `--result` (required), `--note`, `--risk`, `--follow-redirects` |
| `auth` | `--token`, `--technique` |
| `authz` | `--low-token`, `--high-token` |
| `cachepoisoning` | `--technique` |
| `clickjacking` | (url, method only) |
| `cmdi` | `--param`, `--os` (default linux) |
| `cors` | (url, method only) |
| `csrf` | `--token` |
| `csvinjection` | `--submit-url`, `--export-url`, `--param` |
| `fileupload` | `--field`, `--filename`, `--content`, `--mime-type`, `--verify-url`, `--technique` |
| `graphql` | `--technique`, `--token` |
| `grpc` | `--technique`, `--tls-verify` |
| `headerinjection` | `--param` |
| `idor` | `--id`, `--token`, `--owner-token` |
| `jwt` | `--token`, `--technique` |
| `ldap` | `--param`, `--technique` |
| `lfi` | `--param`, `--os` (default linux) |
| `limits` | `--technique`, `--body`, `--param`, `--values`, `--sizes`, `--field`, `--token` |
| `massassignment` | `--body`, `--watch-fields`, `--token` |
| `nosql` | `--param`, `--technique` |
| `propertyauthz` | `--high-token`, `--low-token`, `--watch-fields` |
| `protopollution` | `--technique` |
| `race` | `--body`, `--token`, `--concurrency` |
| `ratelimit` | `--body`, `--token`, `--second-token`, `--burst-count`, `--window-sec` |
| `redirect` | `--param` |
| `rls` | `--project-url`, `--anon-key`, `--jwt-secret`, `--table`, `--tenant-a`, `--tenant-b`, `--select` (no `--url`/`--method`) |
| `sqli` | `--param`, `--db` (default postgres), `--technique`, `--string-boundary` |
| `ssrf` | `--param`, `--callback-url` |
| `ssti` | `--param`, `--engine` (default auto) |
| `websocket` | `--technique`, `--payload`, `--tls-verify` |
| `xpath` | `--param`, `--technique` |
| `xss` | `--param`, `--payload` |
| `xxe` | `--technique` |

### request

```bash
ensphere verify request --url "http://localhost:3000/api/orders/42/refund" --method POST \
  --header "Authorization: Bearer [TENANT_A_USER]" --result baseline --note "legitimate refund" --in-scope localhost
ensphere verify request --url "http://localhost:3000/api/orders/42/refund" --method POST \
  --header "Authorization: Bearer [TENANT_A_USER]" --result probe --note "second refund of the same order" --in-scope localhost
ensphere verify request --url "http://localhost:3000/api/orders/99999/refund" --method POST \
  --header "Authorization: Bearer [TENANT_A_USER]" --result control --note "nonexistent order" --in-scope localhost
```

Vuln type `request`, technique `scoped_request`. Sends one request the
analyst constructs and records it in the ledger with the role the analyst
declares. `--result` is required and must be `baseline`, `probe`, or
`control`; the report gate uses those stages to check that every probed
coverage row also cites a baseline and a control. `--method` is one of
GET, HEAD, POST, PUT, PATCH, DELETE, or OPTIONS. `--body` is limited to
256 KiB; larger bodies belong to `verify limits`. `--risk` (1 to 5,
default 3) is the analyst's declared payload risk and is checked against
`--max-risk` like any family's fixed risk. Redirects are not followed unless
`--follow-redirects` is set, and every hop is scope-checked. `--note` is
stored, redacted, in the ledger entry.

Output `request_measurements` carries `method`, `url`, `result`,
`declared_risk`, `request_body_bytes`, `request_hash`,
`redirects_followed`, one `round` (status, elapsed, body hash and length,
and the response headers lowercased with `set-cookie`, `authorization`,
and `www-authenticate` values replaced by `[REDACTED]`), a bounded redacted
`response_snippet`, and `evidence_id`, the ledger entry written for this
request, so the coverage row can cite it directly. The ledger entry carries
the request hash (of method, URL, and body) and the response hash.

### Injection and template families

`verify sqli` selects DB-specific payloads. `--db` (default `postgres`)
chooses the engine, `--technique` the family (e.g. `blind_time`,
`blind_boolean`), `--param` the parameter, and `--string-boundary` the quoting
context. `verify ssti` takes `--engine` (default `auto`). `verify cmdi` and
`verify lfi` take `--os` (default `linux`). `verify xss` sends an explicit
`--payload`. `verify nosql`, `verify ldap`, and `verify xpath` take a
`--technique` and `--param`.

`verify xxe` accepts only the techniques `file_read` and `ssrf`. There is no
`oob` technique. For out-of-band XXE, run the `ensphere callback` listener,
point the external entity at its URL, and read the recorded callback hits from
the evidence ledger — see [Callback](#callback).

### idor

```bash
ensphere verify idor --url "https://target/api/items/{id}" --id victim-id \
  --token attacker-token --owner-token owner-token --in-scope target
```

Technique `idor_uuid`. The `{id}` placeholder in `--url` is replaced with
`--id`. `--token` is the attacker's bearer token and is always sent.
`--owner-token` is optional: when supplied, the probe first runs a baseline
round with the owner's token (the control that separates "the object exists and
the owner can read it" from "the attacker's token was accepted"). Output
`idor_measurements` carries `probe_round`, an `owner_round` (present only with
`--owner-token`), `hashes_match` and `status_match` (set only when comparing
against an owner round), `resource_id`, and a bounded `response_snippet`.

### Authorization differential (authz, rls, propertyauthz)

`verify authz` emits technique `role_differential` and compares a `--low-token`
response against a `--high-token` response for the same request.
`verify propertyauthz` also emits `role_differential` (vuln type
`property_authz`) and diffs `--watch-fields` between low- and high-privilege
responses. `verify rls` emits technique `rls_isolation`: it authenticates two
tenants (`--tenant-a`, `--tenant-b`) against a Supabase-style endpoint
(`--project-url`, `--anon-key`, `--jwt-secret`, `--table`, `--select`) and
compares the row sets each tenant can read. The technique for each of these
probes is fixed by the command; there is no `--technique` flag.

`verify auth` accepts the techniques `no_token`, `expired_token`, `alg_none`,
and `method_override`. (`auth_control` is not a verify technique — it is a
payload technique in the `auth_bypass` payload set, available through
`ensphere payloads auth_bypass`.)

### protopollution

```bash
ensphere verify protopollution --url "https://target/api/profile" --method POST --technique json_merge --in-scope target
```

Techniques `proto_assignment`, `constructor_pollution`, and `json_merge`. The
probe runs a baseline request, an injection request carrying a marker
(`polluted: ensphere_pp_test`), and a verification request. Output
`proto_pollution_measurements` includes `technique`, the three probe rounds,
`hashes_match`, `payload_used`, `response_snippet`, and `marker_reflected` —
`marker_reflected` is a raw measurement (the post-injection body contains both
the marker key and value), not a judgment that pollution succeeded.

### limits

```bash
ensphere verify limits --url "https://target/api/items" --technique pagination --param limit --values 10,100,1000 --in-scope target
ensphere verify limits --url "https://target/api/upload" --technique upload_size --sizes 1048576,10485760 --field file --in-scope target
ensphere verify limits --url "https://target/api/export" --technique response_size --in-scope target
```

Risk 2. `--technique` is one of:

- `pagination` — requires `--param` and `--values` (1-10 non-negative ints).
  Each value is sent as the parameter (as a JSON body field when `--method` is
  non-GET and `--body` is JSON, otherwise as a query parameter). Each round
  records `value`, `status_code`, `elapsed_ms`, `body_bytes`, `body_hash`,
  `item_count` (array length of the response or its first array field, when
  determinable), and `content_length`.
- `upload_size` — requires `--sizes` (1-5 ints, each at most 100 MB). `--field`
  (default `file`) is the multipart field; the method is forced to POST. Each
  round streams that many random bytes with the body's exact `Content-Length`
  and `Expect: 100-continue`, as a large real upload does, so a server that
  caps on the headers can refuse before any body is sent; it records
  `size_bytes`, `status_code`, `elapsed_ms`, `body_hash`, and
  `response_bytes`. A server that closes the connection before consuming the
  body is recorded, not an error: `connection_closed` is true, with the
  `status_code` it sent first or 0 when it sent none.
- `response_size` — a single request (honoring `--method` and `--body`) that
  records `body_bytes`, `content_length_header`, `content_encoding`,
  `elapsed_ms`, and `body_hash`.

`--token` sends an `Authorization: Bearer` header. Output
`limits_measurements` carries `technique` plus the `pagination`, `upload`, or
`response` rounds for the chosen technique.

### ratelimit

```bash
ensphere verify ratelimit --url "https://target/api/login" --method POST \
  --burst-count 10 --window-sec 10 --token user-a --second-token user-b --in-scope target
```

Risk 2. Vuln type `rate_limit`, technique `rate_limit_burst`. `--burst-count`
is **required** and must be a positive, operator-approved value; there is no
default burst. `--window-sec` (default 10) bounds each burst with a deadline.
Each round captures a rate-limit-relevant header allowlist (lowercased):
`retry-after`, `cf-ray`, `cf-cache-status`, `server`, `x-vercel-id`,
`x-served-by`, `via`, and any header prefixed `ratelimit-` or `x-ratelimit-`.
Throttling is counted on HTTP 429 and 503.

`--second-token` runs a second, separately-identified burst: after the first
burst the probe waits `--window-sec` seconds, then repeats the burst with the
second token. Output `rate_limit_measurements` has `identity_a` and, when a
second token is given, `identity_b`. Each identity records `burst_count`,
`window_sec`, `success_count`, `throttled_count`, `first_throttle_at`,
`status_codes`, per-round detail (`status_code`, `elapsed_ms`, `body_hash`,
`body_length`, `headers`), and `min_ms`/`max_ms`/`avg_ms`.

### fileupload

```bash
ensphere verify fileupload --url "https://target/api/upload" --technique extension_bypass --verify-url "https://target/uploads/" --in-scope target
```

All constructions use inert content (`ensphere_upload_test`). `--technique`
selects what is built:

| Technique | Risk | Construction | Sent as |
|-----------|------|--------------|---------|
| `extension_bypass` | 3 | `double_extension` | filename `name.jpg.<ext>`, MIME `image/jpeg` |
| `mime_bypass` | 3 | `nonimage_bytes_image_content_type` | benign text bytes, MIME `image/png` |
| `content_type_mismatch` | 3 | `image_bytes_html_content_type` | `GIF89a` bytes, MIME `text/html` |
| `polyglot_file` | 4 | `gif89a_polyglot` | `GIF89a` + benign text, filename `name.gif`, MIME `image/gif` |
| `zip_path_traversal` | 4 | `zip_slip` | in-memory zip with entry `../ensphere-zip-slip.txt`, MIME `application/zip` |

`--field` (default `file`) is the multipart field; `--filename`, `--content`,
and `--mime-type` override the defaults. `--verify-url` (optional,
scope-checked) is fetched after the upload to observe whether the file is
retrievable. Output `file_upload_measurements` records `technique`,
`construction`, `upload_probe`, `filename_in_response`, `upload_accepted`, an
optional `verify_probe`/`verify_accessible`, and the `filename_sent`,
`mime_type_sent`, and `content_sent` values.

### Transport families (grpc, websocket)

`verify grpc` accepts techniques `grpc_reflection` and `grpc_plaintext`.
`verify websocket` accepts `ws_injection`, `ws_hijack`, and `ws_origin_check`
and sends a `--payload`. Both expose `--tls-verify` (default `true`): passing
`--tls-verify=false` disables server-certificate verification for the handshake
(for internal-CA endpoints or plaintext/protocol probing).

## Evidence

Write, query, and verify hash-chained JSONL evidence.

```bash
ensphere evidence log \
  --probe-type sqli \
  --technique blind_time \
  --url "https://target/api" \
  --result manual_note \
  --session 2

ensphere evidence query --file ./evidence.jsonl --summary
ensphere evidence query --file ./evidence.jsonl --result probe --limit 10
ensphere evidence verify --file ./evidence.jsonl
```

Flags for `evidence log` (`--probe-type`, `--technique`, `--url`, and
`--result` are required):

```text
--file          Evidence file path (default ./evidence.jsonl)
--id            Optional explicit evidence ID; omitted entries receive EVID-XXX automatically
--probe-type    Probe type (required)
--technique     Technique used (required)
--url           Target URL (required)
--param         Parameter name
--result        Factual result stage: baseline, probe, payload, control, callback, manual_note (required)
--notes         Additional notes
--status-code   HTTP status code
--duration      Probe duration
--session       Session number
--finding-ref   Finding reference, e.g. VULN-001
--screenshot    Screenshot file path
```

Flags for `evidence query`:

```text
--file          Evidence file path (default ./evidence.jsonl)
--id            Filter by evidence ID
--result        Filter by result stage
--probe-type    Filter by probe type
--finding-ref   Filter by finding reference
--after         Include entries at or after this timestamp
--before        Include entries at or before this timestamp
--limit         Maximum entries to return
--summary       Emit counts by result stage and probe type instead of rows
```

`evidence verify` takes `--file` and recomputes the hash chain.

The writer assigns stable `EVID-XXX` IDs at write time, rejects missing,
malformed, or duplicate IDs when continuing a ledger, serializes concurrent
writers with a lock file, redacts supported secret forms, and records
`prev_hash` and `hash` on every row so `evidence verify` can detect a
ledger that was edited or truncated after the fact. The chain is an
integrity check on the file, not a proof of what was measured: the operator
runs the measurements and signs the statement. Finding judgments belong in
reports and registries, never in evidence rows. The `result` field is a
factual stage only:

```text
baseline, probe, payload, control, callback, manual_note
```

The report gate reads these stages: a `tested` coverage row that cites a
`probe`, `payload`, or `callback` entry must also cite a `baseline` and a
`control`. Verify families write `baseline` and `probe` entries themselves;
record a control with `verify request --result control` or `evidence log
--result control`.

## Scan

Scan source code for regex-based sink candidates.

```bash
ensphere scan ./src
ensphere scan ./src --category sqli,xss
ensphere scan ./src --category expensive_operation,rate_limiter
ensphere scan ./src --exclude "test/**"
ensphere scan ./src --context-lines 0
ensphere scan ./src --exit-zero
ensphere scan ./src --absence-check --category rate_limiter
```

Flags:

```text
--category       Restrict to sink categories (comma-separated or repeatable)
--extensions     File extensions to scan (overrides defaults)
--exclude        Glob patterns to skip (repeatable)
--exit-zero      Exit 0 even when matches are found
--absence-check  Report categories with no matches (for control-presence checks)
--context-lines  Lines of surrounding context per match (default bounded, redacted)
```

Scan output includes `analysis_depth: "pattern_match"`. Matches are review
leads, not confirmed vulnerabilities. Context is bounded and redacted by
default.

Two categories support resource-exhaustion review rather than classic
injection sinks. `expensive_operation` matches costly per-request work (image
transforms, headless browsers, PDF/media generation, LLM/email/SMS SDKs,
storage writes, raw queries) — a match is a lead to check whether a limiter,
quota, or size cap guards the caller. `rate_limiter` matches existing limiter
libraries and middleware (for example `express-rate-limit`,
`rate-limiter-flexible`, `@upstash/ratelimit`, `golang.org/x/time/rate`,
Laravel `throttle:`, `django-ratelimit`) — a match documents an existing
control, not a weakness, and pairs with `--absence-check` to flag its absence.

## OpenAPI

Parse OpenAPI or Swagger specifications into endpoint inventory.

```bash
ensphere openapi --file ./openapi.yaml
ensphere openapi --url "https://target/api/docs/openapi.json"
```

`--file` or `--url` selects the source; `--timeout` bounds a URL fetch.

## Callback

Run an out-of-band callback listener for blind SSRF, XXE, and similar probes.
Start the listener, aim the target's external request (an XXE entity, an SSRF
fetch) at the reachable `--external-url`, and the server records each hit into
the evidence ledger.

```bash
ensphere callback --port 8888 --wait 30 --external-url "https://callback.example" --evidence ./evidence.jsonl
```

Flags: `--port`, `--wait` (seconds to listen), `--external-url` (the address to
hand to the target), and `--evidence` (ledger path).

## Cloud

Read cloud configuration facts through the provider CLI (`aws`, `gcloud`, `az`). Every command requires `--provider` and `--in-scope`. Subcommands are `compute`, `iam`, `network`, `logging`, `secrets`, and `storage`.

```bash
ensphere cloud storage --provider aws --bucket my-bucket --in-scope "aws://123456789012"
ensphere cloud iam --provider aws --principal arn:aws:iam::123:user/alice --in-scope "aws://123456789012"
ensphere cloud network --provider aws --vpc-id vpc-abc123 --in-scope "aws://123456789012"
ensphere cloud compute --provider aws --in-scope "aws://123456789012"
ensphere cloud logging --provider aws --in-scope "aws://123456789012"
ensphere cloud secrets --provider aws --in-scope "aws://123456789012"
```

Every cloud command also accepts `--max-risk`, `--timeout`, and `--evidence`;
individual commands add resource selectors (`--bucket`, `--region`,
`--account-name`, `--principal`, `--vpc-id`). Output records the provider's
settings as returned; it does not label exposure or risk.

## CVSS

Calculate a CVSS 4.0 score from explicitly supplied metrics.

```bash
ensphere cvss --av N --ac L --at N --pr N --ui N --vc H --vi H --va H --sc H --si H --sa H
```

CVSS severity is deterministic from supplied metrics. It is not inferred by Ensphere.

## Sinks

List sink categories and embedded regex patterns.

```bash
ensphere sinks
ensphere sinks sqli
ensphere sinks expensive_operation
```

## Compliance

Map vulnerability types to compliance frameworks.

```bash
ensphere compliance --list
ensphere compliance sqli
```

Supported frameworks include OWASP Top 10 2025, OWASP API Security Top 10 2023, PCI-DSS v4.0.1, SOC 2, and ISO 27001.
