# Ensphere CLI Reference

This document is the full command reference for the `ensphere` Go CLI. Commands emit structured JSON where applicable and produce measurements, never security judgments. `ensphere <command> --help` is the source of truth for flags.

## Build and Install

```bash
make build        # build ./bin/ensphere
make install      # install binary to /usr/local/bin/ensphere
make install-all  # install binary and skill files
```

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
- The default maximum risk is 3. Each verify family carries a fixed risk;
  SQLi also selects payload records by risk. Risk 4 and 5 payloads never read
  credentials or execute code.
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
command. Subcommands are `init`, `status`, `next`, `plan`, `report`, and
`statement`.

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
```

Flags for `run init`:

```text
--workspace              Workspace directory, default ensphere-pentest (persistent flag on all run subcommands)
--target                 Base URL of the live target (a sandbox or staging); omit for a source-only assessment
--environment            sandbox, staging, or none; default sandbox when --target is given, none otherwise
--source-path            Path to the source tree under assessment, default "."
--target-type            auto (default), web_app, api_backend, static_site, mobile_client_remote_backend, mobile_client_offline, desktop_or_extension_client, cloud_only, library_or_cli
--cloud                  none (default), aws, gcp, azure, kubernetes, cloudflare, supabase, or comma-separated
--in-scope               In-scope boundary summary
--out-of-scope           Out-of-scope boundary summary
--login-url, --username, --password   Test identity for authenticated sessions
--approved-bursts        Operator-approved rate-limit bursts, e.g. "POST /api/otp: 10/10s"
--approved-upload-sizes  Operator-approved upload sizes in bytes for the size-limit probe
--assessed-by            Model or person performing the assessment, e.g. "Claude Fable 5.1 via Claude Code"
--operator               Person who authorizes the assessment and signs the statement
```

`--assessed-by` and `--operator` are recorded under an `Assessment` heading
in `config.md` and copied into the Statement of Assessment. Both may be
filled in later by editing `config.md`.

`run plan` accepts `--force` to overwrite an existing assessment plan from
config.

Source is always in scope; a live target is optional. Without `--target` the
draft plan carries `coverage_label: source_only` and `environment: none`;
`target.url` may be empty only when the coverage label is `source_only`,
`client_only`, or `cloud_only`. `sandbox` and `staging` require a URL. The
chains session drafts as `run` only when the recon target profile records
`environment: sandbox`; otherwise it drafts `blocked`.

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
only meaningful for a vulnerability. The gate blocks report readiness when
required session reports are missing, planned sessions are not terminal,
`assessment-plan.yaml` is missing or invalid, evidence hash-chain verification
fails, or the finding registry contains uncited findings, missing required
finding fields, invalid or duplicate finding ids, missing or invalid finding
kinds, invalid statuses (`confirmed`, `likely`, `informational`,
`not_supported`, `not_tested`), inconsistent evidence strength, missing CVSS v4
vectors for vulnerability findings, invalid confidence/severity/priority values,
invalid evidence categories, invalid coverage labels, missing or unsafe
transcript/artifact/cleanup paths, or an incomplete final report and evidence
appendix.

The gate also reads every session's `coverage.yaml` (Sessions 02 through
08.7; Recon and the plan carry none). A `DONE` session without the file is
an error. Each row needs an id of the form `COV-<session>-NNN`, a `surface`,
a `check`, and a `state` of `planned`, `tested`, `not_tested`, `blocked`, or
`not_applicable`. A `planned` row blocks the report. A `tested` row must cite
`evidence_ids` that exist in that session's `evidence.jsonl`; every other
resolved state needs a `reason`. `identity`, `transcripts`, `checklist`,
and `hypothesis` (the `HYP-NNN` recon hypothesis the row resolves) are
optional; the gate checks transcript paths and records the rest. The gate output carries a `coverage` block
with counts per session and in total, and `report-gate.md` renders the same
table. Those counts are the only source for the report's "checks executed"
and "not checked" numbers.

`run statement` derives `09-report/statement.yaml` and
`09-report/statement.md`, the one-page Statement of Assessment, from the
workspace alone: target, environment, source path, platforms, assessor and
operator from `config.md`; every session's plan decision, coverage label, and
progress state; the coverage counts above; finding counts by kind, status,
and severity with the unresolved findings listed; each ledger's entry count,
chain validity, and final hash; the earliest and latest evidence timestamps;
and the Ensphere version. Nothing is typed by the caller. The command exits 2
while the report gate has errors. It records a SHA-256 digest of its inputs
in both files; afterwards the gate reports `statement_stale` if any input
changes, `statement_edited` if `statement.md` no longer matches
`statement.yaml`, and `statement_markdown_missing` if the markdown is
deleted. Regenerate rather than edit. The markdown ends with the fixed
self-assessment sentence and a signature block for the operator.

Runner-generated state, plans, recon profiles, report artifacts, and finding
registries use one canonical schema. Unknown fields are rejected rather than
ignored.

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
```

Supported probe families:

```text
auth, authz, cachepoisoning, clickjacking, cmdi, cors, csrf,
csvinjection, fileupload, graphql, grpc, headerinjection, idor,
jwt, ldap, lfi, limits, massassignment, nosql, propertyauthz,
protopollution, race, ratelimit, redirect, rls, sqli, ssrf, ssti,
websocket, xpath, xss, xxe
```

Every HTTP-based family accepts `--url`; most also accept `--method` (and
`--param` where a single parameter is targeted). Beyond the shared probe flags
and those common ones, each family's distinctive flags are:

| Family | Distinctive flags |
|--------|-------------------|
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
  round streams that many random bytes and records `size_bytes`, `status_code`,
  `elapsed_ms`, `body_hash`, and `response_bytes`.
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
`prev_hash` and `hash` on every row so `evidence verify` can detect
tampering. Finding judgments belong in reports and registries, never in
evidence rows. The `result` field is a factual stage only:

```text
baseline, probe, payload, control, callback, manual_note
```

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
