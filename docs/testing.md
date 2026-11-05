# Ensphere Test Reference

## Commands

```bash
make test                                          # go vet + go test ./...
make smoke                                         # build + basic CLI command checks
make verify-generated                              # re-sync the embedded seed copy and fail on drift
cd cli && go test -short ./...                     # fast: contracts + core + evidence + payloads
cd cli && go test ./...                            # full: everything including integration
cd cli && go test -race ./internal/verify/         # race detector on verify package
cd cli && go test -race -short ./internal/verify/  # race detector, fast path only
```

## CI Gates

GitHub Actions runs on every push and on pull requests. The workflow uses `go-version-file: cli/go.mod`, so CI fails clearly if the declared Go toolchain is unavailable. The required gates are:

- `cd cli && go vet ./...`
- `cd cli && go test ./...`
- `cd cli && go test -race -short ./internal/verify/`
- `make smoke`
- `make verify-generated`
- `claude plugin validate .` in a second job, for the plugin and marketplace manifests, the hooks file, and the agent. It is not run with `--strict` because the validator warns that a plugin does not load the repository's CLAUDE.md, which is expected.

## Generated Artifacts

Payload seeds are embedded directly as YAML. `make copy-seeds` (run automatically by `make build`) mirrors `assets/seeds/*.yaml` into `cli/internal/payloads/data/`, which is the copy `go:embed` reads at compile time — Go embed cannot reach files outside the module, so the copy is the only generated artifact. `make verify-generated` re-runs the copy, confirms the copied seeds are tracked, and checks for Git drift in `cli/internal/payloads/data/`. The seed YAML is parsed once on first use, applying each file's `defaults` block and validating every enum value against `cli/internal/enums`. Checklists are Markdown under `skills/ensphere/checklists/` and are not embedded in the binary.

Golden fixtures in `cli/internal/payloads/testdata/` capture a representative `ensphere payloads` query per vulnerability type; a test asserts the YAML store reproduces each byte-for-byte. If payload counts change, update the canary tests and docs together.

## Local Artifacts

Expected local artifacts from builds and smoke runs include `bin/`, `cli/ensphere`, `cli/.gocache/`, `evidence.jsonl`, `evidence.jsonl.lock`, and `ensphere-pentest/`. These are ignored. The embedded seed copy under `cli/internal/payloads/data/` is tracked and visible to Git and CI.

## JSON Contracts

CLI JSON tests assert current parsed semantics rather than pretty formatting.
Verify outputs must remain measurement-only and must not add exact JSON fields
named `status`, `confidence`, `confirmed`, `safe`, or `potential`.

Runner YAML inputs use strict field decoding. Tests cover the current plan,
recon profile, finding registry, coverage file, statement, report-gate,
diff, and SARIF contracts directly.

## Test File Inventory

| File | Package | Purpose |
|------|---------|---------|
| `cmd/helpers_test.go` | cmd | Command helper behavior: header parsing and verify exit-code mapping |
| `cmd/subprocess_test.go` | cmd | Subprocess CLI contract tests for help, JSON output, evidence, scope failure, and malformed headers |
| `cmd/invariants_test.go` | cmd | Subprocess cases for invariants validate (valid, invalid, missing directory, surfaces from the map) and run (happy path and `--out`, enforced failure exit, `--only`, usage exits) |
| `cmd/map_test.go` | cmd | Subprocess cases for map validate (valid, invalid, unreadable) and map changed in a temporary git repository |
| `cmd/run_test.go` | cmd | Runner CLI lifecycle: init, scope list validation and default, environment flag validation, assessor and operator recording, status, next, plan drafting, the report gate, the statement refusal exit code, run diff, run sarif, and the hook commands |
| `runner/workspace_test.go` | runner | Workspace, planning, environment tier and chains drafting, source-only drafting, report contracts, the three progress states, which sessions may omit coverage.yaml, and evidence/citation gates |
| `runner/statement_test.go` | runner | Coverage file validation codes, the baseline/probe/control citation rule, statement generation in YAML, Markdown, and JSON, stable inputs digest, and stale, edited, or missing-JSON statement detection |
| `guard/guard_test.go` | guard | Hook guard classification: allow for ensphere and approved sandbox commands, deny for raw network tools, inline-code interpreters, wrappers, substitutions, and constructs the scanner cannot follow, no opinion otherwise |
| `sysmap/sysmap_test.go` | sysmap | System map: vocabulary, every validation code, strict decoding, the git change set against a temporary repository (changed, unmapped, missing files, sessions affected), git failures |
| `runner/sysmap_test.go` | runner | Gate checks on coverage `surface_id` against the map and map errors, delta since recorded by init, delta drafting (skips, unmapped files keep a full draft, missing map records a reason), the statement's delta line |
| `invariants/load_test.go` | invariants | Loading and validation: one invariant per kind accepted, parse failures as issues, every validation code, duplicate ids across files, surface checks against the map, glob matching |
| `invariants/run_test.go` | invariants | Running: http status, header, and body expectations, no redirect following, scope failure without a request, environment substitution and unset variables, rate-limit throttling with Retry-After, size caps, source pattern and require with excludes and the workspace skipped, command outcomes and timeout, the guard on command invariants inside a workspace, `--only`, summary counts, the exit rule, no forbidden words |
| `runner/diff_test.go` | runner | Workspace comparison: finding matching by title and by location with line drift, new, gone, changed, reopened, and resolved counts, coverage row changes, statement comparison, deterministic output |
| `runner/sarif_test.go` | runner | SARIF export: rule ids, severity-to-level translation, physical and logical locations, registry fallback location, fingerprint stability, excluded statuses, deterministic output |
| `verify/helpers_test.go` | verify | Shared test utilities (newTestServer, baseProbeConfig, assertScopeErr, handler factories) |
| `verify/probe_test.go` | verify | Core infrastructure (CheckScope, CheckMaxRisk, HTTPProbe) |
| `verify/sqli_test.go` | verify | SQLi DB engine normalization and DB-specific payload selection |
| `verify/contracts_test.go` | verify | Safety gate contracts for all 33 probes (scope, max-risk, technique validation, forbidden judgment JSON tags) |
| `verify/request_test.go` | verify | Scoped request: stage and hashes recorded in the ledger, redirect handling, role/method/body/risk validation |
| `verify/integration_injection_test.go` | verify | Integration: sqli, xss, cmdi, lfi, ssti, xxe, nosql, csvinjection, ldap, xpath, fileupload |
| `verify/integration_auth_test.go` | verify | Integration: auth, authz, rls, jwt, cors, csrf, idor, massassignment, countJSONRows |
| `verify/integration_infra_test.go` | verify | Integration: ssrf, redirect, protopollution, graphql, cachepoisoning |
| `verify/limits_test.go` | verify | Integration: pagination, upload-size (with cap rejection), response-size measurements, scope and technique validation |
| `verify/race_test.go` | verify | Race: concurrent burst verification |
| `verify/websocket_test.go` | verify | WebSocket: computeWSAccept, generateWSKey, parseHTTPStatus |
| `verify/grpc_test.go` | verify | gRPC: extractServiceNames, isPrintable |
| `verify/integration_websocket_test.go` | verify | Integration: WebSocket upgrade, origin check, hijack, malformed-101 rejection |
| `verify/integration_grpc_test.go` | verify | Integration: gRPC plaintext detection, reflection probe |
| `verify/ratelimit_test.go` | verify | Integration: sequential burst, no throttling, window expiry |
| `verify/propertyauthz_test.go` | verify | Integration: field difference, identical responses, watch fields, non-JSON |
| `evidence/evidence_test.go` | evidence | Hash chain integrity, redaction, write-time IDs, lock contention, duplicate IDs, read/write/filter, NextID, malformed line handling |
| `payloads/store_test.go` | payloads | Docs canaries (payload count + vuln type set), embedded-seed enum validation, and invalid-enum/invalid-risk/duplicate-id load errors |
| `payloads/golden_test.go` | payloads | Golden reproduction: the YAML store's query output matches the captured per-vuln-type fixtures byte-for-byte |
| `scan/scanner_test.go` | scan | Regex pattern-match scanner: matches, no matches, excludes, absence rules, extension overrides, sorting, redaction |
| `sinks/query_test.go` | sinks | Embedded sink loader, invalid category, and regex compile validation |
| `compliance/query_test.go` | compliance | Mapping list, valid lookup, invalid vuln type, no-mapping behavior |
| `cvss/v40_test.go` | cvss | CVSS v4.0 scoring, macro-vector lookup, vector string, invalid inputs |
| `cloud/exec_test.go` | cloud | Provider CLI runner: installed check, exit codes, output capture |
| `cloud/storage_test.go` | cloud | AWS/GCP/Azure storage parse functions: ACL, encryption, versioning, logging |
| `cloud/iam_test.go` | cloud | IAM parse functions: attached and inline policies, MFA, last-used |
| `cloud/network_test.go` | cloud | Network parse functions: security groups, flow logs, public IPs, port ranges |
| `cloud/compute_test.go` | cloud | AWS/GCP/Azure compute parse functions |
| `cloud/logging_test.go` | cloud | CloudTrail/GCP sinks/Azure diagnostics parse functions |
| `cloud/secrets_test.go` | cloud | Secrets Manager/Secret Manager/Key Vault parse functions |
| `openapi/parser_test.go` | openapi | OpenAPI v3 JSON/YAML parsing, auth detection, parameter merge, HTTP error handling |
| `callback/server_test.go` | callback | OOB callback server: request recording, timeout, multiple callbacks, token uniqueness, body read error |

## Conventions

- Integration tests skip with `testing.Short()` - use `-short` for fast CI
- Assertions are **relational** (e.g., `PayloadAvgMs > BaselineAvgMs`), never exact values or message strings
- No `t.Parallel()` in timing-sensitive or raw-TCP tests
- Use `newTestServer(t, handler)` for all test HTTP servers (IPv4-only, auto-cleanup); never use `httptest.NewServer` directly
- Use `t.Cleanup()` for net.Listener, temp files
- Payload canary values in `payloads/store_test.go` (956 payloads, 25 vuln types) must be updated alongside docs when payloads change
