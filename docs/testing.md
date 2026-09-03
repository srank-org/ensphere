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

## Generated Artifacts

Payload seeds are embedded directly as YAML. `make copy-seeds` (run automatically by `make build`) mirrors `assets/seeds/*.yaml` into `cli/internal/payloads/data/`, which is the copy `go:embed` reads at compile time — Go embed cannot reach files outside the module, so the copy is the only generated artifact. `make verify-generated` re-runs the copy, confirms the copied seeds are tracked, and checks for Git drift in `cli/internal/payloads/data/`. The seed YAML is parsed once on first use, applying each file's `defaults` block and validating every enum value against `cli/internal/enums`. Checklists are Markdown under `skills/checklists/` and are not embedded in the binary.

Golden fixtures in `cli/internal/payloads/testdata/` capture a representative `ensphere payloads` query per vulnerability type; a test asserts the YAML store reproduces each byte-for-byte. If payload counts change, update the canary tests and docs together.

## Local Artifacts

Expected local artifacts from builds and smoke runs include `bin/`, `cli/ensphere`, `cli/.gocache/`, `evidence.jsonl`, `evidence.jsonl.lock`, and `ensphere-pentest/`. These are ignored. The embedded seed copy under `cli/internal/payloads/data/` is tracked and visible to Git and CI.

## JSON Contracts

CLI JSON tests assert current parsed semantics rather than pretty formatting.
Verify outputs must remain measurement-only and must not add exact JSON fields
named `status`, `confidence`, `confirmed`, `safe`, or `potential`.

Runner YAML inputs use strict field decoding. Tests cover the current plan,
recon profile, finding registry, coverage file, statement, and report-gate
contracts directly.

## Test File Inventory

| File | Package | Purpose |
|------|---------|---------|
| `cmd/helpers_test.go` | cmd | Command helper behavior: header parsing and verify exit-code mapping |
| `cmd/subprocess_test.go` | cmd | Subprocess CLI contract tests for help, JSON output, evidence, scope failure, and malformed headers |
| `cmd/run_test.go` | cmd | Runner CLI lifecycle: init, environment flag validation, assessor and operator recording, status, next, plan drafting, the report gate, and the statement refusal exit code |
| `runner/workspace_test.go` | runner | Workspace, planning, environment tier and chains drafting, source-only coverage, report contracts, and evidence/citation gates |
| `runner/statement_test.go` | runner | Coverage file validation codes, statement generation, stable inputs digest, and stale or edited statement detection |
| `verify/helpers_test.go` | verify | Shared test utilities (newTestServer, baseProbeConfig, assertScopeErr, handler factories) |
| `verify/probe_test.go` | verify | Core infrastructure (CheckScope, CheckMaxRisk, HTTPProbe) |
| `verify/sqli_test.go` | verify | SQLi DB engine normalization and DB-specific payload selection |
| `verify/contracts_test.go` | verify | Safety gate contracts for all 32 probes (scope, max-risk, technique validation, forbidden judgment JSON tags) |
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
