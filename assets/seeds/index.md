# Payload Seed Index

Last updated: 2026-06-07

Payload seeds are YAML source files embedded into the `ensphere` binary. `make
build` mirrors these files into `cli/internal/payloads/data/` (the copy
`go:embed` reads, since embed cannot reach files outside the Go module) and the
payloads package parses them once on first use. Edit the sources here, never the
copy under `cli/internal/payloads/data/`.

| Category | Seed File |
|----------|-----------|
| Authentication bypass | [auth-bypass.yaml](auth-bypass.yaml) |
| Authorization | [authz.yaml](authz.yaml) |
| Cache poisoning | [cache-poisoning.yaml](cache-poisoning.yaml) |
| Command injection | [cmdi.yaml](cmdi.yaml) |
| CORS | [cors.yaml](cors.yaml) |
| CSRF | [csrf.yaml](csrf.yaml) |
| CSV injection | [csv-injection.yaml](csv-injection.yaml) |
| File upload | [file-upload.yaml](file-upload.yaml) |
| GraphQL | [graphql.yaml](graphql.yaml) |
| Header injection | [header-injection.yaml](header-injection.yaml) |
| IDOR/BOLA | [idor-bola.yaml](idor-bola.yaml) |
| JWT | [jwt.yaml](jwt.yaml) |
| LDAP injection | [ldap.yaml](ldap.yaml) |
| LFI | [lfi.yaml](lfi.yaml) |
| Mass assignment | [mass-assignment.yaml](mass-assignment.yaml) |
| NoSQL injection | [nosql.yaml](nosql.yaml) |
| Prototype pollution | [prototype-pollution.yaml](prototype-pollution.yaml) |
| Race condition | [race-condition.yaml](race-condition.yaml) |
| Redirect | [redirect.yaml](redirect.yaml) |
| SQLi MSSQL | [sqli-mssql.yaml](sqli-mssql.yaml) |
| SQLi MySQL | [sqli-mysql.yaml](sqli-mysql.yaml) |
| SQLi PostgreSQL | [sqli-postgres.yaml](sqli-postgres.yaml) |
| SQLi SQLite | [sqli-sqlite.yaml](sqli-sqlite.yaml) |
| SSRF | [ssrf.yaml](ssrf.yaml) |
| SSTI | [ssti.yaml](ssti.yaml) |
| XPath injection | [xpath.yaml](xpath.yaml) |
| XSS | [xss-all.yaml](xss-all.yaml) |
| XXE | [xxe.yaml](xxe.yaml) |

## Update Rule

After editing seeds, run:

```bash
make verify-generated
```
