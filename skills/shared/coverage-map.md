# Coverage map

Due-diligence readers know OWASP WSTG and ASVS. This file maps Ensphere
sessions to those catalogues at category level so Session 09 can write the
coverage appendix in a language the reader expects, and so gaps are stated
rather than implied. It is a map, not a conformance claim. When writing the
appendix, cite the specific WSTG test identifier for each executed check from
the current WSTG; this file only names categories.

## OWASP WSTG v4.2 categories

| WSTG category | Ensphere coverage | Not covered by any session |
|---------------|-------------------|----------------------------|
| INFO Information gathering | 01, source-driven inventory | Search-engine recon, fingerprinting sweeps, metafile review |
| CONF Configuration and deployment | 07 platform configuration, 08 documentation exposure, 08.5 size limits | Backup and unreferenced files, HTTP method testing, subdomain takeover, HSTS and file-extension handling |
| IDNT Identity management | 03 registration and account-enumeration behaviour | Username policy, account provisioning process |
| ATHN Authentication | 03 | Browser cache weaknesses; password policy strength is informational only |
| ATHZ Authorization | 04 object, function, property, tenant; 02 path handling | |
| SESS Session management | 03 session, tokens, logout; `verify csrf` | Session puzzling; cookie attribute audit beyond what 03 records |
| INPV Input validation | 02 injection families, 05 XSS, 06 SSRF, 08 mass assignment | HTTP parameter pollution, host header injection, format string, incubated vulnerabilities |
| ERRH Error handling | 03 error differentiation only | Stack trace and verbose error review as its own check |
| CRYP Cryptography | 03 JWT algorithm and signature checks only | TLS configuration, padding oracle, unencrypted channels |
| BUSL Business logic | 04 workflow and state, 08.7 chains, 08.5 misuse defenses, `verify fileupload` | Process timing; function-use limits beyond rate limits |
| CLNT Client-side | 05 DOM XSS; `verify cors`, `verify clickjacking`, `verify redirect`, `verify websocket` | Client-side storage, cross-site script inclusion, reverse tabnabbing |
| APIT API testing | 08 GraphQL, gRPC, schema exposure; 08.5 | |

## OWASP ASVS 4.0.3 chapters

| ASVS chapter | Ensphere coverage |
|--------------|-------------------|
| V1 Architecture | Not covered |
| V2 Authentication | 03 |
| V3 Session management | 03 |
| V4 Access control | 04 |
| V5 Validation, sanitization, encoding | 02, 05 |
| V6 Stored cryptography | Not covered |
| V7 Error handling and logging | 07 logging configuration only |
| V8 Data protection | 07 storage configuration only |
| V9 Communication | Not covered |
| V10 Malicious code | Not covered |
| V11 Business logic | 04, 08.5, 08.7 |
| V12 Files and resources | 02 path handling, 08.5 uploads |
| V13 API and web service | 08 |
| V14 Configuration | 07 |

## Using this file

- The appendix lists every WSTG category and ASVS chapter, in this order,
  with one of: the evidence IDs of the checks executed, `not_tested` with the
  reason, or `not covered` when no Ensphere session addresses it.
- "Not covered" rows are the honest answer to "did you follow WSTG". Never
  write "conducted in accordance with" any catalogue.
- When a session's coverage matrix has rows a category needs and they were
  `blocked`, the appendix row is `not_tested`, not `not covered`.
